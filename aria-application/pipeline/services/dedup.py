"""
Source-specific deduplication module.
Handles deduplication based on source type using Redis.
"""

import hashlib
import structlog
from typing import Optional, Dict, Any
from datetime import datetime, timezone

logger = structlog.get_logger()

# Deduplication TTL per source (in seconds)
DEDUP_TTL = {
    "wazuh": 300,      # 5 minutes (reduced duplicate noise)
    "falco": 300,      # 5 minutes (reduced duplicate noise)
    "suricata": 300,   # 5 minutes (reduced duplicate noise)
    "filebeat": 300,   # 5 minutes (reduced duplicate noise)
}

# Extended TTL for threat intel feeds (group by rule, not per-IP)
THREAT_INTEL_TTL = 300  # 5 minutes

# Patterns that indicate a threat intel blocklist match (passive, not active attack)
_THREAT_INTEL_PATTERNS = [
    'drop ',
    'cins active threat',
    'spamhaus',
    'block listed',
    'threat intelligence',
]

# In-memory fallback cache when Redis is unavailable
_memory_cache: Dict[str, float] = {}
MAX_MEMORY_CACHE = 10000


def _get_ttl(source: str) -> int:
    """Get TTL for a source (default 5 minutes)."""
    return DEDUP_TTL.get(source, 300)


def _is_threat_intel(payload: Dict[str, Any]) -> bool:
    """Check if alert is a threat intel blocklist match (passive detection)."""
    rule_name = (payload.get("rule_name", "") or payload.get("title", "")).lower()
    return any(x in rule_name for x in _THREAT_INTEL_PATTERNS)


def _generate_dedup_key(source: str, payload: Dict[str, Any]) -> str:
    """Generate a source-specific deduplication key."""
    
    if source == "wazuh":
        # Wazuh: agent.id + rule.id + source_ip (different attacker IPs = separate alerts)
        agent_id = payload.get("metadata", {}).get("agent_id", "")
        rule_id = payload.get("metadata", {}).get("rule_id", "")
        src_ip = payload.get("source_ip", "")
        if not agent_id:
            agent = payload.get("agent", {})
            agent_id = agent.get("id", "") if isinstance(agent, dict) else ""
        if not rule_id:
            rule = payload.get("rule", {})
            rule_id = str(rule.get("id", "")) if isinstance(rule, dict) else ""
        key_parts = [source, agent_id, rule_id, src_ip]
        
    elif source == "falco":
        # Falco: hostname + container_id + rule_name (+ proc_name + fd_name for granularity)
        hostname = payload.get("hostname", "")
        meta = payload.get("metadata", {}) or {}
        container_id = meta.get("container_id") or meta.get("container", {}).get("id", "")
        rule_name = payload.get("rule_name", "") or payload.get("title", "")
        proc_name = payload.get("proc_name", "")
        fd_name = payload.get("fd_name", "")
        key_parts = [source, hostname, container_id, rule_name, proc_name, fd_name]
        
    elif source == "suricata":
        # Suricata: signature_id + src_ip + dst_ip + dst_port
        sig_id = str(payload.get("metadata", {}).get("signature_id", ""))
        src_ip = payload.get("source_ip", "")
        dst_ip = payload.get("dest_ip", "")
        dst_port = str(payload.get("metadata", {}).get("dst_port", ""))
        key_parts = [source, sig_id, src_ip, dst_ip, dst_port]
        
    elif source == "filebeat":
        # Filebeat: threat intel feeds dedup by rule_name only (group all IPs)
        # Active attacks dedup by rule_name + source_ip + dst_ip
        rule_name = payload.get("rule_name", "") or payload.get("title", "")
        
        if _is_threat_intel(payload):
            # Threat intel: group by rule only
            key_parts = [source, "threat_intel", rule_name]
        else:
            # Active attacks: per-IP dedup
            src_ip = payload.get("source_ip", "")
            dst_ip = payload.get("dest_ip", "")
            key_parts = [source, rule_name, src_ip, dst_ip]
        
    else:
        # Default: use source_id
        key_parts = [source, payload.get("source_id", "")]
    
    # Create hash from key parts (filter empty)
    key_str = ":".join(str(k) for k in key_parts if k)
    return f"opensoar:dedup:{hashlib.md5(key_str.encode()).hexdigest()[:16]}"


async def _redis_get(key: str) -> Optional[str]:
    """Get value from Redis."""
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        return await redis.get(key)
    except Exception:
        return None


async def _redis_set(key: str, value: str, ttl: int) -> None:
    """Set value in Redis with TTL."""
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        await redis.setex(key, ttl, value)
    except Exception:
        pass


def generate_dedup_key(source: str, payload: Dict[str, Any]) -> str:
    """Public accessor for dedup key generation."""
    return _generate_dedup_key(source, payload)


async def _db_has_dedup_key(key: str, ttl: int) -> bool:
    """Check if an alert with the same dedup_key exists in the local DB within TTL window."""
    try:
        from datetime import datetime, timezone, timedelta
        from sqlalchemy import select
        from response.db import AsyncSessionLocal
        from response.models import Alert

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=ttl)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Alert.id).where(
                    Alert.dedup_key == key,
                    Alert.created_at >= cutoff,
                ).limit(1)
            )
            return result.scalar_one_or_none() is not None
    except Exception as e:
        logger.debug("dedup_db_check_failed", error=str(e))
        return False


async def is_duplicate(source: str, payload: Dict[str, Any]) -> bool:
    """
    Check if alert is a duplicate based on source-specific key.
    
    Args:
        source: Source type (wazuh, falco, suricata)
        payload: The mapped alert payload
        
    Returns:
        True if this is a duplicate, False if unique
    """
    key = _generate_dedup_key(source, payload)
    
    # Use extended TTL for threat intel feeds
    if _is_threat_intel(payload):
        ttl = THREAT_INTEL_TTL
    else:
        ttl = _get_ttl(source)
    
    # Try Redis first
    existing = await _redis_get(key)
    if existing:
        logger.debug(
            "dedup_duplicate_redis",
            source=source,
            key_hash=key[-8:],
            ttl_remaining=ttl,
        )
        return True
    
    # Fallback to memory cache
    if key in _memory_cache:
        logger.debug(
            "dedup_duplicate_memory",
            source=source,
            key_hash=key[-8:],
        )
        return True
    
    # Check local shadow DB
    if await _db_has_dedup_key(key, ttl):
        logger.debug(
            "dedup_duplicate_db",
            source=source,
            key_hash=key[-8:],
        )
        return True
    
    # New alert - mark as seen
    await _redis_set(key, "1", ttl)
    
    # Also track in memory for faster lookups
    _memory_cache[key] = datetime.now(timezone.utc).timestamp()
    _cleanup_memory_cache()
    
    logger.debug(
        "dedup_new_alert",
        source=source,
        key_hash=key[-8:],
    )
    return False


def _cleanup_memory_cache() -> None:
    """Clean up old entries from memory cache."""
    if len(_memory_cache) > MAX_MEMORY_CACHE:
        # Remove oldest entries
        sorted_items = sorted(_memory_cache.items(), key=lambda x: x[1])
        to_remove = len(_memory_cache) - MAX_MEMORY_CACHE + 100
        for key, _ in sorted_items[:to_remove]:
            del _memory_cache[key]


async def clear_dedup_cache(source: Optional[str] = None) -> None:
    """
    Clear deduplication cache.
    
    Args:
        source: Optional source to clear. If None, clears all.
    """
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        
        if source:
            pattern = f"opensoar:dedup:{source[:3]}*"
        else:
            pattern = "opensoar:dedup:*"
        
        keys = await redis.keys(pattern)
        if keys:
            await redis.delete(*keys)
            logger.info("dedup_cache_cleared", source=source, keys_deleted=len(keys))
    except Exception as e:
        logger.warning("dedup_cache_clear_failed", error=str(e))
    
    # Clear memory cache
    global _memory_cache
    if source:
        _memory_cache = {
            k: v for k, v in _memory_cache.items() 
            if not k.startswith(f"opensoar:dedup:{source[:3]}")
        }
    else:
        _memory_cache = {}


def get_dedup_stats() -> Dict[str, Any]:
    """Get deduplication statistics."""
    return {
        "memory_cache_size": len(_memory_cache),
        "source_ttls": DEDUP_TTL,
    }
