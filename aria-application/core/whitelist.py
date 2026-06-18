"""
Whitelist system.
Checks IPs, subnets, and domains against the whitelist before any blocking action.
"""

import ipaddress
import structlog
import time
from typing import Optional, List, Dict, Any

from response.db import AsyncSessionLocal
from response.models import WhitelistEntry
from sqlalchemy import select, or_, and_
from datetime import datetime, timezone

def _serialize_dt(dt: Optional[datetime]) -> Optional[str]:
    """Serialize a datetime to ISO format, appending Z if naive (SQLite stores UTC without tzinfo)."""
    if not dt:
        return None
    s = dt.isoformat()
    # If no timezone indicator, assume UTC and append Z
    if dt.tzinfo is None and not s.endswith("Z") and "+" not in s[-6:] and "-" not in s[-6:]:
        s += "Z"
    return s

logger = structlog.get_logger()

# Global in-memory cache for whitelist checks (TTL: 60 seconds)
_whitelist_cache: dict[str, tuple[bool, float]] = {}
_CACHE_TTL_SECONDS = 60


def _parse_ip_or_network(value: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse an IP or CIDR network string."""
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        return ipaddress.ip_address(value)
    except ValueError:
        return None


async def is_whitelisted(value: str, check_type: Optional[str] = None) -> bool:
    """
    Check if a value (IP, subnet, or domain) is whitelisted.
    
    Args:
        value: The value to check
        check_type: Optional type hint ('ip', 'subnet', 'domain'). If None, auto-detect.
    
    Returns:
        True if whitelisted, False otherwise
    """
    if not value:
        return False

    value_lower = value.lower().strip()
    cache_key = f"{value_lower}:{check_type or 'auto'}"
    now = time.time()

    # Check cache
    cached = _whitelist_cache.get(cache_key)
    if cached and (now - cached[1]) < _CACHE_TTL_SECONDS:
        return cached[0]

    # Determine type
    if check_type is None:
        if "/" in value_lower or _parse_ip_or_network(value_lower):
            check_type = "ip"
        else:
            check_type = "domain"

    result = False
    try:
        async with AsyncSessionLocal() as session:
            # Exact match for domain or IP
            db_result = await session.execute(
                select(WhitelistEntry).where(
                    WhitelistEntry.value.ilike(value_lower)
                ).limit(1)
            )
            if db_result.scalar_one_or_none():
                result = True
            else:
                # For IPs, also check subnet containment
                if check_type == "ip":
                    addr = _parse_ip_or_network(value_lower)
                    if isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                        # Check all subnet entries (and ip entries that contain CIDR)
                        subnet_result = await session.execute(
                            select(WhitelistEntry).where(
                                or_(
                                    WhitelistEntry.type == "subnet",
                                    and_(WhitelistEntry.type == "ip", WhitelistEntry.value.like("%/%")),
                                )
                            )
                        )
                        for entry in subnet_result.scalars().all():
                            network = _parse_ip_or_network(entry.value)
                            if isinstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                                if addr in network:
                                    result = True
                                    break
    except Exception as e:
        logger.error("whitelist_check_failed", value=value, error=str(e))
        # Fail-safe: if check fails, do NOT assume whitelisted
        result = False

    # Update cache
    _whitelist_cache[cache_key] = (result, now)
    return result


async def check_alert_whitelist(alert: Dict[str, Any]) -> bool:
    """Check if an alert's source_ip, dest_ip, or hostname is whitelisted. Returns True if whitelisted."""
    for field in ("source_ip", "dest_ip"):
        ip = alert.get(field)
        if ip and await is_whitelisted(ip):
            return True
    hostname = alert.get("hostname")
    if hostname and await is_whitelisted(hostname, check_type="domain"):
        return True
    return False


async def get_whitelist_entries(
    type_filter: Optional[str] = None,
    label_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Get all whitelist entries."""
    async with AsyncSessionLocal() as session:
        stmt = select(WhitelistEntry)
        if type_filter:
            stmt = stmt.where(WhitelistEntry.type == type_filter)
        if label_filter:
            stmt = stmt.where(WhitelistEntry.label == label_filter)
        stmt = stmt.order_by(WhitelistEntry.created_at.desc())
        result = await session.execute(stmt)
        entries = result.scalars().all()
        return [
            {
                "id": e.id,
                "type": e.type,
                "value": e.value,
                "label": e.label,
                "description": e.description,
                "created_at": _serialize_dt(e.created_at),
            }
            for e in entries
        ]


async def add_whitelist_entry(
    type: str, value: str, label: str = "trusted", description: Optional[str] = None
) -> Dict[str, Any]:
    """Add a new whitelist entry."""
    # Validate IP/subnet
    if type in ("ip", "subnet"):
        parsed = _parse_ip_or_network(value)
        if parsed is None:
            raise ValueError(f"Invalid IP or subnet: {value}")
        # Auto-correct type to subnet if value contains CIDR notation
        if type == "ip" and "/" in value:
            type = "subnet"
            logger.warning("whitelist_type_auto_corrected", original_type="ip", corrected_type="subnet", value=value)

    async with AsyncSessionLocal() as session:
        # Check for duplicates
        existing = await session.execute(
            select(WhitelistEntry).where(WhitelistEntry.value.ilike(value.strip()))
        )
        if existing.scalar_one_or_none():
            raise ValueError(f"Entry already exists: {value}")

        entry = WhitelistEntry(
            type=type,
            value=value.strip(),
            label=label,
            description=description,
        )
        session.add(entry)
        await session.commit()
        await session.refresh(entry)
        logger.info("whitelist_entry_added", id=entry.id, value=entry.value, type=entry.type)
        return {
            "id": entry.id,
            "type": entry.type,
            "value": entry.value,
            "label": entry.label,
            "description": entry.description,
            "created_at": _serialize_dt(entry.created_at),
        }


async def remove_whitelist_entry(entry_id: str) -> bool:
    """Remove a whitelist entry."""
    async with AsyncSessionLocal() as session:
        entry = await session.get(WhitelistEntry, entry_id)
        if not entry:
            return False
        # Invalidate cache for this value
        value_lower = entry.value.lower().strip()
        for ct in ("auto", "ip", "subnet", "domain"):
            _whitelist_cache.pop(f"{value_lower}:{ct}", None)
        await session.delete(entry)
        await session.commit()
        logger.info("whitelist_entry_removed", id=entry_id, value=entry.value)
        return True


async def _retroactively_mark_alerts(value: str) -> int:
    """Mark existing alerts as whitelisted if they match the given value (IP or subnet).
    Returns the number of alerts updated."""
    from sqlalchemy import update
    from response.db import AsyncSessionLocal
    from response.models import Alert
    from datetime import datetime, timezone, timedelta

    try:
        async with AsyncSessionLocal() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

            # Try to parse as subnet
            network = _parse_ip_or_network(value.strip())
            is_subnet = isinstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network))

            if is_subnet:
                # For subnets, we need to check each alert individually
                # because SQLAlchemy+SQLite can't do IP-in-network checks in SQL
                result = await session.execute(
                    select(Alert)
                    .where(
                        Alert.created_at >= cutoff,
                        Alert.whitelisted == False,
                    )
                )
                alerts_to_update = []
                for alert in result.scalars().all():
                    for field in ("source_ip", "dest_ip"):
                        ip_str = getattr(alert, field)
                        if ip_str:
                            try:
                                addr = ipaddress.ip_address(ip_str.strip())
                                if addr in network:
                                    alerts_to_update.append(alert.id)
                                    break
                            except ValueError:
                                pass
                if alerts_to_update:
                    await session.execute(
                        update(Alert)
                        .where(Alert.id.in_(alerts_to_update))
                        .values(whitelisted=True)
                    )
                    await session.commit()
                    logger.info("retroactive_whitelist_applied", value=value, updated=len(alerts_to_update))
                    return len(alerts_to_update)
            else:
                # Exact match for IP
                stmt = (
                    update(Alert)
                    .where(
                        Alert.created_at >= cutoff,
                        Alert.whitelisted == False,
                        ((Alert.source_ip == value) | (Alert.dest_ip == value))
                    )
                    .values(whitelisted=True)
                )
                result = await session.execute(stmt)
                await session.commit()
                updated = result.rowcount
                logger.info("retroactive_whitelist_applied", value=value, updated=updated)
                return updated
    except Exception as e:
        logger.warning("retroactive_whitelist_failed", value=value, error=str(e))
    return 0
