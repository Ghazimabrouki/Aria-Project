"""
Central asset-aware Elasticsearch query scoping helper.
Resolves asset_id + source → index pattern + host identity filter.
"""

import copy
import structlog
from typing import Optional

logger = structlog.get_logger()

# ═══════════════════════════════════════════════════════════════════════════════
# Host identity fields per source
# ═══════════════════════════════════════════════════════════════════════════════

HOST_IDENTITY_FIELDS = {
    "wazuh": ["agent.name", "agent.id", "host.name"],
    "falco": ["hostname", "host.name", "output_fields.hostname"],
    "telegraf": ["tag.host", "tags.host", "host", "host.name"],
    "filebeat": ["host.name", "agent.name", "agent.hostname"],
    "suricata": ["host.name", "agent.name", "agent.hostname", "observer.hostname"],
    "generic": ["hostname", "host.name", "agent.name", "tag.host"],
}

# Default index patterns (fallback to global settings)
DEFAULT_INDEX_PATTERNS = {
    "wazuh": "wazuh-alerts-4.x-*",
    "falco": "falco-events-*",
    "telegraf": "telegraf-*",
    "filebeat": "filebeat-*",
    "suricata": "suricata-*",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Core helpers
# ═══════════════════════════════════════════════════════════════════════════════

async def _get_asset(session, asset_id: str):
    """Fetch a MonitoredAsset by asset_id."""
    from response.models import MonitoredAsset
    from sqlalchemy import select
    result = await session.execute(select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id))
    return result.scalar_one_or_none()


def _get_source_config(asset_source_json: dict, source: str) -> dict:
    """Extract source-specific config from asset.source_config_json."""
    if not asset_source_json:
        return {}
    return asset_source_json.get(source, {}) or {}


def _build_host_filter(
    source: str,
    host_name: Optional[str] = None,
    agent_name: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> Optional[dict]:
    """Build an ES bool.should filter for host identity matching.
    Returns None if no identity fields are available.
    """
    should_clauses = []

    if source == "wazuh":
        if agent_name:
            should_clauses.append({"term": {"agent.name": agent_name}})
        if agent_id:
            should_clauses.append({"term": {"agent.id": agent_id}})
        if host_name:
            should_clauses.append({"term": {"host.name": host_name}})
    elif source == "falco":
        if host_name:
            should_clauses.append({"term": {"hostname": host_name}})
            should_clauses.append({"term": {"host.name": host_name}})
            should_clauses.append({"term": {"output_fields.hostname": host_name}})
    elif source == "telegraf":
        if host_name:
            should_clauses.append({"term": {"tag.host": host_name}})
            should_clauses.append({"term": {"tags.host": host_name}})
            should_clauses.append({"term": {"host": host_name}})
            should_clauses.append({"term": {"host.name": host_name}})
    elif source in ("filebeat", "suricata"):
        if host_name:
            should_clauses.append({"term": {"host.name": host_name}})
            should_clauses.append({"term": {"agent.name": host_name}})
            should_clauses.append({"term": {"agent.hostname": host_name}})
    else:
        if host_name:
            should_clauses.append({"term": {"host.name": host_name}})
            should_clauses.append({"term": {"hostname": host_name}})
            should_clauses.append({"term": {"agent.name": host_name}})

    if not should_clauses:
        return None

    return {"bool": {"should": should_clauses, "minimum_should_match": 1}}


def get_index_pattern(source: str, asset_source_json: Optional[dict] = None) -> str:
    """Return the index pattern for a source, optionally using asset-specific override."""
    if asset_source_json:
        cfg = asset_source_json.get(source, {})
        if cfg and cfg.get("index_pattern"):
            return cfg["index_pattern"]
    from config import get_settings
    settings = get_settings()
    settings_map = {
        "wazuh": settings.wazuh_index_pattern,
        "falco": settings.falco_index_pattern,
        "telegraf": settings.telegraf_index_pattern,
        "filebeat": settings.filebeat_index_pattern,
        "suricata": settings.suricata_index_pattern,
    }
    return settings_map.get(source, DEFAULT_INDEX_PATTERNS.get(source, "*"))


def wrap_query(
    base_query: dict,
    source: str,
    asset_source_json: Optional[dict] = None,
) -> dict:
    """Inject host identity filter into an existing ES query safely.
    
    - asset_source_json is the asset's source_config_json dict (or None for legacy).
    - Deep-copies base_query before mutation.
    - If no host identity is configured, returns unmodified copy.
    """
    if not asset_source_json:
        return copy.deepcopy(base_query)

    cfg = asset_source_json.get(source, {})
    if not cfg:
        return copy.deepcopy(base_query)

    host_filter = _build_host_filter(
        source=source,
        host_name=cfg.get("host_name"),
        agent_name=cfg.get("agent_name"),
        agent_id=cfg.get("agent_id"),
    )
    if not host_filter:
        return copy.deepcopy(base_query)

    query = copy.deepcopy(base_query)

    # Suricata dataset filter (when Suricata ships through Filebeat)
    extra_filters = []
    if source == "suricata":
        extra_filters.append({
            "bool": {
                "should": [
                    {"term": {"event.dataset": "suricata.eve"}},
                    {"term": {"event.module": "suricata"}},
                    {"term": {"fileset.name": "eve"}},
                ],
                "minimum_should_match": 1,
            }
        })

    # Safely inject into existing query structure
    if "bool" in query:
        query["bool"].setdefault("filter", [])
        query["bool"]["filter"].append(host_filter)
        for ef in extra_filters:
            query["bool"]["filter"].append(ef)
    else:
        new_query = {"bool": {"must": [query], "filter": [host_filter]}}
        for ef in extra_filters:
            new_query["bool"]["filter"].append(ef)
        query = new_query

    return query


# ═══════════════════════════════════════════════════════════════════════════════
# Async resolution helpers (for routes with DB access)
# ═══════════════════════════════════════════════════════════════════════════════

async def resolve_asset_scope(
    source: str,
    asset_id: Optional[str] = None,
    session=None,
) -> dict:
    """Resolve full scope for a source + asset_id.
    
    Returns dict with:
      - index_pattern: str
      - query_filter: ES query dict (or None)
      - asset_source_json: the asset's source config (or None)
    """
    # asset_id=None → legacy unscoped
    # asset_id="all" → global read, no host filter
    if asset_id is None or asset_id == "all" or not asset_id:
        return {
            "index_pattern": get_index_pattern(source),
            "query_filter": None,
            "asset_source_json": None,
        }

    if session is None:
        # No session provided — return default scope
        logger.warning("resolve_asset_scope_no_session", asset_id=asset_id, source=source)
        return {
            "index_pattern": get_index_pattern(source),
            "query_filter": None,
            "asset_source_json": None,
        }

    from response.models import MonitoredAsset
    from sqlalchemy import select
    result = await session.execute(select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id))
    asset = result.scalar_one_or_none()

    if not asset:
        return {
            "index_pattern": get_index_pattern(source),
            "query_filter": None,
            "asset_source_json": None,
        }

    source_json = asset.source_config_json or {}
    index_pattern = get_index_pattern(source, source_json)
    query_filter = wrap_query({"match_all": {}}, source, source_json)

    return {
        "index_pattern": index_pattern,
        "query_filter": query_filter,
        "asset_source_json": source_json,
    }


async def resolve_asset_from_hostname(
    hostname: Optional[str],
    agent_name: Optional[str] = None,
    agent_id: Optional[str] = None,
    session=None,
) -> Optional[str]:
    """Given a hostname/agent name from an alert doc, resolve to a MonitoredAsset.asset_id.
    Returns None if no unique match found.
    """
    if not hostname and not agent_name and not agent_id:
        return None

    if session is None:
        return None

    from response.models import MonitoredAsset
    from sqlalchemy import select, or_

    conditions = []
    if hostname:
        conditions.append(MonitoredAsset.hostname == hostname)
        conditions.append(MonitoredAsset.asset_id == hostname)
    if agent_name:
        conditions.append(MonitoredAsset.hostname == agent_name)
        conditions.append(MonitoredAsset.asset_id == agent_name)
    if agent_id:
        # agent_id might match asset_id or be in source_config_json
        conditions.append(MonitoredAsset.asset_id == agent_id)

    if not conditions:
        return None

    stmt = (
        select(MonitoredAsset)
        .where(MonitoredAsset.enabled == True)
        .where(or_(*conditions))
    )
    result = await session.execute(stmt)
    matches = result.scalars().all()

    if len(matches) == 1:
        return matches[0].asset_id
    elif len(matches) > 1:
        logger.warning(
            "ambiguous_asset_resolution",
            hostname=hostname,
            agent_name=agent_name,
            agent_id=agent_id,
            matches=[m.asset_id for m in matches],
        )
        return None

    # Fallback: search source_config_json for agent_id / agent_name / host_name matches
    # This handles cases where the Wazuh/Syslog agent name differs from the asset hostname
    if agent_id or agent_name or hostname:
        all_assets_result = await session.execute(
            select(MonitoredAsset).where(MonitoredAsset.enabled == True)
        )
        all_assets = all_assets_result.scalars().all()
        json_matches = []
        for asset in all_assets:
            sc = asset.source_config_json or {}
            for source, cfg in sc.items():
                if not isinstance(cfg, dict):
                    continue
                if agent_id and cfg.get("agent_id") == agent_id:
                    json_matches.append(asset)
                    break
                if agent_name and cfg.get("agent_name") == agent_name:
                    json_matches.append(asset)
                    break
                if hostname and cfg.get("host_name") == hostname:
                    json_matches.append(asset)
                    break
        if len(json_matches) == 1:
            return json_matches[0].asset_id
        elif len(json_matches) > 1:
            logger.warning(
                "ambiguous_asset_resolution_json",
                hostname=hostname,
                agent_name=agent_name,
                agent_id=agent_id,
                matches=[m.asset_id for m in json_matches],
            )
            return None

    return None
