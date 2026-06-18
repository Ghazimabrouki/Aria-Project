"""
Dashboard API - Summary with navigation links.
Uses local shadow store for accurate counts (no 200-item upstream limit).

Caching strategy:
- Short in-memory TTL (20s) for dashboard endpoints to reduce repeated
  COUNT queries during rapid polling / multiple concurrent UI clients.
- Cache is local to the process, endpoint-scoped, and range-aware.
- Errors are never cached.
"""
from fastapi import APIRouter, Query, HTTPException, Depends
from response.auth import require_auth, CurrentUser
from api.routes._shared import validate_asset_id, enforce_asset_scope
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
import structlog

from sqlalchemy import select, func, text, not_, exists
from config import get_settings
from core.asset_scope import wrap_query

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


# ---------------------------------------------------------------------------
# Dashboard cache: uses Redis if available, otherwise no caching.
# TTL is intentionally short (20s) because counts change frequently and
# we never want stale data to mislead SOC operators for long.
# ---------------------------------------------------------------------------
import json


class _DashboardCache:
    """Redis-backed TTL cache for dashboard responses. Falls back to no-op if Redis is unavailable."""

    def __init__(self, ttl_seconds: int = 20):
        self._ttl = ttl_seconds

    def _key(self, endpoint: str, **params) -> str:
        parts = ["dashboard", endpoint]
        for k in sorted(params):
            parts.append(f"{k}:{params[k]}")
        return ":".join(parts)

    async def get(self, endpoint: str, **params) -> Optional[Any]:
        try:
            from core.redis import get_redis_client
            redis = await get_redis_client()
            key = self._key(endpoint, **params)
            raw = await redis.get(key)
            if raw:
                return json.loads(raw)
        except Exception:
            pass
        return None

    async def set(self, endpoint: str, value: Any, **params) -> None:
        try:
            from core.redis import get_redis_client
            redis = await get_redis_client()
            key = self._key(endpoint, **params)
            await redis.setex(key, self._ttl, json.dumps(value, default=str))
        except Exception:
            pass

    async def clear(self) -> None:
        try:
            from core.redis import get_redis_client
            redis = await get_redis_client()
            keys = await redis.keys("dashboard:*")
            if keys:
                await redis.delete(*keys)
        except Exception:
            pass


_dashboard_cache = _DashboardCache(ttl_seconds=20)


def _parse_range(range_str: str) -> datetime:
    """Parse a time range string into a cutoff datetime."""
    now = datetime.now(timezone.utc)
    mapping = {
        "15m": timedelta(minutes=15),
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
    }
    return now - mapping.get(range_str, timedelta(hours=24))


def _get_previous_period(range_str: str) -> tuple[datetime, datetime]:
    """Return (prev_start, prev_end) for the period immediately before the current range."""
    now = datetime.now(timezone.utc)
    mapping = {
        "15m": timedelta(minutes=15),
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
    }
    delta = mapping.get(range_str, timedelta(hours=24))
    return (now - 2 * delta, now - delta)


def _calc_delta_pct(current: int, previous: int) -> Optional[float]:
    """Calculate percentage change. Returns None for special cases."""
    if previous == 0 and current == 0:
        return 0.0
    if previous == 0 and current > 0:
        return None  # signals "New activity"
    return round(((current - previous) / previous) * 100, 1)


async def _validate_asset(asset_id: Optional[str]) -> Optional[str]:
    """Validate asset_id if multi-server is enabled. Returns normalized asset_id or None."""
    if not asset_id or asset_id.lower() == "all":
        return None
    settings = get_settings()
    if not settings.multi_server_enabled:
        return None
    from response.db import AsyncSessionLocal
    from response.models import MonitoredAsset
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
        )
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=400, detail=f"Invalid asset_id: {asset_id}")
        if not asset.enabled:
            raise HTTPException(status_code=400, detail=f"Asset {asset_id} is disabled.")
    return asset_id


@router.get("/summary")
async def get_dashboard_summary(
    range: Optional[str] = Query("24h", description="Time range: 15m | 1h | 24h | 7d"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """Get all counts with navigation links from local shadow store."""
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    cache_kwargs = {"range": range}
    if asset_id:
        cache_kwargs["asset_id"] = asset_id
    cached = await _dashboard_cache.get("summary", **cache_kwargs)
    if cached is not None:
        return cached

    from response.db import AsyncSessionLocal
    from response.models import Investigation, Archive, Alert, Incident, AlertIncidentLink

    settings = get_settings()
    cutoff = _parse_range(range)

    # Alerts from local DB (exclude Falco/runtime alerts from SOC dashboard)
    alert_total = 0
    alert_active = 0
    alert_critical = 0
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(func.count(Alert.id)).where(Alert.created_at >= cutoff, Alert.source != "falco")
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            result = await session.execute(stmt)
            alert_total = result.scalar_one()
            stmt = select(func.count(Alert.id)).where(
                Alert.status == "active", Alert.created_at >= cutoff, Alert.source != "falco"
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            result = await session.execute(stmt)
            alert_active = result.scalar_one()
            stmt = select(func.count(Alert.id)).where(
                Alert.severity == "critical", Alert.created_at >= cutoff, Alert.source != "falco"
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            result = await session.execute(stmt)
            alert_critical = result.scalar_one()
    except Exception as e:
        logger.warning("dashboard_alerts_failed", error=str(e))

    # Incidents from local DB — count ALL open incidents regardless of creation time,
    # excluding Falco-derived incidents to keep SOC KPIs clean
    incident_total = 0
    open_count = 0
    incident_severity_counts = {}
    try:
        async with AsyncSessionLocal() as session:
            no_runtime_inv = not_(
                exists().where(
                    Investigation.local_incident_id == Incident.id,
                    Investigation.investigation_type == "runtime",
                )
            )
            no_falco_alert = not_(
                exists().where(
                    AlertIncidentLink.incident_id == Incident.id,
                    AlertIncidentLink.alert_id == Alert.id,
                    Alert.source == "falco",
                )
            )
            stmt = select(func.count(Incident.id)).where(no_runtime_inv, no_falco_alert)
            if asset_id:
                stmt = stmt.where(Incident.asset_id == asset_id)
            result = await session.execute(stmt)
            incident_total = result.scalar_one()
            stmt = select(func.count(Incident.id)).where(
                Incident.status == "open", no_runtime_inv, no_falco_alert
            )
            if asset_id:
                stmt = stmt.where(Incident.asset_id == asset_id)
            result = await session.execute(stmt)
            open_count = result.scalar_one()
            # Severity breakdown for all open incidents
            stmt = (
                select(Incident.severity, func.count(Incident.id))
                .where(Incident.status == "open", no_runtime_inv, no_falco_alert)
                .group_by(Incident.severity)
            )
            if asset_id:
                stmt = stmt.where(Incident.asset_id == asset_id)
            sev_result = await session.execute(stmt)
            incident_severity_counts = {row[0]: row[1] for row in sev_result.all()}
    except Exception as e:
        logger.warning("dashboard_incidents_failed", error=str(e))

    # Fallback to upstream for incidents if local is empty (skip when asset-scoped)
    if incident_total == 0 and settings.upstream_enabled and not asset_id:
        try:
            from pipeline.sender import client
            upstream = await client.list_incidents(limit=200)
            upstream_list = upstream.get("incidents", [])
            incident_total = upstream.get("total", len(upstream_list))
            open_count = len([i for i in upstream_list if i.get("status") == "open"])
        except Exception:
            pass

    # Investigations from local DB (exclude runtime/infrastructure from SOC KPIs)
    status_counts = {}
    total_inv = 0
    active_inv = 0
    try:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(Investigation.status, func.count(Investigation.id))
                .where(
                    Investigation.investigation_type != "infrastructure",
                    Investigation.investigation_type != "runtime",
                )
                .group_by(Investigation.status)
            )
            if asset_id:
                stmt = stmt.where(Investigation.asset_id == asset_id)
            result = await session.execute(stmt)
            status_counts = {row[0]: row[1] for row in result.all()}
            total_inv = sum(status_counts.values())
            active_inv = sum(
                status_counts.get(s, 0)
                for s in ["pending", "awaiting_approval", "approved", "running"]
            )
    except Exception as e:
        logger.warning("dashboard_investigations_failed", error=str(e))

    # Archives
    archive_count = 0
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(func.count(Archive.id))
            if asset_id:
                stmt = stmt.join(Investigation, Archive.investigation_id == Investigation.id).where(
                    Investigation.asset_id == asset_id
                )
            result = await session.execute(stmt)
            archive_count = result.scalar_one()
    except Exception:
        pass

    result = {
        "alerts": {
            "total": alert_total,
            "active": alert_active,
            "critical": alert_critical,
            "links": {
                "list": "/api/v1/alerts",
                "by_severity": "/api/v1/alerts?severity=critical"
            }
        },
        "incidents": {
            "total": incident_total,
            "open": open_count,
            "by_severity": incident_severity_counts,
            "links": {
                "list": "/api/v1/incidents",
                "by_status": "/api/v1/incidents?status=open"
            }
        },
        "investigations": {
            "total": total_inv,
            "active": active_inv,
            "by_status": status_counts,
            "links": {
                "list": "/api/v1/investigations",
                "stats": "/api/v1/investigations/stats",
                "awaiting_approval": "/api/v1/investigations?status=awaiting_approval",
                "running": "/api/v1/investigations?status=running"
            }
        },
        "archives": {
            "total": archive_count,
            "links": {
                "list": "/api/v1/archives",
                "stats": "/api/v1/archives/stats"
            }
        },
        "navigation": [
            {"label": "Alerts", "path": "/api/v1/alerts", "icon": "bell"},
            {"label": "Incidents", "path": "/api/v1/incidents", "icon": "alert-triangle"},
            {"label": "Investigations", "path": "/api/v1/investigations", "icon": "search"},
            {"label": "Archives", "path": "/api/v1/archives", "icon": "archive"},
            {"label": "Performance", "path": "/api/v1/metrics/dashboard", "icon": "activity"},
            {"label": "Search", "path": "/api/v1/search", "icon": "search"},
            {"label": "Pipeline", "path": "/api/v1/pipeline/status", "icon": "activity"}
        ]
    }
    await _dashboard_cache.set("summary", result, **cache_kwargs)
    return result


@router.get("/quick-stats")
async def get_quick_stats(
    range: Optional[str] = Query("24h", description="Time range: 15m | 1h | 24h | 7d"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """Minimal stats for header/footer display from local shadow store."""
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    cache_kwargs = {"range": range}
    if asset_id:
        cache_kwargs["asset_id"] = asset_id
    cached = await _dashboard_cache.get("quick-stats", **cache_kwargs)
    if cached is not None:
        return cached

    from response.db import AsyncSessionLocal
    from response.models import Investigation, Archive, Alert, Incident, AlertIncidentLink

    settings = get_settings()
    cutoff = _parse_range(range)
    prev_start, prev_end = _get_previous_period(range)
    counts = {
        "alerts": 0,
        "critical_alerts": 0,
        "incidents": 0,
        "investigations": 0,
        "pending_approvals": 0,
        "archives": 0,
    }

    try:
        async with AsyncSessionLocal() as session:
            stmt = select(func.count(Alert.id)).where(Alert.created_at >= cutoff, Alert.source != "falco")
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            result = await session.execute(stmt)
            counts["alerts"] = result.scalar_one()
            stmt = select(func.count(Alert.id)).where(
                Alert.severity == "critical", Alert.created_at >= cutoff, Alert.source != "falco"
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            result = await session.execute(stmt)
            counts["critical_alerts"] = result.scalar_one()
            # Previous-period deltas for alerts
            stmt = select(func.count(Alert.id)).where(
                Alert.created_at >= prev_start,
                Alert.created_at < prev_end,
                Alert.source != "falco",
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            prev_alert = await session.scalar(stmt)
            stmt = select(func.count(Alert.id)).where(
                Alert.created_at >= prev_start,
                Alert.created_at < prev_end,
                Alert.severity == "critical",
                Alert.source != "falco",
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            prev_critical = await session.scalar(stmt)
            counts["alerts_delta_pct"] = _calc_delta_pct(counts["alerts"], prev_alert or 0)
            counts["critical_alerts_delta_pct"] = _calc_delta_pct(counts["critical_alerts"], prev_critical or 0)
    except Exception:
        pass

    # Count ALL open incidents (not just recently created), excluding Falco-derived
    try:
        async with AsyncSessionLocal() as session:
            no_runtime_inv = not_(
                exists().where(
                    Investigation.local_incident_id == Incident.id,
                    Investigation.investigation_type == "runtime",
                )
            )
            no_falco_alert = not_(
                exists().where(
                    AlertIncidentLink.incident_id == Incident.id,
                    AlertIncidentLink.alert_id == Alert.id,
                    Alert.source == "falco",
                )
            )
            stmt = select(func.count(Incident.id)).where(
                Incident.status == "open", no_runtime_inv, no_falco_alert
            )
            if asset_id:
                stmt = stmt.where(Incident.asset_id == asset_id)
            result = await session.execute(stmt)
            counts["incidents"] = result.scalar_one()
    except Exception:
        pass

    # Fallback to upstream if local incidents empty (skip when asset-scoped)
    if counts.get("incidents", 0) == 0 and settings.upstream_enabled and not asset_id:
        try:
            from pipeline.sender import client
            upstream = await client.list_incidents(status="open", limit=200)
            upstream_list = upstream.get("incidents", [])
            counts["incidents"] = upstream.get("total", len(upstream_list))
        except Exception:
            pass

    # Active investigations = pending + running + awaiting_approval + approved
    try:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(func.count(Investigation.id))
                .where(
                    Investigation.status.in_(["pending", "running", "awaiting_approval", "approved"]),
                    Investigation.investigation_type != "infrastructure",
                    Investigation.investigation_type != "runtime",
                )
            )
            if asset_id:
                stmt = stmt.where(Investigation.asset_id == asset_id)
            result = await session.execute(stmt)
            counts["investigations"] = result.scalar_one()
    except Exception as e:
        logger.warning("quick_stats_investigations_failed", error=str(e))

    try:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(func.count(Investigation.id))
                .where(
                    Investigation.status == "awaiting_approval",
                    Investigation.investigation_type != "infrastructure",
                    Investigation.investigation_type != "runtime",
                )
            )
            if asset_id:
                stmt = stmt.where(Investigation.asset_id == asset_id)
            result = await session.execute(stmt)
            counts["pending_approvals"] = result.scalar_one()
    except Exception as e:
        logger.warning("quick_stats_pending_approvals_failed", error=str(e))

    try:
        async with AsyncSessionLocal() as session:
            stmt = select(func.count(Archive.id))
            if asset_id:
                stmt = stmt.join(Investigation, Archive.investigation_id == Investigation.id).where(
                    Investigation.asset_id == asset_id
                )
            result = await session.execute(stmt)
            counts["archives"] = result.scalar_one()
    except Exception as e:
        logger.warning("quick_stats_archives_failed", error=str(e))

    # Whitelisted alerts (time-scoped like other alert counts)
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(func.count(Alert.id)).where(
                Alert.whitelisted == True, Alert.created_at >= cutoff, Alert.source != "falco"
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            result = await session.execute(stmt)
            counts["whitelisted_alerts"] = result.scalar_one()
            stmt = select(func.count(Alert.id)).where(
                Alert.whitelisted == True,
                Alert.created_at >= prev_start,
                Alert.created_at < prev_end,
                Alert.source != "falco",
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            prev_whitelisted = await session.scalar(stmt)
            counts["whitelisted_alerts_delta_pct"] = _calc_delta_pct(
                counts["whitelisted_alerts"], prev_whitelisted or 0
            )
    except Exception as e:
        logger.warning("quick_stats_whitelisted_alerts_failed", error=str(e))

    # Whitelisted incidents (not time-scoped; all whitelisted incidents regardless of creation time)
    try:
        async with AsyncSessionLocal() as session:
            no_runtime_inv = not_(
                exists().where(
                    Investigation.local_incident_id == Incident.id,
                    Investigation.investigation_type == "runtime",
                )
            )
            no_falco_alert = not_(
                exists().where(
                    AlertIncidentLink.incident_id == Incident.id,
                    AlertIncidentLink.alert_id == Alert.id,
                    Alert.source == "falco",
                )
            )
            stmt = select(func.count(Incident.id)).where(
                Incident.whitelisted == True, no_runtime_inv, no_falco_alert
            )
            if asset_id:
                stmt = stmt.where(Incident.asset_id == asset_id)
            result = await session.execute(stmt)
            counts["whitelisted_incidents"] = result.scalar_one()
    except Exception as e:
        logger.warning("quick_stats_whitelisted_incidents_failed", error=str(e))

    await _dashboard_cache.set("quick-stats", counts, **cache_kwargs)
    return counts


@router.get("/trends")
async def get_alert_trends(
    range: Optional[str] = Query("24h", description="Time range: 15m | 1h | 24h | 7d"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """Server-side alert trend data for the dashboard chart."""
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    cache_kwargs = {"range": range}
    if asset_id:
        cache_kwargs["asset_id"] = asset_id
    cached = await _dashboard_cache.get("trends", **cache_kwargs)
    if cached is not None:
        return cached

    from response.db import AsyncSessionLocal
    from response.models import Alert

    cutoff = _parse_range(range)
    bucket_format = {
        "15m": "%Y-%m-%d %H:%M",
        "1h": "%Y-%m-%d %H:%M",
        "24h": "%Y-%m-%d %H:00",
        "7d": "%Y-%m-%d",
    }.get(range, "%Y-%m-%d %H:00")

    try:
        async with AsyncSessionLocal() as session:
            # SQLite strftime grouping
            sql = """
                SELECT strftime(:bucket, created_at) as bucket, COUNT(*) as cnt
                FROM alerts
                WHERE created_at >= :cutoff
                AND source != 'falco'
                {asset_clause}
                GROUP BY bucket
                ORDER BY bucket ASC
            """.format(
                asset_clause="AND asset_id = :asset_id" if asset_id else ""
            )
            params = {"bucket": bucket_format, "cutoff": cutoff.isoformat()}
            if asset_id:
                params["asset_id"] = asset_id
            result = await session.execute(text(sql), params)
            rows = result.all()
            result = {
                "range": range,
                "buckets": [{"time": row.bucket, "count": row.cnt} for row in rows],
            }
            await _dashboard_cache.set("trends", result, **cache_kwargs)
            return result
    except Exception as e:
        logger.warning("dashboard_trends_failed", error=str(e))
        return {"range": range, "buckets": []}


@router.get("/source-breakdown")
async def get_source_breakdown(
    range: Optional[str] = Query("24h", description="Time range: 15m | 1h | 24h | 7d"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """Alert counts grouped by source for the selected time range.

    Filebeat-polled alerts are exclusively Suricata eve logs, so their count
    is merged into Suricata. Falco is shown as a regular source.
    """
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    cache_kwargs = {"range": range}
    if asset_id:
        cache_kwargs["asset_id"] = asset_id
    cached = await _dashboard_cache.get("source-breakdown", **cache_kwargs)
    if cached is not None:
        return cached

    from response.db import AsyncSessionLocal
    from response.models import Alert

    cutoff = _parse_range(range)
    sources: Dict[str, int] = {}

    try:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(Alert.source, func.count(Alert.id))
                .where(Alert.created_at >= cutoff)
                .group_by(Alert.source)
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            result_rows = await session.execute(stmt)
            for row in result_rows.all():
                sources[row[0]] = row[1]
    except Exception as e:
        logger.warning("dashboard_source_breakdown_failed", error=str(e))

    # Filebeat-polled alerts are exclusively Suricata eve logs, but stored
    # with source="filebeat" due to a persistence bug. Merge them into suricata.
    filebeat_count = sources.pop("filebeat", 0)
    if filebeat_count:
        sources["suricata"] = sources.get("suricata", 0) + filebeat_count

    # Normalize: ensure known sources are present even if zero
    known_sources = ["wazuh", "suricata", "falco"]
    normalized: list[Dict[str, Any]] = []
    for src in known_sources:
        normalized.append({"source": src, "count": sources.get(src, 0)})
    # Catch any other sources
    other_count = sum(c for s, c in sources.items() if s not in known_sources)
    if other_count > 0:
        normalized.append({"source": "other", "count": other_count})

    result = {
        "range": range,
        "sources": normalized,
        "runtime_excluded": {},
    }
    await _dashboard_cache.set("source-breakdown", result, **cache_kwargs)
    return result


# ── MITRE ATT&CK Coverage ──────────────────────────────────────────────────

@router.get("/mitre-coverage")
async def get_mitre_coverage(
    range: Optional[str] = Query("24h", description="Time range: 15m | 1h | 24h | 7d"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """MITRE ATT&CK tactic/technique coverage from alerts in the selected range.

    Aggregates structured MITRE data from alert_metadata and tags.
    Falco alerts are excluded from SOC coverage counts.
    """
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    cache_kwargs = {"range": range}
    if asset_id:
        cache_kwargs["asset_id"] = asset_id
    cached = await _dashboard_cache.get("mitre-coverage", **cache_kwargs)
    if cached is not None:
        return cached

    from response.db import AsyncSessionLocal
    from response.models import Alert

    cutoff = _parse_range(range)
    tactics: Dict[str, Dict[str, Any]] = {}

    try:
        async with AsyncSessionLocal() as session:
            stmt = select(Alert.alert_metadata, Alert.tags).where(
                Alert.created_at >= cutoff, Alert.source != "falco"
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            result = await session.execute(stmt)
            rows = result.all()

            for metadata_json, tags in rows:
                # --- Collect structured metadata ---
                meta = metadata_json or {}
                meta_tactics = set()
                meta_techniques: Dict[str, Optional[str]] = {}
                for t in (meta.get("mitre_tactics") or []):
                    if t and isinstance(t, str):
                        meta_tactics.add(t.strip())
                meta_ids = meta.get("mitre_ids") or []
                for idx, tech_name in enumerate(meta.get("mitre_techniques") or []):
                    if tech_name and isinstance(tech_name, str):
                        tech_id = meta_ids[idx] if idx < len(meta_ids) else None
                        name = tech_name.strip()
                        # Keep the first ID seen; prefer non-None
                        if name not in meta_techniques or (tech_id and not meta_techniques[name]):
                            meta_techniques[name] = tech_id

                # --- Collect tags fallback ---
                tag_list = tags or []
                tag_tactics = set()
                tag_techniques: Dict[str, Optional[str]] = {}
                tag_ids: list[str] = []
                for tag in tag_list:
                    if not isinstance(tag, str):
                        continue
                    tag_lower = tag.lower()
                    if tag_lower.startswith("mitre-tactic-"):
                        tag_tactics.add(tag.replace("mitre-tactic-", "").strip())
                    elif tag_lower.startswith("mitre-technique-"):
                        name = tag.replace("mitre-technique-", "").strip()
                        tag_techniques[name] = tag_techniques.get(name) or None
                    elif tag_lower.startswith("mitre-t") and len(tag) > 7 and tag[7:8].isdigit():
                        tag_ids.append(tag.replace("mitre-", "").strip())

                for tid in tag_ids:
                    # Map tag IDs to themselves as technique names if no better name exists
                    if tid not in tag_techniques:
                        tag_techniques[tid] = tid

                # --- Deduplicate per alert ---
                all_tactics = meta_tactics | tag_tactics
                all_techniques: Dict[str, Optional[str]] = {}
                # Metadata is higher-confidence; apply first so tags don't
                # overwrite a known ID with None when names collide.
                for name, tid in meta_techniques.items():
                    all_techniques[name] = tid
                for name, tid in tag_techniques.items():
                    if name not in all_techniques or (tid and not all_techniques[name]):
                        all_techniques[name] = tid

                # Attach to primary tactic (first from metadata, then tags, then Uncategorized)
                primary_tactic = next(iter(meta_tactics), None)
                if not primary_tactic:
                    primary_tactic = next(iter(tag_tactics), None)
                attach_tactic = primary_tactic if primary_tactic else "Uncategorized"

                # Increment tactic counts once per unique tactic per alert
                for t in all_tactics:
                    if t not in tactics:
                        tactics[t] = {"count": 0, "techniques": {}}
                    tactics[t]["count"] += 1

                # If no tactics but we have techniques, ensure the Uncategorized bucket exists
                if not all_tactics and all_techniques:
                    if "Uncategorized" not in tactics:
                        tactics["Uncategorized"] = {"count": 0, "techniques": {}}
                    tactics["Uncategorized"]["count"] += 1

                # Increment technique counts once per unique technique per alert
                for name, tid in all_techniques.items():
                    if attach_tactic not in tactics:
                        tactics[attach_tactic] = {"count": 0, "techniques": {}}
                    t_map = tactics[attach_tactic]["techniques"]
                    tech_key = tid or name
                    if tech_key not in t_map:
                        t_map[tech_key] = {
                            "technique_id": tid,
                            "technique": name,
                            "count": 0,
                        }
                    else:
                        # Prefer human-readable names over raw IDs when the key
                        # is an ID shared across alerts (some may only have tags).
                        if tid and t_map[tech_key]["technique"] == tech_key and name != tech_key:
                            t_map[tech_key]["technique"] = name
                    t_map[tech_key]["count"] += 1

    except Exception as e:
        logger.warning("dashboard_mitre_coverage_failed", error=str(e))

    # Sort tactics by count desc, then deduplicate and sort techniques
    sorted_tactics = []
    for tactic_name, data in sorted(tactics.items(), key=lambda x: -x[1]["count"]):
        # Merge techniques with the same name, preferring entries that have a technique_id
        merged: Dict[str, Dict[str, Any]] = {}
        for tech in data["techniques"].values():
            name = tech["technique"]
            if name not in merged:
                merged[name] = dict(tech)
            else:
                merged[name]["count"] += tech["count"]
                if tech["technique_id"] and not merged[name]["technique_id"]:
                    merged[name]["technique_id"] = tech["technique_id"]
        techs = sorted(merged.values(), key=lambda x: -x["count"])
        sorted_tactics.append({
            "tactic": tactic_name,
            "count": data["count"],
            "techniques": techs,
        })

    result = {
        "range": range,
        "tactics": sorted_tactics,
    }
    await _dashboard_cache.set("mitre-coverage", result, **cache_kwargs)
    return result


# ── Response Metrics (MTTD / MTTR) ─────────────────────────────────────────

@router.get("/response-metrics")
async def get_response_metrics(
    range: Optional[str] = Query("24h", description="Time range: 15m | 1h | 24h | 7d"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) for the selected range.

    Definitions:
    - MTTD: average time from first linked alert creation to incident creation.
            Measures detection latency from alert ingestion to incident correlation.
    - MTTR: average time from incident creation to incident resolution.
            Uses Incident.resolved_at when available.
    - Operational MTTR: average time from incident creation to first investigation
      completion (status completed or archived). Captures ARIA workflow resolution
      even when Incident.resolved_at is not explicitly set.
    All metrics exclude Falco/runtime incidents to keep SOC KPIs clean.
    """
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    cache_kwargs = {"range": range}
    if asset_id:
        cache_kwargs["asset_id"] = asset_id
    cached = await _dashboard_cache.get("response-metrics", **cache_kwargs)
    if cached is not None:
        return cached

    from response.db import AsyncSessionLocal
    from response.models import Alert, Incident, Investigation, AlertIncidentLink

    cutoff = _parse_range(range)
    notes: list[str] = []

    mttd_seconds: Optional[float] = None
    mttr_seconds: Optional[float] = None
    mttd_sample = 0
    mttr_sample = 0

    # Subqueries for Falco/runtime exclusion (avoids correlation issues when
    # Alert/AlertIncidentLink are joined in the outer query).
    falco_incident_ids = (
        select(AlertIncidentLink.incident_id)
        .join(Alert, AlertIncidentLink.alert_id == Alert.id)
        .where(Alert.source == "falco")
    ).scalar_subquery()

    runtime_incident_ids = (
        select(Investigation.local_incident_id)
        .where(
            Investigation.investigation_type == "runtime",
            Investigation.local_incident_id.isnot(None),
        )
    ).scalar_subquery()

    try:
        async with AsyncSessionLocal() as session:
            # ── MTTD ──
            stmt = (
                select(
                    Incident.id,
                    Incident.created_at,
                    func.min(Alert.created_at).label("first_alert_at"),
                )
                .join(AlertIncidentLink, Incident.id == AlertIncidentLink.incident_id)
                .join(Alert, AlertIncidentLink.alert_id == Alert.id)
                .where(
                    Incident.created_at >= cutoff,
                    Alert.source != "falco",
                    ~Incident.id.in_(runtime_incident_ids),
                    ~Incident.id.in_(falco_incident_ids),
                )
                .group_by(Incident.id)
            )
            if asset_id:
                stmt = stmt.where(Incident.asset_id == asset_id)
            mttd_rows = await session.execute(stmt)

            mttd_total = 0.0
            for row in mttd_rows.all():
                incident_created = row.created_at
                first_alert = row.first_alert_at
                if first_alert and incident_created:
                    delta = (incident_created - first_alert).total_seconds()
                    if delta >= 0:
                        mttd_total += delta
                        mttd_sample += 1
                    else:
                        # Alert created after incident (possible manual creation); skip
                        pass

            if mttd_sample > 0:
                mttd_seconds = round(mttd_total / mttd_sample, 1)
    except Exception as e:
        logger.warning("dashboard_response_metrics_mttd_failed", error=str(e))

    try:
        async with AsyncSessionLocal() as session:
            # ── MTTR ──
            stmt = (
                select(
                    Incident.created_at,
                    Incident.resolved_at,
                )
                .where(
                    Incident.created_at >= cutoff,
                    Incident.resolved_at.isnot(None),
                    ~Incident.id.in_(runtime_incident_ids),
                    ~Incident.id.in_(falco_incident_ids),
                )
            )
            if asset_id:
                stmt = stmt.where(Incident.asset_id == asset_id)
            mttr_rows = await session.execute(stmt)

            mttr_total = 0.0
            for row in mttr_rows.all():
                created = row.created_at
                resolved = row.resolved_at
                if created and resolved:
                    delta = (resolved - created).total_seconds()
                    if delta >= 0:
                        mttr_total += delta
                        mttr_sample += 1

            if mttr_sample > 0:
                mttr_seconds = round(mttr_total / mttr_sample, 1)
            else:
                notes.append("No resolved incidents in selected range.")
    except Exception as e:
        logger.warning("dashboard_response_metrics_mttr_failed", error=str(e))
        notes.append("Calculation error; metrics unavailable.")

    # ── Operational MTTR (incident → first investigation completion) ──
    operational_mttr_seconds: Optional[float] = None
    operational_mttr_sample = 0
    try:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(
                    Incident.id,
                    Incident.created_at,
                    func.min(Investigation.updated_at).label("first_completed_at"),
                )
                .join(Investigation, Investigation.local_incident_id == Incident.id)
                .where(
                    Incident.created_at >= cutoff,
                    Investigation.status.in_(["completed", "archived"]),
                    Investigation.local_incident_id.isnot(None),
                    ~Incident.id.in_(runtime_incident_ids),
                    ~Incident.id.in_(falco_incident_ids),
                )
                .group_by(Incident.id)
            )
            if asset_id:
                stmt = stmt.where(Incident.asset_id == asset_id, Investigation.asset_id == asset_id)
            op_rows = await session.execute(stmt)

            op_total = 0.0
            for row in op_rows.all():
                created = row.created_at
                completed = row.first_completed_at
                if created and completed:
                    delta = (completed - created).total_seconds()
                    if delta >= 0:
                        op_total += delta
                        operational_mttr_sample += 1

            if operational_mttr_sample > 0:
                operational_mttr_seconds = round(op_total / operational_mttr_sample, 1)
    except Exception as e:
        logger.warning("dashboard_response_metrics_operational_mttr_failed", error=str(e))
        notes.append("Operational MTTR calculation unavailable.")

    result = {
        "range": range,
        "mttd_seconds": mttd_seconds,
        "mttr_seconds": mttr_seconds,
        "operational_mttr_seconds": operational_mttr_seconds,
        "sample_size": {
            "mttd": mttd_sample,
            "mttr": mttr_sample,
            "operational_mttr": operational_mttr_sample,
        },
        "notes": notes,
    }
    await _dashboard_cache.set("response-metrics", result, **cache_kwargs)
    return result


# ── Geographic Threats ─────────────────────────────────────────────────────

@router.get("/geo-threats")
async def get_geo_threats(
    range: Optional[str] = Query("24h", description="Time range: 15m | 1h | 24h | 7d"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """Geographic threat visibility from GeoIP-enriched alerts.

    Uses alert_metadata._geo.source coordinates. Falco/runtime alerts are
    excluded. Invalid coordinates (0,0, out-of-bounds, NaN) and private IPs
    are filtered out and reported as unresolved_count.
    """
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    cache_kwargs = {"range": range}
    if asset_id:
        cache_kwargs["asset_id"] = asset_id
    cached = await _dashboard_cache.get("geo-threats", **cache_kwargs)
    if cached is not None:
        return cached

    from response.db import AsyncSessionLocal
    from response.models import Alert
    from core.geoip import is_private_ip, _is_valid_coords

    cutoff = _parse_range(range)
    points: list[dict] = []
    unresolved_count = 0

    try:
        async with AsyncSessionLocal() as session:
            stmt = select(Alert.alert_metadata, Alert.severity, Alert.source_ip).where(
                Alert.created_at >= cutoff, Alert.source != "falco"
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            result = await session.execute(stmt)
            rows = result.all()

            location_map: Dict[tuple, dict] = {}
            ip_counts: Dict[tuple, Dict[str, int]] = {}

            for metadata_json, severity, src_ip in rows:
                geo = (metadata_json or {}).get("_geo", {})
                source_geo = geo.get("source", {})

                lat = source_geo.get("latitude")
                lon = source_geo.get("longitude")
                country = source_geo.get("country_name") or source_geo.get("country")
                country_code = source_geo.get("country_code")
                city = source_geo.get("city") or ""

                if not _is_valid_coords(lat, lon):
                    unresolved_count += 1
                    continue

                if src_ip and is_private_ip(src_ip):
                    unresolved_count += 1
                    continue

                key = (
                    country_code or "unknown",
                    city,
                    round(float(lat), 4),
                    round(float(lon), 4),
                )

                if key not in location_map:
                    location_map[key] = {
                        "country": country or "Unknown",
                        "country_code": country_code,
                        "city": city,
                        "latitude": float(lat),
                        "longitude": float(lon),
                        "count": 0,
                        "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                        "top_ip": src_ip,
                    }
                    ip_counts[key] = {}

                location_map[key]["count"] += 1
                sev = severity or "low"
                if sev in location_map[key]["severity_breakdown"]:
                    location_map[key]["severity_breakdown"][sev] += 1
                else:
                    location_map[key]["severity_breakdown"]["low"] += 1

                if src_ip:
                    ip_counts[key][src_ip] = ip_counts[key].get(src_ip, 0) + 1
                    current_top = location_map[key]["top_ip"]
                    if current_top is None or ip_counts[key][src_ip] > ip_counts[key].get(current_top, 0):
                        location_map[key]["top_ip"] = src_ip

            points = sorted(location_map.values(), key=lambda x: -x["count"])[:20]

    except Exception as e:
        logger.warning("dashboard_geo_threats_failed", error=str(e))

    result = {
        "range": range,
        "points": points,
        "unresolved_count": unresolved_count,
    }
    await _dashboard_cache.set("geo-threats", result, **cache_kwargs)
    return result

