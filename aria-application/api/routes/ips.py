"""
IPS Attack Visualization API Routes.
Real-time world map showing cyber attack traffic between source and destination IPs.
Includes geoIP resolution, live events, statistics, and filtering.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
import uuid
import asyncio

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from core.geoip import resolve_ip, async_resolve_ip, is_private_ip
from response.db import AsyncSessionLocal
from response.models import Investigation, InvestigationAlert, Alert, Incident, AlertIncidentLink
from config.settings import get_settings
from response.auth import require_auth, CurrentUser

_settings = get_settings()
IPS_DEFAULT_DEST_IP = _settings.ips_default_dest_ip
IPS_HOME_BASE_LAT = _settings.ips_home_base_lat
IPS_HOME_BASE_LON = _settings.ips_home_base_lon
IPS_HOME_BASE_LABEL = _settings.ips_home_base_label

router = APIRouter(prefix="/api/v1/ips", tags=["ips-visualization"])

MAX_EVENTS = 2500
KEEP_MINUTES = 240

_recent_events: List[Dict] = []
_event_stats = {
    "total_attacks": 0,
    "unique_sources": set(),
    "unique_targets": set(),
    "top_countries": {},
    "top_industries": {},
    "top_isps": {},
    "top_targets": {},
    "top_attack_types": {},
    "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "by_category": {},
    "by_protocol": {},
    "last_24h": 0,
}

# Lock for all global mutable state above
_global_state_lock = asyncio.Lock()

# Simple in-memory TTL cache for alert events to avoid hitting OpenSOAR on every request
_alert_cache: List[Dict] = []
_alert_cache_time: Optional[datetime] = None
_ALERT_CACHE_TTL_SECONDS = 60

# Lifecycle cache: alert_id -> (lifecycle, cached_at)
_lifecycle_cache: Dict[str, tuple] = {}
_LIFECYCLE_CACHE_TTL_SECONDS = 15
_LIFECYCLE_PRIORITY = {"blocked": 0, "mitigated": 1, "investigating": 2, "active": 3}


def _trim_counter_dict(d: Dict[str, int], max_size: int = 500) -> None:
    """Keep only the top-N entries by count to prevent unbounded growth."""
    if len(d) > max_size:
        top = sorted(d.items(), key=lambda x: x[1], reverse=True)[:max_size]
        d.clear()
        d.update(top)


def _parse_timestamp(ts: str) -> datetime:
    if not ts:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


def _filter_by_time_range(events: List[Dict], time_range: Optional[int]) -> List[Dict]:
    """Filter events to only those within `time_range` minutes from now."""
    if not time_range:
        return events
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_range)
    return [e for e in events if _parse_timestamp(e.get("timestamp", "")) > cutoff]


def _lifecycle_for_investigation(inv: Investigation) -> str:
    """Determine lifecycle string for a single investigation."""
    status = inv.status
    approval = inv.approval
    run = inv.run
    verification = inv.verification
    fix_status = verification.status if verification else None

    # blocked: approved AND (playbook run completed OR approval decision = approved)
    if status == "approved" and (
        (run and run.status == "completed") or (approval and approval.decision == "approved")
    ):
        return "blocked"

    # mitigated: fix likely_fixed OR archived (resolved and closed) OR (completed AND run completed AND fix != not_fixed)
    if fix_status == "likely_fixed":
        return "mitigated"
    if status == "archived":
        return "mitigated"
    if status == "completed" and run and run.status == "completed" and fix_status != "not_fixed":
        return "mitigated"

    # active: failed OR fix_status in (not_fixed, playbook_failed_but_quiet)
    if status == "failed" or fix_status in ("not_fixed", "playbook_failed_but_quiet"):
        return "active"

    # investigating: pending, approved (pre-execution), awaiting_approval, completed but unverified, run=running, approval declined
    if status in ("pending", "approved"):
        return "investigating"
    if status == "awaiting_approval":
        return "investigating"
    if status == "completed" and not verification:
        return "investigating"
    if run and run.status == "running":
        return "investigating"
    if approval and approval.decision == "declined":
        return "investigating"

    return "active"


async def _get_lifecycle_for_alert(alert_id: str, fallback_ids: Optional[List[str]] = None) -> str:
    """Lookup lifecycle from investigations DB with 15s in-memory cache.

    Tries alert_id first, then any fallback_ids (e.g., external_id for local alerts
    that were forwarded upstream, where InvestigationAlert stores the upstream ID).
    """
    now = datetime.now(timezone.utc)
    cache_key = alert_id
    cached = _lifecycle_cache.get(cache_key)
    if cached:
        lifecycle, cached_at = cached
        if (now - cached_at).total_seconds() < _LIFECYCLE_CACHE_TTL_SECONDS:
            return lifecycle

    lifecycle = "active"
    ids_to_try = [alert_id]
    if fallback_ids:
        ids_to_try.extend([fid for fid in fallback_ids if fid and fid != alert_id])

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Investigation)
                .join(InvestigationAlert, InvestigationAlert.investigation_id == Investigation.id)
                .where(InvestigationAlert.alert_id.in_(ids_to_try))
                .options(
                    selectinload(Investigation.approval),
                    selectinload(Investigation.run),
                    selectinload(Investigation.verification),
                )
            )
            investigations = result.scalars().all()
            best_priority = 99
            for inv in investigations:
                lc = _lifecycle_for_investigation(inv)
                p = _LIFECYCLE_PRIORITY.get(lc, 2)
                if p < best_priority:
                    best_priority = p
                    lifecycle = lc
        _lifecycle_cache[cache_key] = (lifecycle, now)
    except Exception as e:
        import structlog

        logger = structlog.get_logger()
        logger.warning("lifecycle_lookup_failed", alert_id=alert_id, fallback_ids=fallback_ids, error=str(e))

    return lifecycle


def _apply_common_filters(
    events: List[Dict],
    *,
    time_range: Optional[int] = None,
    severity: Optional[str] = None,
    country: Optional[str] = None,
    lifecycle: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    protocol: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> List[Dict]:
    """Apply standard filters to an event list."""
    events = _filter_by_time_range(events, time_range)
    if asset_id:
        events = [e for e in events if e.get("asset_id") == asset_id]
    if severity and severity != "all":
        events = [e for e in events if e.get("severity") == severity]
    if country and country != "all":
        events = [e for e in events if e.get("source", {}).get("country") == country]
    if lifecycle and lifecycle != "all":
        events = [e for e in events if e.get("lifecycle", "active") == lifecycle]
    if category and category != "all":
        events = [e for e in events if e.get("category") == category]
    if source and source != "all":
        events = [e for e in events if e.get("alert_source") == source]
    if protocol and protocol != "all":
        events = [e for e in events if e.get("protocol") == protocol]
    return events


def _alert_to_event(
    alert: dict,
    now: datetime,
    geo_cache: Dict[str, Optional[Dict]],
) -> Optional[Dict]:
    """Convert an alert dict (from upstream or local DB) to an IPS event.

    geo_cache must be provided with pre-resolved geo data to avoid blocking
    the event loop with synchronous resolve_ip() calls.
    """
    source_ip = alert.get("source_ip")
    if not source_ip:
        return None
    if is_private_ip(source_ip):
        return None

    dest_ip = alert.get("dest_ip") or IPS_DEFAULT_DEST_IP

    geo = geo_cache.get(source_ip)
    target_geo = geo_cache.get(dest_ip) if dest_ip else None

    lat = geo.get("latitude") if geo else None
    lon = geo.get("longitude") if geo else None

    # Derive category from real attack classification (not source name)
    # Priority: metadata.category > alert.category > title pattern matching > "unknown"
    metadata = alert.get("metadata") or {}
    category = metadata.get("category") if isinstance(metadata, dict) else None
    if not category:
        category = alert.get("category")

    # Only do title-based pattern matching if the category is missing or too generic
    if not category or category in ("other", "unknown", "system", "network", "informational", "authentication"):
        title = (alert.get("title") or alert.get("rule_name") or "").lower()
        # Brute-force: sustained password attacks
        if any(k in title for k in (
            "multiple failed logins", "brute force", "bruteforce",
            "password guessing", "credential stuffing", "missed the password"
        )):
            category = "brute-force"
        # Web attacks
        elif any(k in title for k in (
            "sql injection", "sqli", "xss", "directory traversal",
            "command injection", "lfi", "rfi", "web shell", "webshell",
            "remote code execution", "rce"
        )):
            category = "web-attack"
        # Reconnaissance / scanning
        elif any(k in title for k in (
            "port scan", "nmap", "scan detected", "reconnaissance",
            "sweep", "network scan"
        )):
            category = "reconnaissance"
        # Malware
        elif any(k in title for k in (
            "malware", "trojan", "virus", "backdoor", "rootkit",
            "coinminer", "mining"
        )):
            category = "malware"
        # DoS
        elif any(k in title for k in (
            "denial of service", "dos", "ddos", "flood"
        )):
            category = "dos"
        # C2 / Botnet
        elif any(k in title for k in (
            "command and control", "c2", "botnet", "beacon", "callback"
        )):
            category = "c2"
        # Privilege escalation
        elif any(k in title for k in (
            "privilege escalation", "privesc", "administrator privilege",
            "root access"
        )):
            category = "privilege-escalation"
        # Exfiltration
        elif any(k in title for k in (
            "exfiltration", "data exfiltration", "data leakage"
        )):
            category = "exfiltration"
        # Threat intel / reputation
        elif any(k in title for k in (
            "threat intel", "blocked threat", "block list", "reputation",
            "known compromised", "threat intelligence"
        )):
            category = "threat-intel"
        # Authentication events (single events, NOT brute-force)
        elif any(k in title for k in (
            "authentication success", "login success", "session opened",
            "session closed", "accepted password", "accepted publickey"
        )):
            category = "authentication"
        # Single auth failures — still suspicious but not confirmed brute-force
        elif any(k in title for k in (
            "login failed", "authentication failure", "invalid user",
            "non-existent user", "authentication failed"
        )):
            category = "brute-force"

    if not category:
        category = "unknown"

    event_id = alert.get("id") or alert.get("external_id") or str(uuid.uuid4())

    # If geo lookup lacks city-level detail, fall back to .env configured home base.
    _geo_has_city = bool(target_geo and target_geo.get("city"))
    _dest_lat = target_geo.get("latitude") if _geo_has_city else IPS_HOME_BASE_LAT
    _dest_lon = target_geo.get("longitude") if _geo_has_city else IPS_HOME_BASE_LON
    _dest_city = target_geo.get("city", "") if _geo_has_city else ""
    _dest_region = target_geo.get("region", "") if _geo_has_city else ""

    return {
        "event_id": event_id,
        "timestamp": alert.get("created_at") or alert.get("timestamp") or now.isoformat(),
        "alert_source": (alert.get("source") or "").lower(),
        "asset_id": alert.get("asset_id"),
        "source": {
            "ip": source_ip,
            "port": alert.get("source_port") or alert.get("dest_port") or 0,
            "country": geo.get("country_code", "XX") if geo else "XX",
            "country_name": geo.get("country_name", "Unknown") if geo else "Unknown",
            "city": geo.get("city", "") if geo else "",
            "region": geo.get("region", "") if geo else "",
            "isp": geo.get("isp", "") if geo else "",
            "asn": geo.get("asn", "") if geo else "",
            "lat": lat,
            "lon": lon,
            "org": geo.get("org", "") if geo else "",
        },
        "destination": {
            "ip": dest_ip,
            "port": alert.get("dest_port") or 0,
            "country": target_geo.get("country_code", "XX") if target_geo else "XX",
            "country_name": target_geo.get("country_name", "Unknown") if target_geo else "Unknown",
            "city": _dest_city,
            "region": _dest_region,
            "lat": _dest_lat,
            "lon": _dest_lon,
        },
        "severity": alert.get("severity", "medium"),
        "alert_name": alert.get("title") or alert.get("rule_name") or "Unknown",
        "category": category,
        "protocol": alert.get("protocol") or "TCP",
        "signature_id": alert.get("signature_id") or "",
        "lifecycle": "active",
    }


async def _get_upstream_events(limit: int) -> List[Dict]:
    """Try to fetch events from upstream OpenSOAR."""
    from core.geoip import async_resolve_ips

    events = []
    try:
        from pipeline.sender import client
        await client.authenticate()
        alerts_resp = await client.list_alerts(limit=limit)
        alerts = alerts_resp.get("alerts", [])

        # Batch-resolve all unique IPs in parallel
        ips_to_resolve: set = set()
        for alert in alerts:
            sip = alert.get("source_ip")
            if sip:
                ips_to_resolve.add(sip)
            dip = alert.get("dest_ip")
            if dip:
                ips_to_resolve.add(dip)
        if ips_to_resolve:
            await async_resolve_ips(list(ips_to_resolve))

        # Build geo cache from resolved IPs
        from core.geoip import _ip_cache
        geo_cache = {ip: _ip_cache.get(ip) for ip in ips_to_resolve}

        now = datetime.now(timezone.utc)
        for alert in alerts:
            ev = _alert_to_event(alert, now, geo_cache=geo_cache)
            if ev:
                ev["lifecycle"] = await _get_lifecycle_for_alert(ev["event_id"])
                events.append(ev)
    except Exception as e:
        import structlog
        logger = structlog.get_logger()
        logger.warning("ips_upstream_fetch_failed", error=str(e))
    return events


async def _get_local_events(limit: int) -> List[Dict]:
    """Fetch events from local SQLite alerts, ensuring all sources are represented.

    Instead of fetching the N most recent overall (which can drown old Suricata
    alerts under a flood of Wazuh events), we fetch up to limit/2 from each
    source and merge them.

    Performance: collects all unique IPs first, then resolves them in parallel
    (async batch) rather than one-by-one synchronously.
    """
    from core.geoip import async_resolve_ips

    events: List[Dict] = []
    per_source_limit = max(limit // 2, 50)
    raw_alerts: List[tuple] = []  # (alert_dict, alert_id, alert_external_id)

    try:
        async with AsyncSessionLocal() as session:
            now = datetime.now(timezone.utc)
            # Single query instead of N+1 per source
            result = await session.execute(
                select(Alert)
                .where(Alert.source_ip.isnot(None))
                .order_by(Alert.created_at.desc())
                .limit(limit * 2)
            )
            alerts = result.scalars().all()

            seen_ids: set = set()
            source_counts: Dict[str, int] = {}
            for alert in alerts:
                alert_key = alert.external_id or alert.id
                if alert_key in seen_ids:
                    continue
                src = alert.source or "unknown"
                if source_counts.get(src, 0) >= per_source_limit:
                    continue
                source_counts[src] = source_counts.get(src, 0) + 1
                seen_ids.add(alert_key)

                meta = alert.alert_metadata or {}
                if not isinstance(meta, dict):
                    meta = {}

                alert_dict = {
                    "id": alert.external_id or alert.id,
                    "external_id": alert.external_id,
                    "source_ip": alert.source_ip,
                    "dest_ip": alert.dest_ip or IPS_DEFAULT_DEST_IP,
                    "source_port": meta.get("src_port") or meta.get("source_port"),
                    "dest_port": meta.get("dst_port") or meta.get("dest_port"),
                    "created_at": alert.created_at.isoformat() if alert.created_at else None,
                    "severity": alert.severity,
                    "title": alert.title,
                    "rule_name": alert.rule_name,
                    "source": alert.source,
                    "protocol": meta.get("protocol") or meta.get("proto"),
                    "signature_id": meta.get("signature_id") or meta.get("sid"),
                    "category": meta.get("category"),
                    "metadata": meta,
                    "asset_id": alert.asset_id,
                    # Phase 3: pre-computed geo from ingestion
                    "_source_geo": meta.get("_geo", {}).get("source") if "_geo" in meta else None,
                    "_dest_geo": meta.get("_geo", {}).get("dest") if "_geo" in meta else None,
                }
                raw_alerts.append((alert_dict, alert.id, alert.external_id))
    except Exception as e:
        import structlog
        logger = structlog.get_logger()
        logger.warning("ips_local_fetch_failed", error=str(e))
        return events

    # ── Batch geo-resolution (Phase 2) ──────────────────────────────────────
    # Collect IPs that are NOT already pre-computed in alert_metadata
    ips_to_resolve: set = set()
    for alert_dict, _aid, _eid in raw_alerts:
        if not alert_dict.get("_source_geo"):
            ips_to_resolve.add(alert_dict["source_ip"])
        if alert_dict.get("dest_ip") and not alert_dict.get("_dest_geo"):
            ips_to_resolve.add(alert_dict["dest_ip"])

    if ips_to_resolve:
        await async_resolve_ips(list(ips_to_resolve))

    # Build geo cache from pre-computed + resolved data
    from core.geoip import _ip_cache as _global_ip_cache
    geo_cache: Dict[str, Optional[Dict]] = {}
    for alert_dict, _aid, _eid in raw_alerts:
        src_ip = alert_dict["source_ip"]
        dst_ip = alert_dict.get("dest_ip")
        if alert_dict.get("_source_geo"):
            geo_cache[src_ip] = alert_dict["_source_geo"]
        else:
            geo_cache[src_ip] = geo_cache.get(src_ip) if src_ip in geo_cache else None
            if geo_cache[src_ip] is None:
                geo_cache[src_ip] = _global_ip_cache.get(src_ip)
        if dst_ip:
            if alert_dict.get("_dest_geo"):
                geo_cache[dst_ip] = alert_dict["_dest_geo"]
            else:
                geo_cache[dst_ip] = geo_cache.get(dst_ip) if dst_ip in geo_cache else None
                if geo_cache[dst_ip] is None:
                    geo_cache[dst_ip] = _global_ip_cache.get(dst_ip)

    # ── Build events with pre-resolved geo ──────────────────────────────────
    now = datetime.now(timezone.utc)
    for alert_dict, alert_id, alert_external_id in raw_alerts:
        ev = _alert_to_event(alert_dict, now, geo_cache=geo_cache)
        if ev:
            fallback_ids = [alert_id]
            if alert_external_id and alert_external_id != ev["event_id"]:
                fallback_ids.insert(0, alert_external_id)
            ev["lifecycle"] = await _get_lifecycle_for_alert(ev["event_id"], fallback_ids=fallback_ids)
            events.append(ev)

    events.sort(key=lambda x: _parse_timestamp(x.get("timestamp", "")), reverse=True)
    return events[:limit]


_alert_fetch_lock = asyncio.Lock()

async def _get_alerts_as_events(limit: int = 200) -> List[Dict]:
    """Fetch alerts from OpenSOAR upstream AND local SQLite, merge and deduplicate.

    Upstream provides recent alerts but strips metadata/category. Local SQLite
    preserves the full mapper metadata. We merge both so old/local-only alerts
    (e.g., historical Suricata) still appear, and upstream alerts get enriched
    with local metadata when available.
    """
    global _alert_cache, _alert_cache_time
    now = datetime.now(timezone.utc)
    if _alert_cache_time is not None and (now - _alert_cache_time).total_seconds() < _ALERT_CACHE_TTL_SECONDS:
        return _alert_cache[:limit]

    async with _alert_fetch_lock:
        if _alert_cache_time is not None and (datetime.now(timezone.utc) - _alert_cache_time).total_seconds() < _ALERT_CACHE_TTL_SECONDS:
            return _alert_cache[:limit]

        settings = get_settings()
        upstream_events = await _get_upstream_events(limit) if settings.upstream_enabled else []
        local_events = await _get_local_events(limit)

        # Merge: upstream IDs take precedence, but local-only alerts are included.
        # Also enrich upstream events with local metadata (category, protocol, etc.)
        merged: Dict[str, Dict] = {}

        # Index local events by ID for fast lookup
        local_by_id: Dict[str, Dict] = {}
        for ev in local_events:
            eid = ev.get("event_id")
            if eid:
                local_by_id[eid] = ev

        for ev in upstream_events:
            eid = ev.get("event_id")
            if eid and eid not in merged:
                local_ev = local_by_id.get(eid)
                if local_ev:
                    # Enrich upstream event with local metadata, but only override
                    # the category if the local category is specific (not generic).
                    local_cat = local_ev.get("category")
                    upstream_cat = ev.get("category")
                    generic_cats = {"other", "unknown", "system", "network", "informational", "authentication"}
                    if local_cat and local_cat not in generic_cats:
                        ev["category"] = local_cat
                    elif not upstream_cat or upstream_cat in generic_cats:
                        ev["category"] = local_cat or upstream_cat

                    ev["protocol"] = local_ev.get("protocol") or ev.get("protocol")
                    ev["signature_id"] = local_ev.get("signature_id") or ev.get("signature_id")
                    if local_ev.get("source", {}).get("port"):
                        ev.setdefault("source", {})["port"] = local_ev["source"]["port"]
                    if local_ev.get("destination", {}).get("port"):
                        ev.setdefault("destination", {})["port"] = local_ev["destination"]["port"]
                merged[eid] = ev

        for ev in local_events:
            eid = ev.get("event_id")
            if eid and eid not in merged:
                merged[eid] = ev

        events = sorted(merged.values(), key=lambda x: _parse_timestamp(x.get("timestamp", "")), reverse=True)
        _alert_cache = events
        _alert_cache_time = datetime.now(timezone.utc)
        return events


async def _get_all_events(limit: int = 200) -> List[Dict]:
    """Combine manually posted events with real alerts from OpenSOAR."""
    global _recent_events
    alert_events = await _get_alerts_as_events(limit=limit)

    async with _global_state_lock:
        # Prune stale manual events
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=KEEP_MINUTES)
        _recent_events = [e for e in _recent_events if _parse_timestamp(e.get("timestamp", "")) > cutoff]

        # Use event_id as key to deduplicate
        seen = {e.get("event_id"): e for e in _recent_events}
        for e in alert_events:
            if e.get("event_id") not in seen:
                seen[e.get("event_id")] = e
        # Sort by timestamp descending
        all_events = sorted(seen.values(), key=lambda x: _parse_timestamp(x.get("timestamp", "")), reverse=True)
        return all_events[:MAX_EVENTS]


@router.post("/event")
async def receive_attack_event(event: Dict) -> Dict:
    """
    Receive attack event from Suricata or other source.
    Enriches with geoIP data and stores for visualization.
    """
    global _recent_events, _event_stats

    source_ip = event.get("source_ip", "")
    dest_ip = event.get("dest_ip", "")
    src_port = event.get("src_port") or event.get("source_port", 0)
    dst_port = event.get("dst_port") or event.get("dest_port", 0)
    protocol = event.get("protocol", "TCP")
    alert_name = event.get("alert_name", event.get("signature", "Unknown"))
    severity = event.get("severity", "medium")
    category = event.get("category", event.get("classification", "Unknown"))
    signature_id = event.get("signature_id", "")
    timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())

    if not source_ip or is_private_ip(source_ip):
        return {"status": "ignored", "reason": "private_ip"}

    geo = await async_resolve_ip(source_ip)
    target_geo = await async_resolve_ip(dest_ip) if dest_ip else None

    lat = geo.get("latitude") if geo else None
    lon = geo.get("longitude") if geo else None

    event_id = str(uuid.uuid4())

    enriched_event = {
        "event_id": event_id,
        "timestamp": timestamp,
        "alert_source": (event.get("source") or "").lower(),
        "source": {
            "ip": source_ip,
            "port": src_port,
            "country": geo.get("country_code", "XX") if geo else "XX",
            "country_name": geo.get("country_name", "Unknown") if geo else "Unknown",
            "city": geo.get("city", "") if geo else "",
            "region": geo.get("region", "") if geo else "",
            "isp": geo.get("isp", "") if geo else "",
            "asn": geo.get("asn", "") if geo else "",
            "lat": lat,
            "lon": lon,
            "org": geo.get("org", "") if geo else "",
        },
        "destination": {
            "ip": dest_ip,
            "port": dst_port,
            "country": target_geo.get("country_code", "XX") if target_geo else "XX",
            "country_name": target_geo.get("country_name", "Unknown") if target_geo else "Unknown",
            "city": target_geo.get("city", "") if target_geo else "",
            "lat": target_geo.get("latitude") if target_geo else None,
            "lon": target_geo.get("longitude") if target_geo else None,
        },
        "severity": severity,
        "alert_name": alert_name,
        "category": category,
        "protocol": protocol,
        "signature_id": signature_id,
        "lifecycle": "active",
        "raw": event,
    }

    async with _global_state_lock:
        _recent_events.insert(0, enriched_event)
        _recent_events = _recent_events[:MAX_EVENTS]

        _event_stats["total_attacks"] += 1
        _event_stats["unique_sources"].add(source_ip)
        if dest_ip:
            _event_stats["unique_targets"].add(dest_ip)

        country = geo.get("country_code", "XX") if geo else "XX"
        _event_stats["top_countries"][country] = _event_stats["top_countries"].get(country, 0) + 1

        isp = geo.get("isp", "Unknown") if geo else "Unknown"
        _event_stats["top_isps"][isp] = _event_stats["top_isps"].get(isp, 0) + 1

        _event_stats["by_severity"][severity] = _event_stats["by_severity"].get(severity, 0) + 1
        _event_stats["by_category"][category] = _event_stats["by_category"].get(category, 0) + 1
        _event_stats["by_protocol"][protocol] = _event_stats["by_protocol"].get(protocol, 0) + 1

        _trim_counter_dict(_event_stats["top_countries"])
        _trim_counter_dict(_event_stats["top_isps"])
        _trim_counter_dict(_event_stats["by_category"])
        _trim_counter_dict(_event_stats["by_protocol"])

    return {"status": "stored", "event_id": event_id}


@router.post("/events/bulk")
async def receive_bulk_events(events: List[Dict]) -> Dict:
    """Receive multiple attack events at once."""
    if len(events) > 1000:
        raise HTTPException(status_code=400, detail="Max 1000 events per batch")
    stored = 0
    for event in events:
        result = await receive_attack_event(event)
        if result.get("status") == "stored":
            stored += 1
    return {"status": "stored", "events_count": stored}


@router.delete("/events")
async def clear_events() -> Dict:
    """Clear all stored events (admin)."""
    global _recent_events, _event_stats

    async with _global_state_lock:
        _recent_events = []
        _event_stats = {
            "total_attacks": 0,
            "unique_sources": set(),
            "unique_targets": set(),
            "top_countries": {},
            "top_industries": {},
            "top_isps": {},
            "top_targets": {},
            "top_attack_types": {},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_category": {},
            "by_protocol": {},
            "last_24h": 0,
        }
    return {"status": "cleared"}


@router.get("/map-data")
async def get_map_data(
    limit: int = Query(200, le=500),
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source (wazuh, suricata, falco)"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict:
    """Get attack data for world map visualization with animated paths."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source, protocol=protocol, asset_id=asset_id,
    )
    events = events[:limit]

    paths = []
    for e in events:
        src = e.get("source", {})
        dst = e.get("destination", {})
        lat = src.get("lat")
        lon = src.get("lon")
        # Only create paths for events with valid source coordinates
        if lat is not None and lon is not None:
            paths.append(
                {
                    "id": e.get("event_id"),
                    "from": {
                        "lat": lat,
                        "lon": lon,
                        "city": src.get("city", ""),
                        "region": src.get("region", ""),
                        "country": src.get("country_name", ""),
                    },
                    "to": {
                        "lat": dst.get("lat") if dst.get("lat") is not None else IPS_HOME_BASE_LAT,
                        "lon": dst.get("lon") if dst.get("lon") is not None else IPS_HOME_BASE_LON,
                        "city": dst.get("city") or IPS_HOME_BASE_LABEL,
                        "region": dst.get("region", ""),
                        "country": dst.get("country_name") or "Tunisia",
                    },
                    "severity": e.get("severity"),
                    "timestamp": e.get("timestamp"),
                    "lifecycle": e.get("lifecycle", "active"),
                }
            )

    return {
        "attacks": events,
        "paths": paths,
        "count": len(events),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/events")
async def get_events(
    limit: int = Query(20, le=100),
    offset: int = Query(0, ge=0),
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = None,
    country: Optional[str] = None,
    protocol: Optional[str] = None,
    category: Optional[str] = None,
    lifecycle: Optional[str] = None,
    source: Optional[str] = Query(None, description="Filter by alert source"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict:
    """Get paginated attack events table."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source, protocol=protocol, asset_id=asset_id,
    )
    total = len(events)
    paginated = events[offset : offset + limit]
    return {"events": paginated, "total": total, "limit": limit, "offset": offset}


@router.get("/events/live")
async def get_live_events(
    limit: int = Query(100, le=500),
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = None,
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict:
    """Get live events for real-time table display."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source, protocol=protocol, asset_id=asset_id,
    )
    total_before_limit = len(events)
    events = events[:limit]

    live_data = []
    for e in events:
        src = e.get("source", {})
        dst = e.get("destination", {})
        live_data.append(
            {
                "event_id": e.get("event_id"),
                "timestamp": e.get("timestamp"),
                "alert_source": e.get("alert_source", ""),
                "source_ip": src.get("ip"),
                "source_city": src.get("city", ""),
                "source_country": src.get("country_name", ""),
                "source_country_code": src.get("country"),
                "dest_ip": dst.get("ip"),
                "dest_city": dst.get("city", ""),
                "dest_country": dst.get("country_name", "Tunisia"),
                "severity": e.get("severity"),
                "alert_name": e.get("alert_name"),
                "category": e.get("category"),
                "protocol": e.get("protocol"),
                "lifecycle": e.get("lifecycle", "active"),
            }
        )

    return {
        "events": live_data,
        "count": len(live_data),
        "total": total_before_limit,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/statistics")
async def get_statistics(
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict:
    """Get comprehensive attack statistics from all events."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source, protocol=protocol,
        asset_id=asset_id,
    )

    total = len(events)
    unique_sources = set()
    unique_targets = set()
    top_countries = {}
    country_names = {}
    top_isps = {}
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_category = {}
    by_protocol = {}
    by_lifecycle = {}
    for e in events:
        src = e.get("source", {})
        dst = e.get("destination", {})
        ip = src.get("ip")
        if ip:
            unique_sources.add(ip)
        target_ip = dst.get("ip")
        if target_ip:
            unique_targets.add(target_ip)
        cc = src.get("country", "XX")
        top_countries[cc] = top_countries.get(cc, 0) + 1
        if cc not in country_names:
            country_names[cc] = src.get("country_name", cc)
        isp = src.get("isp", "Unknown")
        top_isps[isp] = top_isps.get(isp, 0) + 1
        sev = e.get("severity", "medium").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = e.get("category", "Unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
        prot = e.get("protocol", "TCP")
        by_protocol[prot] = by_protocol.get(prot, 0) + 1
        lc = e.get("lifecycle", "active")
        by_lifecycle[lc] = by_lifecycle.get(lc, 0) + 1

    top_countries_list = sorted(
        [{"code": k, "count": v, "name": country_names.get(k, k)} for k, v in top_countries.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:15]
    top_isps_list = sorted(
        [{"isp": k, "count": v} for k, v in top_isps.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]
    top_categories_list = sorted(
        [{"category": k, "count": v} for k, v in by_category.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]
    top_protocols_list = sorted(
        [{"protocol": k, "count": v} for k, v in by_protocol.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:5]
    by_lifecycle_list = sorted(
        [{"lifecycle": k, "count": v} for k, v in by_lifecycle.items()],
        key=lambda x: x["count"],
        reverse=True,
    )

    # Top sources by IP (more useful when geoIP returns Unknown)
    top_sources_map = {}
    top_sources_meta = {}
    for e in events:
        ip = e.get("source", {}).get("ip")
        if ip:
            top_sources_map[ip] = top_sources_map.get(ip, 0) + 1
            if ip not in top_sources_meta:
                src = e.get("source", {})
                top_sources_meta[ip] = {
                    "country": src.get("country", "XX"),
                    "country_name": src.get("country_name", "Unknown"),
                    "lifecycle": e.get("lifecycle", "active"),
                }
    top_sources_list = sorted(
        [{"ip": k, "count": v, **top_sources_meta.get(k, {})} for k, v in top_sources_map.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    # Compute last_24h from the already-fetched events (not restricted by other filters)
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    last_24h = sum(1 for e in events if _parse_timestamp(e.get("timestamp", "")) > cutoff_24h)

    return {
        "total_attacks": total,
        "unique_sources": len(unique_sources),
        "unique_targets": len(unique_targets),
        "active_events": sum(1 for e in events if e.get("lifecycle", "active") == "active"),
        "by_severity": by_severity,
        "by_category": top_categories_list,
        "by_protocol": top_protocols_list,
        "by_lifecycle": by_lifecycle_list,
        "top_countries": top_countries_list,
        "top_isps": top_isps_list,
        "top_sources": top_sources_list,
        "last_24h": last_24h,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/statistics/industries")
async def get_industry_stats(
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict:
    """Get attack statistics by target industry."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source, asset_id=asset_id,
    )
    total = len(events)
    industries_map = {}
    for e in events:
        ind = e.get("category", "Unknown")
        industries_map[ind] = industries_map.get(ind, 0) + 1
    industries = []
    for industry, count in industries_map.items():
        industries.append(
            {
                "industry": industry,
                "count": count,
                "percentage": round(count / total * 100, 1) if total > 0 else 0,
            }
        )
    industries.sort(key=lambda x: x["count"], reverse=True)
    return {"industries": industries, "total": total}


@router.get("/statistics/targets")
async def get_target_stats(
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict:
    """Get most targeted hosts/IPs."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source, asset_id=asset_id,
    )
    total = len(events)
    targets_map = {}
    for e in events:
        ip = e.get("destination", {}).get("ip")
        if ip:
            targets_map[ip] = targets_map.get(ip, 0) + 1
    targets = []
    for ip, count in targets_map.items():
        targets.append(
            {
                "ip": ip,
                "count": count,
                "percentage": round(count / total * 100, 1) if total > 0 else 0,
            }
        )
    targets.sort(key=lambda x: x["count"], reverse=True)
    return {"targets": targets, "total": total}


@router.get("/statistics/attack-types")
async def get_attack_type_stats(
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict:
    """Get most common attack types."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source, asset_id=asset_id,
    )
    total = len(events)
    attack_map = {}
    for e in events:
        atype = e.get("alert_name") or "Unknown"
        attack_map[atype] = attack_map.get(atype, 0) + 1
    attacks = []
    for attack_type, count in attack_map.items():
        attacks.append({"type": attack_type, "count": count})
    attacks.sort(key=lambda x: x["count"], reverse=True)
    return {"attack_types": attacks, "total": total}


@router.get("/countries")
async def get_country_breakdown(
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
) -> Dict:
    """Get attack count by country with details."""
    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source,
    )
    total = len(events)
    country_map = {}
    for e in events:
        src = e.get("source", {})
        code = src.get("country", "XX")
        country_map[code] = country_map.get(code, 0) + 1
    countries = []
    name_map = {}
    for e in events:
        src = e.get("source", {})
        code = src.get("country", "XX")
        if code not in name_map:
            name_map[code] = src.get("country_name", code)
    for code, count in country_map.items():
        countries.append(
            {
                "code": code,
                "name": name_map.get(code, code),
                "count": count,
                "percentage": round(count / total * 100, 1) if total > 0 else 0,
            }
        )
    countries.sort(key=lambda x: x["count"], reverse=True)
    return {"countries": countries, "total": total}


@router.get("/filters")
async def get_available_filters(
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict:
    """Get available filter options."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source, protocol=protocol,
        asset_id=asset_id,
    )
    severities = sorted(set(e.get("severity", "medium") for e in events))
    categories = sorted(set(e.get("category", "Unknown") for e in events))
    protocols = sorted(set(e.get("protocol", "TCP") for e in events))
    countries = sorted(set(e.get("source", {}).get("country", "XX") for e in events))
    sources = sorted(set(e.get("alert_source", "") for e in events if e.get("alert_source")))
    return {
        "severities": severities,
        "categories": categories,
        "protocols": protocols,
        "countries": countries,
        "sources": sources,
    }


@router.get("/status")
async def health_check(
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
) -> Dict:
    """Health check."""
    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source,
    )
    unique_sources = set(e.get("source", {}).get("ip") for e in events)
    return {
        "status": "healthy",
        "events_stored": len(events),
        "unique_sources": len(unique_sources),
        "total_processed": len(events),
    }


@router.get("/status/detailed")
async def detailed_health(
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
) -> Dict:
    """Detailed health with all stats."""
    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source,
    )
    unique_sources = set(e.get("source", {}).get("ip") for e in events)
    unique_targets = set(e.get("destination", {}).get("ip") for e in events)
    by_severity = {}
    by_category = {}
    for e in events:
        sev = e.get("severity", "medium")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = e.get("category", "Unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
    return {
        "status": "healthy",
        "events": {
            "stored": len(events),
            "max_events": MAX_EVENTS,
            "retention_minutes": KEEP_MINUTES,
        },
        "statistics": {
            "total": len(events),
            "unique_sources": len(unique_sources),
            "unique_targets": len(unique_targets),
            "by_severity": by_severity,
            "by_category": by_category,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/summary")
async def get_summary(
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict:
    """Quick summary for sidebar widgets."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source, protocol=protocol,
        asset_id=asset_id,
    )

    unique_sources = set(e.get("source", {}).get("ip") for e in events)
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for e in events:
        sev = e.get("severity", "medium").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
    active_count = sum(1 for e in events if e.get("lifecycle", "active") == "active")
    return {
        "total": len(events),
        "active": active_count,
        "unique_sources": len(unique_sources),
        "critical": by_severity.get("critical", 0),
        "high": by_severity.get("high", 0),
        "medium": by_severity.get("medium", 0),
        "low": by_severity.get("low", 0),
    }


@router.get("/health")
async def ips_health(
    time_range: Optional[int] = Query(None, description="Minutes of history"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    country: Optional[str] = Query(None, description="Filter by source country code"),
    lifecycle: Optional[str] = Query(None, description="Filter by lifecycle"),
    category: Optional[str] = Query(None, description="Filter by category"),
    source: Optional[str] = Query(None, description="Filter by alert source"),
) -> Dict:
    """Health check (alias)."""
    events = await _get_all_events(limit=MAX_EVENTS)
    events = _apply_common_filters(
        events, time_range=time_range, severity=severity, country=country,
        lifecycle=lifecycle, category=category, source=source,
    )
    unique_sources = set(e.get("source", {}).get("ip") for e in events)
    return {
        "status": "healthy",
        "events_stored": len(events),
        "unique_sources": len(unique_sources),
    }


@router.get("/events/{event_id}/related")
async def get_event_related(event_id: str) -> Dict:
    """Find incident and investigation IDs related to an alert/event."""
    incident_id = None
    investigation_id = None
    try:
        async with AsyncSessionLocal() as session:
            # Try to find the local alert by external_id
            alert_result = await session.execute(
                select(Alert.id).where(Alert.external_id == event_id)
            )
            alert_row = alert_result.scalar_one_or_none()
            if not alert_row:
                # Fallback: try by primary id
                alert_result = await session.execute(
                    select(Alert.id).where(Alert.id == event_id)
                )
                alert_row = alert_result.scalar_one_or_none()

            if alert_row:
                # Check AlertIncidentLink
                link_result = await session.execute(
                    select(AlertIncidentLink.incident_id).where(
                        AlertIncidentLink.alert_id == alert_row
                    ).limit(1)
                )
                incident_id = link_result.scalar_one_or_none()

                # Check InvestigationAlert
                inv_result = await session.execute(
                    select(InvestigationAlert.investigation_id).where(
                        InvestigationAlert.alert_id == alert_row
                    ).limit(1)
                )
                investigation_id = inv_result.scalar_one_or_none()
    except Exception as e:
        import structlog
        structlog.get_logger().warning("ips_event_related_failed", event_id=event_id, error=str(e))

    return {
        "event_id": event_id,
        "incident_id": incident_id,
        "investigation_id": investigation_id,
        "has_incident": bool(incident_id),
        "has_investigation": bool(investigation_id),
    }


@router.get("/event/{event_id}/links")
async def get_event_links(event_id: str) -> Dict:
    """Find related alert, incident, and investigation IDs for an IPS event."""
    result: Dict[str, Any] = {"event_id": event_id, "alert_id": None, "incident_id": None, "investigation_id": None}
    try:
        async with AsyncSessionLocal() as session:
            # Try to find local alert by external_id
            alert_result = await session.execute(
                select(Alert).where(Alert.external_id == event_id).limit(1)
            )
            alert = alert_result.scalar_one_or_none()
            if not alert:
                alert_result = await session.execute(
                    select(Alert).where(Alert.id == event_id).limit(1)
                )
                alert = alert_result.scalar_one_or_none()
            if alert:
                result["alert_id"] = alert.id
                # Find incident via AlertIncidentLink
                link_result = await session.execute(
                    select(AlertIncidentLink).where(AlertIncidentLink.alert_id == alert.id).limit(1)
                )
                link = link_result.scalar_one_or_none()
                if link:
                    result["incident_id"] = link.incident_id
                # Find investigation via InvestigationAlert
                inv_result = await session.execute(
                    select(InvestigationAlert).where(InvestigationAlert.alert_id == alert.id).limit(1)
                )
                inv = inv_result.scalar_one_or_none()
                if inv:
                    result["investigation_id"] = inv.investigation_id
    except Exception as e:
        import structlog
        structlog.get_logger().warning("ips_event_links_failed", event_id=event_id, error=str(e))
    return result


# Put specific routes BEFORE the wildcard {event_id} route
@router.get("/{event_id}")
async def get_event(event_id: str) -> Dict:
    """Get single event detail with full info."""
    if event_id in [
        "map-data",
        "events",
        "events/live",
        "statistics",
        "statistics/industries",
        "statistics/targets",
        "statistics/attack-types",
        "countries",
        "filters",
        "status",
        "status/detailed",
        "summary",
    ]:
        raise HTTPException(status_code=404, detail="Event not found")
    events = await _get_all_events(limit=MAX_EVENTS)
    event_map = {e.get("event_id"): e for e in events if e.get("event_id")}
    if event_id in event_map:
        return event_map[event_id]
    raise HTTPException(status_code=404, detail="Event not found")
