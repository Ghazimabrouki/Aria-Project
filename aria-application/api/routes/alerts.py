"""
Alert API with full relationship support.
Hybrid mode: reads from local shadow store + falls back to upstream OpenSOAR.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import select, func, or_, Text
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import get_session
from response.models import Alert, Incident, AlertIncidentLink
from response.auth import require_auth, CurrentUser

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


async def _get_upstream_alerts(limit: int = 200, **filters) -> tuple[list, int]:
    """Fetch alerts from upstream OpenSOAR as fallback."""
    from config import get_settings
    settings = get_settings()
    if not settings.upstream_enabled:
        return [], 0
    from pipeline.sender import client
    try:
        alerts = await client.list_alerts(limit=limit, **filters)
        alert_list = alerts.get("alerts", [])
        total = alerts.get("total", len(alert_list))
        return alert_list, total
    except Exception:
        return [], 0


def _alert_to_dict(alert: Alert) -> Dict[str, Any]:
    return {
        "id": alert.id,
        "external_id": alert.external_id,
        "source": alert.source,
        "source_id": alert.source_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "category": alert.category,
        "source_ip": alert.source_ip,
        "dest_ip": alert.dest_ip,
        "hostname": alert.hostname,
        "rule_name": alert.rule_name,
        "tags": alert.tags,
        "iocs": alert.iocs,
        "observables": alert.observables,
        "metadata": alert.alert_metadata,
        "event_time": alert.event_time.isoformat() if alert.event_time else None,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
        "archived_at": alert.archived_at.isoformat() if alert.archived_at else None,
        "whitelisted": alert.whitelisted,
    }


@router.get("/{alert_id}")
async def get_alert(alert_id: str, session: AsyncSession = Depends(get_session)):
    """Get alert from local DB or upstream OpenSOAR. Returns frontend-compatible format."""
    # Try local first
    result = await session.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        result = await session.execute(select(Alert).where(Alert.external_id == alert_id))
        alert = result.scalar_one_or_none()

    if alert:
        # Build relationships for local alert
        incident_result = await session.execute(
            select(Incident)
            .join(AlertIncidentLink, Incident.id == AlertIncidentLink.incident_id)
            .where(AlertIncidentLink.alert_id == alert.id)
            .limit(20)
        )
        incidents = incident_result.scalars().all()

        # Similar alerts
        similar = []
        if alert.source_ip or alert.rule_name:
            filters = []
            if alert.source_ip:
                filters.append(Alert.source_ip == alert.source_ip)
            if alert.rule_name:
                filters.append(Alert.rule_name == alert.rule_name)
            if filters:
                if len(filters) == 1:
                    stmt = select(Alert).where(Alert.id != alert.id, filters[0])
                else:
                    stmt = select(Alert).where(Alert.id != alert.id, or_(*filters))
                stmt = stmt.order_by(Alert.created_at.desc()).limit(10)
                similar_result = await session.execute(stmt)
                similar = similar_result.scalars().all()

        return {
            "data": _alert_to_dict(alert),
            "relationships": {
                "incidents": {
                    "type": "incident",
                    "count": len(incidents),
                    "items": [{"id": i.id, "title": i.title, "status": i.status} for i in incidents[:5]],
                    "link": f"/api/v1/alerts/{alert_id}/incidents",
                },
                "similar": {
                    "type": "alert",
                    "count": len(similar),
                    "items": [_alert_to_dict(a) for a in similar[:5]],
                    "link": f"/api/v1/alerts/{alert_id}/similar",
                },
            },
            "actions": {
                "view_incidents": f"/api/v1/alerts/{alert_id}/incidents",
                "view_similar": f"/api/v1/alerts/{alert_id}/similar",
            },
        }

    # Fallback to upstream
    from pipeline.sender import client
    try:
        os_alert = await client.get_alert(alert_id)
        if os_alert:
            return {
                "data": os_alert,
                "relationships": os_alert.get("relationships", {}),
                "actions": os_alert.get("actions", {}),
            }
    except Exception:
        pass

    raise HTTPException(status_code=404, detail="Alert not found")


def _alert_has_mitre_technique(alert: Dict[str, Any], technique: str) -> bool:
    """Check whether an alert dict matches a MITRE technique name or ID."""
    metadata = alert.get("metadata") or {}
    techniques = metadata.get("mitre_techniques") or []
    ids = metadata.get("mitre_ids") or []
    if technique in techniques or technique in ids:
        return True
    tags = alert.get("tags") or []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        if tag.lower() == f"mitre-technique-{technique.lower()}":
            return True
        if tag.lower() == f"mitre-{technique.lower()}":
            return True
    return False


def _alert_has_tactic(alert: Dict[str, Any], tactic: str) -> bool:
    """Check whether an alert dict matches a MITRE tactic name."""
    metadata = alert.get("metadata") or {}
    tactics = metadata.get("mitre_tactics") or []
    if tactic in tactics:
        return True
    tags = alert.get("tags") or []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        if tag.lower() == f"mitre-tactic-{tactic.lower()}":
            return True
    return False


@router.get("")
async def list_alerts(
    source: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    whitelisted: Optional[bool] = None,
    mitre_technique: Optional[str] = None,
    tactic: Optional[str] = None,
    time_from: Optional[datetime] = Query(None, description="Filter alerts from this ISO datetime (inclusive)"),
    time_to: Optional[datetime] = Query(None, description="Filter alerts up to this ISO datetime (inclusive)"),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_auth),
):
    """List alerts: local DB + upstream OpenSOAR merged.

    Falco runtime alerts are excluded from the generic alerts list by default.
    They remain accessible via the runtime investigations API.
    """
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    # Query local
    stmt = select(Alert)
    # Falco runtime alerts are scoped to /runtime/investigations only
    stmt = stmt.where(Alert.source != "falco")
    if asset_id:
        stmt = stmt.where(Alert.asset_id == asset_id)
    if source:
        stmt = stmt.where(Alert.source == source)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status:
        stmt = stmt.where(Alert.status == status)
    if category:
        stmt = stmt.where(Alert.category == category)
    if whitelisted is not None:
        stmt = stmt.where(Alert.whitelisted == whitelisted)
    if mitre_technique:
        stmt = stmt.where(
            or_(
                Alert.alert_metadata.cast(Text).ilike(f"%{mitre_technique}%"),
                Alert.tags.cast(Text).ilike(f"%mitre-technique-{mitre_technique}%"),
                Alert.tags.cast(Text).ilike(f"%mitre-{mitre_technique}%"),
            )
        )
    if tactic:
        stmt = stmt.where(
            or_(
                Alert.alert_metadata.cast(Text).ilike(f"%{tactic}%"),
                Alert.tags.cast(Text).ilike(f"%mitre-tactic-{tactic}%"),
            )
        )
    if time_from:
        stmt = stmt.where(func.coalesce(Alert.event_time, Alert.created_at) >= time_from)
    if time_to:
        stmt = stmt.where(func.coalesce(Alert.event_time, Alert.created_at) <= time_to)
    if time_from and time_to and time_from > time_to:
        raise HTTPException(status_code=422, detail="time_from must not be after time_to")

    total_result = await session.execute(select(func.count()).select_from(stmt.subquery()))
    local_total = total_result.scalar() or 0

    # Fetch ALL local results for proper merge + sort (don't paginate yet)
    stmt = stmt.order_by(Alert.created_at.desc())
    result = await session.execute(stmt)
    local_alerts = [_alert_to_dict(a) for a in result.scalars().all()]

    from config import get_settings
    settings = get_settings()

    if settings.upstream_enabled:
        # Fetch upstream and merge (local takes precedence for same ID).
        # Upstream may not support MITRE filters, so we apply them post-merge.
        upstream_alerts, upstream_total = await _get_upstream_alerts(
            limit=500,
            source=source,
            severity=severity,
            status=status,
            category=category,
            whitelisted=whitelisted,
        )

        local_ids = {a["id"] for a in local_alerts}
        local_external_ids = {a.get("external_id") for a in local_alerts if a.get("external_id")}
        merged = list(local_alerts)
        for ua in upstream_alerts:
            uid = ua.get("id")
            # Exclude Falco runtime alerts from upstream merge
            if ua.get("source") == "falco":
                continue
            if uid and uid not in local_ids and uid not in local_external_ids:
                merged.append(ua)

        # Post-filter for MITRE criteria when upstream is involved
        if mitre_technique:
            merged = [a for a in merged if _alert_has_mitre_technique(a, mitre_technique)]
        if tactic:
            merged = [a for a in merged if _alert_has_tactic(a, tactic)]

        def _sort_key(a):
            ts = a.get("created_at") or a.get("event_time") or ""
            return str(ts)
        merged.sort(key=_sort_key, reverse=True)

        total = len(merged)
        paginated = merged[offset : offset + limit]
        source_label = "merged"
    else:
        total = local_total
        paginated = local_alerts[offset : offset + limit]
        source_label = "local"

    return {
        "alerts": paginated,
        "total": total,
        "limit": limit,
        "offset": offset,
        "source": source_label,
    }


@router.patch("/{alert_id}/archive")
async def archive_alert(
    alert_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Archive an alert (local only; never delete)."""
    from datetime import datetime, timezone

    result = await session.execute(
        select(Alert).where(or_(Alert.id == alert_id, Alert.external_id == alert_id))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "archived"
    alert.archived_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(alert)
    return {"success": True, "alert_id": alert.id, "status": alert.status}
