"""
Incident API with full relationship support.
Hybrid mode: local shadow store + upstream OpenSOAR fallback.
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy import select, func, insert
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import get_session
from response.models import Incident, Alert, AlertIncidentLink, Investigation
from response.auth import require_auth, CurrentUser

logger = structlog.get_logger()


async def _incident_has_falco_link(session: AsyncSession, incident_id: str) -> bool:
    """Return True if the incident is linked to a runtime investigation or has any Falco alert."""
    from sqlalchemy import exists
    # Check for linked runtime investigation
    result = await session.execute(
        select(Investigation.id)
        .where(
            Investigation.local_incident_id == incident_id,
            Investigation.investigation_type == "runtime",
        )
        .limit(1)
    )
    if result.scalar_one_or_none():
        return True
    # Check for any linked Falco alert
    result = await session.execute(
        select(Alert.id)
        .join(AlertIncidentLink, Alert.id == AlertIncidentLink.alert_id)
        .where(
            AlertIncidentLink.incident_id == incident_id,
            Alert.source == "falco",
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


def _filter_falco_from_incidents_stmt(stmt):
    """Add WHERE clauses to exclude Falco-derived incidents from a SELECT(Incident) statement."""
    from sqlalchemy import not_, exists
    # Exclude incidents linked to a runtime investigation
    no_runtime_inv = not_(
        exists().where(
            Investigation.local_incident_id == Incident.id,
            Investigation.investigation_type == "runtime",
        )
    )
    # Exclude incidents that have any linked Falco alert
    no_falco_alert = not_(
        exists().where(
            AlertIncidentLink.incident_id == Incident.id,
            AlertIncidentLink.alert_id == Alert.id,
            Alert.source == "falco",
        )
    )
    return stmt.where(no_runtime_inv, no_falco_alert)


class CreateManualIncidentRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1)
    severity: str
    alert_ids: List[str]
    source_ips: Optional[List[str]] = None
    hostnames: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    assigned_to: Optional[str] = None
    created_by: Optional[str] = "analyst"

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v

    @field_validator("alert_ids")
    @classmethod
    def validate_alert_ids(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("at least one alert_id is required")
        if len(v) > 100:
            raise ValueError("maximum 100 alert_ids allowed")
        return v


router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


async def _get_upstream_incidents(limit: int = 200, **filters) -> tuple[list, int]:
    """Fetch incidents from upstream OpenSOAR as fallback."""
    from config import get_settings
    settings = get_settings()
    if not settings.upstream_enabled:
        return [], 0
    from pipeline.sender import client
    try:
        incidents = await client.list_incidents(limit=limit, **filters)
        incident_list = incidents.get("incidents", [])
        total = incidents.get("total", len(incident_list))
        return incident_list, total
    except Exception:
        return [], 0


def _incident_to_dict(incident: Incident, alert_count: int = None) -> Dict[str, Any]:
    result = {
        "id": incident.id,
        "external_id": incident.external_id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "source_ips": incident.source_ips,
        "hostnames": incident.hostnames,
        "rule_ids": incident.rule_ids,
        "alert_ids": incident.alert_ids,
        "resolved_by": incident.resolved_by,
        "soar_actions": incident.soar_actions,
        "assigned_to": incident.assigned_to,
        "assigned_username": incident.assigned_username,
        "tags": incident.tags or [],
        "whitelisted": incident.whitelisted,
        "created_by": incident.created_by,
        "updated_by": incident.updated_by,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "archived_at": incident.archived_at.isoformat() if incident.archived_at else None,
    }
    # Compute alert_count from alert_ids JSON or provided count
    if alert_count is not None:
        result["alert_count"] = alert_count
    elif incident.alert_ids:
        result["alert_count"] = len(incident.alert_ids)
    else:
        result["alert_count"] = 0
    return result


@router.get("/suggestions")
async def get_incident_suggestions(session: AsyncSession = Depends(get_session)):
    """Get incident suggestions from local DB."""
    from sqlalchemy import text
    result = await session.execute(
        text("""
            SELECT source_ip, COUNT(*) as cnt, GROUP_CONCAT(id) as alert_ids
            FROM alerts
            WHERE status = 'active' AND source_ip IS NOT NULL AND source_ip != ''
            AND source != 'falco'
            AND id NOT IN (SELECT alert_id FROM alert_incident_links)
            GROUP BY source_ip
            HAVING cnt >= 2
            ORDER BY cnt DESC
            LIMIT 50
        """)
    )
    rows = result.all()
    return {
        "suggestions": [
            {
                "source_ip": row.source_ip,
                "alert_count": row.cnt,
                "alert_ids": row.alert_ids.split(",") if row.alert_ids else [],
            }
            for row in rows
        ]
    }


@router.post("/manual")
async def create_manual_incident(
    request: CreateManualIncidentRequest,
    session: AsyncSession = Depends(get_session),
):
    """
    Manually create an incident from one or more existing alerts.
    """
    # 1. Validate all alert_ids exist
    result = await session.execute(
        select(Alert).where(Alert.id.in_(request.alert_ids))
    )
    found_alerts = result.scalars().all()
    found_ids = {a.id for a in found_alerts}
    missing = set(request.alert_ids) - found_ids
    if missing:
        raise HTTPException(status_code=404, detail=f"Alerts not found: {sorted(missing)}")

    # Preserve request order
    alerts_by_id = {a.id: a for a in found_alerts}
    alerts = [alerts_by_id[aid] for aid in request.alert_ids if aid in alerts_by_id]

    # 1b. Reject Falco runtime alerts — they belong to /runtime/investigations only
    falco_alerts = [a for a in alerts if a.source == "falco"]
    if falco_alerts:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot create incident from Falco runtime alerts. Use Runtime Security instead. Falco alert IDs: {[a.id for a in falco_alerts]}",
        )

    # 2. Auto-extract source_ips and hostnames if not provided
    source_ips = request.source_ips or []
    hostnames = request.hostnames or []
    if not source_ips:
        source_ips = list({a.source_ip for a in alerts if a.source_ip})
    if not hostnames:
        hostnames = list({a.hostname for a in alerts if a.hostname})

    tags = list(request.tags or [])
    if "manual" not in tags:
        tags.append("manual")
    # Deduplicate while preserving order
    tags = list(dict.fromkeys(tags))

    # Create incident
    incident = Incident(
        title=request.title,
        description=request.description,
        severity=request.severity,
        status="open",
        source_ips=source_ips if source_ips else None,
        hostnames=hostnames if hostnames else None,
        alert_ids=request.alert_ids,
        tags=tags if tags else None,
        assigned_to=request.assigned_to,
        created_by=request.created_by,
        updated_by=request.created_by,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(incident)
    await session.flush()
    await session.refresh(incident)

    # 3. Create AlertIncidentLink rows (idempotent)
    for alert in alerts:
        existing = await session.execute(
            select(AlertIncidentLink).where(
                AlertIncidentLink.alert_id == alert.id,
                AlertIncidentLink.incident_id == incident.id,
            )
        )
        if existing.scalar_one_or_none():
            continue
        await session.execute(
            insert(AlertIncidentLink).values(
                alert_id=alert.id,
                incident_id=incident.id,
                correlation_confidence="manual",
                correlation_reason="Analyst manually linked alert to incident",
                linked_at=datetime.now(timezone.utc),
            )
        )

    await session.commit()
    await session.refresh(incident)

    # 4. Optionally create upstream incident
    try:
        from config import get_settings
        settings = get_settings()
        if settings.upstream_enabled:
            from pipeline.sender import client
            upstream = await client.create_incident(
                title=request.title,
                description=request.description,
                severity=request.severity,
                tags=tags,
            )
            upstream_id = upstream.get("id")
            if upstream_id:
                incident.external_id = upstream_id
                await session.commit()
                await session.refresh(incident)
    except Exception as e:
        logger.warning("manual_incident_upstream_create_failed", incident_id=incident.id, error=str(e)[:100])

    # 5. Broadcast WebSocket update
    try:
        from api.websocket import ws_manager
        await ws_manager.broadcast("investigations", {
            "type": "incident_created",
            "incident_id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "source": "manual",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        logger.warning("manual_incident_websocket_broadcast_failed", incident_id=incident.id, error=str(e)[:100])

    # 6. Return incident with linked alerts
    return {
        "data": _incident_to_dict(incident, alert_count=len(alerts)),
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "source": a.source,
                "source_ip": a.source_ip,
                "hostname": a.hostname,
            }
            for a in alerts
        ],
        "source": "local",
    }


@router.get("/by-alert/{alert_id}")
async def get_incident_by_alert(
    alert_id: str, session: AsyncSession = Depends(get_session)
):
    """Find which incident(s) contain this alert."""
    # First check if the alert itself is a Falco alert — if so, no generic incident should contain it
    alert_check = await session.execute(
        select(Alert.source).where(Alert.id == alert_id)
    )
    alert_source = alert_check.scalar_one_or_none()
    if alert_source == "falco":
        return {"alert_id": alert_id, "incidents": [], "total": 0, "source": "local"}

    result = await session.execute(
        select(Incident)
        .join(AlertIncidentLink, Incident.id == AlertIncidentLink.incident_id)
        .where(AlertIncidentLink.alert_id == alert_id)
        .limit(50)
    )
    incidents = result.scalars().all()
    # Filter out Falco-derived incidents
    filtered = [i for i in incidents if not await _incident_has_falco_link(session, i.id)]
    if filtered:
        return {
            "alert_id": alert_id,
            "incidents": [_incident_to_dict(i) for i in filtered],
            "total": len(filtered),
            "source": "local",
        }
    # Fallback to upstream
    from config import get_settings
    settings = get_settings()
    if settings.upstream_enabled:
        from pipeline.sender import client
        try:
            upstream = await client.list_incidents(alert_id=alert_id, limit=50)
            upstream_list = upstream.get("incidents", [])
            return {
                "alert_id": alert_id,
                "incidents": upstream_list,
                "total": len(upstream_list),
                "source": "upstream",
            }
        except Exception:
            pass
    return {"alert_id": alert_id, "incidents": [], "total": 0}


@router.get("/{incident_id}")
async def get_incident(
    incident_id: str, session: AsyncSession = Depends(get_session)
):
    """Get incident from local DB or upstream. Returns format matching frontend expectations."""
    from sqlalchemy import or_
    result = await session.execute(
        select(Incident).where(
            or_(Incident.id == incident_id, Incident.external_id == incident_id)
        )
    )
    incident = result.scalar_one_or_none()
    if incident:
        # Block access to Falco-derived incidents from generic endpoint
        if await _incident_has_falco_link(session, incident.id):
            raise HTTPException(status_code=404, detail="Incident not found")
        local_id = incident.id
        # Related alerts
        alert_result = await session.execute(
            select(Alert)
            .join(AlertIncidentLink, Alert.id == AlertIncidentLink.alert_id)
            .where(AlertIncidentLink.incident_id == local_id)
            .limit(100)
        )
        alerts = alert_result.scalars().all()
        alert_count = len(alerts)
        alert_items = [{"id": a.id, "title": a.title, "severity": a.severity, "source": a.source} for a in alerts[:10]]

        # If no local alerts, try upstream for count/metadata
        from config import get_settings
        settings = get_settings()
        if alert_count == 0 and incident.external_id and settings.upstream_enabled:
            try:
                from pipeline.sender import client
                upstream_alerts = await client.get_incident_alerts(incident.external_id)
                alert_count = len(upstream_alerts)
                alert_items = upstream_alerts[:10]
            except Exception:
                pass

        # Related investigations — use external_id since Investigation.incident_id stores upstream id
        query_id = incident.external_id or incident.id
        inv_result = await session.execute(
            select(Investigation).where(Investigation.incident_id == query_id).limit(1)
        )
        inv = inv_result.scalar_one_or_none()
        incident_dict = _incident_to_dict(incident, alert_count=alert_count)

        return {
            "data": incident_dict,
            "relationships": {
                "alerts": {
                    "type": "alert",
                    "count": alert_count,
                    "items": alert_items,
                    "link": f"/api/v1/incidents/{incident_id}/alerts",
                },
                "investigation": {
                    "type": "investigation",
                    "exists": inv is not None,
                    "item": {
                        "id": inv.id,
                        "status": inv.status,
                        "ai_summary": inv.ai_summary,
                        "has_playbook": bool(inv.playbook_yaml),
                        "incident_id": inv.incident_id,
                        "local_incident_id": inv.local_incident_id,
                        "upstream_incident_id": inv.upstream_incident_id,
                    } if inv else None,
                    "link": f"/api/v1/investigations?incident_id={incident_id}" if inv else None,
                },
            },
        }

    # Fallback to upstream
    from config import get_settings
    settings = get_settings()
    if settings.upstream_enabled:
        from pipeline.sender import client
        try:
            upstream = await client.list_incidents(limit=200)
            for inc in upstream.get("incidents", []):
                if inc.get("id") == incident_id:
                    # Fetch related alerts from upstream
                    try:
                        upstream_alerts = await client.get_incident_alerts(incident_id)
                    except Exception:
                        upstream_alerts = []
                    # Fetch investigation from upstream incident
                    upstream_inv = None
                    try:
                        upstream_inv_raw = await client.get_incident(incident_id)
                        if upstream_inv_raw:
                            invs = upstream_inv_raw.get("investigations", [])
                            upstream_inv = invs[0] if invs else None
                    except Exception:
                        pass
                    return {
                        "data": inc,
                        "relationships": {
                            "alerts": {
                                "type": "alert",
                                "count": len(upstream_alerts),
                                "items": upstream_alerts[:10],
                                "link": f"/api/v1/incidents/{incident_id}/alerts",
                            },
                            "investigation": {
                                "type": "investigation",
                                "exists": upstream_inv is not None,
                                "item": upstream_inv,
                                "link": f"/api/v1/investigations?incident_id={incident_id}" if upstream_inv else None,
                            },
                        },
                    }
        except Exception:
            pass

    raise HTTPException(status_code=404, detail="Incident not found")


@router.get("/{incident_id}/alerts")
async def get_incident_alerts(
    incident_id: str, session: AsyncSession = Depends(get_session)
):
    """Get all alerts linked to this incident — local first, upstream fallback."""
    from sqlalchemy import or_, insert

    # Resolve incident_id to local row
    inc_result = await session.execute(
        select(Incident).where(
            or_(Incident.id == incident_id, Incident.external_id == incident_id)
        )
    )
    local_incident = inc_result.scalar_one_or_none()
    if local_incident and await _incident_has_falco_link(session, local_incident.id):
        raise HTTPException(status_code=404, detail="Incident not found")

    # Continue with original logic but local_incident already resolved above
    local_id = local_incident.id if local_incident else incident_id

    # 1. Try AlertIncidentLink first (properly linked alerts)
    result = await session.execute(
        select(Alert)
        .join(AlertIncidentLink, Alert.id == AlertIncidentLink.alert_id)
        .where(AlertIncidentLink.incident_id == local_id)
        .limit(100)
    )
    local_alerts = result.scalars().all()
    if local_alerts:
        return {
            "alerts": [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "source": a.source,
                    "status": a.status,
                    "source_ip": a.source_ip,
                    "hostname": a.hostname,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in local_alerts
            ],
            "total": len(local_alerts),
            "source": "local",
        }

    # 2. Intermediate fallback: resolve Incident.alert_ids via Alert.external_id
    #    and lazily backfill missing AlertIncidentLink rows.
    if local_incident and local_incident.alert_ids:
        upstream_ids = [aid for aid in local_incident.alert_ids if aid]
        if upstream_ids:
            resolved_result = await session.execute(
                select(Alert).where(Alert.external_id.in_(upstream_ids)).limit(100)
            )
            resolved_alerts = resolved_result.scalars().all()
            if resolved_alerts:
                # Lazily create missing link rows
                existing_links_result = await session.execute(
                    select(AlertIncidentLink.alert_id).where(
                        AlertIncidentLink.incident_id == local_id
                    )
                )
                existing_link_ids = {row[0] for row in existing_links_result.all()}
                for a in resolved_alerts:
                    if a.id not in existing_link_ids:
                        try:
                            await session.execute(
                                insert(AlertIncidentLink).values(
                                    alert_id=a.id,
                                    incident_id=local_id,
                                    correlation_confidence="high",
                                    correlation_reason="auto-backfilled from alert_ids",
                                    linked_at=datetime.now(timezone.utc),
                                )
                            )
                        except Exception:
                            pass
                await session.commit()

                return {
                    "alerts": [
                        {
                            "id": a.id,
                            "title": a.title,
                            "severity": a.severity,
                            "source": a.source,
                            "status": a.status,
                            "source_ip": a.source_ip,
                            "hostname": a.hostname,
                            "created_at": a.created_at.isoformat() if a.created_at else None,
                        }
                        for a in resolved_alerts
                    ],
                    "total": len(resolved_alerts),
                    "source": "local_resolved",
                }

    # 3. Fallback: upstream OpenSOAR (use external_id if we have it)
    from config import get_settings
    settings = get_settings()
    if settings.upstream_enabled:
        from pipeline.sender import client
        upstream_incident_id = (local_incident.external_id or local_incident.id) if local_incident else incident_id
        try:
            upstream_alerts = await client.get_incident_alerts(upstream_incident_id)
            return {
                "alerts": upstream_alerts,
                "total": len(upstream_alerts),
                "source": "upstream",
            }
        except Exception:
            pass
    return {"alerts": [], "total": 0, "source": "none"}


@router.get("/{incident_id}/investigations")
async def get_incident_investigations(
    incident_id: str, session: AsyncSession = Depends(get_session)
):
    """Get investigations linked to this incident."""
    from sqlalchemy import or_
    # Resolve to external_id since Investigation.incident_id stores upstream IDs
    inc_result = await session.execute(
        select(Incident).where(
            or_(Incident.id == incident_id, Incident.external_id == incident_id)
        )
    )
    local_incident = inc_result.scalar_one_or_none()
    if local_incident and await _incident_has_falco_link(session, local_incident.id):
        raise HTTPException(status_code=404, detail="Incident not found")
    query_id = (local_incident.external_id or local_incident.id) if local_incident else incident_id

    result = await session.execute(
        select(Investigation)
        .where(
            Investigation.incident_id == query_id,
            Investigation.investigation_type != "runtime",
        )
        .limit(50)
    )
    investigations = result.scalars().all()
    return {
        "investigations": [
            {
                "id": inv.id,
                "status": inv.status,
                "incident_id": inv.incident_id,
                "local_incident_id": inv.local_incident_id,
                "upstream_incident_id": inv.upstream_incident_id,
                "incident_title": inv.incident_title,
                "incident_severity": inv.incident_severity,
                "target_host": inv.target_host,
                "ai_summary": inv.ai_summary,
                "has_playbook": bool(inv.playbook_yaml),
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
                "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
            }
            for inv in investigations
        ],
        "total": len(investigations),
        "source": "local",
    }


@router.get("/{incident_id}/timeline")
async def get_incident_timeline(
    incident_id: str, session: AsyncSession = Depends(get_session)
):
    """Return ordered timeline events for this incident.
    Looks up by local id first, then by external_id (upstream id)."""
    from sqlalchemy import or_
    result = await session.execute(
        select(Incident).where(
            or_(Incident.id == incident_id, Incident.external_id == incident_id)
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if await _incident_has_falco_link(session, incident.id):
        raise HTTPException(status_code=404, detail="Incident not found")

    events = []
    if incident.created_at:
        events.append({
            "timestamp": incident.created_at.isoformat(),
            "type": "incident_created",
            "description": "Incident created from alerts",
        })

    # Use external_id when present; local-only investigations store the local id.
    query_id = incident.external_id or incident.id
    inv_result = await session.execute(
        select(Investigation)
        .where(
            Investigation.incident_id == query_id,
            Investigation.investigation_type != "runtime",
        )
    )
    investigations = inv_result.scalars().all()
    for inv in investigations:
        events.append({
            "timestamp": inv.created_at.isoformat() if inv.created_at else None,
            "type": "investigation_started",
            "description": f"Investigation {inv.id} started",
        })
        if inv.status in ("awaiting_approval", "approved", "declined"):
            events.append({
                "timestamp": inv.updated_at.isoformat() if inv.updated_at else None,
                "type": "ai_analysis_complete",
                "description": f"AI analysis complete; status: {inv.status}",
            })
        if inv.status in ("completed", "failed"):
            events.append({
                "timestamp": inv.updated_at.isoformat() if inv.updated_at else None,
                "type": "playbook_executed",
                "description": f"Playbook execution finished with status: {inv.status}",
            })

    if incident.resolved_at:
        events.append({
            "timestamp": incident.resolved_at.isoformat(),
            "type": "incident_resolved",
            "description": f"Incident resolved by {incident.resolved_by or 'unknown'}",
        })

    if incident.archived_at:
        events.append({
            "timestamp": incident.archived_at.isoformat(),
            "type": "incident_archived",
            "description": "Incident archived",
        })

    events.sort(key=lambda e: e["timestamp"] or "")
    return {"incident_id": incident_id, "events": events, "total_events": len(events)}


@router.get("")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assignee: Optional[str] = None,
    whitelisted: Optional[bool] = None,
    time_from: Optional[datetime] = Query(None, description="Filter incidents from this ISO datetime (inclusive)"),
    time_to: Optional[datetime] = Query(None, description="Filter incidents up to this ISO datetime (inclusive)"),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_auth),
):
    """List incidents: local DB + upstream fallback.

    Falco runtime cases are excluded — they live in /runtime/investigations only.
    """
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    stmt = select(Incident)
    if asset_id:
        stmt = stmt.where(Incident.asset_id == asset_id)
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if assignee:
        stmt = stmt.where(Incident.assigned_to == assignee)
    if whitelisted is not None:
        stmt = stmt.where(Incident.whitelisted == whitelisted)
    if time_from:
        stmt = stmt.where(Incident.created_at >= time_from)
    if time_to:
        stmt = stmt.where(Incident.created_at <= time_to)
    if time_from and time_to and time_from > time_to:
        raise HTTPException(status_code=422, detail="time_from must not be after time_to")

    # Exclude Falco-derived incidents
    stmt = _filter_falco_from_incidents_stmt(stmt)

    total_result = await session.execute(select(func.count()).select_from(stmt.subquery()))
    local_total = total_result.scalar() or 0

    # Fetch ALL local results for proper merge + sort (don't paginate yet)
    stmt = stmt.order_by(Incident.created_at.desc())
    result = await session.execute(stmt)
    local_incidents = [_incident_to_dict(i) for i in result.scalars().all()]

    from config import get_settings
    settings = get_settings()

    if settings.upstream_enabled:
        upstream_incidents, upstream_total = await _get_upstream_incidents(
            limit=500, status=status, severity=severity, whitelisted=whitelisted
        )

        local_ids = {i["id"] for i in local_incidents}
        local_external_ids = {i["external_id"] for i in local_incidents if i.get("external_id")}
        merged = list(local_incidents)
        for ui in upstream_incidents:
            uid = ui.get("id")
            if uid and uid not in local_ids and uid not in local_external_ids:
                merged.append(ui)

        def _sort_key(i):
            ts = i.get("created_at") or ""
            return str(ts)
        merged.sort(key=_sort_key, reverse=True)

        total = len(merged)
        paginated = merged[offset : offset + limit]
        source_label = "merged"
    else:
        total = local_total
        paginated = local_incidents[offset : offset + limit]
        source_label = "local"

    return {
        "incidents": paginated,
        "total": total,
        "limit": limit,
        "offset": offset,
        "source": source_label,
    }


@router.patch("/{incident_id}")
async def patch_incident(
    incident_id: str,
    updates: dict,
    session: AsyncSession = Depends(get_session)
):
    """Update incident fields: status, severity, assigned_to, assigned_username, tags."""
    from sqlalchemy import update, or_
    from datetime import datetime, timezone

    result = await session.execute(
        select(Incident).where(or_(Incident.id == incident_id, Incident.external_id == incident_id))
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    allowed = {"status", "severity", "assigned_to", "assigned_username", "tags", "description", "title"}
    filtered = {k: v for k, v in updates.items() if k in allowed}
    if not filtered:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    filtered["updated_at"] = datetime.now(timezone.utc)

    await session.execute(
        update(Incident).where(Incident.id == incident.id).values(**filtered)
    )
    await session.commit()

    # Refresh and return
    result = await session.execute(select(Incident).where(Incident.id == incident.id))
    updated = result.scalar_one()
    return {"data": _incident_to_dict(updated, alert_count=len(updated.alert_ids or [])), "source": "local"}


@router.patch("/{incident_id}/archive")
async def archive_incident(
    incident_id: str, session: AsyncSession = Depends(get_session)
):
    """Archive an incident (local only; never delete)."""
    from datetime import datetime, timezone
    from sqlalchemy import or_

    result = await session.execute(
        select(Incident).where(
            or_(Incident.id == incident_id, Incident.external_id == incident_id)
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = "archived"
    incident.archived_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(incident)
    return {"success": True, "incident_id": incident.id, "status": incident.status}
