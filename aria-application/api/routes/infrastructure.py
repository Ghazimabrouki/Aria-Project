"""
Infrastructure Investigation API routes.

Dedicated endpoints for resource/infrastructure investigations.
These are separate from security investigations in behavior and semantics.
"""

import asyncio
from typing import Optional
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import get_session, AsyncSessionLocal
from response.auth import require_auth, CurrentUser
from response.models import (
    Investigation,
    InvestigationAlert,
    InvestigationAuditEvent,
    MonitoredAsset,
    PlaybookApproval,
    PlaybookRun,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/infrastructure", tags=["infrastructure"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────


class InfrastructureInvestigationSummary(BaseModel):
    id: str
    incident_id: str
    incident_title: str
    incident_severity: str
    status: str
    investigation_type: str
    target_host: Optional[str]
    resource_type: Optional[str]
    affected_service: Optional[str]
    current_value: Optional[float]
    threshold: Optional[float]
    unit: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ApproveInfrastructureRequest(BaseModel):
    decided_by: str = "analyst"
    acknowledge_risk: bool = False


class DeclineInfrastructureRequest(BaseModel):
    decided_by: str = "analyst"
    reason: Optional[str] = None


class SuggestedActionResponse(BaseModel):
    action: str
    risk: str
    expected_outcome: str
    system_impact: str
    rollback_feasible: bool


class ResourceContextResponse(BaseModel):
    resource_type: str
    current_value: float
    threshold: float
    unit: str
    affected_host: str
    affected_service: Optional[str]
    affected_process: Optional[dict]
    top_processes: list
    metrics_snapshot: dict
    historical_trend: str
    baseline_deviation: Optional[str]
    root_cause_confidence: float


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _get_investigation_or_404(
    investigation_id: str, session: AsyncSession
) -> Investigation:
    result = await session.execute(
        select(Investigation).where(Investigation.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if inv.investigation_type != "infrastructure":
        raise HTTPException(
            status_code=400,
            detail="This investigation is not an infrastructure investigation",
        )
    return inv


def _extract_resource_context(inv: Investigation) -> Optional[dict]:
    """Extract resource context from investigation."""
    if inv.resource_context_json:
        return inv.resource_context_json
    return None


async def _create_audit_event(
    session: AsyncSession,
    investigation_id: str,
    event_type: str,
    previous_status: Optional[str] = None,
    new_status: Optional[str] = None,
    actor: str = "analyst",
    details: Optional[str] = None,
) -> None:
    """Create an audit event for an infrastructure investigation."""
    event = InvestigationAuditEvent(
        investigation_id=investigation_id,
        event_type=event_type,
        actor=actor,
        details=details or (f"Status changed from {previous_status} to {new_status}" if previous_status and new_status else None),
    )
    session.add(event)
    await session.commit()


def _extract_suggested_actions(inv: Investigation) -> list:
    """Extract suggested actions from investigation findings or resource context."""
    # Prefer post-diagnostic recommendations if available
    findings = inv.findings_json or {}
    recommendations = findings.get("recommendations", [])
    if recommendations:
        actions = []
        for rec in recommendations:
            if isinstance(rec, dict):
                actions.append({
                    "action": rec.get("action", ""),
                    "risk": rec.get("risk", "Unknown"),
                    "expected_outcome": rec.get("expected_outcome", ""),
                    "system_impact": rec.get("system_impact", ""),
                    "rollback_feasible": rec.get("rollback_feasible", False),
                })
            elif isinstance(rec, str):
                actions.append({
                    "action": rec,
                    "risk": "Unknown",
                    "expected_outcome": "",
                    "system_impact": "",
                    "rollback_feasible": False,
                })
        return actions

    # Fall back to resource_context_json (pre-diagnostic)
    ctx = inv.resource_context_json or {}
    if ctx:
        mitigation = ctx.get("immediate_mitigation", {})
        long_term = ctx.get("long_term_optimization", {})
        actions = []
        if mitigation:
            actions.append({
                "action": mitigation.get("action", ""),
                "risk": mitigation.get("risk", "Unknown"),
                "expected_outcome": mitigation.get("expected_outcome", ""),
                "system_impact": mitigation.get("system_impact", ""),
                "rollback_feasible": mitigation.get("rollback_feasible", False),
            })
        if long_term:
            actions.append({
                "action": long_term.get("action", ""),
                "risk": long_term.get("risk", "Unknown"),
                "expected_outcome": long_term.get("expected_outcome", ""),
                "system_impact": long_term.get("system_impact", ""),
                "rollback_feasible": True,
            })
        return actions
    return []


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("/investigations", response_model=dict)
async def list_infrastructure_investigations(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    time_from: Optional[datetime] = Query(None, description="Filter investigations from this ISO datetime (inclusive)"),
    time_to: Optional[datetime] = Query(None, description="Filter investigations up to this ISO datetime (inclusive)"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_auth),
):
    """List infrastructure investigations with resource-specific filtering."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    q = select(Investigation).where(Investigation.investigation_type == "infrastructure")
    if asset_id:
        q = q.where(Investigation.asset_id == asset_id)

    if status and status != "all":
        q = q.where(Investigation.status == status)
    if severity and severity != "all":
        q = q.where(Investigation.incident_severity == severity)
    if resource_type and resource_type != "all":
        q = q.where(Investigation.resource_type == resource_type)
    if host:
        q = q.where(Investigation.target_host.ilike(f"%{host}%"))
    if time_from:
        q = q.where(Investigation.created_at >= time_from)
    if time_to:
        q = q.where(Investigation.created_at <= time_to)
    if time_from and time_to and time_from > time_to:
        raise HTTPException(status_code=422, detail="time_from must not be after time_to")

    q = q.order_by(Investigation.created_at.desc()).offset(offset).limit(limit)

    result = await session.execute(q)
    investigations = result.scalars().all()

    # Count total
    count_q = select(func.count(Investigation.id)).where(
        Investigation.investigation_type == "infrastructure"
    )
    if asset_id:
        count_q = count_q.where(Investigation.asset_id == asset_id)
    if status and status != "all":
        count_q = count_q.where(Investigation.status == status)
    if severity and severity != "all":
        count_q = count_q.where(Investigation.incident_severity == severity)
    if resource_type and resource_type != "all":
        count_q = count_q.where(Investigation.resource_type == resource_type)
    if host:
        count_q = count_q.where(Investigation.target_host.ilike(f"%{host}%"))
    if time_from:
        count_q = count_q.where(Investigation.created_at >= time_from)
    if time_to:
        count_q = count_q.where(Investigation.created_at <= time_to)

    total = (await session.execute(count_q)).scalar_one()

    items = []
    for inv in investigations:
        ctx = _extract_resource_context(inv)
        items.append({
            "id": inv.id,
            "incident_id": inv.incident_id,
            "incident_title": inv.incident_title,
            "incident_severity": inv.incident_severity,
            "status": inv.status,
            "investigation_type": inv.investigation_type,
            "target_host": inv.target_host,
            "resource_type": inv.resource_type or (ctx.get("resource_type") if ctx else None),
            "affected_service": ctx.get("affected_service") if ctx else None,
            "current_value": ctx.get("current_value") if ctx else None,
            "threshold": ctx.get("threshold") if ctx else None,
            "unit": ctx.get("unit") if ctx else None,
            "created_at": inv.created_at.isoformat(),
            "updated_at": inv.updated_at.isoformat(),
        })

    return {
        "investigations": items,
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/investigations/stats")
async def get_infrastructure_stats(
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_auth),
):
    """Get infrastructure investigation statistics."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    total_q = select(func.count(Investigation.id)).where(
        Investigation.investigation_type == "infrastructure"
    )
    if asset_id:
        total_q = total_q.where(Investigation.asset_id == asset_id)
    total = (await session.execute(total_q)).scalar_one()

    status_counts = {}
    for status in ("pending", "diagnosing", "findings_ready", "acknowledged", "escalated", "archived"):
        q = select(func.count(Investigation.id)).where(
            Investigation.investigation_type == "infrastructure",
            Investigation.status == status,
        )
        if asset_id:
            q = q.where(Investigation.asset_id == asset_id)
        status_counts[status] = (await session.execute(q)).scalar_one()

    return {
        "total": total,
        "by_status": status_counts,
    }


@router.get("/investigations/{investigation_id}")
async def get_infrastructure_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get full infrastructure investigation detail."""
    inv = await _get_investigation_or_404(investigation_id, session)
    ctx = _extract_resource_context(inv)
    actions = _extract_suggested_actions(inv)

    # Get linked alerts (explicit query to avoid lazy loading issues)
    alert_result = await session.execute(
        select(InvestigationAlert).where(
            InvestigationAlert.investigation_id == investigation_id
        )
    )
    alerts = alert_result.scalars().all()

    # Get approval (explicit query)
    approval_result = await session.execute(
        select(PlaybookApproval).where(
            PlaybookApproval.investigation_id == investigation_id
        )
    )
    approval = approval_result.scalar_one_or_none()
    approval_dict = None
    if approval:
        approval_dict = {
            "decision": approval.decision,
            "decided_by": approval.decided_by,
            "decided_at": approval.decided_at.isoformat(),
            "reason": approval.reason,
        }

    # Get run (explicit query)
    run_result = await session.execute(
        select(PlaybookRun).where(
            PlaybookRun.investigation_id == investigation_id
        )
    )
    run = run_result.scalar_one_or_none()
    run_dict = None
    if run:
        run_dict = {
            "status": run.status,
            "exit_code": run.exit_code,
            "current_phase": run.current_phase,
            "phases_json": run.phases_json,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        }

    return {
        "id": inv.id,
        "incident_id": inv.incident_id,
        "incident_title": inv.incident_title,
        "incident_severity": inv.incident_severity,
        "incident_status": inv.incident_status,
        "status": inv.status,
        "source": inv.source,
        "investigation_type": inv.investigation_type,
        "target_host": inv.target_host,
        "target_user": inv.target_user,
        "target_os": inv.target_os,
        "ai_summary": inv.ai_summary,
        "playbook_yaml": inv.playbook_yaml,
        "playbook_valid": inv.playbook_valid,
        "resource_context": ctx,
        "findings_json": inv.findings_json,
        "diagnostic_output": inv.diagnostic_output,
        "suggested_actions": actions,
        "evidence_json": inv.evidence_json,
        "rollback_playbook": inv.rollback_playbook,
        "ai_error": inv.ai_error,
        "created_at": inv.created_at.isoformat(),
        "updated_at": inv.updated_at.isoformat(),
        "alerts": [
            {
                "alert_id": a.alert_id,
                "severity": a.severity,
                "source": a.source,
                "title": a.title,
            }
            for a in alerts
        ],
        "approval": approval_dict,
        "run": run_dict,
    }


@router.get("/investigations/{investigation_id}/resource-context")
async def get_resource_context(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get structured resource context for an infrastructure investigation."""
    inv = await _get_investigation_or_404(investigation_id, session)
    ctx = _extract_resource_context(inv)
    if not ctx:
        raise HTTPException(status_code=404, detail="No resource context found")
    return ctx


@router.get("/investigations/{investigation_id}/suggested-actions")
async def get_suggested_actions(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get suggested remediation actions with risk assessment."""
    inv = await _get_investigation_or_404(investigation_id, session)
    actions = _extract_suggested_actions(inv)
    return {
        "investigation_id": investigation_id,
        "actions": actions,
    }


@router.post("/investigations/{investigation_id}/acknowledge")
async def acknowledge_infrastructure_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Acknowledge an infrastructure investigation and close it without action."""
    inv = await _get_investigation_or_404(investigation_id, session)
    previous_status = inv.status

    if inv.status not in ("findings_ready", "diagnosing"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot acknowledge when status is '{inv.status}'",
        )

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="acknowledged", updated_at=datetime.now(timezone.utc))
    )
    await session.commit()

    await _create_audit_event(
        session=session,
        investigation_id=investigation_id,
        event_type="acknowledged",
        previous_status=previous_status,
        new_status="acknowledged",
        actor="analyst",
    )

    logger.info("infrastructure_investigation_acknowledged", investigation_id=investigation_id)
    return {"status": "acknowledged", "investigation_id": investigation_id}


@router.post("/investigations/{investigation_id}/escalate")
async def escalate_infrastructure_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Escalate an infrastructure investigation for future remediation."""
    inv = await _get_investigation_or_404(investigation_id, session)
    previous_status = inv.status

    if inv.status not in ("findings_ready", "diagnosing"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot escalate when status is '{inv.status}'",
        )

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="escalated", updated_at=datetime.now(timezone.utc))
    )
    await session.commit()

    await _create_audit_event(
        session=session,
        investigation_id=investigation_id,
        event_type="escalated",
        previous_status=previous_status,
        new_status="escalated",
        actor="analyst",
    )

    logger.info("infrastructure_investigation_escalated", investigation_id=investigation_id)
    return {"status": "escalated", "investigation_id": investigation_id}


@router.post("/investigations/{investigation_id}/diagnose")
async def diagnose_infrastructure_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Manually re-trigger the diagnostic playbook for an infrastructure investigation."""
    inv = await _get_investigation_or_404(investigation_id, session)
    previous_status = inv.status

    # Allow re-diagnosis from most terminal states
    if inv.status not in ("findings_ready", "escalated", "acknowledged", "diagnosing", "failed"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot re-diagnose when status is '{inv.status}'",
        )

    resource_context = inv.resource_context_json or {}

    # Reset diagnostic timestamps, status, and clear stale findings/output
    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(
            status="diagnosing",
            diagnostic_started_at=datetime.now(timezone.utc),
            diagnostic_finished_at=None,
            findings_json=None,
            diagnostic_output=None,
            updated_at=datetime.now(timezone.utc),
        )
    )
    await session.commit()

    await _create_audit_event(
        session=session,
        investigation_id=investigation_id,
        event_type="diagnosed",
        previous_status=previous_status,
        new_status="diagnosing",
        actor="analyst",
        details="Re-diagnosis triggered by analyst",
    )

    # Trigger diagnostic pipeline in background
    from pipeline.datausage.performance_orchestrator import _run_diagnostic_pipeline
    asyncio.create_task(_run_diagnostic_pipeline(investigation_id, resource_context))

    logger.info("infrastructure_investigation_re_diagnosing", investigation_id=investigation_id)
    return {"status": "diagnosing", "investigation_id": investigation_id}


@router.post("/investigations/{investigation_id}/archive")
async def archive_infrastructure_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Archive a completed infrastructure investigation."""
    inv = await _get_investigation_or_404(investigation_id, session)
    previous_status = inv.status

    if inv.status not in ("acknowledged", "escalated"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot archive when status is '{inv.status}' — must be acknowledged or escalated",
        )

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="archived", updated_at=datetime.now(timezone.utc))
    )
    await session.commit()

    await _create_audit_event(
        session=session,
        investigation_id=investigation_id,
        event_type="archived",
        previous_status=previous_status,
        new_status="archived",
        actor="analyst",
    )

    logger.info("infrastructure_investigation_archived", investigation_id=investigation_id)
    return {"status": "archived", "investigation_id": investigation_id}


@router.get("/investigations/{investigation_id}/timeline")
async def get_infrastructure_timeline(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get timeline events for an infrastructure investigation.

    Merges real audit events with legacy synthetic events for backward compatibility.
    """
    inv = await _get_investigation_or_404(investigation_id, session)

    events = []
    events.append({
        "type": "created",
        "timestamp": inv.created_at.isoformat(),
        "description": f"Investigation created for {inv.incident_title}",
    })

    # Approval event
    approval_result = await session.execute(
        select(PlaybookApproval).where(PlaybookApproval.investigation_id == investigation_id)
    )
    approval = approval_result.scalar_one_or_none()
    if approval:
        events.append({
            "type": "approved" if approval.decision == "approved" else "declined",
            "timestamp": approval.decided_at.isoformat() if approval.decided_at else None,
            "description": f"Playbook {approval.decision} by {approval.decided_by}",
            "decision": approval.decision,
            "decided_by": approval.decided_by,
            "reason": approval.reason,
        })

    # Run event
    run_result = await session.execute(
        select(PlaybookRun).where(PlaybookRun.investigation_id == investigation_id)
    )
    run = run_result.scalar_one_or_none()
    if run:
        events.append({
            "type": "execution",
            "timestamp": run.started_at.isoformat() if run.started_at else None,
            "description": f"Playbook execution {run.status}",
            "status": run.status,
            "exit_code": run.exit_code,
        })

    # Real audit events (acknowledge, escalate, archive, diagnose, etc.)
    audit_result = await session.execute(
        select(InvestigationAuditEvent)
        .where(InvestigationAuditEvent.investigation_id == investigation_id)
        .order_by(InvestigationAuditEvent.created_at.asc())
    )
    audit_events = audit_result.scalars().all()

    for audit in audit_events:
        events.append({
            "type": audit.event_type,
            "timestamp": audit.created_at.isoformat() if audit.created_at else None,
            "description": audit.details or f"Investigation {audit.event_type}",
            "decided_by": audit.actor,
            "actor": audit.actor,
            "reason": audit.details,
        })

    # Synthetic fallback: only for legacy investigations with no audit rows
    if not audit_events:
        if inv.status not in ("pending", "awaiting_approval"):
            already_captured = any(
                e.get("type") == inv.status or
                (e.get("type") == "execution" and e.get("status") == inv.status)
                for e in events
            )
            if not already_captured and inv.updated_at and inv.updated_at != inv.created_at:
                events.append({
                    "type": inv.status,
                    "timestamp": inv.updated_at.isoformat(),
                    "description": f"Investigation status changed to {inv.status}",
                })

    events.sort(key=lambda x: x["timestamp"] or "")
    return {"investigation_id": investigation_id, "events": events}


# ── Debug: synthetic data injection ───────────────────────────────────────────

class InjectPerformanceAlertRequest(BaseModel):
    host: str = "ghazi"
    resource_type: str = "cpu"
    current_value: float = 95.0
    threshold: float = 90.0
    severity: str = "critical"
    affected_service: Optional[str] = None


@router.post("/debug/inject-performance-alert")
async def inject_performance_alert(
    body: InjectPerformanceAlertRequest,
    session: AsyncSession = Depends(get_session),
):
    """Inject a synthetic performance alert for end-to-end testing. DEBUG ONLY."""
    from config import get_settings
    # This endpoint is intentionally unrestricted for testing purposes.
    # It requires a specific POST body and is documented as DEBUG ONLY.

    alert_id = f"perf-debug-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    alert = {
        "id": alert_id,
        "title": f"{body.resource_type.upper()} High on {body.host}",
        "severity": body.severity,
        "source": "performance",
        "host": body.host,
        "resource_type": body.resource_type,
        "current_value": body.current_value,
        "threshold": body.threshold,
        "affected_service": body.affected_service,
    }

    # Create incident
    from response.models import Incident
    incident = Incident(
        title=alert["title"],
        description=f"Synthetic {body.resource_type} alert: {body.current_value}% (threshold: {body.threshold}%)",
        severity=body.severity,
        status="open",
        source_ips=[body.host],
    )
    session.add(incident)
    await session.flush()

    # Link alert to incident
    from response.models import Alert, AlertIncidentLink
    db_alert = Alert(
        title=alert["title"],
        severity=body.severity,
        source="performance",
        source_id=alert_id,
        hostname=body.host,
    )
    session.add(db_alert)
    await session.flush()

    link = AlertIncidentLink(alert_id=db_alert.id, incident_id=incident.id)
    session.add(link)

    # Create investigation
    from response.infrastructure_ai_engine.playbook_generator import generate_safe_playbook

    playbook_yaml = generate_safe_playbook(
        resource_type=body.resource_type,
        host=body.host,
        affected_service=body.affected_service or "unknown",
        mitigation_action="investigate",
    )

    resource_context = {
        "resource_type": body.resource_type,
        "current_value": body.current_value,
        "threshold": body.threshold,
        "unit": "%",
        "affected_host": body.host,
        "affected_service": body.affected_service,
        "affected_process": {"name": "unknown", "pid": 0, "cpu_percent": 0.0, "memory_rss": 0, "memory_percent": 0.0, "cmdline": ""},
        "top_processes": [],
        "metrics_snapshot": {},
        "historical_trend": "synthetic",
        "baseline_deviation": None,
        "root_cause_confidence": 0.0,
    }

    investigation = Investigation(
        incident_title=alert["title"],
        incident_severity=body.severity,
        incident_status="open",
        status="diagnosing",
        incident_id=alert_id,
        ai_summary=f"Synthetic {body.resource_type} anomaly on {body.host}",
        playbook_yaml=playbook_yaml,
        playbook_valid=True,
        target_host=body.host,
        target_user="ghazi",
        hostnames=body.host,
        source="performance",
        investigation_type="infrastructure",
        resource_type=body.resource_type,
        resource_context_json=resource_context,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        diagnostic_started_at=datetime.now(timezone.utc),
    )
    session.add(investigation)
    await session.flush()

    inv_alert = InvestigationAlert(
        investigation_id=investigation.id,
        alert_id=alert_id,
        alert_json=str(alert),
        severity=body.severity,
        source="performance",
        title=alert["title"],
    )
    session.add(inv_alert)

    await session.commit()

    # Auto-trigger diagnostic pipeline in background
    from pipeline.datausage.performance_orchestrator import _run_diagnostic_pipeline
    asyncio.create_task(_run_diagnostic_pipeline(investigation.id, resource_context))

    logger.info("synthetic_performance_alert_injected", investigation_id=investigation.id, alert_id=alert_id)
    return {
        "status": "injected",
        "incident_id": str(incident.id),
        "investigation_id": investigation.id,
        "alert_id": alert_id,
    }

