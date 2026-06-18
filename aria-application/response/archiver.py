"""
Archive System.

Called when an investigation is fully resolved (fix verified or declined).
Assembles a complete JSON record of everything that happened and stores it
in the `archives` table for future reference and AI assistant queries.
"""
import json
from datetime import datetime, timezone
from typing import Optional, Any

import structlog
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from response.db import AsyncSessionLocal
from response.models import (
    Investigation, InvestigationAlert, PlaybookApproval,
    PlaybookRun, FixVerification, Archive, Incident
)

logger = structlog.get_logger()


async def archive_investigation(investigation_id: str, fix_status: str = "unknown"):
    """
    Build full context snapshot and save to archives table.
    Safe to call multiple times — skips if already archived.
    """
    async with AsyncSessionLocal() as session:
        # Check if already archived
        existing = await session.execute(
            select(Archive).where(Archive.investigation_id == investigation_id)
        )
        if existing.scalar_one_or_none():
            logger.debug("archive_already_exists", investigation_id=investigation_id)
            return

        # Load full investigation with all relations
        result = await session.execute(
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .options(
                selectinload(Investigation.alerts),
                selectinload(Investigation.approval),
                selectinload(Investigation.run),
                selectinload(Investigation.verification),
            )
        )
        inv = result.scalar_one_or_none()
        if not inv:
            logger.error("archive_investigation_not_found", investigation_id=investigation_id)
            return

        # Load linked local incident if exists
        incident_result = await session.execute(
            select(Incident).where(Incident.id == inv.incident_id)
        )
        local_incident = incident_result.scalar_one_or_none()

        # Build full context
        context = _build_full_context(inv, incident=local_incident)
        context_json = json.dumps(context, default=str)

        # Determine final fix status
        if inv.verification:
            fix_status = inv.verification.status
        elif inv.approval and inv.approval.decision == "declined":
            fix_status = "declined"

        fix_detail = inv.verification.detail if inv.verification else None

        archive = Archive(
            investigation_id=investigation_id,
            incident_id=inv.incident_id,
            full_context_json=context_json,
            source_ips=inv.source_ips,
            hostnames=inv.hostnames,
            mitre_tactics=inv.mitre_tactics,
            severity=inv.incident_severity,
            fix_status=fix_status,
            incident_title=inv.incident_title or None,
            fix_detail=fix_detail,
            archived_at=datetime.now(timezone.utc),
        )
        session.add(archive)

        # Update investigation status to archived
        from sqlalchemy import update
        await session.execute(
            update(Investigation)
            .where(Investigation.id == investigation_id)
            .values(status="archived", updated_at=datetime.now(timezone.utc))
        )

        # Archive linked local incident
        if local_incident:
            local_incident.status = "archived"
            local_incident.archived_at = datetime.now(timezone.utc)
            if fix_status in ("likely_fixed", "verified"):
                local_incident.status = "resolved"
                local_incident.resolved_at = datetime.now(timezone.utc)
                local_incident.resolved_by = "auto"
            await session.commit()

            # Store SOAR actions summary on incident
            soar_actions = local_incident.soar_actions or {}
            soar_actions["archive_summary"] = {
                "investigation_id": investigation_id,
                "fix_status": fix_status,
                "fix_detail": fix_detail,
                "archived_at": datetime.now(timezone.utc).isoformat(),
                "playbook_run": context.get("playbook_run"),
            }
            local_incident.soar_actions = soar_actions
            await session.commit()

        logger.info(
            "investigation_archived",
            investigation_id=investigation_id,
            incident_id=inv.incident_id,
            fix_status=fix_status,
        )


def _build_full_context(inv: Investigation, incident: Optional[Any] = None) -> dict:
    """Assemble the complete investigation record."""
    # Parse alert JSONs
    alerts_data = []
    for a in inv.alerts:
        try:
            alert_obj = json.loads(a.alert_json)
        except Exception:
            alert_obj = {"id": a.alert_id, "title": a.title, "severity": a.severity}
        alerts_data.append(alert_obj)

    context = {
        "investigation": {
            "id": inv.id,
            "incident_id": inv.incident_id,
            "incident_title": inv.incident_title,
            "incident_severity": inv.incident_severity,
            "target_host": inv.target_host,
            "source_ips": inv.source_ips,
            "hostnames": inv.hostnames,
            "mitre_tactics": inv.mitre_tactics,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
            "ai_summary": inv.ai_summary,
            "ai_narrative": inv.ai_narrative,
            "ai_risk": inv.ai_risk,
            "playbook_yaml": inv.playbook_yaml,
            "playbook_valid": inv.playbook_valid,
        },
        "alerts": alerts_data,
        "approval": None,
        "playbook_run": None,
        "fix_verification": None,
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "source_ips": incident.source_ips,
            "hostnames": incident.hostnames,
            "soar_actions": incident.soar_actions,
            "resolved_by": incident.resolved_by,
            "assigned_username": incident.assigned_username,
            "alert_count": len(incident.alert_ids) if incident.alert_ids else 0,
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            "archived_at": incident.archived_at.isoformat() if incident.archived_at else None,
            "closed_at": incident.resolved_at.isoformat() if incident.resolved_at else incident.archived_at.isoformat() if incident.archived_at else None,
            "created_at": incident.created_at.isoformat() if incident.created_at else None,
            "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        } if incident else None,
        "archived_at": datetime.now(timezone.utc).isoformat(),
    }

    if inv.approval:
        context["approval"] = {
            "decision": inv.approval.decision,
            "decided_by": inv.approval.decided_by,
            "decided_at": inv.approval.decided_at.isoformat() if inv.approval.decided_at else None,
            "reason": inv.approval.reason,
            "used_edited_playbook": bool(inv.approval.edited_playbook),
        }

    if inv.run:
        context["playbook_run"] = {
            "status": inv.run.status,
            "exit_code": inv.run.exit_code,
            "output": inv.run.output,
            "started_at": inv.run.started_at.isoformat() if inv.run.started_at else None,
            "finished_at": inv.run.finished_at.isoformat() if inv.run.finished_at else None,
            "duration_seconds": (
                int((inv.run.finished_at - inv.run.started_at).total_seconds())
                if inv.run.finished_at and inv.run.started_at
                else None
            ),
        }

    if inv.verification:
        context["fix_verification"] = {
            "status": inv.verification.status,
            "new_alerts_found": inv.verification.new_alerts_found,
            "checked_at": inv.verification.checked_at.isoformat() if inv.verification.checked_at else None,
            "detail": inv.verification.detail,
        }

    return context
