"""Archive search API routes."""
import json
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import get_session
from response.models import Archive, Investigation
from response.auth import require_auth, CurrentUser


def _generate_synthetic_summary(investigation: dict, archive: Archive) -> str:
    """Generate a descriptive summary from available archive data when AI summary is missing."""
    parts = []
    title = investigation.get("incident_title") or archive.incident_title or "Untitled investigation"
    parts.append(f"**Investigation:** {title}")

    target = investigation.get("target_host")
    if target:
        parts.append(f"**Target Host:** {target}")

    source_ips = investigation.get("source_ips") or archive.source_ips
    if source_ips:
        if isinstance(source_ips, list):
            parts.append(f"**Source IPs:** {', '.join(source_ips)}")
        else:
            parts.append(f"**Source IPs:** {source_ips}")

    severity = investigation.get("incident_severity") or archive.severity
    if severity:
        parts.append(f"**Severity:** {severity.upper()}")

    fix_status = archive.fix_status
    if fix_status:
        parts.append(f"**Fix Status:** {fix_status.replace('_', ' ').title()}")

    risk = investigation.get("ai_risk")
    if risk:
        # Extract first paragraph as summary
        first_para = risk.strip().split('\n')[0]
        parts.append(f"**Risk:** {first_para}")

    alerts = investigation.get("alerts", [])
    if alerts:
        parts.append(f"**Related Alerts:** {len(alerts)}")

    return "\n\n".join(parts)


def _generate_synthetic_narrative(investigation: dict, archive: Archive) -> str:
    """Generate an attack narrative from available archive data when AI narrative is missing."""
    parts = []
    title = investigation.get("incident_title") or archive.incident_title or "the incident"
    parts.append(f"An investigation was initiated for {title}.")

    target = investigation.get("target_host")
    source_ips = investigation.get("source_ips") or archive.source_ips
    if source_ips and target:
        if isinstance(source_ips, list):
            ips_str = ", ".join(source_ips)
        else:
            ips_str = source_ips
        parts.append(f"The attack originated from {ips_str} and targeted {target}.")
    elif target:
        parts.append(f"The targeted host was {target}.")
    elif source_ips:
        if isinstance(source_ips, list):
            ips_str = ", ".join(source_ips)
        else:
            ips_str = source_ips
        parts.append(f"The attack originated from {ips_str}.")

    severity = investigation.get("incident_severity") or archive.severity
    if severity:
        parts.append(f"The incident was classified with {severity} severity.")

    playbook = investigation.get("playbook_yaml")
    if playbook:
        parts.append("A remediation playbook was generated and executed to contain the threat.")

    fix_status = archive.fix_status
    if fix_status == "likely_fixed":
        parts.append("Verification confirmed that the threat has been mitigated and no further suspicious activity was detected.")
    elif fix_status == "verified":
        parts.append("The fix was fully verified — no recurrence of the attack pattern was observed.")
    elif fix_status == "not_fixed":
        parts.append("The issue was not fully resolved — follow-up action may be required.")
    elif fix_status == "declined":
        parts.append("The remediation playbook was declined by the analyst.")
    else:
        parts.append(f"Final status: {fix_status.replace('_', ' ').title()}.")

    return " ".join(parts)


async def _fetch_upstream_incident(incident_id: str) -> Optional[dict]:
    """Try to fetch incident details from upstream OpenSOAR if local data is missing."""
    if not incident_id:
        return None
    try:
        from pipeline.sender import client
        await client.authenticate()
        incident = await client.get_incident(incident_id)
        if incident:
            return {
                "id": incident.get("id", incident_id),
                "title": incident.get("title", "Unknown Incident"),
                "description": incident.get("description", ""),
                "severity": incident.get("severity", "medium"),
                "status": incident.get("status", "unknown"),
                "source_ips": incident.get("source_ips", []),
                "hostnames": incident.get("hostnames", []),
                "created_at": incident.get("created_at"),
                "updated_at": incident.get("updated_at"),
                "resolved_at": incident.get("resolved_at"),
                "assigned_username": incident.get("assigned_username"),
                "alert_count": incident.get("alert_count", 0),
                "tags": incident.get("tags", []),
            }
    except Exception:
        pass
    return None

router = APIRouter(prefix="/api/v1/archives", tags=["archives"])


@router.get("")
async def list_archives(
    severity: Optional[str] = Query(None),
    fix_status: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    time_from: Optional[str] = Query(None),
    time_to: Optional[str] = Query(None),
    mitre_tactic: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset via linked investigation"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_auth),
):
    """Search archived investigations."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    # Base query — join Investigation when asset_id filter is needed
    if asset_id:
        q = (
            select(Archive)
            .join(Investigation, Archive.investigation_id == Investigation.id)
            .where(Investigation.asset_id == asset_id)
            .order_by(Archive.archived_at.desc())
        )
        total_q = (
            select(func.count(Archive.id))
            .join(Investigation, Archive.investigation_id == Investigation.id)
            .where(Investigation.asset_id == asset_id)
        )
    else:
        q = select(Archive).order_by(Archive.archived_at.desc())
        total_q = select(func.count(Archive.id))

    if severity:
        q = q.where(Archive.severity == severity)
        total_q = total_q.where(Archive.severity == severity)
    if fix_status:
        q = q.where(Archive.fix_status == fix_status)
        total_q = total_q.where(Archive.fix_status == fix_status)
    if source_ip:
        q = q.where(Archive.source_ips.contains(source_ip))
        total_q = total_q.where(Archive.source_ips.contains(source_ip))
    if search:
        search_term = f"%{search}%"
        q = q.where(
            or_(
                Archive.incident_title.ilike(search_term),
                Archive.source_ips.ilike(search_term),
            )
        )
        total_q = total_q.where(
            or_(
                Archive.incident_title.ilike(search_term),
                Archive.source_ips.ilike(search_term),
            )
        )
    if time_from:
        try:
            from datetime import datetime as _dt
            from datetime import timezone as _tz
            dt_from = _dt.fromisoformat(time_from.replace("Z", "+00:00"))
            q = q.where(Archive.archived_at >= dt_from)
            total_q = total_q.where(Archive.archived_at >= dt_from)
        except Exception:
            pass
    if time_to:
        try:
            from datetime import datetime as _dt
            from datetime import timezone as _tz
            dt_to = _dt.fromisoformat(time_to.replace("Z", "+00:00"))
            q = q.where(Archive.archived_at <= dt_to)
            total_q = total_q.where(Archive.archived_at <= dt_to)
        except Exception:
            pass
    if mitre_tactic:
        q = q.where(Archive.mitre_tactics.ilike(f"%{mitre_tactic}%"))
        total_q = total_q.where(Archive.mitre_tactics.ilike(f"%{mitre_tactic}%"))

    total = (await session.execute(total_q)).scalar_one()
    result = await session.execute(q.offset(offset).limit(limit))
    archives = result.scalars().all()

    return {
        "archives": [
            {
                "id": a.id,
                "investigation_id": a.investigation_id,
                "incident_id": a.incident_id,
                "incident_title": a.incident_title,
                "severity": a.severity,
                "fix_status": a.fix_status,
                "fix_detail": a.fix_detail,
                "source_ips": a.source_ips,
                "hostnames": a.hostnames,
                "mitre_tactics": a.mitre_tactics,
                "archived_at": a.archived_at.isoformat(),
            }
            for a in archives
        ],
        "total": total,
    }


@router.get("/stats")
async def archive_stats(
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset via linked investigation"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_auth),
):
    """Aggregated statistics from all archived investigations."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    if asset_id:
        total_q = (
            select(func.count(Archive.id))
            .join(Investigation, Archive.investigation_id == Investigation.id)
            .where(Investigation.asset_id == asset_id)
        )
        fix_q = (
            select(Archive.fix_status, func.count(Archive.id))
            .join(Investigation, Archive.investigation_id == Investigation.id)
            .where(Investigation.asset_id == asset_id)
            .group_by(Archive.fix_status)
        )
        sev_q = (
            select(Archive.severity, func.count(Archive.id))
            .join(Investigation, Archive.investigation_id == Investigation.id)
            .where(Investigation.asset_id == asset_id)
            .group_by(Archive.severity)
        )
    else:
        total_q = select(func.count(Archive.id))
        fix_q = select(Archive.fix_status, func.count(Archive.id)).group_by(Archive.fix_status)
        sev_q = select(Archive.severity, func.count(Archive.id)).group_by(Archive.severity)

    total = (await session.execute(total_q)).scalar_one()

    # Fix status breakdown
    fix_result = await session.execute(fix_q)
    fix_counts = {row[0]: row[1] for row in fix_result.all()}

    # Severity breakdown
    sev_result = await session.execute(sev_q)
    sev_counts = {row[0]: row[1] for row in sev_result.all()}

    successful_statuses = {"likely_fixed", "verified", "archived_fixed"}
    fixed = sum(fix_counts.get(s, 0) for s in successful_statuses)
    fix_rate = round(fixed / total * 100, 1) if total > 0 else 0

    return {
        "total_archived": total,
        "fix_success_rate_pct": fix_rate,
        "by_fix_status": fix_counts,
        "by_severity": sev_counts,
    }


@router.get("/{archive_id}")
async def get_archive(
    archive_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get full archived investigation context."""
    result = await session.execute(
        select(Archive).where(Archive.id == archive_id)
    )
    archive = result.scalar_one_or_none()
    if not archive:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Archive not found")

    try:
        full_context = json.loads(archive.full_context_json)
    except Exception:
        full_context = {}

    # Normalize legacy archive structures:
    # Old archives stored AI fields under "ai_investigation" and incident under "local_incident"
    investigation = full_context.get("investigation") or {}
    ai_inv = full_context.get("ai_investigation")
    if ai_inv and isinstance(ai_inv, dict):
        investigation["ai_summary"] = ai_inv.get("summary") or investigation.get("ai_summary")
        investigation["ai_narrative"] = ai_inv.get("attack_narrative") or investigation.get("ai_narrative")
        investigation["ai_risk"] = ai_inv.get("risk_assessment") or investigation.get("ai_risk")
        investigation["playbook_yaml"] = ai_inv.get("playbook_yaml") or investigation.get("playbook_yaml")
        investigation["playbook_valid"] = ai_inv.get("playbook_valid") or investigation.get("playbook_valid")
        full_context["investigation"] = investigation

    if "local_incident" in full_context and "incident" not in full_context:
        full_context["incident"] = full_context.pop("local_incident")

    # Generate synthetic AI summary/narrative if originals are empty
    if not investigation.get("ai_summary"):
        investigation["ai_summary"] = _generate_synthetic_summary(investigation, archive)
    if not investigation.get("ai_narrative"):
        investigation["ai_narrative"] = _generate_synthetic_narrative(investigation, archive)

    # Fetch upstream incident if local data is missing but incident_id exists
    incident = full_context.get("incident")
    if not incident and archive.incident_id:
        from config import get_settings
        if get_settings().upstream_enabled:
            upstream_incident = await _fetch_upstream_incident(archive.incident_id)
            if upstream_incident:
                full_context["incident"] = upstream_incident

    return {
        "id": archive.id,
        "investigation_id": archive.investigation_id,
        "incident_id": archive.incident_id,
        "incident_title": archive.incident_title,
        "severity": archive.severity,
        "fix_status": archive.fix_status,
        "fix_detail": archive.fix_detail,
        "source_ips": archive.source_ips,
        "hostnames": archive.hostnames,
        "mitre_tactics": archive.mitre_tactics,
        "archived_at": archive.archived_at.isoformat(),
        "full_context": full_context,
    }


@router.get("/{archive_id}/original-incident")
async def get_archive_original_incident(
    archive_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get OpenSOAR incident at archive time."""
    result = await session.execute(
        select(Archive).where(Archive.id == archive_id)
    )
    archive = result.scalar_one_or_none()
    if not archive:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Archive not found")
    
    if archive.full_context_json:
        context = json.loads(archive.full_context_json)
        return {"original_incident": context.get("incident")}
    
    return {"note": "Original incident data not preserved"}


@router.get("/{archive_id}/alerts")
async def get_archive_alerts(
    archive_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get alert snapshots from archive."""
    result = await session.execute(
        select(Archive).where(Archive.id == archive_id)
    )
    archive = result.scalar_one_or_none()
    if not archive or not archive.full_context_json:
        return {"alerts": [], "total": 0}
    
    context = json.loads(archive.full_context_json)
    return {
        "alerts": context.get("alerts", []),
        "total": len(context.get("alerts", []))
    }


@router.get("/by-investigation/{investigation_id}")
async def get_archive_by_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Find archive for specific investigation."""
    result = await session.execute(
        select(Archive).where(Archive.investigation_id == investigation_id)
    )
    archive = result.scalar_one_or_none()
    
    if not archive:
        return {"exists": False}
    
    return {
        "exists": True,
        "archive_id": archive.id,
        "investigation_id": archive.investigation_id,
        "incident_id": archive.incident_id,
        "incident_title": archive.incident_title,
        "fix_status": archive.fix_status,
        "fix_detail": archive.fix_detail,
        "archived_at": archive.archived_at.isoformat()
    }

