"""ARIA internal alerting system for SOC workflow anomalies."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select as sa_select

from response.models import AriaAlert


async def create_aria_alert(
    session: AsyncSession,
    alert_type: str,
    severity: str,
    investigation_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    title: str = "",
    description: Optional[str] = None,
    acknowledged: bool = False,
) -> AriaAlert:
    """Create a new ARIA alert."""
    alert = AriaAlert(
        alert_type=alert_type,
        severity=severity,
        investigation_id=investigation_id,
        incident_id=incident_id,
        title=title,
        description=description,
        acknowledged=acknowledged,
        created_at=datetime.now(timezone.utc),
    )
    session.add(alert)
    await session.commit()
    return alert


async def alert_on_regeneration_requested(
    session: AsyncSession,
    investigation,
    decided_by: str,
    reason: str,
) -> None:
    """Create an ARIA alert when playbook regeneration is requested."""
    await create_aria_alert(
        session,
        alert_type="regeneration_requested",
        severity="medium",
        investigation_id=investigation.id if investigation else None,
        title="Playbook Regeneration Requested",
        description=f"Regeneration requested by {decided_by}. Reason: {reason}",
    )


async def alert_on_unsafe_playbook(
    session: AsyncSession,
    investigation,
    reasons: list,
) -> None:
    """Create an ARIA alert when an unsafe playbook is detected."""
    reasons_str = "; ".join(str(r) for r in reasons) if reasons else "Unknown safety concern"
    await create_aria_alert(
        session,
        alert_type="unsafe_playbook",
        severity="high",
        investigation_id=investigation.id if investigation else None,
        title="Unsafe Playbook Detected",
        description=f"Playbook failed safety checks: {reasons_str}",
    )


async def alert_on_ai_quality(
    session: AsyncSession,
    investigation,
) -> None:
    """Create an ARIA alert for AI quality issues."""
    await create_aria_alert(
        session,
        alert_type="ai_quality_failed",
        severity="medium",
        investigation_id=investigation.id if investigation else None,
        title="AI Quality Check Failed",
        description="AI-generated playbook or analysis failed quality validation.",
    )


async def alert_on_execution_failed(
    session: AsyncSession,
    investigation,
    playbook_run=None,
) -> None:
    """Create an ARIA alert when playbook execution fails."""
    run_info = f" Run ID: {playbook_run.id}" if playbook_run else ""
    await create_aria_alert(
        session,
        alert_type="execution_failed",
        severity="critical",
        investigation_id=investigation.id if investigation else None,
        title="Playbook Execution Failed",
        description=f"Remediation execution failed for investigation {investigation.id if investigation else 'unknown'}.{run_info}",
    )
