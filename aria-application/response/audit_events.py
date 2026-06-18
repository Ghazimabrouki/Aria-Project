"""
Standardized audit event helpers for admin override / manual remediation actions.

Every manual remediation lifecycle action writes a structured InvestigationAuditEvent
so the full override history is preserved with reason, risk level, confirmation,
playbook hash, and result.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional

from response.db import AsyncSessionLocal
from response.models import InvestigationAuditEvent


async def log_manual_remediation_action(
    investigation_id: str,
    action: str,
    previous_status: str,
    new_status: str,
    actor: str,
    reason: str,
    risk_level: Optional[str] = None,
    playbook_yaml: Optional[str] = None,
    confirmation_text: Optional[str] = None,
    result: Optional[str] = None,
) -> None:
    """
    Write a structured audit event for a manual remediation action.

    Args:
        investigation_id: UUID of the investigation.
        action: One of:
            manual_remediation_created
            manual_remediation_playbook_edited
            manual_remediation_validated
            manual_remediation_approved
            manual_remediation_declined
            manual_remediation_executed
            manual_remediation_completed
            manual_remediation_failed
            force_declined
            reopened
        previous_status: Status before the action.
        new_status: Status after the action.
        actor: "analyst" or system identifier.
        reason: Human-readable reason for the action.
        risk_level: low | medium | high | critical (optional).
        playbook_yaml: Raw YAML of the playbook (optional; hash will be stored).
        confirmation_text: Typed confirmation (optional).
        result: Result message (optional).
    """
    details_parts = [
        f"Action: {action}",
        f"Previous status: {previous_status}",
        f"New status: {new_status}",
        f"Reason: {reason}",
    ]
    if risk_level:
        details_parts.append(f"Risk level: {risk_level}")
    if playbook_yaml:
        playbook_hash = hashlib.sha256(playbook_yaml.encode("utf-8")).hexdigest()[:16]
        details_parts.append(f"Playbook hash: {playbook_hash}")
    if confirmation_text:
        details_parts.append(f"Confirmed: {confirmation_text}")
    if result:
        details_parts.append(f"Result: {result}")

    async with AsyncSessionLocal() as session:
        event = InvestigationAuditEvent(
            investigation_id=investigation_id,
            event_type=action,
            actor=actor,
            details="\n".join(details_parts),
        )
        session.add(event)
        await session.commit()


async def record_audit_event(
    session,
    investigation_id: str,
    event_type: str,
    actor: str = "system",
    details: Optional[str] = None,
    operator_label: Optional[str] = None,
    source_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    auth_mode: Optional[str] = None,
) -> None:
    """Record a simple audit event for an investigation. Commits reliably."""
    event = InvestigationAuditEvent(
        investigation_id=investigation_id,
        event_type=event_type,
        actor=actor,
        details=details or "",
        operator_label=operator_label,
        source_ip=source_ip,
        user_agent=user_agent,
        request_id=request_id,
        auth_mode=auth_mode or "internal_trusted",
    )
    session.add(event)
    await session.commit()
