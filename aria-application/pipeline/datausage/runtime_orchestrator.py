"""
Runtime Security Orchestrator.

Creates and manages runtime security investigations for Falco events.
Follows the diagnostic-first pattern:
  1. Build RuntimeContext from Falco alert
  2. Generate read-only diagnostic playbook
  3. Create Investigation with investigation_type="runtime"
  4. Trigger background diagnostic pipeline
"""

import asyncio
import json
import structlog
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from config import get_settings
from response.db import AsyncSessionLocal
from response.models import Investigation, InvestigationAlert

logger = structlog.get_logger()

# Global semaphore to limit concurrent diagnostic executions and protect host resources
_DIAGNOSTIC_SEMAPHORE = asyncio.Semaphore(5)
_DIAGNOSTIC_METRICS = {
    "queued": 0,
    "running": 0,
    "completed": 0,
    "failed": 0,
}


async def create_runtime_investigation(
    alert_payload: Dict[str, Any],
    local_alert_id: Optional[str] = None,
) -> Optional[str]:
    """
    Create a runtime security investigation from a Falco alert.

    Args:
        alert_payload: The enriched alert payload from the poller
        local_alert_id: Local SQLite alert ID (optional)

    Returns:
        Investigation ID or None if creation failed
    """
    settings = get_settings()

    # Extract runtime-specific fields from the mapped alert
    runtime_context = alert_payload.get("runtime_context", {}) or {}
    runtime_category = alert_payload.get("runtime_category", "unknown")
    rule_name = alert_payload.get("rule_name") or alert_payload.get("title", "Unknown Rule")
    severity = alert_payload.get("severity", "medium")
    hostname = alert_payload.get("hostname", "unknown")
    is_intervention = alert_payload.get("is_intervention_required", False)

    # Build the runtime context object for the AI engine
    from response.runtime_ai_engine.context_builder import RuntimeContext

    if isinstance(runtime_context, dict):
        ctx = RuntimeContext.from_dict(runtime_context)
    else:
        ctx = RuntimeContext(
            runtime_category=runtime_category,
            rule_name=rule_name,
            priority=alert_payload.get("priority", "warning"),
            severity=severity,
            hostname=hostname,
        )

    # Generate diagnostic playbook
    from response.runtime_ai_engine.playbook_generator import generate_runtime_diagnostic_playbook

    try:
        playbook_yaml = generate_runtime_diagnostic_playbook(
            runtime_context=ctx.to_dict(),
            host=hostname,
            target_user=settings.ansible_remote_user or "root",
        )
    except Exception as e:
        logger.error(
            "runtime_diagnostic_playbook_generation_failed",
            rule=rule_name,
            host=hostname,
            error=str(e),
        )
        playbook_yaml = ""

    if not playbook_yaml:
        logger.warning(
            "runtime_playbook_not_generated",
            rule=rule_name,
            host=hostname,
        )
        return None

    # Build description / AI summary
    description = (
        f"Runtime security event detected on {hostname}: {rule_name}. "
        f"Category: {runtime_category}. "
        f"Intervention required: {is_intervention}."
    )

    # Create investigation record
    async with AsyncSessionLocal() as session:
        investigation = Investigation(
            incident_title=f"Runtime: {rule_name} on {hostname}",
            incident_severity=severity,
            incident_status="open",
            status="diagnosing",
            incident_id=alert_payload.get("id", ""),
            ai_summary=description,
            playbook_yaml=playbook_yaml,
            playbook_valid=True,
            evidence_json={
                "artifact_type": "runtime_diagnostic",
                "diagnostic_playbook_yaml": playbook_yaml,
                "diagnostic_is_remediation": False,
            },
            target_host=hostname,
            target_user=settings.ansible_remote_user or "root",
            hostnames=hostname,
            source="falco",
            investigation_type="runtime",
            resource_type=runtime_category,
            resource_context_json=ctx.to_dict(),
            asset_id=alert_payload.get("asset_id"),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            diagnostic_started_at=datetime.now(timezone.utc),
        )

        session.add(investigation)
        await session.flush()

        # Link the alert to the investigation
        investigation_alert = InvestigationAlert(
            investigation_id=investigation.id,
            alert_id=alert_payload.get("id", local_alert_id or ""),
            alert_json=json.dumps(alert_payload),
            severity=severity,
            source=alert_payload.get("source", "falco"),
            title=rule_name,
        )
        session.add(investigation_alert)

        await session.commit()
        await session.refresh(investigation)

        logger.info(
            "runtime_investigation_created",
            investigation_id=investigation.id,
            rule=rule_name,
            host=hostname,
            category=runtime_category,
            alert_id=local_alert_id,
        )

        # Broadcast via WebSocket
        try:
            from api.websocket import broadcast_investigation_change
            await broadcast_investigation_change(
                investigation.id,
                old_status="pending",
                new_status="diagnosing",
                details=f"Runtime diagnostic started for {rule_name} on {hostname}",
            )
        except Exception as e:
            logger.debug("ws_broadcast_runtime_investigation_failed", error=str(e))

        # Auto-trigger the diagnostic pipeline in the background with semaphore-guarded concurrency
        async def _diagnostic_with_metrics(inv_id: str, ctx_dict: dict):
            _DIAGNOSTIC_METRICS["queued"] += 1
            async with _DIAGNOSTIC_SEMAPHORE:
                _DIAGNOSTIC_METRICS["queued"] -= 1
                _DIAGNOSTIC_METRICS["running"] += 1
                try:
                    await _run_runtime_diagnostic_pipeline(inv_id, ctx_dict)
                    _DIAGNOSTIC_METRICS["completed"] += 1
                except Exception as e:
                    _DIAGNOSTIC_METRICS["failed"] += 1
                    logger.error("runtime_diagnostic_background_failed", investigation_id=inv_id, error=str(e))
                finally:
                    _DIAGNOSTIC_METRICS["running"] -= 1

        asyncio.create_task(_diagnostic_with_metrics(investigation.id, ctx.to_dict()))

        return investigation.id


async def _run_runtime_diagnostic_pipeline(
    investigation_id: str,
    runtime_context: Dict[str, Any],
) -> None:
    """
    Run the diagnostic pipeline for a runtime security investigation.

    1. Execute diagnostic playbook on target host
    2. Collect raw output
    3. Interpret output (rule-based primary, AI fallback)
    4. Update investigation with findings and set status to 'findings_ready'
    """
    from sqlalchemy import select
    from response.models import Investigation
    from response.runtime_ai_engine.diagnostic_interpreter import interpret_runtime_diagnostic
    from response.runtime_ai_engine.context_builder import RuntimeContext
    from response.runtime_ai_engine.remediation_planner import (
        build_runtime_remediation_plan,
        derive_runtime_status,
    )
    from response.ansible_exec import execute_diagnostic_playbook

    logger.info(
        "runtime_diagnostic_pipeline_started",
        investigation_id=investigation_id,
    )

    # Step 1: Run diagnostic playbook
    diagnostic_result = await execute_diagnostic_playbook(investigation_id)
    exit_code = diagnostic_result.get("exit_code", -1)
    raw_output = diagnostic_result.get("output", "")

    # Update investigation with diagnostic output
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        inv = result.scalar_one_or_none()
        if not inv:
            logger.error("runtime_diagnostic_pipeline_investigation_not_found", investigation_id=investigation_id)
            return

        inv.diagnostic_output = raw_output
        inv.diagnostic_finished_at = datetime.now(timezone.utc)
        evidence = dict(inv.evidence_json or {})
        evidence["diagnostic_result"] = {
            "status": diagnostic_result.get("status"),
            "exit_code": exit_code,
            "started_at": diagnostic_result.get("started_at"),
            "finished_at": diagnostic_result.get("finished_at"),
            "stderr": diagnostic_result.get("stderr", ""),
        }
        evidence.setdefault("diagnostic_playbook_yaml", inv.playbook_yaml)
        evidence["diagnostic_is_remediation"] = False
        inv.evidence_json = evidence
        await session.commit()

    # Step 2: Interpret diagnostic output
    findings = None
    if runtime_context:
        try:
            context = RuntimeContext.from_dict(runtime_context)
            findings = interpret_runtime_diagnostic(context, raw_output)
        except Exception as e:
            logger.error(
                "runtime_diagnostic_interpretation_failed",
                investigation_id=investigation_id,
                error=str(e),
            )

    if not findings:
        findings = {
            "detected_cause": "Diagnostic completed but interpretation unavailable",
            "confidence": 0.0,
            "severity": "medium",
            "impact": "Unknown",
            "is_temporary": False,
            "is_expected": False,
            "technical_explanation": "The diagnostic playbook ran but the interpretation step failed. Please review the raw diagnostic output.",
            "evidence": [],
            "recommendations": [
                {
                    "action": "Review raw diagnostic output manually",
                    "priority": 1,
                    "risk": "none",
                    "rationale": "Interpretation failed",
                }
            ],
            "requires_action": True,
            "expert_summary": "Diagnostic data collected but interpretation unavailable.",
        }

    # Step 3: Update investigation with findings
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        inv = result.scalar_one_or_none()
        if inv:
            plan = build_runtime_remediation_plan(
                runtime_context=runtime_context,
                findings=findings,
                diagnostic_output=raw_output,
                alert_payloads=[],
            )
            evidence = dict(inv.evidence_json or {})
            evidence["remediation_plan"] = plan
            evidence["actual_remediation_available"] = bool(plan.get("actual_remediation_available"))
            inv.evidence_json = evidence
            inv.findings_json = findings
            inv.ai_error = None
            inv.status = derive_runtime_status(plan, "findings_ready")
            inv.updated_at = datetime.now(timezone.utc)
            await session.commit()

            logger.info(
                "runtime_diagnostic_pipeline_complete",
                investigation_id=investigation_id,
                cause=findings.get("detected_cause", "")[:80],
                confidence=findings.get("confidence", 0),
                severity=findings.get("severity", "unknown"),
            )

            # Broadcast findings ready
            try:
                from api.websocket import broadcast_investigation_change
                await broadcast_investigation_change(
                    investigation_id,
                    old_status="diagnosing",
                    new_status=inv.status,
                    details=f"Runtime diagnostic findings available for {inv.incident_title}",
                )
            except Exception as e:
                logger.debug("ws_broadcast_runtime_findings_ready_failed", error=str(e))
