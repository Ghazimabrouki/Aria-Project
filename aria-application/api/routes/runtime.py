"""
Runtime Security API routes.

Dedicated endpoints for Falco runtime security investigations.
"""

import asyncio
import json
from typing import Optional, Any
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from response.db import get_session, AsyncSessionLocal
from response.models import Investigation, InvestigationAlert, PlaybookApproval, Alert, MonitoredAsset
from response.auth import require_auth, CurrentUser
from response.runtime_ai_engine.remediation_planner import (
    build_runtime_remediation_plan,
    derive_runtime_status,
    has_corrective_actions,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/runtime", tags=["runtime"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class RuntimeInvestigationSummary(BaseModel):
    id: str
    incident_id: str
    incident_title: str
    incident_severity: str
    status: str
    investigation_type: str
    target_host: Optional[str]
    resource_type: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AcknowledgeRuntimeRequest(BaseModel):
    decided_by: str = "analyst"


class EscalateRuntimeRequest(BaseModel):
    decided_by: str = "analyst"
    reason: Optional[str] = None


class ApproveRuntimeRequest(BaseModel):
    decided_by: str = "analyst"
    acknowledge_risk: bool = False


class DeclineRuntimeRequest(BaseModel):
    decided_by: str = "analyst"
    reason: Optional[str] = None


# ── Admin Override / Manual Remediation schemas ───────────────────────────────

class ManualRemediationCreateRequest(BaseModel):
    admin_reason: str = Field(..., min_length=10)
    business_justification: str = Field(..., min_length=10)
    target_scope_confirmation: str = Field(..., min_length=5)
    expected_impact: str = Field(..., min_length=5)
    rollback_plan_yaml: str = Field(..., min_length=50)
    verification_plan_yaml: str = Field(..., min_length=20)
    decided_by: str = "analyst"


class ManualRemediationPlaybookPatch(BaseModel):
    playbook_yaml: str = Field(..., min_length=50)
    decided_by: str = "analyst"


class ManualRemediationApproveRequest(BaseModel):
    confirmation_text: str = Field(..., pattern=r"^I UNDERSTAND THE RISK$")
    decided_by: str = "analyst"


class ForceDeclineRequest(BaseModel):
    reason: str = Field(..., min_length=10)
    decided_by: str = "analyst"


class ReopenRequest(BaseModel):
    reason: str = Field(..., min_length=10)
    decided_by: str = "analyst"


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_investigation_or_404(
    investigation_id: str, session: AsyncSession
) -> Investigation:
    result = await session.execute(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .options(
            selectinload(Investigation.run),
            selectinload(Investigation.verification),
            selectinload(Investigation.approval),
        )
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if inv.investigation_type != "runtime":
        raise HTTPException(
            status_code=400,
            detail="This investigation is not a runtime security investigation",
        )
    return inv


def _extract_runtime_context(inv: Investigation) -> Optional[dict]:
    """Extract runtime context from investigation."""
    if inv.resource_context_json:
        return inv.resource_context_json
    return None


def _extract_suggested_actions(inv: Investigation) -> list:
    """Extract suggested actions from investigation findings."""
    findings = inv.findings_json or {}
    return findings.get("recommendations", [])


def _stored_plan(inv: Investigation) -> Optional[dict]:
    evidence = inv.evidence_json or {}
    if isinstance(evidence, dict):
        plan = evidence.get("remediation_plan")
        if isinstance(plan, dict):
            return plan
    return None


async def _alert_payloads(investigation_id: str, session: AsyncSession) -> list[dict[str, Any]]:
    result = await session.execute(
        select(InvestigationAlert).where(
            InvestigationAlert.investigation_id == investigation_id
        )
    )
    alerts = result.scalars().all()
    payloads = []
    for alert in alerts:
        try:
            payloads.append(json.loads(alert.alert_json))
        except Exception:
            payloads.append({"alert_id": alert.alert_id, "title": alert.title, "severity": alert.severity})
    return payloads


async def _runtime_plan(inv: Investigation, session: AsyncSession) -> dict:
    stored = _stored_plan(inv)
    if stored:
        if inv.status == "awaiting_approval" and not has_corrective_actions(stored):
            stored = dict(stored)
            stored["legacy_inconsistent_state"] = True
            stored["decision_reason"] = (
                "Historical/pre-fix record: case is awaiting approval but has no "
                "evidence-backed corrective actions. Approval is blocked."
            )
        return stored
    plan = build_runtime_remediation_plan(
        runtime_context=inv.resource_context_json or {},
        findings=inv.findings_json or {},
        diagnostic_output=inv.diagnostic_output or "",
        alert_payloads=await _alert_payloads(inv.id, session),
        verification_history=_verification_payload(inv),
    )
    if inv.status == "awaiting_approval" and not has_corrective_actions(plan):
        plan["legacy_inconsistent_state"] = True
        plan["decision_reason"] = (
            "Historical/pre-fix record: case is awaiting approval but has no "
            "evidence-backed corrective actions. Approval is blocked."
        )
    return plan


def _verification_payload(inv: Investigation) -> dict:
    verification = getattr(inv, "verification", None)
    if not verification:
        return {}
    return {
        "status": verification.status,
        "new_alerts_found": verification.new_alerts_found,
        "checked_at": verification.checked_at.isoformat() if verification.checked_at else None,
        "detail": verification.detail,
    }


def _run_payload(inv: Investigation) -> Optional[dict]:
    run = getattr(inv, "run", None)
    if not run:
        return None
    return {
        "status": run.status,
        "exit_code": run.exit_code,
        "output": run.output,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "current_phase": run.current_phase,
        "phases": run.phases_json or {},
    }


def _available_actions(inv: Investigation, plan: dict) -> dict:
    corrective = has_corrective_actions(plan)
    status = derive_runtime_status(plan, inv.status) if inv.status == "findings_ready" else inv.status

    # Manual remediation eligibility
    manual_eligible = status in {
        "observe", "findings_ready", "manual_review_required",
        "acknowledged", "archived_not_fixed", "declined", "archived", "closed_with_risk",
    }
    manual_draft = status == "manual_remediation_draft"
    manual_validating = status == "manual_remediation_validating"
    manual_awaiting = status == "manual_remediation_awaiting_approval"
    manual_executing = status in {"manual_remediation_approved", "manual_remediation_executing", "running"}

    return {
        "acknowledge": status in {"findings_ready", "observe", "manual_review_required"},
        "escalate": status in {"findings_ready", "manual_review_required"} and (
            corrective or plan.get("decision") == "manual_review_required"
        ),
        "approve_run": status == "awaiting_approval" and corrective,
        "decline": status == "awaiting_approval",
        "rediagnose": status in {
            "findings_ready",
            "observe",
            "manual_review_required",
            "remediation_failed",
            "verification_failed",
            "failed",
        },
        "archive": status in {
            "acknowledged",
            "observe",
            "manual_review_required",
            "verified",
            "fixed",
            "not_fixed",
            "inconclusive",
            "remediation_failed",
            "verification_failed",
            "declined",
            "failed",
            "closed_with_risk",
        },
        # Admin override actions
        "create_manual_remediation": manual_eligible and not (manual_draft or manual_validating or manual_awaiting or manual_executing),
        "edit_manual_playbook": manual_draft or manual_validating,
        "validate_manual_playbook": manual_draft or manual_validating,
        "approve_manual_remediation": manual_awaiting,
        "force_decline": status not in {"archived_fixed", "closed_with_risk"},
        "reopen": status in {"archived_not_fixed", "archived_fixed", "declined", "archived", "closed_with_risk"},
        "reason": plan.get("decision_reason"),
    }


def _apply_data_quality_guards(ctx: dict) -> dict:
    """Recover corrupted fields from proc_exepath when possible.

    Mutates ctx in place with recovered values so downstream display
    shows clean data. Only returns quality entries for fields that
    could NOT be recovered.
    """
    import re

    quality = {}
    proc_name = ctx.get("proc_name")
    proc_exepath = ctx.get("proc_exepath")
    recovered_name = None

    if proc_name and isinstance(proc_name, str) and proc_name.isdigit():
        # Try to recover real process name from executable path
        if proc_exepath and isinstance(proc_exepath, str):
            recovered_name = proc_exepath.split("/")[-1]
            if recovered_name:
                ctx["proc_name"] = recovered_name
        if recovered_name:
            # Recovered — do not add to quality warnings
            pass
        else:
            quality["proc_name"] = {
                "value": proc_name,
                "status": "corrupted",
                "reason": "Historical Falco event contained a numeric process name (likely a PID or mapping bug). Do not trust this value.",
            }

    proc_cmdline = ctx.get("proc_cmdline")
    if proc_cmdline and isinstance(proc_cmdline, str) and proc_cmdline.strip() and proc_cmdline.strip()[0].isdigit():
        # Try to recover cmdline by replacing leading numeric token with recovered exe name
        exe_name = recovered_name or (proc_exepath.split("/")[-1] if proc_exepath and isinstance(proc_exepath, str) else "")
        recovered_cmdline = None
        if exe_name:
            recovered_cmdline = re.sub(r"^(\d+\b)", exe_name, proc_cmdline.strip(), count=1)
            if recovered_cmdline != proc_cmdline.strip():
                ctx["proc_cmdline"] = recovered_cmdline
        if recovered_cmdline:
            # Recovered — do not add to quality warnings
            pass
        else:
            quality["proc_cmdline"] = {
                "value": proc_cmdline,
                "status": "corrupted",
                "reason": "Historical Falco event contained a command line starting with a numeric value. Do not trust this value.",
            }
    return quality


def _context_sections(ctx: dict, plan: dict) -> dict:
    quality = _apply_data_quality_guards(ctx)
    return {
        "host": {
            "hostname": ctx.get("hostname"),
            "target_host": plan.get("target_host"),
            "scope_reason": plan.get("scope_reason"),
        },
        "container": {
            "container_id": ctx.get("container_id"),
            "container_name": ctx.get("container_name"),
            "image": ctx.get("container_image_repository"),
            "image_tag": ctx.get("container_image_tag"),
        },
        "kubernetes": {
            "namespace": ctx.get("k8s_ns_name"),
            "pod": ctx.get("k8s_pod_name"),
        },
        "filesystem": {
            "path": ctx.get("fd_name"),
            "type": ctx.get("fd_type"),
        },
        "process_namespace": {
            "process": ctx.get("proc_name"),
            "pid": ctx.get("proc_pid"),
            "parent": ctx.get("proc_pname"),
            "ancestors": ctx.get("proc_ancestors") or [],
            "_data_quality": quality,
        },
        "network": plan.get("target_network_endpoint") or {},
    }


def _diagnostic_summary(inv: Investigation, plan: dict, ctx: dict | None = None) -> dict:
    evidence = inv.evidence_json or {}
    diagnostic_result = evidence.get("diagnostic_result") if isinstance(evidence, dict) else {}
    findings = inv.findings_json or {}
    output = inv.diagnostic_output or ""
    exit_code = (diagnostic_result or {}).get("exit_code")
    status = (diagnostic_result or {}).get("status")
    ctx = ctx or {}

    # Determine target context
    container_id = ctx.get("container_id")
    k8s_pod = ctx.get("k8s_pod_name")
    hostname = ctx.get("hostname") or inv.target_host or "unknown"
    if k8s_pod:
        target_context = "kubernetes"
        target = f"pod {k8s_pod} in namespace {ctx.get('k8s_ns_name', 'unknown')}"
    elif container_id:
        target_context = "container"
        target = ctx.get("container_name") or container_id[:12]
    else:
        target_context = "host"
        target = hostname

    # Main finding & conclusion
    main_finding = findings.get("detected_cause") or findings.get("expert_summary") or "No detailed finding available."
    conclusion = findings.get("expert_summary") or findings.get("technical_explanation") or ""
    confidence = findings.get("confidence")
    threat = findings.get("threat_assessment") or "unknown"

    # Build checked items from evidence + context
    checked_items = []
    evidence_list = findings.get("evidence") or []
    for ev in evidence_list:
        checked_items.append({
            "name": ev.get("source", "Evidence item").replace("_", " ").title(),
            "status": "checked",
            "result": ev.get("finding", ""),
            "important_values": {},
        })

    # Add context-based checks
    if ctx.get("fd_name"):
        checked_items.append({
            "name": "Target file details",
            "status": "checked",
            "result": f"File path inspected: {ctx['fd_name']}",
            "important_values": {"path": ctx["fd_name"]},
        })
    if ctx.get("proc_name"):
        checked_items.append({
            "name": "Process context",
            "status": "checked",
            "result": f"Process {ctx['proc_name']} (PID {ctx.get('proc_pid', 'unknown')}) was active",
            "important_values": {"process": ctx["proc_name"], "pid": ctx.get("proc_pid")},
        })
    if container_id:
        checked_items.append({
            "name": "Container context",
            "status": "checked",
            "result": f"Container {ctx.get('container_name') or container_id[:12]} inspected",
            "important_values": {"container": ctx.get("container_name"), "image": ctx.get("container_image_repository")},
        })
    if ctx.get("hostname"):
        checked_items.append({
            "name": "Host context",
            "status": "checked",
            "result": f"Host {ctx['hostname']} was the target",
            "important_values": {"hostname": ctx["hostname"]},
        })

    # Extract key evidence facts from output + findings
    evidence_extracted: dict[str, Any] = {
        "file_exists": None,
        "file_permissions": None,
        "file_hash": None,
        "service_status": None,
        "failed_units_count": None,
        "recent_errors_count": None,
        "process_running": None,
        "container_inspected": bool(container_id),
        "command_execution_status": status,
    }
    out_lower = output.lower()
    if "file exists" in out_lower or "exists" in out_lower:
        evidence_extracted["file_exists"] = True
    elif "no such file" in out_lower or "file missing" in out_lower:
        evidence_extracted["file_exists"] = False
    if "sha256sum" in out_lower or "sha256" in out_lower:
        # Try to extract hash
        import re as _re
        m = _re.search(r"[a-f0-9]{64}", output)
        if m:
            evidence_extracted["file_hash"] = m.group(0)
    if "systemctl" in out_lower:
        failed = out_lower.count("failed") + out_lower.count("dead")
        evidence_extracted["failed_units_count"] = failed
        if "active (running)" in out_lower:
            evidence_extracted["service_status"] = "active"
        elif "inactive" in out_lower:
            evidence_extracted["service_status"] = "inactive"
    if ctx.get("proc_name"):
        evidence_extracted["process_running"] = True

    # Diagnostic gaps
    gaps = []
    if plan.get("decision") == "manual_review_required":
        gaps.append("No trusted baseline found — automatic restore is unsafe without a known-good reference.")
    if evidence_extracted["file_hash"] is None and ctx.get("fd_name"):
        gaps.append("File hash was not collected or sha256sum was unavailable.")
    if container_id and "nsenter" not in out_lower and "docker exec" not in out_lower:
        gaps.append("Container namespace was not explicitly validated during diagnostic.")
    if "command not found" in out_lower or "not installed" in out_lower:
        gaps.append("Some diagnostic tools were missing on the target host.")
    if exit_code not in (0, None):
        gaps.append("Diagnostic playbook exited with an error; some evidence may be incomplete.")
    if not output.strip():
        gaps.append("No diagnostic output was captured.")
    if not findings:
        gaps.append("No structured findings were produced from the diagnostic output.")

    # Meaning / interpretation
    meaning = ""
    if threat in {"expected", "expected_administrative_activity"}:
        meaning = "This diagnostic confirms the event occurred, but the activity appears expected or administrative."
    elif threat == "suspicious":
        meaning = "This diagnostic confirms the event occurred. The activity is flagged as suspicious and requires review."
    elif threat == "malicious":
        meaning = "This diagnostic confirms the event occurred. The activity is assessed as potentially malicious."
    elif threat == "observe":
        meaning = "This diagnostic collected evidence. No immediate threat was identified, but continued monitoring is advised."
    else:
        meaning = "This diagnostic confirms the event occurred, but does not prove malicious intent."

    if plan.get("decision") == "manual_review_required":
        meaning += " No trusted baseline was found, so automatic remediation is unsafe."
    elif not has_corrective_actions(plan):
        meaning += " This is evidence-only. No corrective action was applied."

    # Next steps
    next_steps = []
    for rec in findings.get("recommendations") or []:
        action = rec.get("action", "")
        if action:
            next_steps.append(action)
    if not next_steps and plan.get("next_manual_steps"):
        next_steps = plan["next_manual_steps"]
    if not next_steps:
        if plan.get("decision") == "manual_review_required":
            next_steps = ["Review the evidence and determine if the activity was expected.", "Compare affected files or services with a known-good baseline."]
        elif threat in {"expected", "expected_administrative_activity", "observe"}:
            next_steps = ["Continue monitoring. No immediate action is required."]
        else:
            next_steps = ["Review the investigation details and available evidence."]

    return {
        "label": "Diagnostic Playbook",
        "artifact_type": "evidence_collection",
        "is_remediation": False,
        "status": status,
        "exit_code": exit_code,
        "started_at": (diagnostic_result or {}).get("started_at")
        or (inv.diagnostic_started_at.isoformat() if inv.diagnostic_started_at else None),
        "finished_at": (diagnostic_result or {}).get("finished_at")
        or (inv.diagnostic_finished_at.isoformat() if inv.diagnostic_finished_at else None),
        "message": "Evidence collected only. No corrective remediation was applied by this playbook.",
        "error": inv.ai_error if inv.status in {"diagnosing", "findings_ready", "manual_review_required"} else None,
        # New human-readable fields
        "target_context": target_context,
        "target": target,
        "main_finding": main_finding,
        "conclusion": conclusion,
        "confidence": confidence,
        "threat_assessment": threat,
        "checked_items": checked_items,
        "evidence_extracted": evidence_extracted,
        "diagnostic_gaps": gaps,
        "meaning": meaning,
        "next_steps": next_steps,
    }


def _outcome_summary(inv: Investigation, plan: dict) -> dict:
    verification = _verification_payload(inv)
    corrective = has_corrective_actions(plan)
    fixed = inv.status in {"verified", "fixed", "archived_fixed"} or verification.get("status") in {
        "likely_fixed",
        "verified",
    }
    unresolved = inv.status in {"not_fixed", "archived_not_fixed", "closed_with_risk"} or verification.get("status") in {
        "not_fixed",
        "inconclusive",
        "playbook_failed_problem_worse",
    }
    return {
        "final_state": inv.status,
        "decision": plan.get("decision"),
        "fixed": bool(fixed),
        "unresolved_risk": bool(unresolved or (not corrective and plan.get("decision") not in {"observe", "no_action_expected_activity"})),
        "message": (
            "Real remediation is available and requires approval."
            if corrective and inv.status == "awaiting_approval"
            else plan.get("decision_reason")
        ),
        "next_action": (plan.get("next_manual_steps") or ["Review the investigation details."])[0],
    }


def _playbook_summary(inv: Investigation, plan: dict) -> dict:
    corrective = has_corrective_actions(plan)
    evidence = inv.evidence_json or {}
    diagnostic_yaml = evidence.get("diagnostic_playbook_yaml") if isinstance(evidence, dict) else None
    current_yaml = inv.playbook_yaml or ""
    is_diagnostic_current = "Runtime Diagnostic" in current_yaml or not corrective
    return {
        "diagnostic_playbook_yaml": diagnostic_yaml or (current_yaml if is_diagnostic_current else ""),
        "remediation_playbook_yaml": current_yaml if corrective and not is_diagnostic_current else "",
        "current_playbook_label": "Remediation Playbook" if corrective and not is_diagnostic_current else "Diagnostic Playbook",
        "current_playbook_is_remediation": bool(corrective and not is_diagnostic_current),
    }


def _runtime_signature(inv: Investigation, ctx: dict, plan: dict) -> str:
    parts = [
        inv.target_host or ctx.get("hostname") or "",
        ctx.get("rule_name") or inv.incident_title,
        ctx.get("runtime_category") or inv.resource_type or "",
        ctx.get("proc_name") or "",
        ctx.get("user_name") or "",
        ctx.get("fd_name") or "",
        ctx.get("container_id") or ctx.get("container_name") or "",
        str((plan.get("target_network_endpoint") or {}).get("remote_ip") or ""),
    ]
    return "|".join(str(p).lower() for p in parts)


def _display_status(inv: Investigation, plan: dict) -> str:
    if inv.status in {"findings_ready", "awaiting_approval"} and not has_corrective_actions(plan):
        return derive_runtime_status(plan, inv.status)
    return inv.status


# ── Allowed transitions ───────────────────────────────────────────────────────

_ALLOWED_TRANSITIONS = {
    "diagnosing": {"findings_ready", "observe", "manual_review_required", "failed"},
    "findings_ready": {"acknowledged", "awaiting_approval", "manual_review_required", "observe", "diagnosing", "manual_remediation_draft"},
    "observe": {"acknowledged", "diagnosing", "closed_with_risk", "archived_not_fixed", "manual_remediation_draft"},
    "manual_review_required": {"acknowledged", "diagnosing", "closed_with_risk", "archived_not_fixed", "manual_remediation_draft"},
    "escalated": {"awaiting_approval", "manual_review_required", "diagnosing"},
    "awaiting_approval": {"approved", "declined"},
    "approved": {"executing", "running"},
    "executing": {"verified", "fixed", "not_fixed", "inconclusive", "remediation_failed", "verification_failed"},
    "running": {"verified", "fixed", "not_fixed", "inconclusive", "remediation_failed", "verification_failed", "completed", "failed"},
    "completed": {"verified", "fixed", "not_fixed", "inconclusive", "archived_fixed", "archived_not_fixed"},
    "verified": {"archived_fixed"},
    "fixed": {"archived_fixed"},
    "not_fixed": {"archived_not_fixed", "closed_with_risk", "manual_remediation_draft"},
    "inconclusive": {"archived_not_fixed", "closed_with_risk", "manual_remediation_draft"},
    "remediation_failed": {"diagnosing", "archived_not_fixed", "closed_with_risk", "manual_remediation_draft"},
    "verification_failed": {"diagnosing", "archived_not_fixed", "closed_with_risk", "manual_remediation_draft"},
    "failed": {"diagnosing", "archived_not_fixed", "closed_with_risk", "manual_remediation_draft"},
    "declined": {"closed_with_risk", "archived_not_fixed", "manual_remediation_draft", "reopened"},
    "acknowledged": {"archived_not_fixed", "closed_with_risk", "manual_remediation_draft"},
    "archived_not_fixed": {"reopened", "manual_remediation_draft"},
    "archived_fixed": {"reopened"},
    "archived": {"reopened", "manual_remediation_draft"},
    "closed_with_risk": {"reopened", "manual_remediation_draft"},
    "manual_remediation_draft": {"manual_remediation_validating", "diagnosing"},
    "manual_remediation_validating": {"manual_remediation_awaiting_approval", "manual_remediation_draft", "diagnosing"},
    "manual_remediation_awaiting_approval": {"manual_remediation_approved", "manual_remediation_draft", "declined"},
    "manual_remediation_approved": {"manual_remediation_executing", "running"},
    "manual_remediation_executing": {"manual_remediation_completed", "manual_remediation_failed", "failed"},
    "manual_remediation_completed": {"archived_fixed", "archived_not_fixed"},
    "manual_remediation_failed": {"diagnosing", "archived_not_fixed", "closed_with_risk", "manual_remediation_draft"},
    "reopened": {"manual_remediation_draft", "diagnosing", "findings_ready"},
}


def _can_transition(current: str, target: str) -> bool:
    return target in _ALLOWED_TRANSITIONS.get(current, set())


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/investigations", response_model=dict)
async def list_runtime_investigations(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
    container: Optional[str] = Query(None),
    time_from: Optional[datetime] = Query(None, description="Filter investigations from this ISO datetime (inclusive)"),
    time_to: Optional[datetime] = Query(None, description="Filter investigations up to this ISO datetime (inclusive)"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_auth),
):
    """List runtime security investigations grouped by runtime signature."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    q = select(Investigation).where(Investigation.investigation_type == "runtime")
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

    q = q.order_by(Investigation.created_at.desc()).limit(2000)

    result = await session.execute(q)
    investigations = list(result.scalars().all())

    groups: dict[str, dict[str, Any]] = {}
    for inv in investigations:
        ctx = _extract_runtime_context(inv)
        if ctx:
            _apply_data_quality_guards(ctx)  # recover corrupted fields in place
        plan = _stored_plan(inv) or build_runtime_remediation_plan(
            runtime_context=ctx or {},
            findings=inv.findings_json or {},
            diagnostic_output=inv.diagnostic_output or "",
        )
        if decision and decision != "all" and plan.get("decision") != decision:
            continue
        container_value = (ctx or {}).get("container_name") or (ctx or {}).get("container_id") or ""
        if container and container.lower() not in str(container_value).lower():
            continue
        signature = _runtime_signature(inv, ctx or {}, plan)
        item = {
            "id": inv.id,
            "incident_id": inv.incident_id,
            "incident_title": inv.incident_title,
            "incident_severity": inv.incident_severity,
            "status": inv.status,
            "investigation_type": inv.investigation_type,
            "asset_id": inv.asset_id,
            "target_host": inv.target_host,
            "resource_type": inv.resource_type or (ctx.get("runtime_category") if ctx else None),
            "rule_name": ctx.get("rule_name") if ctx else None,
            "proc_name": ctx.get("proc_name") if ctx else None,
            "user_name": ctx.get("user_name") if ctx else None,
            "file_path": ctx.get("fd_name") if ctx else None,
            "container": container_value or None,
            "decision": plan.get("decision"),
            "target_context": plan.get("target_context"),
            "signature": signature,
            "occurrence_count": 1,
            "first_seen": inv.created_at.isoformat(),
            "last_seen": inv.created_at.isoformat(),
            "latest_status": inv.status,
            "latest_decision": plan.get("decision"),
            "created_at": inv.created_at.isoformat(),
            "updated_at": inv.updated_at.isoformat(),
        }
        group = groups.get(signature)
        if not group:
            groups[signature] = item
        else:
            count = group["occurrence_count"] + 1
            first_seen = min(group["first_seen"], inv.created_at.isoformat())
            last_seen = max(group["last_seen"], inv.created_at.isoformat())
            group["occurrence_count"] = count
            group["first_seen"] = first_seen
            group["last_seen"] = last_seen
            if inv.created_at.isoformat() >= last_seen:
                group.update(item)
                group["occurrence_count"] = count
                group["first_seen"] = first_seen
                group["last_seen"] = last_seen

    items = sorted(groups.values(), key=lambda item: item["last_seen"], reverse=True)
    total = len(items)
    page_items = items[offset: offset + limit]

    return {
        "investigations": page_items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "grouped": True,
    }


@router.get("/investigations/stats")
async def get_runtime_stats(
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_auth),
):
    """Get runtime investigation statistics."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    total_q = select(func.count(Investigation.id)).where(
        Investigation.investigation_type == "runtime"
    )
    if asset_id:
        total_q = total_q.where(Investigation.asset_id == asset_id)
    total = (await session.execute(total_q)).scalar_one()

    status_counts = {}
    for status in (
        "diagnosing", "findings_ready", "observe", "manual_review_required",
        "acknowledged", "awaiting_approval", "approved", "executing", "running",
        "verified", "fixed", "not_fixed", "inconclusive", "remediation_failed",
        "verification_failed", "failed", "declined", "archived_fixed",
        "archived_not_fixed", "closed_with_risk",
    ):
        q = select(func.count(Investigation.id)).where(
            Investigation.investigation_type == "runtime",
            Investigation.status == status,
        )
        if asset_id:
            q = q.where(Investigation.asset_id == asset_id)
        status_counts[status] = (await session.execute(q)).scalar_one()

    # Count by runtime category
    category_q = select(
        Investigation.resource_type,
        func.count(Investigation.id)
    ).where(
        Investigation.investigation_type == "runtime"
    ).group_by(Investigation.resource_type)
    if asset_id:
        category_q = category_q.where(Investigation.asset_id == asset_id)

    category_result = await session.execute(category_q)
    by_category = {row[0] or "unknown": row[1] for row in category_result.all()}

    return {
        "total": total,
        "by_status": status_counts,
        "by_category": by_category,
    }


@router.get("/investigations/{investigation_id}")
async def get_runtime_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get full runtime investigation detail."""
    inv = await _get_investigation_or_404(investigation_id, session)
    ctx = _extract_runtime_context(inv) or {}
    actions = _extract_suggested_actions(inv)
    plan = await _runtime_plan(inv, session)

    # Get linked alerts
    alert_result = await session.execute(
        select(InvestigationAlert).where(
            InvestigationAlert.investigation_id == investigation_id
        )
    )
    alerts = alert_result.scalars().all()
    alert_payloads = []
    raw_snapshots = []
    for alert in alerts:
        try:
            payload = json.loads(alert.alert_json)
        except Exception:
            payload = {"alert_id": alert.alert_id, "title": alert.title, "severity": alert.severity}
        alert_payloads.append(payload)
        # Fetch raw snapshot from Alert shadow record
        raw_result = await session.execute(
            select(Alert.raw_source_json).where(
                (Alert.id == alert.alert_id) | (Alert.source_id == alert.alert_id)
            ).limit(1)
        )
        raw_row = raw_result.scalar_one_or_none()
        if raw_row:
            try:
                raw_snapshots.append(json.loads(raw_row))
            except Exception:
                raw_snapshots.append({"_parse_error": True, "raw": raw_row[:500]})

    data_quality = _apply_data_quality_guards(ctx)

    # Resolve target asset for remediation readiness display
    target_asset = None
    if inv.asset_id:
        asset_result = await session.execute(
            select(MonitoredAsset).where(MonitoredAsset.asset_id == inv.asset_id)
        )
        asset = asset_result.scalar_one_or_none()
        if asset:
            ansible = asset.ansible_config_json or {}
            target_asset = {
                "asset_id": asset.asset_id,
                "name": asset.name,
                "enabled": asset.enabled,
                "remediation_enabled": asset.remediation_enabled,
                "ansible_host": ansible.get("ansible_host") or asset.hostname or asset.ip_address,
                "ansible_user": ansible.get("ansible_user"),
                "ansible_port": ansible.get("ansible_port", 22),
            }

    playbook_summary = _playbook_summary(inv, plan)
    evidence_summary = {
        "what_happened": (inv.findings_json or {}).get("detected_cause") or inv.ai_summary,
        "evidence_count": len((inv.findings_json or {}).get("evidence") or []),
        "evidence": (inv.findings_json or {}).get("evidence") or [],
    }
    remediation_summary = {
        "actual_remediation_available": has_corrective_actions(plan),
        "approval_required": bool(plan.get("approval_required")),
        "corrective_actions": plan.get("corrective_actions") or [],
        "rollback_actions": plan.get("rollback_actions") or [],
        "message": (
            "No corrective remediation was generated because the planner did not find a safe, evidence-backed action."
            if not has_corrective_actions(plan)
            else "Planner produced corrective actions that require approval before execution."
        ),
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
        "asset_id": inv.asset_id,
        "target_host": inv.target_host,
        "target_user": inv.target_user,
        "target_os": inv.target_os,
        "target_asset": target_asset,
        "ai_summary": inv.ai_summary,
        "playbook_yaml": inv.playbook_yaml,
        "playbook_valid": inv.playbook_valid,
        "resource_context": ctx,
        "context_sections": _context_sections(ctx, plan),
        "classification_context": {
            "runtime_category": ctx.get("runtime_category"),
            "rule_name": ctx.get("rule_name"),
            "severity": ctx.get("severity") or inv.incident_severity,
            "is_intervention_required": ctx.get("is_intervention_required"),
            "is_expected_admin_activity": ctx.get("is_expected_admin_activity"),
            "provenance": "falco_runtime_mapper_and_runtime_context_builder",
            "_data_quality": data_quality,
        },
        "alert_payloads": alert_payloads,
        "evidence_summary": evidence_summary,
        "diagnostic_summary": _diagnostic_summary(inv, plan, ctx),
        "findings_json": inv.findings_json,
        "diagnostic_output": inv.diagnostic_output,
        "suggested_actions": actions,
        "evidence_json": inv.evidence_json,
        "playbook_summary": playbook_summary,
        "playbook_phases": (_run_payload(inv) or {}).get("phases") or {},
        "remediation_plan": plan,
        "remediation_summary": remediation_summary,
        "outcome_summary": _outcome_summary(inv, plan),
        "verification": _verification_payload(inv),
        "run": _run_payload(inv),
        "available_actions": _available_actions(inv, plan),
        "rollback_playbook": inv.rollback_playbook,
        "manual_override_json": inv.manual_override_json,
        "ai_error": inv.ai_error,
        "created_at": inv.created_at.isoformat(),
        "updated_at": inv.updated_at.isoformat(),
        "raw_snapshots": raw_snapshots,
        "alerts": [
            {
                "alert_id": a.alert_id,
                "severity": a.severity,
                "source": a.source,
                "title": a.title,
                "payload": alert_payloads[idx] if idx < len(alert_payloads) else None,
            }
            for idx, a in enumerate(alerts)
        ],
    }


@router.post("/investigations/{investigation_id}/acknowledge")
async def acknowledge_runtime_investigation(
    investigation_id: str,
    body: AcknowledgeRuntimeRequest,
    session: AsyncSession = Depends(get_session),
):
    """Acknowledge a runtime investigation — closes it without action."""
    inv = await _get_investigation_or_404(investigation_id, session)

    if not _can_transition(inv.status, "acknowledged"):
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

    logger.info("runtime_investigation_acknowledged", investigation_id=investigation_id, decided_by=body.decided_by)
    return {"status": "acknowledged", "investigation_id": investigation_id, "message": "Investigation acknowledged and will be monitored."}


@router.post("/investigations/{investigation_id}/escalate")
async def escalate_runtime_investigation(
    investigation_id: str,
    body: EscalateRuntimeRequest,
    session: AsyncSession = Depends(get_session),
):
    """Escalate a runtime investigation — triggers remediation playbook generation."""
    inv = await _get_investigation_or_404(investigation_id, session)

    if inv.status not in {"findings_ready", "manual_review_required"}:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot escalate when status is '{inv.status}'",
        )

    resource_context = inv.resource_context_json or {}
    findings = inv.findings_json or {}
    alert_payloads = await _alert_payloads(investigation_id, session)
    plan = build_runtime_remediation_plan(
        runtime_context=resource_context,
        findings=findings,
        diagnostic_output=inv.diagnostic_output or "",
        alert_payloads=alert_payloads,
        verification_history=_verification_payload(inv),
    )
    evidence = dict(inv.evidence_json or {})
    evidence.setdefault("diagnostic_playbook_yaml", inv.playbook_yaml)
    evidence["remediation_plan"] = plan
    evidence["actual_remediation_available"] = has_corrective_actions(plan)

    if not has_corrective_actions(plan):
        new_status = derive_runtime_status(plan, inv.status)
        await session.execute(
            update(Investigation)
            .where(Investigation.id == investigation_id)
            .values(
                status=new_status,
                evidence_json=evidence,
                updated_at=datetime.now(timezone.utc),
            )
        )
        await session.commit()
        return {
            "status": new_status,
            "investigation_id": investigation_id,
            "remediation_generated": False,
            "decision": plan.get("decision"),
            "message": plan.get("decision_reason"),
        }

    try:
        from response.runtime_ai_engine.remediation_playbook_generator import generate_runtime_remediation_playbook
        remediation_playbook = generate_runtime_remediation_playbook(
            runtime_context=resource_context,
            findings=findings,
            host=inv.target_host or "localhost",
            target_user=inv.target_user or "root",
            remediation_plan=plan,
        )
    except Exception as e:
        logger.error("runtime_remediation_generation_failed", investigation_id=investigation_id, error=str(e))
        remediation_playbook = ""

    if not remediation_playbook:
        await session.execute(
            update(Investigation)
            .where(Investigation.id == investigation_id)
            .values(
                status="manual_review_required",
                evidence_json=evidence,
                updated_at=datetime.now(timezone.utc),
            )
        )
        await session.commit()
        return {
            "status": "manual_review_required",
            "investigation_id": investigation_id,
            "remediation_generated": False,
            "decision": plan.get("decision"),
            "message": "Planner had corrective actions, but remediation playbook generation failed.",
        }

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(
            status="awaiting_approval",
            playbook_yaml=remediation_playbook,
            evidence_json=evidence,
            updated_at=datetime.now(timezone.utc),
        )
    )
    await session.commit()

    logger.info("runtime_investigation_escalated", investigation_id=investigation_id, decided_by=body.decided_by)
    return {
        "status": "awaiting_approval",
        "investigation_id": investigation_id,
        "remediation_generated": True,
        "decision": plan.get("decision"),
        "message": "Evidence-backed remediation generated and waiting for approval.",
    }


@router.post("/investigations/{investigation_id}/approve")
async def approve_runtime_investigation(
    investigation_id: str,
    body: ApproveRuntimeRequest,
    session: AsyncSession = Depends(get_session),
):
    """Approve a runtime remediation playbook for execution."""
    inv = await _get_investigation_or_404(investigation_id, session)

    if not _can_transition(inv.status, "approved"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot approve when status is '{inv.status}'",
        )
    plan = await _runtime_plan(inv, session)
    if not has_corrective_actions(plan):
        raise HTTPException(
            status_code=400,
            detail=(
                "Approval rejected: this runtime investigation has no evidence-backed "
                "corrective actions. Diagnostic-only and manual-review cases cannot be approved for remediation."
            ),
        )
    if not inv.playbook_yaml:
        raise HTTPException(status_code=400, detail="No remediation playbook generated")

    existing = await session.execute(
        select(PlaybookApproval).where(PlaybookApproval.investigation_id == investigation_id)
    )
    if not existing.scalar_one_or_none():
        session.add(
            PlaybookApproval(
                investigation_id=investigation_id,
                decision="approved",
                decided_by=body.decided_by,
                decided_at=datetime.now(timezone.utc),
            )
        )

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="approved", updated_at=datetime.now(timezone.utc))
    )
    await session.commit()

    logger.info("runtime_investigation_approved", investigation_id=investigation_id, decided_by=body.decided_by)

    from response.ansible_exec import execute_playbook
    asyncio.create_task(execute_playbook(investigation_id))

    return {"status": "approved", "investigation_id": investigation_id, "message": "Approved remediation. Execution started."}


@router.post("/investigations/{investigation_id}/decline")
async def decline_runtime_investigation(
    investigation_id: str,
    body: DeclineRuntimeRequest,
    session: AsyncSession = Depends(get_session),
):
    """Decline a runtime remediation playbook."""
    inv = await _get_investigation_or_404(investigation_id, session)

    if not _can_transition(inv.status, "declined"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot decline when status is '{inv.status}'",
        )

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="declined", updated_at=datetime.now(timezone.utc))
    )
    await session.commit()

    logger.info("runtime_investigation_declined", investigation_id=investigation_id, decided_by=body.decided_by)
    return {"status": "declined", "investigation_id": investigation_id, "message": "Remediation declined. Case closed without action."}


@router.post("/investigations/{investigation_id}/diagnose")
async def diagnose_runtime_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Manually re-trigger the diagnostic playbook for a runtime investigation."""
    inv = await _get_investigation_or_404(investigation_id, session)

    if not _can_transition(inv.status, "diagnosing"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot re-diagnose when status is '{inv.status}'",
        )

    resource_context = inv.resource_context_json or {}

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(
            status="diagnosing",
            diagnostic_started_at=datetime.now(timezone.utc),
            diagnostic_finished_at=None,
            updated_at=datetime.now(timezone.utc),
        )
    )
    await session.commit()

    # Trigger diagnostic pipeline in background
    from pipeline.datausage.runtime_orchestrator import _run_runtime_diagnostic_pipeline
    asyncio.create_task(_run_runtime_diagnostic_pipeline(investigation_id, resource_context))

    logger.info("runtime_investigation_re_diagnosing", investigation_id=investigation_id)
    return {"status": "diagnosing", "investigation_id": investigation_id, "message": "Diagnostic playbook triggered. Evidence collection in progress."}


@router.post("/investigations/{investigation_id}/archive")
async def archive_runtime_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Archive a completed runtime investigation."""
    inv = await _get_investigation_or_404(investigation_id, session)

    if not _available_actions(inv, await _runtime_plan(inv, session)).get("archive"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot archive when status is '{inv.status}'",
        )
    plan = await _runtime_plan(inv, session)
    verification = _verification_payload(inv)
    if inv.status in {"verified", "fixed"} or verification.get("status") in {"likely_fixed", "verified"}:
        archive_status = "archived_fixed"
    elif plan.get("decision") in {"observe", "no_action_expected_activity"}:
        archive_status = "closed_with_risk" if inv.status not in {"acknowledged", "observe"} else "archived_not_fixed"
    else:
        archive_status = "archived_not_fixed"

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status=archive_status, updated_at=datetime.now(timezone.utc))
    )
    await session.commit()

    from response.archiver import archive_investigation
    await archive_investigation(investigation_id, fix_status=archive_status)

    logger.info("runtime_investigation_archived", investigation_id=investigation_id)
    return {"status": archive_status, "investigation_id": investigation_id, "message": "Investigation archived."}


@router.get("/investigations/{investigation_id}/timeline")
async def get_runtime_timeline(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get timeline events for a runtime investigation."""
    inv = await _get_investigation_or_404(investigation_id, session)

    events = []
    events.append({
        "type": "created",
        "timestamp": inv.created_at.isoformat(),
        "description": f"Investigation created for {inv.incident_title}",
    })

    if inv.diagnostic_started_at:
        events.append({
            "type": "diagnosing",
            "timestamp": inv.diagnostic_started_at.isoformat(),
            "description": "Diagnostic playbook started",
        })

    if inv.diagnostic_finished_at:
        events.append({
            "type": "findings_ready",
            "timestamp": inv.diagnostic_finished_at.isoformat(),
            "description": "Diagnostic findings available",
        })

    if inv.updated_at and inv.updated_at != inv.created_at:
        events.append({
            "type": inv.status,
            "timestamp": inv.updated_at.isoformat(),
            "description": f"Status changed to {inv.status}",
        })

    events.sort(key=lambda x: x["timestamp"] or "")
    return {"investigation_id": investigation_id, "events": events}


# ── Admin Override / Manual Remediation ───────────────────────────────────────

@router.post("/investigations/{investigation_id}/manual-remediation")
async def create_manual_remediation(
    investigation_id: str,
    body: ManualRemediationCreateRequest,
    session: AsyncSession = Depends(get_session),
):
    """Create a manual remediation draft for a runtime investigation.

    Available when the investigation status is one of:
    observe, findings_ready, manual_review_required, acknowledged,
    archived_not_fixed, declined, archived, closed_with_risk.
    """
    inv = await _get_investigation_or_404(investigation_id, session)

    if not _can_transition(inv.status, "manual_remediation_draft"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot create manual remediation when status is '{inv.status}'",
        )

    manual_override = {
        "status": "manual_remediation_draft",
        "admin_reason": body.admin_reason,
        "business_justification": body.business_justification,
        "target_scope_confirmation": body.target_scope_confirmation,
        "expected_impact": body.expected_impact,
        "rollback_plan_yaml": body.rollback_plan_yaml,
        "verification_plan_yaml": body.verification_plan_yaml,
        "risk_level": "unknown",
        "confirmation_text": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "validation_result": {},
    }

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(
            status="manual_remediation_draft",
            manual_override_json=manual_override,
            updated_at=datetime.now(timezone.utc),
        )
    )
    await session.commit()

    from response.audit_events import log_manual_remediation_action
    await log_manual_remediation_action(
        investigation_id=investigation_id,
        action="manual_remediation_created",
        previous_status=inv.status,
        new_status="manual_remediation_draft",
        actor=body.decided_by,
        reason=body.admin_reason,
    )

    logger.info("manual_remediation_created", investigation_id=investigation_id, decided_by=body.decided_by)
    return {
        "status": "manual_remediation_draft",
        "investigation_id": investigation_id,
        "message": "Manual remediation draft created. Edit the playbook and run validation before approval.",
    }


@router.patch("/investigations/{investigation_id}/manual-remediation/playbook")
async def patch_manual_remediation_playbook(
    investigation_id: str,
    body: ManualRemediationPlaybookPatch,
    session: AsyncSession = Depends(get_session),
):
    """Update the playbook YAML for a manual remediation draft."""
    inv = await _get_investigation_or_404(investigation_id, session)

    if inv.status not in {"manual_remediation_draft", "manual_remediation_validating"}:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot edit manual playbook when status is '{inv.status}'",
        )

    manual_override = dict(inv.manual_override_json or {})
    manual_override["updated_at"] = datetime.now(timezone.utc).isoformat()
    manual_override["validation_result"] = {}

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(
            playbook_yaml=body.playbook_yaml,
            manual_override_json=manual_override,
            updated_at=datetime.now(timezone.utc),
        )
    )
    await session.commit()

    from response.audit_events import log_manual_remediation_action
    await log_manual_remediation_action(
        investigation_id=investigation_id,
        action="manual_remediation_playbook_edited",
        previous_status=inv.status,
        new_status=inv.status,
        actor=body.decided_by,
        reason="Manual playbook updated",
        playbook_yaml=body.playbook_yaml,
    )

    logger.info("manual_remediation_playbook_edited", investigation_id=investigation_id, decided_by=body.decided_by)
    return {
        "status": inv.status,
        "investigation_id": investigation_id,
        "message": "Manual remediation playbook updated.",
    }


@router.post("/investigations/{investigation_id}/manual-remediation/validate")
async def validate_manual_remediation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Validate a manual remediation playbook.

    Runs YAML syntax, Ansible syntax-check, firewall safety, and comprehensive
    playbook safety validation. Returns validation result and computed risk level.
    """
    inv = await _get_investigation_or_404(investigation_id, session)

    if inv.status not in {"manual_remediation_draft", "manual_remediation_validating"}:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot validate manual playbook when status is '{inv.status}'",
        )

    playbook_yaml = inv.playbook_yaml or ""
    if not playbook_yaml.strip():
        raise HTTPException(status_code=400, detail="No playbook YAML to validate")

    # Layer 1: YAML syntax
    import yaml
    try:
        parsed = yaml.safe_load(playbook_yaml)
        if not isinstance(parsed, list):
            raise ValueError("Playbook must be a YAML list")
    except Exception as e:
        return {
            "valid": False,
            "executable": False,
            "reasons": [f"YAML syntax error: {e}"],
            "blocked_tasks": [],
            "risk_level": "critical",
            "can_approve": False,
        }

    # Layer 2: Ansible syntax check
    from response.ansible_exec import _validate_ansible_syntax
    is_valid_ansible, ansible_error = await _validate_ansible_syntax(playbook_yaml, investigation_id)
    if not is_valid_ansible:
        return {
            "valid": False,
            "executable": False,
            "reasons": [f"Ansible syntax error: {ansible_error}"],
            "blocked_tasks": [],
            "risk_level": "critical",
            "can_approve": False,
        }

    # Layer 3: Firewall safety
    from response.ansible_exec import _sanitize_firewall_tasks, _get_protected_ips
    protected_ips = await _get_protected_ips(inv.target_host or "localhost")
    is_safe, safety_error, sanitized_yaml = _sanitize_firewall_tasks(playbook_yaml, protected_ips)
    if not is_safe:
        return {
            "valid": False,
            "executable": False,
            "reasons": [f"Firewall safety blocked: {safety_error}"],
            "blocked_tasks": [],
            "risk_level": "critical",
            "can_approve": False,
        }

    # Layer 4: Comprehensive playbook safety
    from response.playbook_safety import validate_playbook_safety
    investigation_context = {
        "investigation_type": inv.investigation_type or "security",
        "target_host": inv.target_host or "localhost",
        "alert_sources": [],
    }
    safety = validate_playbook_safety(sanitized_yaml, investigation_context)

    # Compute risk level
    risk_level = "low"
    if safety["blocked_tasks"]:
        risk_level = "critical"
    elif safety["reasons"]:
        risk_level = "high"
    elif "iptables" in playbook_yaml.lower() or "firewall" in playbook_yaml.lower():
        risk_level = "medium"

    can_approve = safety["executable"] and is_safe and is_valid_ansible

    validation_result = {
        "valid": is_safe and is_valid_ansible,
        "executable": safety["executable"],
        "reasons": safety["reasons"],
        "blocked_tasks": safety["blocked_tasks"],
        "risk_level": risk_level,
        "can_approve": can_approve,
    }

    manual_override = dict(inv.manual_override_json or {})
    manual_override["status"] = "manual_remediation_validating"
    manual_override["updated_at"] = datetime.now(timezone.utc).isoformat()
    manual_override["validation_result"] = validation_result
    manual_override["risk_level"] = risk_level

    new_status = "manual_remediation_validating"
    if can_approve:
        new_status = "manual_remediation_awaiting_approval"
        manual_override["status"] = new_status

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(
            status=new_status,
            manual_override_json=manual_override,
            updated_at=datetime.now(timezone.utc),
        )
    )
    await session.commit()

    from response.audit_events import log_manual_remediation_action
    await log_manual_remediation_action(
        investigation_id=investigation_id,
        action="manual_remediation_validated",
        previous_status=inv.status,
        new_status=new_status,
        actor="system",
        reason=f"Validation result: executable={safety['executable']}, risk={risk_level}",
        playbook_yaml=playbook_yaml,
        result=f"can_approve={can_approve}",
    )

    logger.info("manual_remediation_validated", investigation_id=investigation_id, can_approve=can_approve, risk_level=risk_level)
    return {**validation_result, "status": new_status, "investigation_id": investigation_id}


@router.post("/investigations/{investigation_id}/manual-remediation/approve-run")
async def approve_manual_remediation(
    investigation_id: str,
    body: ManualRemediationApproveRequest,
    session: AsyncSession = Depends(get_session),
):
    """Approve and execute a manual remediation playbook.

    Requires the playbook to have passed validation and the admin to have typed
    the exact confirmation text 'I UNDERSTAND THE RISK'.
    """
    inv = await _get_investigation_or_404(investigation_id, session)

    if not _can_transition(inv.status, "manual_remediation_approved"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot approve manual remediation when status is '{inv.status}'",
        )

    manual_override = inv.manual_override_json or {}
    validation_result = manual_override.get("validation_result", {})

    if not validation_result.get("can_approve"):
        raise HTTPException(
            status_code=400,
            detail="Manual remediation cannot be approved: playbook has not passed validation or contains blocked tasks.",
        )

    if body.confirmation_text != "I UNDERSTAND THE RISK":
        raise HTTPException(
            status_code=400,
            detail="Approval rejected: confirmation text must be exactly 'I UNDERSTAND THE RISK'.",
        )

    admin_reason = manual_override.get("admin_reason", "")
    risk_level = manual_override.get("risk_level", "unknown")

    # Create or update PlaybookApproval
    existing = await session.execute(
        select(PlaybookApproval).where(PlaybookApproval.investigation_id == investigation_id)
    )
    approval_record = existing.scalar_one_or_none()
    if approval_record:
        approval_record.decision = "approved"
        approval_record.decided_by = body.decided_by
        approval_record.decided_at = datetime.now(timezone.utc)
        approval_record.reason = admin_reason
    else:
        session.add(
            PlaybookApproval(
                investigation_id=investigation_id,
                decision="approved",
                decided_by=body.decided_by,
                decided_at=datetime.now(timezone.utc),
                reason=admin_reason,
            )
        )

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="manual_remediation_approved", updated_at=datetime.now(timezone.utc))
    )
    await session.commit()

    from response.audit_events import log_manual_remediation_action
    await log_manual_remediation_action(
        investigation_id=investigation_id,
        action="manual_remediation_approved",
        previous_status=inv.status,
        new_status="manual_remediation_approved",
        actor=body.decided_by,
        reason=admin_reason,
        playbook_yaml=inv.playbook_yaml,
        risk_level=risk_level,
        confirmation_text=body.confirmation_text,
    )

    logger.info("manual_remediation_approved", investigation_id=investigation_id, decided_by=body.decided_by, risk_level=risk_level)

    from response.ansible_exec import execute_playbook
    asyncio.create_task(execute_playbook(investigation_id))

    return {
        "status": "manual_remediation_approved",
        "investigation_id": investigation_id,
        "message": "Manual remediation approved and execution started.",
    }


@router.post("/investigations/{investigation_id}/force-decline")
async def force_decline_runtime_investigation(
    investigation_id: str,
    body: ForceDeclineRequest,
    session: AsyncSession = Depends(get_session),
):
    """Force-decline / close a runtime investigation with reason.

    Available from almost any status except terminal archived/closed states.
    """
    inv = await _get_investigation_or_404(investigation_id, session)

    blocked_statuses = {"archived_fixed", "closed_with_risk"}
    if inv.status in blocked_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot force-decline when status is '{inv.status}'",
        )

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="declined", updated_at=datetime.now(timezone.utc))
    )
    await session.commit()

    from response.audit_events import log_manual_remediation_action
    await log_manual_remediation_action(
        investigation_id=investigation_id,
        action="force_declined",
        previous_status=inv.status,
        new_status="declined",
        actor=body.decided_by,
        reason=body.reason,
    )

    logger.info("runtime_investigation_force_declined", investigation_id=investigation_id, decided_by=body.decided_by, reason=body.reason)
    return {"status": "declined", "investigation_id": investigation_id, "message": f"Investigation force-declined: {body.reason}"}


@router.post("/investigations/{investigation_id}/reopen")
async def reopen_runtime_investigation(
    investigation_id: str,
    body: ReopenRequest,
    session: AsyncSession = Depends(get_session),
):
    """Reopen an archived or closed runtime investigation.

    Clears manual_override_json so the case can start fresh.
    """
    inv = await _get_investigation_or_404(investigation_id, session)

    if not _can_transition(inv.status, "reopened"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot reopen when status is '{inv.status}'",
        )

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(
            status="reopened",
            manual_override_json=None,
            updated_at=datetime.now(timezone.utc),
        )
    )
    await session.commit()

    from response.audit_events import log_manual_remediation_action
    await log_manual_remediation_action(
        investigation_id=investigation_id,
        action="reopened",
        previous_status=inv.status,
        new_status="reopened",
        actor=body.decided_by,
        reason=body.reason,
    )

    logger.info("runtime_investigation_reopened", investigation_id=investigation_id, decided_by=body.decided_by, reason=body.reason)
    return {"status": "reopened", "investigation_id": investigation_id, "message": f"Investigation reopened: {body.reason}"}


# ── Falco Events (raw) ────────────────────────────────────────────────────────

@router.get("/events")
async def list_falco_events(
    priority: Optional[str] = Query(None),
    rule: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
):
    """List raw Falco events from Elasticsearch."""
    from config import get_settings
    from core.elasticsearch import get_es_client
    from core.asset_scope import resolve_asset_scope
    from api.routes._shared import validate_asset_id, enforce_asset_scope

    settings = get_settings()
    es = await get_es_client()

    # Validate and resolve asset scope if provided
    index_pattern = settings.falco_index_pattern
    if asset_id and settings.multi_server_enabled:
        asset_id = await validate_asset_id(asset_id)
        asset_id = await enforce_asset_scope(user, asset_id)
        if asset_id:
            scope = await resolve_asset_scope("falco", asset_id, None)
            index_pattern = scope["index_pattern"]
            if scope["query_filter"]:
                query = scope["query_filter"]
            else:
                query = {"match_all": {}}
        else:
            query = {"bool": {"must": []}}
    else:
        query = {"bool": {"must": []}}
        if priority:
            query["bool"]["must"].append({"term": {"priority.keyword": priority}})
        if rule:
            query["bool"]["must"].append({"wildcard": {"rule.keyword": f"*{rule}*"}})
        if host:
            query["bool"]["must"].append({"term": {"hostname.keyword": host}})
        if not query["bool"]["must"]:
            query = {"match_all": {}}

    try:
        result = await es.search(
            index=index_pattern,
            body={
                "query": query,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "from": offset,
                "size": limit,
            },
        )

        hits = result["hits"]["hits"]
        events = []
        for hit in hits:
            source = hit["_source"]
            of = source.get("output_fields", {})
            events.append({
                "id": hit["_id"],
                "timestamp": source.get("@timestamp"),
                "priority": source.get("priority"),
                "rule": source.get("rule"),
                "hostname": source.get("hostname"),
                "output": source.get("output", "")[:300],
                "proc_name": of.get("proc_name"),
                "proc_cmdline": of.get("proc_cmdline"),
                "user_name": of.get("user_name"),
                "fd_name": of.get("fd_name"),
                "container_name": of.get("container_name"),
                "tags": source.get("tags", []),
            })

        return {
            "events": events,
            "total": result["hits"]["total"]["value"],
            "offset": offset,
            "limit": limit,
        }
    except Exception as e:
        logger.error("falco_events_query_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to query Falco events: {str(e)}")


@router.get("/events/{event_id}")
async def get_falco_event(event_id: str):
    """Get a single Falco event by ID."""
    from config import get_settings
    from core.elasticsearch import get_es_client

    settings = get_settings()
    es = await get_es_client()

    try:
        result = await es.get(
            index=settings.falco_index_pattern,
            id=event_id,
        )
        return result["_source"]
    except Exception as e:
        logger.error("falco_event_get_failed", event_id=event_id, error=str(e))
        raise HTTPException(status_code=404, detail="Falco event not found")


@router.get("/rules")
async def list_falco_rules():
    """List all Falco rules seen in recent events."""
    from config import get_settings
    from core.elasticsearch import get_es_client

    settings = get_settings()
    es = await get_es_client()

    try:
        result = await es.search(
            index=settings.falco_index_pattern,
            body={
                "size": 0,
                "aggs": {
                    "rules": {"terms": {"field": "rule.keyword", "size": 100}}
                },
            },
        )

        rules = [
            {"name": bucket["key"], "count": bucket["doc_count"]}
            for bucket in result["aggregations"]["rules"]["buckets"]
        ]

        return {"rules": rules}
    except Exception as e:
        logger.error("falco_rules_query_failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to query Falco rules: {str(e)}")

