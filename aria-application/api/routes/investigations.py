"""
Investigation API routes — approval workflow, playbook editing, run status.
"""

import json
import os
import structlog
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = structlog.get_logger()

from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update, func, insert, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from response.db import get_session, AsyncSessionLocal
from response.models import (
    Investigation,
    InvestigationAlert,
    InvestigationAuditEvent,
    PlaybookApproval,
    PlaybookRun,
    FixVerification,
    Archive,
    Incident,
    Alert,
    AlertIncidentLink,
    MonitoredAsset,
)
from response.auth import require_auth, CurrentUser
from api.routes._shared import validate_asset_id, enforce_asset_scope
from response.audit_events import record_audit_event
from response.workflow_summary import (
    alert_snapshot_to_dict,
    build_playbook_summary,
    build_workflow_summary,
)

router = APIRouter(prefix="/api/v1/investigations", tags=["investigations"])


# ── RBAC / Admin authorization helpers ───────────────────────────────────────

def _validate_admin_access(
    decided_by: str,
    admin_secret_header: str | None = None,
) -> str:
    """
    Internal trusted mode admin validation.
    
    Requires X-ARIA-Admin-Secret header matching settings.aria_admin_secret.
    In production/internal mode, if the admin secret is empty/default/changeme,
    admin endpoints are blocked.
    
    Returns the validated actor label. Never logs the secret.
    """
    from config import get_settings
    settings = get_settings()
    expected = (settings.aria_admin_secret or "").strip()
    
    if not expected or expected.lower() in ("", "changeme", "default", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Admin access is disabled because aria_admin_secret is not configured or uses a default value. Set a strong secret in settings.",
        )
    
    provided = (admin_secret_header or "").strip()
    if not provided:
        raise HTTPException(
            status_code=403,
            detail="Admin action requires X-ARIA-Admin-Secret header.",
        )
    if provided != expected:
        raise HTTPException(
            status_code=403,
            detail="Invalid admin secret.",
        )
    
    return decided_by or "admin"


def _audit_ctx(request) -> dict:
    """Extract audit context from a FastAPI request.
    
    Handles direct function calls in tests where request may be a Depends placeholder.
    """
    if request is None:
        return {}
    if not hasattr(request, "client"):
        return {}
    return {
        "source_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent") if hasattr(request, "headers") else None,
        "request_id": request.headers.get("x-request-id") if hasattr(request, "headers") else None,
    }


def _get_alert_payload(alert: InvestigationAlert) -> dict:
    """Safely extract alert payload from InvestigationAlert.
    
    Supports both alert_json (current) and alert_snapshot (legacy).
    """
    raw = getattr(alert, "alert_json", None) or getattr(alert, "alert_snapshot", None) or "{}"
    if isinstance(raw, str):
        try:
            return json.loads(raw) or {}
        except Exception:
            return {}
    if isinstance(raw, dict):
        return raw
    return {}


# ── Pydantic schemas ──────────────────────────────────────────────────────────


class InvestigationSummary(BaseModel):
    id: str
    incident_id: str
    local_incident_id: Optional[str] = None
    upstream_incident_id: Optional[str] = None
    incident_title: str
    incident_severity: str
    status: str
    source: str
    investigation_type: str = "security"
    ai_summary: Optional[str]
    playbook_valid: bool
    target_host: Optional[str]
    source_ips: Optional[str]
    mitre_tactics: Optional[str]
    playbook_safety_status: str = "safe"
    rollback_safety_status: str = "safe"
    is_safe_to_display: bool = True
    has_remediation_action: bool = False
    execution_mode: str = "none"
    is_executable: bool = False
    blocked_reasons: list[str] = Field(default_factory=list)
    safety_tier: str = "safe"
    hard_block_reasons: list[str] = Field(default_factory=list)
    completion_quality: str = "unknown"
    failed_phase: Optional[str] = None
    warning_phases: Optional[list] = None
    verification_status: Optional[str] = None
    ai_quality_status: str = "unknown"
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertSummary(BaseModel):
    alert_id: str
    severity: str
    source: str
    title: str
    description: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    rule_name: Optional[str] = None
    tags: list = Field(default_factory=list)
    iocs: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)
    created_at: Optional[str] = None
    raw: dict = Field(default_factory=dict)

    model_config = {"from_attributes": True}


class TruthReport(BaseModel):
    observed_facts: list[str] = Field(default_factory=list)
    inferred_findings: list[str] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    final_classification: str = "inconclusive"
    confidence: str = "low"
    evidence_quality: str = "unknown"


class InvestigationDetail(BaseModel):
    id: str
    incident_id: str
    local_incident_id: Optional[str] = None
    upstream_incident_id: Optional[str] = None
    incident_title: str
    incident_severity: str
    incident_status: str
    status: str
    source: str
    investigation_type: str = "security"
    resource_context_json: Optional[dict] = None
    ai_summary: Optional[str]
    ai_narrative: Optional[str]
    ai_risk: Optional[str]
    playbook_yaml: Optional[str]
    playbook_valid: bool
    target_host: Optional[str]
    target_user: str
    target_os: Optional[str]
    source_ips: Optional[str]
    hostnames: Optional[str]
    mitre_tactics: Optional[str]
    ai_error: Optional[str]
    evidence_json: Optional[dict]
    rollback_playbook: Optional[str]
    created_at: datetime
    updated_at: datetime
    alerts: list[AlertSummary]
    approval: Optional[dict]
    run: Optional[dict]
    verification: Optional[dict]
    workflow: Optional[dict] = None
    playbook_summary: Optional[dict] = None
    playbook_safety_status: str = "safe"
    rollback_safety_status: str = "safe"
    is_safe_to_display: bool = True
    has_remediation_action: bool = False
    execution_mode: str = "none"
    is_executable: bool = False
    blocked_reasons: list[str] = Field(default_factory=list)
    completion_quality: str = "unknown"
    failed_phase: Optional[str] = None
    warning_phases: Optional[list] = None
    verification_status: Optional[str] = None
    ai_quality_status: str = "unknown"
    ai_quality_json: Optional[dict] = None
    verification_plan_json: Optional[dict] = None
    post_rollback_verification_json: Optional[dict] = None
    truth_report: Optional[TruthReport] = None
    analyst_actions: list[str] = Field(default_factory=list)
    admin_actions: list[str] = Field(default_factory=list)
    safety_tier: str = "safe"
    hard_block_reasons: list[str] = Field(default_factory=list)
    audit_events: list[dict] = Field(default_factory=list)
    asset_id: Optional[str] = None

    model_config = {"from_attributes": True}


class ApproveRequest(BaseModel):
    decided_by: str = "analyst"


class DeclineRequest(BaseModel):
    decided_by: str = "analyst"
    reason: Optional[str] = None


class RegenerateRequest(BaseModel):
    decided_by: str = "analyst"
    reason: Optional[str] = None


class MarkReviewedRequest(BaseModel):
    decided_by: str = "analyst"
    reason: Optional[str] = None


class EditPlaybookRequest(BaseModel):
    playbook_yaml: str


class StatsResponse(BaseModel):
    pending: int
    awaiting_approval: int
    approved: int
    decision_approved: int = 0
    declined: int
    running: int
    completed: int
    completed_with_warnings: int = 0
    failed: int
    archived: int
    manual_review_required: int = 0
    regeneration_requested: int = 0
    reviewed_no_action: int = 0
    total: int


class CreateManualInvestigationRequest(BaseModel):
    incident_id: str
    target_host: Optional[str] = None
    target_user: Optional[str] = "root"
    created_by: Optional[str] = "analyst"


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _get_investigation_or_404(
    investigation_id: str, session: AsyncSession
) -> Investigation:
    result = await session.execute(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .options(
            selectinload(Investigation.alerts),
            selectinload(Investigation.approval),
            selectinload(Investigation.run),
            selectinload(Investigation.verification),
            selectinload(Investigation.audit_events),
        )
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


# Allowed state transitions
_ALLOWED_TRANSITIONS = {
    "pending": {"running", "declined"},
    "running": {"awaiting_approval", "completed", "completed_with_warnings", "failed"},
    "awaiting_approval": {"approved", "declined", "regeneration_requested", "reviewed_no_action", "decision_approved"},
    "approved": {"running"},
    "decision_approved": {"archived", "regeneration_requested", "reviewed_no_action", "declined"},
    "completed": {"archived"},
    "completed_with_warnings": {"archived"},
    "failed": {"archived", "approved", "regeneration_requested", "decision_approved"},
    "declined": {"archived", "regeneration_requested"},
    "manual_review_required": {"declined", "archived", "regeneration_requested", "reviewed_no_action", "decision_approved", "approved"},
    "regeneration_requested": {"pending", "archived"},
    "reviewed_no_action": {"archived"},
    # Runtime investigation statuses
    "observe": {"awaiting_approval", "approved", "archived", "manual_review_required"},
    "findings_ready": {"awaiting_approval", "approved", "archived", "manual_review_required"},
    "diagnosing": {"findings_ready", "archived", "failed"},
}


def _validate_status_transition(current: str, desired: str) -> bool:
    """Validate if a status transition is allowed."""
    allowed = _ALLOWED_TRANSITIONS.get(current, set())
    return desired in allowed


def _approval_to_dict(approval: Optional[PlaybookApproval]) -> Optional[dict]:
    if not approval:
        return None
    return {
        "decision": approval.decision,
        "decided_by": approval.decided_by,
        "decided_at": approval.decided_at.isoformat(),
        "reason": approval.reason,
        "edited_playbook": approval.edited_playbook,
        "override": approval.override,
        "override_by": approval.override_by,
        "override_at": approval.override_at.isoformat() if approval.override_at else None,
        "override_reason": approval.override_reason,
        "original_safety_tier": approval.original_safety_tier,
        "original_blocked_reasons": approval.original_blocked_reasons,
        "feature_flag_used": approval.feature_flag_used,
    }


def _run_to_dict(run: Optional[PlaybookRun]) -> Optional[dict]:
    if not run:
        return None
    return {
        "status": run.status,
        "exit_code": run.exit_code,
        "output": run.output,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "current_phase": run.current_phase,
        "phases": run.phases_json or {},
        "completion_quality": run.completion_quality,
        "failed_phase": run.failed_phase,
        "warning_phases": run.warning_phases or [],
        "verification_plan_json": run.verification_plan_json,
    }


def _verification_to_dict(v: Optional[FixVerification]) -> Optional[dict]:
    if not v:
        return None
    return {
        "status": v.status,
        "new_alerts_found": v.new_alerts_found,
        "checked_at": v.checked_at.isoformat(),
        "detail": v.detail,
    }


def _has_evidence_of_compromise(inv: Investigation) -> dict:
    """Check alert evidence for indicators of actual compromise.

    Returns dict with keys: has_successful_login, has_malware, has_lateral_movement.
    """
    result = {"has_successful_login": False, "has_malware": False, "has_lateral_movement": False}
    evidence = inv.evidence_json or {}
    alerts = evidence.get("alerts", [])
    if not alerts and inv.alerts:
        # Fallback to linked alerts raw snapshots
        alerts = []
        for a in inv.alerts:
            try:
                snap = _get_alert_payload(a)
                alerts.append(snap or {})
            except Exception:
                pass

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        raw = str(alert.get("raw", alert))
        raw_lower = raw.lower()
        title = str(alert.get("title", "")).lower()
        tags = alert.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        tags_lower = [str(t).lower() for t in tags]

        # Successful login indicators
        if any(k in raw_lower for k in ("authentication_success", "accepted password", "accepted publickey", "session opened")):
            result["has_successful_login"] = True
        # Malware indicators
        if any(k in raw_lower for k in ("malware", "trojan", "virus", "backdoor", "rootkit", "cryptominer")):
            result["has_malware"] = True
        # Lateral movement indicators — require actual post-auth behavior, not just MITRE tag
        has_lm_tag = any("lateral movement" in t for t in tags_lower)
        has_lm_text = any(k in raw_lower for k in ("lateral_movement", "pass the hash", "wmexec", "psexec", "rdp tunnel"))
        # Wazuh tags SSH as T1021.004 (Remote Services: SSH) which is NOT lateral movement without successful login
        is_ssh_failed_login = "ssh" in title and "failed" in title
        if has_lm_tag and is_ssh_failed_login:
            # MITRE tag from source is NOT evidence of actual lateral movement for failed logins
            pass
        elif has_lm_text:
            result["has_lateral_movement"] = True

    return result


def _build_truth_report(inv: Investigation) -> dict:
    """Build a structured truth report from AI outputs and quality data.

    Evidence-aware classification:
    - observed_facts: only what the alerts actually show
    - inferred_findings: reasonable deductions WITH evidence support
    - unsupported_claims: claims made by AI without evidence
    """
    observed_facts = []
    inferred_findings = []
    unsupported_claims = []
    recommended_next_steps = []
    final_classification = "inconclusive"
    confidence = "low"
    evidence_quality = inv.ai_quality_status or "unknown"

    # Check actual evidence
    evidence_flags = _has_evidence_of_compromise(inv)
    is_ssh_bruteforce = False
    source_ips = []
    if inv.source_ips:
        source_ips = [ip.strip() for ip in inv.source_ips.split(",") if ip.strip()]
    target_host = inv.target_host or "unknown"

    # Determine attack type from alert evidence, not just AI summary
    alert_titles = []
    alert_tags = []
    if inv.alerts:
        for a in inv.alerts:
            try:
                snap = _get_alert_payload(a)
                if snap:
                    alert_titles.append(str(snap.get("title", "")).lower())
                    tags = snap.get("tags", [])
                    if isinstance(tags, str):
                        tags = [tags]
                    alert_tags.extend([str(t).lower() for t in tags])
            except Exception:
                alert_titles.append(str(getattr(a, "title", "")).lower())

    all_alert_text = " ".join(alert_titles + alert_tags)
    has_ssh_failed = any("ssh" in t and ("failed" in t or "authentication" in t) for t in alert_titles)
    has_pam_failed = any("pam" in t and "failed" in t for t in alert_titles)
    has_brute_force_tag = any("brute" in t or "password guessing" in t for t in alert_tags)

    is_ssh_bruteforce = False
    if inv.ai_summary:
        summary_lower = inv.ai_summary.lower()
        is_ssh_bruteforce = (
            "brute force" in summary_lower
            or "brute-force" in summary_lower
            or ("ssh" in summary_lower and ("failed" in summary_lower or "authentication" in summary_lower))
            or has_ssh_failed
            or has_pam_failed
            or has_brute_force_tag
        )
    else:
        # Detect from alert evidence even when AI summary is missing
        is_ssh_bruteforce = has_ssh_failed or has_pam_failed or has_brute_force_tag

    # Always record observable facts from available fields, even without AI summary
    if source_ips:
        observed_facts.append(f"Source IP {source_ips[0]} detected")
    if target_host and target_host != "unknown":
        observed_facts.append(f"Target host {target_host}")
    if inv.incident_title:
        incident_lower = inv.incident_title.lower()
        if "malicious ip" in incident_lower or "suspicious network" in incident_lower:
            observed_facts.append("Investigation classified as malicious IP traffic / suspicious network traffic")
    if getattr(inv, "title", None):
        title_lower = inv.title.lower()
        if "malicious ip" in title_lower or "suspicious network" in title_lower:
            if "Investigation classified as malicious IP traffic" not in observed_facts:
                observed_facts.append("Investigation classified as malicious IP traffic / suspicious network traffic")
    if alert_titles:
        observed_facts.append(f"Alert context: {alert_titles[0]}")
    # Extract playbook vars if present
    if inv.playbook_yaml:
        try:
            import yaml as _yaml
            pb = _yaml.safe_load(inv.playbook_yaml)
            if isinstance(pb, list) and pb:
                first_play = pb[0]
                if isinstance(first_play, dict):
                    pb_vars = first_play.get("vars", {})
                    if isinstance(pb_vars, dict):
                        if pb_vars.get("attacker_ips"):
                            observed_facts.append(f"Playbook vars include attacker_ips: {pb_vars['attacker_ips']}")
                        if pb_vars.get("target_ips"):
                            observed_facts.append(f"Playbook vars include target_ips: {pb_vars['target_ips']}")
        except Exception:
            pass

    # Extract from ai_quality_json
    if inv.ai_quality_json:
        grounding = inv.ai_quality_json.get("grounding", {})
        if grounding.get("reasons"):
            # Filter out builder metadata from unsupported claims
            builder_meta = {"deterministic_builder_used", "fallback_used_timeout", "fallback_used_error"}
            for reason in grounding["reasons"]:
                if reason not in builder_meta:
                    unsupported_claims.append(reason)
        # Recognize deterministic builder quality
        builder_info = inv.ai_quality_json.get("builder", {})
        if builder_info.get("deterministic"):
            evidence_quality = "passed"
            confidence = "medium"
        quality = inv.ai_quality_json.get("quality", {})
        scores = quality.get("scores", {})
        avg_score = sum(scores.values()) / max(len(scores), 1) if scores else 0
        if avg_score >= 0.8:
            confidence = "high"
        elif avg_score >= 0.5:
            confidence = "medium"
        else:
            confidence = "low"

    has_compromise_mention = False
    has_compromise_negation = False

    # SSH brute-force base facts (from alert evidence, independent of AI summary)
    if is_ssh_bruteforce:
        if has_pam_failed:
            observed_facts.append("Failed PAM authentication detected")
        if has_ssh_failed:
            observed_facts.append("Failed SSH password attempt detected")
        if not has_pam_failed and not has_ssh_failed:
            observed_facts.append("Failed SSH/PAM authentication attempts detected")
        observed_facts.append("No successful login evidence found")
        observed_facts.append("No post-auth activity found")
        inferred_findings.append("Credential access attempt")
        inferred_findings.append("SSH password guessing / brute-force attempt")
        # If the AI said "attack type is unknown" but we have SSH brute-force evidence, correct it
        if inv.ai_summary and "attack type is unknown" in inv.ai_summary.lower():
            unsupported_claims.append("Attack type incorrectly labeled as 'unknown' — evidence shows SSH brute-force / password guessing")
        # Distinguish source MITRE tags from ARIA inferred behavior
        if any("t1021.004" in t for t in alert_tags):
            observed_facts.append("MITRE T1021.004 (SSH) tagged by source alert — not confirmed lateral movement")
        if any("lateral movement" in t for t in alert_tags) and not evidence_flags["has_lateral_movement"]:
            unsupported_claims.append("Source alert includes 'Lateral Movement' MITRE tactic but no post-auth pivot evidence exists")

    # Extract from ai_summary (evidence-aware + negation-aware)
    if inv.ai_summary:
        summary_lower = inv.ai_summary.lower()

        # Malware: only infer if evidence exists; otherwise unsupported
        if "malware" in summary_lower:
            if evidence_flags["has_malware"]:
                inferred_findings.append("Possible malware infection (evidence-supported)")
            else:
                unsupported_claims.append("Claim of malware infection without supporting alert evidence")

        # Lateral movement: only infer if evidence exists; otherwise unsupported
        if "lateral movement" in summary_lower:
            has_lm_negation = (
                "no lateral movement" in summary_lower
                or "without lateral movement" in summary_lower
                or "no evidence of lateral movement" in summary_lower
            )
            if has_lm_negation:
                observed_facts.append("No lateral movement observed")
            elif evidence_flags["has_lateral_movement"]:
                inferred_findings.append("Possible lateral movement detected (evidence-supported)")
            else:
                unsupported_claims.append("Claim of lateral movement without supporting alert evidence")

        # Compromise: only infer if evidence exists; otherwise unsupported
        has_compromise_mention = "compromise" in summary_lower or "breach" in summary_lower
        has_compromise_negation = (
            "no compromise" in summary_lower
            or "no definitive proof of compromise" in summary_lower
            or "no evidence of compromise" in summary_lower
            or "without compromise" in summary_lower
            or "not compromised" in summary_lower
            or "no breach" in summary_lower
            or "without breach" in summary_lower
        )
        if has_compromise_mention:
            if has_compromise_negation:
                observed_facts.append("No compromise confirmed")
            elif evidence_flags["has_successful_login"]:
                inferred_findings.append("Possible system compromise (successful login observed)")
            else:
                unsupported_claims.append("Claim of system compromise without evidence of successful authentication")

        # Classification based on login evidence
        if "no successful login" in summary_lower or "no compromise" in summary_lower:
            final_classification = "suspected_threat"
            observed_facts.append("No successful authentication observed")
        elif "successful login" in summary_lower:
            if evidence_flags["has_successful_login"]:
                final_classification = "confirmed_threat"
                observed_facts.append("Successful authentication observed")
            else:
                final_classification = "suspected_threat"
                unsupported_claims.append("Claim of successful login not supported by alert evidence")

    if not observed_facts:
        unsupported_claims.append("Alert evidence is limited or could not be fully parsed. Classification may be incomplete.")

    # Build recommended next steps from playbook and evidence
    has_unresolved_jinja = bool(inv.playbook_yaml and "{{" in inv.playbook_yaml)
    if inv.playbook_yaml:
        playbook_lower = inv.playbook_yaml.lower()
        # Advisory: unresolved Jinja variables may require review
        if has_unresolved_jinja:
            recommended_next_steps.append("Review playbook for unresolved template variables")
            if source_ips:
                recommended_next_steps.append(f"Consider using exact IP {source_ips[0]} instead of Jinja2 variables")
            recommended_next_steps.append("Ensure rollback playbook exists and is precise")
            recommended_next_steps.append("Validate verification plan before execution")
        # For SSH brute-force without compromise: do NOT recommend isolation
        elif is_ssh_bruteforce and not evidence_flags["has_successful_login"]:
            if source_ips:
                recommended_next_steps.append(f"Review auth logs for {source_ips[0]}")
            else:
                recommended_next_steps.append("Review auth logs for the source IP")
            recommended_next_steps.append("Check if any successful login followed the failed attempts")
            if source_ips:
                recommended_next_steps.append(f"If policy allows, block exact source IP {source_ips[0]}")
            else:
                recommended_next_steps.append("If policy allows, block exact source IP")
            recommended_next_steps.append("Continue monitoring")
            recommended_next_steps.append("Do NOT isolate host unless compromise evidence appears")
            recommended_next_steps.append("Do NOT edit sshd_config automatically for this medium-severity case")
            recommended_next_steps.append("Do NOT restart SSH automatically for this case")
            if "isolate" in playbook_lower:
                unsupported_claims.append("Playbook recommends system isolation but no compromise evidence exists")
            if "sshd_config" in playbook_lower:
                unsupported_claims.append("Playbook edits sshd_config but this is not justified for failed-login-only evidence")
            if "restart" in playbook_lower and "ssh" in playbook_lower:
                unsupported_claims.append("Playbook restarts SSH service but no service compromise is confirmed")
        else:
            if "block" in playbook_lower or "drop" in playbook_lower:
                recommended_next_steps.append("Block attacker IP addresses at firewall")
            if "isolate" in playbook_lower:
                recommended_next_steps.append("Isolate affected systems")
            if "collect" in playbook_lower or "evidence" in playbook_lower:
                recommended_next_steps.append("Collect forensic evidence")
            if "verify" in playbook_lower:
                recommended_next_steps.append("Verify remediation effectiveness")
    else:
        recommended_next_steps.append("No remediation playbook available — manual action required")

    # Determine final classification
    if final_classification == "inconclusive":
        if evidence_flags["has_successful_login"] and (has_compromise_mention or is_ssh_bruteforce):
            final_classification = "confirmed_threat"
            confidence = "high"
        elif is_ssh_bruteforce and not evidence_flags["has_successful_login"]:
            final_classification = "suspected_threat"
            confidence = "medium" if source_ips else "low"
        elif source_ips and not evidence_flags["has_successful_login"]:
            # Network anomaly / malicious IP / port scan / threat intel cases
            network_indicators = ["malicious ip", "suspicious network", "port scan", "threat intel", "drop listed", "spamhaus", "dshield", "et drop"]
            has_network_indicator = any(ind in (inv.incident_title or "").lower() for ind in network_indicators)
            has_network_alert = any(ind in all_alert_text for ind in network_indicators + ["drop", "port scan", "reconnaissance", "scanning"])
            if has_network_indicator or has_network_alert:
                final_classification = "suspected_threat"
                confidence = "medium"
        elif inv.ai_quality_status == "passed" and inv.playbook_yaml:
            final_classification = "suspected_threat"
        elif inv.ai_quality_status == "failed":
            final_classification = "inconclusive"
        elif inv.status in ("completed", "completed_with_warnings"):
            final_classification = "confirmed_threat"

    return {
        "observed_facts": observed_facts,
        "inferred_findings": inferred_findings,
        "unsupported_claims": unsupported_claims,
        "recommended_next_steps": recommended_next_steps,
        "final_classification": final_classification,
        "confidence": confidence,
        "evidence_quality": evidence_quality,
    }


def _compute_analyst_actions(inv: Investigation, safety: dict) -> list[str]:
    """Compute available analyst actions for the current investigation state.

    Respects has_remediation_action and execution_mode so that diagnostic-only
    investigations never show approve/execute buttons, and decision_approved
    never shows execute (the endpoint rejects it anyway).

    Rollback is only offered when the remediation playbook was actually executed
    (inv.run exists) — showing rollback before execution makes no sense.
    """
    actions = []
    status = inv.status
    has_rollback = bool(inv.rollback_playbook and inv.rollback_playbook.strip())
    has_remediation = safety.get("has_remediation_action", True)
    was_executed = inv.run is not None

    if status == "pending":
        actions = ["decline"]
    elif status == "running":
        actions = []
    elif status == "awaiting_approval":
        actions = ["decline", "request_regeneration", "mark_reviewed", "edit_playbook"]
        if has_remediation:
            actions.append("approve")
    elif status == "approved":
        actions = ["archive"]
        if has_remediation:
            actions.append("execute")
    elif status == "decision_approved":
        # decision_approved means a decision was already recorded;
        # execution is not allowed without re-approval
        actions = ["archive"]
    elif status == "manual_review_required":
        actions = ["archive", "request_regeneration", "mark_reviewed", "edit_playbook"]
        if has_remediation:
            actions.append("approve")
    elif status == "failed":
        actions = ["archive", "request_regeneration"]
        if has_remediation:
            actions.append("approve")
        # Only show rollback if execution was actually attempted;
        # otherwise the failure happened before anything was applied.
        if has_rollback and was_executed:
            actions.append("rollback")
    elif status in ("completed", "completed_with_warnings"):
        actions = ["archive"]
        # Completed implies execution happened, but guard anyway.
        if has_rollback and was_executed:
            actions.append("rollback")
    elif status == "declined":
        actions = ["archive", "request_regeneration"]
    elif status == "regeneration_requested":
        actions = ["archive"]
    elif status == "reviewed_no_action":
        actions = ["archive"]
    elif status == "archived":
        actions = []

    return actions


def _compute_admin_actions(inv: Investigation, safety: dict) -> list[str]:
    """Compute available admin actions for the current investigation state.

    Kept identical to analyst actions in this pass — privilege separation
    is out of scope.  The frontend only needs one source of truth.
    """
    return _compute_analyst_actions(inv, safety)


def _has_valid_override_approval(inv: Investigation) -> bool:
    """Check if investigation has a valid admin soft-override approval record."""
    if not inv.approval:
        return False
    return bool(
        inv.approval.decision == "approved"
        and inv.approval.override is True
        and inv.approval.override_by
        and inv.approval.override_reason
    )


def _audit_events_to_dict(events: list) -> list[dict]:
    return [
        {
            "event_type": e.event_type,
            "actor": e.actor,
            "details": e.details,
            "created_at": e.created_at.isoformat(),
        }
        for e in events
    ]


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("", response_model=dict)
async def list_investigations(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    investigation_type: Optional[str] = Query(None),
    time_from: Optional[datetime] = Query(None, description="Filter investigations from this ISO datetime (inclusive)"),
    time_to: Optional[datetime] = Query(None, description="Filter investigations up to this ISO datetime (inclusive)"),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_auth),
):
    """List all investigations with optional filtering.

    Infrastructure investigations are shown only in /infrastructure/investigations.
    """
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    q = select(Investigation).where(
        Investigation.investigation_type != "infrastructure",
        Investigation.investigation_type != "runtime",
    )
    if asset_id:
        q = q.where(Investigation.asset_id == asset_id)
    if status:
        q = q.where(Investigation.status == status)
    if severity:
        q = q.where(Investigation.incident_severity == severity)
    if source:
        q = q.where(Investigation.source == source)
    if investigation_type:
        q = q.where(Investigation.investigation_type == investigation_type)
    if time_from:
        q = q.where(Investigation.created_at >= time_from)
    if time_to:
        q = q.where(Investigation.created_at <= time_to)
    if time_from and time_to and time_from > time_to:
        raise HTTPException(status_code=422, detail="time_from must not be after time_to")
    q = q.order_by(Investigation.created_at.desc()).offset(offset).limit(limit)

    result = await session.execute(q)
    investigations = result.scalars().all()

    count_q = select(func.count(Investigation.id)).where(
        Investigation.investigation_type != "infrastructure",
        Investigation.investigation_type != "runtime",
    )
    if asset_id:
        count_q = count_q.where(Investigation.asset_id == asset_id)
    if status:
        count_q = count_q.where(Investigation.status == status)
    if severity:
        count_q = count_q.where(Investigation.incident_severity == severity)
    if source:
        count_q = count_q.where(Investigation.source == source)
    if investigation_type:
        count_q = count_q.where(Investigation.investigation_type == investigation_type)
    if time_from:
        count_q = count_q.where(Investigation.created_at >= time_from)
    if time_to:
        count_q = count_q.where(Investigation.created_at <= time_to)
    total = (await session.execute(count_q)).scalar_one()

    # Compute safety for list view (lightweight)
    from response.playbook_safety import compute_investigation_safety
    inv_list = []
    for inv in investigations:
        safety = compute_investigation_safety(inv)
        inv_list.append({
            "id": inv.id,
            "incident_id": inv.incident_id,
            "local_incident_id": inv.local_incident_id,
            "upstream_incident_id": inv.upstream_incident_id,
            "incident_title": inv.incident_title,
            "incident_severity": inv.incident_severity,
            "status": inv.status,
            "source": inv.source,
            "investigation_type": inv.investigation_type,
            "ai_summary": inv.ai_summary,
            "playbook_valid": inv.playbook_valid,
            "target_host": inv.target_host,
            "target_os": inv.target_os,
            "source_ips": inv.source_ips,
            "mitre_tactics": inv.mitre_tactics,
            "playbook_safety_status": safety["playbook_safety_status"],
            "rollback_safety_status": safety["rollback_safety_status"],
            "is_safe_to_display": safety["is_safe_to_display"],
            "has_remediation_action": safety["has_remediation_action"],
            "execution_mode": safety["execution_mode"],
            "is_executable": safety["is_executable"],
            "blocked_reasons": safety["blocked_reasons"],
            "safety_tier": "safe",
            "hard_block_reasons": [],
            "completion_quality": inv.completion_quality or "unknown",
            "failed_phase": inv.failed_phase,
            "warning_phases": inv.warning_phases,
            "verification_status": inv.verification_status,
            "ai_quality_status": inv.ai_quality_status or "unknown",
            "verification_plan_json": inv.verification_plan_json,
            "created_at": inv.created_at.isoformat(),
            "updated_at": inv.updated_at.isoformat(),
        })

    return {
        "investigations": inv_list,
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.post("/manual")
async def create_manual_investigation(
    request: CreateManualInvestigationRequest,
    http_request: Request,
    session: AsyncSession = Depends(get_session),
):
    """
    Manually launch an investigation from an incident.
    """
    # 1. Validate incident exists (local first, then upstream)
    result = await session.execute(
        select(Incident).where(
            or_(Incident.id == request.incident_id, Incident.external_id == request.incident_id)
        )
    )
    local_incident = result.scalar_one_or_none()

    # Block manual investigation creation from Falco-derived incidents
    if local_incident:
        from api.routes.incidents import _incident_has_falco_link
        if await _incident_has_falco_link(session, local_incident.id):
            raise HTTPException(
                status_code=400,
                detail="Cannot create investigation from a Falco runtime incident. Use Runtime Security instead.",
            )

    incident_dict = None
    canonical_incident_id = request.incident_id
    alert_rows = []

    if local_incident:
        canonical_incident_id = local_incident.external_id or local_incident.id
        incident_dict = {
            "id": canonical_incident_id,
            "title": local_incident.title,
            "description": local_incident.description,
            "severity": local_incident.severity,
            "status": local_incident.status,
        }
        # Fetch linked alerts
        alert_result = await session.execute(
            select(Alert)
            .join(AlertIncidentLink, Alert.id == AlertIncidentLink.alert_id)
            .where(AlertIncidentLink.incident_id == local_incident.id)
            .limit(100)
        )
        alert_rows = alert_result.scalars().all()
    else:
        # Try upstream
        from config import get_settings
        if get_settings().upstream_enabled:
            from pipeline.sender import client
            try:
                upstream_incident = await client.get_incident(request.incident_id)
                if upstream_incident:
                    incident_dict = upstream_incident
                    canonical_incident_id = upstream_incident.get("id", request.incident_id)
                    upstream_alerts = await client.get_incident_alerts(canonical_incident_id)
                    alert_rows = upstream_alerts if upstream_alerts else []
            except Exception:
                pass

    if not incident_dict:
        raise HTTPException(status_code=404, detail="Incident not found")

    # 2. Check for active investigation (with process-level lock to prevent race conditions)
    import asyncio
    _investigation_locks: dict[str, asyncio.Lock] = getattr(create_manual_investigation, "_locks", {})
    if canonical_incident_id not in _investigation_locks:
        _investigation_locks[canonical_incident_id] = asyncio.Lock()
    create_manual_investigation._locks = _investigation_locks

    async with _investigation_locks[canonical_incident_id]:
        active_result = await session.execute(
            select(Investigation).where(
                Investigation.incident_id == canonical_incident_id,
                Investigation.status != "archived",
            )
        )
        if active_result.scalar_one_or_none():
            raise HTTPException(
                status_code=409,
                detail="Incident already has an active investigation",
            )

    # 3. Build context from linked alerts
    if alert_rows:
        if local_incident:
            alert_dicts = []
            for a in alert_rows:
                alert_dicts.append({
                    "id": a.id,
                    "title": a.title,
                    "description": a.description,
                    "severity": a.severity,
                    "source": a.source,
                    "source_ip": a.source_ip,
                    "dest_ip": a.dest_ip,
                    "hostname": a.hostname,
                    "rule_name": a.rule_name,
                    "tags": a.tags or [],
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                })
        else:
            alert_dicts = alert_rows if isinstance(alert_rows, list) else []

        try:
            from response.watcher.context_builder import _build_investigation_context
            context = _build_investigation_context(incident_dict, alert_dicts)
        except Exception as e:
            logger.warning("context_build_failed", error=str(e)[:100])
            # Build simplified context manually
            source_ips = set()
            hostnames = set()
            mitre_tactics = set()
            timeline = []
            for idx, a in enumerate(alert_dicts):
                if a.get("source_ip"):
                    source_ips.add(a["source_ip"])
                if a.get("hostname"):
                    hostnames.add(a["hostname"])
                for tag in a.get("tags", []):
                    if isinstance(tag, str) and tag.startswith("mitre-tactic-"):
                        mitre_tactics.add(tag.replace("mitre-tactic-", ""))
                timeline.append({
                    "idx": idx + 1,
                    "time": a.get("created_at") or a.get("timestamp", ""),
                    "severity": a.get("severity", "medium"),
                    "source": a.get("source", "unknown"),
                    "title": a.get("title", ""),
                })
            context = {
                "incident": incident_dict,
                "source_ips": sorted(list(source_ips)),
                "hostnames": sorted(list(hostnames)),
                "mitre_tactics": sorted(list(mitre_tactics)),
                "timeline": timeline,
                "alert_count": len(alert_dicts),
                "alerts": alert_dicts,
            }
    else:
        context = {"incident": incident_dict, "alert_count": 0, "alerts": []}

    # 4. Create Investigation row
    import uuid

    investigation_id = str(uuid.uuid4())

    target_host = request.target_host
    if not target_host and context.get("hostnames"):
        target_host = context["hostnames"][0]
    elif not target_host and context.get("source_ips"):
        target_host = context["source_ips"][0]
    if not target_host:
        from config import get_settings

        settings = get_settings()
        target_host = settings.ansible_remote_host or "localhost"

    await session.execute(
        insert(Investigation).values(
            id=investigation_id,
            incident_id=canonical_incident_id,
            local_incident_id=local_incident.id if local_incident else None,
            upstream_incident_id=local_incident.external_id if local_incident and local_incident.external_id else (canonical_incident_id if not local_incident else None),
            incident_title=incident_dict.get("title", ""),
            incident_severity=incident_dict.get("severity", "medium"),
            incident_status=incident_dict.get("status", "open"),
            status="pending",
            source="manual",
            target_host=target_host,
            target_user=request.target_user or "root",
            source_ips=",".join(context.get("source_ips", [])) if context.get("source_ips") else None,
            hostnames=",".join(context.get("hostnames", [])) if context.get("hostnames") else None,
            mitre_tactics=",".join(context.get("mitre_tactics", [])) if context.get("mitre_tactics") else None,
            created_by=request.created_by,
            created_at=datetime.now(timezone.utc),
        )
    )

    # 5. Create InvestigationAlert snapshots
    if local_incident:
        alert_dicts_for_storage = []
        for a in alert_rows:
            alert_dicts_for_storage.append({
                "id": a.id,
                "title": a.title,
                "description": a.description,
                "severity": a.severity,
                "source": a.source,
                "source_ip": a.source_ip,
                "dest_ip": a.dest_ip,
                "hostname": a.hostname,
                "rule_name": a.rule_name,
                "tags": a.tags or [],
                "created_at": a.created_at.isoformat() if a.created_at else None,
            })
    else:
        alert_dicts_for_storage = alert_rows if isinstance(alert_rows, list) else []

    for alert in alert_dicts_for_storage:
        await session.execute(
            insert(InvestigationAlert).values(
                id=str(uuid.uuid4()),
                investigation_id=investigation_id,
                alert_id=alert.get("id", ""),
                alert_json=json.dumps(alert),
                severity=alert.get("severity", "medium"),
                source=alert.get("source", {}).get("name", "unknown") if isinstance(alert.get("source"), dict) else str(alert.get("source", "unknown")),
                title=alert.get("title", ""),
            )
        )

    await session.commit()

    # 6. Spawn AI engine as background task (with failure handling)
    import asyncio
    from response.watcher.ai_runner import _run_ai_engine

    async def _run_ai_engine_safe(inv_id: str, ctx: dict):
        try:
            await _run_ai_engine(inv_id, ctx)
        except Exception as e:
            logger.error("manual_investigation_ai_engine_failed", investigation_id=inv_id, error=str(e)[:200])
            # Update investigation status to failed
            try:
                async with AsyncSessionLocal() as fail_session:
                    await fail_session.execute(
                        update(Investigation)
                        .where(Investigation.id == inv_id)
                        .values(status="failed", ai_error=str(e)[:500], updated_at=datetime.now(timezone.utc))
                    )
                    await fail_session.commit()
            except Exception as db_err:
                logger.error("manual_investigation_status_update_failed", investigation_id=inv_id, error=str(db_err)[:200])

    asyncio.create_task(_run_ai_engine_safe(investigation_id, context))

    # 7. Broadcast WebSocket update
    try:
        from response.watcher.ai_runner import _broadcast_new_investigation

        await _broadcast_new_investigation(
            investigation_id,
            incident_dict.get("title", ""),
            incident_dict.get("severity", "medium"),
        )
    except Exception as e:
        logger.warning("manual_investigation_websocket_broadcast_failed", investigation_id=investigation_id, error=str(e)[:100])

    # 8. Record creation audit event
    await record_audit_event(session, investigation_id, "created", actor=request.created_by or "analyst", details=f"Manual investigation created for incident {canonical_incident_id}", **_audit_ctx(http_request))

    # 9. Return investigation
    return {
        "investigation_id": investigation_id,
        "incident_id": canonical_incident_id,
        "incident_title": incident_dict.get("title", ""),
        "incident_severity": incident_dict.get("severity", "medium"),
        "status": "pending",
        "source": "manual",
        "target_host": target_host,
        "target_user": request.target_user or "root",
    }


@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
):
    """Count investigations by status."""
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    stmt = (
        select(Investigation.status, func.count(Investigation.id))
        .where(
            Investigation.investigation_type != "infrastructure",
            Investigation.investigation_type != "runtime",
        )
        .group_by(Investigation.status)
    )
    if asset_id:
        stmt = stmt.where(Investigation.asset_id == asset_id)
    result = await session.execute(stmt)
    counts = {row[0]: row[1] for row in result.all()}
    statuses = [
        "pending",
        "awaiting_approval",
        "approved",
        "decision_approved",
        "declined",
        "running",
        "completed",
        "completed_with_warnings",
        "failed",
        "archived",
        "manual_review_required",
        "regeneration_requested",
        "reviewed_no_action",
    ]
    data = {s: counts.get(s, 0) for s in statuses}
    data["total"] = sum(data.values())
    return data


@router.get("/{investigation_id}", response_model=InvestigationDetail)
async def get_investigation(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get full investigation detail including alerts, approval, run, verification."""
    inv = await _get_investigation_or_404(investigation_id, session)
    # Runtime investigations are scoped to /runtime/investigations only
    if inv.investigation_type == "runtime":
        raise HTTPException(status_code=404, detail="Investigation not found")
    from response.playbook_safety import compute_investigation_safety
    safety = compute_investigation_safety(inv)
    return InvestigationDetail(
        id=inv.id,
        incident_id=inv.incident_id,
        local_incident_id=inv.local_incident_id,
        upstream_incident_id=inv.upstream_incident_id,
        incident_title=inv.incident_title,
        incident_severity=inv.incident_severity,
        incident_status=inv.incident_status,
        status=inv.status,
        source=inv.source,
        investigation_type=inv.investigation_type,
        resource_context_json=inv.resource_context_json,
        ai_summary=inv.ai_summary,
        ai_narrative=inv.ai_narrative,
        ai_risk=inv.ai_risk,
        playbook_yaml=inv.playbook_yaml,
        playbook_valid=inv.playbook_valid,
        target_host=inv.target_host,
        target_user=inv.target_user,
        target_os=inv.target_os,
        source_ips=inv.source_ips,
        hostnames=inv.hostnames,
        mitre_tactics=inv.mitre_tactics,
        ai_error=inv.ai_error,
        evidence_json=inv.evidence_json,
        rollback_playbook=inv.rollback_playbook,
        created_at=inv.created_at,
        updated_at=inv.updated_at,
        alerts=[AlertSummary(**alert_snapshot_to_dict(a)) for a in inv.alerts],
        approval=_approval_to_dict(inv.approval),
        run=_run_to_dict(inv.run),
        verification=_verification_to_dict(inv.verification),
        workflow=build_workflow_summary(inv),
        playbook_summary=build_playbook_summary(inv),
        playbook_safety_status=safety["playbook_safety_status"],
        rollback_safety_status=safety["rollback_safety_status"],
        is_safe_to_display=safety["is_safe_to_display"],
        has_remediation_action=safety["has_remediation_action"],
        execution_mode=safety["execution_mode"],
        is_executable=safety["is_executable"],
        blocked_reasons=safety["blocked_reasons"],
        safety_tier="safe",
        hard_block_reasons=[],
        completion_quality=inv.completion_quality or "unknown",
        failed_phase=inv.failed_phase,
        warning_phases=inv.warning_phases,
        verification_status=inv.verification_status,
        ai_quality_status=inv.ai_quality_status or "unknown",
        ai_quality_json=inv.ai_quality_json,
        verification_plan_json=inv.verification_plan_json,
        post_rollback_verification_json=inv.post_rollback_verification_json,
        truth_report=_build_truth_report(inv),
        analyst_actions=_compute_analyst_actions(inv, safety),
        admin_actions=_compute_admin_actions(inv, safety),
        audit_events=_audit_events_to_dict(inv.audit_events),
        asset_id=inv.asset_id,
    )


@router.patch("/{investigation_id}/playbook")
async def edit_playbook(
    investigation_id: str,
    body: EditPlaybookRequest,
    http_request: Request,
    session: AsyncSession = Depends(get_session),
):
    """
    Analyst edits the AI-generated playbook before approving.
    Only allowed when status=awaiting_approval.
    """
    inv = await _get_investigation_or_404(investigation_id, session)
    if inv.status != "awaiting_approval":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot edit playbook when status is '{inv.status}'. Must be 'awaiting_approval'.",
        )
    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(playbook_yaml=body.playbook_yaml, updated_at=datetime.now(timezone.utc))
    )
    await session.commit()
    await record_audit_event(session, investigation_id, "playbook_edited", actor="analyst", details="Playbook edited by analyst", **_audit_ctx(http_request))
    return {"message": "Playbook updated successfully"}


@router.put("/{investigation_id}/playbook")
async def update_playbook(
    investigation_id: str,
    body: EditPlaybookRequest,
    http_request: Request,
    session: AsyncSession = Depends(get_session),
):
    """
    Update/edit playbook YAML.
    Alias for PATCH method - provides RESTful PUT semantics.
    Only allowed when status=awaiting_approval.
    """
    inv = await _get_investigation_or_404(investigation_id, session)
    if inv.status != "awaiting_approval":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot edit playbook when status is '{inv.status}'. Must be 'awaiting_approval'.",
        )
    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(playbook_yaml=body.playbook_yaml, updated_at=datetime.now(timezone.utc))
    )
    await session.commit()
    await record_audit_event(session, investigation_id, "playbook_edited", actor="analyst", details="Playbook updated by analyst", **_audit_ctx(http_request))
    return {"message": "Playbook updated successfully"}


@router.get("/{investigation_id}/playbook/yaml")
async def get_playbook_yaml(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """
    Get raw YAML of the playbook.
    Returns only the YAML string for direct display in YAML editor.
    """
    inv = await _get_investigation_or_404(investigation_id, session)
    if not inv.playbook_yaml:
        raise HTTPException(
            status_code=404, detail="No playbook generated for this investigation"
        )

    return {
        "investigation_id": investigation_id,
        "yaml": inv.playbook_yaml,
        "valid": inv.playbook_valid,
    }


@router.post("/{investigation_id}/execute")
async def execute_playbook_direct(
    investigation_id: str,
    body: ApproveRequest,
    http_request: Request,
    session: AsyncSession = Depends(get_session),
):
    """
    Execute an already-approved playbook.
    """
    inv = await _get_investigation_or_404(investigation_id, session)

    if inv.status != "approved":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot execute when status is '{inv.status}'. Approve the playbook first.",
        )

    if not inv.playbook_yaml:
        raise HTTPException(status_code=400, detail="No playbook to execute")

    # ── Pre-execution asset / remediation re-validation ──────────────────────
    if inv.asset_id:
        from config import get_settings
        settings = get_settings()
        if settings.multi_server_enabled:
            asset_result = await session.execute(
                select(MonitoredAsset).where(MonitoredAsset.asset_id == inv.asset_id)
            )
            asset = asset_result.scalar_one_or_none()
            if not asset:
                raise HTTPException(
                    status_code=400,
                    detail=f"EXECUTION BLOCKED: Target asset '{inv.asset_id}' does not exist. Configure it in Settings > Assets.",
                )
            if not asset.enabled:
                raise HTTPException(
                    status_code=400,
                    detail=f"EXECUTION BLOCKED: Target asset '{asset.name}' ({inv.asset_id}) is disabled. Enable it in Settings > Assets.",
                )
            ansible_cfg = asset.ansible_config_json or {}
            if not ansible_cfg.get("ansible_host"):
                raise HTTPException(
                    status_code=400,
                    detail=f"EXECUTION BLOCKED: Ansible host is not configured for asset '{asset.name}' ({inv.asset_id}). Configure it in Settings > Assets.",
                )
            if not asset.remediation_enabled:
                raise HTTPException(
                    status_code=400,
                    detail=f"EXECUTION BLOCKED: Remediation is not enabled for asset '{asset.name}' ({inv.asset_id}). Enable it in Settings > Assets.",
                )
            # Validate auth credentials match auth_type
            auth_type = ansible_cfg.get("auth_type", "private_key")
            if auth_type == "private_key":
                key_ref = ansible_cfg.get("ssh_key_ref")
                if key_ref and not os.path.exists(key_ref):
                    raise HTTPException(
                        status_code=400,
                        detail=f"EXECUTION BLOCKED: SSH key file not found at {key_ref} for asset '{asset.name}'. Check the path in Settings > Ansible.",
                    )
            elif auth_type == "password":
                secret_ref = ansible_cfg.get("password_secret_ref")
                if not secret_ref or not os.environ.get(secret_ref):
                    raise HTTPException(
                        status_code=400,
                        detail=f"EXECUTION BLOCKED: SSH password environment variable is not set for asset '{asset.name}'. Add it to .env and restart the backend.",
                    )

    import asyncio
    from response.ansible_exec import execute_playbook

    now = datetime.now(timezone.utc)
    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="running", updated_at=now)
    )
    await session.commit()

    await record_audit_event(session, investigation_id, "execution_started", actor=body.decided_by, details="Playbook execution started", **_audit_ctx(http_request))

    asyncio.create_task(execute_playbook(investigation_id))

    return {
        "message": "Playbook execution started",
        "investigation_id": investigation_id,
        "status": "running",
        "run_status_url": f"/api/v1/investigations/{investigation_id}/run-status",
    }


@router.post("/{investigation_id}/approve")
async def approve_investigation(
    investigation_id: str,
    body: ApproveRequest,
    http_request: Request,
    session: AsyncSession = Depends(get_session),
):
    """
    Approve the AI-generated playbook for execution.
    Triggers the Ansible executor.
    """
    inv = await _get_investigation_or_404(investigation_id, session)
    if not _validate_status_transition(inv.status, "approved"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot approve when status is '{inv.status}'. Allowed transitions: {_ALLOWED_TRANSITIONS.get(inv.status, set())}",
        )
    if not inv.playbook_yaml:
        raise HTTPException(status_code=400, detail="No playbook generated yet")

    # AI quality gate: do not approve if summary is empty or quality failed
    if not inv.ai_summary or len(inv.ai_summary.strip()) < 10:
        raise HTTPException(
            status_code=400,
            detail="APPROVAL BLOCKED: AI summary is empty or insufficient. The investigation requires manual review.",
        )
    if inv.ai_quality_status == "failed":
        raise HTTPException(
            status_code=400,
            detail=f"APPROVAL BLOCKED: AI quality check failed. Reasons: {inv.ai_quality_json.get('grounding', {}).get('reasons', []) if inv.ai_quality_json else 'unknown'}",
        )

    # ── Pre-approval asset / remediation validation ──────────────────────────
    if inv.asset_id:
        from config import get_settings
        settings = get_settings()
        if settings.multi_server_enabled:
            asset_result = await session.execute(
                select(MonitoredAsset).where(MonitoredAsset.asset_id == inv.asset_id)
            )
            asset = asset_result.scalar_one_or_none()
            if not asset:
                raise HTTPException(
                    status_code=400,
                    detail=f"APPROVAL BLOCKED: Target asset '{inv.asset_id}' does not exist. Configure it in Settings > Assets.",
                )
            if not asset.enabled:
                raise HTTPException(
                    status_code=400,
                    detail=f"APPROVAL BLOCKED: Target asset '{asset.name}' ({inv.asset_id}) is disabled. Enable it in Settings > Assets.",
                )
            ansible_cfg = asset.ansible_config_json or {}
            if not ansible_cfg.get("ansible_host"):
                raise HTTPException(
                    status_code=400,
                    detail=f"APPROVAL BLOCKED: Ansible host is not configured for asset '{asset.name}' ({inv.asset_id}). Configure it in Settings > Assets.",
                )
            if not asset.remediation_enabled:
                raise HTTPException(
                    status_code=400,
                    detail=f"APPROVAL BLOCKED: Remediation is not enabled for asset '{asset.name}' ({inv.asset_id}). Enable it in Settings > Assets.",
                )
            # Validate auth credentials match auth_type
            auth_type = ansible_cfg.get("auth_type", "private_key")
            if auth_type == "private_key":
                key_ref = ansible_cfg.get("ssh_key_ref")
                if key_ref and not os.path.exists(key_ref):
                    raise HTTPException(
                        status_code=400,
                        detail=f"APPROVAL BLOCKED: SSH key file not found at {key_ref} for asset '{asset.name}'. Check the path in Settings > Ansible.",
                    )
            elif auth_type == "password":
                secret_ref = ansible_cfg.get("password_secret_ref")
                if not secret_ref or not os.environ.get(secret_ref):
                    raise HTTPException(
                        status_code=400,
                        detail=f"APPROVAL BLOCKED: SSH password environment variable is not set for asset '{asset.name}'. Add it to .env and restart the backend.",
                    )

    # Record approval (skip if already exists to allow retrying failed investigations)
    from sqlalchemy import select as sa_select
    existing_approval = await session.execute(
        sa_select(PlaybookApproval).where(PlaybookApproval.investigation_id == investigation_id)
    )
    if existing_approval.scalar_one_or_none():
        logger.info("approval_already_exists", investigation_id=investigation_id, action="reusing")
    else:
        approval = PlaybookApproval(
            investigation_id=investigation_id,
            decision="approved",
            decided_by=body.decided_by,
            decided_at=datetime.now(timezone.utc),
        )
        session.add(approval)

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="approved", updated_at=datetime.now(timezone.utc))
    )
    await record_audit_event(session, investigation_id, "approved", actor=body.decided_by, details="Playbook approved for execution", **_audit_ctx(http_request))
    await session.commit()

    # Broadcast approval via WebSocket
    try:
        from api.websocket import broadcast_investigation_change

        await broadcast_investigation_change(
            investigation_id,
            "awaiting_approval",
            "approved",
            f"Approved by {body.decided_by}",
        )
    except Exception:
        pass

    # Trigger Ansible executor as background task
    import asyncio
    from response.ansible_exec import execute_playbook

    asyncio.create_task(execute_playbook(investigation_id))

    return {
        "message": "Playbook approved. Execution started.",
        "investigation_id": investigation_id,
    }


@router.post("/{investigation_id}/decline")
async def decline_investigation(
    investigation_id: str,
    body: DeclineRequest,
    http_request: Request,
    session: AsyncSession = Depends(get_session),
):
    """
    Decline the playbook. Records reason and moves to archive.
    """
    inv = await _get_investigation_or_404(investigation_id, session)
    if not _validate_status_transition(inv.status, "declined"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot decline when status is '{inv.status}'. Allowed transitions: {_ALLOWED_TRANSITIONS.get(inv.status, set())}",
        )

    # Record decline (skip if already exists to allow retrying failed investigations)
    from sqlalchemy import select as sa_select
    existing_approval = await session.execute(
        sa_select(PlaybookApproval).where(PlaybookApproval.investigation_id == investigation_id)
    )
    if existing_approval.scalar_one_or_none():
        logger.info("decline_already_exists", investigation_id=investigation_id, action="reusing")
    else:
        approval = PlaybookApproval(
            investigation_id=investigation_id,
            decision="declined",
            decided_by=body.decided_by,
            decided_at=datetime.now(timezone.utc),
            reason=body.reason,
        )
        session.add(approval)

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="declined", updated_at=datetime.now(timezone.utc))
    )
    await record_audit_event(session, investigation_id, "declined", actor=body.decided_by, details=body.reason or "Investigation declined", **_audit_ctx(http_request))
    await session.commit()

    # Broadcast decline via WebSocket
    try:
        from api.websocket import broadcast_investigation_change

        await broadcast_investigation_change(
            investigation_id,
            "awaiting_approval",
            "declined",
            f"Declined by {body.decided_by}: {body.reason}",
        )
    except Exception:
        pass

    # Archive the declined investigation
    import asyncio
    from response.archiver import archive_investigation

    asyncio.create_task(archive_investigation(investigation_id, fix_status="declined"))

    return {
        "message": "Investigation declined and queued for archive",
        "investigation_id": investigation_id,
    }


@router.post("/{investigation_id}/request-regeneration")
async def request_regeneration(
    investigation_id: str,
    body: RegenerateRequest,
    http_request: Request,
    session: AsyncSession = Depends(get_session),
):
    """
    Analyst requests AI playbook regeneration.
    Moves investigation to regeneration_requested status and re-runs AI engine.
    """
    inv = await _get_investigation_or_404(investigation_id, session)
    if not _validate_status_transition(inv.status, "regeneration_requested"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot request regeneration when status is '{inv.status}'. Allowed transitions: {_ALLOWED_TRANSITIONS.get(inv.status, set())}",
        )

    # Record regeneration request
    from sqlalchemy import select as sa_select
    existing_approval = await session.execute(
        sa_select(PlaybookApproval).where(PlaybookApproval.investigation_id == investigation_id)
    )
    if existing_approval.scalar_one_or_none():
        logger.info("regeneration_reuses_approval", investigation_id=investigation_id, action="reusing")
    else:
        approval = PlaybookApproval(
            investigation_id=investigation_id,
            decision="regeneration_requested",
            decided_by=body.decided_by,
            decided_at=datetime.now(timezone.utc),
            reason=body.reason,
        )
        session.add(approval)

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(
            status="regeneration_requested",
            updated_at=datetime.now(timezone.utc),
            ai_summary=None,
            ai_narrative=None,
            ai_risk=None,
            playbook_yaml=None,
            rollback_playbook=None,
            ai_quality_status="unknown",
            ai_quality_json=None,
            playbook_valid=False,
        )
    )
    await session.commit()
    await record_audit_event(
        session, investigation_id, "regeneration_requested",
        actor=body.decided_by,
        details=body.reason or "Analyst requested playbook regeneration",
        **_audit_ctx(http_request),
    )

    # Create ARIA alert
    try:
        from response.aria_alerts import alert_on_regeneration_requested
        await alert_on_regeneration_requested(session, inv, body.decided_by, body.reason)
    except Exception:
        pass

    # Re-run AI engine in background
    import asyncio
    import json
    from response.watcher.ai_runner import _run_ai_engine
    from response.watcher.context_builder import _build_investigation_context

    async def _regenerate_safe(inv_id: str):
        try:
            # Rebuild context from investigation data (alerts, incident metadata)
            async with AsyncSessionLocal() as ctx_session:
                from sqlalchemy import select as sa_select
                stmt = sa_select(Investigation).where(Investigation.id == inv_id).options(
                    selectinload(Investigation.alerts)
                )
                result = await ctx_session.execute(stmt)
                inv_ctx = result.scalar_one_or_none()
                if not inv_ctx:
                    raise ValueError(f"Investigation {inv_id} not found for regeneration context")

                incident = {
                    "id": inv_ctx.incident_id,
                    "title": inv_ctx.incident_title,
                    "severity": inv_ctx.incident_severity,
                    "status": inv_ctx.incident_status,
                    "source": inv_ctx.source,
                    "investigation_type": inv_ctx.investigation_type,
                    "target_host": inv_ctx.target_host,
                    "target_user": inv_ctx.target_user,
                    "target_os": inv_ctx.target_os,
                    "source_ips": inv_ctx.source_ips,
                    "hostnames": inv_ctx.hostnames,
                    "mitre_tactics": inv_ctx.mitre_tactics,
                }
                alerts_raw = []
                for a in inv_ctx.alerts:
                    try:
                        alert_data = json.loads(a.alert_json) if a.alert_json else {}
                    except json.JSONDecodeError:
                        alert_data = {}
                    alert_data.setdefault("id", a.alert_id)
                    alert_data.setdefault("severity", a.severity)
                    alert_data.setdefault("source", a.source)
                    alert_data.setdefault("title", a.title)
                    alert_data.setdefault("created_at", a.created_at.isoformat() if a.created_at else "")
                    alerts_raw.append(alert_data)

                context = _build_investigation_context(incident, alerts_raw)
                logger.info("regeneration_context_rebuilt", investigation_id=inv_id, context_keys=list(context.keys()), alert_count=len(alerts_raw))

            await _run_ai_engine(inv_id, context)
        except Exception as e:
            logger.error("regeneration_failed", investigation_id=inv_id, error=str(e)[:200])
            try:
                async with AsyncSessionLocal() as fail_session:
                    await fail_session.execute(
                        update(Investigation)
                        .where(Investigation.id == inv_id)
                        .values(status="failed", ai_error=str(e)[:500], updated_at=datetime.now(timezone.utc))
                    )
                    await fail_session.commit()
            except Exception:
                pass

    asyncio.create_task(_regenerate_safe(investigation_id))

    return {
        "message": "Regeneration requested. AI engine is re-analyzing the incident.",
        "investigation_id": investigation_id,
        "status": "regeneration_requested",
    }


@router.post("/{investigation_id}/mark-reviewed")
async def mark_reviewed(
    investigation_id: str,
    body: MarkReviewedRequest,
    http_request: Request,
    session: AsyncSession = Depends(get_session),
):
    """
    Analyst marks investigation as reviewed with no action required.
    Moves to reviewed_no_action status.
    """
    inv = await _get_investigation_or_404(investigation_id, session)
    if not _validate_status_transition(inv.status, "reviewed_no_action"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot mark as reviewed when status is '{inv.status}'. Allowed transitions: {_ALLOWED_TRANSITIONS.get(inv.status, set())}",
        )

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="reviewed_no_action", updated_at=datetime.now(timezone.utc))
    )
    await session.commit()
    await record_audit_event(
        session, investigation_id, "reviewed_no_action",
        actor=body.decided_by,
        details=body.reason or "Analyst reviewed — no action required",
        **_audit_ctx(http_request),
    )

    return {
        "message": "Investigation marked as reviewed (no action)",
        "investigation_id": investigation_id,
        "status": "reviewed_no_action",
    }


@router.post("/{investigation_id}/archive")
async def archive_investigation_endpoint(
    investigation_id: str,
    http_request: Request,
    session: AsyncSession = Depends(get_session),
):
    """
    Manually archive an investigation. Idempotent — skips if already archived.
    """
    inv = await _get_investigation_or_404(investigation_id, session)

    if inv.status == "archived":
        return {"message": "Already archived", "investigation_id": investigation_id}

    if not _validate_status_transition(inv.status, "archived"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot archive when status is '{inv.status}'. Allowed transitions: {_ALLOWED_TRANSITIONS.get(inv.status, set())}",
        )

    # Determine fix status from existing verification/approval
    fix_status = "unknown"
    if inv.verification:
        fix_status = inv.verification.status
    elif inv.status == "declined":
        fix_status = "declined"
    elif inv.status == "completed":
        fix_status = "verified"

    # Check if already archived in DB
    existing = await session.execute(
        select(Archive).where(Archive.investigation_id == investigation_id)
    )
    if existing.scalar_one_or_none():
        return {
            "message": "Investigation already archived",
            "investigation_id": investigation_id,
        }

    import asyncio
    from response.archiver import archive_investigation

    asyncio.create_task(archive_investigation(investigation_id, fix_status=fix_status))

    await session.execute(
        update(Investigation)
        .where(Investigation.id == investigation_id)
        .values(status="archived", updated_at=datetime.now(timezone.utc))
    )
    await record_audit_event(session, investigation_id, "archived", actor="analyst", details="Investigation manually archived", **_audit_ctx(http_request))
    await session.commit()

    # Broadcast via WebSocket
    try:
        from api.websocket import broadcast_investigation_change

        await broadcast_investigation_change(
            investigation_id,
            inv.status,
            "archived",
            "Investigation manually archived",
        )
    except Exception:
        pass

    return {
        "message": "Investigation archived",
        "investigation_id": investigation_id,
    }


@router.get("/{investigation_id}/run-status")
async def get_run_status(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get live Ansible playbook run status and output."""
    result = await session.execute(
        select(PlaybookRun).where(PlaybookRun.investigation_id == investigation_id)
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(
            status_code=404, detail="No playbook run found for this investigation"
        )

    return {
        "status": run.status,
        "exit_code": run.exit_code,
        "output": run.output or "",
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "current_phase": run.current_phase,
        "phases": run.phases_json or {},
    }


@router.get("/{investigation_id}/alerts")
async def get_investigation_alerts(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get alerts linked to a specific investigation."""
    result = await session.execute(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .options(selectinload(Investigation.alerts))
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return {
        "investigation_id": investigation_id,
        "alerts": [alert_snapshot_to_dict(a) for a in inv.alerts],
    }


@router.get("/{investigation_id}/timeline")
async def get_investigation_timeline(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get full timeline of investigation events for frontend visualization."""
    from sqlalchemy.orm import selectinload

    result = await session.execute(
        select(Investigation)
        .options(
            selectinload(Investigation.alerts),
            selectinload(Investigation.approval),
            selectinload(Investigation.run),
            selectinload(Investigation.verification),
            selectinload(Investigation.audit_events),
        )
        .where(Investigation.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    events = []
    workflow = build_workflow_summary(inv)

    # 1. Creation event
    events.append(
        {
            "timestamp": inv.created_at.isoformat(),
            "event": "created",
            "details": f"Investigation created from incident {inv.incident_id[:8]}...",
            "severity": inv.incident_severity,
        }
    )

    # 2. Check if AI analysis completed
    if inv.ai_summary:
        events.append(
            {
                "timestamp": inv.updated_at.isoformat(),
                "event": "ai_analysis",
                "details": "AI generated summary and risk assessment",
                "severity": "info",
            }
        )

    # 3. Check for playbook generation
    if inv.playbook_yaml:
        events.append(
            {
                "timestamp": inv.updated_at.isoformat(),
                "event": "playbook_generated",
                "details": "Ansible playbook generated for remediation",
                "severity": "info",
            }
        )

    # 4. Approval status
    if inv.status == "awaiting_approval":
        events.append(
            {
                "timestamp": inv.updated_at.isoformat(),
                "event": "awaiting_approval",
                "details": "Waiting for analyst approval",
                "severity": "warning",
            }
        )

    # 5. Check approval record
    if inv.approval:
        if inv.approval.decision == "approved":
            events.append(
                {
                    "timestamp": inv.approval.decided_at.isoformat(),
                    "event": "approved",
                    "details": f"Analyst approved playbook",
                    "severity": "success",
                }
            )
        elif inv.approval.decision == "declined":
            events.append(
                {
                    "timestamp": inv.approval.decided_at.isoformat(),
                    "event": "declined",
                    "details": f"Analyst declined: {inv.approval.reason or 'No reason provided'}",
                    "severity": "error",
                }
            )

    # 6. Playbook run status
    if inv.run:
        events.append(
            {
                "timestamp": inv.run.started_at.isoformat(),
                "event": "running",
                "details": "Playbook execution started",
                "severity": "info",
            }
        )

        if inv.run.finished_at:
            if inv.run.status == "completed":
                events.append(
                    {
                        "timestamp": inv.run.finished_at.isoformat(),
                        "event": "completed",
                        "details": "Remediation successful - fix verified",
                        "severity": "success",
                    }
                )
            elif inv.run.status == "failed":
                events.append(
                    {
                        "timestamp": inv.run.finished_at.isoformat(),
                        "event": "failed",
                        "details": f"Remediation failed (exit code: {inv.run.exit_code})",
                        "severity": "error",
                    }
                )

    # 7. Verification status
    if inv.verification:
        if inv.verification.status == "likely_fixed":
            events.append(
                {
                    "timestamp": inv.verification.checked_at.isoformat(),
                    "event": "verified",
                    "details": "Post-remediation check confirmed fix",
                    "severity": "success",
                }
            )
        elif inv.verification.status == "not_fixed":
            events.append(
                {
                    "timestamp": inv.verification.checked_at.isoformat(),
                    "event": "verification_failed",
                    "details": "Post-remediation check shows issue persists",
                    "severity": "error",
                }
            )

    # 8. Archive status
    if inv.status == "archived":
        events.append(
            {
                "timestamp": inv.updated_at.isoformat(),
                "event": "archived",
                "details": "Investigation archived",
                "severity": "info",
            }
        )

    # 9. Merge audit events from DB
    for ae in inv.audit_events:
        events.append(
            {
                "timestamp": ae.created_at.isoformat(),
                "event": ae.event_type,
                "details": ae.details or f"{ae.actor}: {ae.event_type}",
                "severity": "info",
                "actor": ae.actor,
            }
        )

    # Sort by timestamp (most recent first)
    events.sort(key=lambda x: x["timestamp"], reverse=True)

    return {
        "investigation_id": inv.id,
        "incident_title": inv.incident_title,
        "current_status": inv.status,
        "workflow": workflow,
        "events": events,
    }


@router.get("/{investigation_id}/evidence-files")
async def get_evidence_files(
    investigation_id: str,
    session: AsyncSession = Depends(get_session),
):
    """List evidence files collected for this investigation.
    
    Returns metadata about the evidence archive and a list of files
    with sizes and timestamps.
    """
    inv = await _get_investigation_or_404(investigation_id, session)
    evidence = inv.evidence_json or {}
    
    local_path = evidence.get("local_path")
    archive_path = evidence.get("archive_path")
    
    files = []
    archive_size = None
    archive_exists = False
    
    if archive_path and Path(archive_path).exists():
        archive_exists = True
        archive_size = Path(archive_path).stat().st_size
    
    if local_path and Path(local_path).exists():
        evidence_dir = Path(local_path)
        for fpath in sorted(evidence_dir.rglob("*")):
            if fpath.is_file():
                stat = fpath.stat()
                files.append({
                    "name": fpath.name,
                    "relative_path": str(fpath.relative_to(evidence_dir)),
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                })
    
    return {
        "investigation_id": investigation_id,
        "collected_at": evidence.get("collected_at"),
        "exit_code": evidence.get("exit_code"),
        "target_path": evidence.get("path"),
        "local_path": local_path,
        "archive_path": archive_path,
        "archive_exists": archive_exists,
        "archive_size_bytes": archive_size,
        "file_count": len(files),
        "files": files,
    }


# ── Rollback endpoint ────────────────────────────────────────────────────────

class RollbackRequest(BaseModel):
    decided_by: str = "analyst"
    reason: str


@router.post("/{investigation_id}/rollback")
async def rollback_investigation(
    investigation_id: str,
    body: RollbackRequest,
    http_request: Request,
    session: AsyncSession = Depends(get_session),
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    """
    Execute the rollback playbook for a completed investigation.
    Requires admin authorization.
    """
    # Validate admin access
    actor = _validate_admin_access(body.decided_by, x_aria_admin_secret)

    # Load investigation
    result = await session.execute(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .options(selectinload(Investigation.audit_events))
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Check rollback playbook exists
    if not inv.rollback_playbook or not inv.rollback_playbook.strip():
        raise HTTPException(status_code=400, detail="No rollback playbook exists for this investigation")

    # Only allow rollback for completed/failed investigations
    if inv.status not in {"completed", "completed_with_warnings", "failed"}:
        raise HTTPException(
            status_code=400,
            detail=f"Rollback not allowed for status '{inv.status}'. Must be completed, completed_with_warnings, or failed."
        )

    # Record audit event
    await record_audit_event(
        session, investigation_id, "rollback_requested",
        actor=actor,
        details=f"Rollback requested via API. Reason: {body.reason}",
        **_audit_ctx(http_request),
    )
    await session.commit()

    # Execute rollback
    from response.ansible_exec import execute_rollback
    rollback_result = await execute_rollback(
        investigation_id=investigation_id,
        decided_by=actor,
        reason=body.reason,
    )

    if rollback_result.get("status") == "failed":
        raise HTTPException(
            status_code=400,
            detail=rollback_result.get("error", "Rollback failed"),
        )

    return {
        "message": "Rollback completed successfully",
        "investigation_id": investigation_id,
        "status": rollback_result.get("status"),
        "exit_code": rollback_result.get("exit_code"),
        "verification": rollback_result.get("verification"),
    }
