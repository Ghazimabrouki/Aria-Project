"""Computed SOC workflow summaries for investigations.

These helpers derive operator-facing workflow state from existing persisted
records. They intentionally avoid adding schema so old investigations can be
rendered with the same contract.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import yaml

from response.models import Investigation, InvestigationAlert


STAGE_DEFINITIONS = [
    ("incident_selected", "Incident selected"),
    ("evidence_collection", "Evidence collection"),
    ("ai_root_cause", "AI/root-cause analysis"),
    ("remediation_planning", "Remediation planning"),
    ("approval", "Approval"),
    ("execution", "Execution"),
    ("verification", "Verification"),
    ("completed", "Completed"),
    ("archived", "Archived"),
]


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _phase_status(inv: Investigation, phase: str) -> str | None:
    phases = inv.run.phases_json if inv.run and inv.run.phases_json else {}
    if not isinstance(phases, dict):
        return None
    phase_data = phases.get(phase) or {}
    return phase_data.get("status") if isinstance(phase_data, dict) else None


def _stage(key: str, inv: Investigation) -> dict[str, Any]:
    label = dict(STAGE_DEFINITIONS)[key]
    status = "pending"
    timestamp = None
    details = ""

    if key == "incident_selected":
        status = "completed"
        timestamp = inv.created_at
        details = f"Investigation opened for incident {inv.incident_id}."

    elif key == "evidence_collection":
        evidence_status = _phase_status(inv, "evidence") or _phase_status(inv, "diagnostic")
        # Evidence is "collected" if: staged evidence exists, diagnostic output exists,
        # OR alerts exist and AI analysis has used them (ai_summary present)
        has_alert_evidence = bool(inv.alerts) and bool(inv.ai_summary)
        if inv.evidence_json or evidence_status == "completed" or inv.diagnostic_output or has_alert_evidence:
            status = "completed"
            timestamp = inv.diagnostic_finished_at or inv.updated_at
            details = "Evidence and diagnostic output are available."
        elif evidence_status == "failed":
            status = "failed"
            timestamp = inv.updated_at
            details = "Evidence or diagnostic collection failed."
        elif inv.status == "diagnosing" or (inv.run and inv.run.current_phase in {"evidence", "diagnostic"}):
            status = "current"
            timestamp = inv.diagnostic_started_at or inv.updated_at
            details = "Collecting diagnostic evidence from the target."
        else:
            details = "Evidence will be collected before staged remediation runs."

    elif key == "ai_root_cause":
        if inv.ai_summary:
            status = "completed"
            timestamp = inv.updated_at
            details = "AI analysis and root-cause summary are available."
        elif inv.ai_error and inv.status == "failed":
            status = "failed"
            timestamp = inv.updated_at
            details = inv.ai_error
        elif inv.status in {"pending", "diagnosing", "findings_ready"}:
            status = "current"
            timestamp = inv.updated_at
            details = "AI analysis is pending or in progress."

    elif key == "remediation_planning":
        if inv.playbook_yaml:
            status = "completed"
            timestamp = inv.updated_at
            details = "A remediation playbook is attached for review."
        elif inv.ai_summary and inv.status not in {"failed", "declined"}:
            status = "current"
            timestamp = inv.updated_at
            details = "Remediation plan is being generated from the investigation findings."
        elif inv.ai_error:
            status = "failed"
            timestamp = inv.updated_at
            details = inv.ai_error

    elif key == "approval":
        if inv.approval:
            if inv.approval.decision == "approved":
                status = "completed"
            elif inv.approval.decision == "decision_approved":
                status = "completed"
                details = f"Decision recorded by {inv.approval.decided_by}."
            else:
                status = "failed"
                details = f"Playbook {inv.approval.decision} by {inv.approval.decided_by}."
            timestamp = inv.approval.decided_at
            if inv.approval.reason:
                if details:
                    details += f" Reason: {inv.approval.reason}"
                else:
                    details = f"Reason: {inv.approval.reason}"
        elif inv.status == "awaiting_approval":
            status = "current"
            timestamp = inv.updated_at
            details = "Waiting for analyst approval before execution."
        elif inv.status in {"approved", "running", "completed", "archived", "decision_approved"}:
            status = "completed"
            timestamp = inv.updated_at
            details = "Approval requirement satisfied."

    elif key == "execution":
        if inv.run:
            timestamp = inv.run.finished_at or inv.run.started_at
            if inv.run.status in {"completed", "skipped"}:
                status = "completed"
                details = f"Playbook run {inv.run.status}."
            elif inv.run.status == "failed":
                status = "failed"
                details = f"Playbook execution failed with exit code {inv.run.exit_code}."
            else:
                status = "current"
                details = f"Execution is running. Current phase: {inv.run.current_phase or 'unknown'}."
        elif inv.status in {"approved", "running", "decision_approved"}:
            status = "current"
            timestamp = inv.updated_at
            if inv.status == "running":
                details = "Execution is running."
            else:
                details = "Approved and queued for execution."
        elif inv.status == "failed":
            status = "failed"
            timestamp = inv.updated_at
            details = inv.ai_error or "Execution failed before a run record was created."

    elif key == "verification":
        if inv.verification:
            status = "completed" if inv.verification.status in {"likely_fixed", "verified"} else "failed"
            timestamp = inv.verification.checked_at
            details = inv.verification.detail or f"Verification status: {inv.verification.status}."
        else:
            # Check phases_json for immediate verification result
            v_phase = _phase_status(inv, "verification")
            if v_phase == "completed":
                status = "completed"
                timestamp = inv.run.finished_at if inv.run else inv.updated_at
                details = "Verification phase completed successfully."
            elif v_phase == "failed":
                status = "failed"
                timestamp = inv.run.finished_at if inv.run else inv.updated_at
                details = "Verification phase failed."
            elif inv.status in {"completed", "decision_approved"}:
                status = "current"
                timestamp = inv.updated_at
                details = "Execution completed; verification result is pending."
            elif inv.status == "failed" and inv.run:
                status = "failed"
                timestamp = inv.updated_at
                details = "Verification could not confirm remediation because execution failed."

    elif key == "completed":
        if inv.status in {"completed", "archived", "decision_approved"}:
            status = "completed"
            timestamp = inv.updated_at
            details = "Investigation reached a terminal operational state."
        elif inv.status in {"failed", "declined"}:
            status = "failed"
            timestamp = inv.updated_at
            details = f"Investigation ended as {inv.status}."

    elif key == "archived":
        if inv.status == "archived":
            status = "completed"
            timestamp = inv.updated_at
            details = "Case has been archived."

    return {
        "key": key,
        "label": label,
        "status": status,
        "timestamp": _iso(timestamp),
        "details": details,
    }


def build_workflow_summary(inv: Investigation) -> dict[str, Any]:
    """Return a deterministic SOC workflow summary for an investigation."""
    stages = [_stage(key, inv) for key, _ in STAGE_DEFINITIONS]
    current = next((stage for stage in stages if stage["status"] == "current"), None)
    if not current:
        current = next((stage for stage in stages if stage["status"] == "failed"), None)
    if not current:
        current = next((stage for stage in stages if stage["status"] == "blocked"), None)
    if not current:
        current = next((stage for stage in reversed(stages) if stage["status"] == "completed"), stages[0])
    return {
        "current_stage": current,
        "stages": stages,
    }


def alert_snapshot_to_dict(snapshot: InvestigationAlert) -> dict[str, Any]:
    """Return the stored alert snapshot with normalized top-level evidence fields."""
    raw: dict[str, Any] = {}
    try:
        raw = json.loads(snapshot.alert_json or "{}")
    except Exception:
        raw = {}

    return {
        "alert_id": snapshot.alert_id,
        "severity": snapshot.severity,
        "source": snapshot.source,
        "title": snapshot.title,
        "description": raw.get("description") or raw.get("full_log"),
        "source_ip": raw.get("source_ip"),
        "dest_ip": raw.get("dest_ip"),
        "hostname": raw.get("hostname") or raw.get("agent_name"),
        "rule_name": raw.get("rule_name") or raw.get("rule_description"),
        "tags": raw.get("tags") or [],
        "iocs": raw.get("iocs") or {},
        "metadata": raw.get("metadata") or raw.get("alert_metadata") or {},
        "created_at": raw.get("created_at") or raw.get("timestamp") or raw.get("event_time"),
        "raw": raw,
    }


def build_playbook_summary(inv: Investigation) -> dict[str, Any] | None:
    """Summarize the remediation playbook for analyst approval."""
    if not inv.playbook_yaml:
        return None

    tasks: list[str] = []
    verification_checks: list[str] = []
    risky_terms = {"iptables", "firewall", "drop", "reject", "service", "systemd", "kill", "delete", "remove"}

    try:
        parsed = yaml.safe_load(inv.playbook_yaml)
    except Exception:
        parsed = None

    if isinstance(parsed, list):
        for play in parsed:
            if not isinstance(play, dict):
                continue
            for task in play.get("tasks", []) or []:
                if not isinstance(task, dict):
                    continue
                name = str(task.get("name") or "Unnamed task").strip()
                tasks.append(name)
                if any(word in name.lower() for word in ("verify", "check", "confirm", "validate", "health")):
                    verification_checks.append(name)

    yaml_lower = inv.playbook_yaml.lower()
    high_impact = inv.incident_severity in {"high", "critical"} or any(term in yaml_lower for term in risky_terms)
    target = inv.target_host or inv.hostnames or inv.source_ips or "unknown target"
    first_sentence = (inv.ai_summary or inv.incident_title or "").strip().split("\n", 1)[0]

    expected_impact = []
    # SSH brute-force with only network filtering: be precise about impact
    is_ssh_bruteforce = "ssh" in (inv.ai_summary or "").lower() or "brute" in (inv.ai_summary or "").lower()
    has_sshd_edit = "sshd_config" in yaml_lower or "permitsrootlogin" in yaml_lower
    has_ssh_restart = "restart" in yaml_lower and "ssh" in yaml_lower
    has_host_deny = "hosts.deny" in yaml_lower
    has_unresolved_jinja = "{{" in yaml_lower

    if is_ssh_bruteforce and not has_sshd_edit and not has_ssh_restart and not has_host_deny:
        expected_impact.append("Network filtering will change for the exact source IP only")
        expected_impact.append("No SSH service restart, host isolation, package update, or configuration change is planned")
    elif is_ssh_bruteforce and (has_sshd_edit or has_ssh_restart or has_host_deny or has_unresolved_jinja):
        expected_impact.append("This playbook contains UNSAFE actions that must not be executed")
        if has_unresolved_jinja:
            expected_impact.append("unresolved Jinja2 firewall source — exact IP required")
        if has_host_deny:
            expected_impact.append("host isolation via hosts.deny — not permitted")
        if has_sshd_edit:
            expected_impact.append("automated SSH configuration change — not permitted")
        if has_ssh_restart:
            expected_impact.append("SSH service restart — not permitted")
    else:
        if "iptables" in yaml_lower or "firewall" in yaml_lower:
            expected_impact.append("network filtering may change for listed attacker/source IPs")
        if ("service" in yaml_lower or "systemd" in yaml_lower) and not is_ssh_bruteforce:
            expected_impact.append("target services may be restarted, reloaded, or hardened")
        if "shell" in yaml_lower or "command" in yaml_lower:
            expected_impact.append("diagnostic or corrective shell commands will run on the target")
    if not expected_impact:
        expected_impact.append("actions are limited to the generated Ansible tasks")

    return {
        "what_it_will_do": tasks[:8],
        "why_needed": first_sentence or "Generated from the investigation context.",
        "target": target,
        "expected_impact": "; ".join(expected_impact),
        "rollback_possible": bool(inv.rollback_playbook),
        "rollback_summary": "Rollback playbook is available." if inv.rollback_playbook else "No rollback playbook has been generated yet.",
        "verification_checks": verification_checks[:6],
        "requires_approval": True,
        "high_impact": high_impact,
        "task_count": len(tasks),
    }
