"""Presentation and workflow helpers for investigation routes."""

import json
from typing import Optional

from response.models import (
    Investigation,
    PlaybookApproval,
    PlaybookRun,
    FixVerification,
)

from api.routes._investigations.auth import _get_alert_payload

# ── Helpers ───────────────────────────────────────────────────────────────────


from api.routes._investigations.repository import _get_investigation_or_404

from api.routes._investigations.transitions import _ALLOWED_TRANSITIONS, _validate_status_transition


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

