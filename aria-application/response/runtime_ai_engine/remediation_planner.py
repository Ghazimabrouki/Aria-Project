"""
Evidence-driven runtime remediation planner.

The planner is intentionally conservative: it decides whether a runtime
investigation is diagnostic-only, needs manual review, or has a precise
corrective action before any remediation playbook is generated.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional


NON_CORRECTIVE_DECISIONS = {
    "no_action_expected_activity",
    "observe",
    "manual_review_required",
    "evidence_only",
    "cannot_remediate_missing_context",
    "remediation_not_supported_for_category",
}

CORRECTIVE_DECISIONS = {
    "high_risk_action_requires_approval",
}


def build_runtime_remediation_plan(
    runtime_context: Dict[str, Any] | None,
    findings: Dict[str, Any] | None,
    diagnostic_output: str | None = None,
    alert_payloads: Optional[List[Dict[str, Any]]] = None,
    verification_history: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a structured, conservative remediation decision."""
    ctx = runtime_context or {}
    findings = findings or {}
    diagnostic_output = diagnostic_output or ""
    alert_payloads = alert_payloads or []
    target = _target_context(ctx)
    category = ctx.get("runtime_category") or "unknown"
    threat = str(findings.get("threat_assessment") or "").lower()
    expected = bool(findings.get("is_expected")) or threat in {
        "expected",
        "expected_administrative_activity",
    }

    plan = _base_plan(ctx, findings, target, alert_payloads, verification_history)

    if expected:
        return _finish(
            plan,
            decision="no_action_expected_activity",
            reason="Diagnostic evidence and classification indicate expected activity.",
            next_steps=["No corrective action is required. Continue routine monitoring."],
        )

    if threat == "observe" or findings.get("requires_intervention") is False:
        return _finish(
            plan,
            decision="observe",
            reason="Evidence does not justify a corrective change.",
            next_steps=[
                "Keep the case in observe state.",
                "Escalate manually only if matching alerts recur or the process/user becomes suspicious.",
            ],
        )

    if target["target_context"] in {"container", "kubernetes"} and category in {
        "persistence",
        "service_change",
        "file_access",
        "credential_access",
    }:
        return _finish(
            plan,
            decision="manual_review_required",
            reason=(
                "The event has container or Kubernetes context. Host-level file or service "
                "remediation is blocked until namespace and mount scope are validated."
            ),
            evidence_gaps=[
                "Confirm whether the path is container-local or host-mounted.",
                "Confirm container image, writable layer, pod namespace, and hostPath mounts.",
            ],
            next_steps=[
                "Inspect the container or pod filesystem from the runtime platform.",
                "Confirm whether the affected path maps to the host before changing host files.",
            ],
        )

    if category == "package_manager":
        return _plan_package_manager(plan, ctx, findings, diagnostic_output)
    if category in {"credential_access", "sensitive_file_access"}:
        return _plan_credential_access(plan, ctx, findings)
    if category in {"file_access", "file_modification"}:
        return _plan_file_access(plan, ctx, findings, diagnostic_output)
    if category in {"persistence", "service_change"}:
        return _plan_service_or_persistence(plan, ctx, findings, diagnostic_output)
    if category in {"process_execution", "suspicious_shell", "container_runtime"}:
        return _plan_process_or_container(plan, ctx, findings)
    if category in {"network_behavior", "network_activity"}:
        return _plan_network(plan, ctx, findings)
    if category in {"privilege_escalation", "kernel_module", "kernel/module activity"}:
        return _finish(
            plan,
            decision="manual_review_required",
            reason="Privilege or kernel activity is high impact and needs analyst confirmation before changes.",
            evidence_gaps=["Confirm exploit path, account authorization, and affected kernel/module state."],
            next_steps=["Review collected privilege evidence and determine the exact corrective action manually."],
        )

    return _finish(
        plan,
        decision="remediation_not_supported_for_category",
        reason=f"No automated runtime remediation is supported for category '{category}'.",
        next_steps=["Review diagnostic evidence and create a manual response plan if needed."],
    )


def has_corrective_actions(plan: Dict[str, Any] | None) -> bool:
    """True only when a plan contains real corrective changes."""
    if not plan:
        return False
    return (
        plan.get("decision") in CORRECTIVE_DECISIONS
        and bool(plan.get("corrective_actions"))
        and bool(plan.get("actual_remediation_available"))
    )


def derive_runtime_status(plan: Dict[str, Any] | None, current_status: str = "findings_ready") -> str:
    """Map a plan to a truthful investigation status for diagnostic-only cases."""
    decision = (plan or {}).get("decision")
    if decision == "observe" or decision == "no_action_expected_activity":
        return "observe"
    if decision in {
        "manual_review_required",
        "cannot_remediate_missing_context",
        "remediation_not_supported_for_category",
    }:
        return "manual_review_required"
    if decision == "evidence_only":
        return "findings_ready"
    if decision == "high_risk_action_requires_approval":
        return "awaiting_approval"
    return current_status


def _base_plan(
    ctx: Dict[str, Any],
    findings: Dict[str, Any],
    target: Dict[str, Any],
    alert_payloads: List[Dict[str, Any]],
    verification_history: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    plan = {
        "decision": "evidence_only",
        "decision_reason": "Diagnostic evidence has been collected; no corrective action has been selected.",
        "confidence": findings.get("confidence", 0),
        "target_context": target["target_context"],
        "scope": target["scope"],
        "scope_reason": target["scope_reason"],
        "affected_scope": target["affected_scope"],
        "target_host": ctx.get("hostname") or ctx.get("target_host"),
        "target_container": _clean(ctx.get("container_id")) or _clean(ctx.get("container_name")),
        "target_pod": _clean(ctx.get("k8s_pod_name")),
        "target_namespace": _clean(ctx.get("k8s_ns_name")),
        "target_process": ctx.get("proc_name"),
        "target_pid": ctx.get("proc_pid"),
        "target_user": ctx.get("user_name"),
        "target_file": ctx.get("fd_name"),
        "target_service": _extract_service(ctx.get("proc_cmdline") or "", ctx.get("fd_name") or ""),
        "target_network_endpoint": _extract_remote_endpoint(ctx, alert_payloads),
        "evidence_gaps": [],
        "corrective_actions": [],
        "rollback_actions": [],
        "verification_checks": [],
        "approval_required": False,
        "destructive_action": False,
        "actual_remediation_available": False,
        "next_manual_steps": [],
        "verification_history": verification_history or {},
        "legacy_inconsistent_state": False,
    }
    return plan


def _target_context(ctx: Dict[str, Any]) -> Dict[str, Any]:
    container_id = _clean(ctx.get("container_id"))
    container_name = _clean(ctx.get("container_name"))
    pod = _clean(ctx.get("k8s_pod_name"))
    namespace = _clean(ctx.get("k8s_ns_name"))
    host = ctx.get("hostname") or "unknown host"

    if pod or namespace:
        return {
            "target_context": "kubernetes",
            "scope": "pod",
            "affected_scope": f"{namespace or 'unknown namespace'}/{pod or 'unknown pod'} on {host}",
            "scope_reason": "Falco event includes Kubernetes pod or namespace metadata.",
        }
    if container_id or container_name:
        return {
            "target_context": "container",
            "scope": "container",
            "affected_scope": f"{container_name or container_id} on {host}",
            "scope_reason": "Falco event includes non-host container metadata.",
        }
    return {
        "target_context": "host",
        "scope": "host",
        "affected_scope": host,
        "scope_reason": "Falco event has no container or Kubernetes metadata, so host scope is assumed.",
    }


def _plan_package_manager(
    plan: Dict[str, Any],
    ctx: Dict[str, Any],
    findings: Dict[str, Any],
    diagnostic_output: str,
) -> Dict[str, Any]:
    # Container/K8s safety gate: never propose host-scoped package remediation
    if plan.get("target_context") in {"container", "kubernetes"}:
        return _finish(
            plan,
            decision="manual_review_required",
            reason="Package manager activity detected in a container or Kubernetes context. Host-level package removal is unsafe without validating the container namespace and image layer.",
            evidence_gaps=["Container namespace and mount scope not validated for package removal."],
            next_steps=[
                "Inspect the container image layers to identify if the package was baked into the image or installed at runtime.",
                "If the package is malicious, rebuild the container image and redeploy rather than modifying the running container.",
            ],
        )

    cmd = str(ctx.get("proc_cmdline") or "").lower()
    diag = diagnostic_output.lower()
    suspicious_package = _find_suspicious_package(cmd) or _find_suspicious_package(diag)
    if "apt update" in cmd and not any(x in cmd for x in (" install", " remove", " purge")):
        return _finish(
            plan,
            decision="observe",
            reason="The package manager activity appears to be metadata refresh only.",
            next_steps=["Monitor for follow-up install/remove operations in the same maintenance window."],
        )
    if not suspicious_package:
        return _finish(
            plan,
            decision="manual_review_required",
            reason="Package manager execution was observed, but no exact malicious package or repository was proven.",
            evidence_gaps=["Exact package/repository change requiring removal is not identified."],
            next_steps=["Review apt/dpkg logs and change-management records before removing packages."],
        )

    action = {
        "type": "package_remove",
        "package": suspicious_package,
        "description": f"Remove confirmed suspicious package '{suspicious_package}' and refresh apt metadata.",
    }
    plan["corrective_actions"] = [action]
    plan["rollback_actions"] = [
        {
            "type": "package_reinstall",
            "package": suspicious_package,
            "description": f"Reinstall '{suspicious_package}' only if removal breaks a validated service.",
        }
    ]
    plan["verification_checks"] = [
        f"dpkg -l | grep -w {suspicious_package} must return no installed package",
        "No new matching package-manager Falco event for the same host/process after remediation",
    ]
    return _finish(
        plan,
        decision="high_risk_action_requires_approval",
        reason=f"Suspicious package '{suspicious_package}' was identified; removal changes system state.",
        approval_required=True,
        destructive=True,
        remediation_available=True,
    )


def _plan_credential_access(
    plan: Dict[str, Any], ctx: Dict[str, Any], findings: Dict[str, Any]
) -> Dict[str, Any]:
    proc = str(ctx.get("proc_name") or "").lower()
    fd_name = ctx.get("fd_name") or "sensitive file"
    trusted = {"wazuh-syscheckd", "ossec-syscheckd", "sshd", "sudo", "passwd", "login"}
    if proc in trusted or findings.get("is_expected"):
        return _finish(
            plan,
            decision="observe",
            reason=f"{proc or 'the process'} is a trusted system/security process for this access pattern.",
            next_steps=["Continue monitoring for non-trusted readers or write activity."],
        )
    return _finish(
        plan,
        decision="manual_review_required",
        reason=(
            f"{proc or 'An unknown process'} accessed {fd_name}. Credential rotation or process "
            "termination is too destructive without confirming compromise."
        ),
        evidence_gaps=["Confirm whether data was exfiltrated and whether the process is authorized."],
        next_steps=[
            "Preserve process and file evidence.",
            "If compromise is confirmed, rotate affected credentials and contain the exact process/session.",
        ],
    )


def _plan_file_access(
    plan: Dict[str, Any],
    ctx: Dict[str, Any],
    findings: Dict[str, Any],
    diagnostic_output: str,
) -> Dict[str, Any]:
    rule = str(ctx.get("rule_name") or "").lower()
    proc = str(ctx.get("proc_name") or "").lower()
    if "clear log" in rule or "log" in str(ctx.get("fd_name") or "").lower():
        decision = "observe" if proc in {"audit2allow", "ausearch", "auditctl"} else "manual_review_required"
        return _finish(
            plan,
            decision=decision,
            reason=(
                "Log-related file activity requires evidence of deletion or tampering before remediation. "
                f"Current process: {proc or 'unknown'}."
            ),
            evidence_gaps=[] if decision == "observe" else ["No confirmed log deletion/tampering artifact."],
            next_steps=[
                "Review diagnostic file metadata, process tree, and audit logs.",
                "Do not rotate, delete, or restore logs unless tampering is confirmed.",
            ],
        )
    return _finish(
        plan,
        decision="manual_review_required",
        reason="File access was observed, but no exact safe corrective change is proven.",
        evidence_gaps=["Need file baseline or confirmed malicious modification before remediation."],
        next_steps=["Compare file metadata/hash against a trusted baseline."],
    )


def _plan_service_or_persistence(
    plan: Dict[str, Any],
    ctx: Dict[str, Any],
    findings: Dict[str, Any],
    diagnostic_output: str,
) -> Dict[str, Any]:
    fd_name = ctx.get("fd_name")
    service = plan.get("target_service")
    baseline = _extract_baseline_path(findings, diagnostic_output)
    if fd_name and baseline and plan["target_context"] == "host":
        plan["corrective_actions"] = [
            {
                "type": "restore_file_from_baseline",
                "path": fd_name,
                "baseline": baseline,
                "description": f"Restore {fd_name} from trusted baseline {baseline}.",
            }
        ]
        if service:
            plan["corrective_actions"].append(
                {
                    "type": "systemd_reload_validate",
                    "service": service,
                    "description": f"Reload systemd and validate {service}.",
                }
            )
        plan["rollback_actions"] = [
            {
                "type": "restore_prechange_backup",
                "path": fd_name,
                "description": "Restore the exact pre-remediation backup captured by the playbook.",
            }
        ]
        plan["verification_checks"] = [
            f"sha256sum {fd_name} matches trusted baseline",
            "systemctl daemon-reload succeeds",
            f"systemctl status {service}" if service else "systemctl list-units succeeds",
            "No new matching Falco event for the same host/path after remediation",
        ]
        return _finish(
            plan,
            decision="high_risk_action_requires_approval",
            reason="A host-scoped file has a trusted baseline, so an exact restore can be proposed.",
            approval_required=True,
            destructive=True,
            remediation_available=True,
        )
    return _finish(
        plan,
        decision="manual_review_required",
        reason="No trusted baseline was found for an exact service or persistence restore.",
        evidence_gaps=["Trusted baseline or approved desired state is missing."],
        next_steps=["Compare the unit/file with source control, package owner, or a known-good host."],
    )


def _plan_process_or_container(
    plan: Dict[str, Any], ctx: Dict[str, Any], findings: Dict[str, Any]
) -> Dict[str, Any]:
    proc_pid = ctx.get("proc_pid")
    binary = _first_absolute_token(ctx.get("proc_cmdline") or ctx.get("proc_exepath") or "")
    if plan["target_context"] in {"container", "kubernetes"}:
        return _finish(
            plan,
            decision="manual_review_required",
            reason="Container process containment must target the workload, not blindly kill host processes.",
            evidence_gaps=["Confirm workload owner and whether the container should be stopped, isolated, or redeployed."],
            next_steps=[
                "Inspect container image, process tree, mounts, and network connections.",
                "Redeploy or isolate the exact workload if compromise is confirmed.",
            ],
        )
    if proc_pid and binary and findings.get("requires_intervention"):
        plan["corrective_actions"] = [
            {
                "type": "terminate_process",
                "pid": proc_pid,
                "description": f"Terminate confirmed suspicious PID {proc_pid}.",
            },
            {
                "type": "quarantine_file",
                "path": binary,
                "description": f"Move suspicious binary {binary} to a dated quarantine path.",
            },
        ]
        plan["rollback_actions"] = [
            {
                "type": "restore_quarantined_file",
                "path": binary,
                "description": "Move the quarantined binary back only after analyst approval.",
            }
        ]
        plan["verification_checks"] = [
            f"PID {proc_pid} is not running",
            f"{binary} no longer exists at the executable path",
            "No new matching process execution Falco event after remediation",
        ]
        return _finish(
            plan,
            decision="high_risk_action_requires_approval",
            reason="A specific suspicious process and executable path are known.",
            approval_required=True,
            destructive=True,
            remediation_available=True,
        )
    return _finish(
        plan,
        decision="manual_review_required",
        reason="The exact suspicious PID and executable path are not both confirmed.",
        evidence_gaps=["Need PID and executable path before kill/quarantine is safe."],
        next_steps=["Use diagnostic output to identify the exact process and binary before containment."],
    )


def _plan_network(plan: Dict[str, Any], ctx: Dict[str, Any], findings: Dict[str, Any]) -> Dict[str, Any]:
    endpoint = plan.get("target_network_endpoint") or {}
    remote_ip = endpoint.get("remote_ip")
    if not remote_ip:
        return _finish(
            plan,
            decision="cannot_remediate_missing_context",
            reason="No remote network endpoint was identified; blocking without a remote IP is unsafe.",
            evidence_gaps=["Remote IP/port for the connection is missing."],
            next_steps=["Review Falco fd fields and network diagnostics to identify the true remote endpoint."],
        )
    plan["corrective_actions"] = [
        {
            "type": "block_remote_endpoint",
            "remote_ip": remote_ip,
            "remote_port": endpoint.get("remote_port"),
            "description": f"Block exact remote endpoint {remote_ip}:{endpoint.get('remote_port') or 'any'}.",
        }
    ]
    plan["rollback_actions"] = [
        {
            "type": "remove_exact_firewall_rule",
            "remote_ip": remote_ip,
            "remote_port": endpoint.get("remote_port"),
            "description": "Remove only the exact firewall rule inserted by remediation.",
        }
    ]
    plan["verification_checks"] = [
        f"No active connection to {remote_ip}",
        "No new matching Falco network event for same host/process/endpoint",
    ]
    return _finish(
        plan,
        decision="high_risk_action_requires_approval",
        reason="A precise remote endpoint is available; exact blocking is possible with rollback.",
        approval_required=True,
        destructive=True,
        remediation_available=True,
    )


def _finish(
    plan: Dict[str, Any],
    decision: str,
    reason: str,
    evidence_gaps: Optional[List[str]] = None,
    next_steps: Optional[List[str]] = None,
    approval_required: bool = False,
    destructive: bool = False,
    remediation_available: bool = False,
) -> Dict[str, Any]:
    updated = deepcopy(plan)
    updated["decision"] = decision
    updated["decision_reason"] = reason
    if evidence_gaps:
        updated["evidence_gaps"].extend(evidence_gaps)
    if next_steps:
        updated["next_manual_steps"].extend(next_steps)
    updated["approval_required"] = approval_required
    updated["destructive_action"] = destructive
    updated["actual_remediation_available"] = remediation_available and bool(updated["corrective_actions"])
    if not updated["actual_remediation_available"]:
        updated["corrective_actions"] = []
        updated["rollback_actions"] = []
    return updated


def _clean(value: Any) -> Optional[str]:
    if value in (None, "", "host", "<NA>", "N/A"):
        return None
    return str(value)


def _extract_service(cmdline: str, fd_name: str) -> Optional[str]:
    parts = cmdline.split()
    for i, part in enumerate(parts):
        if part in {"start", "stop", "restart", "enable", "disable", "status"} and i + 1 < len(parts):
            return parts[i + 1]
    if fd_name.endswith(".service"):
        return fd_name.rsplit("/", 1)[-1]
    return None


def _extract_remote_endpoint(ctx: Dict[str, Any], alert_payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    candidates = [ctx]
    for alert in alert_payloads:
        metadata = alert.get("metadata") or {}
        candidates.append(metadata.get("output_fields") or {})
        candidates.append(alert.get("runtime_context") or {})
    for item in candidates:
        remote_ip = item.get("fd_rip") or item.get("fd_sip") or item.get("remote_ip")
        remote_port = item.get("fd_rport") or item.get("fd_sport") or item.get("remote_port")
        if remote_ip and str(remote_ip) not in {"127.0.0.1", "0.0.0.0", "::1"}:
            return {"remote_ip": str(remote_ip), "remote_port": remote_port}
    return {}


def _find_suspicious_package(text: str) -> Optional[str]:
    suspicious = [
        "rootkit",
        "backdoor",
        "meterpreter",
        "mimikatz",
        "mimipenguin",
        "xmrig",
        "dnscat",
        "iodine",
        "proxychains",
        "ncat",
        "netcat",
        "nc-traditional",
    ]
    lower = text.lower()
    for name in suspicious:
        if name in lower:
            return name
    return None


def _extract_baseline_path(findings: Dict[str, Any], diagnostic_output: str) -> Optional[str]:
    for key in ("trusted_baseline", "baseline_path", "known_good_path"):
        value = findings.get(key)
        if value:
            return str(value)
    marker = "trusted baseline:"
    lower = diagnostic_output.lower()
    idx = lower.find(marker)
    if idx >= 0:
        line = diagnostic_output[idx:].splitlines()[0]
        return line.split(":", 1)[-1].strip() or None
    return None


def _first_absolute_token(text: str) -> Optional[str]:
    for token in text.split():
        if token.startswith("/"):
            return token
    return None
