"""
Runtime Security Diagnostic Interpreter.

Rule-based primary interpretation of runtime diagnostic output.
AI fallback only for ambiguous or novel patterns.
"""

from typing import Dict, Any, List, Optional
import structlog

from response.runtime_ai_engine.context_builder import RuntimeContext

logger = structlog.get_logger()


def interpret_runtime_diagnostic(
    context: RuntimeContext,
    diagnostic_output: str,
) -> Dict[str, Any]:
    """
    Interpret diagnostic output for a runtime security event.

    Primary path: rule-based interpretation using RuntimeContext.
    Fallback: AI for ambiguous patterns.
    """
    # Try rule-based first
    findings = _rule_based_interpretation(context, diagnostic_output)
    if findings:
        logger.info(
            "runtime_diagnostic_rule_based",
            rule=context.rule_name,
            category=context.runtime_category,
            confidence=findings.get("confidence"),
        )
        return findings

    # AI fallback for ambiguous cases
    logger.info(
        "runtime_diagnostic_ai_fallback",
        rule=context.rule_name,
        category=context.runtime_category,
    )
    return _ai_fallback_interpretation(context, diagnostic_output)


def _rule_based_interpretation(
    context: RuntimeContext,
    diagnostic_output: str,
) -> Optional[Dict[str, Any]]:
    """Deterministic interpretation based on runtime category and context."""
    category = context.runtime_category
    priority = context.priority.lower()

    # ── Expected Administrative Activity ──
    if context.is_expected_admin_activity:
        return _build_expected_admin_findings(context)

    # ── Category-specific interpretations ──
    if category == "package_manager":
        return _interpret_package_manager(context, diagnostic_output)

    if category == "credential_access":
        return _interpret_credential_access(context, diagnostic_output)

    if category == "persistence":
        return _interpret_persistence(context, diagnostic_output)

    if category == "privilege_escalation":
        return _interpret_privilege_escalation(context, diagnostic_output)

    if category == "service_change":
        return _interpret_service_change(context, diagnostic_output)

    if category == "file_access":
        return _interpret_file_access(context, diagnostic_output)

    if category == "process_execution":
        return _interpret_process_execution(context, diagnostic_output)

    if category == "container_runtime":
        return _interpret_container_runtime(context, diagnostic_output)

    # High-priority unknown categories always need attention
    if priority in ["critical", "alert", "emergency"]:
        return _build_high_priority_unknown_findings(context)

    # For unknown/low-priority, return None to trigger AI fallback
    return None


def _build_expected_admin_findings(context: RuntimeContext) -> Dict[str, Any]:
    """Findings for expected administrative activity."""
    tty_note = " with an interactive TTY session" if context.proc_tty else " (non-interactive session)"
    return {
        "detected_cause": (
            f"{context.proc_name} ({context.proc_cmdline}) executed by {context.user_name} "
            f"on {context.hostname} as expected administrative activity"
        ),
        "confidence": 0.95,
        "severity": context.severity,
        "impact": f"Runtime activity on {context.hostname}",
        "is_temporary": True,
        "is_expected": True,
        "technical_explanation": (
            f"This event matches the pattern of expected system administration: "
            f"{context.runtime_category} activity by {context.user_name}{tty_note}. "
            f"The process ({context.proc_name}) is a standard administrative tool "
            f"and the execution context is legitimate."
        ),
        "evidence": _build_base_evidence(context),
        "recommendations": [
            {
                "action": "This is expected system maintenance. No action required.",
                "priority": 1,
                "risk": "none",
                "rationale": "Expected administrative activity within normal parameters",
            },
            {
                "action": (
                    f"Monitor for deviations: `grep '{context.proc_name}' /var/log/auth.log 2>/dev/null | tail -5` "
                    f"or review `ausearch -ts recent -k user_logins`"
                ),
                "priority": 3,
                "risk": "none",
                "rationale": "Continuous monitoring ensures the pattern remains expected",
            },
        ],
        "requires_intervention": False,
        "expert_summary": (
            f"Expected admin activity on {context.hostname}: {context.proc_name} by {context.user_name}. "
            f"No security concern."
        ),
        "threat_assessment": "expected_administrative_activity",
        "runtime_category": context.runtime_category,
    }


def _interpret_package_manager(context: RuntimeContext, diagnostic_output: str) -> Dict[str, Any]:
    """Interpret package manager events using context + diagnostic evidence."""
    user = context.user_name
    proc = context.proc_name
    tty = context.proc_tty
    cmdline = (context.proc_cmdline or "").lower()
    parent = (context.proc_pname or "").lower()

    # ── Parse diagnostic output for legitimacy signals ──
    diag_lower = (diagnostic_output or "").lower()

    # Signs of normal system maintenance in diagnostics
    has_unattended_upgrade = "unattended-upgrade" in diag_lower
    has_apt_update_only = "apt update" in cmdline and "apt install" not in cmdline and "apt remove" not in cmdline
    is_read_only_operation = cmdline.startswith("apt update") or cmdline.startswith("apt-cache")

    # Check if dpkg.log shows only standard maintenance (no suspicious packages)
    dpkg_suspicious = _check_dpkg_for_suspicious(diag_lower)

    # Parent is sudo → admin intentionally elevated privileges
    parent_is_sudo = parent in ("sudo", "su")

    # ── Decision matrix ──

    # 1. Definite expected admin: root + (sudo or unattended-upgrades) + normal dpkg
    if (
        user == "root"
        and (parent_is_sudo or has_unattended_upgrade or is_read_only_operation)
        and not dpkg_suspicious
    ):
        return _build_expected_admin_findings(context)

    # 2. Read-only operations by root are generally low risk even without TTY
    if user == "root" and is_read_only_operation and not dpkg_suspicious:
        return {
            "detected_cause": (
                f"Package manager ({proc}) executed by {user} on {context.hostname} — "
                f"read-only operation (`{context.proc_cmdline}`)"
            ),
            "confidence": 0.80,
            "severity": "low",
            "impact": f"No software changes — read-only package metadata update on {context.hostname}",
            "is_temporary": True,
            "is_expected": True,
            "technical_explanation": (
                f"The command `{context.proc_cmdline}` is a read-only operation that does not "
                f"install, remove, or modify any packages. Executed by root{(' via ' + context.proc_pname) if context.proc_pname else ''}. "
                f"Diagnostic output shows normal system state with no suspicious packages."
            ),
            "evidence": _build_base_evidence(context),
            "recommendations": [
                {
                    "action": "No action required — read-only package manager operation.",
                    "priority": 1,
                    "risk": "none",
                    "rationale": "apt update does not modify system state",
                },
                {
                    "action": "Monitor for follow-up install/remove operations in the next 10 minutes",
                    "priority": 3,
                    "risk": "none",
                    "rationale": "Ensure read-only operation is not reconnaissance before actual changes",
                },
            ],
            "requires_intervention": False,
            "expert_summary": (
                f"Expected admin activity on {context.hostname}: {context.proc_cmdline} by {user}. "
                f"Read-only operation — no security concern."
            ),
            "threat_assessment": "expected_administrative_activity",
            "runtime_category": context.runtime_category,
        }

    # 3. Non-root user trying to use package manager → suspicious
    if user != "root":
        return {
            "detected_cause": (
                f"Package manager ({proc}) executed by non-root user ({user}) on {context.hostname}"
            ),
            "confidence": 0.75,
            "severity": "medium",
            "impact": f"Potential unauthorized software changes by non-privileged user on {context.hostname}",
            "is_temporary": False,
            "is_expected": False,
            "technical_explanation": (
                f"Package manager execution by non-root user ({user}) is atypical. "
                f"Most package operations require root privileges. This may indicate "
                f"a misconfiguration, local privilege escalation, or unauthorized attempt."
            ),
            "evidence": _build_base_evidence(context),
            "recommendations": [
                {
                    "action": f"Check sudo privileges: `sudo -l -U {user}`",
                    "priority": 1,
                    "risk": "low",
                    "rationale": "Determine if user has legitimate package management privileges",
                },
                {
                    "action": f"Review recent package activity in /var/log/dpkg.log and /var/log/apt/history.log",
                    "priority": 1,
                    "risk": "low",
                    "rationale": "Identify what was changed",
                },
            ],
            "requires_intervention": True,
            "expert_summary": (
                f"Package manager use by non-root user {user} on {context.hostname}. Review privileges."
            ),
            "threat_assessment": "suspicious",
            "runtime_category": context.runtime_category,
        }

    # 4. Root user without TTY doing install/remove — moderate concern, check diagnostics
    if not tty and not is_read_only_operation:
        if dpkg_suspicious:
            return {
                "detected_cause": (
                    f"Package manager ({proc}) executed by root without TTY, "
                    f"and diagnostic output contains suspicious package indicators"
                ),
                "confidence": 0.80,
                "severity": "high",
                "impact": f"Potential unauthorized software installation on {context.hostname}",
                "is_temporary": False,
                "is_expected": False,
                "technical_explanation": (
                    f"Root executed {proc} without an interactive TTY session. "
                    f"The diagnostic output shows potentially suspicious package activity. "
                    f"This pattern can indicate automated malware deployment or compromise."
                ),
                "evidence": _build_base_evidence(context),
                "recommendations": [
                    {
                        "action": "Review all recent package changes in /var/log/dpkg.log",
                        "priority": 1,
                        "risk": "low",
                        "rationale": "Identify unauthorized installations",
                    },
                    {
                        "action": "Check for unauthorized cron jobs or systemd timers",
                        "priority": 1,
                        "risk": "low",
                        "rationale": "Automated package changes often use scheduled tasks",
                    },
                ],
                "requires_intervention": True,
                "expert_summary": (
                    f"Suspicious non-interactive package activity on {context.hostname}. "
                    f"Investigate immediately."
                ),
                "threat_assessment": "suspicious",
                "runtime_category": context.runtime_category,
            }
        else:
            # No TTY but diagnostics look clean — observe rather than alert
            return {
                "detected_cause": (
                    f"Package manager ({proc}) executed by root without TTY on {context.hostname}. "
                    f"Diagnostics show normal system state."
                ),
                "confidence": 0.55,
                "severity": "low",
                "impact": f"Possible automated maintenance on {context.hostname}",
                "is_temporary": True,
                "is_expected": True,
                "technical_explanation": (
                    f"Root executed {proc} without an interactive TTY. While this deviates from "
                    f"typical interactive admin patterns, the diagnostic output shows normal system "
                    f"maintenance activity (standard packages, no anomalies). This is commonly seen "
                    f"with configuration management tools (Ansible, Chef), cron jobs, or systemd timers."
                ),
                "evidence": _build_base_evidence(context),
                "recommendations": [
                    {
                        "action": "Verify this is an expected automated task (check cron, systemd timers, CM tools)",
                        "priority": 2,
                        "risk": "none",
                        "rationale": "Confirm the non-interactive execution is expected",
                    },
                    {
                        "action": "Review /var/log/apt/history.log for context around this timestamp",
                        "priority": 2,
                        "risk": "none",
                        "rationale": "Correlate Falco event with actual apt operations",
                    },
                ],
                "requires_intervention": False,
                "expert_summary": (
                    f"Non-interactive package manager use on {context.hostname} by root. "
                    f"Diagnostics clean — likely automated maintenance. Observe."
                ),
                "threat_assessment": "observe",
                "runtime_category": context.runtime_category,
            }

    # 5. Fallback: interactive root session — expected admin
    return _build_expected_admin_findings(context)


def _check_dpkg_for_suspicious(diagnostic_output_lower: str) -> bool:
    """Check diagnostic output for suspicious package indicators.

    Returns True if dpkg/apt logs contain clearly suspicious entries.
    """
    if not diagnostic_output_lower:
        return False

    # Suspicious package name patterns
    suspicious_patterns = [
        "backdoor", "rootkit", "netcat", "ncat", "nc-traditional",
        "rsh-redone", "rsh-client", "telnetd", "ftpd", "vsftpd",
        "bind9", "tor", "proxychains", "iodine", "dnscat",
        "meterpreter", "cobalt", "mimikatz", "mimipenguin",
    ]

    for pattern in suspicious_patterns:
        if pattern in diagnostic_output_lower:
            return True

    # Check for dpkg.log entries that indicate installation of unknown packages
    # (heuristic: if we see "install" followed by non-standard package names)
    # This is intentionally conservative — only flag obvious threats

    return False


def _interpret_credential_access(context: RuntimeContext, diagnostic_output: str) -> Dict[str, Any]:
    """Interpret credential access events."""
    fd_name = context.fd_name or "sensitive file"
    proc = context.proc_name
    user = context.user_name

    # Trusted programs reading credentials may be expected
    trusted_programs = ["passwd", "chpasswd", "usermod", "groupmod", "sshd", "sudo", "login"]
    is_trusted = proc.lower() in trusted_programs

    if is_trusted:
        return {
            "detected_cause": (
                f"Trusted program ({proc}) accessed {fd_name} on {context.hostname} "
                f"as part of normal user management"
            ),
            "confidence": 0.88,
            "severity": "low",
            "impact": f"Expected credential management on {context.hostname}",
            "is_temporary": True,
            "is_expected": True,
            "technical_explanation": (
                f"{proc} is a trusted system program that legitimately accesses "
                f"{fd_name} for user management operations. This is expected behavior."
            ),
            "evidence": _build_base_evidence(context),
            "recommendations": [
                {
                    "action": "No action required. This is expected system behavior.",
                    "priority": 1,
                    "risk": "none",
                    "rationale": f"{proc} is a trusted system program",
                },
            ],
            "requires_intervention": False,
            "expert_summary": (
                f"Expected credential access on {context.hostname}: trusted program {proc} accessed {fd_name}."
            ),
            "threat_assessment": "expected",
            "runtime_category": context.runtime_category,
        }

    # Non-trusted program reading credentials = suspicious
    return {
        "detected_cause": (
            f"Non-trusted program ({proc}) accessed sensitive file {fd_name} "
            f"on {context.hostname} as {user}"
        ),
        "confidence": 0.90,
        "severity": context.severity,
        "impact": f"Potential credential theft on {context.hostname}",
        "is_temporary": False,
        "is_expected": False,
        "technical_explanation": (
            f"{proc} ({context.proc_exepath}) is not a standard credential management program, "
            f"yet it accessed {fd_name}. The process was executed by {user} "
            f"with parent {context.proc_pname}. This is a potential credential access attempt."
        ),
        "evidence": _build_base_evidence(context),
        "recommendations": [
            {
                "action": (
                    f"Verify user authorization: `last {user}` and `sudo -l -U {user}`. "
                    f"Check if {user} was expected to access {fd_name}."
                ),
                "priority": 1,
                "risk": "low",
                "rationale": "Confirm whether this was authorized administrative activity",
            },
            {
                "action": (
                    f"Check file integrity: `sha256sum {fd_name}` and compare with baseline. "
                    f"Verify permissions: `ls -la {fd_name}` and `getfacl {fd_name}`."
                ),
                "priority": 1,
                "risk": "low",
                "rationale": "Detect if the file was modified or exfiltrated",
            },
            {
                "action": (
                    "Audit login activity: `lastb -20` for failed logins and "
                    "`aureport --login --summary -i` for authentication events."
                ),
                "priority": 2,
                "risk": "low",
                "rationale": "Identify potential lateral movement or brute force",
            },
            {
                "action": (
                    f"Investigate the process: `cat /proc/{context.proc_pid}/cmdline` and "
                    f"`lsof -p {context.proc_pid}` to understand what {proc} was doing."
                ),
                "priority": 2,
                "risk": "low",
                "rationale": "Understand the full scope of the process activity",
            },
        ],
        "requires_intervention": True,
        "expert_summary": (
            f"Credential access alert on {context.hostname}: {proc} read {fd_name} as {user}. "
            f"Investigate whether this was authorized."
        ),
        "threat_assessment": "suspicious",
        "runtime_category": context.runtime_category,
    }


def _interpret_persistence(context: RuntimeContext, diagnostic_output: str) -> Dict[str, Any]:
    """Interpret persistence events."""
    fd_name = context.fd_name or "system file"
    proc = context.proc_name
    user = context.user_name

    return {
        "detected_cause": (
            f"Potential persistence attempt: {proc} modified {fd_name} on {context.hostname}"
        ),
        "confidence": 0.88,
        "severity": context.severity,
        "impact": f"Potential malware persistence on {context.hostname}",
        "is_temporary": False,
        "is_expected": False,
        "technical_explanation": (
            f"A system file or service configuration ({fd_name}) was modified by {proc} "
            f"running as {user}. This is a common persistence technique used by malware "
            f"to survive reboots and maintain access. The modification requires investigation "
            f"to distinguish between legitimate administration and malicious activity."
        ),
        "evidence": _build_base_evidence(context),
        "recommendations": [
            {
                "action": (
                    f"Examine the modified file: `cat {fd_name}` and compare with a known-good backup. "
                    f"Check: `diff {fd_name} {fd_name}.bak` if backup exists."
                ),
                "priority": 1,
                "risk": "low",
                "rationale": "Identify exactly what was changed",
            },
            {
                "action": (
                    "Check for other persistence mechanisms: "
                    "`find /etc/cron* -type f -mmin -60`, `ls -la /etc/systemd/system/`, "
                    "`find /home -name 'authorized_keys' -mmin -60`"
                ),
                "priority": 1,
                "risk": "low",
                "rationale": "Malware often establishes multiple persistence mechanisms",
            },
            {
                "action": (
                    f"Verify the change is legitimate: check with system administrators "
                    f"or review change management logs for {context.hostname}."
                ),
                "priority": 2,
                "risk": "low",
                "rationale": "Legitimate changes should be documented in change management",
            },
        ],
        "requires_intervention": True,
        "expert_summary": (
            f"Persistence attempt detected on {context.hostname}: {proc} modified {fd_name}. "
            f"Investigate whether this change is legitimate or malicious."
        ),
        "threat_assessment": "suspicious",
        "runtime_category": context.runtime_category,
    }


def _interpret_privilege_escalation(context: RuntimeContext, diagnostic_output: str) -> Dict[str, Any]:
    """Interpret privilege escalation events."""
    proc = context.proc_name
    user = context.user_name
    parent = context.proc_pname

    return {
        "detected_cause": (
            f"Potential privilege escalation: {proc} executed by {user} on {context.hostname} "
            f"(parent: {parent})"
        ),
        "confidence": 0.85,
        "severity": context.severity,
        "impact": f"Potential unauthorized privilege gain on {context.hostname}",
        "is_temporary": False,
        "is_expected": False,
        "technical_explanation": (
            f"A privilege escalation attempt was detected: {proc} was executed by {user} "
            f"with parent process {parent}. If {user} is not authorized to run {proc}, "
            f"this could indicate exploitation of a sudo misconfiguration, SUID binary abuse, "
            f"or kernel privilege escalation."
        ),
        "evidence": _build_base_evidence(context),
        "recommendations": [
            {
                "action": (
                    f"Check sudo privileges: `sudo -l -U {user}` and review /etc/sudoers. "
                    f"Look for overly permissive entries."
                ),
                "priority": 1,
                "risk": "low",
                "rationale": "Identify the privilege escalation vector",
            },
            {
                "action": (
                    "Find SUID binaries: `find / -perm -4000 -type f 2>/dev/null` and "
                    "verify each binary is expected and from a trusted package."
                ),
                "priority": 1,
                "risk": "low",
                "rationale": "SUID binaries are common privilege escalation vectors",
            },
            {
                "action": (
                    "Check for kernel exploits: `uname -r` and verify the kernel version "
                    "has no known CVEs. Review `dmesg` for OOM or segfault patterns."
                ),
                "priority": 2,
                "risk": "low",
                "rationale": "Kernel exploits can provide root access without leaving process traces",
            },
        ],
        "requires_intervention": True,
        "expert_summary": (
            f"Privilege escalation attempt on {context.hostname}: {proc} by {user}. "
            f"Investigate the escalation vector immediately."
        ),
        "threat_assessment": "suspicious",
        "runtime_category": context.runtime_category,
    }


def _interpret_service_change(context: RuntimeContext, diagnostic_output: str) -> Dict[str, Any]:
    """Interpret service change events."""
    proc = context.proc_name
    user = context.user_name
    cmdline = context.proc_cmdline

    # Extract service name
    service_name = ""
    if cmdline and "systemctl" in cmdline:
        parts = cmdline.split()
        for i, part in enumerate(parts):
            if part in ["start", "stop", "restart", "enable", "disable"] and i + 1 < len(parts):
                service_name = parts[i + 1]
                break

    is_expected = user == "root" and context.proc_tty and context.priority.lower() in ["notice", "info", "informational"]

    if is_expected:
        return {
            "detected_cause": (
                f"Service change by {user} on {context.hostname}: {cmdline}"
            ),
            "confidence": 0.90,
            "severity": "low",
            "impact": f"Expected service management on {context.hostname}",
            "is_temporary": True,
            "is_expected": True,
            "technical_explanation": (
                f"Service management command ({cmdline}) was executed by root with an interactive TTY. "
                f"This matches the pattern of expected system administration."
            ),
            "evidence": _build_base_evidence(context),
            "recommendations": [
                {
                    "action": "No action required. This is expected service management.",
                    "priority": 1,
                    "risk": "none",
                    "rationale": "Expected administrative activity",
                },
            ],
            "requires_intervention": False,
            "expert_summary": f"Expected service change on {context.hostname} by {user}.",
            "threat_assessment": "expected_administrative_activity",
            "runtime_category": context.runtime_category,
        }

    return {
        "detected_cause": (
            f"Suspicious service change by {user} on {context.hostname}: {cmdline}"
        ),
        "confidence": 0.85,
        "severity": context.severity,
        "impact": f"Potential unauthorized service modification on {context.hostname}",
        "is_temporary": False,
        "is_expected": False,
        "technical_explanation": (
            f"A system service was modified by {user} using {proc}. "
            f"The execution context (TTY={context.proc_tty}, priority={context.priority}) "
            f"suggests this may be unauthorized. Service changes can be used for persistence "
            f"or to disable security controls."
        ),
        "evidence": _build_base_evidence(context),
        "recommendations": [
            {
                "action": (
                    f"Check service status: `systemctl status {service_name or '*'} --no-pager` and "
                    f"`systemctl cat {service_name or '*'} | head -40`"
                ),
                "priority": 1,
                "risk": "low",
                "rationale": "Understand what service was changed and how",
            },
            {
                "action": (
                    "Review systemd journal: `journalctl --since '1 hour ago' | grep -E 'systemd|service'`"
                ),
                "priority": 2,
                "risk": "low",
                "rationale": "Identify the full sequence of service changes",
            },
        ],
        "requires_intervention": True,
        "expert_summary": (
            f"Suspicious service change on {context.hostname} by {user}: {cmdline}. Investigate."
        ),
        "threat_assessment": "suspicious",
        "runtime_category": context.runtime_category,
    }


def _interpret_file_access(context: RuntimeContext, diagnostic_output: str) -> Dict[str, Any]:
    """Interpret file access events."""
    fd_name = context.fd_name or "unknown file"
    proc = context.proc_name
    user = context.user_name

    # Sensitive files always get attention
    sensitive_files = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh", "/root/.ssh"]
    is_sensitive = any(fd_name.startswith(sf) for sf in sensitive_files)

    if is_sensitive and user != "root":
        return {
            "detected_cause": (
                f"Non-root user ({user}) accessed sensitive file {fd_name} via {proc} on {context.hostname}"
            ),
            "confidence": 0.88,
            "severity": "high",
            "impact": f"Unauthorized sensitive file access on {context.hostname}",
            "is_temporary": False,
            "is_expected": False,
            "technical_explanation": (
                f"{fd_name} is a sensitive system file that should only be accessed by root or "
                f"trusted system processes. {proc} running as {user} accessed this file, "
                f"which is outside normal access patterns."
            ),
            "evidence": _build_base_evidence(context),
            "recommendations": [
                {
                    "action": f"Check file integrity: `sha256sum {fd_name}` and `ls -la {fd_name}`",
                    "priority": 1,
                    "risk": "low",
                    "rationale": "Detect unauthorized modifications",
                },
                {
                    "action": f"Audit user {user}: `last {user}` and `sudo -l -U {user}`",
                    "priority": 1,
                    "risk": "low",
                    "rationale": "Verify user legitimacy and privileges",
                },
            ],
            "requires_intervention": True,
            "expert_summary": (
                f"Sensitive file access on {context.hostname}: {user} read {fd_name} via {proc}. Investigate."
            ),
            "threat_assessment": "suspicious",
            "runtime_category": context.runtime_category,
        }

    # Root accessing files = often expected, but still note it
    return {
        "detected_cause": f"{proc} accessed {fd_name} on {context.hostname} as {user}",
        "confidence": 0.75,
        "severity": "low",
        "impact": f"File access on {context.hostname}",
        "is_temporary": True,
        "is_expected": user == "root",
        "technical_explanation": (
            f"{proc} accessed {fd_name} as {user}. This may be normal system operation."
        ),
        "evidence": _build_base_evidence(context),
        "recommendations": [
            {
                "action": f"Monitor: verify `ls -la {fd_name}` shows expected permissions",
                "priority": 3,
                "risk": "none",
                "rationale": "Ensure file was not modified",
            },
        ],
        "requires_intervention": False,
        "expert_summary": f"File access on {context.hostname}: {proc} read {fd_name} as {user}.",
        "threat_assessment": "observe",
        "runtime_category": context.runtime_category,
    }


def _interpret_process_execution(context: RuntimeContext, diagnostic_output: str) -> Dict[str, Any]:
    """Interpret process execution events."""
    proc = context.proc_name
    cmdline = context.proc_cmdline
    user = context.user_name

    # Shell execution by non-root without TTY is suspicious
    shells = ["bash", "sh", "zsh", "fish", "dash"]
    is_shell = proc.lower() in shells
    is_suspicious = is_shell and user != "root" and not context.proc_tty

    if is_suspicious:
        return {
            "detected_cause": (
                f"Suspicious shell execution: {proc} ({cmdline}) by {user} on {context.hostname}"
            ),
            "confidence": 0.82,
            "severity": "high",
            "impact": f"Potential reverse shell or unauthorized access on {context.hostname}",
            "is_temporary": False,
            "is_expected": False,
            "technical_explanation": (
                f"A shell ({proc}) was executed by {user} without an interactive TTY. "
                f"This is a common indicator of reverse shells, web shell exploitation, "
                f"or automated attack tools."
            ),
            "evidence": _build_base_evidence(context),
            "recommendations": [
                {
                    "action": (
                        f"Investigate the shell session: `last {user}`, `who`, and "
                        f"`ps auxf | grep -E '{proc}|{user}'`"
                    ),
                    "priority": 1,
                    "risk": "low",
                    "rationale": "Identify how the shell was spawned",
                },
                {
                    "action": (
                        "Check for network connections: `ss -tunapl | grep ESTAB` and "
                        "`netstat -tunapl | grep ESTAB`"
                    ),
                    "priority": 1,
                    "risk": "low",
                    "rationale": "Detect reverse shell connections",
                },
            ],
            "requires_intervention": True,
            "expert_summary": (
                f"Suspicious shell on {context.hostname}: {proc} by {user} without TTY. Investigate immediately."
            ),
            "threat_assessment": "suspicious",
            "runtime_category": context.runtime_category,
        }

    return {
        "detected_cause": f"Process execution: {proc} ({cmdline}) by {user} on {context.hostname}",
        "confidence": 0.70,
        "severity": "low",
        "impact": f"Process execution on {context.hostname}",
        "is_temporary": True,
        "is_expected": True,
        "technical_explanation": f"{proc} executed as {user}. Normal system operation.",
        "evidence": _build_base_evidence(context),
        "recommendations": [
            {
                "action": "No action required. Standard process execution.",
                "priority": 3,
                "risk": "none",
                "rationale": "Normal system operation",
            },
        ],
        "requires_intervention": False,
        "expert_summary": f"Process execution on {context.hostname}: {proc} by {user}.",
        "threat_assessment": "expected",
        "runtime_category": context.runtime_category,
    }


def _interpret_container_runtime(context: RuntimeContext, diagnostic_output: str) -> Dict[str, Any]:
    """Interpret container runtime events."""
    container = context.container_name or context.container_id or "unknown"
    proc = context.proc_name

    return {
        "detected_cause": (
            f"Container runtime event: {proc} in container {container} on {context.hostname}"
        ),
        "confidence": 0.80,
        "severity": context.severity,
        "impact": f"Container security event on {context.hostname}",
        "is_temporary": False,
        "is_expected": False,
        "technical_explanation": (
            f"A container runtime security event was detected in {container}. "
            f"The process {proc} executed an action that violated the container security policy."
        ),
        "evidence": _build_base_evidence(context),
        "recommendations": [
            {
                "action": (
                    f"Inspect container: `docker inspect {container}` and "
                    f"`docker logs --tail 50 {container}`"
                ),
                "priority": 1,
                "risk": "low",
                "rationale": "Understand what the container was doing",
            },
            {
                "action": (
                    f"Check container image: `docker history {context.container_image_repository or container}` "
                    f"and verify image provenance"
                ),
                "priority": 2,
                "risk": "low",
                "rationale": "Compromised images are a common attack vector",
            },
        ],
        "requires_intervention": True,
        "expert_summary": (
            f"Container runtime event on {context.hostname}: {proc} in {container}. Investigate."
        ),
        "threat_assessment": "suspicious",
        "runtime_category": context.runtime_category,
    }


def _build_high_priority_unknown_findings(context: RuntimeContext) -> Dict[str, Any]:
    """Findings for high-priority events with unknown category."""
    return {
        "detected_cause": (
            f"High-priority runtime event: {context.rule_name} on {context.hostname} "
            f"(process: {context.proc_name})"
        ),
        "confidence": 0.70,
        "severity": context.severity,
        "impact": f"Unknown runtime security event on {context.hostname}",
        "is_temporary": False,
        "is_expected": False,
        "technical_explanation": (
            f"A high-priority Falco event ({context.priority}) was triggered by {context.rule_name}, "
            f"but the event category is unknown or does not match standard patterns. "
            f"Manual investigation is required."
        ),
        "evidence": _build_base_evidence(context),
        "recommendations": [
            {
                "action": (
                    f"Investigate the process: `ps aux | grep {context.proc_name}` and "
                    f"`cat /proc/{context.proc_pid}/cmdline`"
                ),
                "priority": 1,
                "risk": "low",
                "rationale": "Understand what triggered the alert",
            },
            {
                "action": (
                    f"Review Falco logs: `grep '{context.rule_name}' /var/log/falco.log 2>/dev/null | tail -10`"
                ),
                "priority": 2,
                "risk": "low",
                "rationale": "Get more context from Falco's own logs",
            },
        ],
        "requires_intervention": True,
        "expert_summary": (
            f"High-priority runtime event on {context.hostname}: {context.rule_name}. "
            f"Manual investigation required."
        ),
        "threat_assessment": "unknown",
        "runtime_category": context.runtime_category,
    }


def _ai_fallback_interpretation(
    context: RuntimeContext,
    diagnostic_output: str,
) -> Dict[str, Any]:
    """AI fallback for ambiguous runtime events."""
    # For now, return a structured fallback indicating AI is needed
    # In production, this would call the LLM with a compact prompt
    return {
        "detected_cause": (
            f"Runtime event: {context.rule_name} triggered by {context.proc_name} on {context.hostname}"
        ),
        "confidence": 0.60,
        "severity": context.severity,
        "impact": f"Runtime security event on {context.hostname}",
        "is_temporary": False,
        "is_expected": False,
        "technical_explanation": (
            f"Falco rule '{context.rule_name}' detected {context.runtime_category} activity. "
            f"Process: {context.proc_name} ({context.proc_cmdline}). "
            f"User: {context.user_name}. File: {context.fd_name or 'N/A'}. "
            f"This event requires manual review to determine if it is malicious, suspicious, or expected."
        ),
        "evidence": _build_base_evidence(context),
        "recommendations": [
            {
                "action": (
                    f"Review the process: `ps aux | grep {context.proc_name}` and "
                    f"investigate `/proc/{context.proc_pid}/` if still running."
                ),
                "priority": 1,
                "risk": "low",
                "rationale": "Understand what the process is doing",
            },
            {
                "action": (
                    f"Check system logs: `journalctl --since '10 minutes ago' | grep {context.proc_name}`"
                ),
                "priority": 2,
                "risk": "low",
                "rationale": "Get more context from system logs",
            },
        ],
        "requires_intervention": context.is_intervention_required,
        "expert_summary": (
            f"Runtime event on {context.hostname}: {context.rule_name} triggered by {context.proc_name}. "
            f"Manual review recommended."
        ),
        "threat_assessment": "unknown",
        "runtime_category": context.runtime_category,
    }


def _build_base_evidence(context: RuntimeContext) -> List[Dict[str, Any]]:
    """Build base evidence items from RuntimeContext."""
    evidence = []

    evidence.append({
        "source": "falco",
        "finding": (
            f"Rule: {context.rule_name} | Priority: {context.priority} | "
            f"Category: {context.runtime_category} | Process: {context.proc_name} ({context.proc_pid})"
        ),
        "timestamp": context.timestamp,
    })

    evidence.append({
        "source": "process",
        "finding": (
            f"{context.proc_name} (PID {context.proc_pid}) | Exe: {context.proc_exepath} | "
            f"Cmdline: {context.proc_cmdline} | Parent: {context.proc_pname} (PPID {context.proc_ppid})"
        ),
        "timestamp": context.timestamp,
    })

    if context.proc_ancestors:
        evidence.append({
            "source": "process_tree",
            "finding": f"Process ancestors: {' -> '.join(reversed(context.proc_ancestors))} -> {context.proc_pname} -> {context.proc_name}",
            "timestamp": context.timestamp,
        })

    evidence.append({
        "source": "user",
        "finding": f"User: {context.user_name} (UID {context.user_uid}, loginuid {context.user_loginuid})",
        "timestamp": context.timestamp,
    })

    if context.fd_name:
        evidence.append({
            "source": "file",
            "finding": f"File: {context.fd_name} (type: {context.fd_type or 'unknown'})",
            "timestamp": context.timestamp,
        })

    if context.container_id and context.container_id != "host":
        evidence.append({
            "source": "container",
            "finding": (
                f"Container: {context.container_name} ({context.container_id}) | "
                f"Image: {context.container_image_repository}:{context.container_image_tag}"
            ),
            "timestamp": context.timestamp,
        })

    if context.mitre_techniques:
        evidence.append({
            "source": "mitre",
            "finding": f"MITRE ATT&CK techniques: {', '.join(context.mitre_techniques)}",
            "timestamp": context.timestamp,
        })

    return evidence
