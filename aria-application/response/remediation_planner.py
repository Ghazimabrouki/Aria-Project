"""
ARIA Deterministic Remediation Planner

For known, well-understood attack scenarios, generates safe remediation playbooks
deterministically rather than relying on LLM free-form output.

Principles:
- LLM generates narrative/explanation only
- Executable YAML comes from deterministic builders for known scenarios
- Every deterministic playbook passes safety validation before storage
- Unknown scenarios fall back to LLM draft or diagnostic-only
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def plan_remediation(context: dict) -> dict | None:
    """
    Analyze investigation context and return deterministic remediation plan
    if the scenario is known and safe to automate.

    Returns None if the scenario should be handled by LLM or manual review.
    """
    classification = _classify_scenario(context)
    scenario = classification["scenario"]

    if scenario == "ssh_bruteforce_public_ip":
        return _build_ssh_bruteforce_remediation(context, classification)

    if scenario == "suricata_reputation_public_ip":
        return _build_suricata_reputation_block(context, classification)

    if scenario == "suricata_portscan_public_ip":
        return _build_suricata_portscan_block(context, classification)

    if scenario == "suricata_c2_outbound":
        return _build_suricata_c2_review(context, classification)

    if scenario == "falco_expected_startup":
        return _build_falco_diagnostic(context, classification, "Expected container startup behavior — no action required")

    if scenario == "falco_read_sensitive_file":
        return _build_falco_diagnostic(context, classification, "Sensitive file read detected — review process context before action")

    if scenario == "falco_systemd_modified":
        return _build_manual_review(context, classification, "Systemd unit file modified inside container — host-level review required")

    if scenario == "falco_process_anomaly":
        return _build_falco_diagnostic(context, classification, "Container process anomaly — review required before host remediation")

    if scenario == "file_quarantine_safe":
        return _build_file_quarantine(context, classification)

    if scenario == "diagnostic_only":
        return _build_diagnostic_only(context, classification)

    if scenario == "manual_review_required":
        return _build_manual_review(context, classification)

    # Unknown or unhandled scenario — let LLM handle it
    return None


# ---------------------------------------------------------------------------
# Scenario Classification
# ---------------------------------------------------------------------------

def _classify_scenario(context: dict) -> dict:
    """
    Classify the investigation into a known scenario or return diagnostic/manual_review.
    """
    alerts = context.get("alerts", [])
    source_ips = context.get("source_ips", [])
    hostnames = context.get("hostnames", [])
    attack_type = context.get("attack_type", "unknown")
    auth_analysis = context.get("auth_analysis", {})
    proof_of_compromise = context.get("proof_of_compromise", {})
    behavioral = context.get("behavioral_indicators", {})
    alert_sources = list({a.get("source", "") for a in alerts})

    result = {
        "scenario": "unknown",
        "reasons": [],
        "source_ips": source_ips,
        "public_ips": [],
        "private_ips": [],
        "has_successful_login": False,
        "has_post_auth_activity": False,
        "has_compromise_evidence": False,
        "target_host": hostnames[0] if hostnames else None,
        "alert_sources": alert_sources,
        "attack_type": attack_type,
        "alert_titles": [a.get("title", "") for a in alerts],
        "alert_tags": [],
        "files": [],
    }

    # Extract tags
    for a in alerts:
        tags = a.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        result["alert_tags"].extend([str(t).lower() for t in tags])

    # Extract file paths from alerts
    for a in alerts:
        meta = a.get("metadata", {}) or {}
        if meta.get("data_file"):
            result["files"].append(meta["data_file"])
        desc = a.get("description", "") or ""
        for match in re.findall(r"(/[a-zA-Z0-9_./-]+)", str(desc)):
            if len(match) > 3 and not match.startswith("/proc"):
                result["files"].append(match)
    result["files"] = list(set(result["files"]))[:5]

    # Classify IPs
    for ip in source_ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_global and not addr.is_reserved and not addr.is_loopback:
                result["public_ips"].append(ip)
            else:
                result["private_ips"].append(ip)
        except ValueError:
            result["reasons"].append(f"Invalid IP address: {ip}")

    # Auth analysis
    successful_logins = auth_analysis.get("successful_logins", [])
    result["has_successful_login"] = len(successful_logins) > 0
    result["has_post_auth_activity"] = (
        result["has_successful_login"]
        or behavioral.get("privilege_escalation", 0) > 0
        or behavioral.get("execution", 0) > 0
        or behavioral.get("system_modification", 0) > 0
    )
    result["has_compromise_evidence"] = proof_of_compromise.get("compromised", False)

    # ------------------------------------------------------------------
    # SSH brute-force detection
    # ------------------------------------------------------------------
    is_ssh_bruteforce = (
        attack_type in ("brute_force", "unknown")
        and behavioral.get("auth_failure", 0) > 0
        and any("ssh" in str(a.get("title", "")).lower() or "pam" in str(a.get("title", "")).lower() for a in alerts)
    )

    if is_ssh_bruteforce:
        if not result["public_ips"]:
            result["scenario"] = "diagnostic_only"
            result["reasons"].append("SSH brute-force from non-public IP — automated blocking not recommended without policy review")
        elif result["has_compromise_evidence"] or result["has_post_auth_activity"]:
            result["scenario"] = "manual_review_required"
            result["reasons"].append("SSH brute-force with post-auth activity or compromise evidence — manual review required")
        else:
            result["scenario"] = "ssh_bruteforce_public_ip"
        return result

    # ------------------------------------------------------------------
    # Suricata / Filebeat network detection
    # ------------------------------------------------------------------
    is_suricata = "suricata" in alert_sources or "filebeat" in alert_sources
    is_reputation = any("reputation" in t.lower() or "cins" in t.lower() or "tor" in t.lower() for t in result["alert_tags"])
    is_portscan = attack_type == "port_scan" or behavioral.get("reconnaissance", 0) > 0
    is_c2 = "c2" in attack_type or any("c2" in t.lower() for t in result["alert_tags"])

    # Web attack / exploit detection: signatures that indicate active exploitation attempts
    combined_titles_lower = " ".join(result["alert_titles"]).lower()
    is_web_attack = any(x in combined_titles_lower for x in [
        "sql injection", "sqli", "xss", "cross-site scripting", "csrf",
        "path traversal", "directory traversal", "command injection",
        "shell command", "remote code execution", "rce", "exploit",
        "cve-", "wordpress", "joomla", "drupal", "cgi", "php",
        "lfi", "rfi", "local file inclusion", "remote file inclusion",
        "web attack", "web shell", "backdoor", "malicious request",
    ])
    is_command_injection = any(x in combined_titles_lower for x in [
        "cmd.exe", "powershell", "bash", "sh -c", "wget", "curl",
        "nc -e", "perl -e", "python -c", "bash -i", "bash -c",
        "eval(", "exec(", "system(", "passthru(", "shell_exec",
    ])

    if is_suricata:
        if is_web_attack:
            # Web attacks should NOT be auto-remediated as simple IP blocks.
            # They need analyst review to determine if the attack succeeded,
            # if the vulnerability exists, and what the proper fix is.
            result["scenario"] = "manual_review_required"
            result["reasons"].append(
                "Web attack or exploit attempt detected — "
                "automatic IP blocking may not address the underlying vulnerability. "
                "Manual review required to assess exploit success and proper remediation."
            )
        elif is_command_injection:
            result["scenario"] = "manual_review_required"
            result["reasons"].append(
                "Command injection or shell execution indicators detected — "
                "manual review required to confirm compromise and determine remediation scope."
            )
        elif is_reputation and result["public_ips"]:
            # Reputation-only alerts: default to diagnostic/manual-review unless
            # there is clear repeated malicious behavior or high-confidence policy.
            alert_count = len(alerts)
            has_repeated_behavior = behavioral.get("network_anomaly", 0) > 1 or alert_count >= 3
            if has_repeated_behavior:
                result["scenario"] = "suricata_reputation_public_ip"
                result["reasons"].append(
                    f"Reputation alert with {alert_count} events and repeated behavior — "
                    "auto-block permitted by policy."
                )
            else:
                result["scenario"] = "manual_review_required"
                result["reasons"].append(
                    "Reputation-only alert with limited evidence — "
                    "manual review required before blocking. "
                    "Consider verifying the source and checking existing block policies."
                )
        elif is_portscan and result["public_ips"]:
            result["scenario"] = "suricata_portscan_public_ip"
        elif is_c2:
            result["scenario"] = "suricata_c2_outbound"
            result["reasons"].append("C2-like traffic detected — confirm direction and asset impact before blocking")
        elif not result["public_ips"] and (is_reputation or is_portscan):
            result["scenario"] = "diagnostic_only"
            result["reasons"].append("Suricata alert with non-public source IP — automated blocking not recommended")

    # ------------------------------------------------------------------
    # Falco runtime detection
    # ------------------------------------------------------------------
    is_falco = "falco" in alert_sources
    if is_falco:
        titles_lower = [t.lower() for t in result["alert_titles"]]
        desc_lower = " ".join([str(a.get("description", "")).lower() for a in alerts])
        combined = " ".join(titles_lower) + " " + desc_lower

        if any(x in combined for x in ["unexpected connection", "contact ec2", "contact metadata", "terminal shell"]):
            result["scenario"] = "falco_process_anomaly"
        elif any(x in combined for x in ["write below", "modify binary", "exec binary", "unexpected exe"]):
            result["scenario"] = "falco_process_anomaly"
        elif "systemd" in combined or "unit file" in combined:
            result["scenario"] = "falco_systemd_modified"
            result["reasons"].append("Systemd modification inside container — host-level review required")
        elif any(x in combined for x in ["read sensitive file", 'read "/etc/shadow"', 'read "/etc/passwd"']):
            result["scenario"] = "falco_read_sensitive_file"
        elif any(x in combined for x in ["container started", "pod started", "deployment created"]):
            result["scenario"] = "falco_expected_startup"
        else:
            result["scenario"] = "falco_process_anomaly"

    # ------------------------------------------------------------------
    # File quarantine (Wazuh file integrity)
    # ------------------------------------------------------------------
    is_file_integrity = behavioral.get("file_integrity", 0) > 0
    if is_file_integrity and result["files"]:
        safe, reason = _validate_quarantine_path(result["files"][0])
        if safe:
            result["scenario"] = "file_quarantine_safe"
        else:
            result["scenario"] = "manual_review_required"
            result["reasons"].append(reason)

    return result


# ---------------------------------------------------------------------------
# Deterministic Builders
# ---------------------------------------------------------------------------

def _build_iptables_block_playbook(primary_ip: str, target_host: str, title: str, severity: str, alert_count: int, alert_titles: list, source_type: str) -> dict:
    """Shared deterministic builder for exact-IP iptables block + rollback + verification."""
    playbook_yaml = f"""---
- name: "ARIA Remediation - {title[:50]}"
  hosts: {target_host}
  become: yes
  gather_facts: no
  tasks:
    - name: "Block source IP {primary_ip}"
      ansible.builtin.iptables:
        chain: INPUT
        source: "{primary_ip}/32"
        jump: DROP
        state: present
      ignore_errors: yes

    - name: "Collect active connections for evidence"
      ansible.builtin.shell: "ss -tunapl | head -20"
      register: conns
      ignore_errors: yes
      changed_when: false
"""

    rollback_yaml = f"""---
- name: "ARIA Rollback - {title[:50]}"
  hosts: {target_host}
  become: yes
  gather_facts: no
  tasks:
    - name: "Remove block for {primary_ip}"
      ansible.builtin.iptables:
        chain: INPUT
        source: "{primary_ip}/32"
        jump: DROP
        state: absent
      ignore_errors: yes
"""

    verification_plan = {
        "type": "iptables_rule",
        "chain": "INPUT",
        "source": primary_ip,
        "jump": "DROP",
    }

    observed_facts = [
        f"{source_type} alert detected from {primary_ip}",
        f"Target host: {target_host}",
        f"Alerts: {', '.join(alert_titles[:5])}",
    ]

    inferred_findings = [
        f"{source_type} activity from public source IP",
        "Network-level access attempt",
    ]

    unsupported_claims = [
        "Host compromise (no host-level evidence)",
        "Malware infection (no malware signature)",
        "Lateral movement (no pivot evidence)",
    ]

    truth_report = {
        "observed_facts": observed_facts,
        "inferred_findings": inferred_findings,
        "unsupported_claims": unsupported_claims,
        "recommended_next_steps": [
            f"Review logs for {primary_ip}",
            f"Source IP {primary_ip} is now blocked via iptables",
            "Continue monitoring for recurrence",
        ],
        "final_classification": "suspected_threat",
        "confidence": "medium",
    }

    risk_level = "High" if severity in ("critical", "high") else "Medium"
    ai_summary = (
        f"{source_type} activity detected from {primary_ip} against {target_host}. "
        f"{alert_count} alert(s). No host compromise evidence. "
        f"Deterministic remediation: block exact source IP via iptables."
    )

    ai_narrative = (
        f"1. Detection: {source_type} alert from {primary_ip}\n"
        f"2. Target: {target_host}\n"
        f"3. Evidence: Network alert only — no host-level compromise confirmed\n"
        f"4. Remediation: Source IP blocked at network level\n"
        f"5. Monitoring: Watch for recurrence from different sources"
    )

    ai_risk = (
        f"**Risk Level: {risk_level}**\n\n"
        f"- External public source IP: {primary_ip}\n"
        f"- Network alerts: {alert_count}\n"
        f"- Host compromise: Not confirmed\n"
        f"- Remediation: Source IP blocked via deterministic playbook"
    )

    return {
        "playbook_yaml": playbook_yaml,
        "rollback_yaml": rollback_yaml,
        "verification_plan": verification_plan,
        "ai_summary": ai_summary,
        "ai_narrative": ai_narrative,
        "ai_risk": ai_risk,
        "truth_report": truth_report,
        "safety_tier": "safe",
        "playbook_safety_status": "safe",
        "rollback_safety_status": "safe",
        "execution_mode": "remediation",
        "builder_name": f"{source_type.lower().replace(' ', '_')}_public_ip",
        "deterministic": True,
    }


def _build_ssh_bruteforce_remediation(context: dict, classification: dict) -> dict:
    """Build deterministic remediation for SSH brute-force from public IP."""
    source_ips = classification["public_ips"]
    target_host = classification["target_host"] or "localhost"
    incident = context.get("incident", {})
    title = incident.get("title", "SSH Brute Force Attack")
    severity = incident.get("severity", "medium")
    alerts = context.get("alerts", [])
    primary_ip = source_ips[0]
    alert_titles = [a.get("title", "") for a in alerts[:5]]

    result = _build_iptables_block_playbook(
        primary_ip, target_host, title, severity, len(alerts), alert_titles, "SSH brute-force"
    )

    # Override truth report for SSH-specific evidence
    result["truth_report"]["observed_facts"] = [
        f"Failed SSH/PAM authentication detected from {primary_ip}",
        f"Target host: {target_host}",
        f"Alerts: {', '.join(alert_titles)}",
        "No successful login confirmed",
        "No post-auth compromise evidence",
    ]
    result["truth_report"]["inferred_findings"] = [
        "Credential access attempt",
        "SSH password guessing / brute-force attempt",
    ]
    result["truth_report"]["recommended_next_steps"] = [
        f"Review auth logs for {primary_ip}",
        "Check if any successful login followed the failed attempts",
        f"Source IP {primary_ip} is now blocked via iptables",
        "Continue monitoring",
    ]
    result["builder_name"] = "ssh_bruteforce_public_ip"
    result["ai_summary"] = (
        f"SSH brute-force / password guessing attempt detected from {primary_ip} "
        f"against {target_host}. {len(alerts)} alert(s) show failed authentication. "
        f"No successful login or compromise evidence found. "
        f"Deterministic remediation: block exact source IP via iptables."
    )
    return result


def _build_suricata_reputation_block(context: dict, classification: dict) -> dict:
    """Build deterministic block for Suricata reputation IP alert."""
    source_ips = classification["public_ips"]
    target_host = classification["target_host"] or "localhost"
    incident = context.get("incident", {})
    title = incident.get("title", "Reputation IP Alert")
    severity = incident.get("severity", "medium")
    alerts = context.get("alerts", [])
    primary_ip = source_ips[0]
    alert_titles = [a.get("title", "") for a in alerts[:5]]

    result = _build_iptables_block_playbook(
        primary_ip, target_host, title, severity, len(alerts), alert_titles, "Reputation IP"
    )
    result["builder_name"] = "suricata_reputation_public_ip"
    result["ai_summary"] = (
        f"Reputation IP alert from {primary_ip} detected by Suricata/Filebeat. "
        f"{len(alerts)} alert(s). No host compromise evidence. "
        f"Deterministic remediation: block exact source IP via iptables."
    )
    return result


def _build_suricata_portscan_block(context: dict, classification: dict) -> dict:
    """Build deterministic block for Suricata port scan from public IP."""
    source_ips = classification["public_ips"]
    target_host = classification["target_host"] or "localhost"
    incident = context.get("incident", {})
    title = incident.get("title", "Port Scan Alert")
    severity = incident.get("severity", "medium")
    alerts = context.get("alerts", [])
    primary_ip = source_ips[0]
    alert_titles = [a.get("title", "") for a in alerts[:5]]

    result = _build_iptables_block_playbook(
        primary_ip, target_host, title, severity, len(alerts), alert_titles, "Port scan"
    )
    result["builder_name"] = "suricata_portscan_public_ip"
    result["ai_summary"] = (
        f"Port scan detected from {primary_ip} by Suricata/Filebeat. "
        f"{len(alerts)} alert(s). No host compromise evidence. "
        f"Deterministic remediation: block exact source IP via iptables."
    )
    return result


def _build_suricata_c2_review(context: dict, classification: dict) -> dict:
    """C2-like traffic requires manual review before any blocking."""
    return _build_manual_review(context, classification, "C2-like outbound traffic detected — confirm direction and asset impact before blocking")


def _build_falco_diagnostic(context: dict, classification: dict, reason: str) -> dict:
    """Build diagnostic-only output for Falco runtime cases."""
    result = _build_diagnostic_only(context, classification)
    result["builder_name"] = "falco_diagnostic"
    result["ai_summary"] += f" Falco runtime: {reason}"
    # Append reason to narrative and truth report
    result["ai_narrative"] += f"\n- {reason}"
    result["truth_report"]["recommended_next_steps"].append(reason)
    return result


def _build_file_quarantine(context: dict, classification: dict) -> dict:
    """Build deterministic file quarantine with safe path validation."""
    files = classification.get("files", [])
    target_host = classification["target_host"] or "localhost"
    incident = context.get("incident", {})
    title = incident.get("title", "File Integrity Alert")
    severity = incident.get("severity", "medium")
    alerts = context.get("alerts", [])

    if not files:
        return _build_manual_review(context, classification, "File integrity alert but no file path available")

    file_path = files[0]
    safe, reason = _validate_quarantine_path(file_path)
    if not safe:
        return _build_manual_review(context, classification, reason)

    quarantine_dir = "/var/quarantine/aria"
    quarantine_path = f"{quarantine_dir}/{Path(file_path).name}"

    playbook_yaml = f"""---
- name: "ARIA Remediation - {title[:50]}"
  hosts: {target_host}
  become: yes
  gather_facts: no
  tasks:
    - name: "Ensure quarantine directory exists"
      ansible.builtin.file:
        path: "{quarantine_dir}"
        state: directory
        mode: '0700'

    - name: "Quarantine file {file_path}"
      ansible.builtin.shell: "cp '{file_path}' '{quarantine_path}' && rm -f '{file_path}'"
      args:
        removes: "{file_path}"
      ignore_errors: yes
      failed_when: false

    - name: "Verify quarantine"
      ansible.builtin.stat:
        path: "{quarantine_path}"
      register: quarantine_stat
      changed_when: false
"""

    rollback_yaml = f"""---
- name: "ARIA Rollback - {title[:50]}"
  hosts: {target_host}
  become: yes
  gather_facts: no
  tasks:
    - name: "Restore file from quarantine"
      ansible.builtin.shell: "cp '{quarantine_path}' '{file_path}' && rm -f '{quarantine_path}'"
      args:
        removes: "{quarantine_path}"
      ignore_errors: yes
      failed_when: false
"""

    verification_plan = {
        "type": "file_quarantine",
        "original_path": file_path,
        "quarantine_path": quarantine_path,
    }

    truth_report = {
        "observed_facts": [
            f"File integrity alert: {file_path}",
            f"Target host: {target_host}",
        ],
        "inferred_findings": ["Unauthorized file modification detected"],
        "unsupported_claims": [
            "Malware infection (no malware signature)",
            "System compromise (no host-level evidence)",
        ],
        "recommended_next_steps": [
            f"Review file {file_path} in quarantine",
            "Determine if modification was authorized",
            f"Original path: {file_path}",
            f"Quarantine path: {quarantine_path}",
        ],
        "final_classification": "suspected_threat",
        "confidence": "medium",
    }

    return {
        "playbook_yaml": playbook_yaml,
        "rollback_yaml": rollback_yaml,
        "verification_plan": verification_plan,
        "ai_summary": f"File integrity alert for {file_path}. File quarantined safely.",
        "ai_narrative": f"File {file_path} was modified. Safe quarantine executed to {quarantine_path}.",
        "ai_risk": f"**Risk Level: Medium**\n\n- Modified file: {file_path}\n- Quarantine: {quarantine_path}",
        "truth_report": truth_report,
        "safety_tier": "safe",
        "playbook_safety_status": "safe",
        "rollback_safety_status": "safe",
        "execution_mode": "remediation",
        "builder_name": "file_quarantine_safe",
        "deterministic": True,
    }


def _build_diagnostic_only(context: dict, classification: dict) -> dict:
    """Build diagnostic-only output with no executable playbook."""
    incident = context.get("incident", {})
    title = incident.get("title", "Incident")
    alerts = context.get("alerts", [])
    reasons = classification.get("reasons", [])

    alert_titles = [a.get("title", "") for a in alerts[:5]]

    ai_summary = (
        f"Diagnostic-only investigation for: {title}. "
        f"{len(alerts)} alert(s) detected. "
        f"Automated remediation is not appropriate: {'; '.join(reasons)}"
    )

    ai_narrative = (
        f"This incident requires diagnostic review before any remediation action.\n\n"
        f"Alerts: {', '.join(alert_titles)}\n\n"
        f"Why no automated remediation:\n"
        + "\n".join(f"- {r}" for r in reasons)
    )

    ai_risk = (
        f"**Risk Level: Unknown**\n\n"
        f"- Automated remediation blocked: {'; '.join(reasons)}\n"
        f"- Recommended action: Manual investigation and review"
    )

    truth_report = {
        "observed_facts": [f"Alert: {t}" for t in alert_titles],
        "inferred_findings": [],
        "unsupported_claims": [],
        "recommended_next_steps": [
            "Investigate alert details manually",
            "Determine if remediation is appropriate",
        ] + reasons,
        "final_classification": "unknown",
        "confidence": "low",
    }

    return {
        "playbook_yaml": None,
        "rollback_yaml": None,
        "verification_plan": None,
        "ai_summary": ai_summary,
        "ai_narrative": ai_narrative,
        "ai_risk": ai_risk,
        "truth_report": truth_report,
        "safety_tier": "safe",
        "playbook_safety_status": "safe",
        "rollback_safety_status": "safe",
        "execution_mode": "diagnostic",
        "builder_name": "diagnostic_only",
        "deterministic": True,
    }


def _build_manual_review(context: dict, classification: dict, extra_reason: str | None = None) -> dict:
    """Build manual-review-required output with no executable playbook."""
    incident = context.get("incident", {})
    title = incident.get("title", "Incident")
    alerts = context.get("alerts", [])
    reasons = classification.get("reasons", [])[:]
    if extra_reason:
        reasons.append(extra_reason)

    alert_titles = [a.get("title", "") for a in alerts[:5]]

    ai_summary = (
        f"Manual review required for: {title}. "
        f"{len(alerts)} alert(s) detected. "
        f"Automated remediation blocked: {'; '.join(reasons)}"
    )

    ai_narrative = (
        f"This incident contains signals that require human analyst review before any action.\n\n"
        f"Alerts: {', '.join(alert_titles)}\n\n"
        f"Blockers:\n"
        + "\n".join(f"- {r}" for r in reasons)
    )

    ai_risk = (
        f"**Risk Level: Unknown**\n\n"
        f"- Automated remediation blocked: {'; '.join(reasons)}\n"
        f"- Recommended action: Analyst manual review"
    )

    truth_report = {
        "observed_facts": [f"Alert: {t}" for t in alert_titles],
        "inferred_findings": [],
        "unsupported_claims": [],
        "recommended_next_steps": [
            "Analyst manual review required",
        ] + reasons,
        "final_classification": "unknown",
        "confidence": "low",
    }

    return {
        "playbook_yaml": None,
        "rollback_yaml": None,
        "verification_plan": None,
        "ai_summary": ai_summary,
        "ai_narrative": ai_narrative,
        "ai_risk": ai_risk,
        "truth_report": truth_report,
        "safety_tier": "manual_review_required",
        "playbook_safety_status": "safe",
        "rollback_safety_status": "safe",
        "execution_mode": "no_action",
        "builder_name": "manual_review_required",
        "deterministic": True,
    }


# ---------------------------------------------------------------------------
# Path validation for file quarantine
# ---------------------------------------------------------------------------

_BLOCKED_PATH_PREFIXES = [
    "/", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/lib", "/lib64", "/usr/lib", "/usr/lib64",
    "/etc/ssh", "/etc/sudoers", "/etc/passwd", "/etc/shadow",
    "/boot", "/dev", "/proc", "/sys", "/run", "/var/run",
]

_ALLOWED_PATH_PATTERNS = [
    r"^/tmp/",
    r"^/var/tmp/",
    r"^/home/[^/]+/",
    r"^/opt/",
    r"^/var/www/",
    r"^/var/log/",
    r"^/data/",
    r"^/app/",
]


def _validate_quarantine_path(file_path: str) -> tuple[bool, str]:
    """Validate that a file path is safe for automated quarantine."""
    if not file_path or not file_path.startswith("/"):
        return False, f"Invalid or relative file path: {file_path}"

    resolved = Path(file_path).resolve()
    str_path = str(resolved)

    for blocked in _BLOCKED_PATH_PREFIXES:
        if str_path.startswith(blocked + "/") or str_path == blocked:
            return False, f"System path blocked from automated quarantine: {file_path}"

    for pattern in _ALLOWED_PATH_PATTERNS:
        if re.match(pattern, str_path):
            return True, ""

    return False, f"File path not in allowed quarantine directories: {file_path}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_public_ip(ip: str) -> bool:
    """Check if IP is a valid public (routable) IPv4/IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global and not addr.is_reserved and not addr.is_loopback and not addr.is_multicast
    except ValueError:
        return False
