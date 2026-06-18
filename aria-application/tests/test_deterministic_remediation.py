"""
Tests for ARIA deterministic remediation planner.

Validates that known scenarios generate safe, correct playbooks
without relying on LLM output.
"""
import pytest
from response.remediation_planner import (
    plan_remediation,
    _classify_scenario,
    _build_ssh_bruteforce_remediation,
    _validate_quarantine_path,
)


# ---------------------------------------------------------------------------
# SSH Brute-Force Scenario Tests
# ---------------------------------------------------------------------------

class TestSSHBruteForceDeterministicBuilder:
    """SSH brute-force from public IP — deterministic builder must produce safe output."""

    def _make_context(self, source_ips, alert_titles, auth_failures=1, auth_successes=0, hostnames=None):
        return {
            "incident": {"id": "test-inc", "title": "SSH Brute Force", "severity": "medium", "status": "open"},
            "alerts": [
                {
                    "title": t,
                    "description": "auth failure",
                    "source": "wazuh",
                    "source_ip": source_ips[0] if source_ips else None,
                    "hostname": hostnames[0] if hostnames else "target",
                    "tags": ["wazuh-rule-5760", "mitre-tactic-Credential Access"],
                }
                for t in alert_titles
            ],
            "source_ips": source_ips,
            "hostnames": hostnames or ["target"],
            "attack_type": "unknown",
            "behavioral_indicators": {"auth_failure": auth_failures, "auth_success": auth_successes},
            "auth_analysis": {
                "failed_logins": [{"ip": ip} for ip in source_ips] if auth_failures else [],
                "successful_logins": [] if not auth_successes else [{"ip": source_ips[0]}],
                "is_suspicious": auth_failures > 0 and auth_successes > 0,
            },
            "proof_of_compromise": {"compromised": False, "confidence": "low", "indicators": []},
        }

    def test_public_ip_produces_deterministic_remediation(self):
        ctx = self._make_context(["36.66.99.135"], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "ssh_bruteforce_public_ip"
        assert plan["safety_tier"] == "safe"
        assert plan["execution_mode"] == "remediation"
        assert plan["deterministic"] is True

    def test_playbook_uses_exact_ip_no_jinja(self):
        ctx = self._make_context(["36.66.99.135"], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        pb = plan["playbook_yaml"]
        assert "36.66.99.135" in pb
        assert "{{" not in pb
        assert "}}" not in pb
        assert "ansible.builtin.iptables:" in pb
        assert "source: \"36.66.99.135/32\"" in pb
        assert "jump: DROP" in pb
        assert "state: present" in pb

    def test_rollback_uses_exact_ip_no_jinja(self):
        ctx = self._make_context(["36.66.99.135"], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        rb = plan["rollback_yaml"]
        assert "36.66.99.135" in rb
        assert "{{" not in rb
        assert "}}" not in rb
        assert "ansible.builtin.iptables:" in rb
        assert "source: \"36.66.99.135/32\"" in rb
        assert "jump: DROP" in rb
        assert "state: absent" in rb

    def test_no_sshd_config_edit(self):
        ctx = self._make_context(["36.66.99.135"], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        pb = plan["playbook_yaml"].lower()
        assert "sshd_config" not in pb

    def test_no_ssh_restart(self):
        ctx = self._make_context(["36.66.99.135"], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        pb = plan["playbook_yaml"].lower()
        assert "service ssh restart" not in pb
        assert "systemctl restart sshd" not in pb

    def test_no_hosts_deny(self):
        ctx = self._make_context(["36.66.99.135"], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        pb = plan["playbook_yaml"].lower()
        assert "hosts.deny" not in pb
        assert "hosts.allow" not in pb

    def test_verification_plan_is_state_based(self):
        ctx = self._make_context(["36.66.99.135"], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        vp = plan["verification_plan"]
        assert vp["type"] == "iptables_rule"
        assert vp["chain"] == "INPUT"
        assert vp["source"] == "36.66.99.135"
        assert vp["jump"] == "DROP"

    def test_ai_summary_identifies_attack_type(self):
        ctx = self._make_context(["36.66.99.135"], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        summary = plan["ai_summary"].lower()
        assert "brute-force" in summary or "brute force" in summary or "password guessing" in summary
        assert "unknown" not in summary

    def test_truth_report_no_compromise_claim(self):
        ctx = self._make_context(["36.66.99.135"], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        tr = plan["truth_report"]
        assert tr["final_classification"] == "suspected_threat"
        assert any("compromise" in c.lower() for c in tr["unsupported_claims"])
        assert "Credential access attempt" in tr["inferred_findings"]

    def test_private_ip_returns_diagnostic_only(self):
        ctx = self._make_context(["192.168.1.50"], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "diagnostic_only"
        assert plan["playbook_yaml"] is None
        assert plan["execution_mode"] == "diagnostic"

    def test_missing_ip_returns_diagnostic_only(self):
        ctx = self._make_context([], ["sshd: authentication failed."])
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "diagnostic_only"
        assert plan["playbook_yaml"] is None

    def test_successful_login_returns_manual_review(self):
        ctx = self._make_context(
            ["36.66.99.135"],
            ["sshd: authentication failed.", "Accepted password for root"],
            auth_failures=1,
            auth_successes=1,
        )
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "manual_review_required"
        assert plan["playbook_yaml"] is None
        assert plan["execution_mode"] == "no_action"


# ---------------------------------------------------------------------------
# Classification Tests
# ---------------------------------------------------------------------------

class TestScenarioClassification:
    """Low-level classification logic."""

    def test_public_ip_classified_correctly(self):
        ctx = {
            "source_ips": ["8.8.8.8"],
            "hostnames": ["target"],
            "attack_type": "unknown",
            "behavioral_indicators": {"auth_failure": 2},
            "alerts": [{"title": "sshd: authentication failed.", "source": "wazuh"}],
            "auth_analysis": {"failed_logins": [{"ip": "8.8.8.8"}], "successful_logins": [], "is_suspicious": False},
            "proof_of_compromise": {"compromised": False},
        }
        result = _classify_scenario(ctx)
        assert result["scenario"] == "ssh_bruteforce_public_ip"
        assert result["public_ips"] == ["8.8.8.8"]
        assert result["has_successful_login"] is False

    def test_loopback_ip_not_public(self):
        ctx = {
            "source_ips": ["127.0.0.1"],
            "hostnames": ["target"],
            "attack_type": "unknown",
            "behavioral_indicators": {"auth_failure": 1},
            "alerts": [{"title": "sshd: authentication failed.", "source": "wazuh"}],
            "auth_analysis": {"failed_logins": [], "successful_logins": [], "is_suspicious": False},
            "proof_of_compromise": {"compromised": False},
        }
        result = _classify_scenario(ctx)
        assert result["public_ips"] == []
        assert result["private_ips"] == ["127.0.0.1"]


# ---------------------------------------------------------------------------
# Fallback / Unknown Scenario Tests
# ---------------------------------------------------------------------------

class TestFileQuarantine:
    """File quarantine path validation."""

    def test_safe_path_allows_quarantine(self):
        safe, reason = _validate_quarantine_path("/tmp/malware.exe")
        assert safe is True
        assert reason == ""

    def test_system_path_blocked(self):
        safe, reason = _validate_quarantine_path("/etc/passwd")
        assert safe is False
        assert "blocked" in reason.lower()

    def test_bin_path_blocked(self):
        safe, reason = _validate_quarantine_path("/usr/bin/ls")
        assert safe is False

    def test_relative_path_blocked(self):
        safe, reason = _validate_quarantine_path("./malware.exe")
        assert safe is False

    def test_home_path_allowed(self):
        safe, reason = _validate_quarantine_path("/home/user/malware.exe")
        assert safe is True

    def test_quarantine_builder_for_safe_file(self):
        ctx = {
            "incident": {"title": "File integrity", "severity": "medium"},
            "source_ips": [],
            "hostnames": ["target"],
            "attack_type": "unknown",
            "behavioral_indicators": {"file_integrity": 1},
            "alerts": [{"title": "File modified", "source": "wazuh", "metadata": {"data_file": "/tmp/suspicious.sh"}}],
            "auth_analysis": {"failed_logins": [], "successful_logins": []},
            "proof_of_compromise": {"compromised": False},
        }
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "file_quarantine_safe"
        assert "/tmp/suspicious.sh" in plan["playbook_yaml"]
        assert "/var/quarantine/aria" in plan["playbook_yaml"]

    def test_quarantine_blocked_for_system_file(self):
        ctx = {
            "incident": {"title": "File integrity", "severity": "medium"},
            "source_ips": [],
            "hostnames": ["target"],
            "attack_type": "unknown",
            "behavioral_indicators": {"file_integrity": 1},
            "alerts": [{"title": "File modified", "source": "wazuh", "metadata": {"data_file": "/etc/ssh/sshd_config"}}],
            "auth_analysis": {"failed_logins": [], "successful_logins": []},
            "proof_of_compromise": {"compromised": False},
        }
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "manual_review_required"
        assert plan["playbook_yaml"] is None


class TestUnknownScenarios:
    """Unknown scenarios should return None (fall through to LLM)."""

    def test_port_scan_returns_deterministic_block(self):
        ctx = {
            "incident": {"title": "Port Scan", "severity": "medium"},
            "source_ips": ["8.8.8.8"],
            "hostnames": ["target"],
            "attack_type": "port_scan",
            "behavioral_indicators": {"reconnaissance": 3},
            "alerts": [{"title": "Port scan detected", "source": "suricata"}],
            "auth_analysis": {"failed_logins": [], "successful_logins": []},
            "proof_of_compromise": {"compromised": False},
        }
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "suricata_portscan_public_ip"
        assert plan["safety_tier"] == "safe"
        assert "8.8.8.8" in plan["playbook_yaml"]

    def test_reputation_ip_returns_deterministic_block(self):
        ctx = {
            "incident": {"title": "Reputation IP", "severity": "high"},
            "source_ips": ["1.2.3.4"],
            "hostnames": ["target"],
            "attack_type": "unknown",
            "behavioral_indicators": {},
            "alerts": [{"title": "Reputation IP hit", "source": "suricata", "tags": ["cins", "reputation"]}],
            "auth_analysis": {"failed_logins": [], "successful_logins": []},
            "proof_of_compromise": {"compromised": False},
        }
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "suricata_reputation_public_ip"
        assert plan["safety_tier"] == "safe"

    def test_c2_outbound_returns_manual_review(self):
        ctx = {
            "incident": {"title": "C2 Traffic", "severity": "high"},
            "source_ips": ["10.0.0.5"],
            "hostnames": ["target"],
            "attack_type": "c2",
            "behavioral_indicators": {},
            "alerts": [{"title": "C2 beacon detected", "source": "suricata", "tags": ["c2"]}],
            "auth_analysis": {"failed_logins": [], "successful_logins": []},
            "proof_of_compromise": {"compromised": False},
        }
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "manual_review_required"
        assert plan["playbook_yaml"] is None

    def test_falco_startup_returns_diagnostic(self):
        ctx = {
            "incident": {"title": "Container started", "severity": "low"},
            "source_ips": [],
            "hostnames": ["target"],
            "attack_type": "unknown",
            "behavioral_indicators": {},
            "alerts": [{"title": "Container started", "source": "falco", "description": "pod started"}],
            "auth_analysis": {"failed_logins": [], "successful_logins": []},
            "proof_of_compromise": {"compromised": False},
        }
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "falco_diagnostic"
        assert plan["execution_mode"] == "diagnostic"

    def test_falco_systemd_modified_returns_manual_review(self):
        ctx = {
            "incident": {"title": "Systemd modified", "severity": "high"},
            "source_ips": [],
            "hostnames": ["target"],
            "attack_type": "unknown",
            "behavioral_indicators": {},
            "alerts": [{"title": "Systemd unit file modified", "source": "falco", "description": "unit file changed"}],
            "auth_analysis": {"failed_logins": [], "successful_logins": []},
            "proof_of_compromise": {"compromised": False},
        }
        plan = plan_remediation(ctx)
        assert plan is not None
        assert plan["builder_name"] == "manual_review_required"
        assert plan["playbook_yaml"] is None

    def test_malware_returns_none(self):
        ctx = {
            "incident": {"title": "Malware detected", "severity": "high"},
            "source_ips": [],
            "hostnames": ["target"],
            "attack_type": "malware",
            "behavioral_indicators": {"malware": 1},
            "alerts": [{"title": "Malware signature match", "source": "wazuh"}],
            "auth_analysis": {"failed_logins": [], "successful_logins": []},
            "proof_of_compromise": {"compromised": True, "confidence": "high"},
        }
        plan = plan_remediation(ctx)
        assert plan is None
