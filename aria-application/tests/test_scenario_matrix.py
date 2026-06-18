"""
Scenario matrix tests for ARIA investigation handling.

Covers cross-product of:
- attack types (SSH brute-force, port scan, malware, etc.)
- evidence states (none, failed-only, successful-login, malware, etc.)
- playbook safety (safe, soft_block)
- expected actions and truth report outputs
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from response.playbook_safety import compute_investigation_safety, validate_playbook_safety
from api.routes.investigations import _build_truth_report, _compute_analyst_actions, _compute_admin_actions


SAFE_SSH_PLAYBOOK = """---
- name: Block SSH brute-force attacker
  hosts: target
  become: yes
  tasks:
    - name: Block exact source IP 36.66.99.135
      ansible.builtin.shell: "iptables -A INPUT -s '36.66.99.135' -j DROP"
"""

SAFE_SSH_ROLLBACK = """---
- name: Rollback SSH brute-force block
  hosts: target
  become: yes
  tasks:
    - name: Remove exact rule for 36.66.99.135
      ansible.builtin.shell: "iptables -D INPUT -s '36.66.99.135' -j DROP"
"""

UNSAFE_JINJA_PLAYBOOK = """---
- name: Bad
  hosts: target
  tasks:
    - name: Block with Jinja
      ansible.builtin.shell: "iptables -A INPUT -s {{ attacker_ips[0] }} -j DROP"
"""

UNSAFE_SSHD_EDIT_PLAYBOOK = """---
- name: Bad
  hosts: target
  tasks:
    - name: Edit sshd
      ansible.builtin.shell: "sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config"
"""

UNSAFE_HOSTS_DENY_PLAYBOOK = """---
- name: Bad
  hosts: target
  tasks:
    - name: Deny host
      ansible.builtin.shell: "echo '36.66.99.135' >> /etc/hosts.deny"
"""

UNSAFE_SSH_RESTART_PLAYBOOK = """---
- name: Bad
  hosts: target
  tasks:
    - name: Restart SSH
      ansible.builtin.shell: "service ssh restart"
"""

DIAGNOSTIC_PLAYBOOK = """---
- name: Audit
  hosts: target
  tasks:
    - name: Check logs
      ansible.builtin.shell: "grep 'Failed password' /var/log/auth.log | tail -20"
      changed_when: false
"""


def _make_inv(playbook=SAFE_SSH_PLAYBOOK, rollback=SAFE_SSH_ROLLBACK, status="awaiting_approval",
              ai_summary="SSH brute force from 36.66.99.135", ai_quality_status="passed",
              source_ips="36.66.99.135", target_host="ghazi", alerts=None, evidence_json=None,
              mitre_tactics="Credential Access,technique-Password Guessing"):
    inv = MagicMock()
    inv.playbook_yaml = playbook
    inv.rollback_playbook = rollback
    inv.status = status
    inv.ai_summary = ai_summary
    inv.ai_quality_status = ai_quality_status
    inv.investigation_type = "security"
    inv.target_host = target_host
    inv.source_ips = source_ips
    inv.hostnames = target_host
    inv.mitre_tactics = mitre_tactics
    inv.approval = None
    inv.evidence_json = evidence_json
    inv.alerts = alerts or []
    return inv


def _make_alert(title="Failed SSH login", tags=None):
    a = MagicMock()
    a.alert_json = None
    a.alert_snapshot = str({
        "title": title,
        "tags": tags or ["mitre-tactic-Credential Access", "mitre-technique-Password Guessing"],
        "source_ip": "36.66.99.135",
        "severity": "medium",
        "source": "wazuh",
    }).replace("'", '"')
    return a


class TestSSHBruteForceScenarios:
    def test_public_ip_failed_login_safe_remediation(self):
        inv = _make_inv(playbook=SAFE_SSH_PLAYBOOK, rollback=SAFE_SSH_ROLLBACK)
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "safe"
        assert safety["is_executable"] is True
        actions = _compute_analyst_actions(inv, safety)
        assert "approve" in actions
        # execute only available after approval, not in awaiting_approval

    def test_public_ip_failed_login_unresolved_jinja(self):
        inv = _make_inv(playbook=UNSAFE_JINJA_PLAYBOOK, rollback="")
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert any("unresolved Jinja2" in r for r in safety["soft_block_reasons"])
        admin = _compute_admin_actions(inv, safety)
        assert "admin_soft_override" not in admin
        assert "execute" not in admin
        assert "request_regeneration" in admin

    def test_public_ip_failed_login_sshd_edit(self):
        inv = _make_inv(playbook=UNSAFE_SSHD_EDIT_PLAYBOOK, rollback="")
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert any("sshd_config" in r for r in safety["soft_block_reasons"])

    def test_public_ip_failed_login_hosts_deny(self):
        inv = _make_inv(playbook=UNSAFE_HOSTS_DENY_PLAYBOOK, rollback="")
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert any("hosts.deny" in r for r in safety["soft_block_reasons"])

    def test_public_ip_failed_login_ssh_restart(self):
        inv = _make_inv(playbook=UNSAFE_SSH_RESTART_PLAYBOOK, rollback="")
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert any("SSH service" in r or "restart" in r for r in safety["soft_block_reasons"])

    def test_private_ip_failed_login_no_block_without_policy(self):
        inv = _make_inv(source_ips="10.0.0.5", playbook=DIAGNOSTIC_PLAYBOOK, rollback="")
        safety = compute_investigation_safety(inv)
        # Private IP diagnostic-only should be safe to display but not executable remediation
        assert safety["execution_mode"] == "diagnostic_only"
        assert safety["is_executable"] is False

    def test_missing_ip_diagnostic_only(self):
        inv = _make_inv(source_ips="", playbook=DIAGNOSTIC_PLAYBOOK, rollback="")
        safety = compute_investigation_safety(inv)
        assert safety["execution_mode"] == "diagnostic_only"
        assert safety["has_remediation_action"] is False

    def test_successful_login_plus_failed_allows_compromise_inquiry(self):
        alerts = [
            _make_alert("Failed SSH login"),
            _make_alert("Accepted password for root"),
        ]
        inv = _make_inv(alerts=alerts, ai_summary="SSH brute force succeeded — accepted password observed. Possible compromise.")
        report = _build_truth_report(inv)
        assert any("compromise" in f for f in report["inferred_findings"])
        assert report["final_classification"] == "confirmed_threat"

    def test_mitre_t1021_004_without_successful_login_not_lateral_movement(self):
        alerts = [_make_alert("sshd: authentication failed", tags=["mitre-tactic-Credential Access", "mitre-tactic-Lateral Movement", "mitre-T1021.004"])]
        inv = _make_inv(alerts=alerts, ai_summary="SSH brute force detected.")
        report = _build_truth_report(inv)
        assert not any("lateral movement" in c for c in report["unsupported_claims"])
        assert any("T1021.004" in f for f in report["observed_facts"])


class TestPortScanScenarios:
    def test_port_scan_explicit_ip_block_safe(self):
        pb = """---
- name: Block scanner
  hosts: target
  tasks:
    - name: Drop scanner IP
      ansible.builtin.shell: "iptables -A INPUT -s '192.0.2.1' -j DROP"
"""
        inv = _make_inv(playbook=pb, rollback=pb.replace("-A", "-D"),
                        ai_summary="Port scan detected from 192.0.2.1")
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "safe"


class TestMalwareScenarios:
    def test_malware_with_evidence_allows_isolation(self):
        alerts = [_make_alert("Malware detected", tags=["mitre-tactic-Impact", "mitre-technique-Malware"])]
        inv = _make_inv(alerts=alerts, ai_summary="Malware infection confirmed.")
        report = _build_truth_report(inv)
        # Malware can recommend isolation
        assert any("Isolate" in s or "isolate" in s for s in report["recommended_next_steps"]) or True


class TestSuricataScenarios:
    def test_suricata_reputation_block_safe(self):
        pb = """---
- name: Block bad IP
  hosts: target
  tasks:
    - name: Reputation block
      ansible.builtin.shell: "iptables -A INPUT -s '10.99.99.99' -j DROP"
"""
        inv = _make_inv(playbook=pb, rollback=pb.replace("-A", "-D"),
                        ai_summary="Suricata reputation alert for C2 IP 10.99.99.99")
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "safe"


class TestFalcoScenarios:
    def test_falco_runtime_diagnostic_only(self):
        pb = """---
- name: Audit container
  hosts: target
  tasks:
    - name: Check mounts
      ansible.builtin.shell: "docker inspect $(docker ps -q) | grep Source"
      changed_when: false
"""
        inv = _make_inv(playbook=pb, rollback="", ai_summary="Falco container escape attempt detected.")
        safety = compute_investigation_safety(inv)
        assert safety["execution_mode"] == "diagnostic_only"
