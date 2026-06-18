"""Tests for safety tiers, admin override, and evidence-aware truth reports."""
from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock

from response.playbook_safety import (
    compute_investigation_safety,
    validate_playbook_safety,
    _classify_safety_tiers,
)


# ── Safety Tier Classification ───────────────────────────────────────────────

SAFE_PLAYBOOK = """---
- name: Safe remediation
  hosts: target
  become: yes
  tasks:
    - name: Block attacker IP
      ansible.builtin.shell: "iptables -A INPUT -s '10.0.0.1' -j DROP"
"""

DANGEROUS_PLAYBOOK = """---
- name: Dangerous
  hosts: target
  become: yes
  tasks:
    - name: Wipe disk
      ansible.builtin.shell: "rm -rf /"
"""

SOFT_BLOCK_PLAYBOOK = """---
- name: Update everything
  hosts: target
  become: yes
  tasks:
    - name: Full system update
      ansible.builtin.shell: "apt-get update && apt-get upgrade -y"
"""

SOFT_BLOCK_ROLLBACK_MISSING = """---
- name: Block IP
  hosts: target
  become: yes
  tasks:
    - name: Block attacker
      ansible.builtin.shell: "iptables -A INPUT -s '10.0.0.1' -j DROP"
"""


def _make_inv(playbook=SAFE_PLAYBOOK, rollback="", status="awaiting_approval",
              ai_summary="SSH brute force detected", ai_quality_status="passed"):
    inv = MagicMock()
    inv.playbook_yaml = playbook
    inv.rollback_playbook = rollback
    inv.status = status
    inv.ai_summary = ai_summary
    inv.ai_quality_status = ai_quality_status
    inv.investigation_type = "security"
    inv.target_host = ""
    inv.approval = None
    return inv


class TestSafetyTiers:
    def test_safe_tier(self):
        inv = _make_inv(
            playbook=SAFE_PLAYBOOK,
            rollback=SAFE_PLAYBOOK,
            ai_quality_status="passed"
        )
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "safe"
        assert safety["soft_block_reasons"] == []
        assert safety["is_executable"] is True
        assert safety["admin_can_soft_override"] is False

    def test_dangerous_playbook_soft_block_tier(self):
        inv = _make_inv(
            playbook=DANGEROUS_PLAYBOOK,
            rollback="",
            ai_quality_status="passed"
        )
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert len(safety["soft_block_reasons"]) > 0
        assert safety["is_executable"] is False
        assert safety["admin_can_soft_override"] is False
        assert safety["admin_can_execute"] is False

    def test_soft_block_tier_generic_updater(self):
        inv = _make_inv(
            playbook=SOFT_BLOCK_PLAYBOOK,
            rollback=SOFT_BLOCK_PLAYBOOK,
            ai_quality_status="passed"
        )
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert len(safety["soft_block_reasons"]) > 0
        assert safety["is_executable"] is False  # generic updater blocks

    def test_soft_block_tier_missing_rollback(self):
        inv = _make_inv(
            playbook=SOFT_BLOCK_ROLLBACK_MISSING,
            rollback="",
            ai_quality_status="passed"
        )
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert any("ROLLBACK REQUIRED" in r for r in safety["soft_block_reasons"])
        assert safety["is_executable"] is False

    def test_soft_block_ai_quality_weak(self):
        inv = _make_inv(
            playbook=SAFE_PLAYBOOK,
            rollback=SAFE_PLAYBOOK,
            ai_quality_status="weak"
        )
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert any("AI QUALITY WEAK" in r for r in safety["soft_block_reasons"])

    def test_ai_quality_failed_soft_block(self):
        inv = _make_inv(
            playbook=SAFE_PLAYBOOK,
            rollback=SAFE_PLAYBOOK,
            ai_quality_status="failed"
        )
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"

    def test_empty_summary_soft_block(self):
        inv = _make_inv(
            playbook=SAFE_PLAYBOOK,
            rollback=SAFE_PLAYBOOK,
            ai_summary="",
            ai_quality_status="passed"
        )
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"

    def test_admin_can_soft_override_when_enabled(self, monkeypatch):
        inv = _make_inv(
            playbook=SOFT_BLOCK_PLAYBOOK,
            rollback=SOFT_BLOCK_PLAYBOOK,
            ai_quality_status="passed"
        )
        mock_settings = MagicMock()
        mock_settings.aria_allow_admin_soft_override = True
        monkeypatch.setattr(
            "config.settings.get_settings",
            lambda: mock_settings
        )
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert safety["admin_can_soft_override"] is True
        assert safety["admin_can_execute"] is True

    def test_admin_cannot_soft_override_when_disabled(self, monkeypatch):
        inv = _make_inv(
            playbook=SOFT_BLOCK_PLAYBOOK,
            rollback=SOFT_BLOCK_PLAYBOOK,
            ai_quality_status="passed"
        )
        mock_settings = MagicMock()
        mock_settings.aria_allow_admin_soft_override = False
        monkeypatch.setattr(
            "config.settings.get_settings",
            lambda: mock_settings
        )
        safety = compute_investigation_safety(inv)
        assert safety["admin_can_soft_override"] is False
        assert safety["admin_can_execute"] is False


# ── Truth Report Evidence-Aware Classification ───────────────────────────────

class TestTruthReportSSHBruteForce:
    def test_malware_without_evidence_is_unsupported(self):
        from api.routes.investigations import _build_truth_report
        inv = MagicMock()
        inv.ai_summary = "SSH brute force attack detected. Possible malware infection."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login from 10.0.0.1"}]}
        inv.alerts = []

        report = _build_truth_report(inv)
        assert any("malware infection" in c for c in report["unsupported_claims"])
        assert not any("malware" in f for f in report["inferred_findings"])

    def test_malware_with_evidence_is_inferred(self):
        from api.routes.investigations import _build_truth_report
        inv = MagicMock()
        inv.ai_summary = "SSH brute force attack detected. Possible malware infection."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "malware trojan detected on host"}]}
        inv.alerts = []

        report = _build_truth_report(inv)
        assert any("malware infection" in f for f in report["inferred_findings"])
        assert not any("malware" in c for c in report["unsupported_claims"])

    def test_lateral_movement_without_evidence_is_unsupported(self):
        from api.routes.investigations import _build_truth_report
        inv = MagicMock()
        inv.ai_summary = "SSH brute force attack detected. Possible lateral movement observed."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []

        report = _build_truth_report(inv)
        assert any("lateral movement" in c for c in report["unsupported_claims"])
        assert not any("lateral movement" in f for f in report["inferred_findings"])

    def test_lateral_movement_negated_is_observed_fact(self):
        from api.routes.investigations import _build_truth_report
        inv = MagicMock()
        inv.ai_summary = "SSH brute force attack detected. No lateral movement observed."
        inv.ai_quality_status = "passed"
        inv.ai_quality_json = None
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []

        report = _build_truth_report(inv)
        assert any("No lateral movement" in f for f in report["observed_facts"])
        assert not any("lateral movement" in c for c in report["unsupported_claims"])
        assert not any("lateral movement" in f for f in report["inferred_findings"])

    def test_compromise_without_login_evidence_is_unsupported(self):
        from api.routes.investigations import _build_truth_report
        inv = MagicMock()
        inv.ai_summary = "SSH brute force attack detected. System may be compromised."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []

        report = _build_truth_report(inv)
        assert any("compromise without evidence" in c for c in report["unsupported_claims"])

    def test_compromise_with_login_evidence_is_inferred(self):
        from api.routes.investigations import _build_truth_report
        inv = MagicMock()
        inv.ai_summary = "SSH brute force attack detected. System may be compromised."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "accepted password for root from 10.0.0.1"}]}
        inv.alerts = []

        report = _build_truth_report(inv)
        assert any("compromise" in f for f in report["inferred_findings"])
        assert not any("compromise" in c for c in report["unsupported_claims"])

    def test_no_successful_login_classification(self):
        from api.routes.investigations import _build_truth_report
        inv = MagicMock()
        inv.ai_summary = "SSH brute force attack. No successful login observed."
        inv.ai_quality_status = "passed"
        inv.ai_quality_json = None
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []

        report = _build_truth_report(inv)
        assert report["final_classification"] == "suspected_threat"
        assert any("No successful authentication" in f for f in report["observed_facts"])


# ── Admin Actions Computation ──────────────────────────────────────────────────

class TestAdminActions:
    def test_admin_actions_safe_playbook(self):
        from api.routes.investigations import _compute_admin_actions
        inv = MagicMock()
        inv.status = "awaiting_approval"
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.approval = None
        safety = {"safety_tier": "safe", "is_executable": True, "admin_can_soft_override": False, "admin_can_execute": True, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert "admin_soft_override" not in actions
        assert "execute" not in actions  # execute only after approval
        assert "decline" in actions

    def test_admin_actions_soft_block(self):
        from api.routes.investigations import _compute_admin_actions
        inv = MagicMock()
        inv.status = "awaiting_approval"
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.approval = None
        safety = {"safety_tier": "soft_block", "is_executable": False, "admin_can_soft_override": True, "admin_can_execute": True, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert "admin_soft_override" in actions
        assert "execute" not in actions  # no valid override yet
        assert "decline" in actions

    def test_admin_actions_soft_block_with_valid_override(self):
        from api.routes.investigations import _compute_admin_actions
        inv = MagicMock()
        inv.status = "approved"
        inv.playbook_yaml = SAFE_PLAYBOOK
        approval = MagicMock()
        approval.decision = "approved"
        approval.override = True
        approval.override_by = "admin"
        approval.override_reason = "verified safe"
        inv.approval = approval
        safety = {"safety_tier": "soft_block", "is_executable": False, "admin_can_soft_override": True, "admin_can_execute": True, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert "execute" in actions  # valid override exists

    def test_admin_actions_dangerous_soft_block(self):
        from api.routes.investigations import _compute_admin_actions
        inv = MagicMock()
        inv.status = "awaiting_approval"
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.approval = None
        safety = {"safety_tier": "soft_block", "is_executable": False, "admin_can_soft_override": False, "admin_can_execute": False, "is_safe_to_display": False}
        actions = _compute_admin_actions(inv, safety)
        assert "admin_soft_override" not in actions
        assert "execute" not in actions
        assert "decline" in actions

    def test_admin_actions_dangerous_unresolved_firewall_no_soft_override(self):
        from api.routes.investigations import _compute_admin_actions
        inv = MagicMock()
        inv.status = "awaiting_approval"
        inv.playbook_yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Block
      ansible.builtin.shell: "iptables -A INPUT -s {{ attacker_ips[0] }} -j DROP"
"""
        inv.approval = None
        safety = {"safety_tier": "soft_block", "is_executable": False, "admin_can_soft_override": False, "admin_can_execute": False, "is_safe_to_display": False}
        actions = _compute_admin_actions(inv, safety)
        assert "admin_soft_override" not in actions
        assert "execute" not in actions
        assert "request_regeneration" in actions

    def test_admin_actions_no_playbook(self):
        from api.routes.investigations import _compute_admin_actions
        inv = MagicMock()
        inv.status = "awaiting_approval"
        inv.playbook_yaml = ""
        inv.approval = None
        safety = {"safety_tier": "safe", "is_executable": False, "admin_can_soft_override": False, "admin_can_execute": False, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert "admin_soft_override" not in actions
        assert "execute" not in actions

    def test_admin_actions_decision_approved_status(self):
        from api.routes.investigations import _compute_admin_actions
        inv = MagicMock()
        inv.status = "decision_approved"
        inv.playbook_yaml = SAFE_PLAYBOOK
        inv.approval = None
        safety = {"safety_tier": "soft_block", "is_executable": False, "admin_can_soft_override": False, "admin_can_execute": False, "is_safe_to_display": False}
        actions = _compute_admin_actions(inv, safety)
        assert "admin_soft_override" not in actions
        assert "execute" not in actions
        assert "archive" in actions

    def test_analyst_actions_dangerous_soft_block_no_approve(self):
        from api.routes.investigations import _compute_analyst_actions
        inv = MagicMock()
        inv.status = "awaiting_approval"
        inv.playbook_yaml = SAFE_PLAYBOOK
        safety = {"safety_tier": "soft_block", "is_executable": False, "is_safe_to_display": False, "admin_can_soft_override": False, "admin_can_execute": False}
        actions = _compute_analyst_actions(inv, safety)
        assert "approve" not in actions
        assert "execute" not in actions
        assert "decline" in actions
        assert "request_regeneration" in actions

    def test_analyst_actions_decision_approved_no_execute(self):
        from api.routes.investigations import _compute_analyst_actions
        inv = MagicMock()
        inv.status = "decision_approved"
        inv.playbook_yaml = SAFE_PLAYBOOK
        safety = {"safety_tier": "safe", "is_executable": True, "is_safe_to_display": True, "admin_can_soft_override": False, "admin_can_execute": True}
        actions = _compute_analyst_actions(inv, safety)
        assert "approve" not in actions
        assert "execute" not in actions
        assert "archive" in actions


# ── SSH Brute-force Truth Report Accuracy ─────────────────────────────────────

class TestTruthReportSSHBruteForceAccuracy:
    def test_ssh_failed_login_no_unknown_attack_type(self):
        from api.routes.investigations import _build_truth_report
        inv = MagicMock()
        inv.ai_summary = "SSH brute force attack detected from 36.66.99.135. Attack type is unknown."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = None
        inv.status = "awaiting_approval"
        inv.evidence_json = None
        inv.alerts = []
        inv.source_ips = "36.66.99.135"
        inv.target_host = "ghazi"

        report = _build_truth_report(inv)
        assert any("Failed SSH/PAM authentication" in f for f in report["observed_facts"])
        assert any("SSH password guessing" in f for f in report["inferred_findings"])
        assert any("incorrectly labeled as 'unknown'" in c for c in report["unsupported_claims"])
        assert report["final_classification"] == "suspected_threat"

    def test_ssh_failed_login_no_isolate_recommendation(self):
        from api.routes.investigations import _build_truth_report
        inv = MagicMock()
        inv.ai_summary = "SSH brute force attack detected. No successful login."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = "iptables -A INPUT -s 36.66.99.135 -j DROP\nisolate host"
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []
        inv.source_ips = "36.66.99.135"
        inv.target_host = "ghazi"

        report = _build_truth_report(inv)
        assert not any("Isolate affected systems" in s for s in report["recommended_next_steps"])
        assert any("review auth logs" in s.lower() for s in report["recommended_next_steps"])
        assert any("block exact source ip" in s.lower() for s in report["recommended_next_steps"])
        assert any("Playbook recommends system isolation" in c for c in report["unsupported_claims"])

    def test_ssh_failed_login_no_compromise_claims(self):
        from api.routes.investigations import _build_truth_report
        inv = MagicMock()
        inv.ai_summary = "SSH brute force attack detected. No successful login observed."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = None
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []
        inv.source_ips = "36.66.99.135"
        inv.target_host = "ghazi"

        report = _build_truth_report(inv)
        assert not any("compromise" in c for c in report["unsupported_claims"])
        assert not any("lateral movement" in c for c in report["unsupported_claims"])
        assert not any("malware" in c for c in report["unsupported_claims"])
        assert not any("persistence" in c for c in report["unsupported_claims"])
        assert report["confidence"] in ("low", "medium")
        assert report["final_classification"] == "suspected_threat"

    def test_ssh_explicit_ip_safe_tier(self):
        from response.playbook_safety import compute_investigation_safety
        inv = MagicMock()
        inv.playbook_yaml = """---
- name: Safe
  hosts: target
  tasks:
    - name: Block exact IP
      ansible.builtin.shell: "iptables -A INPUT -s '36.66.99.135' -j DROP"
"""
        inv.rollback_playbook = """---
- name: Rollback
  hosts: target
  tasks:
    - name: Remove exact IP
      ansible.builtin.shell: "iptables -D INPUT -s '36.66.99.135' -j DROP"
"""
        inv.status = "awaiting_approval"
        inv.ai_summary = "SSH brute force from 36.66.99.135"
        inv.ai_quality_status = "passed"
        inv.investigation_type = "security"
        inv.target_host = "ghazi"
        inv.alerts = []
        inv.approval = None
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "safe"
        assert safety["playbook_safety_status"] == "safe"
        assert safety["rollback_safety_status"] == "safe"
        assert safety["is_executable"] is True

    def test_ssh_unresolved_jinja_soft_block(self):
        from response.playbook_safety import compute_investigation_safety
        inv = MagicMock()
        inv.playbook_yaml = """---
- name: Bad
  hosts: target
  tasks:
    - name: Block with Jinja
      ansible.builtin.shell: "iptables -A INPUT -s {{ attacker_ips[0] }} -j DROP"
"""
        inv.rollback_playbook = ""
        inv.status = "awaiting_approval"
        inv.ai_summary = "SSH brute force detected"
        inv.ai_quality_status = "passed"
        inv.investigation_type = "security"
        inv.target_host = "ghazi"
        inv.alerts = []
        inv.approval = None
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert any("unresolved Jinja2" in r for r in safety["soft_block_reasons"])
        assert safety["admin_can_soft_override"] is False
        assert safety["admin_can_execute"] is False
