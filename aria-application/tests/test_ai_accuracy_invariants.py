"""
AI accuracy invariant tests for ARIA.

Ensures AI-generated summaries and truth reports do not hallucinate
or make unsupported claims.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from api.routes.investigations import _build_truth_report


class TestUnsupportedClaimsNeverInInferredFindings:
    def test_malware_without_evidence_is_unsupported_not_inferred(self):
        inv = MagicMock()
        inv.ai_summary = "SSH brute force. Possible malware infection."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = None
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []
        inv.source_ips = "10.0.0.1"
        inv.target_host = "host1"

        report = _build_truth_report(inv)
        assert any("malware" in c for c in report["unsupported_claims"])
        assert not any("malware" in f for f in report["inferred_findings"])

    def test_lateral_movement_without_evidence_is_unsupported(self):
        inv = MagicMock()
        inv.ai_summary = "SSH brute force. Lateral movement observed."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = None
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []
        inv.source_ips = "10.0.0.1"
        inv.target_host = "host1"

        report = _build_truth_report(inv)
        assert any("lateral movement" in c for c in report["unsupported_claims"])
        assert not any("lateral movement" in f for f in report["inferred_findings"])

    def test_compromise_without_login_is_unsupported(self):
        inv = MagicMock()
        inv.ai_summary = "System compromised by brute-force attacker."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = None
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []
        inv.source_ips = "10.0.0.1"
        inv.target_host = "host1"

        report = _build_truth_report(inv)
        assert any("compromise" in c for c in report["unsupported_claims"])
        assert not any("compromise" in f for f in report["inferred_findings"])

    def test_ssh_failed_login_never_recommends_isolation(self):
        inv = MagicMock()
        inv.ai_summary = "SSH brute force detected. No successful login."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = "iptables -A INPUT -s 10.0.0.1 -j DROP\nisolate host"
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []
        inv.source_ips = "10.0.0.1"
        inv.target_host = "host1"

        report = _build_truth_report(inv)
        assert not any("Isolate affected systems" in s for s in report["recommended_next_steps"])
        assert any("Playbook recommends system isolation" in c for c in report["unsupported_claims"])

    def test_attack_type_unknown_corrected_for_ssh_evidence(self):
        inv = MagicMock()
        inv.ai_summary = "SSH brute force detected. Attack type is unknown."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = None
        inv.status = "awaiting_approval"
        inv.evidence_json = None
        inv.alerts = []
        inv.source_ips = "36.66.99.135"
        inv.target_host = "ghazi"

        report = _build_truth_report(inv)
        assert any("incorrectly labeled as 'unknown'" in c for c in report["unsupported_claims"])
        assert any("SSH password guessing" in f for f in report["inferred_findings"])


class TestTruthReportClassificationInvariants:
    def test_no_successful_login_classification_is_suspected_threat(self):
        inv = MagicMock()
        inv.ai_summary = "SSH brute force. No successful login."
        inv.ai_quality_status = "passed"
        inv.ai_quality_json = None
        inv.playbook_yaml = None
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []
        inv.source_ips = "10.0.0.1"
        inv.target_host = "host1"

        report = _build_truth_report(inv)
        assert report["final_classification"] == "suspected_threat"
        assert report["confidence"] in ("low", "medium")

    def test_successful_login_classification_is_confirmed_threat(self):
        inv = MagicMock()
        inv.ai_summary = "SSH brute force succeeded. Accepted password observed. Successful login confirmed."
        inv.ai_quality_status = "passed"
        inv.ai_quality_json = None
        inv.playbook_yaml = None
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "accepted password for root from 10.0.0.1"}]}
        inv.alerts = []
        inv.source_ips = "10.0.0.1"
        inv.target_host = "host1"

        report = _build_truth_report(inv)
        assert report["final_classification"] == "confirmed_threat"


class TestTruthReportEvidenceAccuracy:
    def test_malicious_ip_traffic_shows_source_ip_and_target_host_without_ai_summary(self):
        """When ai_summary is missing but source_ips and target_host exist,
        observed facts should not be empty / Unknown everywhere."""
        inv = MagicMock()
        inv.ai_summary = None
        inv.ai_quality_status = "unknown"
        inv.ai_quality_json = None
        inv.playbook_yaml = "---\n- name: Fix\n  hosts: target\n  tasks: []\n"
        inv.status = "awaiting_approval"
        inv.evidence_json = None
        inv.alerts = []
        inv.source_ips = "64.89.163.247"
        inv.target_host = "ghazi"
        inv.incident_title = "Malicious IP traffic detected"
        inv.title = None

        report = _build_truth_report(inv)
        assert any("64.89.163.247" in f for f in report["observed_facts"])
        assert any("ghazi" in f for f in report["observed_facts"])
        assert not any("Alert evidence is limited" in c for c in report["unsupported_claims"])

    def test_unresolved_jinja_recommends_regeneration_not_execution(self):
        """Hard-blocked playbook with unresolved Jinja should recommend regeneration,
        never execution."""
        inv = MagicMock()
        inv.ai_summary = "SSH brute force detected."
        inv.ai_quality_status = "weak"
        inv.ai_quality_json = None
        inv.playbook_yaml = "ansible.builtin.shell: iptables -A INPUT -s {{ attacker_ips[0] }} -j DROP"
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []
        inv.source_ips = "64.89.163.247"
        inv.target_host = "ghazi"
        inv.incident_title = "SSH brute force"
        inv.title = None

        report = _build_truth_report(inv)
        assert any("Regenerate" in s for s in report["recommended_next_steps"])
        assert any("Do NOT execute" in s for s in report["recommended_next_steps"])
        assert any("unresolved Jinja2" in c for c in report["unsupported_claims"])

    def test_no_compromise_inferred_without_host_compromise_evidence(self):
        """Without successful login or malware evidence, classification should not
        infer confirmed compromise."""
        inv = MagicMock()
        inv.ai_summary = "SSH brute force detected. No successful login."
        inv.ai_quality_status = "passed"
        inv.ai_quality_json = None
        inv.playbook_yaml = None
        inv.status = "awaiting_approval"
        inv.evidence_json = {"alerts": [{"raw": "SSH failed login"}]}
        inv.alerts = []
        inv.source_ips = "10.0.0.1"
        inv.target_host = "host1"
        inv.incident_title = "SSH brute force"
        inv.title = None

        report = _build_truth_report(inv)
        assert report["final_classification"] != "confirmed_threat"
        assert not any("compromise" in f.lower() and "possible" not in f.lower() for f in report["inferred_findings"])
