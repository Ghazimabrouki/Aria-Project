import pytest
import json
from api.routes.investigations import _has_evidence_of_compromise, _build_truth_report
from response.models import Investigation, InvestigationAlert


class TestTruthReportEvidence:
    def test_ssh_failed_login_no_compromise(self):
        inv = Investigation(
            id="truth-1",
            incident_id="inc-1",
            status="awaiting_approval",
            source_ips="192.0.2.1",
            target_host="web-server",
        )
        alert = InvestigationAlert(
            investigation_id="truth-1",
            alert_id="alert-1",
            alert_json=json.dumps({
                "title": "Multiple failed SSH login attempts",
                "source_ip": "192.0.2.1",
                "hostname": "web-server",
                "rule_name": "sshd brute force",
                "tags": ["ssh", "authentication_failed"],
            }),
        )
        inv.alerts = [alert]
        result = _has_evidence_of_compromise(inv)
        assert result["has_successful_login"] is False
        assert result["has_malware"] is False
        assert result["has_lateral_movement"] is False

    def test_successful_login_changes_classification(self):
        inv = Investigation(
            id="truth-2",
            incident_id="inc-1",
            status="awaiting_approval",
            source_ips="192.0.2.1",
            target_host="web-server",
        )
        alert = InvestigationAlert(
            investigation_id="truth-2",
            alert_id="alert-1",
            alert_json=json.dumps({
                "title": "Successful SSH login after brute force",
                "source_ip": "192.0.2.1",
                "hostname": "web-server",
                "tags": ["ssh", "authentication_success", "session_opened"],
            }),
        )
        inv.alerts = [alert]
        result = _has_evidence_of_compromise(inv)
        assert result["has_successful_login"] is True

    def test_truth_report_no_compromise_claims_for_ssh_brute(self):
        inv = Investigation(
            id="truth-3",
            incident_id="inc-1",
            status="awaiting_approval",
            source_ips="192.0.2.1",
            target_host="web-server",
            playbook_yaml="- hosts: target\n  tasks:\n  - debug: msg=ok",
            ai_summary="SSH brute force detected. No successful login.",
            ai_quality_status="passed",
        )
        alert = InvestigationAlert(
            investigation_id="truth-3",
            alert_id="alert-1",
            alert_json=json.dumps({
                "title": "Multiple failed SSH login attempts",
                "source_ip": "192.0.2.1",
                "hostname": "web-server",
                "tags": ["ssh", "authentication_failed"],
            }),
        )
        inv.alerts = [alert]
        report = _build_truth_report(inv)
        assert "compromise" not in " ".join(report.get("inferred_findings", [])).lower() or report.get("confidence") in ("low", "medium")
        assert any("SSH" in str(f) or "brute" in str(f).lower() for f in report["observed_facts"])

    def test_legacy_alert_snapshot_fallback(self):
        inv = Investigation(
            id="truth-4",
            incident_id="inc-1",
            status="awaiting_approval",
        )
        alert = InvestigationAlert(
            investigation_id="truth-4",
            alert_id="alert-1",
            alert_json=json.dumps({"title": "Test"}),
        )
        # Simulate legacy object with alert_snapshot attribute
        object.__setattr__(alert, "alert_snapshot", json.dumps({"title": "Legacy snapshot"}))
        inv.alerts = [alert]
        result = _has_evidence_of_compromise(inv)
        # Should not crash and should parse something
        assert isinstance(result, dict)
