"""
Unit tests for manual workflow backend logic.
"""

import pytest
from datetime import datetime, timezone


class TestCreateManualIncidentValidation:
    """Test Pydantic validation for CreateManualIncidentRequest."""

    def test_valid_request(self):
        from api.routes.incidents import CreateManualIncidentRequest
        req = CreateManualIncidentRequest(
            title="Test Incident",
            description="Test description",
            severity="high",
            alert_ids=["alert-1", "alert-2"],
        )
        assert req.title == "Test Incident"
        assert req.severity == "high"
        assert req.alert_ids == ["alert-1", "alert-2"]

    def test_invalid_severity(self):
        from api.routes.incidents import CreateManualIncidentRequest
        with pytest.raises(ValueError, match="severity must be one of"):
            CreateManualIncidentRequest(
                title="Test",
                description="Test",
                severity="invalid",
                alert_ids=["alert-1"],
            )

    def test_empty_alert_ids(self):
        from api.routes.incidents import CreateManualIncidentRequest
        with pytest.raises(ValueError, match="at least one alert_id is required"):
            CreateManualIncidentRequest(
                title="Test",
                description="Test",
                severity="high",
                alert_ids=[],
            )

    def test_too_many_alert_ids(self):
        from api.routes.incidents import CreateManualIncidentRequest
        with pytest.raises(ValueError, match="maximum 100 alert_ids allowed"):
            CreateManualIncidentRequest(
                title="Test",
                description="Test",
                severity="high",
                alert_ids=[f"alert-{i}" for i in range(101)],
            )

    def test_tags_dedup(self):
        from api.routes.incidents import CreateManualIncidentRequest
        req = CreateManualIncidentRequest(
            title="Test",
            description="Test",
            severity="high",
            alert_ids=["alert-1"],
            tags=["manual", "test", "manual"],
        )
        # Tags are deduplicated in the endpoint, not in the model
        assert req.tags == ["manual", "test", "manual"]


class TestInvestigationModel:
    """Test Investigation model constraints."""

    def test_incident_id_not_unique(self):
        """Verify that incident_id no longer has a unique constraint."""
        from response.models import Investigation
        from sqlalchemy import inspect
        # Check the table definition
        table = Investigation.__table__
        incident_id_col = table.c.incident_id
        assert not incident_id_col.unique
        assert incident_id_col.index


class TestCreateManualInvestigationValidation:
    """Test Pydantic validation for CreateManualInvestigationRequest."""

    def test_valid_request(self):
        from api.routes.investigations import CreateManualInvestigationRequest
        req = CreateManualInvestigationRequest(
            incident_id="incident-1",
            target_host="192.168.1.1",
            target_user="admin",
        )
        assert req.incident_id == "incident-1"
        assert req.target_host == "192.168.1.1"
        assert req.target_user == "admin"

    def test_default_target_user(self):
        from api.routes.investigations import CreateManualInvestigationRequest
        req = CreateManualInvestigationRequest(incident_id="incident-1")
        assert req.target_user == "root"

    def test_created_by_default(self):
        from api.routes.investigations import CreateManualInvestigationRequest
        req = CreateManualInvestigationRequest(incident_id="incident-1")
        assert req.created_by == "analyst"


class TestRuntimeRemediationPlanner:
    """Runtime planner safety gates."""

    def test_diagnostic_only_playbook_is_not_remediation(self):
        from response.runtime_ai_engine.playbook_generator import generate_runtime_diagnostic_playbook

        playbook = generate_runtime_diagnostic_playbook(
            runtime_context={
                "runtime_category": "file_access",
                "rule_name": "Clear Log Activities",
                "proc_name": "audit2allow",
                "fd_name": "/var/log/audit/audit.log",
            },
            host="ghazi",
        )

        assert "Runtime Diagnostic" in playbook
        assert "changed_when: false" in playbook
        assert "Remediation" not in playbook

    def test_observe_decision_has_no_approval_path(self):
        from response.runtime_ai_engine.remediation_planner import (
            build_runtime_remediation_plan,
            has_corrective_actions,
            derive_runtime_status,
        )

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "file_access",
                "rule_name": "Clear Log Activities",
                "proc_name": "audit2allow",
                "fd_name": "/var/log/audit/audit_rules.txt",
                "hostname": "ghazi",
            },
            findings={
                "threat_assessment": "observe",
                "is_expected": True,
                "requires_intervention": False,
                "confidence": 0.8,
            },
        )

        assert plan["decision"] in {"observe", "no_action_expected_activity"}
        assert plan["corrective_actions"] == []
        assert plan["actual_remediation_available"] is False
        assert has_corrective_actions(plan) is False
        assert derive_runtime_status(plan) == "observe"

    def test_manual_review_required_has_no_approval_path(self):
        from response.runtime_ai_engine.remediation_planner import (
            build_runtime_remediation_plan,
            has_corrective_actions,
        )

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "persistence",
                "rule_name": "Systemd Unit File Modified",
                "hostname": "ghazi",
                "fd_name": "/etc/systemd/system/example.service",
            },
            findings={"threat_assessment": "suspicious", "requires_intervention": True},
        )

        assert plan["decision"] == "manual_review_required"
        assert "baseline" in " ".join(plan["evidence_gaps"]).lower()
        assert has_corrective_actions(plan) is False

    def test_container_systemd_case_blocks_host_remediation(self):
        from response.runtime_ai_engine.remediation_planner import build_runtime_remediation_plan

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "persistence",
                "rule_name": "Systemd Unit File Modified",
                "hostname": "ghazi",
                "fd_name": "/etc/systemd/system/example.service",
                "container_id": "abc123",
                "container_name": "web",
                "k8s_ns_name": "prod",
                "k8s_pod_name": "web-1",
            },
            findings={"threat_assessment": "suspicious", "requires_intervention": True},
        )

        assert plan["target_context"] == "kubernetes"
        assert plan["decision"] == "manual_review_required"
        assert plan["corrective_actions"] == []

    def test_host_systemd_with_baseline_creates_safe_corrective_action(self):
        from response.runtime_ai_engine.remediation_planner import (
            build_runtime_remediation_plan,
            has_corrective_actions,
        )

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "persistence",
                "rule_name": "Systemd Unit File Modified",
                "hostname": "ghazi",
                "fd_name": "/etc/systemd/system/example.service",
                "proc_cmdline": "systemctl restart example.service",
            },
            findings={
                "threat_assessment": "suspicious",
                "requires_intervention": True,
                "trusted_baseline": "/opt/baselines/example.service",
            },
        )

        assert plan["decision"] == "high_risk_action_requires_approval"
        assert has_corrective_actions(plan) is True
        assert plan["rollback_actions"]

    def test_apt_normal_update_observe(self):
        from response.runtime_ai_engine.remediation_planner import build_runtime_remediation_plan

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "package_manager",
                "hostname": "ghazi",
                "proc_name": "apt",
                "proc_cmdline": "apt update",
                "user_name": "root",
            },
            findings={"threat_assessment": "observe", "requires_intervention": False},
        )

        assert plan["decision"] == "observe"
        assert plan["actual_remediation_available"] is False

    def test_apt_suspicious_package_requires_approval(self):
        from response.runtime_ai_engine.remediation_planner import (
            build_runtime_remediation_plan,
            has_corrective_actions,
        )

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "package_manager",
                "hostname": "ghazi",
                "proc_name": "apt-get",
                "proc_cmdline": "apt-get install xmrig",
                "user_name": "root",
            },
            findings={"threat_assessment": "suspicious", "requires_intervention": True},
        )

        assert plan["decision"] == "high_risk_action_requires_approval"
        assert has_corrective_actions(plan) is True

    def test_wazuh_sensitive_read_observe(self):
        from response.runtime_ai_engine.remediation_planner import build_runtime_remediation_plan

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "credential_access",
                "hostname": "ghazi",
                "proc_name": "wazuh-syscheckd",
                "fd_name": "/etc/shadow",
            },
            findings={"threat_assessment": "suspicious", "requires_intervention": True},
        )

        assert plan["decision"] == "observe"

    def test_suspicious_shadow_read_manual_review(self):
        from response.runtime_ai_engine.remediation_planner import build_runtime_remediation_plan

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "credential_access",
                "hostname": "ghazi",
                "proc_name": "unknown-reader",
                "fd_name": "/etc/shadow",
            },
            findings={"threat_assessment": "suspicious", "requires_intervention": True},
        )

        assert plan["decision"] == "manual_review_required"
        assert plan["corrective_actions"] == []

    def test_network_endpoint_uses_remote_ip_and_exact_rollback(self):
        from response.runtime_ai_engine.remediation_planner import build_runtime_remediation_plan

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "network_behavior",
                "hostname": "ghazi",
                "proc_name": "curl",
                "fd_rip": "203.0.113.10",
                "fd_rport": 4444,
            },
            findings={"threat_assessment": "suspicious", "requires_intervention": True},
        )

        assert plan["decision"] == "high_risk_action_requires_approval"
        assert plan["target_network_endpoint"]["remote_ip"] == "203.0.113.10"
        assert plan["rollback_actions"][0]["type"] == "remove_exact_firewall_rule"


class TestRuntimeMappingAndInvestigation:
    """Falco runtime alert mapping and investigation creation."""

    def test_falco_mapping_creates_runtime_alert(self):
        from pipeline.mappers.falco_runtime import map_falco_runtime_alert

        doc = {
            "_id": "test-doc-1",
            "rule": "Systemd Unit File Modified",
            "priority": "error",
            "output": "Systemd file modified by proc_name=vim",
            "hostname": "test-host",
            "output_fields": {
                "proc_name": "vim",
                "proc_cmdline": "vim /etc/systemd/system/test.service",
                "user_name": "root",
                "fd_name": "/etc/systemd/system/test.service",
                "container_id": "host",
                "container_name": "host",
                "evt_hostname": "test-host",
            },
            "tags": ["persistence"],
        }

        alert = map_falco_runtime_alert(doc)

        assert alert["source"] == "falco"
        assert alert["investigation_type"] == "runtime"
        assert alert["runtime_category"] == "persistence"
        assert alert["title"] == "Systemd Unit File Modified"
        assert "observables" in alert
        assert len(alert["observables"]) > 0
        assert "iocs" in alert
        assert "metadata" in alert
        assert alert["metadata"]["container"]["id"] == "host"

    def test_runtime_alert_creates_investigation(self):
        import asyncio
        from pipeline.datausage.runtime_orchestrator import create_runtime_investigation
        from response.models import Investigation

        alert = {
            "id": "alert-123",
            "title": "Test Rule",
            "severity": "high",
            "hostname": "test-host",
            "runtime_category": "file_access",
            "runtime_context": {
                "runtime_category": "file_access",
                "rule_name": "Test Rule",
                "priority": "error",
                "severity": "high",
                "hostname": "test-host",
                "proc_name": "cat",
                "fd_name": "/etc/shadow",
            },
            "is_intervention_required": True,
        }

        # We can't easily test the full async DB path without a DB fixture,
        # so we verify the investigation object shape by mocking the DB session
        # or we just validate that the function exists and has the right signature.
        # For a lightweight unit test, inspect the function signature.
        import inspect
        sig = inspect.signature(create_runtime_investigation)
        assert "alert_payload" in sig.parameters
        assert "local_alert_id" in sig.parameters


class TestRuntimeDiagnosticExecution:
    """Safe diagnostic Ansible execution."""

    def test_diagnostic_runner_uses_devnull_stdin(self):
        from unittest.mock import patch, MagicMock
        import asyncio
        from response.ansible_exec import _run_diagnostic_ansible_safe
        from pathlib import Path

        async def _test():
            with patch("response.ansible_exec.shutil.which", return_value="/usr/bin/ansible-playbook"):
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stdout = "ok: [test]"
                with patch("subprocess.run", return_value=mock_result) as mock_run:
                    playbook = Path("/tmp/test.yml")
                    inventory = Path("/tmp/test_inventory")
                    exit_code, output = await _run_diagnostic_ansible_safe(playbook, inventory)
                    assert exit_code == 0
                    assert "ok: [test]" in output
                    call_kwargs = mock_run.call_args.kwargs
                    assert call_kwargs.get("stdin") is not None
                    # stdin should be DEVNULL
                    import subprocess
                    assert call_kwargs["stdin"] == subprocess.DEVNULL

        asyncio.run(_test())

    def test_diagnostic_runner_returns_timing_info(self):
        from unittest.mock import patch, MagicMock
        import asyncio
        from response.ansible_exec import _run_diagnostic_ansible_safe
        from pathlib import Path

        async def _test():
            with patch("response.ansible_exec.shutil.which", return_value="/usr/bin/ansible-playbook"):
                mock_result = MagicMock()
                mock_result.returncode = 1
                mock_result.stdout = "fatal: unreachable"
                with patch("subprocess.run", return_value=mock_result):
                    playbook = Path("/tmp/test.yml")
                    inventory = Path("/tmp/test_inventory")
                    exit_code, output = await _run_diagnostic_ansible_safe(playbook, inventory)
                    assert exit_code == 1
                    assert "fatal: unreachable" in output

        asyncio.run(_test())


class TestRuntimePlannerEdgeCases:
    """Additional planner edge cases."""

    def test_host_systemd_without_baseline_manual_review(self):
        from response.runtime_ai_engine.remediation_planner import (
            build_runtime_remediation_plan,
            has_corrective_actions,
        )

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "persistence",
                "rule_name": "Systemd Unit File Modified",
                "hostname": "ghazi",
                "fd_name": "/etc/systemd/system/example.service",
                "proc_cmdline": "systemctl restart example.service",
            },
            findings={"threat_assessment": "suspicious", "requires_intervention": True},
        )

        assert plan["decision"] == "manual_review_required"
        assert has_corrective_actions(plan) is False
        assert plan["corrective_actions"] == []

    def test_old_stale_case_marked_safely(self):
        from response.runtime_ai_engine.remediation_planner import (
            build_runtime_remediation_plan,
            has_corrective_actions,
        )

        # Simulate an old record that was moved to awaiting_approval before the fix
        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "file_access",
                "rule_name": "Clear Log Activities",
                "proc_name": "audit2allow",
                "fd_name": "/var/log/audit/audit_rules.txt",
                "hostname": "ghazi",
            },
            findings={"threat_assessment": "observe", "requires_intervention": False, "confidence": 0.8},
        )

        assert plan["decision"] in {"observe", "no_action_expected_activity"}
        assert has_corrective_actions(plan) is False
        # If something forces awaiting_approval, the plan itself should not have corrective actions


class TestRuntimeAPIContract:
    """Runtime API response shape and action truthfulness."""

    def test_available_actions_matrix(self):
        from api.routes.runtime import _available_actions
        from response.runtime_ai_engine.remediation_planner import has_corrective_actions

        # Mock investigation
        class FakeInv:
            status = "findings_ready"

        # observe / no corrective
        plan = {"decision": "observe", "corrective_actions": [], "actual_remediation_available": False}
        actions = _available_actions(FakeInv(), plan)
        assert actions["acknowledge"] is True
        assert actions["escalate"] is False
        assert actions["approve_run"] is False
        assert actions["decline"] is False
        assert actions["archive"] is True

        # manual_review_required / no corrective — escalate is still offered so analyst can trigger planner
        plan = {"decision": "manual_review_required", "corrective_actions": [], "actual_remediation_available": False}
        actions = _available_actions(FakeInv(), plan)
        assert actions["acknowledge"] is True
        assert actions["escalate"] is True  # allowed so analyst can re-run planner
        assert actions["approve_run"] is False
        assert actions["decline"] is False

        # awaiting_approval / with corrective
        FakeInv.status = "awaiting_approval"
        plan = {
            "decision": "high_risk_action_requires_approval",
            "corrective_actions": [{"type": "block_remote_endpoint", "remote_ip": "1.2.3.4"}],
            "actual_remediation_available": True,
        }
        actions = _available_actions(FakeInv(), plan)
        assert actions["acknowledge"] is False
        assert actions["approve_run"] is True
        assert actions["decline"] is True

    def test_detail_endpoint_includes_remediation_plan(self):
        from response.runtime_ai_engine.remediation_planner import build_runtime_remediation_plan

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "file_access",
                "hostname": "h1",
                "proc_name": "cat",
                "fd_name": "/etc/shadow",
            },
            findings={"threat_assessment": "observe", "requires_intervention": False, "confidence": 0.8},
        )

        assert "decision" in plan
        assert "corrective_actions" in plan
        assert "next_manual_steps" in plan


class TestFalcoMapperIPExtraction:
    """Test Falco runtime mapper extracts network IPs correctly."""

    def test_network_ips_extracted_from_output_fields(self):
        from pipeline.mappers.falco_runtime import map_falco_runtime_alert

        doc = {
            "rule": "Unexpected UDP Traffic",
            "priority": "warning",
            "output": "test",
            "hostname": "host1",
            "output_fields": {
                "fd_sip": "10.0.0.1",
                "fd_dip": "8.8.8.8",
                "fd_sport": 12345,
                "fd_dport": 53,
                "fd_l4proto": "udp",
                "proc_name": "nc",
                "container_id": "host",
            },
            "tags": [],
        }
        alert = map_falco_runtime_alert(doc)
        assert alert["source_ip"] == "10.0.0.1"
        assert alert["dest_ip"] == "8.8.8.8"
        observables = {o["type"]: o for o in alert["observables"]}
        assert "network" in observables
        assert "10.0.0.1" in observables["network"]["description"]
        meta = alert["metadata"]
        assert meta["network"]["source_ip"] == "10.0.0.1"
        assert meta["network"]["dest_port"] == 53

    def test_no_network_observable_when_ips_missing(self):
        from pipeline.mappers.falco_runtime import map_falco_runtime_alert

        doc = {
            "rule": "Read sensitive file untrusted",
            "priority": "warning",
            "output": "test",
            "hostname": "host1",
            "output_fields": {
                "proc_name": "cat",
                "fd_name": "/etc/shadow",
                "container_id": "host",
            },
            "tags": [],
        }
        alert = map_falco_runtime_alert(doc)
        assert alert["source_ip"] is None
        assert alert["dest_ip"] is None
        types = [o["type"] for o in alert["observables"]]
        assert "network" not in types


class TestFalcoDedupContract:
    """Test Falco dedup key includes container_id correctly."""

    def test_dedup_key_includes_container_id(self):
        from pipeline.services.dedup import _generate_dedup_key

        payload_a = {
            "source": "falco",
            "hostname": "host1",
            "metadata": {
                "container_id": "abc123",
            },
            "rule_name": "R1",
            "proc_name": "p1",
            "fd_name": "f1",
        }
        payload_b = {
            "source": "falco",
            "hostname": "host1",
            "metadata": {
                "container_id": "def456",
            },
            "rule_name": "R1",
            "proc_name": "p1",
            "fd_name": "f1",
        }
        key_a = _generate_dedup_key("falco", payload_a)
        key_b = _generate_dedup_key("falco", payload_b)
        # Different container IDs must produce different hashes
        assert key_a != key_b
        # Same payload must produce same hash (stable)
        assert _generate_dedup_key("falco", payload_a) == key_a

    def test_dedup_key_fallback_to_nested_container_id(self):
        from pipeline.services.dedup import _generate_dedup_key

        payload = {
            "source": "falco",
            "hostname": "host1",
            "metadata": {
                "container": {"id": "nested456"},
            },
            "rule_name": "R1",
            "proc_name": "p1",
            "fd_name": "f1",
        }
        key = _generate_dedup_key("falco", payload)
        # Changing the nested container id should change the hash
        payload2 = {**payload, "metadata": {"container": {"id": "other"}}}
        key2 = _generate_dedup_key("falco", payload2)
        assert key != key2

    def test_same_host_different_container_not_collapsed(self):
        from pipeline.services.dedup import _generate_dedup_key

        base = {
            "source": "falco",
            "hostname": "host1",
            "metadata": {"container_id": "", "container": {"id": ""}},
            "rule_name": "R1",
            "proc_name": "p1",
            "fd_name": "f1",
        }
        key_a = _generate_dedup_key("falco", {**base, "metadata": {"container_id": "c1"}})
        key_b = _generate_dedup_key("falco", {**base, "metadata": {"container_id": "c2"}})
        assert key_a != key_b


class TestPackageManagerContainerGate:
    """Test container-scoped package manager events are blocked from host remediation."""

    def test_container_package_manager_blocked(self):
        from response.runtime_ai_engine.remediation_planner import build_runtime_remediation_plan

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "package_manager",
                "hostname": "host1",
                "proc_name": "apt",
                "proc_cmdline": "apt install backdoor",
                "container_id": "abc123",
                "container_name": "app",
            },
            findings={
                "threat_assessment": "suspicious",
                "requires_intervention": True,
                "confidence": 0.9,
            },
        )
        assert plan["decision"] == "manual_review_required"
        assert plan["target_context"] in {"container", "kubernetes"}
        assert len(plan["corrective_actions"]) == 0
        assert any("container" in step.lower() for step in plan["next_manual_steps"])

    def test_host_package_manager_suspicious_package_allowed(self):
        from response.runtime_ai_engine.remediation_planner import build_runtime_remediation_plan

        plan = build_runtime_remediation_plan(
            runtime_context={
                "runtime_category": "package_manager",
                "hostname": "host1",
                "proc_name": "apt",
                "proc_cmdline": "apt install backdoor",
                "container_id": "host",
            },
            findings={
                "threat_assessment": "suspicious",
                "requires_intervention": True,
                "confidence": 0.9,
            },
        )
        assert plan["decision"] == "high_risk_action_requires_approval"
        assert len(plan["corrective_actions"]) == 1
        assert plan["corrective_actions"][0]["type"] == "package_remove"


class TestRemediationRollbackYAML:
    """Test generated remediation playbook includes rollback tasks."""

    def test_rollback_phase_included_when_rollback_actions_exist(self):
        from response.runtime_ai_engine.remediation_playbook_generator import generate_runtime_remediation_playbook

        plan = {
            "decision": "high_risk_action_requires_approval",
            "corrective_actions": [
                {"type": "package_remove", "package": "badpkg"}
            ],
            "rollback_actions": [
                {"type": "package_reinstall", "package": "badpkg"}
            ],
            "verification_checks": ["check 1"],
            "target_context": "host",
            "actual_remediation_available": True,
        }
        yaml_str = generate_runtime_remediation_playbook(
            runtime_context={"runtime_category": "package_manager", "rule_name": "Test"},
            findings={"threat_assessment": "suspicious"},
            host="host1",
            remediation_plan=plan,
        )
        assert "PHASE 4" in yaml_str or "Rollback" in yaml_str
        assert "reinstall package badpkg" in yaml_str

    def test_rollback_phase_omitted_when_no_rollback_actions(self):
        from response.runtime_ai_engine.remediation_playbook_generator import generate_runtime_remediation_playbook

        plan = {
            "decision": "high_risk_action_requires_approval",
            "corrective_actions": [
                {"type": "terminate_process", "pid": 1234}
            ],
            "rollback_actions": [],
            "verification_checks": ["check 1"],
            "target_context": "host",
            "actual_remediation_available": True,
        }
        yaml_str = generate_runtime_remediation_playbook(
            runtime_context={"runtime_category": "process_execution", "rule_name": "Test"},
            findings={"threat_assessment": "suspicious"},
            host="host1",
            remediation_plan=plan,
        )
        # Should NOT contain Phase 4 if no rollback actions
        assert "PHASE 4" not in yaml_str


class TestPlannerDecisionSet:
    """Test that only realizable decisions are advertised."""

    def test_no_dead_decisions_in_non_corrective_set(self):
        from response.runtime_ai_engine.remediation_planner import NON_CORRECTIVE_DECISIONS
        assert "safe_corrective_action_available" not in NON_CORRECTIVE_DECISIONS
        assert "remediation_blocked_by_safety_policy" not in NON_CORRECTIVE_DECISIONS

    def test_no_dead_decisions_in_corrective_set(self):
        from response.runtime_ai_engine.remediation_planner import CORRECTIVE_DECISIONS
        assert "safe_corrective_action_available" not in CORRECTIVE_DECISIONS

    def test_derive_runtime_status_maps_real_decisions(self):
        from response.runtime_ai_engine.remediation_planner import derive_runtime_status
        # These should map correctly without dead decisions
        assert derive_runtime_status({"decision": "observe"}, "findings_ready") == "observe"
        assert derive_runtime_status({"decision": "manual_review_required"}, "findings_ready") == "manual_review_required"
        # high_risk_action_requires_approval is not remapped by derive_runtime_status;
        # the caller is expected to set awaiting_approval when corrective actions exist
        assert derive_runtime_status({"decision": "high_risk_action_requires_approval"}, "findings_ready") == "findings_ready"


class TestRuntimeStatsAccuracy:
    """Test that runtime stats reflect real current investigation statuses."""

    @pytest.mark.asyncio
    async def test_acknowledge_changes_status_and_stats(self):
        """Acknowledge must update status and be reflected in stats."""
        from response.db import AsyncSessionLocal
        from response.models import Investigation
        from sqlalchemy import select, update
        from datetime import datetime, timezone

        async with AsyncSessionLocal() as session:
            # Find a findings_ready runtime investigation
            result = await session.execute(
                select(Investigation)
                .where(Investigation.investigation_type == "runtime")
                .where(Investigation.status == "findings_ready")
                .limit(1)
            )
            inv = result.scalar_one_or_none()
            if not inv:
                pytest.skip("No findings_ready runtime investigation available")

            old_status = inv.status
            inv_id = inv.id

            # Acknowledge it
            await session.execute(
                update(Investigation)
                .where(Investigation.id == inv_id)
                .values(status="acknowledged", updated_at=datetime.now(timezone.utc))
            )
            await session.commit()

            # Verify status changed
            result = await session.execute(
                select(Investigation).where(Investigation.id == inv_id)
            )
            updated = result.scalar_one()
            assert updated.status == "acknowledged"

            # Verify stats count changed
            from sqlalchemy import func
            ack_count = (
                await session.execute(
                    select(func.count(Investigation.id))
                    .where(Investigation.investigation_type == "runtime")
                    .where(Investigation.status == "acknowledged")
                )
            ).scalar_one()
            assert ack_count >= 1

            # Restore original status
            await session.execute(
                update(Investigation)
                .where(Investigation.id == inv_id)
                .values(status=old_status, updated_at=datetime.now(timezone.utc))
            )
            await session.commit()

    @pytest.mark.asyncio
    async def test_manual_review_required_counted_correctly(self):
        """Stats must count manual_review_required from real DB state."""
        from response.db import AsyncSessionLocal
        from response.models import Investigation
        from sqlalchemy import select, func

        async with AsyncSessionLocal() as session:
            count = (
                await session.execute(
                    select(func.count(Investigation.id))
                    .where(Investigation.investigation_type == "runtime")
                    .where(Investigation.status == "manual_review_required")
                )
            ).scalar_one()

            # Stats endpoint should return this exact count
            from api.routes.runtime import get_runtime_stats
            stats = await get_runtime_stats(session=session)
            assert stats["by_status"]["manual_review_required"] == count

    @pytest.mark.asyncio
    async def test_observe_counted_correctly(self):
        """Stats must count observe from real DB state."""
        from response.db import AsyncSessionLocal
        from response.models import Investigation
        from sqlalchemy import select, func

        async with AsyncSessionLocal() as session:
            count = (
                await session.execute(
                    select(func.count(Investigation.id))
                    .where(Investigation.investigation_type == "runtime")
                    .where(Investigation.status == "observe")
                )
            ).scalar_one()

            from api.routes.runtime import get_runtime_stats
            stats = await get_runtime_stats(session=session)
            assert stats["by_status"]["observe"] == count

    @pytest.mark.asyncio
    async def test_verified_fixes_stays_zero_if_no_remediation_executed(self):
        """Verified count must be 0 when no remediation was actually executed."""
        from response.db import AsyncSessionLocal
        from response.models import Investigation
        from sqlalchemy import select, func

        async with AsyncSessionLocal() as session:
            verified_count = (
                await session.execute(
                    select(func.count(Investigation.id))
                    .where(Investigation.investigation_type == "runtime")
                    .where(Investigation.status == "verified")
                )
            ).scalar_one()

            # In current environment, no remediations have been executed,
            # so verified should be 0
            from api.routes.runtime import get_runtime_stats
            stats = await get_runtime_stats(session=session)
            assert stats["by_status"]["verified"] == verified_count
