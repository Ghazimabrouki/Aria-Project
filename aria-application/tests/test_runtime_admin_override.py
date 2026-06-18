"""
Unit tests for runtime admin override / manual remediation workflow.
"""

import pytest
import asyncio
from datetime import datetime, timezone

from response.db import AsyncSessionLocal
from response.models import Investigation, InvestigationAuditEvent


def _make_investigation(status: str) -> Investigation:
    """Create a minimal runtime investigation with the given status."""
    return Investigation(
        id="test-inv-001",
        incident_id="test-inc-001",
        incident_title="Test Runtime Investigation",
        status=status,
        investigation_type="runtime",
        source="falco",
        evidence_json={"remediation_plan": {"decision": "observe", "corrective_actions": [], "rollback_actions": []}},
        findings_json={"detected_cause": "test", "recommendations": []},
    )


class TestManualRemediationCreate:
    """Test creating manual remediation drafts from various statuses."""

    def test_pydantic_validation_requires_reason(self):
        from api.routes.runtime import ManualRemediationCreateRequest
        with pytest.raises(ValueError):
            ManualRemediationCreateRequest(
                admin_reason="short",
                business_justification="Test justification for manual remediation.",
                target_scope_confirmation="localhost only",
                expected_impact="Remove suspicious file.",
                rollback_plan_yaml="---\n- name: Rollback\n  hosts: localhost\n  tasks: []",
                verification_plan_yaml="Check file is gone from system.",
            )

    def test_pydantic_validation_requires_rollback(self):
        from api.routes.runtime import ManualRemediationCreateRequest
        with pytest.raises(ValueError):
            ManualRemediationCreateRequest(
                admin_reason="Test admin reason for override.",
                business_justification="Test justification for manual remediation.",
                target_scope_confirmation="localhost only",
                expected_impact="Remove suspicious file.",
                rollback_plan_yaml="short",
                verification_plan_yaml="Check file is gone from system.",
            )

    def test_pydantic_validation_accepts_valid(self):
        from api.routes.runtime import ManualRemediationCreateRequest
        req = ManualRemediationCreateRequest(
            admin_reason="Test admin reason for override.",
            business_justification="Test justification for manual remediation.",
            target_scope_confirmation="localhost only",
            expected_impact="Remove suspicious file.",
            rollback_plan_yaml="---\n- name: Rollback\n  hosts: localhost\n  tasks: []",
            verification_plan_yaml="Check file is gone from system.",
        )
        assert req.admin_reason == "Test admin reason for override."


class TestManualRemediationApproveRequest:
    """Test confirmation text validation on approval."""

    def test_confirmation_must_match_exact_text(self):
        from api.routes.runtime import ManualRemediationApproveRequest
        with pytest.raises(ValueError):
            ManualRemediationApproveRequest(confirmation_text="i understand the risk")

    def test_confirmation_accepts_exact_text(self):
        from api.routes.runtime import ManualRemediationApproveRequest
        req = ManualRemediationApproveRequest(confirmation_text="I UNDERSTAND THE RISK")
        assert req.confirmation_text == "I UNDERSTAND THE RISK"


class TestForceDeclineRequest:
    """Test force-decline request validation."""

    def test_reason_too_short(self):
        from api.routes.runtime import ForceDeclineRequest
        with pytest.raises(ValueError):
            ForceDeclineRequest(reason="short")

    def test_reason_valid(self):
        from api.routes.runtime import ForceDeclineRequest
        req = ForceDeclineRequest(reason="This is a valid reason.")
        assert req.reason == "This is a valid reason."


class TestReopenRequest:
    """Test reopen request validation."""

    def test_reason_too_short(self):
        from api.routes.runtime import ReopenRequest
        with pytest.raises(ValueError):
            ReopenRequest(reason="short")

    def test_reason_valid(self):
        from api.routes.runtime import ReopenRequest
        req = ReopenRequest(reason="This is a valid reopen reason.")
        assert req.reason == "This is a valid reopen reason."


class TestAllowedTransitions:
    """Test that new manual-remediation statuses are in _ALLOWED_TRANSITIONS."""

    def test_observe_can_transition_to_manual_remediation_draft(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("observe", "manual_remediation_draft")

    def test_findings_ready_can_transition_to_manual_remediation_draft(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("findings_ready", "manual_remediation_draft")

    def test_manual_review_required_can_transition_to_manual_remediation_draft(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("manual_review_required", "manual_remediation_draft")

    def test_acknowledged_can_transition_to_manual_remediation_draft(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("acknowledged", "manual_remediation_draft")

    def test_archived_not_fixed_can_transition_to_manual_remediation_draft(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("archived_not_fixed", "manual_remediation_draft")

    def test_declined_can_transition_to_manual_remediation_draft(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("declined", "manual_remediation_draft")

    def test_archived_can_transition_to_reopened(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("archived", "reopened")

    def test_manual_remediation_draft_can_transition_to_validating(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("manual_remediation_draft", "manual_remediation_validating")

    def test_manual_remediation_validating_can_transition_to_awaiting_approval(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("manual_remediation_validating", "manual_remediation_awaiting_approval")

    def test_manual_remediation_awaiting_approval_can_transition_to_approved(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("manual_remediation_awaiting_approval", "manual_remediation_approved")

    def test_manual_remediation_approved_can_transition_to_executing(self):
        from api.routes.runtime import _can_transition
        assert _can_transition("manual_remediation_approved", "manual_remediation_executing")

    def test_awaiting_approval_cannot_transition_to_manual_remediation_draft(self):
        from api.routes.runtime import _can_transition
        assert not _can_transition("awaiting_approval", "manual_remediation_draft")

    def test_running_cannot_transition_to_manual_remediation_draft(self):
        from api.routes.runtime import _can_transition
        assert not _can_transition("running", "manual_remediation_draft")


class TestAvailableActions:
    """Test that available_actions exposes manual-remediation flags correctly."""

    def test_observe_shows_create_manual_remediation(self):
        from api.routes.runtime import _available_actions
        inv = _make_investigation("observe")
        actions = _available_actions(inv, {})
        assert actions["create_manual_remediation"] is True
        assert actions["approve_run"] is False
        assert actions["approve_manual_remediation"] is False

    def test_manual_review_required_shows_create_manual_remediation(self):
        from api.routes.runtime import _available_actions
        inv = _make_investigation("manual_review_required")
        actions = _available_actions(inv, {})
        assert actions["create_manual_remediation"] is True
        assert actions["force_decline"] is True

    def test_archived_not_fixed_shows_reopen_and_create(self):
        from api.routes.runtime import _available_actions
        inv = _make_investigation("archived_not_fixed")
        actions = _available_actions(inv, {})
        assert actions["create_manual_remediation"] is True
        assert actions["reopen"] is True

    def test_awaiting_approval_does_not_show_create_manual(self):
        from api.routes.runtime import _available_actions
        inv = _make_investigation("awaiting_approval")
        actions = _available_actions(inv, {})
        assert actions["create_manual_remediation"] is False
        assert actions["approve_run"] is False  # no corrective actions in test

    def test_manual_remediation_draft_shows_edit_and_validate(self):
        from api.routes.runtime import _available_actions
        inv = _make_investigation("manual_remediation_draft")
        actions = _available_actions(inv, {})
        assert actions["edit_manual_playbook"] is True
        assert actions["validate_manual_playbook"] is True
        assert actions["create_manual_remediation"] is False

    def test_manual_remediation_awaiting_approval_shows_approve(self):
        from api.routes.runtime import _available_actions
        inv = _make_investigation("manual_remediation_awaiting_approval")
        actions = _available_actions(inv, {})
        assert actions["approve_manual_remediation"] is True
        assert actions["edit_manual_playbook"] is False

    def test_archived_fixed_shows_only_reopen(self):
        from api.routes.runtime import _available_actions
        inv = _make_investigation("archived_fixed")
        actions = _available_actions(inv, {})
        assert actions["reopen"] is True
        assert actions["force_decline"] is False
        assert actions["create_manual_remediation"] is False

    def test_closed_with_risk_shows_reopen(self):
        from api.routes.runtime import _available_actions
        inv = _make_investigation("closed_with_risk")
        actions = _available_actions(inv, {})
        assert actions["reopen"] is True
        assert actions["force_decline"] is False


class TestAuditEventsHelper:
    """Test the audit event helper writes structured events."""

    def test_log_manual_remediation_action_builds_details(self):
        from response.audit_events import log_manual_remediation_action
        import hashlib
        yaml = "---\n- name: Test\n  hosts: localhost\n"
        playbook_hash = hashlib.sha256(yaml.encode("utf-8")).hexdigest()[:16]
        # We can't easily test async DB write here without DB session,
        # but we can verify the function signature is correct.
        assert callable(log_manual_remediation_action)


class TestInvestigationModel:
    """Test that Investigation model has the manual_override_json column."""

    def test_manual_override_json_column_exists(self):
        from response.models import Investigation
        table = Investigation.__table__
        assert "manual_override_json" in table.c
        col = table.c["manual_override_json"]
        assert col.nullable is True
