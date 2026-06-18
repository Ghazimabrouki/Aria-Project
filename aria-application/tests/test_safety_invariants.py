"""
Safety invariant tests for ARIA.

These tests assert non-negotiable safety properties that must hold
for ALL investigations regardless of context.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from response.playbook_safety import compute_investigation_safety, validate_playbook_safety
from api.routes.investigations import _compute_admin_actions, _compute_analyst_actions


class TestSoftBlockInvariants:
    def test_soft_block_cannot_execute_without_valid_override(self):
        inv = MagicMock()
        inv.status = "awaiting_approval"
        inv.playbook_yaml = "---\n- hosts: target\n  tasks:\n    - shell: apt upgrade -y"
        inv.rollback_playbook = "---\n- hosts: target\n  tasks:\n    - shell: echo rollback"
        inv.ai_summary = "test"
        inv.ai_quality_status = "passed"
        inv.investigation_type = "security"
        inv.target_host = ""
        inv.approval = None
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        assert safety["is_executable"] is False
        admin_actions = _compute_admin_actions(inv, safety)
        assert "execute" not in admin_actions

    def test_soft_block_with_override_allows_execute(self):
        inv = MagicMock()
        inv.status = "approved"
        inv.playbook_yaml = "---\n- hosts: target\n  tasks:\n    - shell: apt upgrade -y"
        inv.rollback_playbook = "---\n- hosts: target\n  tasks:\n    - shell: echo rollback"
        inv.ai_summary = "test"
        inv.ai_quality_status = "passed"
        inv.investigation_type = "security"
        inv.target_host = ""
        approval = MagicMock()
        approval.decision = "approved"
        approval.override = True
        approval.override_by = "admin"
        approval.override_reason = "verified safe"
        inv.approval = approval
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        admin_actions = _compute_admin_actions(inv, safety)
        assert "execute" in admin_actions


class TestDiagnosticOnlyInvariants:
    def test_diagnostic_only_never_exposes_approve_or_execute(self):
        inv = MagicMock()
        inv.status = "awaiting_approval"
        inv.playbook_yaml = "---\n- hosts: target\n  tasks:\n    - shell: grep failed /var/log/auth.log\n      changed_when: false"
        inv.rollback_playbook = ""
        inv.ai_summary = "test"
        inv.ai_quality_status = "passed"
        inv.investigation_type = "security"
        inv.target_host = ""
        inv.approval = None
        safety = compute_investigation_safety(inv)
        assert safety["execution_mode"] == "diagnostic_only"
        analyst_actions = _compute_analyst_actions(inv, safety)
        assert "approve" not in analyst_actions
        assert "execute" not in analyst_actions
