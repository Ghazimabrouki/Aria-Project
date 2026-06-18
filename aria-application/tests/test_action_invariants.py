"""
Action contract invariant tests for ARIA.

These tests assert the exact action contract for admin_actions and analyst_actions
across all investigation statuses. The backend is the single source of truth;
frontend must render buttons strictly from these lists.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from api.routes.investigations import _compute_admin_actions, _compute_analyst_actions

SAFE_PLAYBOOK = """---
- hosts: target
  tasks:
    - ansible.builtin.iptables:
        chain: INPUT
        source: 1.2.3.4
        jump: DROP
"""

ROLLBACK_PLAYBOOK = """---
- hosts: target
  tasks:
    - ansible.builtin.iptables:
        chain: INPUT
        source: 1.2.3.4
        jump: DROP
        state: absent
"""


def _make_inv(status: str, playbook: str = "", rollback: str = ""):
    inv = MagicMock()
    inv.status = status
    inv.playbook_yaml = playbook
    inv.rollback_playbook = rollback
    return inv


class TestAwaitingApprovalActions:
    def test_awaiting_approval_admin_actions_no_execute_no_rollback(self):
        inv = _make_inv("awaiting_approval", playbook=SAFE_PLAYBOOK, rollback=ROLLBACK_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "admin_can_soft_override": False, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert "execute" not in actions
        assert "rollback" not in actions
        assert "decline" in actions
        assert "request_regeneration" in actions
        assert "mark_reviewed" in actions

    def test_awaiting_approval_analyst_actions_no_execute(self):
        inv = _make_inv("awaiting_approval", playbook=SAFE_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "is_safe_to_display": True}
        actions = _compute_analyst_actions(inv, safety)
        assert "approve" in actions
        assert "execute" not in actions
        assert "rollback" not in actions


class TestApprovedActions:
    def test_approved_admin_actions_include_execute_no_decision_approve(self):
        inv = _make_inv("approved", playbook=SAFE_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "admin_can_soft_override": False, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert "execute" in actions
        assert "archive" in actions
        assert "admin_decision_approve" not in actions
        assert "rollback" not in actions

    def test_approved_analyst_actions_include_execute(self):
        inv = _make_inv("approved", playbook=SAFE_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "is_safe_to_display": True}
        actions = _compute_analyst_actions(inv, safety)
        assert "execute" in actions
        assert "approve" not in actions


class TestRunningActions:
    def test_running_admin_actions_empty(self):
        inv = _make_inv("running", playbook=SAFE_PLAYBOOK, rollback=ROLLBACK_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "admin_can_soft_override": False, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert actions == []

    def test_running_analyst_actions_empty(self):
        inv = _make_inv("running", playbook=SAFE_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "is_safe_to_display": True}
        actions = _compute_analyst_actions(inv, safety)
        assert actions == []


class TestCompletedActions:
    def test_completed_with_rollback_playbook_includes_rollback(self):
        inv = _make_inv("completed", playbook=SAFE_PLAYBOOK, rollback=ROLLBACK_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "admin_can_soft_override": False, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert "rollback" in actions
        assert "archive" in actions
        assert "admin_decision_approve" not in actions
        assert "execute" not in actions

    def test_completed_without_rollback_playbook_hides_rollback(self):
        inv = _make_inv("completed", playbook=SAFE_PLAYBOOK, rollback="")
        safety = {"safety_tier": "safe", "is_executable": True, "admin_can_soft_override": False, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert "rollback" not in actions
        assert "archive" in actions

    def test_completed_analyst_actions_only_archive(self):
        inv = _make_inv("completed", playbook=SAFE_PLAYBOOK, rollback=ROLLBACK_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "is_safe_to_display": True}
        actions = _compute_analyst_actions(inv, safety)
        assert "archive" in actions


class TestFailedActions:
    def test_failed_with_rollback_playbook_includes_rollback(self):
        inv = _make_inv("failed", playbook=SAFE_PLAYBOOK, rollback=ROLLBACK_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "admin_can_soft_override": False, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert "rollback" in actions
        assert "archive" in actions
        assert "request_regeneration" in actions
        assert "admin_decision_approve" not in actions
        assert "execute" not in actions

    def test_failed_analyst_actions_no_approve(self):
        inv = _make_inv("failed", playbook=SAFE_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "is_safe_to_display": True}
        actions = _compute_analyst_actions(inv, safety)
        assert "approve" not in actions
        assert "execute" not in actions
        assert "archive" in actions
        assert "request_regeneration" in actions


class TestArchivedActions:
    def test_archived_admin_actions_empty(self):
        inv = _make_inv("archived", playbook=SAFE_PLAYBOOK, rollback=ROLLBACK_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "admin_can_soft_override": False, "is_safe_to_display": True}
        actions = _compute_admin_actions(inv, safety)
        assert actions == []

    def test_archived_analyst_actions_empty(self):
        inv = _make_inv("archived", playbook=SAFE_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "is_safe_to_display": True}
        actions = _compute_analyst_actions(inv, safety)
        assert actions == []


class TestFrontendRenderingContract:
    def test_frontend_rollback_button_derives_from_admin_actions(self):
        """Frontend must NOT hardcode rollback visibility; it must use admin_actions."""
        inv = _make_inv("completed", playbook=SAFE_PLAYBOOK, rollback=ROLLBACK_PLAYBOOK)
        safety = {"safety_tier": "safe", "is_executable": True, "admin_can_soft_override": False, "is_safe_to_display": True}
        admin_actions = _compute_admin_actions(inv, safety)
        analyst_actions = _compute_analyst_actions(inv, safety)

        # Rollback visible only when backend includes it in admin_actions
        assert "rollback" in admin_actions
        pass  # rollback available when rollback playbook exists

        # Before execution, rollback must not appear
        inv_before = _make_inv("awaiting_approval", playbook=SAFE_PLAYBOOK, rollback=ROLLBACK_PLAYBOOK)
        admin_before = _compute_admin_actions(inv_before, safety)
        assert "rollback" not in admin_before
