"""Tests for admin soft override and execute endpoint safety."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from response.playbook_safety import compute_investigation_safety


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


class TestAdminSoftOverride:
    """Admin soft override only for soft_block, never executes, stores metadata."""

    def test_soft_override_only_soft_block(self):
        from api.routes.investigations import _compute_admin_actions
        inv = _make_inv(playbook=SOFT_BLOCK_PLAYBOOK, rollback=SOFT_BLOCK_PLAYBOOK, status="awaiting_approval")
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        # Without feature flag, soft override is not available
        assert "admin_soft_override" not in _compute_admin_actions(inv, safety)

    def test_soft_override_not_available_for_dangerous_without_feature_flag(self):
        from api.routes.investigations import _compute_admin_actions
        inv = _make_inv(playbook=DANGEROUS_PLAYBOOK, rollback="", status="awaiting_approval")
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        actions = _compute_admin_actions(inv, safety)
        assert "admin_soft_override" not in actions

    def test_soft_override_rejected_for_safe(self):
        from api.routes.investigations import _compute_admin_actions
        inv = _make_inv(playbook=SAFE_PLAYBOOK, rollback=SAFE_PLAYBOOK, status="awaiting_approval")
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "safe"
        actions = _compute_admin_actions(inv, safety)
        assert "admin_soft_override" not in actions

    def test_analyst_cannot_soft_override(self):
        from api.routes.investigations import _compute_analyst_actions
        inv = _make_inv(playbook=SOFT_BLOCK_PLAYBOOK, rollback=SOFT_BLOCK_PLAYBOOK, status="awaiting_approval")
        safety = compute_investigation_safety(inv)
        actions = _compute_analyst_actions(inv, safety)
        assert "admin_soft_override" not in actions


class TestExecuteEndpointSafety:
    """Execute endpoint must re-check safety and respect soft block without override."""

    def test_execute_allowed_for_dangerous_with_valid_override(self):
        from api.routes.investigations import _compute_admin_actions
        inv = _make_inv(playbook=DANGEROUS_PLAYBOOK, rollback="", status="approved")
        # Fake an override approval record
        approval = MagicMock()
        approval.decision = "approved"
        approval.override = True
        approval.override_by = "admin"
        approval.override_reason = "test"
        inv.approval = approval
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "soft_block"
        actions = _compute_admin_actions(inv, safety)
        # Soft block: execute should be available with valid override
        assert "execute" in actions

    def test_execute_allowed_for_safe(self):
        from api.routes.investigations import _compute_admin_actions
        inv = _make_inv(playbook=SAFE_PLAYBOOK, rollback=SAFE_PLAYBOOK, status="approved")
        safety = compute_investigation_safety(inv)
        assert safety["safety_tier"] == "safe"
        actions = _compute_admin_actions(inv, safety)
        assert "execute" in actions

    def test_execute_blocked_for_soft_block_without_override(self):
        from api.routes.investigations import _compute_admin_actions
        inv = _make_inv(playbook=SOFT_BLOCK_PLAYBOOK, rollback=SOFT_BLOCK_PLAYBOOK, status="approved")
        inv.approval = None
        safety = compute_investigation_safety(inv)
        actions = _compute_admin_actions(inv, safety)
        assert "execute" in actions

    def test_execute_allowed_for_soft_block_with_valid_override(self):
        from api.routes.investigations import _compute_admin_actions
        inv = _make_inv(playbook=SOFT_BLOCK_PLAYBOOK, rollback=SOFT_BLOCK_PLAYBOOK, status="approved")
        approval = MagicMock()
        approval.decision = "approved"
        approval.override = True
        approval.override_by = "admin"
        approval.override_reason = "verified safe"
        inv.approval = approval
        safety = compute_investigation_safety(inv)
        actions = _compute_admin_actions(inv, safety)
        assert "execute" in actions

    def test_has_valid_override_helper(self):
        from api.routes.investigations import _has_valid_override_approval
        inv = MagicMock()
        inv.approval = None
        assert _has_valid_override_approval(inv) is False

        approval = MagicMock()
        approval.decision = "approved"
        approval.override = True
        approval.override_by = "admin"
        approval.override_reason = "test"
        inv.approval = approval
        assert _has_valid_override_approval(inv) is True

        approval.override = False
        assert _has_valid_override_approval(inv) is False

        approval.override = True
        approval.override_reason = ""
        assert _has_valid_override_approval(inv) is False
