"""Tests for auto-approve guardrail blocking manual_review_required status."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from response.auto_approve import _check_guardrails, GuardrailResult
from response.models import Investigation


def test_manual_review_required_blocks_auto_approve():
    """Investigations with manual_review_required status must never be auto-approved."""
    inv = MagicMock(spec=Investigation)
    inv.status = "manual_review_required"
    inv.ai_summary = "Some summary"
    inv.incident_title = "Test"

    result = _check_guardrails("medium", 30, "port_scan", investigation=inv)
    assert result.should_block is True
    assert result.reason == "manual_review_required_blocked"


def test_awaiting_approval_does_not_block():
    """Normal awaiting_approval status should pass guardrails."""
    inv = MagicMock(spec=Investigation)
    inv.status = "awaiting_approval"
    inv.ai_summary = "Some summary"
    inv.incident_title = "Test"

    result = _check_guardrails("low", 10, "port_scan", investigation=inv)
    assert result.should_block is False
