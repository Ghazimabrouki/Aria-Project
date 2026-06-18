"""Tests for workflow_summary evidence_collection stage fix."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from response.workflow_summary import _stage
from response.models import Investigation, InvestigationAlert


def test_evidence_collection_completed_with_alerts_and_ai_summary():
    """If alerts exist and AI summary is present, evidence_collection should be completed."""
    inv = MagicMock(spec=Investigation)
    inv.created_at = datetime.now(timezone.utc)
    inv.updated_at = datetime.now(timezone.utc)
    inv.evidence_json = None
    inv.diagnostic_output = None
    inv.diagnostic_started_at = None
    inv.diagnostic_finished_at = None
    inv.run = None
    inv.alerts = [MagicMock(spec=InvestigationAlert)]
    inv.ai_summary = "AI analyzed the incident."

    stage = _stage("evidence_collection", inv)
    assert stage["status"] == "completed"


def test_evidence_collection_pending_without_alerts_or_ai():
    """Without alerts or AI summary, evidence_collection should be pending."""
    inv = MagicMock(spec=Investigation)
    inv.created_at = datetime.now(timezone.utc)
    inv.updated_at = datetime.now(timezone.utc)
    inv.evidence_json = None
    inv.diagnostic_output = None
    inv.diagnostic_started_at = None
    inv.diagnostic_finished_at = None
    inv.run = None
    inv.alerts = []
    inv.ai_summary = None

    stage = _stage("evidence_collection", inv)
    assert stage["status"] == "pending"


def test_evidence_collection_completed_with_evidence_json():
    """Staged evidence_json should still mark as completed."""
    inv = MagicMock(spec=Investigation)
    inv.created_at = datetime.now(timezone.utc)
    inv.updated_at = datetime.now(timezone.utc)
    inv.evidence_json = {"collected_at": "2024-01-01T00:00:00Z"}
    inv.diagnostic_output = None
    inv.diagnostic_started_at = None
    inv.diagnostic_finished_at = None
    inv.run = None
    inv.alerts = []
    inv.ai_summary = None

    stage = _stage("evidence_collection", inv)
    assert stage["status"] == "completed"
