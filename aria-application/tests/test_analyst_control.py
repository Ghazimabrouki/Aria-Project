"""
Tests for analyst control features: truth reports, new analyst actions,
audit events, and status transitions.
"""

import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import delete

from response.db import AsyncSessionLocal
from response.models import (
    Investigation,
    InvestigationAlert,
    InvestigationAuditEvent,
    PlaybookApproval,
    PlaybookRun,
)


@pytest.fixture(autouse=True)
async def _clean_analyst_control_rows():
    yield
    async with AsyncSessionLocal() as session:
        await session.execute(delete(InvestigationAuditEvent).where(InvestigationAuditEvent.investigation_id.like("analyst-ctrl-%")))
        await session.execute(delete(PlaybookRun).where(PlaybookRun.investigation_id.like("analyst-ctrl-%")))
        await session.execute(delete(PlaybookApproval).where(PlaybookApproval.investigation_id.like("analyst-ctrl-%")))
        await session.execute(delete(InvestigationAlert).where(InvestigationAlert.investigation_id.like("analyst-ctrl-%")))
        await session.execute(delete(Investigation).where(Investigation.id.like("analyst-ctrl-%")))
        await session.commit()


# ── Truth Report Tests ────────────────────────────────────────────────────────


def test_truth_report_populated_from_ai_quality():
    from api.routes.investigations import _build_truth_report

    inv = Investigation(
        id="analyst-ctrl-truth-1",
        incident_id="inc-1",
        incident_title="SSH brute force",
        incident_severity="high",
        status="awaiting_approval",
        ai_summary="SSH brute-force attack detected. No successful login observed. No compromise.",
        playbook_yaml="shell: iptables -A INPUT -s '1.2.3.4' -j DROP",
        ai_quality_status="passed",
        ai_quality_json={
            "grounding": {"status": "passed", "reasons": []},
            "quality": {"scores": {"summary": 0.9, "playbook": 0.85}},
        },
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    report = _build_truth_report(inv)
    assert report["final_classification"] == "suspected_threat"
    assert report["confidence"] == "high"
    assert report["evidence_quality"] == "passed"
    assert any("No successful authentication" in f for f in report["observed_facts"])
    assert any("block exact source ip" in s.lower() for s in report["recommended_next_steps"])


def test_truth_report_with_weak_quality():
    from api.routes.investigations import _build_truth_report

    inv = Investigation(
        id="analyst-ctrl-truth-2",
        incident_id="inc-2",
        incident_title="Malware alert",
        incident_severity="critical",
        status="awaiting_approval",
        ai_summary="Possible malware infection detected on host.",
        playbook_yaml="",
        ai_quality_status="weak",
        ai_quality_json={
            "grounding": {"status": "weak", "reasons": ["Unsupported claim: lateral movement without evidence"]},
            "quality": {"scores": {"summary": 0.4}},
        },
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    report = _build_truth_report(inv)
    assert report["confidence"] == "low"
    assert report["evidence_quality"] == "weak"
    assert any("Unsupported claim" in c for c in report["unsupported_claims"])
    assert any("manual action required" in s.lower() for s in report["recommended_next_steps"])


# ── Analyst Actions Tests ─────────────────────────────────────────────────────


def test_analyst_actions_for_awaiting_approval_include_all():
    from api.routes.investigations import _compute_analyst_actions

    inv = Investigation(
        id="analyst-ctrl-actions-1",
        incident_id="inc-1",
        incident_title="Test",
        status="awaiting_approval",
        playbook_yaml="tasks: []",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    safety = {"is_executable": True, "has_remediation_action": True}
    actions = _compute_analyst_actions(inv, safety)
    assert "approve" in actions
    assert "decline" in actions
    assert "request_regeneration" in actions
    assert "mark_reviewed" in actions


def test_analyst_actions_for_completed_only_archive():
    from api.routes.investigations import _compute_analyst_actions

    inv = Investigation(
        id="analyst-ctrl-actions-2",
        incident_id="inc-1",
        incident_title="Test",
        status="completed",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    actions = _compute_analyst_actions(inv, {})
    assert actions == ["archive"]


def test_analyst_actions_for_manual_review_required():
    from api.routes.investigations import _compute_analyst_actions

    inv = Investigation(
        id="analyst-ctrl-actions-3",
        incident_id="inc-1",
        incident_title="Test",
        status="manual_review_required",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    actions = _compute_analyst_actions(inv, {})
    assert "request_regeneration" in actions
    assert "mark_reviewed" in actions
    assert "archive" in actions
    assert "approve" not in actions


# ── Status Transition Tests ───────────────────────────────────────────────────


def test_allowed_transitions_include_new_statuses():
    from api.routes.investigations import _ALLOWED_TRANSITIONS

    assert "regeneration_requested" in _ALLOWED_TRANSITIONS["awaiting_approval"]
    assert "reviewed_no_action" in _ALLOWED_TRANSITIONS["awaiting_approval"]
    assert "regeneration_requested" in _ALLOWED_TRANSITIONS["failed"]
    assert "regeneration_requested" in _ALLOWED_TRANSITIONS["declined"]
    assert "regeneration_requested" in _ALLOWED_TRANSITIONS["manual_review_required"]
    assert "reviewed_no_action" in _ALLOWED_TRANSITIONS["manual_review_required"]
    assert "pending" in _ALLOWED_TRANSITIONS["regeneration_requested"]
    assert "archived" in _ALLOWED_TRANSITIONS["reviewed_no_action"]


# ── API Endpoint Tests ────────────────────────────────────────────────────────


async def test_request_regeneration_from_awaiting_approval(mock_request):
    from api.routes.investigations import request_regeneration
    from response.db import get_session

    inv_id = "analyst-ctrl-regen-1"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id="inc-regen",
            incident_title="Regen test",
            incident_severity="high",
            status="awaiting_approval",
            ai_summary="Summary",
            playbook_yaml="tasks: []",
            playbook_valid=True,
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        from api.routes.investigations import RegenerateRequest
        result = await request_regeneration(inv_id, RegenerateRequest(decided_by="analyst", reason="Unsafe playbook"), mock_request, session=db_session)
        assert result["status"] == "regeneration_requested"
    finally:
        await gen.aclose()

    # Verify investigation was reset for regeneration
    async with AsyncSessionLocal() as session:
        from sqlalchemy import select
        result = await session.execute(select(Investigation).where(Investigation.id == inv_id))
        inv = result.scalar_one()
        # Status may have changed to failed/pending by background task, but fields should be cleared
        assert inv.ai_summary is None  # Cleared for regeneration
        assert inv.playbook_yaml is None


async def test_mark_reviewed_from_awaiting_approval(mock_request):
    from api.routes.investigations import mark_reviewed
    from response.db import get_session

    inv_id = "analyst-ctrl-reviewed-1"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id="inc-reviewed",
            incident_title="Reviewed test",
            incident_severity="medium",
            status="awaiting_approval",
            ai_summary="Summary",
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        from api.routes.investigations import MarkReviewedRequest
        result = await mark_reviewed(inv_id, MarkReviewedRequest(decided_by="analyst", reason="False positive"), mock_request, session=db_session)
        assert result["status"] == "reviewed_no_action"
    finally:
        await gen.aclose()


async def test_mark_reviewed_blocked_from_completed(mock_request):
    from api.routes.investigations import mark_reviewed
    from response.db import get_session
    from fastapi import HTTPException

    inv_id = "analyst-ctrl-reviewed-2"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id="inc-reviewed-2",
            incident_title="Completed test",
            incident_severity="medium",
            status="completed",
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        from api.routes.investigations import MarkReviewedRequest
        with pytest.raises(HTTPException) as exc_info:
            await mark_reviewed(inv_id, MarkReviewedRequest(decided_by="analyst"), mock_request, session=db_session)
        assert exc_info.value.status_code == 400
    finally:
        await gen.aclose()


# ── Audit Event Tests ─────────────────────────────────────────────────────────


async def test_audit_event_recorded_on_approve(mock_request):
    from api.routes.investigations import approve_investigation
    from response.db import get_session

    inv_id = "analyst-ctrl-audit-approve"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id="inc-audit",
            incident_title="Audit approve test",
            incident_severity="high",
            status="awaiting_approval",
            ai_summary="Valid summary with enough content for approval. SSH brute force from 1.2.3.4. No successful login.",
            playbook_yaml="---\n- hosts: target\n  tasks:\n    - name: Block IP\n      ansible.builtin.shell: iptables -A INPUT -s '1.2.3.4' -j DROP",
            playbook_valid=True,
            rollback_playbook="---\n- hosts: target\n  tasks:\n    - name: Rollback block\n      ansible.builtin.shell: iptables -D INPUT -s '1.2.3.4' -j DROP",
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        from api.routes.investigations import ApproveRequest
        await approve_investigation(inv_id, ApproveRequest(decided_by="test_analyst"), mock_request, session=db_session)
    finally:
        await gen.aclose()

    async with AsyncSessionLocal() as session:
        from sqlalchemy import select
        result = await session.execute(
            select(InvestigationAuditEvent).where(InvestigationAuditEvent.investigation_id == inv_id)
        )
        events = result.scalars().all()
        assert any(e.event_type == "approved" for e in events)
        assert any(e.actor == "test_analyst" for e in events)


async def test_audit_event_recorded_on_decline(mock_request):
    from api.routes.investigations import decline_investigation
    from response.db import get_session

    inv_id = "analyst-ctrl-audit-decline"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id="inc-audit-decline",
            incident_title="Audit decline test",
            incident_severity="high",
            status="awaiting_approval",
            ai_summary="Summary",
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        from api.routes.investigations import DeclineRequest
        await decline_investigation(inv_id, DeclineRequest(decided_by="test_analyst", reason="Too risky"), mock_request, session=db_session)
    finally:
        await gen.aclose()

    async with AsyncSessionLocal() as session:
        from sqlalchemy import select
        result = await session.execute(
            select(InvestigationAuditEvent).where(InvestigationAuditEvent.investigation_id == inv_id)
        )
        events = result.scalars().all()
        assert any(e.event_type == "declined" for e in events)
        assert any(e.details == "Too risky" for e in events)


async def test_timeline_includes_audit_events():
    from api.routes.investigations import get_investigation_timeline
    from response.db import get_session

    inv_id = "analyst-ctrl-timeline"
    async with AsyncSessionLocal() as session:
        inv = Investigation(
            id=inv_id,
            incident_id="inc-timeline",
            incident_title="Timeline test",
            incident_severity="high",
            status="awaiting_approval",
            ai_summary="Summary",
        )
        session.add(inv)
        session.add(InvestigationAuditEvent(
            investigation_id=inv_id,
            event_type="playbook_edited",
            actor="analyst",
            details="Fixed firewall syntax",
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        # Call timeline directly
        timeline = await get_investigation_timeline(inv_id, session=db_session)
        event_types = [e["event"] for e in timeline["events"]]
        assert "playbook_edited" in event_types
    finally:
        await gen.aclose()


async def test_archive_investigation_creates_audit_event(mock_request):
    from api.routes.investigations import archive_investigation_endpoint
    from response.db import get_session

    inv_id = "analyst-ctrl-audit-archive"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id="inc-archive",
            incident_title="Archive audit test",
            incident_severity="low",
            status="declined",
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        await archive_investigation_endpoint(inv_id, mock_request, session=db_session)
    finally:
        await gen.aclose()

    async with AsyncSessionLocal() as session:
        from sqlalchemy import select
        result = await session.execute(
            select(InvestigationAuditEvent).where(InvestigationAuditEvent.investigation_id == inv_id)
        )
        events = result.scalars().all()
        assert any(e.event_type == "archived" for e in events)
