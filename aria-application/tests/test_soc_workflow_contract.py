"""Focused tests for SOC workflow contracts."""

import json
import uuid
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import delete

from response.db import AsyncSessionLocal
from response.models import (
    Alert,
    AlertIncidentLink,
    FixVerification,
    Incident,
    Investigation,
    InvestigationAlert,
    PlaybookApproval,
    PlaybookRun,
)


@pytest.fixture(autouse=True)
async def _clean_soc_contract_rows():
    yield
    async with AsyncSessionLocal() as session:
        await session.execute(delete(FixVerification).where(FixVerification.investigation_id.like("soc-contract-%")))
        await session.execute(delete(PlaybookRun).where(PlaybookRun.investigation_id.like("soc-contract-%")))
        await session.execute(delete(PlaybookApproval).where(PlaybookApproval.investigation_id.like("soc-contract-%")))
        await session.execute(delete(InvestigationAlert).where(InvestigationAlert.investigation_id.like("soc-contract-%")))
        await session.execute(delete(AlertIncidentLink).where(AlertIncidentLink.incident_id.like("soc-contract-%")))
        await session.execute(delete(Investigation).where(Investigation.incident_id.like("soc-contract-%")))
        await session.execute(delete(Investigation).where(Investigation.id.like("soc-contract-%")))
        await session.execute(delete(Incident).where(Incident.id.like("soc-contract-%")))
        await session.execute(delete(Alert).where(Alert.source == "soc_contract"))
        await session.commit()


def test_workflow_summary_exposes_complete_stage_chain():
    from response.workflow_summary import build_workflow_summary

    now = datetime.now(timezone.utc)
    inv = Investigation(
        id=str(uuid.uuid4()),
        incident_id="soc-contract-incident",
        incident_title="SSH brute force",
        incident_severity="high",
        status="awaiting_approval",
        ai_summary="Repeated SSH authentication failures from 1.2.3.4.",
        playbook_yaml="---\n- name: Test\n  hosts: target\n  tasks: []\n",
        playbook_valid=True,
        created_at=now,
        updated_at=now,
    )

    workflow = build_workflow_summary(inv)
    keys = [stage["key"] for stage in workflow["stages"]]

    assert keys == [
        "incident_selected",
        "evidence_collection",
        "ai_root_cause",
        "remediation_planning",
        "approval",
        "execution",
        "verification",
        "completed",
        "archived",
    ]
    assert workflow["current_stage"]["key"] == "approval"


def test_workflow_current_stage_matrix():
    from response.workflow_summary import build_workflow_summary

    now = datetime.now(timezone.utc)

    def make_inv(status: str, **kwargs):
        return Investigation(
            id=str(uuid.uuid4()),
            incident_id=f"soc-contract-{status}",
            incident_title="Matrix case",
            incident_severity="high",
            status=status,
            created_at=now,
            updated_at=now,
            **kwargs,
        )

    cases = [
        (make_inv("pending"), "ai_root_cause"),
        (make_inv("pending", evidence_json={"collected_at": now.isoformat()}), "ai_root_cause"),
        (make_inv("pending", ai_summary="Root cause found"), "remediation_planning"),
        (
            make_inv(
                "awaiting_approval",
                ai_summary="Root cause found",
                playbook_yaml="---\n- name: Fix\n  hosts: target\n  tasks: []\n",
            ),
            "approval",
        ),
        (
            make_inv(
                "approved",
                ai_summary="Root cause found",
                playbook_yaml="---\n- name: Fix\n  hosts: target\n  tasks: []\n",
            ),
            "execution",
        ),
        (
            make_inv("running", playbook_yaml="---\n- name: Fix\n  hosts: target\n  tasks: []\n"),
            "execution",
        ),
        (
            make_inv("completed", playbook_yaml="---\n- name: Fix\n  hosts: target\n  tasks: []\n"),
            "verification",
        ),
        (
            make_inv(
                "completed",
                playbook_yaml="---\n- name: Fix\n  hosts: target\n  tasks: []\n",
                verification=FixVerification(status="likely_fixed", new_alerts_found=0, detail="No new alerts"),
            ),
            "completed",
        ),
        (make_inv("archived"), "archived"),
        (make_inv("failed", ai_error="SSH failed"), "ai_root_cause"),
    ]

    for inv, expected_stage in cases:
        workflow = build_workflow_summary(inv)
        assert workflow["current_stage"]["key"] == expected_stage


def test_fallback_playbook_does_not_block_all_when_source_ip_missing():
    from response.ai_engine.main import _generate_fallback_ai_result

    result = _generate_fallback_ai_result({
        "incident": {"title": "Unknown source alert", "severity": "high"},
        "alerts": [],
        "source_ips": [],
        "dest_ips": ["10.0.0.5"],
        "hostnames": ["web1"],
        "mitre_tactics": [],
        "attack_type": "network_anomaly",
        "proof_of_compromise": {"compromised": False, "confidence": "low", "indicators": []},
        "all_iocs": {},
    })

    assert "0.0.0.0/0" not in result["playbook_yaml"]
    assert "Automated blocking is intentionally skipped" in result["playbook_yaml"]


def test_playbook_summary_explains_target_impact_and_verification():
    from response.workflow_summary import build_playbook_summary

    inv = Investigation(
        id=str(uuid.uuid4()),
        incident_id="soc-contract-summary",
        incident_title="SSH brute force",
        incident_severity="high",
        status="awaiting_approval",
        target_host="web1",
        ai_summary="Repeated SSH authentication failures require containment.",
        rollback_playbook="---\n- name: Rollback\n  hosts: target\n  tasks: []\n",
        playbook_yaml="""---
- name: Remediate SSH brute force
  hosts: target
  tasks:
    - name: Block attacker IP
      ansible.builtin.shell: "iptables -A INPUT -s 1.2.3.4 -j DROP"
    - name: Verify SSH service health
      ansible.builtin.shell: "systemctl status sshd"
""",
    )

    summary = build_playbook_summary(inv)

    assert summary is not None
    assert summary["target"] == "web1"
    assert summary["high_impact"] is True
    assert summary["rollback_possible"] is True
    assert "Block attacker IP" in summary["what_it_will_do"]
    assert "Verify SSH service health" in summary["verification_checks"]


async def test_investigation_detail_returns_alert_evidence_and_local_ids():
    from api.routes.investigations import get_investigation
    from response.db import get_session

    inv_id = "soc-contract-detail"
    local_incident_id = "soc-contract-local-nav"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id="upstream-123",
            local_incident_id=local_incident_id,
            upstream_incident_id="upstream-123",
            incident_title="Evidence detail",
            incident_severity="high",
            status="awaiting_approval",
            playbook_yaml="---\n- name: Fix\n  hosts: target\n  tasks: []\n",
            playbook_valid=True,
        ))
        session.add(InvestigationAlert(
            investigation_id=inv_id,
            alert_id="alert-123",
            severity="high",
            source="wazuh",
            title="SSH brute force",
            alert_json=json.dumps({
                "id": "alert-123",
                "title": "SSH brute force",
                "description": "Multiple failed SSH logins",
                "source_ip": "1.2.3.4",
                "dest_ip": "10.0.0.5",
                "hostname": "web1",
                "rule_name": "sshd brute force",
                "tags": ["mitre-tactic-credential-access"],
                "iocs": {"ips": ["1.2.3.4"]},
                "metadata": {"rule_id": "5712"},
            }),
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        detail = await get_investigation(inv_id, session=db_session)
        assert detail.local_incident_id == local_incident_id
        assert detail.upstream_incident_id == "upstream-123"
        assert detail.alerts[0].source_ip == "1.2.3.4"
        assert detail.alerts[0].dest_ip == "10.0.0.5"
        assert detail.alerts[0].hostname == "web1"
        assert detail.alerts[0].rule_name == "sshd brute force"
        assert detail.alerts[0].raw["metadata"]["rule_id"] == "5712"
    finally:
        await gen.aclose()


async def test_execute_endpoint_requires_approval_record(mock_request):
    from api.routes.investigations import ApproveRequest, execute_playbook_direct
    from response.db import get_session

    inv_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id="soc-contract-execute",
            incident_title="Unsafe direct execution",
            incident_severity="high",
            status="awaiting_approval",
            playbook_yaml="---\n- name: Test\n  hosts: target\n  tasks: []\n",
            playbook_valid=True,
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        with pytest.raises(HTTPException) as exc:
            await execute_playbook_direct(inv_id, ApproveRequest(decided_by="analyst"), mock_request, session=db_session)
        assert exc.value.status_code == 400
        assert "Approve the playbook first" in exc.value.detail
    finally:
        await gen.aclose()


async def test_execute_endpoint_allows_approved_status_without_approval_record(mock_request):
    """Execution is allowed for approved status — safety policy disabled."""
    from api.routes.investigations import ApproveRequest, execute_playbook_direct
    from response.db import get_session

    inv_id = "soc-contract-approved-no-record"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id=inv_id,
            incident_title="Approved without record",
            incident_severity="high",
            status="approved",
            playbook_yaml="---\n- name: Test\n  hosts: target\n  tasks: []\n",
            playbook_valid=True,
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        result = await execute_playbook_direct(inv_id, ApproveRequest(decided_by="analyst"), mock_request, session=db_session)
        assert result["investigation_id"] == inv_id
    finally:
        await gen.aclose()


async def test_likely_fixed_verification_keeps_investigation_completed():
    from response.fix_verifier import _save_verification

    inv_id = "soc-contract-likely-fixed"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id=inv_id,
            incident_title="Verification case",
            incident_severity="high",
            status="running",
        ))
        await session.commit()

    await _save_verification(inv_id, "likely_fixed", 0, "No recurring alerts")

    async with AsyncSessionLocal() as session:
        inv = await session.get(Investigation, inv_id)
        assert inv is not None
        assert inv.status == "completed"


def test_archived_stage_remains_final_lifecycle_step():
    from response.workflow_summary import build_workflow_summary

    now = datetime.now(timezone.utc)
    inv = Investigation(
        id=str(uuid.uuid4()),
        incident_id="soc-contract-archived-stage",
        incident_title="Archived case",
        incident_severity="medium",
        status="archived",
        created_at=now,
        updated_at=now,
    )

    workflow = build_workflow_summary(inv)
    assert workflow["stages"][-1]["key"] == "archived"
    assert workflow["stages"][-1]["status"] == "completed"
    assert workflow["current_stage"]["key"] == "archived"


async def test_incident_timeline_links_local_investigation_without_external_id():
    from api.routes.incidents import get_incident_timeline
    from response.db import get_session

    incident_id = "soc-contract-local-timeline"
    async with AsyncSessionLocal() as session:
        session.add(Incident(
            id=incident_id,
            title="Local correlated incident",
            description="Two related alerts",
            severity="high",
            status="open",
        ))
        session.add(Investigation(
            id=str(uuid.uuid4()),
            incident_id=incident_id,
            local_incident_id=incident_id,
            incident_title="Local correlated incident",
            incident_severity="high",
            status="awaiting_approval",
            ai_summary="Analysis complete.",
            playbook_yaml="---\n- name: Test\n  hosts: target\n  tasks: []\n",
            playbook_valid=True,
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        timeline = await get_incident_timeline(incident_id, session=db_session)
        event_types = {event["type"] for event in timeline["events"]}
        assert "investigation_started" in event_types
        assert "ai_analysis_complete" in event_types
    finally:
        await gen.aclose()


async def test_declined_investigation_cannot_execute(mock_request):
    from api.routes.investigations import ApproveRequest, execute_playbook_direct
    from response.db import get_session

    inv_id = "soc-contract-declined"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id=inv_id,
            incident_title="Declined case",
            incident_severity="high",
            status="declined",
            playbook_yaml="---\n- name: Test\n  hosts: target\n  tasks: []\n",
            playbook_valid=True,
        ))
        session.add(PlaybookApproval(
            investigation_id=inv_id,
            decision="declined",
            decided_by="analyst",
            decided_at=datetime.now(timezone.utc),
            reason="Too risky",
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        with pytest.raises(HTTPException) as exc:
            await execute_playbook_direct(inv_id, ApproveRequest(decided_by="analyst"), mock_request, session=db_session)
        assert exc.value.status_code == 400
        assert "Approve the playbook first" in exc.value.detail
    finally:
        await gen.aclose()


def test_not_fixed_verification_shows_failed_workflow_stage():
    from response.workflow_summary import build_workflow_summary

    now = datetime.now(timezone.utc)
    inv = Investigation(
        id=str(uuid.uuid4()),
        incident_id="soc-contract-not-fixed",
        incident_title="Not fixed case",
        incident_severity="high",
        status="completed",
        playbook_yaml="---\n- name: Test\n  hosts: target\n  tasks: []\n",
        created_at=now,
        updated_at=now,
        verification=FixVerification(
            investigation_id="",
            status="not_fixed",
            new_alerts_found=5,
            checked_at=now,
            detail="Alerts still firing",
        ),
    )

    workflow = build_workflow_summary(inv)
    verification_stage = next((s for s in workflow["stages"] if s["key"] == "verification"), None)
    assert verification_stage is not None
    assert verification_stage["status"] == "failed"
    # When verification fails, the current_stage highlights the failure point
    assert workflow["current_stage"]["key"] == "verification"


async def test_investigation_detail_includes_workflow_and_playbook_summary():
    from api.routes.investigations import get_investigation
    from response.db import get_session

    inv_id = "soc-contract-workflow-summary"
    async with AsyncSessionLocal() as session:
        session.add(Investigation(
            id=inv_id,
            incident_id="inc-123",
            incident_title="Workflow summary case",
            incident_severity="high",
            status="awaiting_approval",
            ai_summary="Root cause identified.",
            playbook_yaml="---\n- name: Fix\n  hosts: target\n  tasks:\n    - name: Block IP\n      ansible.builtin.shell: iptables -A INPUT -s 1.2.3.4 -j DROP\n",
            playbook_valid=True,
            target_host="web1",
        ))
        await session.commit()

    gen = get_session()
    db_session = await gen.__anext__()
    try:
        detail = await get_investigation(inv_id, session=db_session)
        assert detail.workflow is not None
        assert detail.workflow["current_stage"] is not None
        keys = [s["key"] for s in detail.workflow["stages"]]
        assert keys == [
            "incident_selected",
            "evidence_collection",
            "ai_root_cause",
            "remediation_planning",
            "approval",
            "execution",
            "verification",
            "completed",
            "archived",
        ]
        assert detail.playbook_summary is not None
        assert detail.playbook_summary["target"] == "web1"
        assert detail.playbook_summary["requires_approval"] is True
    finally:
        await gen.aclose()


def test_sanitize_firewall_blocks_zero_cidr_and_empty_jinja_source():
    from response.ansible_exec import _sanitize_firewall_tasks

    # 0.0.0.0/0 should be blocked
    yaml_zero = """---
- name: Test
  hosts: target
  tasks:
    - name: Block all
      ansible.builtin.shell: iptables -A INPUT -s 0.0.0.0/0 -j DROP
"""
    safe, error, _ = _sanitize_firewall_tasks(yaml_zero, set())
    assert safe is False
    assert "0.0.0.0/0" in error

    # Empty Jinja2 source variable should be blocked
    yaml_jinja = """---
- name: Test
  hosts: target
  tasks:
    - name: Block attacker
      ansible.builtin.shell: iptables -A INPUT -s {{ attacker_ips[0] }} -j DROP
"""
    safe, error, _ = _sanitize_firewall_tasks(yaml_jinja, set())
    assert safe is False
    assert "Jinja2 template" in error

    # Normal safe playbook should pass
    yaml_safe = """---
- name: Test
  hosts: target
  tasks:
    - name: Block attacker
      ansible.builtin.shell: iptables -A INPUT -s 1.2.3.4 -j DROP
"""
    safe, error, _ = _sanitize_firewall_tasks(yaml_safe, set())
    assert safe is True
    assert error == ""


def test_decision_approved_approval_stage_is_completed_not_failed():
    from response.workflow_summary import build_workflow_summary
    from response.models import PlaybookApproval

    now = datetime.now(timezone.utc)
    inv = Investigation(
        id=str(uuid.uuid4()),
        incident_id="soc-contract-decision-approved",
        incident_title="SSH brute force",
        incident_severity="high",
        status="decision_approved",
        created_at=now,
        updated_at=now,
        approval=PlaybookApproval(
            investigation_id="",
            decision="decision_approved",
            decided_by="admin",
            decided_at=now,
            reason="Reviewed and accepted",
        ),
    )

    workflow = build_workflow_summary(inv)
    approval_stage = next((s for s in workflow["stages"] if s["key"] == "approval"), None)
    assert approval_stage is not None
    assert approval_stage["status"] == "completed"
    assert "Decision recorded" in approval_stage["details"]
    assert "Failed" not in approval_stage["details"]


def test_decision_approved_execution_is_current():
    from response.workflow_summary import build_workflow_summary

    now = datetime.now(timezone.utc)
    inv = Investigation(
        id=str(uuid.uuid4()),
        incident_id="soc-contract-decision-hard",
        incident_title="SSH brute force",
        incident_severity="high",
        status="decision_approved",
        created_at=now,
        updated_at=now,
    )

    workflow = build_workflow_summary(inv)
    execution_stage = next((s for s in workflow["stages"] if s["key"] == "execution"), None)
    assert execution_stage is not None
    assert execution_stage["status"] == "current"
    assert "approved and queued" in execution_stage["details"].lower()


def test_decision_approved_does_not_mark_workflow_failed():
    from response.workflow_summary import build_workflow_summary

    now = datetime.now(timezone.utc)
    inv = Investigation(
        id=str(uuid.uuid4()),
        incident_id="soc-contract-decision-not-failed",
        incident_title="SSH brute force",
        incident_severity="high",
        status="decision_approved",
        created_at=now,
        updated_at=now,
    )

    workflow = build_workflow_summary(inv)
    failed_stages = [s for s in workflow["stages"] if s["status"] == "failed"]
    assert len(failed_stages) == 0
    assert workflow["current_stage"]["key"] != "approval" or workflow["current_stage"]["status"] != "failed"


def test_decision_approved_verification_is_current():
    from response.workflow_summary import build_workflow_summary

    now = datetime.now(timezone.utc)
    inv = Investigation(
        id=str(uuid.uuid4()),
        incident_id="soc-contract-decision-na",
        incident_title="SSH brute force",
        incident_severity="high",
        status="decision_approved",
        created_at=now,
        updated_at=now,
    )

    workflow = build_workflow_summary(inv)
    verification_stage = next((s for s in workflow["stages"] if s["key"] == "verification"), None)
    assert verification_stage is not None
    assert verification_stage["status"] == "current"
