"""
Unit tests for Infrastructure Investigation API routes.

Uses httpx.AsyncClient with async tests to avoid SQLite/TestClient conflicts.
All DB operations run in the same pytest-asyncio event loop.
"""

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
import httpx

from sqlalchemy import select
from response.db import AsyncSessionLocal
from response.models import Investigation, InvestigationAuditEvent


BASE_URL = "http://localhost:8001"


@pytest_asyncio.fixture
async def async_client():
    """Async HTTP client for testing."""
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        yield client


async def _create_infrastructure_investigation(
    title: str = "Test CPU Alert",
    status: str = "awaiting_approval",
    severity: str = "critical",
    resource_type: str = "cpu",
    current_value: float = 95.0,
    affected_service: str = "nginx",
) -> str:
    """Helper to create an infrastructure investigation in the DB."""
    inv_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        investigation = Investigation(
            id=inv_id,
            incident_id=str(uuid.uuid4()),
            incident_title=title,
            incident_severity=severity,
            incident_status="open",
            status=status,
            target_host="test-host",
            hostnames="test-host",
            source="performance",
            investigation_type="infrastructure",
            resource_context_json={
                "resource_type": resource_type,
                "current_value": current_value,
                "threshold": 90.0,
                "unit": "%",
                "affected_host": "test-host",
                "affected_service": affected_service,
                "affected_process": {"name": "nginx", "pid": 1234},
                "top_processes": [
                    {"name": "nginx", "pid": 1234, "cpu_percent": 78.5, "memory_rss": 500000000},
                ],
                "metrics_snapshot": {"cpu_usage_percent": 95.0},
                "historical_trend": "spike",
                "baseline_deviation": "+3.5 stddev",
                "root_cause_confidence": 0.92,
            },
            playbook_yaml="---\n- name: Test playbook\n  hosts: test-host\n  tasks: []",
            playbook_valid=True,
            ai_summary="CPU high due to nginx traffic spike",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(investigation)
        await session.commit()
    return inv_id


async def _create_security_investigation() -> str:
    """Helper to create a security investigation (not infrastructure)."""
    inv_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        investigation = Investigation(
            id=inv_id,
            incident_id=str(uuid.uuid4()),
            incident_title="SSH Brute Force",
            incident_severity="high",
            incident_status="open",
            status="awaiting_approval",
            target_host="web-server",
            source="wazuh",
            investigation_type="security",
            playbook_yaml="---\n- name: Security playbook\n  hosts: web-server\n  tasks: []",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(investigation)
        await session.commit()
    return inv_id


# ─────────────────────────────────────────────────────────────────────────────
# List Investigations
# ─────────────────────────────────────────────────────────────────────────────

class TestListInfrastructureInvestigations:
    @pytest.mark.asyncio
    async def test_empty_list(self, async_client):
        resp = await async_client.get("/api/v1/infrastructure/investigations?status=nonexistent-status")
        assert resp.status_code == 200
        data = resp.json()
        assert "investigations" in data
        assert data["total"] == 0
        assert data["investigations"] == []

    @pytest.mark.asyncio
    async def test_list_with_infrastructure_only(self, async_client):
        infra_id = await _create_infrastructure_investigation(title="CPU High")
        sec_id = await _create_security_investigation()

        resp = await async_client.get("/api/v1/infrastructure/investigations")
        assert resp.status_code == 200
        data = resp.json()

        # Should only show infrastructure, not security
        ids = [i["id"] for i in data["investigations"]]
        assert infra_id in ids
        assert sec_id not in ids

        # Verify resource context fields are extracted
        item = next(i for i in data["investigations"] if i["id"] == infra_id)
        assert item["investigation_type"] == "infrastructure"
        assert item["resource_type"] == "cpu"
        assert item["affected_service"] == "nginx"
        assert item["current_value"] == 95.0

    @pytest.mark.asyncio
    async def test_filter_by_status(self, async_client):
        await _create_infrastructure_investigation(status="awaiting_approval")

        resp = await async_client.get("/api/v1/infrastructure/investigations?status=awaiting_approval")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

        resp = await async_client.get("/api/v1/infrastructure/investigations?status=approved&host=definitely-nonexistent-host")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_filter_by_severity(self, async_client):
        await _create_infrastructure_investigation(severity="critical")

        resp = await async_client.get("/api/v1/infrastructure/investigations?severity=critical")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

        resp = await async_client.get("/api/v1/infrastructure/investigations?severity=low")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_filter_by_host(self, async_client):
        await _create_infrastructure_investigation()

        resp = await async_client.get("/api/v1/infrastructure/investigations?host=test-host")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

        resp = await async_client.get("/api/v1/infrastructure/investigations?host=nonexistent")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_pagination(self, async_client):
        # Create multiple
        for i in range(3):
            await _create_infrastructure_investigation(title=f"Test {i}")

        resp = await async_client.get("/api/v1/infrastructure/investigations?limit=1&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["investigations"]) == 1
        assert data["limit"] == 1
        assert data["offset"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Get Investigation Detail
# ─────────────────────────────────────────────────────────────────────────────

class TestGetInfrastructureInvestigation:
    @pytest.mark.asyncio
    async def test_get_existing(self, async_client):
        infra_id = await _create_infrastructure_investigation()

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{infra_id}")
        assert resp.status_code == 200
        data = resp.json()

        assert data["id"] == infra_id
        assert data["investigation_type"] == "infrastructure"
        assert data["source"] == "performance"
        assert data["resource_context"] is not None
        assert data["resource_context"]["resource_type"] == "cpu"
        assert data["suggested_actions"] is not None

    @pytest.mark.asyncio
    async def test_get_not_found(self, async_client):
        resp = await async_client.get("/api/v1/infrastructure/investigations/nonexistent-id")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_security_rejected(self, async_client):
        sec_id = await _create_security_investigation()

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{sec_id}")
        assert resp.status_code == 400
        assert "not an infrastructure investigation" in resp.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Resource Context Endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestGetResourceContext:
    @pytest.mark.asyncio
    async def test_get_context(self, async_client):
        infra_id = await _create_infrastructure_investigation()

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{infra_id}/resource-context")
        assert resp.status_code == 200
        data = resp.json()
        assert data["resource_type"] == "cpu"
        assert data["current_value"] == 95.0
        assert data["affected_host"] == "test-host"

    @pytest.mark.asyncio
    async def test_get_context_no_data(self, async_client):
        # Create one without resource_context_json
        inv_id = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            investigation = Investigation(
                id=inv_id,
                incident_id=str(uuid.uuid4()),
                incident_title="No Context",
                status="awaiting_approval",
                investigation_type="infrastructure",
                resource_context_json=None,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(investigation)
            await session.commit()

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{inv_id}/resource-context")
        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# Suggested Actions Endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestGetSuggestedActions:
    @pytest.mark.asyncio
    async def test_get_actions(self, async_client):
        infra_id = await _create_infrastructure_investigation()

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{infra_id}/suggested-actions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["investigation_id"] == infra_id
        assert "actions" in data


# ─────────────────────────────────────────────────────────────────────────────
# Approve Endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestApproveInfrastructureInvestigation:
    @pytest.mark.asyncio
    async def test_approve_success(self, async_client):
        infra_id = await _create_infrastructure_investigation()

        resp = await async_client.post(
            f"/api/v1/infrastructure/investigations/{infra_id}/approve",
            json={"decided_by": "test_analyst", "acknowledge_risk": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "approved"
        assert data["investigation_id"] == infra_id

    @pytest.mark.asyncio
    async def test_approve_not_awaiting(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="running")

        resp = await async_client.post(
            f"/api/v1/infrastructure/investigations/{infra_id}/approve",
            json={"decided_by": "test_analyst"},
        )
        assert resp.status_code == 400
        assert "cannot approve" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_approve_no_playbook(self, async_client):
        inv_id = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            investigation = Investigation(
                id=inv_id,
                incident_id=str(uuid.uuid4()),
                incident_title="No Playbook",
                status="awaiting_approval",
                investigation_type="infrastructure",
                playbook_yaml=None,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(investigation)
            await session.commit()

        resp = await async_client.post(
            f"/api/v1/infrastructure/investigations/{inv_id}/approve",
            json={"decided_by": "test_analyst"},
        )
        assert resp.status_code == 400
        assert "no playbook" in resp.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Decline Endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestDeclineInfrastructureInvestigation:
    @pytest.mark.asyncio
    async def test_decline_success(self, async_client):
        infra_id = await _create_infrastructure_investigation()

        resp = await async_client.post(
            f"/api/v1/infrastructure/investigations/{infra_id}/decline",
            json={"decided_by": "test_analyst", "reason": "False positive"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "declined"
        assert data["investigation_id"] == infra_id

    @pytest.mark.asyncio
    async def test_decline_no_reason(self, async_client):
        infra_id = await _create_infrastructure_investigation()

        resp = await async_client.post(
            f"/api/v1/infrastructure/investigations/{infra_id}/decline",
            json={"decided_by": "test_analyst"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "declined"

    @pytest.mark.asyncio
    async def test_decline_not_awaiting(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="running")

        resp = await async_client.post(
            f"/api/v1/infrastructure/investigations/{infra_id}/decline",
            json={"decided_by": "test_analyst"},
        )
        assert resp.status_code == 400
        assert "cannot decline" in resp.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Stats Endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestInfrastructureStats:
    @pytest.mark.asyncio
    async def test_stats_structure(self, async_client):
        resp = await async_client.get("/api/v1/infrastructure/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "by_status" in data
        assert isinstance(data["by_status"], dict)

    @pytest.mark.asyncio
    async def test_stats_with_data(self, async_client):
        await _create_infrastructure_investigation(status="awaiting_approval")
        await _create_infrastructure_investigation(status="approved")
        await _create_security_investigation()

        resp = await async_client.get("/api/v1/infrastructure/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["by_status"]["awaiting_approval"] >= 1
        assert data["by_status"]["approved"] >= 1
        # Security investigations should not count


# ─────────────────────────────────────────────────────────────────────────────
# Main Investigations API (investigation_type filter)
# ─────────────────────────────────────────────────────────────────────────────

class TestInvestigationsTypeFilter:
    @pytest.mark.asyncio
    async def test_filter_by_type_infrastructure(self, async_client):
        infra_id = await _create_infrastructure_investigation()

        resp = await async_client.get("/api/v1/investigations?investigation_type=infrastructure")
        assert resp.status_code == 200
        data = resp.json()
        ids = [i["id"] for i in data.get("investigations", [])]
        assert infra_id in ids

    @pytest.mark.asyncio
    async def test_filter_by_type_security(self, async_client):
        sec_id = await _create_security_investigation()

        resp = await async_client.get("/api/v1/investigations?investigation_type=security")
        assert resp.status_code == 200
        data = resp.json()
        ids = [i["id"] for i in data.get("investigations", [])]
        assert sec_id in ids


# ─────────────────────────────────────────────────────────────────────────────
# Archive Endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestArchiveInfrastructureInvestigation:
    @pytest.mark.asyncio
    async def test_archive_from_acknowledged(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="acknowledged")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/archive")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "archived"
        assert data["investigation_id"] == infra_id

    @pytest.mark.asyncio
    async def test_archive_from_escalated(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="escalated")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/archive")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "archived"

    @pytest.mark.asyncio
    async def test_archive_rejected_from_diagnosing(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="diagnosing")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/archive")
        assert resp.status_code == 400
        assert "acknowledged or escalated" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_archive_rejected_from_findings_ready(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="findings_ready")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/archive")
        assert resp.status_code == 400
        assert "acknowledged or escalated" in resp.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Audit Events
# ─────────────────────────────────────────────────────────────────────────────

async def _get_audit_events(investigation_id: str):
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(InvestigationAuditEvent)
            .where(InvestigationAuditEvent.investigation_id == investigation_id)
            .order_by(InvestigationAuditEvent.created_at.desc())
        )
        return list(result.scalars().all())


class TestInfrastructureAuditEvents:
    @pytest.mark.asyncio
    async def test_acknowledge_creates_audit_event(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="findings_ready")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/acknowledge")
        assert resp.status_code == 200

        events = await _get_audit_events(infra_id)
        assert len(events) >= 1
        assert events[0].event_type == "acknowledged"
        assert events[0].actor == "analyst"
        assert "findings_ready" in (events[0].details or "")

    @pytest.mark.asyncio
    async def test_escalate_creates_audit_event(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="findings_ready")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/escalate")
        assert resp.status_code == 200

        events = await _get_audit_events(infra_id)
        assert any(e.event_type == "escalated" for e in events)

    @pytest.mark.asyncio
    async def test_archive_creates_audit_event(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="acknowledged")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/archive")
        assert resp.status_code == 200

        events = await _get_audit_events(infra_id)
        assert any(e.event_type == "archived" for e in events)

    @pytest.mark.asyncio
    async def test_diagnose_creates_audit_event(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="findings_ready")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/diagnose")
        assert resp.status_code == 200

        events = await _get_audit_events(infra_id)
        assert any(e.event_type == "diagnosed" for e in events)


# ─────────────────────────────────────────────────────────────────────────────
# Re-diagnosis Clears Stale Findings
# ─────────────────────────────────────────────────────────────────────────────

class TestReDiagnosis:
    @pytest.mark.asyncio
    async def test_diagnose_clears_findings_and_output(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="findings_ready")

        # Seed stale findings and output
        async with AsyncSessionLocal() as session:
            inv = await session.get(Investigation, infra_id)
            inv.findings_json = {"detected_cause": "old cause"}
            inv.diagnostic_output = "old stdout"
            inv.diagnostic_finished_at = datetime.now(timezone.utc)
            await session.commit()

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/diagnose")
        assert resp.status_code == 200

        async with AsyncSessionLocal() as session:
            inv = await session.get(Investigation, infra_id)
            assert inv.status == "diagnosing"
            assert inv.findings_json is None
            assert inv.diagnostic_output is None
            assert inv.diagnostic_finished_at is None


# ─────────────────────────────────────────────────────────────────────────────
# Suggested Actions Prefer Findings
# ─────────────────────────────────────────────────────────────────────────────

class TestSuggestedActions:
    @pytest.mark.asyncio
    async def test_suggested_actions_prefer_findings_recommendations(self, async_client):
        infra_id = await _create_infrastructure_investigation()

        # Seed findings with recommendations
        async with AsyncSessionLocal() as session:
            inv = await session.get(Investigation, infra_id)
            inv.findings_json = {
                "recommendations": [
                    {
                        "action": "Kill runaway process",
                        "risk": "low",
                        "expected_outcome": "CPU returns to normal",
                        "system_impact": "Brief interruption",
                        "rollback_feasible": True,
                    }
                ]
            }
            await session.commit()

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{infra_id}/suggested-actions")
        assert resp.status_code == 200
        data = resp.json()
        actions = data["actions"]
        assert len(actions) >= 1
        assert actions[0]["action"] == "Kill runaway process"

    @pytest.mark.asyncio
    async def test_suggested_actions_fallback_to_resource_context(self, async_client):
        infra_id = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            investigation = Investigation(
                id=infra_id,
                incident_id=str(uuid.uuid4()),
                incident_title="Disk Full",
                incident_severity="critical",
                incident_status="open",
                status="findings_ready",
                target_host="test-host",
                hostnames="test-host",
                source="performance",
                investigation_type="infrastructure",
                resource_context_json={
                    "immediate_mitigation": {
                        "action": "Clear temp files",
                        "risk": "low",
                        "expected_outcome": "Free up space",
                        "system_impact": "Minimal",
                        "rollback_feasible": True,
                    },
                    "long_term_optimization": {
                        "action": "Add monitoring",
                        "risk": "low",
                        "expected_outcome": "Early warning",
                        "system_impact": "None",
                    },
                },
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(investigation)
            await session.commit()

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{infra_id}/suggested-actions")
        assert resp.status_code == 200
        data = resp.json()
        actions = data["actions"]
        assert len(actions) >= 1
        assert any("Clear temp files" in a["action"] for a in actions)


# ─────────────────────────────────────────────────────────────────────────────
# Metrics Host Investigations Filter
# ─────────────────────────────────────────────────────────────────────────────

class TestMetricsHostInvestigationsFilter:
    @pytest.mark.asyncio
    async def test_metrics_host_investigations_only_infrastructure(self, async_client):
        # Create infrastructure and security investigations on same host
        async with AsyncSessionLocal() as session:
            infra = Investigation(
                id=str(uuid.uuid4()),
                incident_id=str(uuid.uuid4()),
                incident_title="CPU High",
                incident_severity="critical",
                status="findings_ready",
                target_host="shared-host",
                hostnames="shared-host",
                source="performance",
                investigation_type="infrastructure",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            sec = Investigation(
                id=str(uuid.uuid4()),
                incident_id=str(uuid.uuid4()),
                incident_title="SSH Attack",
                incident_severity="high",
                status="pending",
                target_host="shared-host",
                hostnames="shared-host",
                source="wazuh",
                investigation_type="security",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add_all([infra, sec])
            await session.commit()
            infra_id = infra.id

        resp = await async_client.get("/api/v1/metrics/shared-host/investigations")
        assert resp.status_code == 200
        data = resp.json()
        ids = [i["id"] for i in data["investigations"]]
        assert infra_id in ids
        assert sec.id not in ids


# ─────────────────────────────────────────────────────────────────────────────
# Timeline Endpoint with Audit Events
# ─────────────────────────────────────────────────────────────────────────────

class TestInfrastructureTimeline:
    @pytest.mark.asyncio
    async def test_timeline_includes_acknowledge_event(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="findings_ready")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/acknowledge")
        assert resp.status_code == 200

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{infra_id}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["investigation_id"] == infra_id
        types = [e["type"] for e in data["events"]]
        assert "acknowledged" in types
        ack_event = next(e for e in data["events"] if e["type"] == "acknowledged")
        assert ack_event.get("decided_by") == "analyst"
        assert "findings_ready" in (ack_event.get("description") or "")

    @pytest.mark.asyncio
    async def test_timeline_includes_escalate_event(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="findings_ready")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/escalate")
        assert resp.status_code == 200

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{infra_id}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        types = [e["type"] for e in data["events"]]
        assert "escalated" in types

    @pytest.mark.asyncio
    async def test_timeline_includes_archive_event(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="acknowledged")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/archive")
        assert resp.status_code == 200

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{infra_id}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        types = [e["type"] for e in data["events"]]
        assert "archived" in types

    @pytest.mark.asyncio
    async def test_timeline_includes_diagnose_event(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="findings_ready")

        resp = await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/diagnose")
        assert resp.status_code == 200

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{infra_id}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        types = [e["type"] for e in data["events"]]
        assert "diagnosed" in types

    @pytest.mark.asyncio
    async def test_timeline_chronological_order(self, async_client):
        infra_id = await _create_infrastructure_investigation(status="findings_ready")

        # Perform actions in sequence
        await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/acknowledge")
        await async_client.post(f"/api/v1/infrastructure/investigations/{infra_id}/archive")

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{infra_id}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        events = data["events"]

        # created should be first, then acknowledged, then archived
        created_idx = next(i for i, e in enumerate(events) if e["type"] == "created")
        ack_idx = next(i for i, e in enumerate(events) if e["type"] == "acknowledged")
        arch_idx = next(i for i, e in enumerate(events) if e["type"] == "archived")
        assert created_idx < ack_idx < arch_idx

    @pytest.mark.asyncio
    async def test_timeline_synthetic_fallback_for_legacy_investigations(self, async_client):
        """Old investigations without audit rows still get synthetic status event."""
        inv_id = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            investigation = Investigation(
                id=inv_id,
                incident_id=str(uuid.uuid4()),
                incident_title="Legacy CPU Alert",
                incident_severity="critical",
                incident_status="open",
                status="acknowledged",
                target_host="legacy-host",
                hostnames="legacy-host",
                source="performance",
                investigation_type="infrastructure",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(investigation)
            await session.commit()

        resp = await async_client.get(f"/api/v1/infrastructure/investigations/{inv_id}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        types = [e["type"] for e in data["events"]]
        assert "created" in types
        # Should have synthetic status event because no audit rows exist
        assert "acknowledged" in types
        # But should NOT duplicate if no audit rows
        assert types.count("acknowledged") == 1
