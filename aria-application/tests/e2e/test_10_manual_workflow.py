"""
E2E tests for manual workflow control:
- Manual incident creation from alerts
- Manual investigation launch from incidents
- Historical data visibility (archived/resolved filters)
"""

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
import httpx

BASE_URL = "http://localhost:8001/api/v1"


@pytest_asyncio.fixture
async def client():
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as c:
        yield c


@pytest_asyncio.fixture
async def local_test_alerts():
    """Create test alerts directly in the local SQLite DB. Yields their IDs."""
    import sqlite3
    from pathlib import Path

    db_path = Path(__file__).parent.parent.parent / "data" / "investigations.db"
    alert_ids = []

    conn = sqlite3.connect(str(db_path))
    now = datetime.now(timezone.utc).isoformat()
    for i in range(2):
        alert_id = str(uuid.uuid4())
        source_id = f"e2e-test-{alert_id}"
        conn.execute(
            """
            INSERT INTO alerts (
                id, source, source_id, title, description, severity, status,
                category, source_ip, dest_ip, hostname, rule_name, tags, iocs,
                observables, alert_metadata, event_time, created_at, updated_at,
                whitelisted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                "wazuh",
                source_id,
                f"[E2E] Test Alert {i+1}",
                "Created by E2E test fixture",
                "high" if i == 0 else "medium",
                "new",
                "test",
                "10.0.0.1",
                "192.168.1.1",
                "test-host",
                "e2e_test_rule",
                '["e2e-test"]',
                '{"ip": ["10.0.0.1"]}',
                None,
                '{"test": true}',
                now,
                now,
                now,
                0,
            ),
        )
        alert_ids.append(alert_id)

    conn.commit()
    conn.close()

    yield alert_ids

    # Cleanup
    conn = sqlite3.connect(str(db_path))
    placeholders = ",".join("?" * len(alert_ids))
    conn.execute(f"DELETE FROM alerts WHERE id IN ({placeholders})", alert_ids)
    conn.commit()
    conn.close()


class TestManualIncidentCreation:
    @pytest.mark.asyncio
    async def test_create_manual_incident_success(self, client, local_test_alerts):
        """Create a manual incident from existing alerts."""
        alert_ids = local_test_alerts[:2]

        resp = await client.post("/incidents/manual", json={
            "title": "Manual Test Incident",
            "description": "Created manually during test",
            "severity": "high",
            "alert_ids": alert_ids,
            "tags": ["manual", "test"],
            "created_by": "e2e-test-analyst",
        })
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["title"] == "Manual Test Incident"
        assert data["severity"] == "high"
        assert data["status"] == "open"
        assert "manual" in (data.get("tags") or [])
        assert data.get("created_by") == "e2e-test-analyst"

        # Cleanup
        incident_id = data["id"]
        import sqlite3
        from pathlib import Path
        db_path = Path(__file__).parent.parent.parent / "data" / "investigations.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM alert_incident_links WHERE incident_id = ?", (incident_id,))
        conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()

    @pytest.mark.asyncio
    async def test_create_manual_incident_missing_alerts(self, client):
        """Should 404 if alert IDs don't exist."""
        resp = await client.post("/incidents/manual", json={
            "title": "Bad Incident",
            "description": "Should fail",
            "severity": "medium",
            "alert_ids": ["00000000-0000-0000-0000-000000000000"],
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_create_manual_incident_invalid_severity(self, client):
        """Should 422 if severity is invalid."""
        resp = await client.post("/incidents/manual", json={
            "title": "Bad Incident",
            "description": "Should fail",
            "severity": "invalid",
            "alert_ids": ["00000000-0000-0000-0000-000000000000"],
        })
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_create_manual_incident_no_alerts(self, client):
        """Should 422 if no alert_ids provided."""
        resp = await client.post("/incidents/manual", json={
            "title": "Bad Incident",
            "description": "Should fail",
            "severity": "medium",
            "alert_ids": [],
        })
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_create_manual_incident_links_alerts(self, client, local_test_alerts):
        """Verify linked alerts appear in incident detail."""
        resp = await client.post("/incidents/manual", json={
            "title": "Link Test Incident",
            "description": "Testing alert links",
            "severity": "critical",
            "alert_ids": [local_test_alerts[0]],
        })
        assert resp.status_code == 200
        incident_id = resp.json()["data"]["id"]

        detail = await client.get(f"/incidents/{incident_id}")
        assert detail.status_code == 200
        relationships = detail.json().get("relationships", {})
        assert relationships["alerts"]["count"] >= 1

        # Cleanup
        import sqlite3
        from pathlib import Path
        db_path = Path(__file__).parent.parent.parent / "data" / "investigations.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM alert_incident_links WHERE incident_id = ?", (incident_id,))
        conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()


class TestManualInvestigationLaunch:
    @pytest.mark.asyncio
    async def test_create_manual_investigation_success(self, client, local_test_alerts):
        """Launch a manual investigation from an incident."""
        # Create a fresh incident first
        inc_resp = await client.post("/incidents/manual", json={
            "title": "Investigation Success Test Incident",
            "description": "For investigation success test",
            "severity": "high",
            "alert_ids": [local_test_alerts[0]],
        })
        assert inc_resp.status_code == 200
        incident_id = inc_resp.json()["data"]["id"]

        resp = await client.post("/investigations/manual", json={
            "incident_id": incident_id,
            "target_host": "test-host",
            "target_user": "root",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"
        assert data["source"] == "manual"
        assert data["incident_id"] == incident_id

        # Cleanup
        inv_id = data["investigation_id"]
        await client.post(f"/investigations/{inv_id}/decline", json={"decided_by": "e2e-test"})
        import asyncio
        await asyncio.sleep(0.5)
        import sqlite3
        from pathlib import Path
        db_path = Path(__file__).parent.parent.parent / "data" / "investigations.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM alert_incident_links WHERE incident_id = ?", (incident_id,))
        conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()

    @pytest.mark.asyncio
    async def test_create_manual_investigation_incident_not_found(self, client):
        """Should 404 if incident doesn't exist."""
        resp = await client.post("/investigations/manual", json={
            "incident_id": "00000000-0000-0000-0000-000000000000",
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_create_manual_investigation_duplicate(self, client, local_test_alerts):
        """Should 409 if incident already has an active investigation."""
        # Create a fresh incident and investigation
        inc_resp = await client.post("/incidents/manual", json={
            "title": "Duplicate Test Incident",
            "description": "For duplicate test",
            "severity": "medium",
            "alert_ids": [local_test_alerts[0]],
        })
        assert inc_resp.status_code == 200
        incident_id = inc_resp.json()["data"]["id"]

        inv_resp = await client.post("/investigations/manual", json={
            "incident_id": incident_id,
            "target_host": "test-host",
        })
        assert inv_resp.status_code == 200

        # Try to create another investigation for the same incident — should 409
        resp = await client.post("/investigations/manual", json={
            "incident_id": incident_id,
        })
        assert resp.status_code == 409

        # Cleanup
        inv_id = inv_resp.json()["investigation_id"]
        await client.post(f"/investigations/{inv_id}/decline", json={"decided_by": "e2e-test"})
        import asyncio
        await asyncio.sleep(0.5)
        import sqlite3
        from pathlib import Path
        db_path = Path(__file__).parent.parent.parent / "data" / "investigations.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM alert_incident_links WHERE incident_id = ?", (incident_id,))
        conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()

    @pytest.mark.asyncio
    async def test_manual_investigation_appears_in_list(self, client, local_test_alerts):
        """Manual investigation should appear in list with source=manual."""
        inc_resp = await client.post("/incidents/manual", json={
            "title": "List Test Incident",
            "description": "For investigation list test",
            "severity": "medium",
            "alert_ids": [local_test_alerts[0]],
        })
        assert inc_resp.status_code == 200
        incident_id = inc_resp.json()["data"]["id"]

        inv_resp = await client.post("/investigations/manual", json={
            "incident_id": incident_id,
        })
        assert inv_resp.status_code == 200
        investigation_id = inv_resp.json()["investigation_id"]

        list_resp = await client.get("/investigations?limit=50")
        assert list_resp.status_code == 200
        investigations = list_resp.json().get("investigations", [])
        manual_invs = [i for i in investigations if i.get("source") == "manual"]
        assert len(manual_invs) > 0
        assert any(i.get("id") == investigation_id for i in manual_invs)

        # Cleanup: archive investigation then delete incident
        await client.post(f"/investigations/{investigation_id}/archive")
        import sqlite3
        from pathlib import Path
        db_path = Path(__file__).parent.parent.parent / "data" / "investigations.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM alert_incident_links WHERE incident_id = ?", (incident_id,))
        conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()

    @pytest.mark.asyncio
    async def test_archived_investigation_can_be_reinvestigated(self, client, local_test_alerts):
        """After archiving an investigation, a new one can be launched for the same incident."""
        # Create incident
        inc_resp = await client.post("/incidents/manual", json={
            "title": "Reinvestigation Test Incident",
            "description": "Testing reinvestigation after archive",
            "severity": "high",
            "alert_ids": [local_test_alerts[0]],
        })
        assert inc_resp.status_code == 200
        incident_id = inc_resp.json()["data"]["id"]

        # Launch first investigation
        inv1_resp = await client.post("/investigations/manual", json={
            "incident_id": incident_id,
            "target_host": "test-host-1",
        })
        assert inv1_resp.status_code == 200
        inv1_id = inv1_resp.json()["investigation_id"]

        # Decline the investigation (this automatically archives it in the background)
        decline_resp = await client.post(f"/investigations/{inv1_id}/decline", json={"decided_by": "e2e-test"})
        assert decline_resp.status_code == 200

        # Wait a moment for background archive to complete
        import asyncio
        await asyncio.sleep(0.5)

        # Launch second investigation for same incident — should succeed now
        inv2_resp = await client.post("/investigations/manual", json={
            "incident_id": incident_id,
            "target_host": "test-host-2",
        })
        assert inv2_resp.status_code == 200
        inv2_id = inv2_resp.json()["investigation_id"]
        assert inv2_id != inv1_id

        # Cleanup
        await client.post(f"/investigations/{inv2_id}/archive")
        import sqlite3
        from pathlib import Path
        db_path = Path(__file__).parent.parent.parent / "data" / "investigations.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM alert_incident_links WHERE incident_id = ?", (incident_id,))
        conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
        conn.commit()
        conn.close()

    @pytest.mark.asyncio
    async def test_investigations_source_filter(self, client, local_test_alerts):
        """Investigations endpoint should support source filter."""
        resp = await client.get("/investigations?source=manual&limit=1")
        assert resp.status_code == 200
        data = resp.json()
        assert "investigations" in data


class TestHistoricalDataVisibility:
    @pytest.mark.asyncio
    async def test_alerts_archived_filter(self, client):
        """Alerts endpoint should support archived status filter."""
        resp = await client.get("/alerts?status=archived&limit=1")
        assert resp.status_code == 200
        data = resp.json()
        assert "alerts" in data

    @pytest.mark.asyncio
    async def test_incidents_resolved_filter(self, client):
        """Incidents endpoint should support resolved status filter."""
        resp = await client.get("/incidents?status=resolved&limit=1")
        assert resp.status_code == 200
        data = resp.json()
        assert "incidents" in data

    @pytest.mark.asyncio
    async def test_incidents_archived_filter(self, client):
        """Incidents endpoint should support archived status filter."""
        resp = await client.get("/incidents?status=archived&limit=1")
        assert resp.status_code == 200
        data = resp.json()
        assert "incidents" in data
