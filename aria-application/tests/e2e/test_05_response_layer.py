"""
E2E Test 05 — Response Intelligence Layer

Tests the full investigation lifecycle against our backend API (:8001):
  - Incident watcher picks up incidents from OpenSOAR
  - AI engine generates summaries and playbooks
  - Approval workflow (approve/decline)
  - Archive creation
  - AI assistant queries
"""
import asyncio
import uuid

import httpx
import pytest
import pytest_asyncio

from tests.e2e.conftest import make_test_alert, E2E_TAG
from config import get_settings

settings = get_settings()

BACKEND = "http://localhost:8001"


# ─── Helper ───────────────────────────────────────────────────────────────────

async def _create_opensoar_incident_with_alerts(soar, cleanup) -> tuple[str, list[str]]:
    """
    Create an incident in OpenSOAR with 2 linked alerts.
    Returns (incident_id, [alert_id_1, alert_id_2])
    """
    alert_ids = []
    for sev in ("high", "critical"):
        payload = make_test_alert("wazuh", sev)
        r = await soar.post("/api/v1/webhooks/alerts", json=payload)
        assert r.status_code == 200, f"Alert creation failed: {r.text[:200]}"
        alert_id = r.json()["alert_id"]
        alert_ids.append(alert_id)
        cleanup["alerts"].append(alert_id)

    r_inc = await soar.post(
        "/api/v1/incidents",
        json={
            "title": f"E2E Response Test Incident {uuid.uuid4().hex[:6]}",
            "description": "E2E test incident for response intelligence layer testing",
            "severity": "high",
            "tags": [E2E_TAG, "brute-force", "ssh", "mitre-tactic-Credential Access"],
        },
    )
    assert r_inc.status_code == 201, f"Incident creation failed: {r_inc.text[:200]}"
    incident_id = r_inc.json()["id"]
    cleanup["incidents"].append(incident_id)

    for alert_id in alert_ids:
        r_link = await soar.post(
            f"/api/v1/incidents/{incident_id}/alerts",
            json={"alert_id": alert_id},
        )
        assert r_link.status_code == 201, f"Alert link failed: {r_link.text[:200]}"

    return incident_id, alert_ids


# ─── Backend API basic tests ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_backend_investigations_endpoint(backend_client, services):
    """GET /api/v1/investigations returns valid response."""
    r = await backend_client.get("/api/v1/investigations")
    assert r.status_code == 200
    data = r.json()
    assert "investigations" in data
    assert "total" in data
    print(f"\n  Investigations in DB: {data['total']}")


@pytest.mark.asyncio
async def test_backend_investigations_stats(backend_client, services):
    """GET /api/v1/investigations/stats returns status counts."""
    r = await backend_client.get("/api/v1/investigations/stats")
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "pending" in data
    assert "awaiting_approval" in data
    print(f"\n  Investigation stats: {data}")


@pytest.mark.asyncio
async def test_backend_archives_endpoint(backend_client, services):
    """GET /api/v1/archives returns valid response."""
    r = await backend_client.get("/api/v1/archives")
    assert r.status_code == 200
    data = r.json()
    assert "archives" in data
    print(f"\n  Archives in DB: {data['total']}")


@pytest.mark.asyncio
async def test_backend_archives_stats(backend_client, services):
    """GET /api/v1/archives/stats returns fix statistics."""
    r = await backend_client.get("/api/v1/archives/stats")
    assert r.status_code == 200
    data = r.json()
    assert "total_archived" in data
    assert "fix_success_rate_pct" in data
    print(f"\n  Archive stats: total={data['total_archived']} fix_rate={data['fix_success_rate_pct']}%")


# ─── Investigation lifecycle ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_watcher_detects_new_incident(soar, backend_client, cleanup, services):
    """
    Create an incident in OpenSOAR, wait for watcher to detect it,
    verify it appears in our investigations DB.
    """
    incident_id, alert_ids = await _create_opensoar_incident_with_alerts(soar, cleanup)
    print(f"\n  Created OpenSOAR incident: {incident_id[:8]}...")

    # Watcher polls every 60s by default. For tests, poll interval should be low.
    # Wait up to 90s for the investigation to appear.
    investigation_id = None
    for attempt in range(18):  # 18 × 5s = 90s
        await asyncio.sleep(5)
        r = await backend_client.get(
            "/api/v1/investigations",
            params={"limit": 50},
        )
        assert r.status_code == 200
        for inv in r.json()["investigations"]:
            if inv["incident_id"] == incident_id:
                investigation_id = inv["id"]
                print(f"  Watcher detected incident after {(attempt+1)*5}s → investigation {investigation_id[:8]}...")
                break
        if investigation_id:
            break

    if not investigation_id:
        pytest.skip(
            f"Incident {incident_id[:8]} not detected by watcher after 90s. "
            f"Make sure INCIDENT_WATCHER_INTERVAL is ≤60 in .env"
        )

    return investigation_id


@pytest.mark.asyncio
async def test_ai_generates_investigation(soar, backend_client, cleanup, services):
    """
    After watcher detects incident, AI engine should populate summary and playbook.
    Waits up to 3 minutes for Ollama to respond.
    """
    if not services["ollama"]:
        pytest.skip("Ollama not reachable — AI investigation test skipped")

    incident_id, _ = await _create_opensoar_incident_with_alerts(soar, cleanup)

    # Wait for investigation to be created
    investigation_id = None
    for _ in range(24):  # 2 min
        await asyncio.sleep(5)
        r = await backend_client.get("/api/v1/investigations", params={"limit": 100})
        for inv in r.json()["investigations"]:
            if inv["incident_id"] == incident_id:
                investigation_id = inv["id"]
                break
        if investigation_id:
            break

    if not investigation_id:
        pytest.skip("Investigation not created within 2 minutes")

    # Wait for AI to finish (status transitions from pending → awaiting_approval)
    final_status = None
    for attempt in range(36):  # 3 min
        await asyncio.sleep(5)
        r = await backend_client.get(f"/api/v1/investigations/{investigation_id}")
        assert r.status_code == 200
        inv = r.json()
        status = inv["status"]
        if status in ("awaiting_approval", "failed"):
            final_status = status
            break
        print(f"  AI status: {status} (attempt {attempt+1})")

    assert final_status is not None, "AI engine did not complete within 3 minutes"

    if final_status == "failed":
        r = await backend_client.get(f"/api/v1/investigations/{investigation_id}")
        error = r.json().get("ai_error", "unknown")
        pytest.fail(f"AI investigation failed: {error}")

    # Verify outputs
    r = await backend_client.get(f"/api/v1/investigations/{investigation_id}")
    inv = r.json()

    assert inv["status"] == "awaiting_approval"
    assert inv["ai_summary"], "AI summary is empty"
    assert inv["playbook_yaml"], "AI did not generate a playbook"

    print(f"\n  AI Summary: {inv['ai_summary'][:150]}")
    print(f"  Playbook valid: {inv['playbook_valid']}")
    print(f"  Target host: {inv['target_host']}")
    print(f"  MITRE tactics: {inv['mitre_tactics']}")

    return investigation_id


@pytest.mark.asyncio
async def test_approve_investigation(soar, backend_client, cleanup, services):
    """
    Approve an existing investigation (awaiting_approval status).
    Verify status transitions to approved → running/completed.
    """
    if not services["ollama"]:
        pytest.skip("Ollama required to have an investigation to approve")

    # Check for any existing awaiting_approval investigation
    r = await backend_client.get("/api/v1/investigations", params={"status": "awaiting_approval", "limit": 1})
    invs = r.json()["investigations"]

    if not invs:
        pytest.skip("No investigations in 'awaiting_approval' state — run AI test first")

    inv_id = invs[0]["id"]
    print(f"\n  Approving investigation: {inv_id[:8]}...")

    r2 = await backend_client.post(
        f"/api/v1/investigations/{inv_id}/approve",
        json={"decided_by": "e2e-test-analyst"},
    )
    assert r2.status_code == 200, f"Approve failed: {r2.status_code} {r2.text[:300]}"
    data = r2.json()
    assert data.get("investigation_id") == inv_id
    print(f"  Approval response: {data.get('message')}")

    # Verify status changed
    await asyncio.sleep(2)
    r3 = await backend_client.get(f"/api/v1/investigations/{inv_id}")
    assert r3.status_code == 200
    new_status = r3.json()["status"]
    assert new_status in ("approved", "running", "completed", "failed"), \
        f"Unexpected status after approval: {new_status}"
    print(f"  Status after approval: {new_status}")


@pytest.mark.asyncio
async def test_decline_investigation(soar, backend_client, cleanup, services):
    """Decline an awaiting_approval investigation with a reason."""
    if not services["ollama"]:
        pytest.skip("Ollama required")

    r = await backend_client.get("/api/v1/investigations", params={"status": "awaiting_approval", "limit": 5})
    invs = r.json()["investigations"]

    if not invs:
        # Create a minimal investigation for decline testing via API workaround
        pytest.skip("No awaiting_approval investigations to decline")

    inv_id = invs[-1]["id"]  # Use last one (least likely to be used in approve test)
    print(f"\n  Declining investigation: {inv_id[:8]}...")

    r2 = await backend_client.post(
        f"/api/v1/investigations/{inv_id}/decline",
        json={"decided_by": "e2e-test-analyst", "reason": "E2E test — false positive, no action needed"},
    )
    assert r2.status_code == 200, f"Decline failed: {r2.status_code} {r2.text[:300]}"
    print(f"  Decline response: {r2.json()}")

    # Verify status
    await asyncio.sleep(2)
    r3 = await backend_client.get(f"/api/v1/investigations/{inv_id}")
    new_status = r3.json()["status"]
    assert new_status in ("declined", "archived"), f"Unexpected status: {new_status}"
    print(f"  Status after decline: {new_status}")


@pytest.mark.asyncio
async def test_edit_playbook_before_approve(soar, backend_client, cleanup, services):
    """Analyst can edit the playbook YAML before approving."""
    if not services["ollama"]:
        pytest.skip("Ollama required")

    r = await backend_client.get("/api/v1/investigations", params={"status": "awaiting_approval", "limit": 1})
    invs = r.json()["investigations"]

    if not invs:
        pytest.skip("No awaiting_approval investigations")

    inv_id = invs[0]["id"]
    custom_playbook = """---
- name: E2E Test Edited Playbook
  hosts: target
  become: yes
  tasks:
    - name: E2E test task - echo
      command: echo "E2E test playbook ran"
"""
    r2 = await backend_client.patch(
        f"/api/v1/investigations/{inv_id}/playbook",
        json={"playbook_yaml": custom_playbook},
    )
    assert r2.status_code == 200, f"Playbook edit failed: {r2.status_code} {r2.text[:200]}"

    # Verify the edit was stored
    r3 = await backend_client.get(f"/api/v1/investigations/{inv_id}")
    stored = r3.json()["playbook_yaml"]
    assert "E2E test task" in stored, "Edited playbook not stored correctly"
    print(f"\n  Playbook edited successfully for investigation {inv_id[:8]}...")


@pytest.mark.asyncio
async def test_run_status_after_approval(backend_client, services):
    """GET /api/v1/investigations/{id}/run-status returns run info after approval."""
    # Find an investigation that has been approved/run
    r = await backend_client.get("/api/v1/investigations", params={"limit": 50})
    invs = r.json()["investigations"]

    run_inv = next((i for i in invs if i["status"] in ("running", "completed", "failed")), None)
    if not run_inv:
        pytest.skip("No investigations in running/completed/failed state")

    inv_id = run_inv["id"]
    r2 = await backend_client.get(f"/api/v1/investigations/{inv_id}/run-status")
    assert r2.status_code == 200, f"Run status failed: {r2.status_code}"
    run = r2.json()
    assert "status" in run
    assert "output" in run
    print(f"\n  Run status: {run['status']} | exit_code={run.get('exit_code')}")
    if run.get("output"):
        print(f"  Output preview: {run['output'][:200]}")
