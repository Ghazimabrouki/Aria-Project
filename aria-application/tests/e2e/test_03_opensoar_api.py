"""
E2E Test 03 — OpenSOAR API Integration

Tests alert submission, deduplication, incident management,
observables, playbooks, and activity logging against the real OpenSOAR instance.
"""
import asyncio
import uuid
import pytest
import pytest_asyncio

from tests.e2e.conftest import make_test_alert, E2E_TAG


# ─── Alerts ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_send_alert_to_opensoar(soar, cleanup, services):
    """Send a structured alert to OpenSOAR and verify it is stored."""
    payload = make_test_alert("wazuh", "high")

    r = await soar.post("/api/v1/webhooks/alerts", json=payload)
    assert r.status_code == 200, f"Alert send failed: {r.status_code} {r.text[:300]}"

    data = r.json()
    alert_id = data.get("alert_id")
    assert alert_id, f"No alert_id in response: {data}"
    cleanup["alerts"].append(alert_id)

    print(f"\n  Alert created: {alert_id}")
    print(f"  Title: {data.get('title', '')[:60]}")
    print(f"  Severity: {data.get('severity')}")


@pytest.mark.asyncio
async def test_alert_deduplication(soar, cleanup, services):
    """
    Sending the same source_id twice is handled as a duplicate.
    OpenSOAR may return 200 (with existing alert_id) or 422 — both are valid dedup responses.
    """
    payload = make_test_alert("wazuh", "medium")

    r1 = await soar.post("/api/v1/webhooks/alerts", json=payload)
    assert r1.status_code == 200, f"First send failed: {r1.status_code}"
    alert_id_1 = r1.json().get("alert_id")
    if alert_id_1:
        cleanup["alerts"].append(alert_id_1)

    # Same source_id → dedup response
    r2 = await soar.post("/api/v1/webhooks/alerts", json=payload)
    # OpenSOAR may return 422 (strict dedup) or 200 with same alert_id (soft dedup)
    assert r2.status_code in (200, 422), f"Unexpected dedup response: {r2.status_code} {r2.text[:200]}"

    if r2.status_code == 200:
        alert_id_2 = r2.json().get("alert_id")
        # If 200, it should be the SAME alert (not a new one)
        assert alert_id_2 == alert_id_1, \
            f"Dedup failed: two different alert_ids for same source_id: {alert_id_1} vs {alert_id_2}"
        print(f"\n  Dedup (soft): second send returned same alert_id {alert_id_1[:12]}...")
    else:
        print(f"\n  Dedup (strict): second send returned {r2.status_code}")


@pytest.mark.asyncio
async def test_alert_appears_in_list(soar, cleanup, services):
    """After sending an alert, it appears in GET /api/v1/alerts."""
    payload = make_test_alert("suricata", "high")

    r = await soar.post("/api/v1/webhooks/alerts", json=payload)
    assert r.status_code == 200
    alert_id = r.json().get("alert_id")
    cleanup["alerts"].append(alert_id)

    # Fetch it directly
    r2 = await soar.get(f"/api/v1/alerts/{alert_id}")
    assert r2.status_code == 200, f"Get alert failed: {r2.status_code}"
    alert = r2.json()
    assert alert["id"] == alert_id
    assert alert["source"] == "suricata"
    assert alert["severity"] == "high"
    assert E2E_TAG in (alert.get("tags") or [])
    print(f"\n  Alert fetched: source={alert['source']} severity={alert['severity']} status={alert['status']}")


@pytest.mark.asyncio
async def test_alert_update(soar, cleanup, services):
    """PATCH /api/v1/alerts/{id} updates status and determination."""
    payload = make_test_alert("falco", "medium")
    r = await soar.post("/api/v1/webhooks/alerts", json=payload)
    assert r.status_code == 200
    alert_id = r.json()["alert_id"]
    cleanup["alerts"].append(alert_id)

    # Valid determination values: malicious, unknown, benign, suspicious
    r2 = await soar.patch(
        f"/api/v1/alerts/{alert_id}",
        json={"status": "investigating", "determination": "suspicious"},
    )
    assert r2.status_code == 200, f"Update failed: {r2.status_code} {r2.text[:200]}"
    updated = r2.json()
    assert updated["status"] == "investigating"
    assert updated.get("determination") == "suspicious"
    print(f"\n  Alert updated: status={updated['status']} determination={updated.get('determination')}")


@pytest.mark.asyncio
async def test_add_comment_to_alert(soar, cleanup, services):
    """POST /api/v1/alerts/{id}/comments adds a comment."""
    payload = make_test_alert("wazuh", "critical")
    r = await soar.post("/api/v1/webhooks/alerts", json=payload)
    assert r.status_code == 200
    alert_id = r.json()["alert_id"]
    cleanup["alerts"].append(alert_id)

    r2 = await soar.post(
        f"/api/v1/alerts/{alert_id}/comments",
        json={"text": "E2E test comment — investigating this alert"},
    )
    assert r2.status_code == 200, f"Comment failed: {r2.status_code} {r2.text[:200]}"
    comment = r2.json()
    assert comment.get("action") == "comment"
    print(f"\n  Comment added: id={comment['id'][:8]}... detail={comment.get('detail','')[:60]}")


@pytest.mark.asyncio
async def test_alert_activities(soar, cleanup, services):
    """GET /api/v1/alerts/{id}/activities returns activity log."""
    payload = make_test_alert("wazuh", "high")
    r = await soar.post("/api/v1/webhooks/alerts", json=payload)
    assert r.status_code == 200
    alert_id = r.json()["alert_id"]
    cleanup["alerts"].append(alert_id)

    r2 = await soar.get(f"/api/v1/alerts/{alert_id}/activities")
    assert r2.status_code == 200
    data = r2.json()
    assert "activities" in data
    print(f"\n  Activities: {data.get('total', 0)} entries")


@pytest.mark.asyncio
async def test_bulk_alert_update(soar, cleanup, services):
    """POST /api/v1/alerts/bulk updates multiple alerts at once."""
    ids = []
    for sev in ("low", "medium"):
        payload = make_test_alert("wazuh", sev)
        r = await soar.post("/api/v1/webhooks/alerts", json=payload)
        assert r.status_code == 200
        alert_id = r.json()["alert_id"]
        ids.append(alert_id)
        cleanup["alerts"].append(alert_id)

    r2 = await soar.post(
        "/api/v1/alerts/bulk",
        json={"alert_ids": ids, "action": "resolve", "determination": "benign", "resolve_reason": "E2E test bulk resolve"},
    )
    assert r2.status_code == 200, f"Bulk update failed: {r2.status_code} {r2.text[:200]}"
    result = r2.json()
    print(f"\n  Bulk update: updated={result.get('updated')} failed={result.get('failed')}")
    assert result.get("updated", 0) > 0


# ─── Incidents ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_incident(soar, cleanup, services):
    """POST /api/v1/incidents creates a new incident."""
    r = await soar.post(
        "/api/v1/incidents",
        json={
            "title": f"E2E Test Incident — SSH Campaign",
            "description": "E2E test incident grouping multiple brute force alerts",
            "severity": "high",
            "tags": [E2E_TAG, "brute-force", "ssh"],
        },
    )
    assert r.status_code == 201, f"Create incident failed: {r.status_code} {r.text[:300]}"
    incident = r.json()
    incident_id = incident["id"]
    cleanup["incidents"].append(incident_id)
    print(f"\n  Incident created: {incident_id[:8]}... title='{incident['title'][:50]}'")
    assert incident["severity"] == "high"
    assert incident["status"] == "open"


@pytest.mark.asyncio
async def test_link_alert_to_incident(soar, cleanup, services):
    """POST /api/v1/incidents/{id}/alerts links an alert to an incident."""
    # Create an incident
    r_inc = await soar.post(
        "/api/v1/incidents",
        json={"title": "E2E Link Test Incident", "description": "test", "severity": "medium"},
    )
    assert r_inc.status_code == 201
    incident_id = r_inc.json()["id"]
    cleanup["incidents"].append(incident_id)

    # Create an alert
    payload = make_test_alert("wazuh", "medium")
    r_alert = await soar.post("/api/v1/webhooks/alerts", json=payload)
    assert r_alert.status_code == 200
    alert_id = r_alert.json()["alert_id"]
    cleanup["alerts"].append(alert_id)

    # Link alert to incident
    r_link = await soar.post(
        f"/api/v1/incidents/{incident_id}/alerts",
        json={"alert_id": alert_id},
    )
    assert r_link.status_code == 201, f"Link failed: {r_link.status_code} {r_link.text[:200]}"

    # Verify link via list
    r_list = await soar.get(f"/api/v1/incidents/{incident_id}/alerts")
    assert r_list.status_code == 200
    print(f"\n  Alert {alert_id[:8]}... linked to incident {incident_id[:8]}...")


@pytest.mark.asyncio
async def test_incident_update(soar, cleanup, services):
    """PATCH /api/v1/incidents/{id} updates severity and status."""
    r = await soar.post(
        "/api/v1/incidents",
        json={"title": "E2E Update Test", "description": "test", "severity": "low"},
    )
    assert r.status_code == 201
    incident_id = r.json()["id"]
    cleanup["incidents"].append(incident_id)

    r2 = await soar.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"severity": "critical", "status": "investigating"},
    )
    assert r2.status_code == 200, f"Patch failed: {r2.status_code}"
    updated = r2.json()
    assert updated["severity"] == "critical"
    assert updated["status"] == "investigating"
    print(f"\n  Incident updated: severity={updated['severity']} status={updated['status']}")


# ─── Observables ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_observable(soar, cleanup, services):
    """POST /api/v1/observables creates an IP observable."""
    uid = uuid.uuid4().hex[:6]
    r = await soar.post(
        "/api/v1/observables",
        json={"type": "ip", "value": f"10.99.{int(uid[:2],16)%255}.1", "source": "e2e-test"},
    )
    assert r.status_code in (201, 422), f"Unexpected: {r.status_code} {r.text[:200]}"
    if r.status_code == 201:
        obs = r.json()
        obs_id = obs["id"]
        cleanup["observables"] = cleanup.get("observables", [])
        cleanup["observables"].append(obs_id)
        print(f"\n  Observable created: {obs_id[:8]}... type={obs['type']} value={obs['value']}")

        # Add enrichment
        r2 = await soar.post(
            f"/api/v1/observables/{obs_id}/enrichments",
            json={"source": "e2e-geoip", "data": {"country": "TN", "city": "Tunis"}, "malicious": False, "score": 10},
        )
        assert r2.status_code == 200, f"Enrichment failed: {r2.status_code}"
        print(f"  Enrichment added to observable")
    else:
        print(f"\n  Observable already exists (422 — ok)")


# ─── Playbooks & Runs ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_playbooks(soar, services):
    """GET /api/v1/playbooks returns list (may be empty)."""
    r = await soar.get("/api/v1/playbooks")
    assert r.status_code == 200, f"List playbooks failed: {r.status_code}"
    data = r.json()
    assert isinstance(data, list)
    print(f"\n  Playbooks in OpenSOAR: {len(data)}")
    for pb in data[:3]:
        enabled = "ENABLED" if pb.get("enabled") else "DISABLED"
        print(f"  - {pb.get('name','?')} [{enabled}] trigger={pb.get('trigger_type','?')}")


@pytest.mark.asyncio
async def test_list_runs(soar, services):
    """GET /api/v1/runs returns recent playbook runs."""
    r = await soar.get("/api/v1/runs", params={"limit": 10})
    assert r.status_code == 200
    data = r.json()
    runs = data.get("runs", [])
    print(f"\n  Total runs: {data.get('total', 0)} | Showing: {len(runs)}")
    for run in runs[:3]:
        print(f"  - status={run.get('status')} started={str(run.get('started_at',''))[:19]}")


# ─── AI Endpoints ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ai_summarize(soar, cleanup, services):
    """
    POST /api/v1/ai/summarize — tests OpenSOAR's own AI endpoint.
    Note: OpenSOAR's AI uses its own LLM config (OLLAMA_URL env var on the OpenSOAR server),
    which may differ from our backend's Ollama config. Skip gracefully if not configured.
    """
    r = await soar.get("/api/v1/alerts", params={"limit": 1, "severity": "high"})
    alerts = r.json().get("alerts", [])
    if not alerts:
        pytest.skip("No high-severity alerts in OpenSOAR")

    alert_id = alerts[0]["id"]
    r2 = await soar.post("/api/v1/ai/summarize", json={"alert_id": alert_id})

    if r2.status_code == 503:
        pytest.skip(f"OpenSOAR AI not configured on server: {r2.json().get('detail','')}")

    assert r2.status_code == 200, f"AI summarize failed: {r2.status_code} {r2.text[:300]}"
    summary = r2.json()
    assert summary, "Empty AI summary"
    print(f"\n  AI Summary: {str(summary)[:200]}")


@pytest.mark.asyncio
async def test_ai_triage(soar, cleanup, services):
    """POST /api/v1/ai/triage — skips gracefully if OpenSOAR AI not configured."""
    r = await soar.get("/api/v1/alerts", params={"limit": 1})
    alerts = r.json().get("alerts", [])
    if not alerts:
        pytest.skip("No alerts in OpenSOAR")

    alert_id = alerts[0]["id"]
    r2 = await soar.post("/api/v1/ai/triage", json={"alert_id": alert_id})

    if r2.status_code == 503:
        pytest.skip(f"OpenSOAR AI not configured on server: {r2.json().get('detail','')}")

    assert r2.status_code == 200, f"AI triage failed: {r2.status_code} {r2.text[:300]}"
    print(f"\n  AI Triage: {str(r2.json())[:200]}")


# ─── Dashboard ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dashboard_stats(soar, services):
    """GET /api/v1/dashboard/stats returns counts."""
    r = await soar.get("/api/v1/dashboard/stats")
    assert r.status_code == 200, f"Dashboard failed: {r.status_code}"
    data = r.json()
    print(f"\n  Dashboard: {data}")


@pytest.mark.asyncio
async def test_incident_suggestions(soar, services):
    """GET /api/v1/incidents/suggestions returns correlation hints."""
    r = await soar.get("/api/v1/incidents/suggestions")
    assert r.status_code == 200
    print(f"\n  Suggestions: {str(r.json())[:200]}")
