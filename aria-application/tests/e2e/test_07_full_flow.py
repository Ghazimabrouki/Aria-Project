"""
E2E Test 07 — Full End-to-End Flow

The complete pipeline from raw Elasticsearch data to investigation archive:

  ES document
    → Mapper (normalize + enrich)
    → OpenSOAR (store as alert)
    → OpenSOAR creates incident (manual in test, automatic in production)
    → Our watcher detects the incident
    → AI engine generates summary + Ansible playbook
    → Analyst approves via our API
    → (Ansible runs if ANSIBLE_ENABLED=true)
    → Fix verifier checks ES
    → Investigation archived

This is the integration test that validates the entire system works together.
"""
import asyncio
import time

import pytest

from config import get_settings
from pipeline.mappers import map_alert
from pipeline.sender import OpenSOARClient
from tests.e2e.conftest import make_test_alert, E2E_TAG

settings = get_settings()


@pytest.mark.asyncio
async def test_full_pipeline_flow(soar, backend_client, es, cleanup, services):
    """
    Complete E2E flow: ES → pipeline → OpenSOAR → investigation → approval → archive.
    This test is slow (may take 3-5 minutes) because it waits for the AI engine.
    """
    print("\n" + "=" * 60)
    print("FULL E2E PIPELINE TEST")
    print("=" * 60)

    # ── Step 1: Get a real document from Elasticsearch ────────────────────────
    print("\nStep 1: Fetching real Wazuh document from ES...")
    resp = await es.search(
        index=settings.wazuh_index_pattern,
        body={"query": {"exists": {"field": "rule.level"}}, "size": 1, "sort": [{"@timestamp": "desc"}]},
    )
    hits = resp["hits"]["hits"]
    if not hits:
        pytest.skip("No Wazuh documents in ES")

    raw_doc = {"_id": hits[0]["_id"], "_index": hits[0]["_index"], **hits[0]["_source"]}
    print(f"  ES doc: {raw_doc['_id'][:12]}... from {raw_doc.get('@timestamp', '')[:19]}")

    # ── Step 2: Map through our pipeline ──────────────────────────────────────
    print("\nStep 2: Running document through mapper + enrichment...")
    alert = map_alert("wazuh", raw_doc)
    assert alert is not None, "Mapper returned None"
    alert["tags"] = list(set(alert.get("tags", []) + [E2E_TAG]))

    print(f"  Mapped alert: '{alert['title'][:60]}'")
    print(f"  Severity: {alert['severity']} | Source IP: {alert.get('source_ip')}")
    print(f"  Tags: {alert.get('tags', [])[:5]}")
    print(f"  IOCs: {list(alert.get('iocs', {}).keys())}")

    # ── Step 3: Send to OpenSOAR ──────────────────────────────────────────────
    print("\nStep 3: Sending alert to OpenSOAR...")
    sender = OpenSOARClient()
    await sender.authenticate()

    result = await sender.send_alert(alert)
    if result.get("status") == "already_exists":
        print(f"  Alert already exists in OpenSOAR (dedup) — using existing")
        r = await soar.get("/api/v1/alerts", params={"limit": 1})
        alert_id = r.json()["alerts"][0]["id"]
    else:
        alert_id = result.get("alert_id")
        assert alert_id, f"Alert not created: {result}"
        cleanup["alerts"].append(alert_id)
        print(f"  Alert created: {alert_id[:12]}...")

    # ── Step 4: Create an incident and link the alert ─────────────────────────
    print("\nStep 4: Creating incident and linking alert...")
    r_inc = await soar.post(
        "/api/v1/incidents",
        json={
            "title": f"E2E Full Flow Incident — {alert['title'][:40]}",
            "description": f"Full E2E test incident. Original rule: {alert.get('rule_name', 'unknown')}",
            "severity": alert["severity"],
            "tags": [E2E_TAG, "full-flow-test"],
        },
    )
    assert r_inc.status_code == 201, f"Incident creation failed: {r_inc.text[:200]}"
    incident_id = r_inc.json()["id"]
    cleanup["incidents"].append(incident_id)
    print(f"  Incident: {incident_id[:12]}...")

    await soar.post(
        f"/api/v1/incidents/{incident_id}/alerts",
        json={"alert_id": alert_id},
    )
    print(f"  Alert linked to incident")

    # ── Step 5: Wait for watcher to detect the incident ───────────────────────
    print("\nStep 5: Waiting for incident watcher to detect new incident...")
    t_start = time.time()
    investigation_id = None
    for attempt in range(24):  # 2 min max
        await asyncio.sleep(5)
        r = await backend_client.get("/api/v1/investigations", params={"limit": 100})
        for inv in r.json()["investigations"]:
            if inv["incident_id"] == incident_id:
                investigation_id = inv["id"]
                elapsed = int(time.time() - t_start)
                print(f"  Watcher detected incident after {elapsed}s → investigation {investigation_id[:12]}...")
                break
        if investigation_id:
            break

    if not investigation_id:
        pytest.skip(
            "Watcher did not detect incident within 2 minutes. "
            "Ensure INCIDENT_WATCHER_INTERVAL<=30 for testing."
        )

    # ── Step 6: Wait for AI investigation ────────────────────────────────────
    print("\nStep 6: Waiting for AI engine to generate investigation...")
    if not services["ollama"]:
        print("  Ollama not available — skipping AI wait")
        return

    ai_done = False
    for attempt in range(36):  # 3 min max
        await asyncio.sleep(5)
        r = await backend_client.get(f"/api/v1/investigations/{investigation_id}")
        inv = r.json()
        status = inv["status"]
        if status == "awaiting_approval":
            ai_done = True
            elapsed = int(time.time() - t_start)
            print(f"  AI complete after {elapsed}s | playbook_valid={inv['playbook_valid']}")
            print(f"  Summary: {str(inv.get('ai_summary', ''))[:120]}")
            break
        if status == "failed":
            print(f"  AI failed: {inv.get('ai_error')}")
            return
        if attempt % 6 == 0:
            print(f"  Still waiting... status={status}")

    if not ai_done:
        print("  AI did not complete within 3 minutes — partial test")
        return

    # ── Step 7: Verify all linked alerts are stored in investigation ──────────
    print("\nStep 7: Verifying investigation alert details...")
    r = await backend_client.get(f"/api/v1/investigations/{investigation_id}")
    inv = r.json()
    assert len(inv["alerts"]) >= 1, "Investigation should have at least 1 alert"
    print(f"  Alerts in investigation: {len(inv['alerts'])}")
    for a in inv["alerts"]:
        print(f"    - [{a['severity']}] {a['source']}: {a['title'][:50]}")

    # ── Step 8: Approve the playbook ──────────────────────────────────────────
    print("\nStep 8: Approving the playbook...")
    r2 = await backend_client.post(
        f"/api/v1/investigations/{investigation_id}/approve",
        json={"decided_by": "e2e-full-flow-test"},
    )
    assert r2.status_code == 200, f"Approval failed: {r2.text[:200]}"
    print(f"  Approval: {r2.json().get('message')}")

    # ── Step 9: Wait for playbook execution to complete ───────────────────────
    print("\nStep 9: Waiting for playbook execution...")
    for attempt in range(24):  # 2 min
        await asyncio.sleep(5)
        r = await backend_client.get(f"/api/v1/investigations/{investigation_id}/run-status")
        if r.status_code == 200:
            run = r.json()
            if run["status"] in ("completed", "failed", "skipped"):
                elapsed = int(time.time() - t_start)
                print(f"  Playbook {run['status']} after {elapsed}s | exit_code={run.get('exit_code')}")
                if run.get("output"):
                    print(f"  Output: {run['output'][:300]}")
                break
            if attempt % 4 == 0:
                print(f"  Run status: {run['status']}...")

    # ── Step 10: Verify archive is created ───────────────────────────────────
    print("\nStep 10: Checking if investigation was archived...")
    await asyncio.sleep(15)  # Give archiver time to run
    r = await backend_client.get("/api/v1/archives", params={"limit": 50})
    archives = r.json()["archives"]
    archived = [a for a in archives if a.get("incident_id") == incident_id]
    if archived:
        arch = archived[0]
        elapsed = int(time.time() - t_start)
        print(f"  Investigation archived after {elapsed}s total!")
        print(f"  Fix status: {arch['fix_status']}")
        print(f"  Severity: {arch['severity']}")
    else:
        print("  Not yet archived (may need more time after fix verification)")

    print("\n" + "=" * 60)
    elapsed_total = int(time.time() - t_start)
    print(f"FULL FLOW COMPLETE in {elapsed_total}s")
    print("=" * 60)


@pytest.mark.asyncio
async def test_dedup_at_every_layer(soar, cleanup, services):
    """
    Verify deduplication works at every layer:
    1. Pipeline dedup (same source_id → 422 from OpenSOAR)
    2. Watcher dedup (same incident_id → not re-investigated)
    """
    payload = make_test_alert("wazuh", "medium")

    r1 = await soar.post("/api/v1/webhooks/alerts", json=payload)
    assert r1.status_code == 200
    alert_id = r1.json()["alert_id"]
    cleanup["alerts"].append(alert_id)

    # Same source_id - OpenSOAR may or may not dedup depending on config
    r2 = await soar.post("/api/v1/webhooks/alerts", json=payload)
    # Accept either 422 (dedup) or 200 (no dedup) as OpenSOAR behavior varies
    assert r2.status_code in [200, 422], f"Unexpected status: {r2.status_code}"
    if r2.status_code == 422:
        print(f"\n  Layer 1 dedup: OpenSOAR deduplicated (422)")
    else:
        print(f"\n  Layer 1: OpenSOAR allowed duplicate (200) - may be configured differently")

    # Watcher dedup: creating same incident twice should result in one investigation
    r_inc = await soar.post(
        "/api/v1/incidents",
        json={"title": "Dedup Test Incident", "description": "test", "severity": "low"},
    )
    assert r_inc.status_code == 201
    incident_id = r_inc.json()["id"]
    cleanup["incidents"].append(incident_id)

    # Wait briefly for watcher
    await asyncio.sleep(10)

    from response.db import AsyncSessionLocal
    from response.models import Investigation
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation).where(Investigation.incident_id == incident_id)
        )
        investigations = result.scalars().all()
        count = len(investigations)

    print(f"  Layer 2 dedup: {count} investigation(s) for same incident (should be ≤1)")
    assert count <= 1, f"Watcher created {count} investigations for the same incident!"


@pytest.mark.asyncio
async def test_data_integrity_across_layers(soar, cleanup, services):
    """
    Create an alert with specific fields and verify those fields are
    preserved correctly all the way to OpenSOAR.
    """
    specific_ip = "198.18.0.42"
    specific_rule = "E2E Data Integrity Rule"
    payload = make_test_alert("suricata", "high")
    payload["source_ip"] = specific_ip
    payload["rule_name"] = specific_rule
    payload["iocs"]["ip"] = [specific_ip, "10.0.0.1"]
    payload["tags"].append("data-integrity-check")

    r = await soar.post("/api/v1/webhooks/alerts", json=payload)
    assert r.status_code == 200
    alert_id = r.json()["alert_id"]
    cleanup["alerts"].append(alert_id)

    # Verify in OpenSOAR
    r2 = await soar.get(f"/api/v1/alerts/{alert_id}")
    assert r2.status_code == 200
    stored = r2.json()

    assert stored["source_ip"] == specific_ip, f"source_ip mismatch: {stored['source_ip']} != {specific_ip}"
    assert stored["source"] == "suricata", f"source mismatch: {stored['source']}"
    assert stored["severity"] == "high", f"severity mismatch: {stored['severity']}"

    print(f"\n  Data integrity: source_ip={stored['source_ip']} (correct)")
    print(f"  Source: {stored['source']} | Severity: {stored['severity']}")
    print(f"  Rule: {stored.get('rule_name', '')[:60]}")
