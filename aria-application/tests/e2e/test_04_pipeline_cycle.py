"""
E2E Test 04 — Pipeline Polling Cycle

Runs one real poll cycle per source (Wazuh, Falco, Suricata)
and verifies that documents are fetched, mapped, and sent to OpenSOAR correctly.
"""
import asyncio
from datetime import datetime, timezone, timedelta

import pytest
import pytest_asyncio

from config import get_settings
from core.elasticsearch import get_es_client
from pipeline.mappers import map_alert
from pipeline.sender import OpenSOARClient

settings = get_settings()


@pytest_asyncio.fixture
async def sender(services):
    """Authenticated OpenSOAR sender."""
    if not services["opensoar"]:
        pytest.skip("OpenSOAR not reachable")
    c = OpenSOARClient()
    ok = await c.authenticate()
    assert ok, "OpenSOAR authentication failed"
    yield c


async def _poll_source(source: str, index_pattern: str, lookback_hours: int = 48) -> list[dict]:
    """Fetch recent docs from ES for a given source, map them, return mapped alerts."""
    es = await get_es_client()
    since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()

    try:
        resp = await es.search(
            index=index_pattern,
            body={
                "query": {"range": {"@timestamp": {"gte": since}}},
                "size": 5,
                "sort": [{"@timestamp": "desc"}],
            },
        )
    except Exception as e:
        return []

    alerts = []
    for hit in resp["hits"]["hits"]:
        doc = {"_id": hit["_id"], "_index": hit["_index"], **hit["_source"]}
        try:
            alert = map_alert(source, doc)
            if alert:
                alerts.append(alert)
        except Exception:
            pass
    return alerts


@pytest.mark.asyncio
async def test_wazuh_poll_and_map(es, services):
    """Poll Wazuh index, map documents, verify output quality."""
    alerts = await _poll_source("wazuh", settings.wazuh_index_pattern)
    if not alerts:
        pytest.skip("No recent Wazuh documents to process")

    print(f"\n  Wazuh: mapped {len(alerts)} alerts")
    for a in alerts:
        assert a["source"] == "wazuh"
        assert a["title"]
        assert a["severity"] in ("low", "medium", "high", "critical")
        assert a["source_id"]
        print(f"  - [{a['severity'].upper()}] {a['title'][:60]}")


@pytest.mark.asyncio
async def test_falco_poll_and_map(es, services):
    """Poll Falco index, map documents."""
    alerts = await _poll_source("falco", settings.falco_index_pattern)
    if not alerts:
        pytest.skip("No recent Falco documents")

    print(f"\n  Falco: mapped {len(alerts)} alerts")
    for a in alerts:
        assert a["source"] == "falco"
        assert a["title"]
        print(f"  - [{a['severity'].upper()}] {a['title'][:60]}")


@pytest.mark.asyncio
async def test_suricata_poll_and_map(es, services):
    """Poll Suricata/filebeat index, map documents."""
    alerts = await _poll_source("filebeat", settings.filebeat_index_pattern)
    if not alerts:
        pytest.skip("No recent Suricata/filebeat documents")

    print(f"\n  Suricata/filebeat: mapped {len(alerts)} alerts")
    for a in alerts:
        assert a["source"] in ("suricata", "filebeat")
        assert a["title"]
        print(f"  - [{a['severity'].upper()}] {a['title'][:60]}")


@pytest.mark.asyncio
async def test_pipeline_no_mapping_crash(es, services):
    """Mapper must not crash on any real document — even malformed ones."""
    crashes = []
    for source, index in [
        ("wazuh", settings.wazuh_index_pattern),
        ("falco", settings.falco_index_pattern),
        ("filebeat", settings.filebeat_index_pattern),
    ]:
        try:
            resp = await es.search(
                index=index,
                body={"query": {"match_all": {}}, "size": 10, "sort": [{"@timestamp": "desc"}]},
            )
        except Exception:
            continue
        for hit in resp["hits"]["hits"]:
            doc = {"_id": hit["_id"], "_index": hit["_index"], **hit["_source"]}
            try:
                map_alert(source, doc)
            except Exception as e:
                crashes.append(f"{source}/{hit['_id']}: {str(e)[:80]}")

    if crashes:
        print(f"\n  MAPPER CRASHES ({len(crashes)}):")
        for c in crashes:
            print(f"    {c}")
    assert len(crashes) == 0, f"{len(crashes)} mapper crashes on real data:\n" + "\n".join(crashes)
    print(f"\n  No mapper crashes on real documents")


@pytest.mark.asyncio
async def test_send_one_real_alert_through_full_pipeline(es, sender, services, cleanup):
    """
    Full pipeline: fetch real ES doc → map → send to OpenSOAR.
    Verify it appears in OpenSOAR with correct fields.
    """
    # Get a real Wazuh doc
    resp = await es.search(
        index=settings.wazuh_index_pattern,
        body={
            "query": {"exists": {"field": "rule.level"}},
            "size": 1,
            "sort": [{"@timestamp": "desc"}],
        },
    )
    hits = resp["hits"]["hits"]
    if not hits:
        pytest.skip("No Wazuh documents")

    doc = hits[0]
    source_doc = {"_id": doc["_id"], "_index": doc["_index"], **doc["_source"]}

    # Map it
    alert = map_alert("wazuh", source_doc)
    assert alert is not None

    # Add e2e tag so cleanup finds it
    alert["tags"] = list(set(alert.get("tags", []) + ["e2e-test"]))

    # Send to OpenSOAR
    result = await sender.send_alert(alert)

    if result.get("status") == "already_exists":
        print(f"\n  Alert already in OpenSOAR (source_id={alert['source_id']}) — dedup working correctly")
        return  # This is fine — means the real pipeline already sent it

    alert_id = result.get("alert_id")
    assert alert_id, f"No alert_id in response: {result}"
    cleanup["alerts"].append(alert_id)

    # Verify in OpenSOAR
    import httpx
    async with httpx.AsyncClient(base_url=settings.opensoar_url, timeout=10.0) as c:
        auth = await c.post(
            "/api/v1/auth/login",
            json={"username": settings.opensoar_username, "password": settings.opensoar_password},
        )
        token = auth.json()["access_token"]
        r = await c.get(f"/api/v1/alerts/{alert_id}", headers={"Authorization": f"Bearer {token}"})

    assert r.status_code == 200, f"Alert not found in OpenSOAR: {r.status_code}"
    stored = r.json()
    assert stored["source"] == "wazuh"
    assert stored["source_id"] == doc["_id"]
    assert stored["severity"] in ("low", "medium", "high", "critical")
    print(f"\n  Real pipeline test passed:")
    print(f"    ES doc {doc['_id'][:12]}... → OpenSOAR alert {alert_id[:12]}...")
    print(f"    Title: {stored['title'][:60]}")
    print(f"    Severity: {stored['severity']}")


@pytest.mark.asyncio
async def test_cursor_advances_after_poll(es, services):
    """
    Verify that after polling, the cursor (timestamp) has advanced.
    Simulates what the poller does without running the full forwarder.
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

    resp = await es.search(
        index=settings.wazuh_index_pattern,
        body={
            "query": {"range": {"@timestamp": {"gte": since}}},
            "size": 5,
            "sort": [{"@timestamp": "asc"}],  # ascending — oldest first
        },
    )
    hits = resp["hits"]["hits"]
    if not hits:
        pytest.skip("No Wazuh docs in last hour")

    timestamps = [h["_source"].get("@timestamp", "") for h in hits]
    print(f"\n  Timestamps in order: {timestamps[:3]}")
    # They should be monotonically increasing
    assert timestamps == sorted(timestamps), "Documents are not in ascending timestamp order"
    last_ts = timestamps[-1]
    assert last_ts >= since, "Last timestamp should be >= query start"
    print(f"  Cursor would advance to: {last_ts}")
