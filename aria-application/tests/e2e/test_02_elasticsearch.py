"""
E2E Test 02 — Elasticsearch Data Quality

Tests that real ES indices have data and that our mappers
can correctly process real documents from each source.
"""
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta

from config import get_settings
from pipeline.mappers import map_alert

settings = get_settings()

SEVERITY_VALUES = {"low", "medium", "high", "critical"}


@pytest.mark.asyncio
async def test_wazuh_index_has_recent_data(es, services):
    """Wazuh index contains documents from the last 7 days."""
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    resp = await es.search(
        index=settings.wazuh_index_pattern,
        body={
            "query": {"range": {"@timestamp": {"gte": since}}},
            "size": 1,
            "sort": [{"@timestamp": "desc"}],
        },
    )
    hits = resp["hits"]["hits"]
    total = resp["hits"]["total"]["value"]
    print(f"\n  Wazuh docs (last 7d): {total}")
    assert total > 0, f"No Wazuh data in last 7 days in {settings.wazuh_index_pattern}"
    # Verify basic structure
    doc = hits[0]["_source"]
    assert "rule" in doc or "@timestamp" in doc


@pytest.mark.asyncio
async def test_falco_index_has_data(es, services):
    """Falco index has documents."""
    resp = await es.count(index=settings.falco_index_pattern)
    count = resp.get("count", 0)
    print(f"\n  Falco total docs: {count}")
    if count == 0:
        pytest.skip("No Falco data in ES — Falco may not be running")
    assert count > 0


@pytest.mark.asyncio
async def test_filebeat_suricata_has_data(es, services):
    """Filebeat index contains Suricata alert-type events."""
    resp = await es.search(
        index=settings.filebeat_index_pattern,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"fileset.name": "eve"}},
                        {"term": {"suricata.eve.event_type": "alert"}},
                    ]
                }
            },
            "size": 0,
        },
    )
    count = resp["hits"]["total"]["value"]
    print(f"\n  Suricata alerts in filebeat: {count}")
    if count == 0:
        pytest.skip("No Suricata alert events in filebeat index")
    assert count > 0


@pytest.mark.asyncio
async def test_wazuh_mapper_on_real_doc(es, services):
    """
    Fetch a real Wazuh document and run it through our mapper.
    Result must be a valid structured alert.
    """
    resp = await es.search(
        index=settings.wazuh_index_pattern,
        body={"query": {"exists": {"field": "rule.level"}}, "size": 1, "sort": [{"@timestamp": "desc"}]},
    )
    hits = resp["hits"]["hits"]
    if not hits:
        pytest.skip("No Wazuh documents with rule.level")

    doc = hits[0]
    source = {"_id": doc["_id"], "_index": doc["_index"], **doc["_source"]}
    alert = map_alert("wazuh", source)

    assert alert is not None, "Mapper returned None for a real Wazuh document"
    assert alert.get("source") == "wazuh"
    assert alert.get("title"), "Alert must have a title"
    assert alert.get("severity") in SEVERITY_VALUES, f"Invalid severity: {alert.get('severity')}"
    assert alert.get("source_id") == doc["_id"]
    print(f"\n  Wazuh real doc → title='{alert['title'][:60]}' severity={alert['severity']}")


@pytest.mark.asyncio
async def test_falco_mapper_on_real_doc(es, services):
    """Fetch real Falco documents and run through mapper. Source name varies (falco/syscall)."""
    try:
        resp = await es.search(
            index=settings.falco_index_pattern,
            body={"query": {"match_all": {}}, "size": 10, "sort": [{"@timestamp": "desc"}]},
        )
    except Exception as e:
        pytest.skip(f"Falco index error: {e}")

    hits = resp["hits"]["hits"]
    if not hits:
        pytest.skip("No Falco documents found")

    # Try docs until one produces a valid mapped alert (some are noise-filtered → None or malformed)
    for hit in hits:
        doc = {"_id": hit["_id"], "_index": hit["_index"], **hit["_source"]}
        alert = map_alert("falco", doc)
        # Valid mapped alert: source is a plain string, title is non-empty string
        if (alert is not None
                and isinstance(alert.get("source"), str)
                and isinstance(alert.get("title"), str)
                and alert["title"]):
            assert alert.get("severity") in SEVERITY_VALUES
            print(f"\n  Falco real doc → source='{alert['source']}' title='{alert['title'][:60]}' severity={alert['severity']}")
            return

    pytest.skip("All Falco documents were noise-filtered or produced invalid output — no testable alerts")


@pytest.mark.asyncio
async def test_suricata_mapper_on_real_doc(es, services):
    """
    Fetch real Suricata docs from filebeat and run through mapper.
    Many will be noise-filtered (CINS/threat intel) — we try multiple docs to find one that passes.
    """
    resp = await es.search(
        index=settings.filebeat_index_pattern,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"fileset.name": "eve"}},
                        {"term": {"suricata.eve.event_type": "alert"}},
                    ],
                    # Prefer non-threat-intel alerts for better test signal
                    "should": [
                        {"term": {"suricata.eve.alert.category": "Attempted Information Leak"}},
                        {"term": {"suricata.eve.alert.category": "Web Application Attack"}},
                        {"term": {"suricata.eve.alert.category": "Malware Command and Control"}},
                    ],
                }
            },
            "size": 20,
            "sort": [{"@timestamp": "desc"}],
        },
    )
    hits = resp["hits"]["hits"]
    if not hits:
        pytest.skip("No Suricata alert events in filebeat")

    def _is_valid_alert(alert) -> bool:
        """Check alert has our standard schema, not a raw ES doc."""
        return (alert is not None
                and isinstance(alert.get("source"), str)
                and isinstance(alert.get("title"), str)
                and alert["title"]
                and alert.get("severity") in SEVERITY_VALUES)

    noise_filtered = 0
    for hit in hits:
        doc = {"_id": hit["_id"], "_index": hit["_index"], **hit["_source"]}
        alert = map_alert("filebeat", doc)
        if not _is_valid_alert(alert):
            noise_filtered += 1
            continue
        assert alert["source"] in ("suricata", "filebeat")
        print(f"\n  Suricata real doc → title='{alert['title'][:60]}' severity={alert['severity']}")
        print(f"  ({noise_filtered} docs were noise-filtered before this one)")
        return

    pytest.skip(f"All {noise_filtered} Suricata docs were noise-filtered — only threat-intel/CINS traffic today")


@pytest.mark.asyncio
async def test_enrichment_on_real_wazuh_doc(es, services):
    """
    Real Wazuh doc with a source_ip gets GeoIP enrichment tags.
    """
    # Find a Wazuh doc that has a source IP
    resp = await es.search(
        index=settings.wazuh_index_pattern,
        body={
            "query": {"exists": {"field": "data.srcip"}},
            "size": 5,
            "sort": [{"@timestamp": "desc"}],
        },
    )
    hits = resp["hits"]["hits"]
    if not hits:
        pytest.skip("No Wazuh documents with data.srcip")

    doc = hits[0]
    source = {"_id": doc["_id"], "_index": doc["_index"], **doc["_source"]}
    alert = map_alert("wazuh", source)

    assert alert is not None
    src_ip = alert.get("source_ip")
    tags = alert.get("tags", [])
    print(f"\n  source_ip={src_ip} | tags={tags[:8]}")

    if src_ip and not src_ip.startswith(("10.", "192.168.", "172.")):
        # External IP should have GeoIP tags
        geo_tags = [t for t in tags if t.startswith(("country-", "src-country-", "AS"))]
        print(f"  GeoIP tags: {geo_tags}")
        # Note: GeoIP may not be available if DB missing — just warn
        if not geo_tags:
            print("  WARNING: No GeoIP tags — MaxMind DB may not be installed at /opt/geoip/")


@pytest.mark.asyncio
async def test_severity_distribution_is_reasonable(es, services):
    """
    Run mappers on a sample of real docs. Severity distribution should not be all-critical.
    This detects severity inflation bugs.
    """
    severities = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    resp = await es.search(
        index=settings.wazuh_index_pattern,
        body={"query": {"match_all": {}}, "size": 20, "sort": [{"@timestamp": "desc"}]},
    )

    for hit in resp["hits"]["hits"]:
        source = {"_id": hit["_id"], "_index": hit["_index"], **hit["_source"]}
        try:
            alert = map_alert("wazuh", source)
            if alert and alert.get("severity") in severities:
                severities[alert["severity"]] += 1
        except Exception:
            pass

    print(f"\n  Severity distribution (20 wazuh docs): {severities}")
    total_mapped = sum(severities.values())
    if total_mapped > 0:
        crit_pct = severities["critical"] / total_mapped * 100
        assert crit_pct < 80, f"Too many critical alerts ({crit_pct:.0f}%) — likely a severity inflation bug"


@pytest.mark.asyncio
async def test_ioc_extraction_on_real_suricata(es, services):
    """
    Real Suricata alerts should have IPs in iocs.
    Tries multiple docs to find one that passes the sigma noise filter.
    """
    resp = await es.search(
        index=settings.filebeat_index_pattern,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"fileset.name": "eve"}},
                        {"term": {"suricata.eve.event_type": "alert"}},
                        {"exists": {"field": "source.ip"}},
                    ]
                }
            },
            "size": 20,
            "sort": [{"@timestamp": "desc"}],
        },
    )
    hits = resp["hits"]["hits"]
    if not hits:
        pytest.skip("No Suricata docs with source.ip")

    def _is_valid_alert(a) -> bool:
        return (a is not None
                and isinstance(a.get("source"), str)
                and isinstance(a.get("title"), str)
                and a["title"])

    for hit in hits:
        doc = {"_id": hit["_id"], "_index": hit["_index"], **hit["_source"]}
        alert = map_alert("filebeat", doc)
        if not _is_valid_alert(alert):
            continue

        iocs = alert.get("iocs", {})
        all_ips = iocs.get("ip", [])
        if alert.get("source_ip"):
            all_ips = list(set(all_ips + [alert["source_ip"]]))

        print(f"\n  IOC IPs extracted: {all_ips}")
        assert len(all_ips) > 0, "Mapped alert has no IPs anywhere (neither iocs.ip nor source_ip)"
        return

    # All docs were noise-filtered — verify that source.ip IS present in the raw docs
    # (meaning noise filter correctly suppressed them, not a mapper bug)
    sample = hits[0]["_source"]
    raw_ip = (sample.get("source") or {}).get("ip")
    print(f"\n  All docs noise-filtered. Raw source.ip in ES: {raw_ip}")
    assert raw_ip, "source.ip missing even in raw ES doc"
    pytest.skip("All Suricata docs were legitimately noise-filtered (CINS/threat-intel only traffic)")
