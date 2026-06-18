"""
E2E tests for all mappers: wazuh, falco, filebeat, suricata.
Tests field mapping, IOC extraction, tag building, severity, and edge cases.
"""

import pytest
from pipeline.mappers.wazuh import map_wazuh_alert
from pipeline.mappers.falco import map_falco_alert
from pipeline.mappers.filebeat import map_filebeat_alert
from pipeline.mappers.suricata import map_suricata_alert
from pipeline.mappers import map_alert, MAPPERS


# ═══════════════════════════════════════════════════════════════════════════
#  Wazuh Mapper
# ═══════════════════════════════════════════════════════════════════════════

class TestWazuhMapper:

    def test_brute_force_fields(self, wazuh_brute_force):
        result = map_wazuh_alert(wazuh_brute_force)

        assert result["source"] == "wazuh"
        assert result["source_id"] == "wazuh-001"
        assert "brute force" in result["title"].lower()
        assert result["severity"] == "critical"  # level 10
        assert result["status"] == "new"
        assert result["hostname"] == "web-server-01"
        assert result["source_ip"] == "45.33.32.156"
        assert len(result["description"]) > 0
        assert len(result["title"]) <= 200
        assert len(result["description"]) <= 2000

    def test_brute_force_tags(self, wazuh_brute_force):
        result = map_wazuh_alert(wazuh_brute_force)
        tags = result["tags"]

        assert "wazuh-level-10" in tags
        assert "wazuh-rule-5712" in tags
        assert "mitre-tactic-Credential Access" in tags
        assert "mitre-technique-Brute Force" in tags
        assert "mitre-T1110" in tags

    def test_brute_force_iocs(self, wazuh_brute_force):
        result = map_wazuh_alert(wazuh_brute_force)
        iocs = result["iocs"]

        assert "45.33.32.156" in iocs["ip"]
        assert iocs["username"] == ["root"]

    def test_fim_hashes(self, wazuh_fim_alert):
        result = map_wazuh_alert(wazuh_fim_alert)

        assert result["severity"] == "high"  # level 7
        assert "hash" in result["iocs"]
        hashes = result["iocs"]["hash"]
        assert "d41d8cd98f00b204e9800998ecf8427e" in hashes
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in hashes

    def test_windows_hashes_and_url(self, wazuh_windows_hash):
        result = map_wazuh_alert(wazuh_windows_hash)
        iocs = result["iocs"]

        assert "hash" in iocs
        assert any(len(h) >= 32 for h in iocs["hash"])
        assert iocs["url"] == ["http://evil.com/payload.exe"]
        assert "DOMAIN\\admin" in iocs["username"]

    def test_low_level_filtered(self):
        """Wazuh alerts with level < 3 are filtered as low-value."""
        doc = {
            "_id": "wazuh-003",
            "rule": {"id": "530", "name": "Agent started", "description": "Agent started", "level": 2},
            "agent": {"id": "003", "name": "monitor-01"},
            "data": {},
            "full_log": "",
        }
        with pytest.raises(ValueError, match="Low-value alert filtered"):
            map_wazuh_alert(doc)

    def test_empty_doc_filtered(self):
        """Completely empty doc fails validation."""
        with pytest.raises(ValueError, match="missing rule/agent"):
            map_wazuh_alert({"_id": "empty"})

    def test_none_safe_fields_filtered(self):
        """Doc with None rule fails validation."""
        doc = {
            "_id": "null-test",
            "rule": None,
            "agent": None,
            "data": None,
            "syscheck": None,
        }
        with pytest.raises((ValueError, AttributeError)):
            map_wazuh_alert(doc)


# ═══════════════════════════════════════════════════════════════════════════
#  Falco Mapper
# ═══════════════════════════════════════════════════════════════════════════

class TestFalcoMapper:

    def test_container_alert_fields(self, falco_container_alert):
        result = map_falco_alert(falco_container_alert)

        assert result["source"] == "falco"
        assert result["source_id"] == "falco-001"
        assert result["title"] == "Terminal shell in container"
        assert result["severity"] == "medium"  # Notice -> medium
        assert result["hostname"] == "k8s-node-01"
        assert "shell was spawned" in result["description"]

    def test_container_tags(self, falco_container_alert):
        result = map_falco_alert(falco_container_alert)
        tags = result["tags"]

        assert "falco-priority-Notice" in tags
        assert "container" in tags
        assert "shell" in tags
        # MITRE enrichment adds technique IDs, not raw tactic names
        assert any("mitre-T" in t for t in tags)

    def test_container_iocs(self, falco_container_alert):
        result = map_falco_alert(falco_container_alert)
        iocs = result["iocs"]

        assert iocs["container_id"] == ["abc123def456"]
        assert iocs["process"] == ["bash"]
        assert iocs["filepath"] == ["/dev/pts/0"]

    def test_critical_severity(self, falco_critical_alert):
        result = map_falco_alert(falco_critical_alert)
        assert result["severity"] == "critical"

    def test_ip_from_output_regex(self):
        """Network alert may be filtered by Sigma noise rules."""
        doc = {
            "_id": "falco-003",
            "rule": "Unexpected UDP Traffic",
            "priority": "Warning",
            "output": "Unexpected UDP connection from 10.0.0.5 to 8.8.8.8:53",
            "hostname": "k8s-node-01",
            "output_fields": {},
            "tags": ["network"],
        }
        # This alert is filtered by Sigma noise rules
        with pytest.raises(ValueError, match="Noisy alert filtered"):
            map_falco_alert(doc)

    def test_empty_falco_filtered(self):
        """Empty doc fails Falco validation."""
        with pytest.raises(ValueError, match="missing priority/rule/output"):
            map_falco_alert({"_id": "empty"})


# ═══════════════════════════════════════════════════════════════════════════
#  Suricata Mapper
# ═══════════════════════════════════════════════════════════════════════════

class TestSuricataMapper:

    def test_exploit_alert_fields(self, suricata_exploit_alert):
        result = map_suricata_alert(suricata_exploit_alert)

        assert result["source"] == "suricata"
        # source_id is derived from _id by the poller, not the mapper
        assert result["title"] == "ET EXPLOIT Apache Struts RCE"
        assert result["severity"] == "critical"  # exploit category
        assert result["source_ip"] == "192.168.1.100"
        assert result["dest_ip"] == "10.0.0.50"
        assert result["hostname"] == "ids-sensor-01"

    def test_exploit_description_rich(self, suricata_exploit_alert):
        result = map_suricata_alert(suricata_exploit_alert)
        desc = result["description"]

        assert "Rule:" in desc
        assert "SID: 2024897" in desc
        assert "Category:" in desc
        assert "Flow:" in desc

    def test_exploit_tags_no_empty(self, suricata_exploit_alert):
        result = map_suricata_alert(suricata_exploit_alert)
        tags = result["tags"]

        assert "suricata" in tags
        assert "sid-2024897" in tags
        assert "proto-TCP" in tags
        assert "" not in tags  # no empty strings

    def test_exploit_iocs(self, suricata_exploit_alert):
        result = map_suricata_alert(suricata_exploit_alert)
        iocs = result["iocs"]

        assert "192.168.1.100" in iocs["ip"]
        assert "10.0.0.50" in iocs["ip"]
        assert "8080" in iocs["port"] or 8080 in iocs.get("port", [])
        assert "target.example.com" in iocs["domain"]
        assert any("/struts2-showcase" in u for u in iocs.get("url", []))

    def test_dns_alert_iocs(self, suricata_dns_alert):
        result = map_suricata_alert(suricata_dns_alert)
        iocs = result["iocs"]

        assert result["severity"] == "critical"  # command and control category
        assert "evil-c2.example.com" in iocs["domain"]
        # TLS SNI should also be captured (same domain, deduplicated)
        assert iocs["domain"].count("evil-c2.example.com") >= 1

    def test_fileinfo_hashes(self, suricata_with_fileinfo):
        result = map_suricata_alert(suricata_with_fileinfo)
        iocs = result["iocs"]

        assert "hash" in iocs
        assert "md5:abc123abc123abc123abc123abc123ab" in iocs["hash"]
        assert "sha256:def456def456def456def456def456def456def456def456def456def456def4" in iocs["hash"]

    def test_empty_category_tags(self):
        """No empty tags when category/proto are missing."""
        doc = {
            "_id": "minimal",
            "suricata": {"eve": {"alert": {"signature": "Test"}, "event_type": "alert"}},
            "host": {},
        }
        result = map_suricata_alert(doc)
        assert "" not in result["tags"]
        assert "suricata" in result["tags"]


# ═══════════════════════════════════════════════════════════════════════════
#  Filebeat Mapper (Suricata-only)
# ═══════════════════════════════════════════════════════════════════════════

class TestFilebeatMapper:

    def test_generic_filebeat_filtered(self):
        """Generic Filebeat events are rejected; only Suricata alerts pass."""
        doc = {
            "_id": "filebeat-001",
            "rule": {"name": "Unauthorized access attempt", "level": 5},
            "source": {"ip": "172.16.0.10"},
            "host": {"name": "app-server-01"},
        }
        with pytest.raises(ValueError, match="Only Suricata events are processed"):
            map_filebeat_alert(doc)

    def test_suricata_routing(self, filebeat_suricata_embedded):
        """Filebeat mapper should detect Suricata and route to suricata mapper."""
        result = map_filebeat_alert(filebeat_suricata_embedded)

        assert result["source"] == "suricata"  # routed correctly
        assert "Nmap SYN Scan" in result["title"]
        assert result["source_ip"] == "192.168.1.200"


# ═══════════════════════════════════════════════════════════════════════════
#  map_alert() dispatch
# ═══════════════════════════════════════════════════════════════════════════

class TestMapAlert:

    def test_dispatch_wazuh(self, wazuh_brute_force):
        result = map_alert("wazuh", wazuh_brute_force)
        assert result["source"] == "wazuh"

    def test_dispatch_falco(self, falco_container_alert):
        result = map_alert("falco", falco_container_alert)
        assert result["source"] == "falco"

    def test_dispatch_filebeat_suricata(self, filebeat_suricata_embedded):
        result = map_alert("filebeat", filebeat_suricata_embedded)
        assert result["source"] == "suricata"

    def test_dispatch_suricata(self, suricata_exploit_alert):
        result = map_alert("suricata", suricata_exploit_alert)
        assert result["source"] == "suricata"

    def test_unknown_source_uses_generic(self):
        doc = {"_id": "test", "foo": "bar"}
        result = map_alert("unknown_source", doc)
        assert result["source"] == "generic"

    def test_all_mappers_registered(self):
        assert set(MAPPERS.keys()) == {"wazuh", "falco", "filebeat", "suricata", "generic"}


# ═══════════════════════════════════════════════════════════════════════════
#  Output schema validation (all mappers must produce required fields)
# ═══════════════════════════════════════════════════════════════════════════

REQUIRED_FIELDS = ["source", "source_id", "title", "description", "severity",
                   "status", "source_ip", "dest_ip", "hostname", "rule_name",
                   "tags", "iocs"]

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class TestOutputSchema:

    @pytest.fixture(params=[
        "wazuh_brute_force", "wazuh_fim_alert",
        "falco_container_alert", "falco_critical_alert",
        "suricata_exploit_alert", "suricata_dns_alert",
        "filebeat_suricata_embedded",
    ])
    def mapped_alert(self, request):
        doc = request.getfixturevalue(request.param)
        source_map = {
            "wazuh": map_wazuh_alert,
            "falco": map_falco_alert,
            "suricata": map_suricata_alert,
            "filebeat": map_filebeat_alert,
        }
        # Determine which mapper to use based on fixture name
        name = request.param
        if name.startswith("wazuh"):
            return map_wazuh_alert(doc)
        elif name.startswith("falco"):
            return map_falco_alert(doc)
        elif name.startswith("suricata"):
            return map_suricata_alert(doc)
        else:
            return map_filebeat_alert(doc)

    def test_has_all_required_fields(self, mapped_alert):
        for field in REQUIRED_FIELDS:
            assert field in mapped_alert, f"Missing field: {field}"

    def test_severity_is_valid(self, mapped_alert):
        assert mapped_alert["severity"] in VALID_SEVERITIES

    def test_tags_is_list(self, mapped_alert):
        assert isinstance(mapped_alert["tags"], list)

    def test_tags_no_empty_strings(self, mapped_alert):
        assert "" not in mapped_alert["tags"]

    def test_iocs_is_dict(self, mapped_alert):
        assert isinstance(mapped_alert["iocs"], dict)

    def test_iocs_values_are_lists(self, mapped_alert):
        for key, val in mapped_alert["iocs"].items():
            assert isinstance(val, list), f"iocs[{key}] should be a list"

    def test_title_not_empty(self, mapped_alert):
        assert len(mapped_alert["title"]) > 0

    def test_title_max_length(self, mapped_alert):
        assert len(mapped_alert["title"]) <= 200

    def test_description_max_length(self, mapped_alert):
        assert len(mapped_alert["description"]) <= 2000

    def test_status_is_new(self, mapped_alert):
        assert mapped_alert["status"] == "new"
