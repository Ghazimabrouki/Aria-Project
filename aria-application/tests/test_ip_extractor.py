"""
Tests for IP extraction across all sources and fallback mechanisms.
"""

import pytest
from pipeline.mappers.ip_extractor import extract_ips


class TestWazuhIPs:

    def test_top_level_fields(self):
        doc = {"src_ip": "1.1.1.1", "dest_ip": "2.2.2.2"}
        src, dst = extract_ips(doc, "wazuh")
        assert src == "1.1.1.1"
        assert dst == "2.2.2.2"

    def test_data_nested_fields(self):
        doc = {"data": {"srcip": "3.3.3.3", "dstip": "4.4.4.4"}}
        src, dst = extract_ips(doc, "wazuh")
        assert src == "3.3.3.3"
        assert dst == "4.4.4.4"

    def test_regex_fallback_from_full_log(self):
        doc = {"full_log": "Connection from 5.5.5.5 to server port 22"}
        src, dst = extract_ips(doc, "wazuh")
        assert src == "5.5.5.5"
        assert dst is None

    def test_top_level_takes_priority(self):
        doc = {
            "src_ip": "1.1.1.1",
            "data": {"srcip": "9.9.9.9"},
            "full_log": "from 8.8.8.8",
        }
        src, _ = extract_ips(doc, "wazuh")
        assert src == "1.1.1.1"

    def test_no_ips(self):
        src, dst = extract_ips({}, "wazuh")
        assert src is None
        assert dst is None


class TestFalcoIPs:

    def test_from_output_regex(self):
        doc = {"output": "connection from 10.0.0.5 to remote host"}
        src, dst = extract_ips(doc, "falco")
        assert src == "10.0.0.5"

    def test_from_output_fields(self):
        doc = {
            "output_fields": {"fd.sip": "192.168.1.1", "other": "not_an_ip"},
        }
        src, dst = extract_ips(doc, "falco")
        assert src == "192.168.1.1"

    def test_explicit_source_ip(self):
        doc = {"source_ip": "7.7.7.7", "output": "from 8.8.8.8"}
        src, dst = extract_ips(doc, "falco")
        assert src == "7.7.7.7"  # explicit takes priority

    def test_no_ips_container_event(self):
        doc = {"output": "shell spawned in container", "output_fields": {"proc.name": "bash"}}
        src, dst = extract_ips(doc, "falco")
        assert src is None
        assert dst is None


class TestFilebeatIPs:

    def test_ecs_format(self):
        doc = {"source": {"ip": "10.0.0.1"}, "destination": {"ip": "10.0.0.2"}}
        src, dst = extract_ips(doc, "filebeat")
        assert src == "10.0.0.1"
        assert dst == "10.0.0.2"

    def test_flat_fields(self):
        doc = {"source_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
        src, dst = extract_ips(doc, "filebeat")
        assert src == "1.1.1.1"
        assert dst == "2.2.2.2"

    def test_regex_from_message(self):
        doc = {"message": "Failed login from 192.168.1.50 to 10.0.0.1"}
        src, dst = extract_ips(doc, "filebeat")
        assert src == "192.168.1.50"
        assert dst == "10.0.0.1"

    def test_source_is_string_not_dict(self):
        """Handle case where 'source' is a string, not a dict."""
        doc = {"source": "some_source_name"}
        src, dst = extract_ips(doc, "filebeat")
        assert src is None


class TestSuricataIPs:

    def test_ecs_format(self):
        doc = {"source": {"ip": "192.168.1.100"}, "destination": {"ip": "10.0.0.50"}}
        src, dst = extract_ips(doc, "suricata")
        assert src == "192.168.1.100"
        assert dst == "10.0.0.50"

    def test_eve_flow_fallback(self):
        doc = {"suricata": {"eve": {"flow": {"src_ip": "3.3.3.3", "dest_ip": "4.4.4.4"}}}}
        src, dst = extract_ips(doc, "suricata")
        assert src == "3.3.3.3"
        assert dst == "4.4.4.4"

    def test_ecs_takes_priority_over_flow(self):
        doc = {
            "source": {"ip": "1.1.1.1"},
            "destination": {"ip": "2.2.2.2"},
            "suricata": {"eve": {"flow": {"src_ip": "9.9.9.9"}}},
        }
        src, dst = extract_ips(doc, "suricata")
        assert src == "1.1.1.1"
        assert dst == "2.2.2.2"
