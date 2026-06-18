"""
Shared fixtures: realistic Elasticsearch documents for each source.
These mirror actual production data structures.
"""

import os
import sys
import pytest
import asyncio

# Ensure project root is on sys.path so imports work
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


@pytest.fixture(scope="session", autouse=True)
def _init_db_once():
    """Run DB initialization (including lightweight migrations) once per test session."""
    from response.db import init_db
    asyncio.run(init_db())


# ─── Wazuh ──────────────────────────────────────────────────────────────────

@pytest.fixture
def wazuh_brute_force():
    """Wazuh: SSH brute force alert (level 10 = critical)."""
    return {
        "_id": "wazuh-001",
        "_index": "wazuh-alerts-4.x-2026.04.05",
        "rule": {
            "id": "5712",
            "name": "SSHD brute force trying to get access to the system",
            "description": "sshd: brute force attack",
            "level": 10,
            "mitre": {
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"],
                "id": ["T1110"],
            },
        },
        "agent": {"id": "001", "name": "web-server-01"},
        "data": {
            "srcip": "45.33.32.156",
            "srcuser": "root",
        },
        "full_log": "Apr  5 10:23:45 web-server-01 sshd[12345]: Failed password for root from 45.33.32.156 port 22 ssh2",
        "@timestamp": "2026-04-05T10:23:45.000Z",
    }


@pytest.fixture
def wazuh_fim_alert():
    """Wazuh: File integrity monitoring alert with syscheck hashes."""
    return {
        "_id": "wazuh-002",
        "_index": "wazuh-alerts-4.x-2026.04.05",
        "rule": {
            "id": "550",
            "name": "Integrity checksum changed",
            "description": "File modified",
            "level": 7,
            "mitre": {},
        },
        "agent": {"id": "002", "name": "db-server-01"},
        "syscheck": {
            "path": "/etc/passwd",
            "md5_after": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256_after": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "data": {},
        "full_log": "File '/etc/passwd' was modified",
        "@timestamp": "2026-04-05T11:00:00.000Z",
    }


@pytest.fixture
def wazuh_low_level():
    """Wazuh: Low severity alert (level 2 = low)."""
    return {
        "_id": "wazuh-003",
        "_index": "wazuh-alerts-4.x-2026.04.05",
        "rule": {
            "id": "530",
            "name": "Ossec agent started",
            "description": "Agent started",
            "level": 2,
        },
        "agent": {"id": "003", "name": "monitor-01"},
        "data": {},
        "full_log": "",
        "@timestamp": "2026-04-05T09:00:00.000Z",
    }


@pytest.fixture
def wazuh_windows_hash():
    """Wazuh: Windows Sysmon event with process hashes."""
    return {
        "_id": "wazuh-004",
        "_index": "wazuh-alerts-4.x-2026.04.05",
        "rule": {
            "id": "92000",
            "name": "Sysmon - Process creation",
            "description": "Process created",
            "level": 6,
        },
        "agent": {"id": "004", "name": "win-server-01"},
        "data": {
            "win": {
                "eventdata": {
                    "hashes": "SHA256=abc123def456abc123def456abc123def456abc123def456abc123def456abcd,MD5=d41d8cd98f00b204e9800998ecf8427e",
                },
            },
            "url": "http://evil.com/payload.exe",
            "srcuser": "DOMAIN\\admin",
        },
        "syscheck": {},
        "full_log": "",
        "@timestamp": "2026-04-05T12:00:00.000Z",
    }


# ─── Falco ──────────────────────────────────────────────────────────────────

@pytest.fixture
def falco_container_alert():
    """Falco: Container shell spawned (priority=Notice)."""
    return {
        "_id": "falco-001",
        "rule": "Terminal shell in container",
        "priority": "Notice",
        "output": "A shell was spawned in a container with an attached terminal (user=root container_id=abc123 shell=bash)",
        "hostname": "k8s-node-01",
        "output_fields": {
            "container.id": "abc123def456",
            "proc.name": "bash",
            "proc.cmdline": "bash -i",
            "fd.name": "/dev/pts/0",
        },
        "tags": ["container", "shell", "mitre_execution"],
        "@timestamp": "2026-04-05T10:30:00.000Z",
    }


@pytest.fixture
def falco_critical_alert():
    """Falco: Critical BPF alert (priority=Critical)."""
    return {
        "_id": "falco-002",
        "rule": "BPF Program Not Profiled",
        "priority": "Critical",
        "output": "BPF program loaded that is not part of the system profile (proc.name=unknown_bpf)",
        "hostname": "k8s-node-02",
        "output_fields": {
            "proc.name": "unknown_bpf",
        },
        "tags": [],
        "@timestamp": "2026-04-05T10:35:00.000Z",
    }


@pytest.fixture
def falco_network_alert():
    """Falco: Network alert with IP in output."""
    return {
        "_id": "falco-003",
        "rule": "Unexpected UDP Traffic",
        "priority": "Warning",
        "output": "Unexpected UDP connection from 10.0.0.5 to 8.8.8.8:53",
        "hostname": "k8s-node-01",
        "output_fields": {},
        "tags": ["network"],
        "@timestamp": "2026-04-05T10:40:00.000Z",
    }


# ─── Suricata (embedded in Filebeat) ────────────────────────────────────────

@pytest.fixture
def suricata_exploit_alert():
    """Suricata: Exploit attempt via Filebeat."""
    return {
        "_id": "suricata-001",
        "_index": "filebeat-2026.04.05",
        "fileset": {"name": "eve"},
        "suricata": {
            "eve": {
                "event_type": "alert",
                "alert": {
                    "signature": "ET EXPLOIT Apache Struts RCE",
                    "signature_id": 2024897,
                    "category": "Attempted Administrator Privilege Gain",
                    "rev": 3,
                },
                "proto": "TCP",
                "src_port": 54321,
                "dest_port": 8080,
                "http": {
                    "hostname": "target.example.com",
                    "url": "/struts2-showcase/index.action",
                },
                "dns": {},
                "tls": {},
                "fileinfo": {},
                "flow": {},
            },
        },
        "source": {"ip": "192.168.1.100"},
        "destination": {"ip": "10.0.0.50"},
        "host": {"name": "ids-sensor-01"},
        "rule": {},
        "@timestamp": "2026-04-05T10:45:00.000Z",
    }


@pytest.fixture
def suricata_dns_alert():
    """Suricata: DNS-based malware detection."""
    return {
        "_id": "suricata-002",
        "_index": "filebeat-2026.04.05",
        "fileset": {"name": "eve"},
        "suricata": {
            "eve": {
                "event_type": "alert",
                "alert": {
                    "signature": "ET MALWARE Known C2 Domain",
                    "signature_id": 2030001,
                    "category": "Malware Command and Control",
                },
                "proto": "UDP",
                "src_port": 12345,
                "dest_port": 53,
                "dns": {"query": "evil-c2.example.com"},
                "tls": {"sni": "evil-c2.example.com"},
                "http": {},
                "fileinfo": {},
                "flow": {},
            },
        },
        "source": {"ip": "10.0.0.20"},
        "destination": {"ip": "8.8.8.8"},
        "host": {"name": "ids-sensor-01"},
        "rule": {},
        "@timestamp": "2026-04-05T10:50:00.000Z",
    }


@pytest.fixture
def suricata_with_fileinfo():
    """Suricata: Alert with file hash in fileinfo."""
    return {
        "_id": "suricata-003",
        "_index": "filebeat-2026.04.05",
        "fileset": {"name": "eve"},
        "suricata": {
            "eve": {
                "event_type": "alert",
                "alert": {
                    "signature": "ET MALWARE EXE Download",
                    "signature_id": 2018959,
                    "category": "Potentially Bad Traffic",
                },
                "proto": "TCP",
                "src_port": 80,
                "dest_port": 54000,
                "dns": {},
                "tls": {},
                "http": {},
                "fileinfo": {
                    "md5": "abc123abc123abc123abc123abc123ab",
                    "sha256": "def456def456def456def456def456def456def456def456def456def456def4",
                },
                "flow": {},
            },
        },
        "source": {"ip": "5.5.5.5"},
        "destination": {"ip": "10.0.0.30"},
        "host": {"name": "ids-sensor-02"},
        "rule": {},
        "@timestamp": "2026-04-05T11:00:00.000Z",
    }


# ─── Generic Filebeat ───────────────────────────────────────────────────────

@pytest.fixture
def filebeat_generic():
    """Filebeat: Generic log alert with message."""
    return {
        "_id": "filebeat-001",
        "_index": "filebeat-2026.04.05",
        "rule": {"name": "Unauthorized access attempt", "level": 5},
        "event": {"action": "denied", "category": "authentication"},
        "source": {"ip": "172.16.0.10"},
        "destination": {"ip": "10.0.0.1"},
        "host": {"name": "app-server-01"},
        "message": "Failed login attempt for user admin from 172.16.0.10",
        "tags": ["authentication", "failure"],
        "url": {"full": "https://app.example.com/login", "domain": "app.example.com"},
        "user_agent": {"original": "Mozilla/5.0 (compatible; bot/1.0)"},
        "@timestamp": "2026-04-05T11:10:00.000Z",
    }


@pytest.fixture
def filebeat_no_title():
    """Filebeat: Alert with no obvious title fields — tests fallback chain."""
    return {
        "_id": "filebeat-002",
        "_index": "filebeat-2026.04.05",
        "rule": {},
        "event": {
            "original": '{"rule": {"name": "Extracted from original"}, "message": "backup title"}',
        },
        "host": {"name": "unknown-host"},
        "message": "",
        "tags": [],
        "@timestamp": "2026-04-05T11:20:00.000Z",
    }


@pytest.fixture
def filebeat_completely_empty():
    """Filebeat: Completely empty alert — worst case."""
    return {
        "_id": "filebeat-003",
        "_index": "filebeat-2026.04.05",
        "rule": {},
        "event": {},
        "host": {},
        "message": "",
        "tags": [],
        "@timestamp": "2026-04-05T11:30:00.000Z",
    }


@pytest.fixture
def filebeat_suricata_embedded():
    """Filebeat doc that is actually a Suricata alert — tests routing."""
    return {
        "_id": "filebeat-004",
        "_index": "filebeat-2026.04.05",
        "fileset": {"name": "eve"},
        "suricata": {
            "eve": {
                "event_type": "alert",
                "alert": {
                    "signature": "ET SCAN Nmap SYN Scan",
                    "signature_id": 2009582,
                    "category": "Attempted Information Leak",
                },
                "proto": "TCP",
                "src_port": 45000,
                "dest_port": 22,
                "dns": {},
                "tls": {},
                "http": {},
                "fileinfo": {},
                "flow": {},
            },
        },
        "source": {"ip": "192.168.1.200"},
        "destination": {"ip": "10.0.0.1"},
        "host": {"name": "ids-sensor-01"},
        "rule": {},
        "@timestamp": "2026-04-05T11:40:00.000Z",
    }


# ─── ES search response wrapper ────────────────────────────────────────────

@pytest.fixture
def make_es_response():
    """Factory to wrap docs into an ES search response."""
    def _make(docs, total=None):
        hits = []
        for doc in docs:
            hit = {
                "_id": doc.get("_id", "unknown"),
                "_index": doc.get("_index", "test-index"),
                "_source": {k: v for k, v in doc.items() if not k.startswith("_")},
            }
            hits.append(hit)
        return {
            "hits": {
                "total": {"value": total or len(docs), "relation": "eq"},
                "hits": hits,
            }
        }
    return _make


# ─── Mock FastAPI Request for direct endpoint function calls ────────────────

class _MockClient:
    host = "127.0.0.1"

class _MockHeaders:
    def __init__(self, data=None):
        self._data = data or {}
    def get(self, key, default=None):
        return self._data.get(key, default)

class MockRequest:
    """Minimal mock of starlette.requests.Request for testing endpoint functions directly."""
    def __init__(self, client_host="127.0.0.1", headers=None):
        self.client = _MockClient()
        self.client.host = client_host
        self.headers = _MockHeaders(headers or {})

@pytest.fixture
def mock_request():
    return MockRequest()
