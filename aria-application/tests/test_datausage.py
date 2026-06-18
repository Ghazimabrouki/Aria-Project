"""
Comprehensive tests for pipeline/datausage/ — all OpenSOAR API integrations + ticketing.
"""

import asyncio
import os
import sys
import json
import pytest
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ─── Health Monitor ─────────────────────────────────────────────────────────

class TestHealthMonitor:
    def test_circuit_breaker_initial_state(self):
        from pipeline.datausage.health_monitor import CircuitBreaker
        cb = CircuitBreaker()
        assert cb.state == "closed"
        assert cb.failure_count == 0
        assert not cb.is_open

    def test_circuit_breaker_opens_after_threshold(self):
        from pipeline.datausage.health_monitor import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "closed"
        cb.record_failure()
        assert cb.state == "open"
        assert cb.is_open

    def test_circuit_breaker_resets_on_success(self):
        from pipeline.datausage.health_monitor import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.failure_count == 0
        assert cb.state == "closed"

    def test_circuit_breaker_half_open_recovery(self):
        from pipeline.datausage.health_monitor import CircuitBreaker
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        assert cb.state == "open"
        time.sleep(0.02)
        _ = cb.is_open
        assert cb.state == "half-open"
        cb.record_success()
        assert cb.state == "closed"

    def test_health_result_dataclass(self):
        from pipeline.datausage.health_monitor import HealthCheckResult
        r = HealthCheckResult(timestamp=1.0, latency_ms=42.5, healthy=True, status_code=200)
        assert r.healthy is True
        assert r.latency_ms == 42.5

    def test_stats_empty(self):
        from pipeline.datausage.health_monitor import HealthMonitor
        hm = HealthMonitor()
        stats = hm.get_stats()
        assert stats["status"] == "unknown"
        assert stats["checks"] == 0

    def test_stats_with_history(self):
        from pipeline.datausage.health_monitor import HealthMonitor, HealthCheckResult
        hm = HealthMonitor()
        hm._history.append(HealthCheckResult(timestamp=time.time(), latency_ms=10.0, healthy=True, status_code=200))
        hm._history.append(HealthCheckResult(timestamp=time.time(), latency_ms=20.0, healthy=True, status_code=200))
        hm._history.append(HealthCheckResult(timestamp=time.time(), latency_ms=50.0, healthy=False, status_code=500))
        stats = hm.get_stats()
        assert stats["checks"] == 3
        assert stats["healthy"] == 2
        assert stats["unhealthy"] == 1
        assert stats["uptime_pct"] == pytest.approx(66.67, abs=0.1)
        assert "latency_p50_ms" in stats
        assert "latency_p95_ms" in stats
        assert "latency_p99_ms" in stats

    @pytest.mark.asyncio
    async def test_check_health_circuit_open(self):
        from pipeline.datausage.health_monitor import HealthMonitor
        hm = HealthMonitor()
        hm._circuit_breaker.state = "open"
        hm._circuit_breaker.last_failure_time = time.time()
        result = await hm.check_health()
        assert result.healthy is False
        assert "Circuit breaker open" in result.error

    def test_is_healthy(self):
        from pipeline.datausage.health_monitor import HealthMonitor
        hm = HealthMonitor()
        assert hm.is_healthy() is True
        hm._circuit_breaker.state = "open"
        hm._circuit_breaker.last_failure_time = time.time()
        assert hm.is_healthy() is False


# ─── Observable Manager ─────────────────────────────────────────────────────

class TestObservableManager:
    def test_extract_ip_iocs(self):
        from pipeline.datausage.observable_manager import ObservableManager
        om = ObservableManager()
        alert = {"source_ip": "45.33.32.156", "dest_ip": "10.0.0.1"}
        iocs = om.extract_iocs(alert)
        assert "ip" in iocs
        assert "45.33.32.156" in iocs["ip"]
        assert "10.0.0.1" not in iocs.get("ip", [])

    def test_extract_domain_iocs(self):
        from pipeline.datausage.observable_manager import ObservableManager
        om = ObservableManager()
        alert = {
            "title": "Malware C2 connection to evil-c2.example.com detected",
            "description": "Connection to bad-domain.com from internal host",
        }
        iocs = om.extract_iocs(alert)
        assert "domain" in iocs
        assert "evil-c2.example.com" in iocs["domain"]
        assert "bad-domain.com" in iocs["domain"]

    def test_extract_hash_iocs(self):
        from pipeline.datausage.observable_manager import ObservableManager
        om = ObservableManager()
        alert = {
            "description": "File with hash d41d8cd98f00b204e9800998ecf8427e and sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 detected",
        }
        iocs = om.extract_iocs(alert)
        assert "file_hash" in iocs
        assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["file_hash"]
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs["file_hash"]

    def test_extract_url_iocs(self):
        from pipeline.datausage.observable_manager import ObservableManager
        om = ObservableManager()
        alert = {"description": "User visited http://evil.com/malware.exe and https://bad.org/payload"}
        iocs = om.extract_iocs(alert)
        assert "url" in iocs
        assert any("evil.com" in u for u in iocs["url"])
        assert any("bad.org" in u for u in iocs["url"])

    def test_extract_email_iocs(self):
        from pipeline.datausage.observable_manager import ObservableManager
        om = ObservableManager()
        alert = {"description": "Phishing email from attacker@evil.com sent to victim@corp.com"}
        iocs = om.extract_iocs(alert)
        assert "email" in iocs
        assert "attacker@evil.com" in iocs["email"]
        assert "victim@corp.com" in iocs["email"]

    def test_extract_hostname_iocs(self):
        from pipeline.datausage.observable_manager import ObservableManager
        om = ObservableManager()
        alert = {"hostname": "web-server-01"}
        iocs = om.extract_iocs(alert)
        assert "hostname" in iocs
        assert "web-server-01" in iocs["hostname"]

    def test_extract_no_private_ips(self):
        from pipeline.datausage.observable_manager import ObservableManager
        om = ObservableManager()
        alert = {"source_ip": "192.168.1.1", "dest_ip": "10.0.0.5"}
        iocs = om.extract_iocs(alert)
        assert iocs.get("ip", []) == []

    def test_extract_empty_alert(self):
        from pipeline.datausage.observable_manager import ObservableManager
        om = ObservableManager()
        iocs = om.extract_iocs({})
        assert iocs == {}

    def test_extract_raw_payload_hashes(self):
        from pipeline.datausage.observable_manager import ObservableManager
        om = ObservableManager()
        alert = {
            "raw_payload": {
                "hash": "abc123abc123abc123abc123abc123ab",
                "sha256": "def456def456def456def456def456def456def456def456def456def456def4",
            }
        }
        iocs = om.extract_iocs(alert)
        assert "file_hash" in iocs
        assert len(iocs["file_hash"]) >= 1

    def test_stats_initial(self):
        from pipeline.datausage.observable_manager import ObservableManager
        om = ObservableManager()
        stats = om.get_stats()
        assert stats["created"] == 0
        assert stats["skipped_duplicates"] == 0
        assert stats["enriched"] == 0


# ─── Incident Manager ───────────────────────────────────────────────────────

class TestIncidentManager:
    def test_calculate_incident_severity_critical(self):
        from pipeline.datausage.incident_manager import IncidentManager
        im = IncidentManager()
        alerts = [{"severity": "critical", "mitre_tactics": ["exfiltration"]}]
        assert im._calculate_incident_severity(alerts) == "critical"

    def test_calculate_incident_severity_high(self):
        from pipeline.datausage.incident_manager import IncidentManager
        im = IncidentManager()
        alerts = [{"severity": "high", "mitre_tactics": ["initial-access"]}]
        assert im._calculate_incident_severity(alerts) == "high"

    def test_calculate_incident_severity_medium(self):
        from pipeline.datausage.incident_manager import IncidentManager
        im = IncidentManager()
        alerts = [{"severity": "medium", "mitre_tactics": []}]
        assert im._calculate_incident_severity(alerts) == "medium"

    def test_calculate_incident_severity_low(self):
        from pipeline.datausage.incident_manager import IncidentManager
        im = IncidentManager()
        alerts = [{"severity": "low", "mitre_tactics": []}]
        assert im._calculate_incident_severity(alerts) == "low"

    def test_calculate_severity_mitre_boost(self):
        from pipeline.datausage.incident_manager import IncidentManager
        im = IncidentManager()
        alerts = [{"severity": "low", "mitre_tactics": ["Exfiltration", "Impact", "Command and Control"]}]
        result = im._calculate_incident_severity(alerts)
        assert result in ("high", "critical")

    def test_build_incident_tags(self):
        from pipeline.datausage.incident_manager import IncidentManager
        im = IncidentManager()
        alerts = [
            {"source": "wazuh", "mitre_tactics": ["Initial Access"], "cloud_provider": "aws"},
            {"source": "suricata", "mitre_tactics": ["Exfiltration"]},
        ]
        tags = im._build_incident_tags(alerts)
        assert "source:wazuh" in tags
        assert "source:suricata" in tags
        assert "mitre:exfiltration" in tags
        assert "mitre:initial-access" in tags
        assert "cloud:aws" in tags
        assert "multi-source" in tags

    def test_detect_kill_chain_progression(self):
        from pipeline.datausage.incident_manager import IncidentManager
        im = IncidentManager()
        alerts = [
            {"mitre_tactics": ["Initial Access"]},
            {"mitre_tactics": ["Execution"]},
            {"mitre_tactics": ["Exfiltration"]},
        ]
        progression = im._detect_kill_chain_progression(alerts)
        assert "execution" in progression
        assert "exfiltration" in progression

    def test_no_kill_chain_for_single_tactic(self):
        from pipeline.datausage.incident_manager import IncidentManager
        im = IncidentManager()
        alerts = [{"mitre_tactics": ["Initial Access"]}]
        progression = im._detect_kill_chain_progression(alerts)
        assert len(progression) == 0

    def test_stats_initial(self):
        from pipeline.datausage.incident_manager import IncidentManager
        import pytest
        im = IncidentManager()
        stats = im.get_stats()
        assert "created" in stats
        assert "linked_alerts" in stats
        assert "tracked_ips" in stats
        assert isinstance(stats["created"], int)
        assert isinstance(stats["linked_alerts"], int)
        assert isinstance(stats["tracked_ips"], int)


# ─── Playbook Runner ────────────────────────────────────────────────────────

class TestPlaybookRunner:
    def test_match_playbooks_empty_cache(self):
        from pipeline.datausage.playbook_runner import PlaybookRunner
        pr = PlaybookRunner()
        pr._playbooks_cache = []
        result = pr.match_playbooks_for_alert({"severity": "critical"})
        assert result == []

    def test_match_playbooks_by_severity(self):
        from pipeline.datausage.playbook_runner import PlaybookRunner
        pr = PlaybookRunner()
        pr._playbooks_cache = [
            {"id": "pb1", "name": "Critical Incident Response", "description": "Handle critical incidents", "enabled": True},
            {"id": "pb2", "name": "Low Priority Check", "description": "Routine check", "enabled": True},
        ]
        result = pr.match_playbooks_for_alert({"severity": "critical", "source": "", "mitre_tactics": [], "cloud_provider": "", "rule_name": ""})
        assert len(result) >= 1
        assert result[0]["id"] == "pb1"

    def test_match_playbooks_by_source(self):
        from pipeline.datausage.playbook_runner import PlaybookRunner
        pr = PlaybookRunner()
        pr._playbooks_cache = [
            {"id": "pb1", "name": "Container Response", "description": "Falco container response playbook", "enabled": True},
            {"id": "pb2", "name": "Network Response", "description": "Suricata network response", "enabled": True},
        ]
        result = pr.match_playbooks_for_alert({"severity": "low", "source": "falco", "mitre_tactics": [], "cloud_provider": "", "rule_name": ""})
        assert len(result) >= 1
        assert result[0]["id"] == "pb1"

    def test_match_playbooks_by_mitre(self):
        from pipeline.datausage.playbook_runner import PlaybookRunner
        pr = PlaybookRunner()
        pr._playbooks_cache = [
            {"id": "pb1", "name": "Exfiltration Response", "description": "Handle data exfiltration incidents", "enabled": True},
        ]
        result = pr.match_playbooks_for_alert({
            "severity": "low", "source": "", "mitre_tactics": ["Exfiltration"],
            "cloud_provider": "", "rule_name": "",
        })
        assert len(result) >= 1

    def test_match_disabled_playbooks(self):
        from pipeline.datausage.playbook_runner import PlaybookRunner
        pr = PlaybookRunner()
        pr._playbooks_cache = [
            {"id": "pb1", "name": "Disabled Playbook", "description": "Should not match", "enabled": False},
        ]
        result = pr.match_playbooks_for_alert({"severity": "critical", "source": "", "mitre_tactics": [], "cloud_provider": "", "rule_name": ""})
        assert result == []

    def test_stats_initial(self):
        from pipeline.datausage.playbook_runner import PlaybookRunner
        pr = PlaybookRunner()
        stats = pr.get_stats()
        assert stats["triggered"] == 0
        assert stats["failures"] == 0


# ─── Action Executor ────────────────────────────────────────────────────────

class TestActionExecutor:
    def test_match_actions_critical_threat_intel(self):
        from pipeline.datausage.action_executor import ActionExecutor
        ae = ActionExecutor()
        alert = {
            "severity": "critical",
            "source_ip": "45.33.32.156",
            "threat_intel": True,
            "mitre_tactics": [],
            "title": "",
            "rule_name": "",
        }
        matched = ae.match_actions_for_alert(alert)
        assert len(matched) >= 1
        assert matched[0]["ioc_type"] == "ip"
        assert matched[0]["ioc_value"] == "45.33.32.156"

    def test_match_actions_low_severity_no_match(self):
        from pipeline.datausage.action_executor import ActionExecutor
        ae = ActionExecutor()
        alert = {
            "severity": "low",
            "source_ip": "45.33.32.156",
            "threat_intel": False,
            "mitre_tactics": [],
            "title": "",
            "rule_name": "",
        }
        matched = ae.match_actions_for_alert(alert)
        assert matched == []

    def test_match_actions_malware_file_hash(self):
        from pipeline.datausage.action_executor import ActionExecutor
        ae = ActionExecutor()
        alert = {
            "severity": "high",
            "source_ip": "",
            "threat_intel": False,
            "mitre_tactics": ["Execution", "Persistence"],
            "title": "Malware trojan detected",
            "rule_name": "malware_detection",
            "hostname": "compromised-host",
        }
        matched = ae.match_actions_for_alert(alert)
        assert len(matched) >= 1

    def test_stats_initial(self):
        from pipeline.datausage.action_executor import ActionExecutor
        ae = ActionExecutor()
        stats = ae.get_stats()
        assert stats["executed"] == 0
        assert stats["failures"] == 0
        assert stats["rules_count"] > 0


# ─── API Key Manager ────────────────────────────────────────────────────────

class TestAPIKeyManager:
    def test_check_rotation_needed(self):
        from pipeline.datausage.apikey_manager import APIKeyManager
        from datetime import datetime, timezone, timedelta
        km = APIKeyManager()
        old_key = {
            "id": "key1",
            "name": "old-key",
            "is_active": True,
            "created_at": (datetime.now(timezone.utc) - timedelta(days=100)).isoformat(),
            "last_used_at": datetime.now(timezone.utc).isoformat(),
        }
        km._keys_cache = [old_key]
        needed = km.check_rotation_needed()
        assert len(needed) == 1
        assert needed[0]["key"]["id"] == "key1"
        assert needed[0]["age_days"] >= 90

    def test_check_rotation_not_needed(self):
        from pipeline.datausage.apikey_manager import APIKeyManager
        from datetime import datetime, timezone
        km = APIKeyManager()
        new_key = {
            "id": "key2",
            "name": "new-key",
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_used_at": datetime.now(timezone.utc).isoformat(),
        }
        km._keys_cache = [new_key]
        needed = km.check_rotation_needed()
        assert needed == []

    def test_check_unused_keys_never_used(self):
        from pipeline.datausage.apikey_manager import APIKeyManager
        from datetime import datetime, timezone, timedelta
        km = APIKeyManager()
        unused_key = {
            "id": "key3",
            "name": "unused-key",
            "is_active": True,
            "created_at": (datetime.now(timezone.utc) - timedelta(days=61)).isoformat(),
            "last_used_at": None,
        }
        km._keys_cache = [unused_key]
        unused = km.check_unused_keys()
        assert len(unused) == 1
        assert unused[0]["never_used"] is True

    def test_get_stats(self):
        from pipeline.datausage.apikey_manager import APIKeyManager
        from datetime import datetime, timezone
        km = APIKeyManager()
        km._keys_cache = [
            {"id": "k1", "name": "key1", "is_active": True, "created_at": datetime.now(timezone.utc).isoformat(), "last_used_at": datetime.now(timezone.utc).isoformat()},
            {"id": "k2", "name": "key2", "is_active": False, "created_at": datetime.now(timezone.utc).isoformat(), "last_used_at": None},
        ]
        stats = km.get_stats()
        assert stats["total"] == 2
        assert stats["active"] == 1


# ─── Dashboard Monitor ──────────────────────────────────────────────────────

class TestDashboardMonitor:
    def test_detect_anomalies_insufficient_data(self):
        from pipeline.datausage.dashboard_monitor import DashboardMonitor
        dm = DashboardMonitor()
        assert dm.detect_anomalies() == []

    def test_detect_anomalies_spike(self):
        from pipeline.datausage.dashboard_monitor import DashboardMonitor
        dm = DashboardMonitor()
        for i in range(20):
            dm._stats_history.append({"timestamp": f"2026-04-05T{i:02d}:00:00Z", "stats": {"total_alerts": 10}})
        dm._stats_history.append({"timestamp": "2026-04-05T20:00:00Z", "stats": {"total_alerts": 100}})
        anomalies = dm.detect_anomalies()
        assert len(anomalies) >= 1
        assert anomalies[0]["type"] == "spike"
        assert anomalies[0]["metric"] == "total_alerts"

    def test_detect_anomalies_drop(self):
        from pipeline.datausage.dashboard_monitor import DashboardMonitor
        dm = DashboardMonitor()
        for i in range(12):
            dm._stats_history.append({"timestamp": f"2026-04-05T{i:02d}:00:00Z", "stats": {"total_alerts": 100}})
        for i in range(12):
            dm._stats_history.append({"timestamp": f"2026-04-05T{12+i:02d}:00:00Z", "stats": {"total_alerts": 10}})
        anomalies = dm.detect_anomalies()
        assert len(anomalies) >= 1
        assert anomalies[0]["type"] == "drop"

    def test_get_trends_insufficient(self):
        from pipeline.datausage.dashboard_monitor import DashboardMonitor
        dm = DashboardMonitor()
        trends = dm.get_trends()
        assert trends["available"] is False

    def test_get_trends_available(self):
        from pipeline.datausage.dashboard_monitor import DashboardMonitor
        dm = DashboardMonitor()
        dm._stats_history.append({"timestamp": "2026-04-05T01:00:00Z", "stats": {"total_alerts": 50}})
        dm._stats_history.append({"timestamp": "2026-04-05T02:00:00Z", "stats": {"total_alerts": 100}})
        trends = dm.get_trends()
        assert trends["available"] is True
        assert trends["trends"]["total_alerts"]["direction"] == "up"
        assert trends["trends"]["total_alerts"]["change_pct"] == 100.0

    def test_soc_report(self):
        from pipeline.datausage.dashboard_monitor import DashboardMonitor
        dm = DashboardMonitor()
        dm._last_stats = {"total_alerts": 100, "open_alerts": 20}
        report = dm.generate_soc_report()
        assert "generated_at" in report
        assert "current_stats" in report
        assert "trends" in report
        assert "recent_anomalies" in report


# ─── Ticketing Models ───────────────────────────────────────────────────────

class TestTicketModels:
    def test_ticket_defaults(self):
        from pipeline.datausage.ticketing.models import Ticket
        t = Ticket(title="Test Ticket")
        assert t.status.value == "open"
        assert t.severity.value == "medium"
        assert t.priority.value == "P3"
        assert t.auto_created is False
        assert t.alert_ids == []
        assert len(t.id) > 0

    def test_ticket_with_values(self):
        from pipeline.datausage.ticketing.models import Ticket, TicketSeverity, TicketPriority, TicketStatus
        t = Ticket(
            title="Critical Incident",
            severity=TicketSeverity.CRITICAL,
            priority=TicketPriority.P1,
            status=TicketStatus.INVESTIGATING,
            alert_ids=["alert-1"],
            mitre_tactics=["Initial Access"],
        )
        assert t.severity.value == "critical"
        assert t.priority.value == "P1"
        assert t.status.value == "investigating"

    def test_ticket_history(self):
        from pipeline.datausage.ticketing.models import TicketHistory, TicketAction
        h = TicketHistory(
            ticket_id="t1",
            action=TicketAction.STATUS_CHANGE,
            detail="Changed from open to investigating",
        )
        assert h.action.value == "status_change"
        assert h.actor == "system"

    def test_ticket_create_model(self):
        from pipeline.datausage.ticketing.models import TicketCreate, TicketSeverity
        tc = TicketCreate(
            title="Auto Ticket",
            severity=TicketSeverity.HIGH,
            alert_ids=["a1"],
            auto_created=True,
        )
        assert tc.title == "Auto Ticket"
        assert tc.auto_created is True

    def test_ticket_update_model(self):
        from pipeline.datausage.ticketing.models import TicketUpdate, TicketStatus
        tu = TicketUpdate(status=TicketStatus.RESOLVED)
        assert tu.status.value == "resolved"

    def test_enums(self):
        from pipeline.datausage.ticketing.models import TicketStatus, TicketPriority, TicketSeverity, TicketAction
        assert TicketStatus.OPEN.value == "open"
        assert TicketStatus.INVESTIGATING.value == "investigating"
        assert TicketStatus.CONTAINED.value == "contained"
        assert TicketStatus.RESOLVED.value == "resolved"
        assert TicketStatus.CLOSED.value == "closed"
        assert TicketPriority.P1.value == "P1"
        assert TicketPriority.P4.value == "P4"
        assert TicketSeverity.CRITICAL.value == "critical"
        assert TicketAction.CREATED.value == "created"


# ─── Ticket Store ───────────────────────────────────────────────────────────

class TestTicketStore:
    @pytest.fixture(autouse=True)
    def setup_store(self):
        import tempfile
        from pipeline.datausage import ticketing
        from pipeline.datausage.ticketing import store as store_module

        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_tickets.db")
        original_path = store_module.TICKET_DB_PATH

        store_module.TICKET_DB_PATH = Path(self.db_path)
        store_module.ticket_store._conn = None
        store_module.ticket_store._init_db()

        yield

        store_module.TICKET_DB_PATH = original_path
        store_module.ticket_store._conn = None
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_create_ticket(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate
        tc = TicketCreate(title="Test Ticket", description="Test description")
        ticket = ticket_store.create_ticket(tc)
        assert ticket.title == "Test Ticket"
        assert ticket.status.value == "open"
        assert ticket.priority.value == "P3"

    def test_create_ticket_priority_calculation(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate, TicketSeverity
        tc = TicketCreate(title="Critical", severity=TicketSeverity.CRITICAL)
        ticket = ticket_store.create_ticket(tc)
        assert ticket.priority.value == "P1"

        tc2 = TicketCreate(title="High", severity=TicketSeverity.HIGH)
        ticket2 = ticket_store.create_ticket(tc2)
        assert ticket2.priority.value == "P2"

        tc3 = TicketCreate(title="Low", severity=TicketSeverity.LOW)
        ticket3 = ticket_store.create_ticket(tc3)
        assert ticket3.priority.value == "P4"

    def test_get_ticket(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate
        tc = TicketCreate(title="Get Me")
        created = ticket_store.create_ticket(tc)
        fetched = ticket_store.get_ticket(created.id)
        assert fetched is not None
        assert fetched.title == "Get Me"

    def test_get_ticket_not_found(self):
        from pipeline.datausage.ticketing.store import ticket_store
        assert ticket_store.get_ticket("nonexistent") is None

    def test_list_tickets(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate, TicketSeverity
        ticket_store.create_ticket(TicketCreate(title="T1", severity=TicketSeverity.CRITICAL))
        ticket_store.create_ticket(TicketCreate(title="T2", severity=TicketSeverity.LOW))
        tickets = ticket_store.list_tickets()
        assert len(tickets) == 2

    def test_list_tickets_by_status(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate
        ticket_store.create_ticket(TicketCreate(title="Open Ticket"))
        tickets = ticket_store.list_tickets(status="open")
        assert len(tickets) >= 1
        assert all(t.status.value == "open" for t in tickets)

    def test_update_ticket_status(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate, TicketUpdate, TicketStatus
        tc = TicketCreate(title="Update Me")
        created = ticket_store.create_ticket(tc)
        update = TicketUpdate(status=TicketStatus.INVESTIGATING)
        updated = ticket_store.update_ticket(created.id, update)
        assert updated is not None
        assert updated.status.value == "investigating"

    def test_update_ticket_not_found(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketUpdate, TicketStatus
        update = TicketUpdate(status=TicketStatus.CLOSED)
        assert ticket_store.update_ticket("nonexistent", update) is None

    def test_add_alert_to_ticket(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate
        tc = TicketCreate(title="Alert Link Test")
        created = ticket_store.create_ticket(tc)
        result = ticket_store.add_alert_to_ticket(created.id, "alert-1")
        assert result is True
        ticket = ticket_store.get_ticket(created.id)
        assert "alert-1" in ticket.alert_ids

    def test_add_alert_duplicate(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate
        tc = TicketCreate(title="Dup Test", alert_ids=["alert-1"])
        created = ticket_store.create_ticket(tc)
        result = ticket_store.add_alert_to_ticket(created.id, "alert-1")
        assert result is False

    def test_get_history(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate
        tc = TicketCreate(title="History Test")
        created = ticket_store.create_ticket(tc)
        history = ticket_store.get_history(created.id)
        assert len(history) >= 1
        assert history[0].action.value == "created"

    def test_get_stats(self):
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate, TicketSeverity
        ticket_store.create_ticket(TicketCreate(title="S1", severity=TicketSeverity.CRITICAL))
        ticket_store.create_ticket(TicketCreate(title="S2", severity=TicketSeverity.LOW, auto_created=True))
        stats = ticket_store.get_stats()
        assert stats["total"] >= 2
        assert stats["auto_created"] >= 1
        assert "by_status" in stats
        assert "by_priority" in stats


# ─── Ticket Routing Rules ───────────────────────────────────────────────────

class TestRoutingRules:
    def test_should_skip_ai_benign(self):
        from pipeline.datausage.ticketing.routing_rules import should_skip_ticket
        alert = {"severity": "medium", "ai_triage_determination": "benign"}
        assert should_skip_ticket(alert) is True

    def test_should_skip_low_no_context(self):
        from pipeline.datausage.ticketing.routing_rules import should_skip_ticket
        alert = {"severity": "low", "mitre_tactics": [], "campaign_context": "", "cloud_provider": ""}
        assert should_skip_ticket(alert) is True

    def test_should_not_skip_critical(self):
        from pipeline.datausage.ticketing.routing_rules import should_skip_ticket
        alert = {"severity": "critical"}
        assert should_skip_ticket(alert) is False

    def test_evaluate_auto_create_critical(self):
        from pipeline.datausage.ticketing.routing_rules import evaluate_auto_create
        alert = {"severity": "critical"}
        rule = evaluate_auto_create(alert)
        assert rule is not None
        assert rule["name"] == "critical_severity"

    def test_evaluate_auto_create_campaign(self):
        from pipeline.datausage.ticketing.routing_rules import evaluate_auto_create
        alert = {"severity": "low", "campaign_context": "SSH Brute Force from 1.2.3.4"}
        rule = evaluate_auto_create(alert)
        assert rule is not None
        assert rule["name"] == "campaign_detected"

    def test_evaluate_auto_create_mitre_kill_chain(self):
        from pipeline.datausage.ticketing.routing_rules import evaluate_auto_create
        alert = {"severity": "medium", "mitre_tactics": ["Initial Access", "Exfiltration"]}
        rule = evaluate_auto_create(alert)
        assert rule is not None

    def test_evaluate_no_match(self):
        from pipeline.datausage.ticketing.routing_rules import evaluate_auto_create
        alert = {"severity": "low", "mitre_tactics": [], "campaign_context": "", "cloud_provider": "", "sources_seen": []}
        rule = evaluate_auto_create(alert)
        assert rule is None

    def test_determine_assignment_network(self):
        from pipeline.datausage.ticketing.routing_rules import determine_assignment
        alert = {"mitre_tactics": ["Initial Access"]}
        team = determine_assignment(alert)
        assert team == "network-team"

    def test_determine_assignment_cloud(self):
        from pipeline.datausage.ticketing.routing_rules import determine_assignment
        alert = {"cloud_provider": "aws"}
        team = determine_assignment(alert)
        assert team == "cloud-team"

    def test_determine_tags(self):
        from pipeline.datausage.ticketing.routing_rules import determine_tags
        alert = {"severity": "critical", "cloud_provider": "aws", "source": "wazuh"}
        tags = determine_tags(alert)
        assert "cloud:aws" in tags
        assert "source:wazuh" in tags


# ─── Ticket Lifecycle ───────────────────────────────────────────────────────

class TestTicketLifecycle:
    def test_valid_transitions(self):
        from pipeline.datausage.ticketing.lifecycle import can_transition, TicketStatus
        assert can_transition(TicketStatus.OPEN, TicketStatus.INVESTIGATING) is True
        assert can_transition(TicketStatus.OPEN, TicketStatus.CLOSED) is True
        assert can_transition(TicketStatus.OPEN, TicketStatus.RESOLVED) is False
        assert can_transition(TicketStatus.INVESTIGATING, TicketStatus.CONTAINED) is True
        assert can_transition(TicketStatus.CONTAINED, TicketStatus.RESOLVED) is True
        assert can_transition(TicketStatus.RESOLVED, TicketStatus.CLOSED) is True
        assert can_transition(TicketStatus.CLOSED, TicketStatus.OPEN) is True

    def test_allowed_transitions(self):
        from pipeline.datausage.ticketing.lifecycle import get_allowed_transitions, TicketStatus
        open_transitions = get_allowed_transitions(TicketStatus.OPEN)
        assert TicketStatus.INVESTIGATING in open_transitions
        assert TicketStatus.CLOSED in open_transitions
        assert TicketStatus.RESOLVED not in open_transitions

    @pytest.fixture(autouse=True)
    def setup_store(self):
        import tempfile
        from pipeline.datausage.ticketing import store as store_module
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_lifecycle.db")
        original_path = store_module.TICKET_DB_PATH
        store_module.TICKET_DB_PATH = Path(self.db_path)
        store_module.ticket_store._conn = None
        store_module.ticket_store._init_db()
        yield
        store_module.TICKET_DB_PATH = original_path
        store_module.ticket_store._conn = None
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    @pytest.mark.asyncio
    async def test_transition_open_to_investigating(self):
        from pipeline.datausage.ticketing.lifecycle import transition_ticket, TicketStatus
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate
        tc = TicketCreate(title="Transition Test")
        created = ticket_store.create_ticket(tc)
        result = await transition_ticket(created.id, TicketStatus.INVESTIGATING, "Started investigation")
        assert result is not None
        assert result.status.value == "investigating"

    @pytest.mark.asyncio
    async def test_invalid_transition(self):
        from pipeline.datausage.ticketing.lifecycle import transition_ticket, TicketStatus
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate
        tc = TicketCreate(title="Invalid Transition")
        created = ticket_store.create_ticket(tc)
        result = await transition_ticket(created.id, TicketStatus.RESOLVED, "Should fail")
        assert result is None

    @pytest.mark.asyncio
    async def test_reopen_closed_ticket(self):
        from pipeline.datausage.ticketing.lifecycle import transition_ticket, reopen_ticket, TicketStatus
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate
        tc = TicketCreate(title="Reopen Test")
        created = ticket_store.create_ticket(tc)
        await transition_ticket(created.id, TicketStatus.CLOSED, "False positive")
        result = await reopen_ticket(created.id, "Recurrence detected")
        assert result is not None
        assert result.status.value == "open"

    @pytest.mark.asyncio
    async def test_escalate_ticket(self):
        from pipeline.datausage.ticketing.lifecycle import escalate_ticket
        from pipeline.datausage.ticketing.store import ticket_store
        from pipeline.datausage.ticketing.models import TicketCreate, TicketSeverity
        tc = TicketCreate(title="Escalate Test", severity=TicketSeverity.LOW)
        created = ticket_store.create_ticket(tc)
        assert created.priority.value == "P4"
        result = await escalate_ticket(created.id)
        assert result is not None
        assert result.priority.value == "P3"


# ─── Auth Manager ───────────────────────────────────────────────────────────

class TestAuthManager:
    def test_get_analyst_id_from_cache(self):
        from pipeline.datausage.auth_manager import AuthManager
        am = AuthManager()
        am._analysts_cache = [
            {"id": "a1", "username": "analyst1", "is_active": True, "role": "analyst"},
            {"id": "a2", "username": "admin1", "is_active": True, "role": "admin"},
        ]
        assert am.get_analyst_id("analyst1") == "a1"
        assert am.get_analyst_id("nonexistent") is None

    def test_get_current_user_id(self):
        from pipeline.datausage.auth_manager import AuthManager
        am = AuthManager()
        am._current_user = {"id": "u1", "username": "pipeline"}
        assert am.get_current_user_id() == "u1"
        assert am.get_current_username() == "pipeline"


# ─── Integration Point (poller.py) ─────────────────────────────────────────

class TestPollerIntegration:
    def test_process_alert_data_usage_function_exists(self):
        from pipeline.poller import _process_alert_data_usage
        assert callable(_process_alert_data_usage)

    def test_orchestrator_importable(self):
        from pipeline.datausage.orchestrator import process_alert, get_pipeline_stats
        assert callable(process_alert)
        assert callable(get_pipeline_stats)

    def test_pipeline_stats_structure(self):
        from pipeline.datausage.orchestrator import get_pipeline_stats
        stats = get_pipeline_stats()
        assert "pipeline" in stats
        assert "observables" in stats
        assert "ai" in stats
        assert "incidents" in stats
        assert "playbooks" in stats
        assert "actions" in stats
        assert "tickets" in stats
        assert "health" in stats


# ─── Full Integration Test (mocked OpenSOAR API) ───────────────────────────

class TestFullIntegration:
    @pytest.fixture(autouse=True)
    def setup(self):
        import tempfile
        from pipeline.datausage.ticketing import store as store_module
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_integration.db")
        original_path = store_module.TICKET_DB_PATH
        store_module.TICKET_DB_PATH = Path(self.db_path)
        store_module.ticket_store._conn = None
        store_module.ticket_store._init_db()
        yield
        store_module.TICKET_DB_PATH = original_path
        store_module.ticket_store._conn = None
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    @pytest.mark.asyncio
    async def test_full_pipeline_with_mocked_api(self):
        """Test the full orchestrator pipeline with mocked OpenSOAR API responses."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "obs-1", "type": "ip", "value": "45.33.32.156"}
        mock_response.raise_for_status = MagicMock()

        mock_incident = MagicMock()
        mock_incident.status_code = 201
        mock_incident.json.return_value = {"id": "inc-1", "title": "Test", "severity": "high", "tags": []}
        mock_incident.raise_for_status = MagicMock()

        mock_link = MagicMock()
        mock_link.status_code = 201
        mock_link.json.return_value = "linked"
        mock_link.raise_for_status = MagicMock()

        mock_comment = MagicMock()
        mock_comment.status_code = 200
        mock_comment.json.return_value = {"id": "c1"}
        mock_comment.raise_for_status = MagicMock()

        mock_triage = MagicMock()
        mock_triage.status_code = 200
        mock_triage.json.return_value = {"suggested_severity": "high", "determination": "true_positive"}
        mock_triage.raise_for_status = MagicMock()

        mock_empty = MagicMock()
        mock_empty.status_code = 200
        mock_empty.json.return_value = []
        mock_empty.raise_for_status = MagicMock()

        mock_actions_empty = MagicMock()
        mock_actions_empty.status_code = 200
        mock_actions_empty.json.return_value = []
        mock_actions_empty.raise_for_status = MagicMock()

        with patch("pipeline.sender.client._get_http") as mock_http, \
             patch("config.get_settings") as mock_settings:
            mock_settings.return_value.upstream_enabled = True
            mock_settings.return_value.local_ingestion_enabled = True
            mock_settings.return_value.opensoar_enabled = True

            mock_client = MagicMock()
            mock_client.get = AsyncMock(side_effect=[
                mock_response,   # observable create
                mock_triage,     # ai triage
                mock_incident,   # incident create
                mock_link,       # link alert
                mock_comment,    # enrichment comment
                mock_empty,      # playbooks
                mock_actions_empty,  # actions
            ])
            mock_client.post = AsyncMock(side_effect=[
                mock_response,   # observable create
                mock_triage,     # ai triage
                mock_incident,   # incident create
                mock_link,       # link alert
                mock_comment,    # enrichment comment
                mock_empty,      # playbooks list
                mock_actions_empty,  # actions list
            ])
            mock_http.return_value = mock_client

            from pipeline.datausage.orchestrator import process_alert
            alert_data = {
                "title": "SSH Brute Force",
                "description": "Multiple failed SSH attempts",
                "severity": "high",
                "source_ip": "45.33.32.156",
                "source": "wazuh",
                "mitre_tactics": ["Credential Access"],
                "rule_name": "SSHD brute force",
            }
            result = await process_alert("local-test-1", alert_data, upstream_alert_id="upstream-test-1")
            assert result["upstream_alert_id"] == "upstream-test-1"
            assert "stages" in result
            assert "observables" in result["stages"]
            assert "incident" in result["stages"]
            assert "ai" in result["stages"]
