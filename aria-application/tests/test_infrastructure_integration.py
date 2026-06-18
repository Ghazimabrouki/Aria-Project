"""
Integration test for the complete Infrastructure Intelligence pipeline.

Tests the full flow from performance alert → SRE AI analysis → investigation creation → DB state.
Uses mocked LLM and mocked Elasticsearch.
"""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock

from pipeline.performance_poller import HostMetrics
from pipeline.enrichment.anomaly_detector import AnomalyResult, AnomalyType
from pipeline.datausage.performance_orchestrator import _create_performance_investigation

from sqlalchemy import select
from response.db import AsyncSessionLocal
from response.models import Investigation, InvestigationAlert


@pytest.fixture
def high_cpu_alert():
    """A realistic performance alert for CPU high."""
    return {
        "id": "perf-alert-001",
        "source": "performance",
        "title": "CPU High on web-server",
        "severity": "critical",
        "host": "web-server",
        "hostname": "web-server",
        "anomaly_type": "cpu_high",
        "metrics": {
            "cpu": {"current": 95.0, "warning_threshold": 70.0, "critical_threshold": 90.0},
            "memory": {"current": 60.0},
        },
        "baseline_deviation": "+3.5 stddev from 24h baseline",
    }


@pytest.fixture
def high_memory_alert():
    """A realistic performance alert for memory high."""
    return {
        "id": "perf-alert-002",
        "source": "performance",
        "title": "Memory High on db-server",
        "severity": "critical",
        "host": "db-server",
        "hostname": "db-server",
        "anomaly_type": "memory_high",
        "metrics": {
            "cpu": {"current": 30.0, "critical_threshold": 90.0},
            "memory": {"current": 96.0, "warning_threshold": 80.0, "critical_threshold": 90.0},
        },
        "baseline_deviation": "+2.8 stddev",
    }


@pytest.fixture
def disk_full_alert():
    """A realistic performance alert for disk full."""
    return {
        "id": "perf-alert-003",
        "source": "performance",
        "title": "Disk Full on log-server",
        "severity": "critical",
        "host": "log-server",
        "hostname": "log-server",
        "anomaly_type": "disk_full",
        "metrics": {
            "cpu": {"current": 20.0, "critical_threshold": 90.0},
            "memory": {"current": 50.0},
            "disk": [
                {"device": "/dev/sda1", "path": "/var/log", "used_percent": 97.0},
            ],
        },
    }


@pytest.fixture
def sample_host_metrics():
    """Create realistic HostMetrics."""
    return HostMetrics(
        hostname="web-server",
        ip="192.168.1.10",
        timestamp=datetime.now(timezone.utc),
        cpu_usage_percent=95.0,
        cpu_user_percent=80.0,
        cpu_system_percent=15.0,
        memory_used_percent=60.0,
        memory_used_bytes=6e9,
        memory_available_bytes=4e9,
        disk_devices=[
            {"device": "/dev/sda1", "path": "/", "fstype": "ext4", "used_percent": 65.0, "free_bytes": 50e9},
        ],
        network_bytes_recv=1024000,
        network_bytes_sent=512000,
        load_1=8.0,
        load_5=6.0,
        load_15=4.0,
        n_cpus=4,
        top_processes=[
            {"name": "nginx", "pid": 1234, "cpu_percent": 78.5, "memory_rss": 500000000, "memory_percent": 5.0, "cmdline": "nginx: worker process"},
            {"name": "php-fpm", "pid": 5678, "cpu_percent": 10.0, "memory_rss": 200000000, "memory_percent": 2.0, "cmdline": "php-fpm: pool www"},
        ],
    )


@pytest.fixture
def mock_llm_response():
    """A realistic SRE-mode AI response."""
    return json.dumps({
        "resource_impacted": "cpu",
        "responsible_process": {"name": "nginx", "pid": 1234, "cpu_percent": 78.5},
        "responsible_service": "nginx",
        "issue_start_time": "2026-04-28T11:55:00Z",
        "behavior_classification": "temporary_spike",
        "impact_assessment": "Minor latency increase, no service degradation",
        "root_cause": "High traffic spike from marketing campaign causing nginx worker processes to consume excessive CPU",
        "confidence": 0.92,
        "explanation": "The CPU spike correlates with a 5x increase in HTTP requests. nginx workers are the primary consumers. This is expected behavior during campaign launches.",
        "immediate_mitigation": {
            "action": "Gracefully reload nginx to rebalance worker processes",
            "risk": "Low — zero downtime, workers drain existing connections",
            "expected_outcome": "CPU usage drops to 40-50% within 30 seconds",
            "system_impact": "No user-facing impact",
            "rollback_feasible": True,
        },
        "long_term_optimization": {
            "action": "Increase nginx worker_processes to auto and enable connection limiting",
            "risk": "Low — configuration change only",
            "expected_outcome": "Better CPU distribution during traffic spikes",
            "system_impact": "Requires nginx reload during maintenance window",
        },
        "suggested_playbook_tasks": [
            {"name": "Check nginx status", "module": "ansible.builtin.shell", "args": "systemctl status nginx", "purpose": "diagnostic"},
            {"name": "Reload nginx", "module": "ansible.builtin.shell", "args": "systemctl reload nginx", "purpose": "mitigation"},
        ],
    })


# ─────────────────────────────────────────────────────────────────────────────
# Full Flow Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFullInfrastructureFlow:
    @pytest.mark.asyncio
    async def test_cpu_alert_creates_infrastructure_investigation(
        self, high_cpu_alert, sample_host_metrics, mock_llm_response
    ):
        """Test that a CPU alert creates an infrastructure investigation with correct fields."""
        anomaly = AnomalyResult(
            is_anomaly=True,
            severity="critical",
            anomaly_type=AnomalyType.CPU_HIGH,
            reason="CPU at 95%",
            value=95.0,
            threshold=90.0,
        )

        with patch("response.infrastructure_ai_engine.main._call_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = mock_llm_response
            inv_id = await _create_performance_investigation(
                alert=high_cpu_alert,
                host="web-server",
                metrics=sample_host_metrics,
                anomaly=anomaly,
            )

        assert inv_id is not None
        assert len(inv_id) == 36  # UUID

        # Verify in database
        async with AsyncSessionLocal() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(Investigation).where(Investigation.id == inv_id)
            )
            inv = result.scalar_one()

            assert inv.investigation_type == "infrastructure"
            assert inv.source == "performance"
            assert inv.status == "diagnosing"
            assert inv.incident_severity == "critical"
            assert inv.target_host == "web-server"
            assert inv.playbook_yaml is not None
            assert inv.playbook_valid is True
            assert inv.resource_context_json is not None

            # Verify resource context
            ctx = inv.resource_context_json
            assert ctx["resource_type"] == "cpu"
            assert ctx["current_value"] == 95.0
            assert ctx["threshold"] == 90.0
            assert ctx["affected_host"] == "web-server"
            assert ctx["affected_service"] == "nginx"
            assert ctx["affected_process"]["name"] == "nginx"

            # Verify linked alert
            alert_result = await session.execute(
                select(InvestigationAlert).where(
                    InvestigationAlert.investigation_id == inv_id
                )
            )
            alert = alert_result.scalar_one()
            assert alert.alert_id == "perf-alert-001"
            assert alert.source == "performance"

            # Verify playbook is safe (no forbidden patterns)
            from response.infrastructure_ai_engine.playbook_generator import FORBIDDEN_PATTERNS
            for pattern in FORBIDDEN_PATTERNS:
                assert pattern.lower() not in inv.playbook_yaml.lower(), f"Forbidden pattern in playbook: {pattern}"

    @pytest.mark.asyncio
    async def test_memory_alert_creates_infrastructure_investigation(
        self, high_memory_alert, mock_llm_response
    ):
        """Test that a memory alert creates an infrastructure investigation."""
        metrics = HostMetrics(
            hostname="db-server",
            ip="192.168.1.20",
            timestamp=datetime.now(timezone.utc),
            cpu_usage_percent=30.0,
            memory_used_percent=96.0,
            memory_used_bytes=15e9,
            memory_available_bytes=500000000,
            n_cpus=8,
            top_processes=[
                {"name": "java", "pid": 9999, "cpu_percent": 5.0, "memory_rss": 14e9, "memory_percent": 90.0, "cmdline": "java -jar app.jar"},
            ],
        )
        anomaly = AnomalyResult(
            is_anomaly=True,
            severity="critical",
            anomaly_type=AnomalyType.MEMORY_HIGH,
            reason="Memory at 96%",
            value=96.0,
            threshold=90.0,
        )

        # Adjust mock response for memory
        memory_response = json.dumps({
            "resource_impacted": "memory",
            "responsible_process": {"name": "java", "pid": 9999},
            "responsible_service": "java-application",
            "root_cause": "Java heap memory leak",
            "confidence": 0.85,
            "behavior_classification": "persistent",
            "immediate_mitigation": {
                "action": "Restart Java application",
                "risk": "Medium — brief downtime",
                "expected_outcome": "Memory returns to normal",
                "system_impact": "2-3 minute service interruption",
                "rollback_feasible": False,
            },
        })

        with patch("response.infrastructure_ai_engine.main._call_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = memory_response
            inv_id = await _create_performance_investigation(
                alert=high_memory_alert,
                host="db-server",
                metrics=metrics,
                anomaly=anomaly,
            )

        assert inv_id is not None

        async with AsyncSessionLocal() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(Investigation).where(Investigation.id == inv_id)
            )
            inv = result.scalar_one()

            assert inv.investigation_type == "infrastructure"
            assert inv.resource_context_json["resource_type"] == "memory"
            assert inv.resource_context_json["affected_service"] == "java-application"

    @pytest.mark.asyncio
    async def test_disk_alert_creates_infrastructure_investigation(
        self, disk_full_alert, mock_llm_response
    ):
        """Test that a disk alert creates an infrastructure investigation."""
        metrics = HostMetrics(
            hostname="log-server",
            ip="192.168.1.30",
            timestamp=datetime.now(timezone.utc),
            disk_devices=[
                {"device": "/dev/sda1", "path": "/var/log", "fstype": "ext4", "used_percent": 97.0, "free_bytes": 1e9},
            ],
            n_cpus=4,
        )
        anomaly = AnomalyResult(
            is_anomaly=True,
            severity="critical",
            anomaly_type=AnomalyType.DISK_FULL,
            reason="Disk at 97%",
            value=97.0,
            threshold=90.0,
        )

        disk_response = json.dumps({
            "resource_impacted": "disk",
            "responsible_process": None,
            "responsible_service": None,
            "root_cause": "Application logs consuming excessive disk space",
            "confidence": 0.88,
            "behavior_classification": "persistent",
            "immediate_mitigation": {
                "action": "Rotate and compress old logs",
                "risk": "Low",
                "expected_outcome": "Free up 50% disk space",
                "system_impact": "None",
                "rollback_feasible": True,
            },
        })

        with patch("response.infrastructure_ai_engine.main._call_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = disk_response
            inv_id = await _create_performance_investigation(
                alert=disk_full_alert,
                host="log-server",
                metrics=metrics,
                anomaly=anomaly,
            )

        assert inv_id is not None

        async with AsyncSessionLocal() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(Investigation).where(Investigation.id == inv_id)
            )
            inv = result.scalar_one()

            assert inv.investigation_type == "infrastructure"
            assert inv.resource_context_json["resource_type"] == "disk"
            # Disk issues may not have an affected process

    @pytest.mark.asyncio
    async def test_investigation_not_created_when_playbook_empty(
        self, high_cpu_alert, sample_host_metrics, mock_llm_response
    ):
        """Test that no investigation is created when playbook generation fails."""
        anomaly = AnomalyResult(
            is_anomaly=True,
            severity="critical",
            anomaly_type=AnomalyType.CPU_HIGH,
            reason="CPU at 95%",
            value=95.0,
            threshold=90.0,
        )

        with patch("response.infrastructure_ai_engine.main._call_llm", new_callable=AsyncMock) as mock_llm, \
             patch("response.infrastructure_ai_engine.main.generate_safe_playbook") as mock_gen:
            mock_llm.return_value = mock_llm_response
            mock_gen.return_value = ""  # Empty playbook
            inv_id = await _create_performance_investigation(
                alert=high_cpu_alert,
                host="web-server",
                metrics=sample_host_metrics,
                anomaly=anomaly,
            )

        assert inv_id is None

    @pytest.mark.asyncio
    async def test_fallback_playbook_on_ai_failure(
        self, high_cpu_alert, sample_host_metrics
    ):
        """Test that a fallback playbook is used when AI completely fails."""
        anomaly = AnomalyResult(
            is_anomaly=True,
            severity="critical",
            anomaly_type=AnomalyType.CPU_HIGH,
            reason="CPU at 95%",
            value=95.0,
            threshold=90.0,
        )

        with patch("response.infrastructure_ai_engine.main._call_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.side_effect = Exception("LLM service unavailable")
            inv_id = await _create_performance_investigation(
                alert=high_cpu_alert,
                host="web-server",
                metrics=sample_host_metrics,
                anomaly=anomaly,
            )

        assert inv_id is not None

        async with AsyncSessionLocal() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(Investigation).where(Investigation.id == inv_id)
            )
            inv = result.scalar_one()

            assert inv.investigation_type == "infrastructure"
            assert inv.playbook_yaml is not None
            # On AI failure, a diagnostic-only playbook is generated
            assert "System overview" in inv.playbook_yaml
            assert "ansible.builtin.shell" in inv.playbook_yaml

    @pytest.mark.asyncio
    async def test_security_investigations_not_affected(
        self, high_cpu_alert, sample_host_metrics, mock_llm_response
    ):
        """Test that security investigations remain separate from infrastructure ones."""
        # First create a security investigation
        async with AsyncSessionLocal() as session:
            from response.models import Investigation
            sec_inv = Investigation(
                incident_id="sec-001",
                incident_title="SSH Brute Force",
                incident_severity="high",
                status="awaiting_approval",
                investigation_type="security",
                source="wazuh",
                target_host="web-server",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(sec_inv)
            await session.commit()
            sec_id = sec_inv.id

        # Now create an infrastructure one
        anomaly = AnomalyResult(
            is_anomaly=True,
            severity="critical",
            anomaly_type=AnomalyType.CPU_HIGH,
            reason="CPU at 95%",
            value=95.0,
            threshold=90.0,
        )

        with patch("response.infrastructure_ai_engine.main._call_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = mock_llm_response
            infra_id = await _create_performance_investigation(
                alert=high_cpu_alert,
                host="web-server",
                metrics=sample_host_metrics,
                anomaly=anomaly,
            )

        assert infra_id is not None

        # Verify both exist with correct types
        async with AsyncSessionLocal() as session:
            from sqlalchemy import select
            sec_result = await session.execute(
                select(Investigation).where(Investigation.id == sec_id)
            )
            sec = sec_result.scalar_one()
            assert sec.investigation_type == "security"

            infra_result = await session.execute(
                select(Investigation).where(Investigation.id == infra_id)
            )
            infra = infra_result.scalar_one()
            assert infra.investigation_type == "infrastructure"

            # Count by type
            from sqlalchemy import func
            infra_count_result = await session.execute(
                select(func.count(Investigation.id)).where(
                    Investigation.investigation_type == "infrastructure"
                )
            )
            infra_count = infra_count_result.scalar_one()
            sec_count_result = await session.execute(
                select(func.count(Investigation.id)).where(
                    Investigation.investigation_type == "security"
                )
            )
            sec_count = sec_count_result.scalar_one()
            assert infra_count >= 1
            assert sec_count >= 1
