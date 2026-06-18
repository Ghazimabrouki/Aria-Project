"""
Focused tests for Dashboard Priority 3 Phase 1:
- MITRE ATT&CK coverage
- Response metrics (MTTD / MTTR)
"""

import uuid
from datetime import datetime, timezone, timedelta

import pytest_asyncio
import httpx

from response.db import AsyncSessionLocal
from response.models import Alert, Incident, Investigation, AlertIncidentLink
from api.routes.dashboard import _dashboard_cache

BASE_URL = "http://localhost:8001"


@pytest_asyncio.fixture
async def async_client():
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        yield client


async def _create_alert_with_mitre(
    source: str = "wazuh",
    mitre_tactics: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    mitre_ids: list[str] | None = None,
    created_at: datetime | None = None,
) -> str:
    alert_id = str(uuid.uuid4())
    metadata = {}
    if mitre_tactics:
        metadata["mitre_tactics"] = mitre_tactics
    if mitre_techniques:
        metadata["mitre_techniques"] = mitre_techniques
    if mitre_ids:
        metadata["mitre_ids"] = mitre_ids

    tags = []
    for t in (mitre_tactics or []):
        tags.append(f"mitre-tactic-{t}")
    for tech in (mitre_techniques or []):
        tags.append(f"mitre-technique-{tech}")
    for tid in (mitre_ids or []):
        tags.append(f"mitre-{tid}")

    async with AsyncSessionLocal() as session:
        alert = Alert(
            id=alert_id,
            source=source,
            source_id=f"es-{alert_id}",
            title="Test Alert",
            severity="medium",
            status="active",
            alert_metadata=metadata if metadata else None,
            tags=tags if tags else None,
            created_at=created_at or datetime.now(timezone.utc),
            updated_at=created_at or datetime.now(timezone.utc),
        )
        session.add(alert)
        await session.commit()
    return alert_id


async def _create_incident_with_alert(
    alert_id: str,
    resolved_at: datetime | None = None,
    created_at: datetime | None = None,
) -> str:
    incident_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        incident = Incident(
            id=incident_id,
            title="Test Incident",
            description="Test",
            severity="high",
            status="resolved" if resolved_at else "open",
            created_at=created_at or datetime.now(timezone.utc),
            updated_at=created_at or datetime.now(timezone.utc),
            resolved_at=resolved_at,
        )
        session.add(incident)
        await session.flush()
        link = AlertIncidentLink(
            alert_id=alert_id,
            incident_id=incident_id,
            correlation_confidence="manual",
            linked_at=datetime.now(timezone.utc),
        )
        session.add(link)
        await session.commit()
    return incident_id


async def _create_investigation_for_incident(
    incident_id: str,
    status: str = "completed",
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> str:
    inv_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        investigation = Investigation(
            id=inv_id,
            incident_id=incident_id,
            local_incident_id=incident_id,
            incident_title="Test Investigation",
            incident_severity="high",
            incident_status="open",
            status=status,
            investigation_type="security",
            created_at=created_at or datetime.now(timezone.utc),
            updated_at=updated_at or datetime.now(timezone.utc),
        )
        session.add(investigation)
        await session.commit()
    return inv_id


class TestMitreCoverage:
    async def test_mitre_coverage_shape(self, async_client):
        await _dashboard_cache.clear()
        r = await async_client.get("/api/v1/dashboard/mitre-coverage?range=24h")
        assert r.status_code == 200
        data = r.json()
        assert "range" in data
        assert "tactics" in data
        assert isinstance(data["tactics"], list)

    async def test_mitre_coverage_aggregates_metadata(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/mitre-coverage?range=24h")).json()
        before_counts = {t["tactic"]: t["count"] for t in before["tactics"]}

        await _create_alert_with_mitre(
            mitre_tactics=["Initial Access"],
            mitre_techniques=["Brute Force"],
            mitre_ids=["T1110"],
        )

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/mitre-coverage?range=24h")).json()
        after_counts = {t["tactic"]: t["count"] for t in after["tactics"]}

        assert after_counts.get("Initial Access", 0) >= before_counts.get("Initial Access", 0) + 1

        # Verify technique appears under the tactic
        initial_access = next((t for t in after["tactics"] if t["tactic"] == "Initial Access"), None)
        assert initial_access is not None
        techs = {t["technique"]: t for t in initial_access["techniques"]}
        assert "Brute Force" in techs
        assert techs["Brute Force"]["technique_id"] == "T1110"

    async def test_mitre_coverage_excludes_falco(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/mitre-coverage?range=24h")).json()
        before_counts = {t["tactic"]: t["count"] for t in before["tactics"]}

        await _create_alert_with_mitre(
            source="falco",
            mitre_tactics=["Execution"],
            mitre_techniques=["Command and Scripting Interpreter"],
            mitre_ids=["T1059"],
        )

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/mitre-coverage?range=24h")).json()
        after_counts = {t["tactic"]: t["count"] for t in after["tactics"]}

        # Falco tactic should not increase
        assert after_counts.get("Execution", 0) == before_counts.get("Execution", 0)

    async def test_mitre_coverage_respects_range(self, async_client):
        await _dashboard_cache.clear()
        # Create an old alert
        await _create_alert_with_mitre(
            mitre_tactics=["Discovery"],
            created_at=datetime.now(timezone.utc) - timedelta(days=10),
        )

        await _dashboard_cache.clear()
        data = (await async_client.get("/api/v1/dashboard/mitre-coverage?range=7d")).json()
        for t in data["tactics"]:
            assert t["tactic"] != "Discovery"

    async def test_mitre_coverage_tags_fallback(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/mitre-coverage?range=24h")).json()
        before_counts = {t["tactic"]: t["count"] for t in before["tactics"]}

        alert_id = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            alert = Alert(
                id=alert_id,
                source="suricata",
                source_id=f"es-{alert_id}",
                title="Suricata Alert",
                severity="high",
                status="active",
                tags=["mitre-tactic-Reconnaissance", "mitre-T1595"],
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(alert)
            await session.commit()

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/mitre-coverage?range=24h")).json()
        after_counts = {t["tactic"]: t["count"] for t in after["tactics"]}

        assert after_counts.get("Reconnaissance", 0) >= before_counts.get("Reconnaissance", 0) + 1

    async def test_mitre_coverage_no_double_counting(self, async_client):
        """Same tactic/technique in metadata and tags should count once per alert."""
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/mitre-coverage?range=24h")).json()
        before_counts = {t["tactic"]: t["count"] for t in before["tactics"]}
        before_tech_counts = {}
        for tactic in before["tactics"]:
            for tech in tactic["techniques"]:
                before_tech_counts[tech["technique"]] = before_tech_counts.get(tech["technique"], 0) + tech["count"]

        # Create one alert with the SAME tactic and technique in both metadata and tags
        await _create_alert_with_mitre(
            mitre_tactics=["Persistence"],
            mitre_techniques=["Account Manipulation"],
            mitre_ids=["T1098"],
        )

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/mitre-coverage?range=24h")).json()
        after_counts = {t["tactic"]: t["count"] for t in after["tactics"]}

        # Should increase by exactly 1 tactic count for this alert
        assert after_counts.get("Persistence", 0) == before_counts.get("Persistence", 0) + 1

        # Technique count across all tactics should increase by at least 1
        # (exactly 1 for this alert, but prior test data may already exist).
        after_tech_counts = {}
        persistence_tech_counts = {}
        for tactic in after["tactics"]:
            for tech in tactic["techniques"]:
                after_tech_counts[tech["technique"]] = after_tech_counts.get(tech["technique"], 0) + tech["count"]
                if tactic["tactic"] == "Persistence":
                    persistence_tech_counts[tech["technique"]] = persistence_tech_counts.get(tech["technique"], 0) + tech["count"]

        # Verify the new technique appears under Persistence and total increased
        assert persistence_tech_counts.get("Account Manipulation", 0) >= 1
        assert after_tech_counts.get("Account Manipulation", 0) >= before_tech_counts.get("Account Manipulation", 0) + 1


class TestResponseMetrics:
    async def test_response_metrics_shape(self, async_client):
        await _dashboard_cache.clear()
        r = await async_client.get("/api/v1/dashboard/response-metrics?range=24h")
        assert r.status_code == 200
        data = r.json()
        assert "range" in data
        assert "mttd_seconds" in data
        assert "mttr_seconds" in data
        assert "operational_mttr_seconds" in data
        assert "sample_size" in data
        assert "mttd" in data["sample_size"]
        assert "mttr" in data["sample_size"]
        assert "operational_mttr" in data["sample_size"]
        assert "notes" in data

    async def test_response_metrics_mttd_calculation(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/response-metrics?range=24h")).json()

        now = datetime.now(timezone.utc)
        alert_id = await _create_alert_with_mitre(created_at=now - timedelta(minutes=5))
        await _create_incident_with_alert(alert_id, created_at=now)

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/response-metrics?range=24h")).json()

        assert after["sample_size"]["mttd"] >= before["sample_size"]["mttd"] + 1
        assert after["mttd_seconds"] is not None
        assert after["mttd_seconds"] > 0

    async def test_response_metrics_mttr_calculation(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/response-metrics?range=24h")).json()

        now = datetime.now(timezone.utc)
        alert_id = await _create_alert_with_mitre(created_at=now - timedelta(hours=2))
        await _create_incident_with_alert(
            alert_id,
            created_at=now - timedelta(hours=1),
            resolved_at=now,
        )

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/response-metrics?range=24h")).json()

        assert after["sample_size"]["mttr"] >= before["sample_size"]["mttr"] + 1
        assert after["mttr_seconds"] is not None
        # MTTR should be approximately 3600 seconds (1 hour); use stable bounds
        assert 3000 <= after["mttr_seconds"] <= 4200

    async def test_response_metrics_excludes_falco(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/response-metrics?range=24h")).json()

        now = datetime.now(timezone.utc)
        # Create Falco alert and incident
        falco_alert = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            alert = Alert(
                id=falco_alert,
                source="falco",
                source_id=f"es-{falco_alert}",
                title="Falco Alert",
                severity="high",
                status="active",
                created_at=now - timedelta(minutes=10),
                updated_at=now - timedelta(minutes=10),
            )
            session.add(alert)
            await session.flush()
            incident = Incident(
                id=str(uuid.uuid4()),
                title="Falco Incident",
                description="Test",
                severity="high",
                status="resolved",
                created_at=now - timedelta(minutes=5),
                updated_at=now - timedelta(minutes=5),
                resolved_at=now,
            )
            session.add(incident)
            await session.flush()
            link = AlertIncidentLink(
                alert_id=falco_alert,
                incident_id=incident.id,
                correlation_confidence="manual",
                linked_at=now,
            )
            session.add(link)
            await session.commit()

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/response-metrics?range=24h")).json()

        # Falco-derived incident should not increase sample sizes
        assert after["sample_size"]["mttd"] == before["sample_size"]["mttd"]
        assert after["sample_size"]["mttr"] == before["sample_size"]["mttr"]

    async def test_response_metrics_operational_mttr_calculation(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/response-metrics?range=24h")).json()

        now = datetime.now(timezone.utc)
        alert_id = await _create_alert_with_mitre(created_at=now - timedelta(hours=2))
        incident_id = await _create_incident_with_alert(
            alert_id,
            created_at=now - timedelta(hours=1),
        )
        # No resolved_at on incident, but investigation completes
        await _create_investigation_for_incident(
            incident_id,
            status="completed",
            created_at=now - timedelta(minutes=30),
            updated_at=now,
        )

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/response-metrics?range=24h")).json()

        # Operational MTTR should pick up the investigation completion
        assert after["sample_size"]["operational_mttr"] >= before["sample_size"]["operational_mttr"] + 1
        assert after["operational_mttr_seconds"] is not None
        assert after["operational_mttr_seconds"] > 0

    async def test_response_metrics_zero_division_safe(self, async_client):
        await _dashboard_cache.clear()
        # Use a very short range where we likely have no data
        r = await async_client.get("/api/v1/dashboard/response-metrics?range=15m")
        assert r.status_code == 200
        data = r.json()
        # Should not crash; values may be null or real numbers
        assert isinstance(data["sample_size"]["mttd"], int)
        assert isinstance(data["sample_size"]["mttr"], int)
        assert isinstance(data["sample_size"]["operational_mttr"], int)


class TestAlertMitreFilters:
    async def test_alerts_filter_by_mitre_technique(self, async_client):
        alert_id = await _create_alert_with_mitre(
            mitre_techniques=["Data Exfiltration"],
            mitre_ids=["T1041"],
        )
        # Also create a plain alert without the technique
        plain_alert = str(uuid.uuid4())
        async with AsyncSessionLocal() as session:
            alert = Alert(
                id=plain_alert,
                source="wazuh",
                source_id=f"es-{plain_alert}",
                title="Plain Alert",
                severity="medium",
                status="active",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            session.add(alert)
            await session.commit()

        r = await async_client.get("/api/v1/alerts?mitre_technique=Data Exfiltration")
        assert r.status_code == 200
        data = r.json()
        ids = {a["id"] for a in data["alerts"]}
        assert alert_id in ids
        assert plain_alert not in ids

    async def test_alerts_filter_by_tactic(self, async_client):
        alert_id = await _create_alert_with_mitre(
            mitre_tactics=["Defense Evasion"],
        )
        # Create alert with different tactic
        other_alert = await _create_alert_with_mitre(
            mitre_tactics=["Credential Access"],
        )

        r = await async_client.get("/api/v1/alerts?tactic=Defense Evasion")
        assert r.status_code == 200
        data = r.json()
        ids = {a["id"] for a in data["alerts"]}
        assert alert_id in ids
        assert other_alert not in ids


# ── Geographic Threats ──────────────────────────────────────────────────────

async def _create_alert_with_geo(
    source: str = "wazuh",
    severity: str = "high",
    source_ip: str = "8.8.8.8",
    geo_data: dict | None = None,
    created_at: datetime | None = None,
) -> str:
    alert_id = str(uuid.uuid4())
    metadata = {"_geo": geo_data or {}}
    async with AsyncSessionLocal() as session:
        alert = Alert(
            id=alert_id,
            source=source,
            source_id=f"es-{alert_id}",
            title="Test Geo Alert",
            severity=severity,
            status="active",
            source_ip=source_ip,
            alert_metadata=metadata,
            created_at=created_at or datetime.now(timezone.utc),
            updated_at=created_at or datetime.now(timezone.utc),
        )
        session.add(alert)
        await session.commit()
    return alert_id


class TestGeoThreats:
    async def test_geo_threats_shape(self, async_client):
        await _dashboard_cache.clear()
        r = await async_client.get("/api/v1/dashboard/geo-threats?range=24h")
        assert r.status_code == 200
        data = r.json()
        assert "range" in data
        assert "points" in data
        assert isinstance(data["points"], list)
        assert "unresolved_count" in data
        assert isinstance(data["unresolved_count"], int)

    async def test_geo_threats_aggregates_valid_coords(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/geo-threats?range=24h")).json()
        before_us = next((p for p in before["points"] if p["country_code"] == "US" and p["city"] == "New York"), None)
        before_us_count = before_us["count"] if before_us else 0
        before_us_critical = before_us["severity_breakdown"]["critical"] if before_us else 0

        await _create_alert_with_geo(
            geo_data={
                "source": {
                    "country_code": "US",
                    "country_name": "United States",
                    "city": "New York",
                    "latitude": 40.7128,
                    "longitude": -74.0060,
                }
            },
            severity="critical",
        )

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/geo-threats?range=24h")).json()
        us_point = next((p for p in after["points"] if p["country_code"] == "US" and p["city"] == "New York"), None)

        assert us_point is not None
        assert us_point["count"] >= before_us_count + 1
        assert us_point["severity_breakdown"]["critical"] >= before_us_critical + 1

    async def test_geo_threats_excludes_falco(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/geo-threats?range=24h")).json()
        before_count = sum(p["count"] for p in before["points"])

        await _create_alert_with_geo(
            source="falco",
            geo_data={
                "source": {
                    "country_code": "DE",
                    "country_name": "Germany",
                    "city": "Berlin",
                    "latitude": 52.5200,
                    "longitude": 13.4050,
                }
            },
        )

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/geo-threats?range=24h")).json()
        after_count = sum(p["count"] for p in after["points"])

        assert after_count == before_count

    async def test_geo_threats_filters_invalid_coords(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/geo-threats?range=24h")).json()

        # 0,0 coordinates are invalid
        await _create_alert_with_geo(
            geo_data={
                "source": {
                    "country_code": "XX",
                    "country_name": "Unknown",
                    "latitude": 0.0,
                    "longitude": 0.0,
                }
            },
        )

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/geo-threats?range=24h")).json()

        assert after["unresolved_count"] >= before["unresolved_count"] + 1

    async def test_geo_threats_filters_private_ips(self, async_client):
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/geo-threats?range=24h")).json()

        await _create_alert_with_geo(
            source_ip="192.168.1.1",
            geo_data={
                "source": {
                    "country_code": "FR",
                    "country_name": "France",
                    "city": "Paris",
                    "latitude": 48.8566,
                    "longitude": 2.3522,
                }
            },
        )

        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/geo-threats?range=24h")).json()

        assert after["unresolved_count"] >= before["unresolved_count"] + 1

    async def test_geo_threats_respects_range(self, async_client):
        await _dashboard_cache.clear()
        # Use a unique city name to avoid collision with real data
        unique_city = "TestCity-GeoRange-42"
        await _create_alert_with_geo(
            created_at=datetime.now(timezone.utc) - timedelta(days=10),
            geo_data={
                "source": {
                    "country_code": "JP",
                    "country_name": "Japan",
                    "city": unique_city,
                    "latitude": 35.6762,
                    "longitude": 139.6503,
                }
            },
        )

        await _dashboard_cache.clear()
        data = (await async_client.get("/api/v1/dashboard/geo-threats?range=7d")).json()
        for p in data["points"]:
            assert not (p["country_code"] == "JP" and p["city"] == unique_city)


