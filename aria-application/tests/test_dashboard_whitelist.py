"""
Focused tests for dashboard whitelisted visibility.

Verifies that dashboard quick-stats returns separate whitelisted counts
without changing main KPI semantics.
"""

import uuid
from datetime import datetime, timezone

import pytest_asyncio
import httpx

from response.db import AsyncSessionLocal
from response.models import Alert, Incident

BASE_URL = "http://localhost:8001"


@pytest_asyncio.fixture
async def async_client():
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        yield client


async def _create_alert(whitelisted: bool = False) -> str:
    alert_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        alert = Alert(
            id=alert_id,
            source="wazuh",
            source_id=f"es-{alert_id}",
            title="Test Alert",
            severity="medium",
            status="active",
            category="authentication",
            whitelisted=whitelisted,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(alert)
        await session.commit()
    return alert_id


async def _create_incident(whitelisted: bool = False) -> str:
    incident_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        incident = Incident(
            id=incident_id,
            title="Test Incident",
            description="Test",
            severity="medium",
            status="open",
            whitelisted=whitelisted,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(incident)
        await session.commit()
    return incident_id


class TestDashboardWhitelistedCounts:
    async def test_whitelisted_alert_increases_whitelisted_count(self, async_client):
        from api.routes.dashboard import _dashboard_cache
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/quick-stats")).json()
        await _create_alert(whitelisted=True)
        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/quick-stats")).json()

        assert after["whitelisted_alerts"] == before["whitelisted_alerts"] + 1
        # Note: main alert KPI currently still includes whitelisted alerts,
        # so we only assert the dedicated counter increased.

    async def test_whitelisted_incident_increases_whitelisted_count(self, async_client):
        from api.routes.dashboard import _dashboard_cache
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/quick-stats")).json()
        await _create_incident(whitelisted=True)
        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/quick-stats")).json()

        assert after["whitelisted_incidents"] == before["whitelisted_incidents"] + 1

    async def test_non_whitelisted_alert_does_not_affect_whitelisted_count(self, async_client):
        from api.routes.dashboard import _dashboard_cache
        await _dashboard_cache.clear()
        before = (await async_client.get("/api/v1/dashboard/quick-stats")).json()
        await _create_alert(whitelisted=False)
        await _dashboard_cache.clear()
        after = (await async_client.get("/api/v1/dashboard/quick-stats")).json()

        assert after["whitelisted_alerts"] == before["whitelisted_alerts"]
        assert after["alerts"] > before["alerts"]
