"""Lightweight tests for metrics API routes (structural)."""
import pytest
import pytest_asyncio
import httpx

BASE_URL = "http://localhost:8001"


@pytest_asyncio.fixture
async def async_client():
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        yield client


class TestMetricsHealth:
    @pytest.mark.asyncio
    async def test_health_detailed_structure(self, async_client):
        resp = await async_client.get("/api/v1/metrics/health/detailed")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "components" in data
        assert "elasticsearch" in data["components"]
        assert "telegraf" in data["components"]
        assert "redis" in data["components"]
        assert "poller_cache" in data["components"]

    @pytest.mark.asyncio
    async def test_dashboard_returns_hosts_or_error(self, async_client):
        resp = await async_client.get("/api/v1/metrics/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "hosts" in data
