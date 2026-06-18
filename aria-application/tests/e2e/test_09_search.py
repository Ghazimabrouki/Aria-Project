"""
E2E tests for the unified search API.

Prerequisites:
- Backend API running at http://localhost:8001
- SQLite database populated with alerts, incidents, investigations
"""

import pytest
import httpx

BASE_URL = "http://localhost:8001/api/v1"


@pytest.fixture(autouse=True)
def reset_rate_limit():
    """Reset in-memory rate limit store before each test."""
    import api.routes.search as search_module
    search_module._rate_limit_store.clear()
    yield


@pytest.fixture
async def client():
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as c:
        yield c


class TestSearchAll:
    @pytest.mark.asyncio
    async def test_search_alerts(self, client):
        """Search should return alerts matching a known term."""
        r = await client.get("/search?q=ssh&limit=5")
        assert r.status_code == 200
        data = r.json()
        assert data["counts"]["alerts"] > 0
        assert all("id" in a for a in data["results"]["alerts"])
        assert all("title" in a for a in data["results"]["alerts"])

    @pytest.mark.asyncio
    async def test_search_incidents(self, client):
        """Search should return incidents."""
        r = await client.get("/search?q=test&limit=5")
        assert r.status_code == 200
        data = r.json()
        assert data["counts"]["incidents"] > 0

    @pytest.mark.asyncio
    async def test_search_investigations(self, client):
        """Search should return investigations."""
        r = await client.get("/search?q=test&limit=5")
        assert r.status_code == 200
        data = r.json()
        assert data["counts"]["investigations"] > 0

    @pytest.mark.asyncio
    async def test_search_archives(self, client):
        """Search should return archives when available."""
        r = await client.get("/search?q=test&limit=5")
        assert r.status_code == 200
        data = r.json()
        # Archives may be empty; just verify the field exists
        assert "archives" in data["counts"]
        assert "archives" in data["results"]

    @pytest.mark.asyncio
    async def test_search_multi_term(self, client):
        """Multi-term search should work (AND by default)."""
        r = await client.get("/search?q=ssh%20brute&limit=5")
        assert r.status_code == 200
        data = r.json()
        # Should find incidents with both words
        assert data["counts"]["incidents"] > 0

    @pytest.mark.asyncio
    async def test_search_phrase(self, client):
        """Quoted phrase search should match exact phrase."""
        r = await client.get('/search?q=%22test%20host%22&limit=5')
        assert r.status_code == 200
        data = r.json()
        # May or may not find results depending on data
        assert "counts" in data

    @pytest.mark.asyncio
    async def test_search_prefix(self, client):
        """Prefix search with * should match partial words."""
        r = await client.get("/search?q=container*&limit=5")
        assert r.status_code == 200
        data = r.json()
        # Should find alerts with words starting with "container"
        assert data["counts"]["alerts"] > 0

    @pytest.mark.asyncio
    async def test_search_negation(self, client):
        """Negation with - should exclude results."""
        r = await client.get("/search?q=-nonexistentword123&limit=5")
        assert r.status_code == 200
        data = r.json()
        # Negating a word that doesn't exist should still return some results
        # (FTS5 NOT on non-existent term is effectively a no-op)
        assert "counts" in data

    @pytest.mark.asyncio
    async def test_search_empty_query_rejected(self, client):
        """Empty query should be rejected by FastAPI validation."""
        r = await client.get("/search?q=&limit=5")
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_search_severity_filter(self, client):
        """Severity filter should restrict results."""
        r = await client.get("/search?q=ssh&limit=5&severity=critical")
        assert r.status_code == 200
        data = r.json()
        for alert in data["results"]["alerts"]:
            assert alert["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_search_source_filter(self, client):
        """Source filter should restrict results."""
        r = await client.get("/search?q=test&limit=5&source=falco")
        assert r.status_code == 200
        data = r.json()
        for alert in data["results"]["alerts"]:
            assert alert["source"] == "falco"

    @pytest.mark.asyncio
    async def test_search_relevance_field(self, client):
        """Results should include relevance scores."""
        r = await client.get("/search?q=ssh&limit=5")
        assert r.status_code == 200
        data = r.json()
        for alert in data["results"]["alerts"]:
            assert "relevance" in alert
            assert 0.0 <= alert["relevance"] <= 1.0

    @pytest.mark.asyncio
    async def test_search_by_ip(self, client):
        """IP search should return matching entities."""
        r = await client.get("/search/ips/10.0.0.1?limit=5")
        assert r.status_code == 200
        data = r.json()
        assert "counts" in data
        assert "results" in data

    @pytest.mark.asyncio
    async def test_search_by_domain(self, client):
        """Domain search should return matching entities."""
        r = await client.get("/search/domains/test-host?limit=5")
        assert r.status_code == 200
        data = r.json()
        assert "counts" in data
        assert "results" in data


class TestSearchRateLimit:
    @pytest.mark.asyncio
    async def test_search_rate_limit(self, client):
        """Rapid requests should be handled without crashing.
        
        Note: Rate limit is raised to 1000 for E2E tests to avoid
        interfering with other tests. We just verify the endpoint
        remains stable under rapid requests.
        """
        codes = []
        for _ in range(15):
            r = await client.get("/search?q=test&limit=1")
            codes.append(r.status_code)
        assert all(c == 200 for c in codes), f"Unexpected error codes: {codes}"
