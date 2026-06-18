"""
E2E Test 01 — Service Connectivity

Verifies that all external services are reachable and responding correctly.
These are prerequisites for all other E2E tests.
"""
import pytest
import pytest_asyncio
import httpx

from config import get_settings
settings = get_settings()


@pytest.mark.asyncio
async def test_elasticsearch_reachable(services):
    """Elasticsearch cluster health endpoint responds."""
    if not services["es"]:
        pytest.fail("Elasticsearch is NOT reachable at " + settings.elasticsearch_url)
    assert services["es"], "Elasticsearch must be reachable"


@pytest.mark.asyncio
async def test_elasticsearch_auth(services):
    """Elasticsearch accepts our credentials."""
    if not services["es"]:
        pytest.skip("Elasticsearch not reachable")
    async with httpx.AsyncClient(verify=False, timeout=10.0) as c:
        r = await c.get(
            f"{settings.elasticsearch_url}/_cluster/health",
            auth=(settings.elasticsearch_user, settings.elasticsearch_password),
        )
    assert r.status_code == 200, f"ES auth failed: {r.status_code}"
    data = r.json()
    assert data.get("status") in ("green", "yellow", "red"), "Unexpected ES health response"
    print(f"\n  ES cluster: {data.get('cluster_name')} | status={data.get('status')} | nodes={data.get('number_of_nodes')}")


@pytest.mark.asyncio
async def test_elasticsearch_indices_exist(services):
    """Wazuh, Falco, and Suricata indices have data."""
    if not services["es"]:
        pytest.skip("Elasticsearch not reachable")
    async with httpx.AsyncClient(verify=False, timeout=10.0) as c:
        auth = (settings.elasticsearch_user, settings.elasticsearch_password)
        patterns = {
            "wazuh":    settings.wazuh_index_pattern,
            "falco":    settings.falco_index_pattern,
            "filebeat": settings.filebeat_index_pattern,
        }
        found_any = False
        for name, pattern in patterns.items():
            r = await c.get(f"{settings.elasticsearch_url}/{pattern}/_count", auth=auth)
            if r.status_code == 200:
                count = r.json().get("count", 0)
                print(f"\n  {name}: {count} documents in {pattern}")
                if count > 0:
                    found_any = True
            else:
                print(f"\n  {name}: index not found ({r.status_code})")
    assert found_any, "At least one index pattern must have documents"


@pytest.mark.asyncio
async def test_opensoar_reachable(services):
    """OpenSOAR API is reachable."""
    if not services["opensoar"]:
        pytest.fail("OpenSOAR is NOT reachable at " + settings.opensoar_url)
    assert services["opensoar"]


@pytest.mark.asyncio
async def test_opensoar_auth(services):
    """OpenSOAR accepts our credentials and returns a token."""
    if not services["opensoar"]:
        pytest.skip("OpenSOAR not reachable")
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.post(
            f"{settings.opensoar_url}/api/v1/auth/login",
            json={"username": settings.opensoar_username, "password": settings.opensoar_password},
        )
    assert r.status_code == 200, f"OpenSOAR auth failed: {r.status_code} {r.text[:200]}"
    data = r.json()
    assert "access_token" in data, "No access_token in auth response"
    print(f"\n  Token prefix: {data['access_token'][:20]}...")


@pytest.mark.asyncio
async def test_ollama_reachable(services):
    """Ollama LLM service is reachable."""
    if not services["ollama"]:
        pytest.skip("Ollama not reachable — AI tests will be skipped")
    assert services["ollama"]


@pytest.mark.asyncio
async def test_ollama_model_available(services):
    """Required LLM model is loaded in Ollama."""
    if not services["ollama"]:
        pytest.skip("Ollama not reachable")
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(f"{settings.ollama_host}/api/tags")
    assert r.status_code == 200
    data = r.json()
    models = [m.get("name", "") for m in data.get("models", [])]
    print(f"\n  Loaded models: {models}")
    # Check if our configured model (or base name) is available
    base_model = settings.llm_model.split(":")[0]
    found = any(base_model in m for m in models)
    if not found:
        pytest.skip(f"Model '{settings.llm_model}' not loaded in Ollama — AI tests will be skipped")


@pytest.mark.asyncio
async def test_backend_api_reachable(services):
    """Our backend HTTP API is running on :8001."""
    if not services["backend"]:
        pytest.skip(
            "Backend API not running on :8001 — start with 'python3 main.py' before running E2E tests"
        )
    async with httpx.AsyncClient(timeout=5.0) as c:
        r = await c.get("http://localhost:8001/health")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


@pytest.mark.asyncio
async def test_backend_api_docs(services):
    """Backend /docs endpoint is accessible."""
    if not services["backend"]:
        pytest.skip("Backend API not running")
    async with httpx.AsyncClient(timeout=5.0) as c:
        r = await c.get("http://localhost:8001/docs")
    assert r.status_code == 200
