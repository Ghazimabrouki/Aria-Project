"""
E2E test fixtures and service health helpers.

All tests hit real services:
  - Elasticsearch  https://193.95.30.97:9200
  - OpenSOAR       http://193.95.30.97:8000
  - Ollama         http://193.95.30.97:11434
  - Our Backend    http://localhost:8001  (must be running separately)

A test is automatically skipped if its required service is unreachable.
Test data is tagged with E2E_TAG so cleanup can find and delete it.
"""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

# Project root on path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import get_settings

settings = get_settings()

# Tag all test-created data so cleanup can find it
E2E_TAG = "e2e-test"
E2E_SOURCE_PREFIX = "e2e-test-"


# ─── Test alert factory ────────────────────────────────────────────────────────

def make_test_alert(source: str = "wazuh", severity: str = "medium", **overrides) -> dict:
    """Create a test alert payload."""
    alert_id = str(uuid.uuid4())
    base = {
        "source": source,
        "source_id": f"{E2E_SOURCE_PREFIX}{alert_id}",
        "title": f"[E2E] Test {source.upper()} Alert",
        "description": f"E2E test alert created at {datetime.now(timezone.utc).isoformat()}",
        "severity": severity,
        "status": "new",
        "source_ip": "10.0.0.1",
        "dest_ip": "192.168.1.1",
        "hostname": "test-host",
        "rule_name": f"test_rule_{source}",
        "tags": [E2E_TAG],
        "iocs": {"ip": ["10.0.0.1", "192.168.1.1"]},
    }
    base.update(overrides)
    return base


# ─── Connectivity probes ──────────────────────────────────────────────────────

async def _probe(url: str, timeout: float = 5.0) -> bool:
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as c:
            r = await c.get(url)
            return r.status_code < 500
    except Exception:
        return False


async def _probe_es() -> bool:
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as c:
            r = await c.get(
                f"{settings.elasticsearch_url}/_cluster/health",
                auth=(settings.elasticsearch_user, settings.elasticsearch_password),
            )
            return r.status_code == 200
    except Exception:
        return False


async def _probe_opensoar() -> bool:
    return await _probe(f"{settings.opensoar_url}/api/v1/health")


async def _probe_ollama() -> bool:
    return await _probe(f"{settings.ollama_host}/api/tags")


async def _probe_backend() -> bool:
    return await _probe("http://localhost:8001/health", timeout=10.0)


# ─── Backend server lifecycle ─────────────────────────────────────────────────

_backend_process = None

def pytest_sessionstart(session):
    """Start backend server before any tests run."""
    import subprocess
    import time
    
    global _backend_process
    
    # Start the backend server with log output to see issues
    env = os.environ.copy()
    env["SEARCH_RATE_LIMIT_MAX"] = "1000"
    _backend_process = subprocess.Popen(
        ["python3", "-m", "uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8001"],
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    
    # Wait longer for server to be ready
    max_attempts = 60
    for i in range(max_attempts):
        try:
            import httpx
            r = httpx.get("http://localhost:8001/health", timeout=5)
            if r.status_code == 200:
                print(f"\n[E2E] Backend server started on port 8001")
                break
        except Exception as e:
            time.sleep(1)
    else:
        # Print any startup errors
        if _backend_process.poll() is not None:
            stdout, stderr = _backend_process.communicate()
            print(f"\n[E2E] Backend server failed to start:")
            print(f"stdout: {stdout.decode()[:500]}")
            print(f"stderr: {stderr.decode()[:500]}")
        else:
            print(f"\n[E2E] Warning: Backend server may not be ready")


def pytest_sessionfinish(session, exitstatus):
    """Stop backend server after all tests complete."""
    global _backend_process
    if _backend_process:
        _backend_process.terminate()
        try:
            _backend_process.wait(timeout=5)
        except:
            _backend_process.kill()
        print(f"\n[E2E] Backend server stopped")


# ─── Session-scoped service availability flags ────────────────────────────────

def pytest_configure(config):
    """Create session event loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)


# ─── OpenSOAR HTTP client ─────────────────────────────────────────────────────

class OpenSOARTestClient:
    """Authenticated OpenSOAR client for E2E tests."""

    def __init__(self):
        self._token = None
        self._http = httpx.AsyncClient(
            base_url=settings.opensoar_url,
            timeout=httpx.Timeout(30.0),
        )

    async def auth(self):
        r = await self._http.post(
            "/api/v1/auth/login",
            json={"username": settings.opensoar_username, "password": settings.opensoar_password},
        )
        assert r.status_code == 200, f"Auth failed: {r.status_code} {r.text[:200]}"
        self._token = r.json()["access_token"]

    @property
    def h(self):
        return {"Authorization": f"Bearer {self._token}"}

    async def get(self, path, **kw):
        return await self._http.get(path, headers=self.h, **kw)

    async def post(self, path, **kw):
        return await self._http.post(path, headers=self.h, **kw)

    async def patch(self, path, **kw):
        return await self._http.patch(path, headers=self.h, **kw)

    async def delete(self, path, **kw):
        return await self._http.delete(path, headers=self.h, **kw)

    async def close(self):
        await self._http.aclose()


@pytest_asyncio.fixture
async def services():
    """Probe all services for each test. Tests use these flags to skip."""
    return {
        "es":       await _probe_es(),
        "opensoar": await _probe_opensoar(),
        "ollama":   await _probe_ollama(),
        "backend":  await _probe_backend(),
    }


@pytest_asyncio.fixture
async def soar():
    """Authenticated OpenSOAR client for each test."""
    client = OpenSOARTestClient()
    await client.auth()
    yield client
    await client.close()


@pytest_asyncio.fixture
async def cleanup():
    """Track test-created resources for cleanup."""
    return {"alerts": [], "incidents": [], "observables": []}


def skip_if_missing(services_fixture, *needed):
    """Call inside a test to skip if a service is down."""
    for svc in needed:
        if not services_fixture.get(svc):
            pytest.skip(f"Service '{svc}' is not reachable — skipping")


# ─── Test cleanup helpers ──────────────────────────────────────────────────────

async def cleanup_opensoar_test_data(client: OpenSOARTestClient):
    """Delete test alerts/incidents created during E2E tests."""
    # This would delete alerts/incidents tagged with E2E_TAG
    # Implementation depends on OpenSOAR API capabilities
    pass


# ─── Elasticsearch fixtures ──────────────────────────────────────────────────

@pytest_asyncio.fixture
async def es():
    """Elasticsearch client for tests."""
    from elasticsearch import AsyncElasticsearch
    
    client = AsyncElasticsearch(
        hosts=[settings.elasticsearch_url],
        basic_auth=(settings.elasticsearch_user, settings.elasticsearch_password),
        verify_certs=False,
    )
    yield client
    await client.close()


@pytest_asyncio.fixture
async def sender():
    """OpenSOAR sender client for tests."""
    from pipeline.sender import OpenSOARClient
    client = OpenSOARClient()
    await client.authenticate()
    yield client


@pytest_asyncio.fixture
async def backend_client():
    """Our backend API client for tests."""
    client = httpx.AsyncClient(
        base_url="http://localhost:8001",
        timeout=httpx.Timeout(60.0),
    )
    yield client
    await client.aclose()

