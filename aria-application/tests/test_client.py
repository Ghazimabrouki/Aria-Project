"""
Tests for OpenSOAR API client: auth, send_alert, 429 retry, 422 dedup, fallback.
"""

import pytest
import httpx
import respx
from unittest.mock import patch, AsyncMock

from pipeline.sender import OpenSOARClient


@pytest.fixture
def mock_settings():
    """Mock settings for client."""
    class FakeSettings:
        opensoar_url = "http://test-soar:8000"
        opensoar_username = "admin"
        opensoar_password = "password"
        opensoar_webhook_secret = ""
    return FakeSettings()


@pytest.fixture
def client(mock_settings):
    with patch("pipeline.sender.get_settings", return_value=mock_settings):
        c = OpenSOARClient()
        yield c


@pytest.fixture
def alert_payload():
    return {
        "source": "wazuh",
        "source_id": "test-001",
        "title": "Test Alert",
        "description": "Test description",
        "severity": "high",
        "status": "new",
        "source_ip": "1.1.1.1",
        "dest_ip": "2.2.2.2",
        "hostname": "test-host",
        "rule_name": "test rule",
        "tags": ["test"],
        "iocs": {"ip": ["1.1.1.1"]},
    }


# ═══════════════════════════════════════════════════════════════════════════
#  Authentication
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth:

    @pytest.mark.asyncio
    @respx.mock
    async def test_auth_success(self, client):
        respx.post("http://test-soar:8000/api/v1/auth/login").mock(
            return_value=httpx.Response(200, json={"access_token": "tok123"})
        )
        result = await client.authenticate()
        assert result is True
        assert client._token == "tok123"

    @pytest.mark.asyncio
    @respx.mock
    async def test_auth_failure(self, client):
        respx.post("http://test-soar:8000/api/v1/auth/login").mock(
            return_value=httpx.Response(401, json={"detail": "bad credentials"})
        )
        result = await client.authenticate()
        assert result is False
        assert client._token is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_auth_network_error(self, client):
        respx.post("http://test-soar:8000/api/v1/auth/login").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        result = await client.authenticate()
        assert result is False


# ═══════════════════════════════════════════════════════════════════════════
#  send_alert
# ═══════════════════════════════════════════════════════════════════════════

class TestSendAlert:

    @pytest.mark.asyncio
    @respx.mock
    async def test_send_success(self, client, alert_payload):
        respx.post("http://test-soar:8000/api/v1/auth/login").mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        respx.post("http://test-soar:8000/api/v1/webhooks/alerts").mock(
            return_value=httpx.Response(201, json={"alert_id": "uuid-1", "title": "Test"})
        )

        result = await client.send_alert(alert_payload)
        assert result["alert_id"] == "uuid-1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_send_dedup_422(self, client, alert_payload):
        """OpenSOAR returns 422 for duplicate source_id — should not raise."""
        respx.post("http://test-soar:8000/api/v1/auth/login").mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        respx.post("http://test-soar:8000/api/v1/webhooks/alerts").mock(
            return_value=httpx.Response(422, json={"detail": "already exists"})
        )

        result = await client.send_alert(alert_payload)
        assert result["status"] == "already_exists"
        assert result["source_id"] == "test-001"

    @pytest.mark.asyncio
    @respx.mock
    async def test_send_auto_auth(self, client, alert_payload):
        """Client should auto-authenticate if no token."""
        respx.post("http://test-soar:8000/api/v1/auth/login").mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        respx.post("http://test-soar:8000/api/v1/webhooks/alerts").mock(
            return_value=httpx.Response(201, json={"alert_id": "uuid-2"})
        )

        assert client._token is None
        result = await client.send_alert(alert_payload)
        assert client._token == "tok"
        assert result["alert_id"] == "uuid-2"


# ═══════════════════════════════════════════════════════════════════════════
#  401 re-auth
# ═══════════════════════════════════════════════════════════════════════════

class TestReAuth:

    @pytest.mark.asyncio
    @respx.mock
    async def test_reauth_on_401(self, client, alert_payload):
        """First request 401 → re-auth → retry succeeds."""
        client._token = "expired_token"

        call_count = 0

        def alerts_handler(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(401)
            return httpx.Response(201, json={"alert_id": "uuid-3"})

        respx.post("http://test-soar:8000/api/v1/auth/login").mock(
            return_value=httpx.Response(200, json={"access_token": "new_tok"})
        )
        respx.post("http://test-soar:8000/api/v1/webhooks/alerts").mock(
            side_effect=alerts_handler
        )

        result = await client.send_alert(alert_payload)
        assert result["alert_id"] == "uuid-3"
        assert client._token == "new_tok"


# ═══════════════════════════════════════════════════════════════════════════
#  429 rate limit retry
# ═══════════════════════════════════════════════════════════════════════════

class TestRateLimitRetry:

    @pytest.mark.asyncio
    @respx.mock
    async def test_429_retry_then_success(self, client, alert_payload):
        """429 twice, then 201 — should succeed."""
        client._token = "tok"

        call_count = 0

        def handler(request):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return httpx.Response(429, headers={"Retry-After": "0.01"})
            return httpx.Response(201, json={"alert_id": "uuid-4"})

        respx.post("http://test-soar:8000/api/v1/webhooks/alerts").mock(side_effect=handler)

        result = await client.send_alert(alert_payload)
        assert result["alert_id"] == "uuid-4"
        assert call_count == 3

    @pytest.mark.asyncio
    @respx.mock
    async def test_429_exhausted(self, client, alert_payload):
        """429 every time → should raise after max retries."""
        client._token = "tok"

        respx.post("http://test-soar:8000/api/v1/webhooks/alerts").mock(
            return_value=httpx.Response(429)
        )

        with pytest.raises(httpx.HTTPStatusError):
            await client.send_alert(alert_payload)


# ═══════════════════════════════════════════════════════════════════════════
#  forward_elastic_alert (fallback endpoint)
# ═══════════════════════════════════════════════════════════════════════════

class TestForwardElastic:

    @pytest.mark.asyncio
    @respx.mock
    async def test_forward_raw(self, client):
        respx.post("http://test-soar:8000/api/v1/auth/login").mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        respx.post("http://test-soar:8000/api/v1/webhooks/alerts/elastic").mock(
            return_value=httpx.Response(200, json={"alert_id": "uuid-5", "message": "ok"})
        )

        raw = {"_id": "raw-001", "rule": {"name": "test"}, "@timestamp": "2026-04-05T00:00:00Z"}
        result = await client.forward_elastic_alert(raw)
        assert result["alert_id"] == "uuid-5"


# ═══════════════════════════════════════════════════════════════════════════
#  create_alert (map + send convenience method)
# ═══════════════════════════════════════════════════════════════════════════

class TestCreateAlert:

    @pytest.mark.asyncio
    @respx.mock
    async def test_create_maps_and_sends(self, client):
        respx.post("http://test-soar:8000/api/v1/auth/login").mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        respx.post("http://test-soar:8000/api/v1/webhooks/alerts").mock(
            return_value=httpx.Response(201, json={"alert_id": "uuid-6"})
        )

        doc = {
            "_id": "create-001",
            "rule": {"id": "999", "name": "Test Rule", "level": 5},
            "agent": {"id": "001", "name": "host-01"},
            "data": {},
            "full_log": "test log",
        }

        result = await client.create_alert("wazuh", doc)
        assert result["alert_id"] == "uuid-6"

        # Verify the POST body was structured (mapped), not raw
        sent_body = respx.calls[-1].request.content
        import json
        sent = json.loads(sent_body)
        assert sent["source"] == "wazuh"
        assert sent["title"] == "Test Rule"


# ═══════════════════════════════════════════════════════════════════════════
#  Webhook signature header
# ═══════════════════════════════════════════════════════════════════════════

class TestWebhookSignature:

    @pytest.mark.asyncio
    @respx.mock
    async def test_signature_header_when_configured(self):
        class FakeSettings:
            opensoar_url = "http://test-soar:8000"
            opensoar_username = "admin"
            opensoar_password = "password"
            opensoar_webhook_secret = "my-secret-key"

        with patch("pipeline.sender.get_settings", return_value=FakeSettings()):
            c = OpenSOARClient()

        respx.post("http://test-soar:8000/api/v1/auth/login").mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        respx.post("http://test-soar:8000/api/v1/webhooks/alerts").mock(
            return_value=httpx.Response(201, json={"alert_id": "uuid-7"})
        )

        await c.send_alert({"source_id": "test"})
        req = respx.calls[-1].request
        assert req.headers.get("x-webhook-signature") == "my-secret-key"
