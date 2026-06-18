"""
OpenSOAR API Client Service.
Handles authentication and alert forwarding to OpenSOAR.

Two paths for sending alerts:
  1. send_alert()            → POST /api/v1/webhooks/alerts  (structured, pre-mapped data)
  2. forward_elastic_alert() → POST /api/v1/webhooks/alerts/elastic  (raw ES doc fallback)
"""

import asyncio
import httpx
import structlog
from typing import Optional, Dict, Any
from config import get_settings

logger = structlog.get_logger()

# 429 retry config
MAX_429_RETRIES = 4
BASE_429_DELAY = 2.0  # seconds


class OpenSOARClient:
    """Client for interacting with OpenSOAR API."""

    def __init__(self):
        self._settings = get_settings()
        self._token: Optional[str] = None
        self._http: Optional[httpx.AsyncClient] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_http(self) -> httpx.AsyncClient:
        current_loop = asyncio.get_running_loop()
        if self._http is None or self._loop is not current_loop:
            self._http = httpx.AsyncClient(
                base_url=self._settings.opensoar_url,
                timeout=httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=10.0),
            )
            self._loop = current_loop
        return self._http

    async def authenticate(self) -> bool:
        """Login and store Bearer token. Returns True on success."""
        try:
            resp = await self._get_http().post(
                "/api/v1/auth/login",
                json={
                    "username": self._settings.opensoar_username,
                    "password": self._settings.opensoar_password,
                },
            )
            if resp.status_code == 200:
                self._token = resp.json()["access_token"]
                logger.info("opensoar_authenticated", url=self._settings.opensoar_url)
                return True
            logger.error(
                "opensoar_auth_failed",
                status=resp.status_code,
                body=resp.text[:200],
            )
            return False
        except Exception as e:
            logger.error("opensoar_auth_error", error=str(e))
            return False

    def _auth_headers(self) -> dict:
        headers = {"Authorization": f"Bearer {self._token}"}
        if self._settings.opensoar_webhook_secret:
            headers["x-webhook-signature"] = self._settings.opensoar_webhook_secret
        return headers

    async def _post_with_retry(self, endpoint: str, payload: dict) -> httpx.Response:
        """POST with 401 re-auth and 429 exponential backoff."""
        if not self._token:
            if not await self.authenticate():
                raise RuntimeError("OpenSOAR authentication failed")

        http = self._get_http()

        for attempt in range(MAX_429_RETRIES + 1):
            try:
                resp = await asyncio.wait_for(
                    http.post(endpoint, json=payload, headers=self._auth_headers()),
                    timeout=15.0,
                )
            except asyncio.TimeoutError:
                logger.error(
                    "opensoar_request_timeout",
                    endpoint=endpoint,
                    attempt=attempt + 1,
                )
                if attempt >= MAX_429_RETRIES:
                    raise RuntimeError(
                        f"OpenSOAR request timed out after {MAX_429_RETRIES + 1} attempts"
                    )
                await asyncio.sleep(1)
                continue
            except Exception as e:
                logger.error(
                    "opensoar_request_error",
                    endpoint=endpoint,
                    attempt=attempt + 1,
                    error=str(e)[:100],
                )
                if attempt >= MAX_429_RETRIES:
                    raise
                await asyncio.sleep(1)
                continue

            # 401 → re-authenticate once
            if resp.status_code == 401:
                if not await self.authenticate():
                    raise RuntimeError("OpenSOAR re-authentication failed")
                resp = await http.post(
                    endpoint, json=payload, headers=self._auth_headers()
                )
                if resp.status_code == 401:
                    raise RuntimeError("OpenSOAR authentication rejected after retry")

            # 429 → exponential backoff with Retry-After support
            if resp.status_code == 429:
                if attempt >= MAX_429_RETRIES:
                    logger.error(
                        "opensoar_rate_limit_exhausted",
                        endpoint=endpoint,
                        attempts=attempt + 1,
                    )
                    break

                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        delay = float(retry_after)
                    except ValueError:
                        delay = BASE_429_DELAY * (2**attempt)
                else:
                    delay = BASE_429_DELAY * (2**attempt)

                logger.warning(
                    "opensoar_rate_limited",
                    endpoint=endpoint,
                    attempt=attempt + 1,
                    retry_in=delay,
                )
                await asyncio.sleep(delay)
                continue

            # Any other status → return immediately
            return resp

        return resp

    async def send_alert(self, alert_data: dict) -> dict:
        """
        Send a pre-mapped, structured alert to POST /api/v1/webhooks/alerts.
        This is the primary path — data is already normalized by our mappers.

        OpenSOAR will:
          - Store it as a clean, indexed, filterable alert
          - Trigger matching playbooks automatically
          - Handle dedup via source_id (returns 422 if duplicate)
        """
        resp = await self._post_with_retry("/api/v1/webhooks/alerts", alert_data)

        if resp.status_code == 422:
            source_id = alert_data.get("source_id", "unknown")
            logger.debug("alert_already_exists", source_id=source_id)
            return {"status": "already_exists", "source_id": source_id}

        resp.raise_for_status()
        return resp.json()

    async def forward_elastic_alert(self, payload: dict) -> dict:
        """
        POST a raw Elasticsearch document to OpenSOAR's Elastic webhook.
        Fallback path when mapping fails — OpenSOAR parses the raw doc itself.
        """
        resp = await self._post_with_retry("/api/v1/webhooks/alerts/elastic", payload)
        resp.raise_for_status()
        return resp.json()

    async def update_alert(self, alert_id: str, updates: dict) -> dict:
        """
        Update an existing alert via PATCH /api/v1/alerts/{id}.
        Used for grouping repeated alerts with occurrence count.
        """
        if not self._token:
            if not await self.authenticate():
                raise RuntimeError("OpenSOAR authentication failed")

        http = self._get_http()
        endpoint = f"/api/v1/alerts/{alert_id}"

        for attempt in range(MAX_429_RETRIES + 1):
            try:
                resp = await asyncio.wait_for(
                    http.patch(endpoint, json=updates, headers=self._auth_headers()),
                    timeout=15.0,
                )
            except asyncio.TimeoutError:
                if attempt >= MAX_429_RETRIES:
                    raise RuntimeError(
                        f"OpenSOAR PATCH timed out after {MAX_429_RETRIES + 1} attempts"
                    )
                await asyncio.sleep(1)
                continue
            except Exception as e:
                if attempt >= MAX_429_RETRIES:
                    raise
                await asyncio.sleep(1)
                continue

            if resp.status_code == 401:
                if not await self.authenticate():
                    raise RuntimeError("OpenSOAR re-authentication failed")
                resp = await http.patch(
                    endpoint, json=updates, headers=self._auth_headers()
                )
                if resp.status_code == 401:
                    raise RuntimeError("OpenSOAR authentication rejected after retry")

            if resp.status_code == 429:
                if attempt >= MAX_429_RETRIES:
                    break
                retry_after = resp.headers.get("Retry-After")
                delay = (
                    float(retry_after) if retry_after else BASE_429_DELAY * (2**attempt)
                )
                await asyncio.sleep(delay)
                continue

            resp.raise_for_status()
            return resp.json()

    async def _request_with_retry(
        self, method: str, endpoint: str, **kwargs
    ) -> httpx.Response:
        """Generic request with 401 re-auth and 429 exponential backoff."""
        if not self._token:
            if not await self.authenticate():
                raise RuntimeError("OpenSOAR authentication failed")

        http = self._get_http()
        headers = self._auth_headers()

        for attempt in range(MAX_429_RETRIES + 1):
            try:
                if method.upper() == "GET":
                    resp = await asyncio.wait_for(
                        http.get(endpoint, headers=headers, **kwargs),
                        timeout=15.0,
                    )
                elif method.upper() == "PATCH":
                    resp = await asyncio.wait_for(
                        http.patch(endpoint, headers=headers, **kwargs),
                        timeout=15.0,
                    )
                elif method.upper() == "DELETE":
                    resp = await asyncio.wait_for(
                        http.delete(endpoint, headers=headers, **kwargs),
                        timeout=15.0,
                    )
                else:
                    raise ValueError(f"Unsupported method: {method}")
            except asyncio.TimeoutError:
                if attempt >= MAX_429_RETRIES:
                    raise RuntimeError(
                        f"OpenSOAR request timed out after {MAX_429_RETRIES + 1} attempts"
                    )
                await asyncio.sleep(1)
                continue
            except Exception as e:
                if attempt >= MAX_429_RETRIES:
                    raise
                await asyncio.sleep(1)
                continue

            if resp.status_code == 401:
                if not await self.authenticate():
                    raise RuntimeError("OpenSOAR re-authentication failed")
                if method.upper() == "GET":
                    resp = await http.get(
                        endpoint, headers=self._auth_headers(), **kwargs
                    )
                elif method.upper() == "PATCH":
                    resp = await http.patch(
                        endpoint, headers=self._auth_headers(), **kwargs
                    )
                elif method.upper() == "DELETE":
                    resp = await http.delete(
                        endpoint, headers=self._auth_headers(), **kwargs
                    )
                if resp.status_code == 401:
                    raise RuntimeError("OpenSOAR authentication rejected after retry")

            if resp.status_code == 429:
                if attempt >= MAX_429_RETRIES:
                    break
                retry_after = resp.headers.get("Retry-After")
                delay = (
                    float(retry_after) if retry_after else BASE_429_DELAY * (2**attempt)
                )
                await asyncio.sleep(delay)
                continue

            return resp

        return resp

    async def check_health(self) -> dict:
        """GET /api/v1/health — health check."""
        try:
            http = self._get_http()
            resp = await asyncio.wait_for(http.get("/api/v1/health"), timeout=5.0)
            if resp.status_code == 200:
                return {"healthy": True, "status": resp.text.strip()[:100]}
            return {"healthy": False, "status": resp.status_code}
        except Exception as e:
            return {"healthy": False, "error": str(e)[:100]}

    async def list_alerts(self, limit: int = 50, offset: int = 0, **filters) -> dict:
        """GET /api/v1/alerts — list alerts with optional filters."""
        params = {"limit": min(limit, 200), "offset": offset}
        params.update({k: v for k, v in filters.items() if v is not None})
        resp = await self._request_with_retry("GET", "/api/v1/alerts", params=params)
        resp.raise_for_status()
        return resp.json()

    async def get_alert(self, alert_id: str) -> dict:
        """GET /api/v1/alerts/{alert_id} — get full alert details."""
        resp = await self._request_with_retry("GET", f"/api/v1/alerts/{alert_id}")
        resp.raise_for_status()
        return resp.json()

    async def list_incidents(self, limit: int = 50, offset: int = 0, **filters) -> dict:
        """GET /api/v1/incidents — list incidents with optional filters."""
        params = {"limit": min(limit, 200), "offset": offset}
        params.update({k: v for k, v in filters.items() if v is not None})
        resp = await self._request_with_retry("GET", "/api/v1/incidents", params=params)
        resp.raise_for_status()
        return resp.json()

    async def create_incident(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        tags: list = None,
    ) -> dict:
        """POST /api/v1/incidents — create a new incident."""
        payload = {"title": title, "description": description, "severity": severity}
        if tags:
            payload["tags"] = tags
        resp = await self._post_with_retry("/api/v1/incidents", payload)
        resp.raise_for_status()
        return resp.json()

    async def get_incident(self, incident_id: str) -> dict:
        """GET /api/v1/incidents/{id} — get incident details."""
        resp = await self._request_with_retry("GET", f"/api/v1/incidents/{incident_id}")
        resp.raise_for_status()
        return resp.json()

    async def update_incident(self, incident_id: str, updates: dict) -> dict:
        """PATCH /api/v1/incidents/{id} — update incident fields."""
        resp = await self._request_with_retry(
            "PATCH", f"/api/v1/incidents/{incident_id}", json=updates
        )
        resp.raise_for_status()
        return resp.json()

    async def link_alert_to_incident(self, incident_id: str, alert_id: str) -> bool:
        """POST /api/v1/incidents/{id}/alerts — link an alert to an incident."""
        try:
            resp = await self._post_with_retry(
                f"/api/v1/incidents/{incident_id}/alerts",
                {"alert_id": alert_id},
            )
            if resp.status_code in (200, 201):
                return True
            if resp.status_code == 422:
                return False
            if resp.status_code == 409:
                logger.info(
                    "alert_already_linked", incident_id=incident_id, alert_id=alert_id
                )
                return True
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.warning(
                "link_alert_failed",
                incident_id=incident_id,
                alert_id=alert_id,
                error=str(e)[:100],
            )
            return False

    async def get_incident_alerts(self, incident_id: str) -> list:
        """GET /api/v1/incidents/{id}/alerts — list alerts linked to an incident."""
        try:
            resp = await self._request_with_retry(
                "GET", f"/api/v1/incidents/{incident_id}/alerts"
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and "alerts" in data:
                    return data["alerts"]
            return []
        except Exception as e:
            logger.warning(
                "get_incident_alerts_failed",
                incident_id=incident_id,
                error=str(e)[:100],
            )
            return []

    async def unlink_alert_from_incident(self, incident_id: str, alert_id: str) -> bool:
        """DELETE /api/v1/incidents/{id}/alerts/{alert_id} — unlink an alert."""
        try:
            resp = await self._request_with_retry(
                "DELETE", f"/api/v1/incidents/{incident_id}/alerts/{alert_id}"
            )
            return resp.status_code in (200, 204)
        except Exception as e:
            logger.warning(
                "unlink_alert_failed",
                incident_id=incident_id,
                alert_id=alert_id,
                error=str(e)[:100],
            )
            return False

    async def get_incident_suggestions(self) -> dict:
        """GET /api/v1/incidents/suggestions — get OpenSOAR's correlation suggestions."""
        try:
            resp = await self._request_with_retry(
                "GET", "/api/v1/incidents/suggestions"
            )
            if resp.status_code == 200:
                return resp.json()
            return {}
        except Exception as e:
            logger.warning("incident_suggestions_failed", error=str(e)[:100])
            return {}

    async def create_alert(self, source: str, doc: Dict[str, Any]) -> dict:
        """Create an alert from a raw doc (maps + sends). For external callers."""
        from pipeline.mappers import map_alert

        alert_data = map_alert(source, doc)
        return await self.send_alert(alert_data)

    async def close(self) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None
            self._loop = None


client = OpenSOARClient()
