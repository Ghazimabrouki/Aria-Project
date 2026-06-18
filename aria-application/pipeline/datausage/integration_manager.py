"""
Integration Manager.
Integrations CRUD + health monitoring + degradation detection.
"""

import asyncio
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from pipeline.sender import client
from config import get_settings

logger = structlog.get_logger()


class IntegrationManager:
    def __init__(self):
        self._integrations_cache: Optional[List[Dict[str, Any]]] = None
        self._cache_time: float = 0
        self._cache_ttl = 300
        self._health_check_count = 0
        self._degraded_count = 0

    async def list_types(self) -> Any:
        try:
            resp = await client._get_http().get(
                "/api/v1/integrations/types",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("list_integration_types_failed", error=str(e))
            return []

    async def list_integrations(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        if self._integrations_cache and not force_refresh:
            return self._integrations_cache

        try:
            resp = await client._get_http().get(
                "/api/v1/integrations",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._integrations_cache = resp.json()
            self._cache_time = datetime.now(timezone.utc).timestamp()
            return self._integrations_cache
        except Exception as e:
            logger.error("list_integrations_failed", error=str(e))
            return self._integrations_cache or []

    async def get_integration(self, integration_id: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await client._get_http().get(
                f"/api/v1/integrations/{integration_id}",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("get_integration_failed", integration_id=integration_id, error=str(e))
            return None

    async def create_integration(
        self,
        integration_type: str,
        name: str,
        partner: str = "",
        config: Optional[dict] = None,
        enabled: bool = True,
    ) -> Optional[Dict[str, Any]]:
        payload: Dict[str, Any] = {
            "integration_type": integration_type,
            "name": name,
            "partner": partner,
            "enabled": enabled,
        }
        if config:
            payload["config"] = config

        try:
            resp = await client._get_http().post(
                "/api/v1/integrations",
                json=payload,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._integrations_cache = None
            result = resp.json()
            logger.info("integration_created", integration_id=result.get("id"), name=name)
            return result
        except Exception as e:
            logger.error("create_integration_failed", name=name, error=str(e))
            return None

    async def update_integration(self, integration_id: str, updates: dict) -> Optional[Dict[str, Any]]:
        try:
            resp = await client._get_http().patch(
                f"/api/v1/integrations/{integration_id}",
                json=updates,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._integrations_cache = None
            return resp.json()
        except Exception as e:
            logger.error("update_integration_failed", integration_id=integration_id, error=str(e))
            return None

    async def delete_integration(self, integration_id: str) -> bool:
        try:
            resp = await client._get_http().delete(
                f"/api/v1/integrations/{integration_id}",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._integrations_cache = None
            logger.info("integration_deleted", integration_id=integration_id)
            return True
        except Exception as e:
            logger.error("delete_integration_failed", integration_id=integration_id, error=str(e))
            return False

    async def check_health(self, integration_id: str) -> Any:
        try:
            resp = await client._get_http().post(
                f"/api/v1/integrations/{integration_id}/health",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._health_check_count += 1
            result = resp.json()
            logger.debug("integration_health_checked", integration_id=integration_id)
            return result
        except Exception as e:
            self._degraded_count += 1
            logger.error("integration_health_check_failed", integration_id=integration_id, error=str(e))
            return None

    async def check_all_health(self) -> Dict[str, Any]:
        integrations = await self.list_integrations()
        results = {}

        for integration in integrations:
            iid = integration["id"]
            name = integration.get("name", iid)
            health = await self.check_health(iid)
            results[iid] = {
                "name": name,
                "previous_status": integration.get("health_status"),
                "result": health,
            }

        degraded = [r for r in results.values() if r.get("result") and "unhealthy" in str(r.get("result", "")).lower()]
        if degraded:
            logger.warning("degraded_integrations_detected", count=len(degraded))

        return results

    async def auto_detect_missing(self) -> List[str]:
        types = await self.list_types()
        existing = await self.list_integrations()
        existing_types = {i.get("integration_type") for i in existing}

        missing = []
        if isinstance(types, list):
            for t in types:
                t_type = t.get("id") or t.get("type") or str(t)
                if t_type and t_type not in existing_types:
                    missing.append(t_type)

        if missing:
            logger.info("missing_integrations_detected", types=missing)

        return missing

    def get_stats(self) -> Dict[str, Any]:
        return {
            "health_checks": self._health_check_count,
            "degraded_detected": self._degraded_count,
            "cached_count": len(self._integrations_cache) if self._integrations_cache else 0,
        }


integration_manager = IntegrationManager()
