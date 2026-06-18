"""
Auth Manager.
All /auth/* endpoints + token lifecycle + analyst cache + capability detection.
"""

import asyncio
import time
import structlog
from typing import Optional, Dict, Any, List

from pipeline.sender import client
from config import get_settings

logger = structlog.get_logger()


class AuthManager:
    def __init__(self):
        self._capabilities: Optional[Dict[str, Any]] = None
        self._current_user: Optional[Dict[str, Any]] = None
        self._analysts_cache: Optional[List[Dict[str, Any]]] = None
        self._analysts_cache_time: float = 0
        self._capabilities_cache_time: float = 0
        self._cache_ttl = 300

    async def get_capabilities(self) -> Dict[str, Any]:
        if self._capabilities and (time.time() - self._capabilities_cache_time) < self._cache_ttl:
            return self._capabilities

        try:
            resp = await client._get_http().get(
                "/api/v1/auth/capabilities",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._capabilities = resp.json()
            self._capabilities_cache_time = time.time()
            logger.info("auth_capabilities_fetched", local_login=self._capabilities.get("local_login_enabled"), providers=len(self._capabilities.get("providers", [])))
            return self._capabilities
        except Exception as e:
            logger.error("get_capabilities_failed", error=str(e))
            return {}

    async def get_me(self) -> Optional[Dict[str, Any]]:
        try:
            resp = await client._get_http().get(
                "/api/v1/auth/me",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._current_user = resp.json()
            return self._current_user
        except Exception as e:
            logger.error("get_me_failed", error=str(e))
            return None

    async def list_analysts(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        if self._analysts_cache and not force_refresh and (time.time() - self._analysts_cache_time) < self._cache_ttl:
            return self._analysts_cache

        try:
            resp = await client._get_http().get(
                "/api/v1/auth/analysts",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._analysts_cache = resp.json()
            self._analysts_cache_time = time.time()
            logger.debug("analysts_cached", count=len(self._analysts_cache))
            return self._analysts_cache
        except Exception as e:
            logger.error("list_analysts_failed", error=str(e))
            return self._analysts_cache or []

    async def update_analyst(self, analyst_id: str, updates: dict) -> Optional[Dict[str, Any]]:
        try:
            resp = await client._get_http().patch(
                f"/api/v1/auth/analysts/{analyst_id}",
                json=updates,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            result = resp.json()
            self._analysts_cache = None
            logger.info("analyst_updated", analyst_id=analyst_id)
            return result
        except Exception as e:
            logger.error("update_analyst_failed", analyst_id=analyst_id, error=str(e))
            return None

    async def register_user(self, username: str, password: str, email: str = "", display_name: str = "", role: str = "analyst") -> Optional[Dict[str, Any]]:
        try:
            resp = await client._get_http().post(
                "/api/v1/auth/register",
                json={
                    "username": username,
                    "password": password,
                    "email": email or f"{username}@opensoar.local",
                    "display_name": display_name or username,
                    "role": role,
                },
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info("user_registered", username=username, role=role)
            return result
        except Exception as e:
            logger.error("register_user_failed", username=username, error=str(e))
            return None

    async def find_analyst_by_role(self, role: str) -> Optional[Dict[str, Any]]:
        analysts = await self.list_analysts()
        for a in analysts:
            if a.get("role") == role and a.get("is_active"):
                return a
        return None

    async def find_analyst_by_name(self, username: str) -> Optional[Dict[str, Any]]:
        analysts = await self.list_analysts()
        for a in analysts:
            if a.get("username") == username and a.get("is_active"):
                return a
        return None

    def get_analyst_id(self, username: str) -> Optional[str]:
        if self._analysts_cache:
            for a in self._analysts_cache:
                if a.get("username") == username:
                    return a.get("id")
        return None

    def get_current_user_id(self) -> Optional[str]:
        if self._current_user:
            return self._current_user.get("id")
        return None

    def get_current_username(self) -> Optional[str]:
        if self._current_user:
            return self._current_user.get("username")
        return None


auth_manager = AuthManager()
