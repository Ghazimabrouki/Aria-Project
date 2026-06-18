"""
API Key Manager.
API keys lifecycle + auto-rotation tracking + usage monitoring.
"""

import asyncio
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta

from pipeline.sender import client
from config import get_settings

logger = structlog.get_logger()


class APIKeyManager:
    def __init__(self):
        self._keys_cache: Optional[List[Dict[str, Any]]] = None
        self._cache_time: float = 0
        self._cache_ttl = 300
        self._rotation_days = 90
        self._unused_days = 30

    async def list_keys(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        if self._keys_cache and not force_refresh:
            return self._keys_cache

        try:
            resp = await client._get_http().get(
                "/api/v1/api-keys",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._keys_cache = resp.json()
            self._cache_time = datetime.now(timezone.utc).timestamp()
            return self._keys_cache
        except Exception as e:
            logger.error("list_api_keys_failed", error=str(e))
            return self._keys_cache or []

    async def create_key(self, name: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await client._get_http().post(
                "/api/v1/api-keys",
                json={"name": name},
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._keys_cache = None
            result = resp.json()
            logger.info("api_key_created", name=name, prefix=result.get("prefix"))
            return result
        except Exception as e:
            logger.error("create_api_key_failed", name=name, error=str(e))
            return None

    async def revoke_key(self, key_id: str) -> bool:
        try:
            resp = await client._get_http().delete(
                f"/api/v1/api-keys/{key_id}",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._keys_cache = None
            logger.info("api_key_revoked", key_id=key_id)
            return True
        except Exception as e:
            logger.error("revoke_api_key_failed", key_id=key_id, error=str(e))
            return False

    async def find_key_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        keys = await self.list_keys()
        for key in keys:
            if key.get("name") == name:
                return key
        return None

    def check_rotation_needed(self) -> List[Dict[str, Any]]:
        keys = self._keys_cache or []
        now = datetime.now(timezone.utc)
        needs_rotation = []

        for key in keys:
            created_at = key.get("created_at", "")
            if created_at:
                try:
                    created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                    age = now - created
                    if age > timedelta(days=self._rotation_days):
                        needs_rotation.append({
                            "key": key,
                            "age_days": age.days,
                            "reason": "rotation_period_exceeded",
                        })
                except ValueError:
                    pass

        return needs_rotation

    def check_unused_keys(self) -> List[Dict[str, Any]]:
        keys = self._keys_cache or []
        now = datetime.now(timezone.utc)
        unused = []

        for key in keys:
            last_used = key.get("last_used_at")
            if not last_used:
                created_at = key.get("created_at", "")
                if created_at:
                    try:
                        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        age = now - created
                        if age > timedelta(days=self._unused_days):
                            unused.append({
                                "key": key,
                                "never_used": True,
                                "age_days": age.days,
                                "reason": "never_used",
                            })
                    except ValueError:
                        pass
            else:
                try:
                    last = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                    idle = now - last
                    if idle > timedelta(days=self._unused_days):
                        unused.append({
                            "key": key,
                            "never_used": False,
                            "idle_days": idle.days,
                            "reason": "unused_period",
                        })
                except ValueError:
                    pass

        return unused

    async def auto_cleanup(self) -> Dict[str, int]:
        unused = self.check_unused_keys()
        revoked = 0

        for item in unused:
            if item.get("never_used") and item.get("age_days", 0) > 60:
                key_id = item["key"]["id"]
                if await self.revoke_key(key_id):
                    revoked += 1

        return {"revoked_unused": revoked, "flagged": len(unused)}

    def get_stats(self) -> Dict[str, Any]:
        keys = self._keys_cache or []
        active = sum(1 for k in keys if k.get("is_active"))
        rotation_needed = len(self.check_rotation_needed())
        unused = len(self.check_unused_keys())

        return {
            "total": len(keys),
            "active": active,
            "needs_rotation": rotation_needed,
            "unused": unused,
            "rotation_days": self._rotation_days,
        }


apikey_manager = APIKeyManager()
