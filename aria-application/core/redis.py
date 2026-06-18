import redis.asyncio as redis
import asyncio
from typing import Optional
import structlog

logger = structlog.get_logger()

_redis_client: Optional[redis.Redis] = None
_redis_loop: Optional[asyncio.AbstractEventLoop] = None


async def get_redis_client() -> redis.Redis:
    global _redis_client, _redis_loop
    current_loop = asyncio.get_running_loop()
    
    if _redis_client is not None and _redis_loop is current_loop:
        return _redis_client

    # Close old client if loop changed
    if _redis_client is not None and _redis_loop is not current_loop:
        try:
            await _redis_client.close()
        except Exception:
            pass

    from config import get_settings
    settings = get_settings()

    _redis_client = redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        decode_responses=True,
    )
    _redis_loop = current_loop
    logger.info("redis_client_initialized", host=settings.redis_host, port=settings.redis_port)

    return _redis_client


async def close_redis_client() -> None:
    global _redis_client, _redis_loop
    if _redis_client:
        try:
            await _redis_client.close()
        except Exception:
            pass
        _redis_client = None
        _redis_loop = None
        logger.info("redis_client_closed")


class RedisManager:
    def __init__(self):
        self._client: Optional[redis.Redis] = None

    async def __aenter__(self):
        self._client = await get_redis_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.close()

    async def get(self, key: str) -> Optional[str]:
        if self._client:
            return await self._client.get(key)
        return None

    async def set(self, key: str, value: str, ttl: Optional[int] = None) -> None:
        if self._client:
            if ttl:
                await self._client.setex(key, ttl, value)
            else:
                await self._client.set(key, value)

    async def delete(self, key: str) -> None:
        if self._client:
            await self._client.delete(key)

    async def keys(self, pattern: str) -> list:
        if self._client:
            return await self._client.keys(pattern)
        return []