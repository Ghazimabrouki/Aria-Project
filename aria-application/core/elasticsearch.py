import asyncio
from typing import Optional
from elasticsearch import AsyncElasticsearch
import structlog

logger = structlog.get_logger()

_client: Optional[AsyncElasticsearch] = None
_es_loop: Optional[asyncio.AbstractEventLoop] = None
_init_lock: Optional[asyncio.Lock] = None
_lock_loop: Optional[asyncio.AbstractEventLoop] = None


def _get_init_lock() -> asyncio.Lock:
    global _init_lock, _lock_loop
    current_loop = asyncio.get_running_loop()
    if _init_lock is None or _lock_loop is not current_loop:
        _init_lock = asyncio.Lock()
        _lock_loop = current_loop
    return _init_lock


async def get_es_client() -> AsyncElasticsearch:
    global _client, _es_loop
    current_loop = asyncio.get_running_loop()
    if _client is not None and _es_loop is current_loop:
        return _client

    async with _get_init_lock():
        if _client is not None and _es_loop is current_loop:
            return _client

        # Close old client if loop changed
        if _client is not None:
            await _client.close()
            _client = None

        from config import get_settings
        settings = get_settings()

        # Build AsyncElasticsearch with proper SSL handling
        client_kwargs = {
            "hosts": [settings.elasticsearch_url],
            "basic_auth": (settings.elasticsearch_user, settings.elasticsearch_password),
            "ssl_show_warn": False,
        }
        
        if not settings.elasticsearch_use_ssl:
            # Disable SSL certificate verification for self-signed certificates
            client_kwargs["verify_certs"] = False
            client_kwargs["ssl_show_warn"] = False
            logger.info("elasticsearch_client_initialized", url=settings.elasticsearch_url, ssl_verification="disabled (self-signed cert)")
        else:
            # Use default SSL verification
            client_kwargs["verify_certs"] = True
            logger.info("elasticsearch_client_initialized", url=settings.elasticsearch_url, ssl_verification="enabled")

        _client = AsyncElasticsearch(**client_kwargs)
        _es_loop = current_loop

    return _client


async def close_es_client() -> None:
    global _client
    if _client:
        await _client.close()
        _client = None
        logger.info("elasticsearch_client_closed")


async def search_alerts(
    index_pattern: str,
    query: Optional[dict] = None,
    size: int = 100,
    sort: Optional[list] = None,
    from_: int = 0,
    aggregations: Optional[dict] = None,
) -> dict:
    client = await get_es_client()
    body: dict = {"query": query or {"match_all": {}}, "size": size, "from": from_}
    if sort:
        body["sort"] = sort
    if aggregations:
        body["aggs"] = aggregations

    async def _search():
        return await client.search(index=index_pattern, body=body)

    return await retry_with_backoff(_search)


async def get_latest_alerts(index_pattern: str, size: int = 100) -> list[dict]:
    response = await search_alerts(
        index_pattern=index_pattern,
        sort=[{"@timestamp": {"order": "desc"}}],
        size=size,
    )
    return [{**hit["_source"], "_id": hit["_id"]} for hit in response.get("hits", {}).get("hits", [])]


async def get_alert_by_id(index_pattern: str, alert_id: str) -> Optional[dict]:
    client = await get_es_client()
    try:
        response = await client.get(index=index_pattern, id=alert_id)
        return response.get("_source")
    except Exception:
        return None


async def count_alerts(index_pattern: str, query: Optional[dict] = None) -> int:
    client = await get_es_client()
    body = {"query": query or {"match_all": {}}}
    response = await client.count(index=index_pattern, body=body)
    return response.get("count", 0)


async def retry_with_backoff(func, max_retries: int = 3, base_delay: float = 1.0):
    import asyncio
    for attempt in range(max_retries):
        try:
            return await func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            delay = base_delay * (2 ** attempt)
            await asyncio.sleep(delay)
            logger.warning("elasticsearch_retry", attempt=attempt + 1, error=str(e))