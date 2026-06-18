import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Any

import structlog
from config import get_settings

logger = structlog.get_logger()
_redis_available: Optional[bool] = None


def _cursor_dir() -> Path:
    return Path(get_settings().cursor_dir)


# Backward-compatible module-level alias (tests may monkeypatch this)
CURSOR_DIR = _cursor_dir()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


async def _redis_get(key: str) -> Optional[str]:
    global _redis_available
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        value = await redis.get(key)
        if _redis_available is not True:
            _redis_available = True
            logger.info("redis_connection_ok")
        return value if isinstance(value, str) else None
    except Exception as e:
        if _redis_available is not False:
            _redis_available = False
            logger.warning("redis_unavailable", error=str(e), fallback="file-based cursors")
        return None


async def _redis_set(key: str, value: str) -> None:
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        await redis.set(key, value)
    except Exception as e:
        if _redis_available is not False:
            logger.warning("redis_set_failed", key=key, error=str(e))


async def _redis_delete(key: str) -> None:
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        await redis.delete(key)
    except Exception as e:
        if _redis_available is not False:
            logger.warning("redis_delete_failed", key=key, error=str(e))


def _cursor_file(source: str) -> Path:
    d = CURSOR_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{source}.cursor"


def _read_file_cursor(source: str) -> Optional[str]:
    path = _cursor_file(source)
    try:
        if path.exists():
            return path.read_text().strip()
    except Exception:
        pass
    return None


def _write_file_cursor(source: str, iso_ts: str) -> None:
    try:
        _cursor_file(source).write_text(iso_ts)
    except Exception:
        pass


async def _get_cursor(source: str) -> datetime:
    settings = get_settings()

    raw = await _redis_get(f"opensoar:cursor:{source}")

    if not raw:
        raw = _read_file_cursor(source)

    if raw:
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass

    first_run_hours = settings.alert_first_run_lookback_hours
    logger.info(
        "cursor_first_run",
        source=source,
        lookback_hours=first_run_hours,
    )
    return _now_utc() - timedelta(hours=first_run_hours)


async def _set_cursor(source: str, ts: datetime) -> None:
    iso = ts.isoformat()
    await _redis_set(f"opensoar:cursor:{source}", iso)
    _write_file_cursor(source, iso)


async def reset_cursor(source: str) -> dict[str, Any]:
    """Reset cursor for a source. Returns before/after state."""
    before = None
    raw = await _redis_get(f"opensoar:cursor:{source}")
    if raw:
        before = raw
    else:
        before = _read_file_cursor(source)

    await _redis_delete(f"opensoar:cursor:{source}")
    try:
        _cursor_file(source).unlink(missing_ok=True)
    except Exception:
        pass

    # After reset, the next read will fall back to lookback
    settings = get_settings()
    after = (_now_utc() - timedelta(hours=settings.alert_first_run_lookback_hours)).isoformat()

    logger.info("cursor_reset", source=source, before=before, after=after)
    return {"source": source, "before": before, "after": after}


def list_cursor_sources() -> list[str]:
    """List sources that have file-based cursors."""
    d = _cursor_dir()
    if not d.exists():
        return []
    return [p.stem for p in d.glob("*.cursor")]
