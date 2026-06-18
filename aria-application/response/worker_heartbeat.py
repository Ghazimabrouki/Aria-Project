"""
Worker heartbeat tracking for background tasks.
"""
from datetime import datetime, timezone
from typing import Optional

import structlog
from sqlalchemy import select

from response.db import AsyncSessionLocal
from response.models import WorkerHeartbeat

logger = structlog.get_logger()


async def update_worker_heartbeat(
    worker_name: str,
    status: str = "running",
    duration_ms: Optional[int] = None,
    error: Optional[str] = None,
):
    """Update or create a heartbeat record for a background worker."""
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(WorkerHeartbeat).where(WorkerHeartbeat.worker_name == worker_name)
        )
        hb = result.scalar_one_or_none()
        if hb:
            if error:
                hb.last_error_at = now
                hb.last_error = error[:500] if error else None
                hb.status = status
            else:
                hb.last_success_at = now
                hb.status = status
            if duration_ms is not None:
                hb.last_duration_ms = duration_ms
            hb.updated_at = now
        else:
            hb = WorkerHeartbeat(
                worker_name=worker_name,
                status=status,
                last_success_at=now if not error else None,
                last_error_at=now if error else None,
                last_error=error[:500] if error else None,
                last_duration_ms=duration_ms,
            )
            session.add(hb)
        await session.commit()
        logger.debug("worker_heartbeat_updated", worker=worker_name, status=status)


async def get_all_worker_heartbeats() -> list[WorkerHeartbeat]:
    """Return all worker heartbeat records."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(WorkerHeartbeat))
        return result.scalars().all()
