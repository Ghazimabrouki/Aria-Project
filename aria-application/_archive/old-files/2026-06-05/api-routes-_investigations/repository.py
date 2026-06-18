"""Database lookup helpers for investigation routes."""

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from response.models import Investigation


async def _get_investigation_or_404(
    investigation_id: str, session: AsyncSession
) -> Investigation:
    result = await session.execute(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .options(
            selectinload(Investigation.alerts),
            selectinload(Investigation.approval),
            selectinload(Investigation.run),
            selectinload(Investigation.verification),
            selectinload(Investigation.audit_events),
        )
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv
