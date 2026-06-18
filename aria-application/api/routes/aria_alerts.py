from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Query
from sqlalchemy import select, func, exists
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import get_session
from response.models import AriaAlert, Investigation
from response.auth import require_auth, CurrentUser
from api.routes._shared import validate_asset_id, enforce_asset_scope

router = APIRouter(prefix="/api/v1/aria-alerts", tags=["aria-alerts"])


def _validate_admin_access(admin_secret_header: str | None = None) -> None:
    from config import get_settings
    settings = get_settings()
    expected = (settings.aria_admin_secret or "").strip()
    if not expected or expected.lower() in ("", "changeme", "default", "admin"):
        raise HTTPException(status_code=403, detail="Admin secret not configured.")
    provided = (admin_secret_header or "").strip()
    if not provided:
        raise HTTPException(status_code=403, detail="X-ARIA-Admin-Secret header required.")
    if provided != expected:
        raise HTTPException(status_code=403, detail="Invalid admin secret.")


def _scoped_aria_alert_count_stmt(asset_id: Optional[str] = None):
    """Build a count statement for AriaAlert scoped by Investigation.asset_id."""
    if asset_id:
        return select(func.count(AriaAlert.id)).where(
            exists().where(
                Investigation.id == AriaAlert.investigation_id,
                Investigation.asset_id == asset_id,
            )
        )
    return select(func.count(AriaAlert.id))


def _scoped_aria_alert_list_stmt(asset_id: Optional[str] = None):
    """Build a list statement for AriaAlert scoped by Investigation.asset_id."""
    stmt = select(AriaAlert)
    if asset_id:
        stmt = stmt.where(
            exists().where(
                Investigation.id == AriaAlert.investigation_id,
                Investigation.asset_id == asset_id,
            )
        )
    return stmt.order_by(AriaAlert.created_at.desc())


@router.get("/stats")
async def get_aria_alert_stats(
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
):
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    total = await session.scalar(_scoped_aria_alert_count_stmt(asset_id))
    by_severity = {}
    for severity in ["low", "medium", "high", "critical"]:
        base_stmt = _scoped_aria_alert_count_stmt(asset_id)
        count = await session.scalar(base_stmt.where(AriaAlert.severity == severity))
        by_severity[severity] = count or 0
    unacknowledged = await session.scalar(
        _scoped_aria_alert_count_stmt(asset_id).where(AriaAlert.acknowledged == False)
    )
    return {
        "total": total or 0,
        "by_severity": by_severity,
        "unacknowledged": unacknowledged or 0,
    }


@router.get("/")
async def list_aria_alerts(
    limit: int = 50,
    offset: int = 0,
    acknowledged: Optional[bool] = None,
    severity: Optional[str] = None,
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
    session: AsyncSession = Depends(get_session),
):
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    stmt = _scoped_aria_alert_list_stmt(asset_id)
    if acknowledged is not None:
        stmt = stmt.where(AriaAlert.acknowledged == acknowledged)
    if severity:
        stmt = stmt.where(AriaAlert.severity == severity)
    total = await session.scalar(_scoped_aria_alert_count_stmt(asset_id))
    result = await session.execute(stmt.offset(offset).limit(limit))
    alerts = result.scalars().all()
    return {
        "alerts": [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "investigation_id": a.investigation_id,
                "incident_id": a.incident_id,
                "title": a.title,
                "description": a.description,
                "acknowledged": a.acknowledged,
                "acknowledged_by": a.acknowledged_by,
                "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
        "total": total or 0,
        "limit": limit,
        "offset": offset,
    }


@router.post("/{alert_id}/acknowledge")
async def acknowledge_aria_alert(
    alert_id: str,
    session: AsyncSession = Depends(get_session),
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    _validate_admin_access(x_aria_admin_secret)
    result = await session.execute(select(AriaAlert).where(AriaAlert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="ARIA alert not found")
    alert.acknowledged = True
    alert.acknowledged_by = "admin"
    from datetime import datetime, timezone
    alert.acknowledged_at = datetime.now(timezone.utc)
    await session.commit()
    return {"message": "ARIA alert acknowledged", "alert_id": alert_id}


@router.delete("/{alert_id}")
async def delete_aria_alert(
    alert_id: str,
    session: AsyncSession = Depends(get_session),
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
):
    _validate_admin_access(x_aria_admin_secret)
    result = await session.execute(select(AriaAlert).where(AriaAlert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="ARIA alert not found")
    await session.delete(alert)
    await session.commit()
    return {"message": "ARIA alert deleted", "alert_id": alert_id}
