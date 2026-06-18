"""Shared helpers for API route modules."""
from typing import Optional
from fastapi import HTTPException, Header, Depends
from config import get_settings


async def validate_asset_id(asset_id: Optional[str]) -> Optional[str]:
    """Normalize and validate asset_id for route handlers.

    Returns None when:
      - asset_id is None/empty
      - asset_id.lower() == "all"
      - multi_server_enabled is False

    Raises HTTPException(400) when:
      - asset_id does not match any MonitoredAsset
      - matched MonitoredAsset is disabled
    """
    if not asset_id or asset_id.lower() == "all":
        return None

    settings = get_settings()
    if not settings.multi_server_enabled:
        return None

    from response.db import AsyncSessionLocal
    from response.models import MonitoredAsset
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
        )
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(
                status_code=400, detail=f"Invalid asset_id: {asset_id}"
            )
        if not asset.enabled:
            raise HTTPException(
                status_code=400, detail=f"Asset {asset_id} is disabled."
            )
    return asset_id


# ── Backward-compatible admin authorization ──────────────────────────────────

from fastapi.security import HTTPBearer
from response.auth import security, get_current_user

# ── Scope enforcement helper ─────────────────────────────────────────────────

from response.auth import CurrentUser

async def enforce_asset_scope(user: CurrentUser, asset_id: Optional[str]) -> Optional[str]:
    """
    Enforce asset scoping for the current user.
    - super_admin: passes through with requested asset_id
    - server_user: forces asset_id to user's assigned asset;
      rejects explicit requests for a different asset
    Returns the effective asset_id to use in queries.
    """
    if user.role == "super_admin":
        return asset_id
    if user.asset_id is None:
        raise HTTPException(
            status_code=403,
            detail="Server user account has no assigned asset. Contact admin.",
        )
    if asset_id and asset_id != user.asset_id:
        raise HTTPException(
            status_code=403,
            detail="You are not authorized to access data for this asset.",
        )
    return user.asset_id


async def validate_admin_access(
    x_aria_admin_secret: Optional[str] = Header(None, alias="X-ARIA-Admin-Secret"),
    credentials: Optional[HTTPBearer] = Depends(security),
) -> None:
    """
    Validates admin access by EITHER:
    - A valid JWT Bearer token from a super_admin, OR
    - The correct X-ARIA-Admin-Secret header

    This preserves backward compatibility with existing scripts/UI
    while enabling the new JWT auth system.
    """
    # Try JWT first
    if credentials and credentials.credentials:
        jwt_user = await get_current_user(credentials)
        if jwt_user and jwt_user.role == "super_admin":
            return

    # Fall back to admin secret
    settings = get_settings()
    secret = settings.aria_admin_secret
    bad_defaults = {"", "changeme", "default", "admin"}
    if not secret or secret.lower() in bad_defaults:
        raise HTTPException(
            status_code=403,
            detail="Admin access is disabled because aria_admin_secret is not configured or uses a default value.",
        )
    if not x_aria_admin_secret:
        raise HTTPException(status_code=403, detail="Authentication required. Provide a valid Bearer token or X-ARIA-Admin-Secret header.")
    if x_aria_admin_secret != secret:
        raise HTTPException(status_code=403, detail="Invalid admin secret.")
