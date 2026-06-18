"""
ARIA Account Management Endpoints
Super-admin only.
"""
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import get_session
from response.models import AriaAccount, MonitoredAsset
from response.auth import require_super_admin, hash_password, CurrentUser
from api.routes._shared import validate_asset_id, enforce_asset_scope

logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1/accounts", tags=["accounts"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class AccountCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1)
    email: Optional[str] = None
    role: str = Field(..., pattern="^(super_admin|server_user)$")
    asset_id: Optional[str] = None
    is_active: bool = True


class AccountUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=1, max_length=255)
    email: Optional[str] = None
    role: Optional[str] = Field(None, pattern="^(super_admin|server_user)$")
    asset_id: Optional[str] = None
    is_active: Optional[bool] = None
    is_banned: Optional[bool] = None


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=1)


class AccountResponse(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    role: str
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    is_active: bool
    is_banned: bool
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    last_login_at: Optional[str] = None

    class Config:
        from_attributes = True


class AccountListResponse(BaseModel):
    accounts: list[AccountResponse]
    total: int


class EnsureDefaultAccountResponse(BaseModel):
    created: bool
    username: str
    password: Optional[str] = None
    message: str


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _get_asset_name(session: AsyncSession, asset_id: Optional[str]) -> Optional[str]:
    if not asset_id:
        return None
    result = await session.execute(
        select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
    )
    asset = result.scalar_one_or_none()
    return asset.name if asset else None


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("", response_model=AccountListResponse)
async def list_accounts(
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_super_admin),
    role: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List all ARIA accounts. Never returns password hashes."""
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    stmt = select(AriaAccount)
    if role:
        stmt = stmt.where(AriaAccount.role == role)
    if asset_id:
        stmt = stmt.where(AriaAccount.asset_id == asset_id)
    if search:
        stmt = stmt.where(
            (AriaAccount.username.ilike(f"%{search}%")) |
            (AriaAccount.email.ilike(f"%{search}%"))
        )

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await session.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.order_by(AriaAccount.created_at.desc()).offset(offset).limit(limit)
    result = await session.execute(stmt)
    accounts = result.scalars().all()

    items = []
    for a in accounts:
        items.append(AccountResponse(
            id=a.id,
            username=a.username,
            email=a.email,
            role=a.role,
            asset_id=a.asset_id,
            asset_name=await _get_asset_name(session, a.asset_id),
            is_active=a.is_active,
            is_banned=a.is_banned,
            created_at=a.created_at.isoformat() if a.created_at else None,
            updated_at=a.updated_at.isoformat() if a.updated_at else None,
            last_login_at=a.last_login_at.isoformat() if a.last_login_at else None,
        ))

    return AccountListResponse(accounts=items, total=total)


@router.post("", response_model=AccountResponse, status_code=201)
async def create_account(
    payload: AccountCreate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_super_admin),
):
    """Create a new ARIA account manually."""
    # Validate unique username
    existing = await session.execute(
        select(AriaAccount).where(AriaAccount.username == payload.username)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username already exists.")

    # Validate asset_id if provided
    if payload.asset_id:
        asset = await session.execute(
            select(MonitoredAsset).where(MonitoredAsset.asset_id == payload.asset_id)
        )
        if not asset.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Assigned asset does not exist.")

    # server_user must have asset_id
    if payload.role == "server_user" and not payload.asset_id:
        raise HTTPException(status_code=400, detail="server_user accounts require an asset_id.")

    account = AriaAccount(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        asset_id=payload.asset_id,
        is_active=payload.is_active,
        is_banned=False,
    )
    session.add(account)
    await session.commit()
    await session.refresh(account)

    logger.info("account_created", username=account.username, role=account.role, by=user.username)

    return AccountResponse(
        id=account.id,
        username=account.username,
        email=account.email,
        role=account.role,
        asset_id=account.asset_id,
        asset_name=await _get_asset_name(session, account.asset_id),
        is_active=account.is_active,
        is_banned=account.is_banned,
        created_at=account.created_at.isoformat() if account.created_at else None,
        updated_at=account.updated_at.isoformat() if account.updated_at else None,
        last_login_at=account.last_login_at.isoformat() if account.last_login_at else None,
    )


@router.patch("/{account_id}", response_model=AccountResponse)
async def update_account(
    account_id: str,
    payload: AccountUpdate,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_super_admin),
):
    """Edit account fields."""
    result = await session.execute(
        select(AriaAccount).where(AriaAccount.id == account_id)
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")

    # Protect the main super_admin from role downgrade
    if account.username == "ghazi.mabrouki@esprit.tn" and payload.role and payload.role != "super_admin":
        raise HTTPException(status_code=403, detail="Cannot downgrade the primary super admin account.")

    if payload.username is not None and payload.username != account.username:
        existing = await session.execute(
            select(AriaAccount).where(AriaAccount.username == payload.username)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Username already exists.")
        account.username = payload.username

    if payload.email is not None:
        account.email = payload.email

    if payload.role is not None:
        account.role = payload.role
        if payload.role == "super_admin":
            account.asset_id = None

    if payload.asset_id is not None:
        if payload.asset_id:
            asset = await session.execute(
                select(MonitoredAsset).where(MonitoredAsset.asset_id == payload.asset_id)
            )
            if not asset.scalar_one_or_none():
                raise HTTPException(status_code=400, detail="Assigned asset does not exist.")
        account.asset_id = payload.asset_id

    # server_user must have asset_id
    if account.role == "server_user" and not account.asset_id:
        raise HTTPException(status_code=400, detail="server_user accounts require an asset_id.")

    if payload.is_active is not None:
        account.is_active = payload.is_active

    if payload.is_banned is not None:
        account.is_banned = payload.is_banned

    account.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(account)

    logger.info("account_updated", account_id=account_id, by=user.username)

    return AccountResponse(
        id=account.id,
        username=account.username,
        email=account.email,
        role=account.role,
        asset_id=account.asset_id,
        asset_name=await _get_asset_name(session, account.asset_id),
        is_active=account.is_active,
        is_banned=account.is_banned,
        created_at=account.created_at.isoformat() if account.created_at else None,
        updated_at=account.updated_at.isoformat() if account.updated_at else None,
        last_login_at=account.last_login_at.isoformat() if account.last_login_at else None,
    )


@router.post("/{account_id}/reset-password")
async def reset_password(
    account_id: str,
    payload: ResetPasswordRequest,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_super_admin),
):
    """Reset an account's password."""
    result = await session.execute(
        select(AriaAccount).where(AriaAccount.id == account_id)
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")

    account.password_hash = hash_password(payload.new_password)
    account.updated_at = datetime.now(timezone.utc)
    await session.commit()

    logger.info("password_reset", account_id=account_id, by=user.username)
    return {"message": "Password reset successfully."}


@router.post("/{account_id}/ban")
async def ban_account(
    account_id: str,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_super_admin),
):
    """Ban an account."""
    result = await session.execute(
        select(AriaAccount).where(AriaAccount.id == account_id)
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")

    # Protect primary super_admin
    if account.username == "ghazi.mabrouki@esprit.tn":
        raise HTTPException(status_code=403, detail="Cannot ban the primary super admin account.")

    account.is_banned = True
    account.updated_at = datetime.now(timezone.utc)
    await session.commit()

    logger.info("account_banned", account_id=account_id, by=user.username)
    return {"message": "Account banned successfully."}


@router.post("/{account_id}/unban")
async def unban_account(
    account_id: str,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_super_admin),
):
    """Unban an account."""
    result = await session.execute(
        select(AriaAccount).where(AriaAccount.id == account_id)
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")

    account.is_banned = False
    account.updated_at = datetime.now(timezone.utc)
    await session.commit()

    logger.info("account_unbanned", account_id=account_id, by=user.username)
    return {"message": "Account unbanned successfully."}


@router.delete("/{account_id}", status_code=204)
async def delete_account(
    account_id: str,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_super_admin),
):
    """Delete an account. Protects primary super_admin."""
    result = await session.execute(
        select(AriaAccount).where(AriaAccount.id == account_id)
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")

    if account.username == "ghazi.mabrouki@esprit.tn":
        raise HTTPException(status_code=403, detail="Cannot delete the primary super admin account.")

    await session.delete(account)
    await session.commit()

    logger.info("account_deleted", account_id=account_id, username=account.username, by=user.username)
    return None


@router.post("/assets/{asset_id}/ensure-default-account", response_model=EnsureDefaultAccountResponse)
async def ensure_default_account_for_asset(
    asset_id: str,
    session: AsyncSession = Depends(get_session),
    user: CurrentUser = Depends(require_super_admin),
):
    """Create or reset the default server_user account for an asset.
    Returns the generated password ONLY on creation/reset (show once).
    """
    asset_result = await session.execute(
        select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
    )
    asset = asset_result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    if not asset.ip_address:
        raise HTTPException(status_code=400, detail="Asset has no IP address configured.")

    username = asset.ip_address
    result = await session.execute(
        select(AriaAccount).where(AriaAccount.username == username)
    )
    existing = result.scalar_one_or_none()

    password = f"ARIA-{username}"
    password_hash = hash_password(password)

    if existing:
        # Reset password and ensure mapped to this asset
        existing.password_hash = password_hash
        existing.asset_id = asset_id
        existing.is_active = True
        existing.is_banned = False
        existing.updated_at = datetime.now(timezone.utc)
        await session.commit()
        logger.info("default_account_reset", username=username, asset_id=asset_id, by=user.username)
        return EnsureDefaultAccountResponse(
            created=False,
            username=username,
            password=password,
            message=f"Account reset. Login: {username} / Password: {password}",
        )

    account = AriaAccount(
        username=username,
        email=None,
        password_hash=password_hash,
        role="server_user",
        asset_id=asset_id,
        is_active=True,
        is_banned=False,
    )
    session.add(account)
    await session.commit()

    logger.info("default_account_created", username=username, asset_id=asset_id, by=user.username)
    return EnsureDefaultAccountResponse(
        created=True,
        username=username,
        password=password,
        message=f"Account created. Login: {username} / Password: {password}",
    )
