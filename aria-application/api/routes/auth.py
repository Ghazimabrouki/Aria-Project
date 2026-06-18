"""
ARIA Authentication Endpoints
"""
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import get_session
from response.models import AriaAccount
from response.auth import (
    verify_password,
    create_access_token,
    require_auth,
    CurrentUser,
)

logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    role: str
    asset_id: Optional[str] = None
    scope_all_assets: bool
    is_active: bool
    is_banned: bool
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None

    class Config:
        from_attributes = True


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


class MeResponse(BaseModel):
    user: UserResponse


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _authenticate(session: AsyncSession, username: str, password: str) -> Optional[AriaAccount]:
    """Lookup account by username or email and verify password."""
    stmt = select(AriaAccount).where(
        (AriaAccount.username == username) | (AriaAccount.email == username)
    )
    result = await session.execute(stmt)
    account = result.scalar_one_or_none()
    if not account:
        return None
    if not verify_password(password, account.password_hash):
        return None
    return account


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, session: AsyncSession = Depends(get_session)):
    """Authenticate and return a JWT access token."""
    account = await _authenticate(session, payload.username, payload.password)
    if not account:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    if not account.is_active:
        raise HTTPException(status_code=401, detail="Account is inactive.")
    if account.is_banned:
        raise HTTPException(status_code=401, detail="Account is banned.")

    # Update last_login_at
    account.last_login_at = datetime.now(timezone.utc)
    await session.commit()

    token_data = {
        "sub": account.id,
        "username": account.username,
        "role": account.role,
        "asset_id": account.asset_id,
        "scope_all_assets": account.role == "super_admin",
    }
    access_token = create_access_token(token_data)

    logger.info("login_success", username=account.username, role=account.role)

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse(
            id=account.id,
            username=account.username,
            email=account.email,
            role=account.role,
            asset_id=account.asset_id,
            scope_all_assets=account.role == "super_admin",
            is_active=account.is_active,
            is_banned=account.is_banned,
            created_at=account.created_at.isoformat() if account.created_at else None,
            last_login_at=account.last_login_at.isoformat() if account.last_login_at else None,
        ),
    )


@router.get("/me", response_model=MeResponse)
async def me(user: CurrentUser = Depends(require_auth)):
    """Return the currently authenticated user's profile."""
    from response.db import AsyncSessionLocal
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AriaAccount).where(AriaAccount.id == user.id)
        )
        account = result.scalar_one_or_none()
        if not account:
            raise HTTPException(status_code=401, detail="User not found.")

        return MeResponse(
            user=UserResponse(
                id=account.id,
                username=account.username,
                email=account.email,
                role=account.role,
                asset_id=account.asset_id,
                scope_all_assets=account.role == "super_admin",
                is_active=account.is_active,
                is_banned=account.is_banned,
                created_at=account.created_at.isoformat() if account.created_at else None,
                last_login_at=account.last_login_at.isoformat() if account.last_login_at else None,
            )
        )
