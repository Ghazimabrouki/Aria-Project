"""
ARIA Authentication Layer
JWT tokens, password hashing, and FastAPI current-user dependency.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

import structlog
from fastapi import Depends, HTTPException, Header, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import get_session
from response.models import AriaAccount

logger = structlog.get_logger()

# ── Configuration ────────────────────────────────────────────────────────────
SECRET_KEY = "ARIA-JWT-SECRET-CHANGE-IN-PRODUCTION-2026"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)


# ── Password utilities ───────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# ── JWT utilities ────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ── Schemas ──────────────────────────────────────────────────────────────────

class TokenPayload(BaseModel):
    sub: str  # user_id
    username: str
    role: str
    asset_id: Optional[str] = None
    scope_all_assets: bool = False


class CurrentUser(BaseModel):
    id: str
    username: str
    role: str
    asset_id: Optional[str] = None
    scope_all_assets: bool = False
    is_active: bool = True
    is_banned: bool = False


# ── Dependency: extract current user from JWT ────────────────────────────────

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[CurrentUser]:
    """
    Extract and validate the current user from the Authorization header.
    Returns None if no token is provided (for optional auth routes).
    Raises 401 if token is invalid or user is inactive/banned.
    """
    if not credentials:
        return None

    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    user_id = payload.get("sub")
    username = payload.get("username")
    role = payload.get("role")

    if not user_id or not username or not role:
        raise HTTPException(status_code=401, detail="Invalid token payload.")

    # Refresh user state from DB (prevents using a token for a banned user)
    from response.db import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AriaAccount).where(AriaAccount.id == user_id)
        )
        account = result.scalar_one_or_none()

        if not account:
            raise HTTPException(status_code=401, detail="User no longer exists.")
        if not account.is_active:
            raise HTTPException(status_code=401, detail="Account is inactive.")
        if account.is_banned:
            raise HTTPException(status_code=401, detail="Account is banned.")

        return CurrentUser(
            id=str(account.id),
            username=account.username,
            role=account.role,
            asset_id=account.asset_id,
            scope_all_assets=(account.role == "super_admin"),
            is_active=account.is_active,
            is_banned=account.is_banned,
        )


async def require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> CurrentUser:
    """Strict dependency: user MUST be authenticated."""
    user = await get_current_user(credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


async def require_super_admin(
    user: CurrentUser = Depends(require_auth),
) -> CurrentUser:
    """Dependency: user MUST be super_admin."""
    if user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Super admin access required.")
    return user


# ── Scope enforcement helpers ────────────────────────────────────────────────

class ScopedAssetId:
    """
    FastAPI dependency that enforces asset scoping.

    For super_admin: returns the requested asset_id (or None).
    For server_user: ALWAYS returns the user's assigned asset_id,
    and rejects requests that explicitly ask for a different asset.
    """

    def __init__(self, allow_none: bool = True):
        self.allow_none = allow_none

    async def __call__(
        self,
        user: CurrentUser = Depends(require_auth),
        asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    ) -> Optional[str]:
        if user.role == "super_admin":
            # Super admin can request any asset (or all)
            if not asset_id or asset_id.lower() == "all":
                return None
            return asset_id

        # server_user: locked to their asset
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


def scoped_asset_id(allow_none: bool = True):
    """Factory to create ScopedAssetId dependency."""
    return ScopedAssetId(allow_none=allow_none)
