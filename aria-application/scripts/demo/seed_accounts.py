#!/usr/bin/env python3
"""
ARIA Account Seed Script

Idempotent seed for the predefined super_admin account and default
server_user accounts for all monitored assets.

Usage:
    python3 scripts/demo/seed_accounts.py

Environment:
    ARIA_ADMIN_PASSWORD  - Override the default super_admin password
    ARIA_RESET_PASSWORD  - If set to "1", reset the super_admin password even if account exists
"""
import asyncio
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from response.db import AsyncSessionLocal, init_db
from response.models import AriaAccount, MonitoredAsset
from response.auth import hash_password
from sqlalchemy import select


ADMIN_USERNAME = "ghazi.mabrouki@esprit.tn"
ADMIN_EMAIL = "ghazi.mabrouki@esprit.tn"
ADMIN_DEFAULT_PASSWORD = "Ghozz1470@"


async def seed_super_admin():
    """Ensure the super_admin account exists."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AriaAccount).where(AriaAccount.username == ADMIN_USERNAME)
        )
        account = result.scalar_one_or_none()

        password = os.environ.get("ARIA_ADMIN_PASSWORD", ADMIN_DEFAULT_PASSWORD)
        reset = os.environ.get("ARIA_RESET_PASSWORD") == "1"

        if account and not reset:
            print(f"[SKIP] Super admin already exists: {account.username}")
            return

        if account and reset:
            account.password_hash = hash_password(password)
            print(f"[RESET] Super admin password updated: {account.username}")
        else:
            account = AriaAccount(
                username=ADMIN_USERNAME,
                email=ADMIN_EMAIL,
                password_hash=hash_password(password),
                role="super_admin",
                asset_id=None,
                is_active=True,
                is_banned=False,
            )
            session.add(account)
            print(f"[CREATE] Super admin created: {account.username}")

        await session.commit()


async def seed_asset_accounts():
    """Ensure every monitored asset with an IP has a default server_user account."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(MonitoredAsset))
        assets = result.scalars().all()

        created = 0
        skipped = 0
        for asset in assets:
            if not asset.ip_address:
                continue
            username = asset.ip_address
            existing = await session.execute(
                select(AriaAccount).where(AriaAccount.username == username)
            )
            if existing.scalar_one_or_none():
                skipped += 1
                continue

            account = AriaAccount(
                username=username,
                email=None,
                password_hash=hash_password(f"ARIA-{username}"),
                role="server_user",
                asset_id=asset.asset_id,
                is_active=True,
                is_banned=False,
            )
            session.add(account)
            created += 1
            print(f"[CREATE] Asset account: {username} -> {asset.asset_id}")

        await session.commit()
        print(f"[DONE] Asset accounts: {created} created, {skipped} already existed")


async def main():
    print("ARIA Account Seed Script")
    print("=" * 40)
    await init_db()
    await seed_super_admin()
    await seed_asset_accounts()
    print("=" * 40)
    print("Seed complete.")


if __name__ == "__main__":
    asyncio.run(main())
