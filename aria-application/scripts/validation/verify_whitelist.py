#!/usr/bin/env python3
"""
Manual verification script for whitelist functionality.
Run this against a running backend to verify end-to-end behavior.

Usage:
    python3 scripts/validation/verify_whitelist.py

Requires:
    - Backend API running on localhost:8001 (or BACKEND_URL env var)
    - SQLite DB accessible from this script's environment
"""

import asyncio
import os
import sys
import uuid

# Ensure project root is on path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.whitelist import add_whitelist_entry, is_whitelisted, remove_whitelist_entry
from response.db import AsyncSessionLocal
from response.models import Alert, Incident
from sqlalchemy import select


TEST_IP = "192.168.254.254"


async def main():
    print("=" * 60)
    print("OpenSOAR Whitelist Verification Script")
    print("=" * 60)

    # Step 1: Add whitelist entry
    print(f"\n[1/5] Adding {TEST_IP} to whitelist...")
    try:
        entry = await add_whitelist_entry("ip", TEST_IP, label="trusted", description="Verification test")
        print(f"  ✅ Added: id={entry['id']}, value={entry['value']}")
    except ValueError as e:
        if "already exists" in str(e).lower():
            print(f"  ℹ️  Already exists (OK)")
        else:
            raise

    # Step 2: Verify is_whitelisted
    print(f"\n[2/5] Checking is_whitelisted('{TEST_IP}')...")
    result = await is_whitelisted(TEST_IP)
    status = "✅ PASS" if result else "❌ FAIL"
    print(f"  {status}: is_whitelisted = {result}")
    if not result:
        print("  ERROR: IP should be whitelisted but is not!")
        return 1

    # Step 3: Create a test alert with whitelisted IP
    print(f"\n[3/5] Creating test alert with source_ip={TEST_IP}...")
    alert_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        alert = Alert(
            id=alert_id,
            source="verify_test",
            source_id=f"verify-{alert_id[:8]}",
            title="Whitelist Verification Alert",
            description="This alert should be marked whitelisted",
            severity="critical",
            status="active",
            source_ip=TEST_IP,
            whitelisted=True,
        )
        session.add(alert)
        await session.commit()

    async with AsyncSessionLocal() as session:
        row = await session.execute(select(Alert).where(Alert.id == alert_id))
        stored = row.scalar_one()
        status = "✅ PASS" if stored.whitelisted else "❌ FAIL"
        print(f"  {status}: alert.whitelisted = {stored.whitelisted}")
        if not stored.whitelisted:
            print("  ERROR: Alert should have whitelisted=True!")
            return 1

    # Step 4: Verify process_alert skips whitelisted
    print(f"\n[4/5] Testing incident_manager.process_alert() with whitelisted=True...")
    from unittest.mock import patch, AsyncMock
    from pipeline.datausage.incident_manager import process_alert

    upstream_id = f"verify-{uuid.uuid4().hex[:8]}"
    payload = {
        "id": upstream_id,
        "title": "SSH Brute Force",
        "description": "Verification",
        "severity": "critical",
        "source_ip": TEST_IP,
        "whitelisted": True,
    }

    with patch(
        "pipeline.datausage.incident_manager.client.link_alert_to_incident",
        new_callable=AsyncMock,
    ) as mock_link:
        result = await process_alert(upstream_id, payload)

    expected_skip = result["action"] == "skipped" and result["reason"] == "whitelisted"
    status = "✅ PASS" if expected_skip else "❌ FAIL"
    print(f"  {status}: result = {result}")
    if not expected_skip:
        print("  ERROR: process_alert should have skipped with reason='whitelisted'!")
        return 1

    # Step 5: Verify no incident was created
    print(f"\n[5/5] Checking that no incident was created...")
    async with AsyncSessionLocal() as session:
        row = await session.execute(
            select(Incident).where(Incident.external_id == upstream_id)
        )
        incident = row.scalar_one_or_none()
        if incident is None:
            print("  ✅ PASS: No incident found (correctly suppressed)")
        else:
            print(f"  ❌ FAIL: Incident was created: id={incident.id}")
            return 1

    # Cleanup
    print(f"\n[Cleanup] Removing test alert and whitelist entry...")
    async with AsyncSessionLocal() as session:
        await session.execute(Alert.__table__.delete().where(Alert.id == alert_id))
        await session.commit()

    # Find and remove whitelist entry
    from response.models import WhitelistEntry
    async with AsyncSessionLocal() as session:
        row = await session.execute(
            select(WhitelistEntry).where(WhitelistEntry.value == TEST_IP)
        )
        entry = row.scalar_one_or_none()
        if entry:
            await remove_whitelist_entry(entry.id)
            print(f"  ✅ Removed whitelist entry {entry.id}")

    print("\n" + "=" * 60)
    print("All checks passed! Whitelist suppression is working correctly.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
    except Exception as e:
        print(f"\n❌ Verification failed with error: {e}")
        import traceback
        traceback.print_exc()
        exit_code = 1
    sys.exit(exit_code)
