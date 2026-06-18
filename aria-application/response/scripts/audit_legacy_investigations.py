#!/usr/bin/env python3
"""
Audit legacy investigations for dangerous playbooks and unsafe rollbacks.

Usage:
    # Dry run — scan and report only
    python response/scripts/audit_legacy_investigations.py --dry-run

    # Mark unsafe investigations as manual_review_required
    python response/scripts/audit_legacy_investigations.py --fix

Output:
    Tab-separated report of investigation safety status.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone

sys.path.insert(0, ".")

from sqlalchemy import update, select
from response.db import AsyncSessionLocal
from response.models import Investigation
from response.playbook_safety import compute_investigation_safety


async def audit_legacy_investigations(dry_run: bool = True, fix: bool = False):
    """Scan all legacy investigations and report or fix unsafe ones."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation)
            .where(Investigation.investigation_type == "security")
            .where(Investigation.status.notin_(["manual_review_required", "archived"]))
        )
        investigations = result.scalars().all()

    unsafe_count = 0
    fixed_count = 0
    headers = [
        "id",
        "status",
        "playbook_safety_status",
        "rollback_safety_status",
        "is_executable",
        "blocked_tasks",
    ]
    print("\t".join(headers))

    for inv in investigations:
        safety = compute_investigation_safety(inv)
        blocked = safety["blocked_reasons"]
        row = [
            inv.id[:8],
            inv.status,
            safety["playbook_safety_status"],
            safety["rollback_safety_status"],
            str(safety["is_executable"]),
            "; ".join(blocked) if blocked else "none",
        ]
        print("\t".join(row))

        if not safety["is_executable"] and safety["has_remediation_action"]:
            unsafe_count += 1
            if fix and not dry_run:
                async with AsyncSessionLocal() as fix_session:
                    await fix_session.execute(
                        update(Investigation)
                        .where(Investigation.id == inv.id)
                        .values(
                            status="manual_review_required",
                            ai_error=(
                                (inv.ai_error or "") + "\n[AUDIT] " + datetime.now(timezone.utc).isoformat() +
                                " Safety audit failed: " + "; ".join(blocked)
                            ).strip(),
                            updated_at=datetime.now(timezone.utc),
                        )
                    )
                    await fix_session.commit()
                fixed_count += 1
                print(f"  -> FIXED: marked as manual_review_required")

    print(f"\n{'=' * 60}")
    print(f"Total investigations scanned: {len(investigations)}")
    print(f"Unsafe investigations:        {unsafe_count}")
    if fix and not dry_run:
        print(f"Fixed (marked manual_review): {fixed_count}")
    elif dry_run:
        print("Run with --fix (without --dry-run) to mark unsafe investigations as manual_review_required.")
    print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(description="Audit legacy investigations for safety.")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Report only (default)")
    parser.add_argument("--fix", action="store_true", help="Mark unsafe investigations as manual_review_required")
    args = parser.parse_args()

    dry_run = not args.fix
    asyncio.run(audit_legacy_investigations(dry_run=dry_run, fix=args.fix))


if __name__ == "__main__":
    main()
