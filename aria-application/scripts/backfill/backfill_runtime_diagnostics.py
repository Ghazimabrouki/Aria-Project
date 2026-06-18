#!/usr/bin/env python3
"""
Backfill script for runtime investigations stuck in 'diagnosing'.

Safely re-runs diagnostics for old cases with concurrency limits.
Cases that fail after max retries are marked as 'findings_ready' with
a clear ai_error so operators can see they were historical/incomplete.

Usage:
    python3 scripts/backfill/backfill_runtime_diagnostics.py [--max-retries 2] [--batch-size 10] [--dry-run]
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import structlog
from sqlalchemy import select, update

from response.db import AsyncSessionLocal, init_db
from response.models import Investigation
from pipeline.datausage.runtime_orchestrator import (
    _run_runtime_diagnostic_pipeline,
    _DIAGNOSTIC_SEMAPHORE,
)

logger = structlog.get_logger()


async def backfill(
    max_retries: int = 2,
    batch_size: int = 10,
    dry_run: bool = False,
    age_minutes: int = 5,
):
    """Backfill stuck runtime diagnostics."""
    await init_db()

    stuck_cutoff = datetime.now(timezone.utc) - timedelta(minutes=age_minutes)
    total_processed = 0
    total_success = 0
    total_failed = 0
    total_marked_historical = 0

    seen_ids = set()
    while True:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Investigation)
                .where(Investigation.status == "diagnosing")
                .where(Investigation.investigation_type == "runtime")
                .where(Investigation.diagnostic_started_at < stuck_cutoff)
                .order_by(Investigation.diagnostic_started_at.asc())
                .limit(batch_size)
            )
            batch = result.scalars().all()

            # Filter out IDs we've already processed in this run to prevent loops
            new_batch = [inv for inv in batch if inv.id not in seen_ids]
            if not new_batch:
                break

            for inv in new_batch:
                seen_ids.add(inv.id)
                total_processed += 1
                retry_count = (inv.evidence_json or {}).get("_backfill_retries", 0)

                if dry_run:
                    logger.info(
                        "backfill_dry_run",
                        investigation_id=inv.id,
                        title=inv.incident_title,
                        retries=retry_count,
                    )
                    continue

                if retry_count >= max_retries:
                    # Mark as historical/incomplete after max retries
                    await session.execute(
                        update(Investigation)
                        .where(Investigation.id == inv.id)
                        .values(
                            status="findings_ready",
                            ai_error=(
                                f"Historical/incomplete: diagnostic failed after {max_retries} backfill retries. "
                                "Original diagnostic task was lost. No trustworthy evidence was collected. "
                                "Please review the event context manually or re-diagnose from the UI."
                            ),
                            updated_at=datetime.now(timezone.utc),
                        )
                    )
                    await session.commit()
                    total_marked_historical += 1
                    logger.warning(
                        "backfill_marked_historical",
                        investigation_id=inv.id,
                        title=inv.incident_title,
                        retries=retry_count,
                    )
                    continue

                try:
                    ctx = inv.resource_context_json or {}
                    logger.info(
                        "backfill_diagnostic_start",
                        investigation_id=inv.id,
                        title=inv.incident_title,
                        retry=retry_count + 1,
                    )
                    async with _DIAGNOSTIC_SEMAPHORE:
                        await _run_runtime_diagnostic_pipeline(inv.id, ctx)
                    total_success += 1
                    logger.info(
                        "backfill_diagnostic_success",
                        investigation_id=inv.id,
                    )
                except Exception as e:
                    total_failed += 1
                    logger.error(
                        "backfill_diagnostic_failed",
                        investigation_id=inv.id,
                        error=str(e),
                    )
                    # Increment retry counter in evidence_json
                    evidence = dict(inv.evidence_json or {})
                    evidence["_backfill_retries"] = retry_count + 1
                    await session.execute(
                        update(Investigation)
                        .where(Investigation.id == inv.id)
                        .values(
                            evidence_json=evidence,
                            updated_at=datetime.now(timezone.utc),
                        )
                    )
                    await session.commit()

    summary = {
        "total_processed": total_processed,
        "total_success": total_success,
        "total_failed": total_failed,
        "total_marked_historical": total_marked_historical,
        "dry_run": dry_run,
    }
    logger.info("backfill_complete", **summary)
    print(json.dumps(summary, indent=2))
    return summary


def main():
    parser = argparse.ArgumentParser(description="Backfill stuck runtime diagnostics")
    parser.add_argument("--max-retries", type=int, default=2, help="Max retries before marking historical")
    parser.add_argument("--batch-size", type=int, default=10, help="Batch size per cycle")
    parser.add_argument("--age-minutes", type=int, default=5, help="Only process cases older than N minutes")
    parser.add_argument("--dry-run", action="store_true", help="Log only, do not modify DB")
    args = parser.parse_args()

    result = asyncio.run(backfill(
        max_retries=args.max_retries,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
        age_minutes=args.age_minutes,
    ))

    # Exit with error code if any failed (but not if dry_run)
    if not args.dry_run and result["total_failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
