#!/usr/bin/env python3
"""
Backfill existing Falco events into Runtime Investigations.

Best-practice approach:
  - Queries all Falco events from Elasticsearch
  - Maps each with the NEW runtime mapper (falco_runtime.py)
  - Creates runtime investigations
  - Runs diagnostics with throttled concurrency (default: 3 concurrent Ansible playbooks)
  - Skips events already backfilled
  - Shows real-time progress

Usage:
    python3 scripts/backfill/backfill_falco_runtime.py [--limit N] [--concurrency N] [--dry-run]
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import structlog

logger = structlog.get_logger()

# ── Configuration ────────────────────────────────────────────────────────────
DEFAULT_CONCURRENCY = 3
ES_INDEX = "falco-events-server-*"


async def _get_es_client():
    from core.elasticsearch import get_es_client
    return await get_es_client()


async def _get_db_session():
    from response.db import AsyncSessionLocal
    return AsyncSessionLocal()


async def _fetch_falco_events(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Fetch all Falco events from Elasticsearch."""
    es = await _get_es_client()
    try:
        query = {
            "size": limit or 10000,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"match_all": {}},
        }
        resp = await es.search(index=ES_INDEX, body=query)
        hits = resp["hits"]["hits"]
        logger.info("falco_events_fetched", count=len(hits))
        return hits
    finally:
        await es.close()


async def _get_existing_runtime_alert_ids() -> set:
    """Get set of ES doc IDs already linked to runtime investigations."""
    from sqlalchemy import text
    from response.db import engine

    existing = set()
    async with engine.begin() as conn:
        result = await conn.execute(
            text("""
                SELECT a.source_id 
                FROM investigation_alerts ia
                JOIN investigations i ON ia.investigation_id = i.id
                JOIN alerts a ON ia.alert_id = a.id
                WHERE i.investigation_type = 'runtime'
            """)
        )
        for row in result.fetchall():
            if row[0]:
                existing.add(row[0])
    return existing


async def _create_runtime_investigation_throttled(
    hit: Dict[str, Any],
    semaphore: asyncio.Semaphore,
    dry_run: bool = False,
) -> Optional[str]:
    """
    Create a runtime investigation for a single Falco ES event.
    Diagnostics are throttled via semaphore.
    """
    es_id = hit["_id"]
    doc = hit["_source"]

    # Map with the NEW runtime mapper
    from pipeline.mappers.falco_runtime import map_falco_runtime_alert

    try:
        alert_payload = map_falco_runtime_alert(doc)
    except Exception as e:
        logger.warning("falco_runtime_map_failed", es_id=es_id, error=str(e))
        return None

    if not alert_payload:
        logger.warning("falco_runtime_map_skipped", es_id=es_id)
        return None

    alert_id = alert_payload.get("id", es_id)

    if dry_run:
        logger.info("dry_run_would_create", es_id=es_id, rule=alert_payload.get("rule_name"))
        return None

    # Create investigation (this also auto-triggers diagnostics)
    from pipeline.datausage.runtime_orchestrator import create_runtime_investigation

    try:
        investigation_id = await create_runtime_investigation(alert_payload)
        if investigation_id:
            logger.info(
                "runtime_investigation_created",
                investigation_id=investigation_id,
                es_id=es_id,
                rule=alert_payload.get("rule_name"),
            )
        return investigation_id
    except Exception as e:
        logger.error("runtime_investigation_creation_failed", es_id=es_id, error=str(e))
        return None


async def _run_diagnostic_with_semaphore(
    investigation_id: str,
    resource_context: Dict[str, Any],
    semaphore: asyncio.Semaphore,
) -> None:
    """Run diagnostic playbook with concurrency throttling."""
    async with semaphore:
        from pipeline.datausage.runtime_orchestrator import _run_runtime_diagnostic_pipeline
        try:
            await _run_runtime_diagnostic_pipeline(investigation_id, resource_context)
        except Exception as e:
            logger.error(
                "runtime_diagnostic_failed",
                investigation_id=investigation_id,
                error=str(e),
            )


async def _create_without_auto_diagnostic(
    alert_payload: Dict[str, Any],
) -> Optional[str]:
    """
    Create a runtime investigation WITHOUT auto-triggering diagnostics.
    We'll run diagnostics separately with throttling.
    """
    from config import get_settings
    from response.db import AsyncSessionLocal
    from response.models import Investigation, InvestigationAlert
    from response.runtime_ai_engine.context_builder import RuntimeContext
    from response.runtime_ai_engine.playbook_generator import generate_runtime_diagnostic_playbook

    settings = get_settings()
    runtime_context = alert_payload.get("runtime_context", {}) or {}
    runtime_category = alert_payload.get("runtime_category", "unknown")
    rule_name = alert_payload.get("rule_name") or alert_payload.get("title", "Unknown Rule")
    severity = alert_payload.get("severity", "medium")
    hostname = alert_payload.get("hostname", "unknown")
    is_intervention = alert_payload.get("is_intervention_required", False)

    if isinstance(runtime_context, dict):
        ctx = RuntimeContext.from_dict(runtime_context)
    else:
        ctx = RuntimeContext(
            runtime_category=runtime_category,
            rule_name=rule_name,
            priority=alert_payload.get("priority", "warning"),
            severity=severity,
            hostname=hostname,
        )

    try:
        playbook_yaml = generate_runtime_diagnostic_playbook(
            runtime_context=ctx.to_dict(),
            host=hostname,
            target_user=settings.ansible_remote_user or "root",
        )
    except Exception as e:
        logger.error("playbook_generation_failed", rule=rule_name, error=str(e))
        playbook_yaml = ""

    if not playbook_yaml:
        return None

    description = (
        f"Runtime security event detected on {hostname}: {rule_name}. "
        f"Category: {runtime_category}. Intervention required: {is_intervention}."
    )

    async with AsyncSessionLocal() as session:
        investigation = Investigation(
            incident_title=f"Runtime: {rule_name} on {hostname}",
            incident_severity=severity,
            incident_status="open",
            status="diagnosing",
            incident_id=alert_payload.get("id", ""),
            ai_summary=description,
            playbook_yaml=playbook_yaml,
            playbook_valid=True,
            target_host=hostname,
            target_user=settings.ansible_remote_user or "root",
            hostnames=hostname,
            source="falco",
            investigation_type="runtime",
            resource_type=runtime_category,
            resource_context_json=ctx.to_dict(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            diagnostic_started_at=datetime.now(timezone.utc),
        )
        session.add(investigation)
        await session.flush()

        investigation_alert = InvestigationAlert(
            investigation_id=investigation.id,
            alert_id=alert_payload.get("id", ""),
            alert_json=json.dumps(alert_payload),
            severity=severity,
            source=alert_payload.get("source", "falco"),
            title=rule_name,
        )
        session.add(investigation_alert)
        await session.commit()
        await session.refresh(investigation)

        logger.info(
            "runtime_investigation_created",
            investigation_id=investigation.id,
            rule=rule_name,
            host=hostname,
        )
        return investigation.id, ctx.to_dict()


async def backfill(
    limit: Optional[int] = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    dry_run: bool = False,
):
    """Main backfill entrypoint."""
    print(f"\n{'='*60}")
    print("Falco Runtime Investigation Backfill")
    print(f"{'='*60}\n")

    # 1. Fetch all Falco events from ES
    print("[1/4] Fetching Falco events from Elasticsearch...")
    hits = await _fetch_falco_events(limit=limit)
    if not hits:
        print("No Falco events found in Elasticsearch.")
        return
    print(f"       Found {len(hits)} events\n")

    # 2. Check which are already backfilled
    print("[2/4] Checking existing runtime investigations...")
    existing_ids = await _get_existing_runtime_alert_ids()
    print(f"       {len(existing_ids)} events already have runtime investigations\n")

    # 3. Filter to unprocessed events
    to_process = []
    for hit in hits:
        es_id = hit["_id"]
        if es_id not in existing_ids:
            to_process.append(hit)

    print(f"[3/4] Events to backfill: {len(to_process)}\n")

    if not to_process:
        print("All events already have runtime investigations. Nothing to do.")
        return

    if dry_run:
        print("[DRY RUN] Would create the following investigations:")
        for hit in to_process:
            doc = hit["_source"]
            rule = doc.get("rule", "unknown")
            print(f"       {hit['_id'][:20]}... | {rule}")
        return

    # 4. Create investigations WITHOUT auto-diagnostics
    print("[4/4] Creating runtime investigations (diagnostics throttled to {} concurrent)...".format(concurrency))
    print()

    investigations: List[tuple] = []  # (investigation_id, resource_context)
    created = 0
    skipped = 0
    failed = 0

    for hit in to_process:
        es_id = hit["_id"]
        doc = hit["_source"]

        from pipeline.mappers.falco_runtime import map_falco_runtime_alert
        try:
            alert_payload = map_falco_runtime_alert(doc)
        except Exception as e:
            logger.warning("map_failed", es_id=es_id, error=str(e))
            failed += 1
            continue

        if not alert_payload:
            skipped += 1
            continue

        try:
            result = await _create_without_auto_diagnostic(alert_payload)
            if result:
                inv_id, ctx = result
                investigations.append((inv_id, ctx))
                created += 1
                print(f"  [{created}/{len(to_process)}] Created {inv_id[:20]}... | {alert_payload.get('rule_name', 'unknown')}")
            else:
                failed += 1
        except Exception as e:
            logger.error("creation_failed", es_id=es_id, error=str(e))
            failed += 1

    print(f"\n  Created: {created} | Skipped: {skipped} | Failed: {failed}")

    # 5. Run diagnostics with throttling
    if investigations:
        print(f"\n[5/5] Running diagnostics (max {concurrency} concurrent)...")
        semaphore = asyncio.Semaphore(concurrency)

        async def run_one(inv_id, ctx, idx, total):
            async with semaphore:
                from pipeline.datausage.runtime_orchestrator import _run_runtime_diagnostic_pipeline
                try:
                    print(f"  [{idx}/{total}] Running diagnostic for {inv_id[:20]}...", end="", flush=True)
                    await _run_runtime_diagnostic_pipeline(inv_id, ctx)
                    print(" ✓ done")
                except Exception as e:
                    print(f" ✗ failed: {e}")

        tasks = [
            run_one(inv_id, ctx, i + 1, len(investigations))
            for i, (inv_id, ctx) in enumerate(investigations)
        ]
        await asyncio.gather(*tasks)

    print(f"\n{'='*60}")
    print("Backfill complete!")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backfill Falco events into Runtime Investigations")
    parser.add_argument("--limit", type=int, default=None, help="Max events to process")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Max concurrent diagnostics")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be created without creating")
    args = parser.parse_args()

    asyncio.run(backfill(
        limit=args.limit,
        concurrency=args.concurrency,
        dry_run=args.dry_run,
    ))
