#!/usr/bin/env python3
"""
Backfill Suricata alerts from Elasticsearch into local SQLite DB.

This is a one-time script to ingest historical Suricata alerts that were
missed by the forwarder (e.g., because the cursor was already at the latest
document when the forwarder started, or because the forwarder was not running).

Usage:
    cd /home/dash/opensoar\ backend
    python3 scripts/backfill/backfill_suricata.py [--hours N] [--dry-run]
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import structlog
from sqlalchemy import select, func
from core.elasticsearch import search_alerts
from pipeline.mappers.filebeat import map_filebeat_alert
from pipeline.poller.alert_processor import _persist_alert_local, _build_clean_payload
from pipeline.poller.seen_ids import _is_ever_seen, _save_seen_ids
from response.db import AsyncSessionLocal
from response.models import Alert

logger = structlog.get_logger()


async def backfill_suricata(hours: int = 72, dry_run: bool = False) -> dict:
    """Backfill Suricata alerts from ES into local DB."""
    source = "filebeat"
    index_pattern = "filebeat-*"
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    
    logger.info(
        "backfill_start",
        source=source,
        index=index_pattern,
        start=start_time.isoformat(),
        end=end_time.isoformat(),
        dry_run=dry_run,
    )
    
    query = {
        "bool": {
            "filter": [
                {"term": {"fileset.name": "eve"}},
                {"term": {"suricata.eve.event_type": "alert"}},
                {"range": {"@timestamp": {"gte": start_time.isoformat().replace("+00:00", "Z"), "lte": end_time.isoformat().replace("+00:00", "Z")}}},
            ]
        }
    }
    
    total_inserted = 0
    total_skipped = 0
    total_errors = 0
    total_seen = 0
    batch_size = 100
    from_offset = 0
    
    while True:
        try:
            response = await search_alerts(
                index_pattern=index_pattern,
                query=query,
                size=batch_size,
                sort=[{"@timestamp": {"order": "asc"}}],
                from_=from_offset,
            )
        except Exception as e:
            logger.error("backfill_es_query_failed", error=str(e))
            break
        
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            break
        
        for hit in hits:
            es_id = hit.get("_id", "")
            source_doc = hit.get("_source", {})
            total_seen += 1
            
            # Skip if already in local DB
            try:
                async with AsyncSessionLocal() as session:
                    existing = await session.execute(
                        select(Alert.id).where(
                            Alert.source == source,
                            Alert.source_id == es_id,
                        ).limit(1)
                    )
                    if existing.scalar_one_or_none():
                        total_skipped += 1
                        continue
            except Exception as e:
                logger.warning("backfill_db_check_failed", es_id=es_id, error=str(e))
            
            if dry_run:
                logger.info("backfill_would_insert", es_id=es_id, timestamp=source_doc.get("@timestamp"))
                total_inserted += 1
                continue
            
            # Map the document
            try:
                payload = map_filebeat_alert(source_doc)
            except ValueError as e:
                logger.debug("backfill_map_skipped", es_id=es_id, reason=str(e))
                total_skipped += 1
                continue
            except Exception as e:
                logger.warning("backfill_map_error", es_id=es_id, error=str(e))
                total_errors += 1
                continue
            
            # Build clean payload
            clean_payload = _build_clean_payload(es_id, source_doc, payload, payload)
            
            # Persist locally
            try:
                local_id = await _persist_alert_local(source, es_id, clean_payload)
                if local_id:
                    total_inserted += 1
                    logger.debug("backfill_inserted", es_id=es_id, local_id=local_id)
                else:
                    total_skipped += 1
            except Exception as e:
                logger.warning("backfill_persist_failed", es_id=es_id, error=str(e))
                total_errors += 1
        
        from_offset += len(hits)
        logger.info(
            "backfill_batch_complete",
            batch_size=len(hits),
            total_seen=total_seen,
            total_inserted=total_inserted,
            total_skipped=total_skipped,
            total_errors=total_errors,
        )
        
        if len(hits) < batch_size:
            break
    
    logger.info(
        "backfill_complete",
        source=source,
        total_seen=total_seen,
        total_inserted=total_inserted,
        total_skipped=total_skipped,
        total_errors=total_errors,
    )
    
    # Clean up ES client
    try:
        from core import close_es_client
        await close_es_client()
    except Exception:
        pass
    
    return {
        "total_seen": total_seen,
        "total_inserted": total_inserted,
        "total_skipped": total_skipped,
        "total_errors": total_errors,
    }


def main():
    parser = argparse.ArgumentParser(description="Backfill Suricata alerts from ES to local DB")
    parser.add_argument("--hours", type=int, default=72, help="How many hours back to query (default: 72)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be inserted without writing")
    args = parser.parse_args()
    
    result = asyncio.run(backfill_suricata(hours=args.hours, dry_run=args.dry_run))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
