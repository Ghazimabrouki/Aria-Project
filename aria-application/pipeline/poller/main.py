"""
OpenSOAR Forwarder Service.
Polls Elasticsearch indices and forwards alerts to OpenSOAR.

Flow:
  1. Poll each ES index for new documents since last cursor
  2. Map raw ES docs → structured OpenSOAR alert format (via source-specific mappers)
  3. Apply source-specific deduplication (dedup.py)
  4. Filter by minimum severity
  5. Send ONLY clean, normalized alert to POST /api/v1/alerts
  6. Track cursor via Redis (fallback: file-based cursors)
  7. Track forwarded ES document IDs to NEVER resend the same doc
"""

import asyncio
from datetime import datetime, timezone
from typing import Tuple

import structlog
from config import get_settings
from core import search_alerts
from pipeline.sender import client
from pipeline.mappers import MAPPERS
from pipeline.poller.cursor_manager import _get_cursor, _set_cursor
from pipeline.poller.pattern_tracker import _cleanup_old_patterns
from pipeline.poller.seen_ids import _is_ever_seen, _save_seen_ids, _SEEN_IDS_CACHE
from pipeline.poller.alert_processor import process_single_alert, _advance_timestamp

logger = structlog.get_logger()


async def poll_source(source: str, index_pattern: str) -> Tuple[int, int]:
    """Poll one ES index, forward new documents to OpenSOAR. Returns (sent, skipped)."""
    settings = get_settings()
    cursor = await _get_cursor(source)
    cursor_iso = cursor.isoformat().replace("+00:00", "Z")

    query = {"bool": {"filter": []}}

    if source == "filebeat":
        query["bool"]["filter"].extend([
            {"term": {"fileset.name": "eve"}},
            {"term": {"suricata.eve.event_type": "alert"}},
        ])

    query["bool"]["filter"].append({"range": {"@timestamp": {"gt": cursor_iso}}})

    try:
        response = await search_alerts(
            index_pattern=index_pattern,
            query=query,
            size=settings.es_batch_size,
            sort=[{"@timestamp": {"order": "asc"}}],
        )
    except Exception as e:
        logger.warning("poll_es_failed", source=source, index=index_pattern, error=str(e))
        return 0, 0

    hits = response.get("hits", {}).get("hits", [])
    total_available = response.get("hits", {}).get("total", {})
    if isinstance(total_available, dict):
        total_available = total_available.get("value", 0)

    logger.info(
        "poll_source_result",
        source=source,
        index=index_pattern,
        cursor=cursor_iso,
        hits_returned=len(hits),
        hits_available=total_available,
    )

    # Update Redis stats even when no hits (shows forwarder is alive)
    try:
        from core import get_redis_client
        import json
        redis = await get_redis_client()
        stats_key = f"opensoar:forwarder:stats:{source}"
        existing_raw = await redis.get(stats_key)
        existing = json.loads(existing_raw) if existing_raw else {
            "total_sent": 0, "total_skipped": 0, "total_errors": 0,
            "total_processed": 0, "cycles": 0
        }
        existing["cycles"] = existing.get("cycles", 0) + 1
        existing["last_run"] = datetime.now(timezone.utc).isoformat()
        existing["last_sent"] = 0
        existing["last_errors"] = 0
        await redis.set(stats_key, json.dumps(existing), ex=86400 * 7)
    except Exception:
        pass

    if not hits:
        return 0, 0

    sent = 0
    skipped = 0
    duplicates = 0
    dedup_skipped = 0
    map_errors = 0
    forward_errors = 0
    latest_ts = cursor
    mapper = MAPPERS.get(source)
    processed_ids = set()

    for hit in hits:
        es_id = hit.get("_id", "")
        source_doc = hit.get("_source", {})

        if es_id in processed_ids:
            duplicates += 1
            latest_ts = _advance_timestamp(source_doc, latest_ts)
            continue
        processed_ids.add(es_id)

        if _is_ever_seen(source, es_id):
            duplicates += 1
            latest_ts = _advance_timestamp(source_doc, latest_ts)
            continue

        result = await process_single_alert(es_id, source_doc, source, mapper, latest_ts)
        sent += result.sent
        skipped += result.skipped
        duplicates += result.duplicates
        dedup_skipped += result.dedup_skipped
        map_errors += result.map_errors
        forward_errors += result.forward_errors
        latest_ts = result.latest_ts

        await asyncio.sleep(0.1)

    if latest_ts > cursor:
        await _set_cursor(source, latest_ts)
        logger.debug(
            "cursor_updated",
            source=source,
            previous=cursor_iso,
            new=latest_ts.isoformat(),
            docs_processed=len(processed_ids),
        )

    if processed_ids:
        _save_seen_ids(source)

    total_processed = len(processed_ids)
    if sent + duplicates + dedup_skipped + map_errors + forward_errors + skipped > 0:
        logger.info(
            "poll_source_summary",
            source=source,
            sent=sent,
            duplicates=duplicates,
            dedup_skipped=dedup_skipped,
            skipped_total=skipped,
            map_errors=map_errors,
            forward_errors=forward_errors,
            total_processed=total_processed,
            success_rate=f"{(sent / total_processed * 100):.1f}%" if total_processed else "0%",
        )

    # Store per-source stats in Redis for pipeline monitoring
    try:
        from core import get_redis_client
        import json
        redis = await get_redis_client()
        stats_key = f"opensoar:forwarder:stats:{source}"
        existing_raw = await redis.get(stats_key)
        existing = json.loads(existing_raw) if existing_raw else {
            "total_sent": 0, "total_skipped": 0, "total_errors": 0,
            "total_processed": 0, "cycles": 0
        }
        existing["total_sent"] = existing.get("total_sent", 0) + sent
        existing["total_skipped"] = existing.get("total_skipped", 0) + skipped
        existing["total_errors"] = existing.get("total_errors", 0) + map_errors + forward_errors
        existing["total_processed"] = existing.get("total_processed", 0) + total_processed
        existing["cycles"] = existing.get("cycles", 0) + 1
        existing["last_run"] = datetime.now(timezone.utc).isoformat()
        existing["last_sent"] = sent
        existing["last_errors"] = map_errors + forward_errors
        await redis.set(stats_key, json.dumps(existing), ex=86400 * 7)
    except Exception:
        pass

    return sent, skipped


async def run_forwarder(shutdown_event: asyncio.Event = None) -> None:
    """Main forwarder loop."""
    settings = get_settings()

    if not settings.local_ingestion_enabled:
        logger.info("local_ingestion_disabled")
        return

    index_patterns = {
        "wazuh": settings.wazuh_index_pattern,
        "falco": settings.falco_index_pattern,
        "filebeat": settings.filebeat_index_pattern,
    }

    if settings.suricata_index_pattern and settings.suricata_index_pattern != settings.filebeat_index_pattern:
        index_patterns["suricata"] = settings.suricata_index_pattern

    logger.info(
        "forwarder_starting",
        poll_interval=settings.alert_poll_interval,
        batch_size=settings.es_batch_size,
        sources=list(index_patterns.keys()),
        min_severity=settings.alert_min_severity,
        first_run_lookback_hours=settings.alert_first_run_lookback_hours,
        upstream_enabled=settings.upstream_enabled,
    )

    if settings.upstream_enabled:
        if not await client.authenticate():
            logger.error("forwarder_auth_failed_on_start")

    # Track last poll time per source for per-source intervals
    last_poll_time: dict[str, datetime] = {}

    def _source_interval(source: str) -> int:
        attr = f"{source}_poll_interval_seconds"
        val = getattr(settings, attr, None)
        if isinstance(val, int) and val >= 5:
            return val
        return settings.alert_poll_interval

    while True:
        if shutdown_event and shutdown_event.is_set():
            logger.info("forwarder_shutdown_requested")
            # Persist seen IDs before exiting
            for source in list(_SEEN_IDS_CACHE.keys()):
                _save_seen_ids(source)
            break

        cycle_start = datetime.now(timezone.utc)
        try:
            # Determine which sources are due based on per-source intervals
            tasks = []
            sources_due = []
            for source, pattern in index_patterns.items():
                last = last_poll_time.get(source)
                interval = _source_interval(source)
                if last is None or (cycle_start - last).total_seconds() >= interval:
                    tasks.append(poll_source(source, pattern))
                    sources_due.append(source)

            if tasks:
                # Execute due sources in parallel, continue even if some fail
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # Update last poll times for sources we attempted
                now = datetime.now(timezone.utc)
                for source in sources_due:
                    last_poll_time[source] = now

                # Aggregate results
                total = 0
                skipped_total = 0
                for result in results:
                    if isinstance(result, Exception):
                        logger.warning("source_polling_error", error=str(result))
                    elif isinstance(result, tuple):
                        s, sk = result
                        total += s
                        skipped_total += sk

                if total or skipped_total:
                    logger.info("forwarder_cycle_done", forwarded=total, skipped=skipped_total)
            else:
                total = 0
                skipped_total = 0

            # ADAPTIVE SLEEP: Adjust based on data volume
            elapsed = (datetime.now(timezone.utc) - cycle_start).total_seconds()

            if total > 20:  # High volume - check again quickly
                await asyncio.sleep(1)
            elif total > 0:  # Normal volume
                await asyncio.sleep(3)
            else:
                # Idle: sleep until the next source is due, or standard interval
                min_sleep = settings.alert_poll_interval
                now = datetime.now(timezone.utc)
                for source in index_patterns:
                    last = last_poll_time.get(source)
                    interval = _source_interval(source)
                    if last:
                        remaining = interval - (now - last).total_seconds()
                        if remaining < min_sleep:
                            min_sleep = max(1, remaining)
                    else:
                        min_sleep = 1
                await asyncio.sleep(min_sleep)

            # Safety: abort if cycle takes too long
            if elapsed > 120:
                logger.warning("cycle_timeout", elapsed_seconds=elapsed)

            # Cleanup old pattern tracking entries every cycle
            _cleanup_old_patterns(max_age_hours=24)

        except Exception as e:
            logger.error("forwarder_cycle_error", error=str(e))
            # Send pipeline failure notification
            try:
                from response.notification import send_pipeline_failure_notification
                await send_pipeline_failure_notification("forwarder", str(e)[:200])
            except Exception:
                pass

        await asyncio.sleep(settings.alert_poll_interval)
