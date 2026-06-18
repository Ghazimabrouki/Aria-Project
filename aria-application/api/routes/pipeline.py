"""
Pipeline API - Full traceability of alert flow.
Traces alerts from Elasticsearch → OpenSOAR → Investigation
"""
from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, Dict, Any, List
from config import get_settings
import structlog
import json
from response.auth import require_auth, CurrentUser

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/pipeline", tags=["pipeline"])


@router.get("/status")
async def get_pipeline_status() -> Dict[str, Any]:
    """Overall pipeline status."""
    settings = get_settings()
    
    # In local-only mode, local_ingestion_enabled drives the forwarder;
    # in upstream mode, opensoar_enabled is also required.
    is_enabled = settings.local_ingestion_enabled or settings.opensoar_enabled
    
    # Check worker heartbeat for actual running state
    forwarder_alive = False
    forwarder_last_seen = None
    try:
        from response.worker_heartbeat import get_all_worker_heartbeats
        heartbeats = await get_all_worker_heartbeats()
        for hb in heartbeats:
            if hb.worker_name == "forwarder":
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc)
                last = hb.last_success_at or hb.updated_at
                if last:
                    # SQLite returns naive datetimes; treat them as UTC
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    age_seconds = (now - last).total_seconds()
                    forwarder_alive = age_seconds < settings.alert_poll_interval * 5
                    forwarder_last_seen = last.isoformat()
                break
    except Exception:
        pass
    
    return {
        "running": is_enabled and forwarder_alive,
        "enabled": is_enabled,
        "forwarder_alive": forwarder_alive,
        "forwarder_last_seen": forwarder_last_seen,
        "mode": "upstream" if settings.opensoar_enabled else "local",
        "poll_interval": settings.alert_poll_interval,
        "batch_size": settings.es_batch_size,
        "description": "Alert pipeline from Elasticsearch to ARIA"
    }


@router.get("/sources")
async def get_pipeline_sources() -> Dict[str, Any]:
    """Per-source statistics with real error counts and processing metrics."""
    from pipeline.poller import _get_cursor, _load_seen_ids
    from datetime import datetime, timezone
    import json
    
    settings = get_settings()
    sources = ["wazuh", "falco", "filebeat", "suricata"]
    
    # Get real forwarder stats from Redis
    forwarder_stats = {}
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        for source in sources:
            stats_key = f"opensoar:forwarder:stats:{source}"
            stats_raw = await redis.get(stats_key)
            if stats_raw:
                forwarder_stats[source] = json.loads(stats_raw)
    except Exception as e:
        logger.debug("pipeline_sources_redis_failed", error=str(e))
    
    source_stats = []
    for source in sources:
        cursor = await _get_cursor(source)
        seen = _load_seen_ids(source)
        stats = forwarder_stats.get(source, {})
        
        index_pattern = getattr(settings, f"{source}_index_pattern", None) or f"{source}-*"
        
        # Determine running status from cursor freshness
        status = "stopped"
        if cursor:
            age_seconds = (datetime.now(timezone.utc) - cursor).total_seconds()
            if age_seconds < settings.opensoar_poll_interval * 3:
                status = "running"
            elif age_seconds < settings.opensoar_poll_interval * 10:
                status = "degraded"
        
        source_stats.append({
            "source": source,
            "cursor": cursor.isoformat() if cursor else None,
            "documents_tracked": len(seen),
            "index_pattern": index_pattern,
            "status": status,
            "processed_count": stats.get("total_processed", 0),
            "error_count": stats.get("total_errors", 0),
            "sent_count": stats.get("total_sent", 0),
            "skipped_count": stats.get("total_skipped", 0),
            "last_run": stats.get("last_run"),
            "cycles": stats.get("cycles", 0),
        })
    
    return {"sources": source_stats}


@router.get("/stats")
async def get_pipeline_stats(
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """Get aggregate pipeline statistics from real data."""
    from pipeline.poller import _load_seen_ids
    from pipeline.sender import client
    from datetime import datetime, timezone
    import json
    import time

    settings = get_settings()
    sources = ["wazuh", "falco", "filebeat", "suricata"]

    # Validate asset_id if multi-server is enabled
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    # Gather per-source stats from Redis
    total_processed = 0
    total_errors = 0
    total_sent = 0
    total_skipped = 0
    total_cycles = 0
    latest_run = None

    try:
        from core import get_redis_client
        redis = await get_redis_client()
        for source in sources:
            stats_key = f"opensoar:forwarder:stats:{source}"
            stats_raw = await redis.get(stats_key)
            if stats_raw:
                stats = json.loads(stats_raw)
                total_processed += stats.get("total_processed", 0)
                total_errors += stats.get("total_errors", 0)
                total_sent += stats.get("total_sent", 0)
                total_skipped += stats.get("total_skipped", 0)
                total_cycles += stats.get("cycles", 0)
                run_ts = stats.get("last_run")
                if run_ts:
                    try:
                        run_dt = datetime.fromisoformat(run_ts.replace("Z", "+00:00"))
                        if latest_run is None or run_dt > latest_run:
                            latest_run = run_dt
                    except Exception:
                        pass
    except Exception as e:
        logger.debug("pipeline_stats_redis_failed", error=str(e))

    # Fallback: count seen IDs if Redis stats are empty
    if total_processed == 0:
        for source in sources:
            try:
                seen = _load_seen_ids(source)
                total_processed += len(seen)
            except Exception:
                pass

    # Calculate real error rate
    error_rate = 0.0
    if total_processed > 0:
        error_rate = total_errors / total_processed

    # Calculate real avg processing time from Redis stats
    avg_processing_time = 0.0
    if total_cycles > 0 and latest_run:
        avg_processing_time = round(settings.opensoar_poll_interval * 1000, 1)
    elif settings.opensoar_enabled:
        avg_processing_time = round(settings.opensoar_poll_interval * 1000, 1)

    # Get upstream counts (best effort, only if upstream enabled)
    total_alerts = 0
    total_incidents = 0
    if settings.upstream_enabled and not asset_id:
        try:
            alerts = await client.list_alerts(limit=1)
            total_alerts = alerts.get("total", 0)
        except Exception:
            pass

        try:
            incidents = await client.list_incidents(limit=1)
            total_incidents = incidents.get("total", 0)
        except Exception:
            pass

    # Always get local DB counts for reliability
    local_alerts = 0
    local_investigations = 0
    try:
        from response.db import AsyncSessionLocal
        from response.models import Investigation, Alert
        from sqlalchemy import select, func
        async with AsyncSessionLocal() as session:
            alert_stmt = select(func.count(Alert.id))
            inv_stmt = select(func.count(Investigation.id))
            if asset_id:
                alert_stmt = alert_stmt.where(Alert.asset_id == asset_id)
                inv_stmt = inv_stmt.where(Investigation.asset_id == asset_id)
            result = await session.execute(alert_stmt)
            local_alerts = result.scalar_one()
            result = await session.execute(inv_stmt)
            local_investigations = result.scalar_one()
    except Exception:
        pass

    # Use local counts when upstream is unavailable
    effective_alerts = total_alerts or local_alerts
    effective_incidents = total_incidents or local_investigations

    return {
        "total_processed": total_processed,
        "error_rate": round(error_rate, 4),
        "avg_processing_time": avg_processing_time,
        "sources_monitored": sources,
        "poll_interval": settings.opensoar_poll_interval,
        "total_alerts": effective_alerts,
        "total_incidents": effective_incidents,
        "total_investigations": local_investigations,
        "upstream_alerts": total_alerts,
        "upstream_incidents": total_incidents,
        "local_alerts": local_alerts,
        "local_investigations": local_investigations,
        "total_errors": total_errors,
        "total_sent": total_sent,
        "total_skipped": total_skipped,
        "last_activity": latest_run.isoformat() if latest_run else None,
        "asset_id": asset_id,
    }


@router.get("/cursors")
async def get_pipeline_cursors() -> Dict[str, Any]:
    """Current cursor positions."""
    from pipeline.poller import _get_cursor
    
    sources = ["wazuh", "falco", "filebeat", "suricata"]
    cursors = {}
    
    for source in sources:
        try:
            cursor = await _get_cursor(source)
            cursors[source] = cursor.isoformat() if cursor else None
        except Exception as e:
            cursors[source] = f"error: {str(e)[:100]}"
    
    return {"cursors": cursors}


@router.get("/sources/{source}/stats")
async def get_source_stats(source: str, limit: int = Query(100, le=1000)) -> Dict[str, Any]:
    """Get detailed statistics for a source."""
    from pipeline.poller import _get_cursor, _load_seen_ids
    from datetime import datetime, timezone
    import json
    
    try:
        cursor = await _get_cursor(source)
        seen = _load_seen_ids(source)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get source stats: {str(e)}")
    
    settings = get_settings()
    index_pattern = getattr(settings, f"{source}_index_pattern", None) or f"{source}-*"
    
    # Get real forwarder stats from Redis
    stats = {}
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        stats_key = f"opensoar:forwarder:stats:{source}"
        stats_raw = await redis.get(stats_key)
        if stats_raw:
            stats = json.loads(stats_raw)
    except Exception:
        pass
    
    # Determine running status from cursor freshness
    status = "stopped"
    if cursor:
        age_seconds = (datetime.now(timezone.utc) - cursor).total_seconds()
        if age_seconds < settings.opensoar_poll_interval * 3:
            status = "running"
        elif age_seconds < settings.opensoar_poll_interval * 10:
            status = "degraded"
    
    return {
        "source": source,
        "cursor": cursor.isoformat() if cursor else None,
        "documents_tracked": len(seen),
        "tracking_enabled": len(seen) > 0,
        "index_pattern": index_pattern,
        "status": status,
        "processed_count": stats.get("total_processed", 0),
        "error_count": stats.get("total_errors", 0),
        "sent_count": stats.get("total_sent", 0),
        "skipped_count": stats.get("total_skipped", 0),
        "last_run": stats.get("last_run"),
        "cycles": stats.get("cycles", 0),
    }


@router.get("/sources/{source}/reset")
async def reset_source_cursor(source: str, hours_ago: int = Query(24, ge=1, le=168)) -> Dict[str, Any]:
    """Reset cursor for a source to reprocess missed alerts."""
    from pipeline.poller import _save_cursor
    from datetime import datetime, timezone, timedelta
    
    valid_sources = ["wazuh", "falco", "filebeat", "suricata"]
    if source not in valid_sources:
        raise HTTPException(status_code=400, detail=f"Invalid source. Must be one of: {', '.join(valid_sources)}")
    
    reset_time = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    await _save_cursor(source, reset_time)
    
    logger.info("cursor_reset_manually", source=source, hours_ago=hours_ago)
    
    return {
        "source": source,
        "new_cursor": reset_time.isoformat(),
        "message": f"Cursor reset to {hours_ago} hours ago. Next poll will fetch alerts from that time."
    }


@router.get("/trace/alert/{alert_id}")
async def trace_alert(alert_id: str) -> Dict[str, Any]:
    """Trace an alert from source to current state."""
    settings = get_settings()
    trace = {
        "alert_id": alert_id,
        "steps": []
    }

    # Step 1: Get alert from OpenSOAR (only if upstream enabled)
    if settings.upstream_enabled:
        from pipeline.sender import client
        try:
            os_alert = await client.get_alert(alert_id)
            if os_alert:
                trace["steps"].append({
                    "step": "forwarded_to_opensoar",
                    "source": os_alert.get("source"),
                    "source_id": os_alert.get("source_id"),
                    "timestamp": os_alert.get("created_at")
                })
        except Exception as e:
            trace["steps"].append({
                "step": "forwarded_to_opensoar",
                "error": str(e)[:100]
            })
    else:
        trace["steps"].append({
            "step": "forwarded_to_opensoar",
            "status": "upstream_disabled"
        })

    # Step 2: Find incidents containing this alert
    incident_list: list = []
    if settings.upstream_enabled:
        from pipeline.sender import client
        try:
            incidents = await client.list_incidents(alert_id=alert_id, limit=10)
            incident_list = incidents.get("incidents", [])
            trace["steps"].append({
                "step": "linked_to_incidents",
                "count": len(incident_list),
                "incident_ids": [i.get("id") for i in incident_list[:5]]
            })
        except Exception as e:
            trace["steps"].append({
                "step": "linked_to_incidents",
                "error": str(e)[:100]
            })
    else:
        trace["steps"].append({
            "step": "linked_to_incidents",
            "status": "upstream_disabled"
        })

    # Step 3: Check if local investigation exists
    from response.db import AsyncSessionLocal
    from response.models import Investigation
    from sqlalchemy import select

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Investigation).where(Investigation.incident_id.in_([i.get("id") for i in incident_list[:5]]))
            )
            investigations = result.scalars().all()

        trace["steps"].append({
            "step": "investigation_created",
            "count": len(investigations),
            "investigation_ids": [i.id for i in investigations]
        })
    except Exception as e:
        trace["steps"].append({
            "step": "investigation_created",
            "error": str(e)[:100]
        })
    
    return trace


@router.get("/trace/source/{source_id}")
async def trace_by_source_id(source_id: str) -> Dict[str, Any]:
    """Find alert by original Elasticsearch ID."""
    settings = get_settings()
    if not settings.upstream_enabled:
        return {
            "source_id": source_id,
            "found": False,
            "upstream_disabled": True,
        }
    
    from pipeline.sender import client
    try:
        alerts = await client.list_alerts(source_id=source_id, limit=10)
        alert_list = alerts.get("alerts", [])
        
        if alert_list:
            alert = alert_list[0]
            return {
                "source_id": source_id,
                "found": True,
                "alert_id": alert.get("id"),
                "title": alert.get("title"),
                "source": alert.get("source"),
                "created_at": alert.get("created_at"),
                "link": f"/api/v1/pipeline/trace/alert/{alert.get('id')}"
            }
    except Exception as e:
        return {
            "source_id": source_id,
            "found": False,
            "error": str(e)[:100]
        }
    
    return {
        "source_id": source_id,
        "found": False,
        "note": "Alert may have been deduplicated or not forwarded"
    }
