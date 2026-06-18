"""
Performance Incident Watcher.

Monitors performance incidents to verify fixes and track resolution.
Part of the Server Performance Monitoring System (v1.0).
"""

import asyncio
import structlog
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta

from config import get_settings
from core.redis_performance import performance_redis
from pipeline.performance_poller import PerformancePoller

logger = structlog.get_logger()

_performance_incidents: Dict[str, Dict[str, Any]] = {}


async def init_performance_watcher():
    """Initialize performance watcher."""
    global _performance_incidents
    
    try:
        stored = await performance_redis.get("performance_incidents")
        if stored:
            _performance_incidents = stored
            logger.info("performance_incidents_loaded", count=len(_performance_incidents))
    except Exception as e:
        logger.warning("performance_incidents_load_failed", error=str(e))


async def track_performance_incident(
    incident_id: str,
    host: str,
    alert_type: str,
    severity: str
) -> None:
    """Track a performance incident for monitoring."""
    global _performance_incidents
    
    _performance_incidents[incident_id] = {
        "host": host,
        "alert_type": alert_type,
        "severity": severity,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_checked": None,
        "resolved": False,
        "verification_attempts": 0,
    }
    
    try:
        await performance_redis.set("performance_incidents", _performance_incidents, ttl=86400)
        logger.info("performance_incident_tracked", incident_id=incident_id, host=host)
    except Exception as e:
        logger.warning("performance_incident_track_failed", error=str(e))


async def check_incident_resolution(incident_id: str) -> Dict[str, Any]:
    """Check if a performance incident has been resolved."""
    global _performance_incidents
    
    if incident_id not in _performance_incidents:
        return {"resolved": False, "reason": "incident_not_found"}
    
    incident = _performance_incidents[incident_id]
    host = incident["host"]
    alert_type = incident["alert_type"]
    
    try:
        poller = PerformancePoller()
        metrics_dict = await poller.poll_once()
        
        if host not in metrics_dict:
            return {"resolved": False, "reason": "host_not_found"}
        
        metrics = metrics_dict[host]
        
        from pipeline.enrichment.anomaly_detector import AnomalyDetector
        detector = AnomalyDetector()
        
        if alert_type == "cpu_high":
            is_resolved = metrics.cpu_usage_percent < get_settings().performance_cpu_critical
        elif alert_type == "memory_high":
            is_resolved = metrics.memory_used_percent < get_settings().performance_memory_critical
        elif alert_type == "disk_full":
            is_resolved = all(d.get("used_percent", 100) < get_settings().performance_disk_critical for d in metrics.disk_devices)
        else:
            is_resolved = False
        
        incident["last_checked"] = datetime.now(timezone.utc).isoformat()
        incident["verification_attempts"] += 1
        
        if is_resolved:
            incident["resolved"] = True
            incident["resolved_at"] = datetime.now(timezone.utc).isoformat()
            logger.info("performance_incident_resolved", incident_id=incident_id, host=host)
        
        await performance_redis.set("performance_incidents", _performance_incidents, ttl=86400)
        
        return {
            "resolved": is_resolved,
            "host": host,
            "alert_type": alert_type,
            "current_metrics": {
                "cpu": metrics.cpu_usage_percent,
                "memory": metrics.memory_used_percent,
            }
        }
        
    except Exception as e:
        logger.error("incident_resolution_check_failed", incident_id=incident_id, error=str(e))
        return {"resolved": False, "error": str(e)}


async def get_active_performance_incidents() -> List[Dict[str, Any]]:
    """Get all active (unresolved) performance incidents."""
    global _performance_incidents
    
    active = []
    for inc_id, incident in _performance_incidents.items():
        if not incident.get("resolved"):
            active.append({
                "incident_id": inc_id,
                **incident
            })
    return active


async def cleanup_resolved_incidents(max_age_hours: int = 24) -> int:
    """Remove resolved incidents older than max_age_hours."""
    global _performance_incidents
    
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    removed = 0
    
    for inc_id in list(_performance_incidents.keys()):
        incident = _performance_incidents[inc_id]
        if incident.get("resolved"):
            resolved_at = incident.get("resolved_at")
            if resolved_at:
                resolved_time = datetime.fromisoformat(resolved_at.replace("+00:00", ""))
                if resolved_time < cutoff:
                    del _performance_incidents[inc_id]
                    removed += 1
    
    if removed > 0:
        try:
            await performance_redis.set("performance_incidents", _performance_incidents, ttl=86400)
            logger.info("resolved_incidents_cleaned", removed=removed)
        except Exception as e:
            logger.warning("incident_cleanup_failed", error=str(e))
    
    return removed


async def run_performance_watcher_cycle() -> Dict[str, Any]:
    """Run one cycle of performance watcher."""
    settings = get_settings()
    
    if not settings.performance_enabled:
        return {"action": "skipped", "reason": "disabled"}
    
    result = {
        "active_incidents": 0,
        "resolved": 0,
        "errors": 0,
    }
    
    try:
        await init_performance_watcher()
        
        active = await get_active_performance_incidents()
        result["active_incidents"] = len(active)
        
        for incident in active:
            check_result = await check_incident_resolution(incident["incident_id"])
            if check_result.get("resolved"):
                result["resolved"] += 1
        
        await cleanup_resolved_incidents()
        
    except Exception as e:
        logger.error("performance_watcher_cycle_error", error=str(e))
        result["errors"] += 1
    
    return result


async def start_performance_watcher():
    """Start the performance watcher loop."""
    settings = get_settings()
    
    if not settings.performance_enabled:
        logger.info("performance_watcher_not_enabled")
        return
    
    logger.info("performance_watcher_started")
    
    await init_performance_watcher()
    
    while True:
        try:
            result = await run_performance_watcher_cycle()
            
            if result.get("resolved", 0) > 0:
                logger.info("performance_watcher_cycle_complete", **result)
                
        except Exception as e:
            logger.error("performance_watcher_loop_error", error=str(e))
        
        await asyncio.sleep(60)  # Check every minute