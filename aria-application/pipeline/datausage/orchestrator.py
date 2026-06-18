"""
Alert Data Usage Orchestrator.
Central coordinator that processes each forwarded alert through smart pipeline stages.

Pipeline stages:
1. Observables - IOC extraction & auto-creation
2. AI triage - smart analysis, summarize, auto-resolve
3. Incidents - correlation & auto-creation
4. Alerts - auto-update status, determination, add enrichment comments
"""

import structlog
from typing import Dict, Any

logger = structlog.get_logger()

_stats: Dict[str, Any] = {
    "alerts_processed": 0,
    "observables": {"created": 0, "errors": 0},
    "ai": {"triaged": 0, "summarized": 0, "errors": 0},
    "incidents": {"created": 0, "linked": 0, "errors": 0},
    "alerts": {"status_updated": 0, "determination_set": 0, "comments_added": 0, "errors": 0},
}


async def process_alert(local_alert_id: str, alert_data: dict, upstream_alert_id: str = None) -> dict:
    """
    Process a forwarded alert through all data usage pipeline stages.
    Called from poller.py via asyncio.create_task() after successful forward.
    
    Args:
        local_alert_id: UUID of the local SQLite alert record
        alert_data: The enriched alert payload
        upstream_alert_id: ID assigned by upstream OpenSOAR (optional, None if upstream disabled)
    """
    from config import get_settings
    settings = get_settings()

    global _stats
    _stats["alerts_processed"] += 1
    results = {"local_alert_id": local_alert_id, "upstream_alert_id": upstream_alert_id, "stages": {}}

    # Observables stage
    try:
        from pipeline.datausage.observable_manager import observable_manager
        if upstream_alert_id:
            obs_result = await observable_manager.auto_create_from_alert(upstream_alert_id, alert_data)
        else:
            obs_result = await observable_manager.auto_create_from_alert(local_alert_id, alert_data)
        results["stages"]["observables"] = {
            "action": "created",
            "count": len(obs_result),
        }
        _stats["observables"]["created"] += len(obs_result)
    except Exception as e:
        logger.warning("observables_stage_failed", local_alert_id=local_alert_id, error=str(e)[:100])
        results["stages"]["observables"] = {"action": "error", "error": str(e)[:100]}
        _stats["observables"]["errors"] += 1

    # AI triage stage
    try:
        from pipeline.datausage.ai_pipeline import ai_pipeline
        if upstream_alert_id:
            ai_result = await ai_pipeline.smart_triage_and_apply(upstream_alert_id, alert_data)
        else:
            ai_result = await ai_pipeline.smart_triage_and_apply(local_alert_id, alert_data)
        results["stages"]["ai"] = ai_result
        if ai_result.get("triaged"):
            _stats["ai"]["triaged"] += 1
        if ai_result.get("summarized"):
            _stats["ai"]["summarized"] += 1
    except Exception as e:
        logger.warning("ai_stage_failed", local_alert_id=local_alert_id, error=str(e)[:100])
        results["stages"]["ai"] = {"action": "error", "error": str(e)[:100]}
        _stats["ai"]["errors"] += 1

    # Incident correlation stage
    try:
        if settings.upstream_enabled:
            from pipeline.datausage.incident_manager import process_alert as process_incident
            incident_result = await process_incident(
                upstream_alert_id=upstream_alert_id or local_alert_id,
                alert_payload=alert_data,
                local_alert_id=local_alert_id,
            )
        else:
            from pipeline.datausage.local_incident_manager import process_alert_local
            incident_result = await process_alert_local(
                alert_id=upstream_alert_id or local_alert_id,
                alert_payload=alert_data,
                local_alert_id=local_alert_id,
            )
        results["stages"]["incident"] = incident_result
        action = incident_result.get("action", "")
        if action == "created":
            _stats["incidents"]["created"] += 1
        elif action == "linked":
            _stats["incidents"]["linked"] += 1
    except Exception as e:
        logger.warning("incident_stage_failed", local_alert_id=local_alert_id, error=str(e)[:100])
        results["stages"]["incident"] = {"action": "error", "error": str(e)[:100]}
        _stats["incidents"]["errors"] += 1

    # Alert enrichment stage
    try:
        from pipeline.datausage.alert_manager import alert_manager
        incident_id = results.get("stages", {}).get("incident", {}).get("incident_id")
        if upstream_alert_id:
            alert_result = await alert_manager.auto_enrich_alert(upstream_alert_id, alert_data, incident_id)
        else:
            alert_result = await alert_manager.auto_enrich_alert(local_alert_id, alert_data, incident_id)
        results["stages"]["alerts"] = alert_result
        actions = alert_result.get("actions", {})
        if actions.get("status_update"):
            _stats["alerts"]["status_updated"] += 1
        if actions.get("determination_set"):
            _stats["alerts"]["determination_set"] += 1
        if actions.get("comment_added"):
            _stats["alerts"]["comments_added"] += 1
    except Exception as e:
        logger.warning("alerts_stage_failed", local_alert_id=local_alert_id, error=str(e)[:100])
        results["stages"]["alerts"] = {"action": "error", "error": str(e)[:100]}
        _stats["alerts"]["errors"] += 1

    return results


def get_pipeline_stats() -> Dict[str, Any]:
    """Get aggregated pipeline statistics."""
    from pipeline.datausage.observable_manager import observable_manager
    from pipeline.datausage.ai_pipeline import ai_pipeline
    from pipeline.datausage.incident_manager import get_correlation_stats

    obs_stats = observable_manager.get_stats()
    ai_stats = ai_pipeline.get_stats()
    incident_stats = get_correlation_stats()

    return {
        "pipeline": dict(_stats),
        "observables": obs_stats,
        "ai": ai_stats,
        "incidents": incident_stats,
        "alerts": dict(_stats.get("alerts", {})),
        "playbooks": {"triggered": 0, "failed": 0},
        "actions": {"executed": 0, "failed": 0},
        "tickets": {"created": 0, "updated": 0},
        "health": {"healthy": True, "last_check": None},
    }
