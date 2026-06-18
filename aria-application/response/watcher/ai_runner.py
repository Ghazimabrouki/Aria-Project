import asyncio
from datetime import datetime, timezone

import structlog
from sqlalchemy import update

from response.db import AsyncSessionLocal
from response.models import Investigation

logger = structlog.get_logger()

# Legacy semaphore - now managed by adaptive system
_ai_semaphore = asyncio.Semaphore(4)  # Default, will be updated by adaptive


async def _broadcast_investigation_update(investigation_id: str, old_status: str, new_status: str, details: str = ""):
    """Broadcast investigation status change via WebSocket."""
    try:
        from api.websocket import broadcast_investigation_change
        await broadcast_investigation_change(investigation_id, old_status, new_status, details)
    except Exception as e:
        logger.debug("websocket_broadcast_failed", error=str(e))


async def _broadcast_new_investigation(investigation_id: str, incident_title: str, severity: str):
    """Broadcast new investigation created."""
    try:
        from api.websocket import ws_manager
        await ws_manager.broadcast("investigations", {
            "type": "investigation_created",
            "investigation_id": investigation_id,
            "incident_title": incident_title,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        logger.debug("websocket_new_investigation_broadcast_failed", error=str(e))


async def _run_ai_engine(investigation_id: str, context: dict):
    """Trigger AI engine — runs with semaphore to limit concurrency to 1."""
    logger.info("ai_engine_context_debug", investigation_id=investigation_id, keys=list(context.keys()))
    async with _ai_semaphore:
        logger.info("ai_engine_started", investigation_id=investigation_id)
        try:
            from response.ai_engine import run_investigation
            await run_investigation(investigation_id, context)
            logger.info("ai_engine_finished", investigation_id=investigation_id)

            # Send notification after successful AI processing
            try:
                from response.notification import send_approval_notification
                await send_approval_notification(
                    investigation_id=investigation_id,
                    incident_title=context.get("incident", {}).get("title", "Unknown"),
                    risk_score=context.get("risk_score", 50),
                    attack_type=context.get("attack_type", "unknown"),
                    target_host=context.get("hostnames", [None])[0] if context.get("hostnames") else None,
                    source_ips=context.get("source_ips", [])
                )
            except Exception as notif_err:
                logger.warning("notification_failed", investigation_id=investigation_id, error=str(notif_err))

        except Exception as e:
            logger.error("ai_engine_trigger_error", investigation_id=investigation_id, error=str(e), exc_info=True)
            from sqlalchemy import update
            async with AsyncSessionLocal() as session:
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == investigation_id)
                    .values(ai_error=str(e), status="pending")
                )
                await session.commit()
