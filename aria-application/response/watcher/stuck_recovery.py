import asyncio
from datetime import datetime, timezone, timedelta

import structlog

from config import get_settings
from pipeline.sender import OpenSOARClient
from response.adaptive import get_adaptive_system
from response.db import AsyncSessionLocal
from response.models import Investigation, PlaybookRun

from response.watcher.ai_runner import _run_ai_engine, _broadcast_investigation_update
from response.watcher.context_builder import _build_investigation_context

logger = structlog.get_logger()
settings = get_settings()

_STUCK_NOTIFIED_INVESTIGATIONS: set = set()


def _ensure_aware(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _retry_pending_investigations():
    """
    Retry stuck 'pending' investigations:
    1. With errors (failed previously)
    2. Without errors but ai_summary is None (never processed)

    Runs on startup and every cycle.
    """
    import time

    # More aggressive retry - run every 30 seconds for pending with no errors
    current_time = time.time()
    if hasattr(_retry_pending_investigations, '_last_run'):
        time_since_last = current_time - _retry_pending_investigations._last_run
        # Allow faster retry for never-processed (ai_summary is None)
        min_interval = 30  # 30 seconds for never processed
        if time_since_last < min_interval:
            return

    _retry_pending_investigations._last_run = current_time

    from sqlalchemy import select
    from datetime import datetime, timezone, timedelta

    # For never-processed (ai_summary is None), use a shorter cutoff to retry faster
    never_processed_cutoff = datetime.now(timezone.utc) - timedelta(seconds=30)
    error_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)

    try:
        async with AsyncSessionLocal() as session:
            # Find pending investigations - both with errors and never processed
            result = await session.execute(
                select(Investigation)
                .where(Investigation.status == "pending")
                .where(Investigation.source != "performance")  # Skip performance investigations - they don't need AI retry
                .where(
                    # Has error (failed previously) but not in last 5 minutes
                    ((Investigation.ai_error.isnot(None) & (Investigation.ai_error != "")) &
                     (Investigation.updated_at < error_cutoff)) |
                    # Never processed by AI (ai_summary is None) - retry if older than 30 seconds
                    (Investigation.ai_summary.is_(None) & Investigation.updated_at < never_processed_cutoff)
                )
                .order_by(Investigation.updated_at.asc())  # Oldest first
                .limit(50)
            )
            pending = result.scalars().all()

            if pending:
                logger.info("retrying_pending_investigations", count=len(pending))

            for inv in pending:
                # Use adaptive retry logic
                try:
                    adaptive = await get_adaptive_system()

                    # Determine error type
                    error_type = None
                    if inv.ai_error:
                        from response.adaptive import ErrorClassifier
                        error_type = ErrorClassifier.categorize(str(inv.ai_error))

                    # Check if we should retry with adaptive wait
                    should_retry, wait = await adaptive.retry.should_retry(inv.id, error_type)

                    if not should_retry:
                        logger.info("retry_rate_limited", investigation_id=inv.id, wait_seconds=wait)
                        continue

                except Exception as e:
                    logger.warning("adaptive_retry_check_failed", error=str(e))
                    # Fall back to simple retry

                logger.info("retrying_investigation", investigation_id=inv.id,
                           has_error=bool(inv.ai_error), has_summary=bool(inv.ai_summary))

                # Re-fetch context from OpenSOAR or local DB
                try:
                    if settings.upstream_enabled:
                        reader = OpenSOARClient()
                        incident = await reader.get_incident(inv.incident_id)
                        alerts_raw = await reader.get_incident_alerts(inv.incident_id)

                        # Skip if no alerts - mark as failed to avoid retry loops
                        if not alerts_raw:
                            logger.warning("retry_skipped_no_alerts", investigation_id=inv.id, incident_id=inv.incident_id)
                            from sqlalchemy import update
                            async with AsyncSessionLocal() as session:
                                await session.execute(
                                    update(Investigation)
                                    .where(Investigation.id == inv.id)
                                    .values(status="failed", ai_error="No alerts in incident")
                                )
                                await session.commit()
                            await _broadcast_investigation_update(inv.id, inv.status, "failed", "No alerts in incident")
                            continue

                        full_alerts = []
                        for a in alerts_raw:
                            alert_id = a.get("id") if isinstance(a, dict) else a
                            if alert_id:
                                full = await reader.get_alert(str(alert_id))
                                if full:
                                    full_alerts.append(full)

                        # Skip if no full alerts after fetching
                        if not full_alerts:
                            logger.warning("retry_skipped_no_full_alerts", investigation_id=inv.id)
                            from sqlalchemy import update
                            async with AsyncSessionLocal() as session:
                                await session.execute(
                                    update(Investigation)
                                    .where(Investigation.id == inv.id)
                                    .values(status="failed", ai_error="Could not fetch alert details")
                                )
                                await session.commit()
                            await _broadcast_investigation_update(inv.id, inv.status, "failed", "Could not fetch alert details")
                            continue
                    else:
                        # Local mode: fetch incident + alerts from SQLite
                        from sqlalchemy import select
                        from response.models import Incident, Alert, AlertIncidentLink
                        async with AsyncSessionLocal() as session:
                            local_inc = await session.get(Incident, inv.local_incident_id or inv.incident_id)
                            if not local_inc:
                                logger.warning("retry_skipped_local_incident_not_found", investigation_id=inv.id)
                                continue
                            incident = {
                                "id": local_inc.id,
                                "title": local_inc.title,
                                "description": local_inc.description,
                                "severity": local_inc.severity,
                                "status": local_inc.status,
                                "source_ips": local_inc.source_ips,
                                "hostnames": local_inc.hostnames,
                                "tags": local_inc.tags,
                                "created_at": local_inc.created_at.isoformat() if local_inc.created_at else None,
                            }
                            link_result = await session.execute(
                                select(Alert)
                                .join(AlertIncidentLink, Alert.id == AlertIncidentLink.alert_id)
                                .where(AlertIncidentLink.incident_id == local_inc.id)
                            )
                            alerts = link_result.scalars().all()
                            full_alerts = []
                            for a in alerts:
                                full_alerts.append({
                                    "id": a.id,
                                    "title": a.title,
                                    "description": a.description,
                                    "severity": a.severity,
                                    "source": a.source,
                                    "source_ip": a.source_ip,
                                    "dest_ip": a.dest_ip,
                                    "hostname": a.hostname,
                                    "tags": a.tags,
                                    "rule_name": a.rule_name,
                                    "created_at": a.created_at.isoformat() if a.created_at else None,
                                })
                        if not full_alerts:
                            logger.warning("retry_skipped_no_local_alerts", investigation_id=inv.id)
                            continue

                    context = _build_investigation_context(incident, full_alerts)

                    # Use adaptive concurrency - await completion to avoid rate limits
                    try:
                        adaptive = await get_adaptive_system()
                        await adaptive.concurrency.acquire(inv.id)

                        # Run AI engine and WAIT for completion to avoid rate limits
                        await _run_ai_engine(inv.id, context)

                        # Release after completion
                        adaptive.concurrency.release()

                    except Exception as conc_err:
                        logger.warning("adaptive_concurrency_failed", error=str(conc_err))
                        # Fall back - but still await to avoid parallel rate limits
                        await _run_ai_engine(inv.id, context)

                except Exception as retry_err:
                    logger.error("retry_investigation_failed", investigation_id=inv.id, error=str(retry_err))
                    # Mark as failed so it doesn't keep retrying
                    try:
                        from sqlalchemy import update
                        async with AsyncSessionLocal() as session:
                            await session.execute(
                                update(Investigation)
                                .where(Investigation.id == inv.id)
                                .values(status="failed", ai_error=f"Retry failed: {retry_err}")
                            )
                            await session.commit()
                    except Exception as e:
                        logger.debug("retry_investigation_error", error=str(e))

    except Exception as e:
        logger.error("retry_pending_error", error=str(e))


async def _execute_approved_investigations():
    """
    Background task to ensure approved investigations get executed.
    Handles cases where approve API call failed silently or was lost.
    """
    from sqlalchemy import select
    from response.models import Investigation, PlaybookRun

    async with AsyncSessionLocal() as session:
        # Find investigations that are approved but have no PlaybookRun
        # (meaning they were approved but never executed)
        result = await session.execute(
            select(Investigation)
            .where(Investigation.status == "approved")
        )
        approved_invs = result.scalars().all()

        executed = 0
        for inv in approved_invs:
            # Check if there's already a PlaybookRun
            run_result = await session.execute(
                select(PlaybookRun).where(PlaybookRun.investigation_id == inv.id)
            )
            existing_run = run_result.scalar_one_or_none()

            if not existing_run:
                logger.info("executing_approved_investigation", investigation_id=inv.id)
                # Trigger playbook execution as background task
                from response.ansible_exec import execute_playbook
                asyncio.create_task(execute_playbook(inv.id))
                executed += 1

        if executed > 0:
            logger.info("approved_investigations_executed", count=executed)


async def _auto_approve_all_pending_investigations():
    """
    When auto_approve_all_enabled is true, automatically approve ALL
    investigations in awaiting_approval status and trigger execution.
    """
    if not getattr(settings, "auto_approve_all_enabled", False):
        return

    from sqlalchemy import select, update
    from response.models import Investigation, PlaybookRun

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation)
            .where(Investigation.status == "awaiting_approval")
        )
        pending = result.scalars().all()

        approved_count = 0
        for inv in pending:
            # Approve immediately
            await session.execute(
                update(Investigation)
                .where(Investigation.id == inv.id)
                .values(
                    status="approved",
                    updated_at=datetime.now(timezone.utc)
                )
            )
            await session.commit()
            approved_count += 1

            # Trigger execution
            from response.ansible_exec import execute_playbook
            asyncio.create_task(execute_playbook(inv.id))

            logger.info(
                "auto_approve_all_applied",
                investigation_id=inv.id,
                reason="auto_approve_all_enabled"
            )

            # Broadcast update
            try:
                from api.websocket import broadcast_investigation_change
                await broadcast_investigation_change(
                    inv.id, "awaiting_approval", "approved",
                    "Auto-approved: auto_approve_all_enabled"
                )
            except Exception:
                pass

        if approved_count > 0:
            logger.info("auto_approve_all_batch_complete", count=approved_count)


async def _check_stuck_investigations():
    """
    Check for investigations stuck too long and send alerts.
    Runs periodically to notify when:
    - awaiting_approval > stuck_investigation_hours (default 2)
    - running > stuck_running_minutes (default 30 min)
    - pending > stuck_pending_hours (default 1)
    """
    from datetime import timedelta
    from sqlalchemy import select
    from response.models import Investigation
    from response.notification import send_stuck_investigation_alert

    now = datetime.now(timezone.utc)
    hours_ago = now - timedelta(hours=settings.stuck_investigation_hours)
    minutes_ago = now - timedelta(minutes=settings.stuck_running_minutes)
    pending_hours_ago = now - timedelta(hours=settings.stuck_pending_hours)

    async with AsyncSessionLocal() as session:
        # Check awaiting_approval stuck > configured hours
        result = await session.execute(
            select(Investigation)
            .where(Investigation.status == "awaiting_approval")
            .where(Investigation.created_at < hours_ago)
        )
        awaiting_stuck = result.scalars().all()

        for inv in awaiting_stuck:
            if inv.id not in _STUCK_NOTIFIED_INVESTIGATIONS:
                hours_stuck = (now - _ensure_aware(inv.created_at)).total_seconds() / 3600
                await send_stuck_investigation_alert(
                    investigation_id=inv.id,
                    status=inv.status,
                    hours_stuck=hours_stuck,
                    severity=inv.incident_severity
                )
                _STUCK_NOTIFIED_INVESTIGATIONS.add(inv.id)
                logger.info("stuck_investigation_notified",
                          investigation_id=inv.id,
                          hours=hours_stuck,
                          severity=inv.incident_severity)

        # Check running stuck > configured minutes
        result2 = await session.execute(
            select(Investigation)
            .where(Investigation.status == "running")
            .where(Investigation.updated_at < now - timedelta(minutes=settings.stuck_running_minutes))
        )
        running_stuck = result2.scalars().all()

        for inv in running_stuck:
            if inv.id not in _STUCK_NOTIFIED_INVESTIGATIONS:
                hours_stuck = (now - _ensure_aware(inv.updated_at)).total_seconds() / 3600
                await send_stuck_investigation_alert(
                    investigation_id=inv.id,
                    status=inv.status,
                    hours_stuck=hours_stuck,
                    severity=inv.incident_severity
                )
                _STUCK_NOTIFIED_INVESTIGATIONS.add(inv.id)
                logger.info("running_investigation_stuck_notified",
                          investigation_id=inv.id,
                          hours=hours_stuck)

        # Check pending stuck > configured hours
        result3 = await session.execute(
            select(Investigation)
            .where(Investigation.status == "pending")
            .where(Investigation.created_at < now - timedelta(hours=settings.stuck_pending_hours))
        )
        pending_stuck = result3.scalars().all()

        for inv in pending_stuck:
            if inv.id not in _STUCK_NOTIFIED_INVESTIGATIONS:
                hours_stuck = (now - _ensure_aware(inv.created_at)).total_seconds() / 3600
                await send_stuck_investigation_alert(
                    investigation_id=inv.id,
                    status=inv.status,
                    hours_stuck=hours_stuck,
                    severity=inv.incident_severity
                )
                _STUCK_NOTIFIED_INVESTIGATIONS.add(inv.id)

        total_stuck = len(awaiting_stuck) + len(running_stuck) + len(pending_stuck)
        if total_stuck > 0:
            logger.info("stuck_investigations_check",
                       awaiting=len(awaiting_stuck),
                       running=len(running_stuck),
                       pending=len(pending_stuck))


async def _recover_stuck_running_investigations():
    """
    Auto-recover investigations stuck in 'running' status for too long.
    Checks if Ansible process is actually running; if not, marks as failed and verifies.
    """
    from datetime import timedelta
    from sqlalchemy import select, update
    from response.models import Investigation, PlaybookRun
    import psutil

    now = datetime.now(timezone.utc)
    timeout_threshold = now - timedelta(minutes=settings.running_investigation_timeout_minutes)

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation)
            .where(Investigation.status == "running")
            .where(Investigation.updated_at < timeout_threshold)
        )
        stuck_running = result.scalars().all()

        recovered = 0
        for inv in stuck_running:
            # Check if Ansible process is still running
            process_found = False
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        cmdline = proc.info.get('cmdline', [])
                        if cmdline and any('opensoar_playbooks' in str(c) and inv.id[:8] in str(c) for c in cmdline):
                            process_found = True
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                logger.debug("process_check_error", investigation_id=inv.id, error=str(e))

            if not process_found:
                logger.warning("recovering_stuck_investigation",
                             investigation_id=inv.id,
                             minutes_stuck=(now - _ensure_aware(inv.updated_at)).total_seconds() / 60)

                # Update investigation status to failed
                await session.execute(
                    update(Investigation)
                    .where(Investigation.id == inv.id)
                    .values(status="failed", ai_error="Auto-recovered: Ansible timeout")
                )

                # Update playbook run
                await session.execute(
                    update(PlaybookRun)
                    .where(PlaybookRun.investigation_id == inv.id)
                    .values(status="failed", output="Auto-terminated: Timeout after 30 minutes")
                )
                await session.commit()

                # Trigger verification to check if problem got worse
                from response.fix_verifier import verify_fix
                asyncio.create_task(verify_fix(inv.id))

                recovered += 1
                logger.info("recovered_stuck_investigation", investigation_id=inv.id)

        if recovered > 0:
            logger.info("stuck_running_recovery_complete", recovered=recovered)
