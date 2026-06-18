#!/usr/bin/env python
"""
OpenSOAR Backend - Main Entry Point

Runs two systems concurrently:
  1. Alert Forwarder (existing) — polls Elasticsearch, enriches alerts, forwards to OpenSOAR
  2. Response Intelligence Layer (new) — watches incidents, runs AI investigation,
     handles approval workflow, executes Ansible playbooks, verifies fixes, archives cases

HTTP API available at http://0.0.0.0:{BACKEND_PORT} (default: 8001)
"""

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import structlog
import uvicorn

from config import get_settings
from pipeline.poller import run_forwarder
from core import close_es_client, close_redis_client

logger = structlog.get_logger()
settings = get_settings()

_shutdown_event = asyncio.Event()
_uvicorn_server = None


def _signal_handler(signum, frame):
    """Handle SIGINT and SIGTERM for graceful shutdown."""
    sig_name = signal.Signals(signum).name
    logger.info("shutdown_signal_received", signal=sig_name)
    _shutdown_event.set()


async def _persist_state_on_shutdown():
    """Persist cursors and seen IDs before exiting."""
    logger.info("persisting_state_before_shutdown")
    try:
        from pipeline.poller import _save_seen_ids, _SEEN_IDS_CACHE
        for source in list(_SEEN_IDS_CACHE.keys()):
            _save_seen_ids(source)
        logger.info("seen_ids_persisted", sources=list(_SEEN_IDS_CACHE.keys()))
    except Exception as e:
        logger.warning("seen_ids_persist_error", error=str(e))
    
    try:
        from pipeline.sender import client
        await client.close()
        logger.info("opensoar_client_closed")
    except Exception as e:
        logger.warning("opensoar_client_close_error", error=str(e))


def _resolve_path(path_str: str) -> Path:
    """Resolve a path relative to project root if not absolute."""
    p = Path(path_str)
    if p.is_absolute():
        return p
    return Path(__file__).parent / p


async def _run_safe_task(coro_func, task_name: str, restart_delay: float = 5, shutdown_event: asyncio.Event = None):
    """
    Wraps a task function with error handling.
    If the task crashes, it logs the error and restarts after a delay.
    This prevents one crashed task from killing the entire application.
    
    Handles both:
    - Blocking tasks (like server.serve()) that we wait on directly
    - Non-blocking tasks (like start_background_monitor()) that create internal tasks
    """
    import time
    
    last_start = time.time()
    consecutive_quick_returns = 0
    
    while True:
        if shutdown_event and shutdown_event.is_set():
            logger.info("task_shutdown_requested", task=task_name)
            break
        
        try:
            # Add a minimum run time check to detect rapid restarts
            start_time = time.time()
            
            await coro_func()
            
            # If we get here, the coroutine completed (not normal for long-running tasks)
            run_duration = time.time() - start_time
            
            # For tasks that return quickly (like start_background_monitor), 
            # this is expected - don't treat as a crash
            if run_duration < 1.0:
                consecutive_quick_returns += 1
                # Only restart if it keeps returning quickly many times (potential fast loop)
                if consecutive_quick_returns > 5:
                    logger.warning("task_rapid_restart_detected", task=task_name, count=consecutive_quick_returns)
                    consecutive_quick_returns = 0
                    await asyncio.sleep(restart_delay)
            else:
                # Task ran for a while then completed - this is unusual for our background tasks
                # But don't restart - the task completed normally
                logger.info("task_completed", task=task_name, duration=run_duration)
                break
                
        except asyncio.CancelledError:
            logger.info("task_cancelled", task=task_name)
            break
        except Exception as e:
            consecutive_quick_returns = 0  # Reset on actual error
            logger.error(
                "task_crashed",
                task=task_name,
                error=str(e),
                restart_delay=restart_delay,
                exc_info=True
            )
            await asyncio.sleep(restart_delay)
            logger.info("task_restarting", task=task_name)


async def _run_watchdog():
    """Watchdog that monitors application health and logs periodic heartbeats."""
    from datetime import datetime, timezone
    import psutil
    from response.worker_heartbeat import update_worker_heartbeat
    
    while True:
        await asyncio.sleep(60)  # Check every minute
        
        # Count active tasks
        try:
            process = psutil.Process()
            children = process.children(recursive=True)
            
            # Get memory usage
            mem_info = process.memory_info()
            mem_mb = mem_info.rss / 1024 / 1024
            
            logger.info(
                "watchdog_heartbeat",
                timestamp=datetime.now(timezone.utc).isoformat(),
                memory_mb=round(mem_mb, 1),
                child_processes=len(children),
            )
            await update_worker_heartbeat("watchdog", status="running")
        except Exception as e:
            await update_worker_heartbeat("watchdog", status="failed", error=str(e))
            logger.warning("watchdog_check_error", error=str(e))


async def _run_auto_transitions_loop():
    from response.worker_heartbeat import update_worker_heartbeat
    while True:
        try:
            from pipeline.datausage.ticketing.lifecycle import run_auto_transitions
            result = await run_auto_transitions()
            if result.get("processed", 0) > 0:
                logger.info("auto_transitions_ran", processed=result["processed"])
            await update_worker_heartbeat("auto_transitions", status="running")
        except Exception as e:
            await update_worker_heartbeat("auto_transitions", status="failed", error=str(e))
            logger.error("auto_transitions_loop_error", error=str(e))
        await asyncio.sleep(3600)


async def _run_incident_correlation_loop():
    from response.worker_heartbeat import update_worker_heartbeat
    settings = get_settings()
    while True:
        try:
            from pipeline.datausage.incident_manager import run_correlation_cycle
            created = await run_correlation_cycle()
            if created > 0:
                logger.info("incident_correlation_cycle_complete", incidents_created=created)
            await update_worker_heartbeat("incident_correlation", status="running")
        except Exception as e:
            await update_worker_heartbeat("incident_correlation", status="failed", error=str(e))
            logger.error("incident_correlation_loop_error", error=str(e))
        await asyncio.sleep(settings.incident_correlation_interval)


async def _run_retry_queue_loop():
    """Process retry queue for failed alerts every 5 minutes."""
    from response.worker_heartbeat import update_worker_heartbeat
    settings = get_settings()
    if not settings.upstream_enabled:
        logger.info("retry_queue_disabled_upstream_not_enabled")
        while True:
            await update_worker_heartbeat("retry_queue", status="running")
            await asyncio.sleep(3600)  # Sleep indefinitely when upstream disabled
    while True:
        try:
            from pipeline.retry_queue import retry_queue
            from pipeline.sender import client
            
            async def process_retry_alert(alert_data):
                try:
                    result = await client.send_alert(alert_data)
                    return result.get("alert_id") is not None
                except Exception:
                    return False
            
            stats = await retry_queue.process_queue(process_retry_alert)
            if stats.get("processed", 0) > 0:
                logger.info("retry_queue_processed", **stats)
            await update_worker_heartbeat("retry_queue", status="running")
        except Exception as e:
            await update_worker_heartbeat("retry_queue", status="failed", error=str(e))
            logger.error("retry_queue_loop_error", error=str(e))
        await asyncio.sleep(300)  # 5 minutes


async def _run_backup_loop():
    """Run daily backup of response database."""
    from response.worker_heartbeat import update_worker_heartbeat
    import os
    from datetime import datetime
    
    backup_dir_path = _resolve_path(settings.backup_dir)
    db_path = _resolve_path(settings.db_path)
    
    while True:
        try:
            # Wait until 3 AM for daily backup
            now = datetime.now()
            seconds_until_3am = (24 - now.hour - 1) * 3600 + (60 - now.minute) * 60
            await asyncio.sleep(seconds_until_3am)
            
            # Run backup
            backup_dir_path.mkdir(parents=True, exist_ok=True)
            
            # Backup response DB
            if db_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = backup_dir_path / f"investigations_{timestamp}.db"
                import shutil
                shutil.copy2(str(db_path), str(backup_path))
                
                # Keep only last 7 backups
                import glob
                backups = sorted(glob.glob(str(backup_dir_path / "investigations_*.db")))
                for old_backup in backups[:-7]:
                    os.remove(old_backup)
                    
                logger.info("backup_completed", backup_path=str(backup_path), kept=len(backups))
            await update_worker_heartbeat("backup", status="running")
        except Exception as e:
            await update_worker_heartbeat("backup", status="failed", error=str(e))
            logger.error("backup_loop_error", error=str(e))
        # Sleep for 24 hours after backup
        await asyncio.sleep(86400)


async def _run_response_api():
    """Start the FastAPI HTTP server for the Response Intelligence Layer."""
    import errno
    import os
    import socket
    import threading
    from api.app import app
    import uvicorn
    
    global _uvicorn_server
    port = settings.backend_port
    
    # Allow containerized deployments to run workers without binding the API port
    if os.environ.get("SKIP_RESPONSE_API", "").lower() in ("1", "true", "yes"):
        logger.info("response_api_skipped_by_env", skip_response_api=True)
        while not _shutdown_event.is_set():
            await asyncio.sleep(60)
        return
    
    logger.info("response_api_starting", port=port)
    
    # Check if port is in use using bind method - use 0.0.0.0 to match server binding
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.close()
        port_in_use = False
        logger.info("response_api_port_free", port=port)
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            port_in_use = True
            logger.info("response_api_port_in_use_skipping", port=port)
        else:
            port_in_use = False
            logger.warning("response_api_port_check_error", error=str(e))
    
    if port_in_use:
        # Keep task alive, checking periodically
        while not _shutdown_event.is_set():
            await asyncio.sleep(60)
        return
    
    # Run uvicorn in a separate thread to avoid blocking the event loop
    def run_uvicorn():
        import uvicorn
        global _uvicorn_server
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=port,
            log_level="warning",
            access_log=False,
            timeout_keep_alive=30,
        )
        _uvicorn_server = uvicorn.Server(config)
        _uvicorn_server.run()
    
    server_thread = threading.Thread(target=run_uvicorn, daemon=True)
    server_thread.start()
    logger.info("response_api_thread_started", port=port)
    
    # Wait for server to be ready
    await asyncio.sleep(2)
    
    # Keep the task alive while server runs
    while not _shutdown_event.is_set():
        await asyncio.sleep(60)
    
    # Signal uvicorn to stop
    if _uvicorn_server:
        _uvicorn_server.should_exit = True
    logger.info("response_api_shutdown_requested", port=port)


async def _run_incident_watcher():
    """Start the incident watcher that monitors OpenSOAR for new incidents."""
    from response.worker_heartbeat import update_worker_heartbeat
    # Small delay so DB is initialized before watcher starts querying
    await asyncio.sleep(5)
    from response.watcher import watch_incidents

    async def _heartbeat_while_running():
        while True:
            await asyncio.sleep(30)
            await update_worker_heartbeat("incident_watcher", status="running")

    try:
        await asyncio.gather(
            watch_incidents(shutdown_event=_shutdown_event),
            _heartbeat_while_running(),
        )
    except asyncio.CancelledError:
        raise
    except Exception as e:
        await update_worker_heartbeat("incident_watcher", status="failed", error=str(e))
        raise


async def _run_fix_verification_job_loop():
    """Periodically process due fix verification jobs from the persistent queue."""
    from response.worker_heartbeat import update_worker_heartbeat
    # Small delay so DB is initialized
    await asyncio.sleep(10)
    # Recover any pending jobs from previous runs
    try:
        from response.fix_verifier import recover_pending_jobs
        await recover_pending_jobs()
    except Exception as e:
        logger.warning("fix_verification_recovery_failed", error=str(e))
    while True:
        try:
            from response.fix_verifier import process_due_verification_jobs
            await process_due_verification_jobs()
            await update_worker_heartbeat("fix_verification_jobs", status="running")
        except Exception as e:
            await update_worker_heartbeat("fix_verification_jobs", status="failed", error=str(e))
            logger.error("fix_verification_job_loop_error", error=str(e))
        await asyncio.sleep(30)  # Check every 30 seconds


async def _run_runtime_diagnostic_recovery_loop():
    """Recover runtime investigations stuck in 'diagnosing' status."""
    await asyncio.sleep(15)  # Let DB and forwarder initialize first
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import select
    from response.db import AsyncSessionLocal
    from response.worker_heartbeat import update_worker_heartbeat
    from response.models import Investigation
    from pipeline.datausage.runtime_orchestrator import (
        _run_runtime_diagnostic_pipeline,
        _DIAGNOSTIC_SEMAPHORE,
        _DIAGNOSTIC_METRICS,
    )

    while True:
        try:
            stuck_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(Investigation)
                    .where(Investigation.status == "diagnosing")
                    .where(Investigation.investigation_type == "runtime")
                    .where(Investigation.diagnostic_started_at < stuck_cutoff)
                    .order_by(Investigation.diagnostic_started_at.asc())
                    .limit(10)
                )
                stuck = result.scalars().all()

                if stuck:
                    logger.info(
                        "runtime_diagnostic_recovery_scan",
                        stuck_count=len(stuck),
                        metrics={k: v for k, v in _DIAGNOSTIC_METRICS.items()},
                    )

                for inv in stuck:
                    try:
                        ctx = inv.resource_context_json or {}
                        logger.info(
                            "runtime_diagnostic_recovery_start",
                            investigation_id=inv.id,
                            title=inv.incident_title,
                            stuck_since=inv.diagnostic_started_at.isoformat() if inv.diagnostic_started_at else None,
                        )
                        async with _DIAGNOSTIC_SEMAPHORE:
                            await _run_runtime_diagnostic_pipeline(inv.id, ctx)
                        logger.info(
                            "runtime_diagnostic_recovery_complete",
                            investigation_id=inv.id,
                        )
                    except Exception as e:
                        logger.error(
                            "runtime_diagnostic_recovery_failed",
                            investigation_id=inv.id,
                            error=str(e),
                        )
            await update_worker_heartbeat("runtime_diagnostic_recovery", status="running")
        except Exception as e:
            await update_worker_heartbeat("runtime_diagnostic_recovery", status="failed", error=str(e))
            logger.error("runtime_diagnostic_recovery_loop_error", error=str(e))
        await asyncio.sleep(60)  # Scan every 60 seconds


async def _run_forwarder_with_heartbeat():
    """Wrap the alert forwarder with heartbeat updates."""
    from response.worker_heartbeat import update_worker_heartbeat

    async def _heartbeat_while_running():
        while True:
            await asyncio.sleep(30)
            await update_worker_heartbeat("forwarder", status="running")

    try:
        await asyncio.gather(
            run_forwarder(),
            _heartbeat_while_running(),
        )
    except asyncio.CancelledError:
        raise
    except Exception as e:
        await update_worker_heartbeat("forwarder", status="failed", error=str(e))
        raise


async def _run_settings_reload_listener():
    """Listen for Redis-published settings changes and reload worker env/settings."""
    from core.redis import get_redis_client
    from config.settings import reload_settings

    SETTINGS_RELOAD_CHANNEL = "aria:settings:reload"
    try:
        client = await get_redis_client()
        pubsub = client.pubsub()
        await pubsub.subscribe(SETTINGS_RELOAD_CHANNEL)
        logger.info("settings_reload_listener_subscribed", channel=SETTINGS_RELOAD_CHANNEL)
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    changed = json.loads(message["data"])
                    os.environ.update(changed)
                    reload_settings()
                    logger.info("settings_reloaded_from_redis", changed_keys=list(changed.keys()))
                except Exception as e:
                    logger.warning("settings_reload_message_error", error=str(e))
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.error("settings_reload_listener_error", error=str(e))


async def main():
    """Main entry point — starts all services concurrently."""
    logger.info("starting_backend", api_port=settings.backend_port, upstream_enabled=settings.upstream_enabled, local_ingestion_enabled=settings.local_ingestion_enabled)

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    logger.info("signal_handlers_registered")

    # Initialize response intelligence DB
    from response.db import init_db
    await init_db()
    logger.info("response_db_initialized")

    # Start existing background services (these have internal error handling)
    from pipeline.datausage.health_monitor import health_monitor
    from pipeline.datausage.dashboard_monitor import dashboard_monitor

    if settings.upstream_enabled:
        await health_monitor.start_background_check()
        logger.info("health_monitor_started")
    else:
        logger.info("health_monitor_skipped_upstream_disabled")

    # Define all tasks with their coroutine functions and names
    # Using _run_safe_task wrapper ensures crashes don't kill the entire app
    # Note: response_api runs separately (api_task) since it needs to block
    task_definitions = [
        (_run_auto_transitions_loop, "auto_transitions"),
        (_run_incident_correlation_loop, "incident_correlation"),
        (_run_incident_watcher, "incident_watcher"),
        (_run_retry_queue_loop, "retry_queue"),
        (_run_backup_loop, "backup"),
        (_run_fix_verification_job_loop, "fix_verification_jobs"),
        (_run_runtime_diagnostic_recovery_loop, "runtime_diagnostic_recovery"),
        (_run_forwarder_with_heartbeat, "forwarder"),
        (_run_settings_reload_listener, "settings_reload_listener"),
    ]

    if settings.performance_enabled:
        from pipeline.datausage.performance_orchestrator import start_performance_monitoring
        from pipeline.datausage.performance_watcher import start_performance_watcher
        # Note: run_performance_poller is NOT started separately because
        # start_performance_monitoring already polls metrics inside its cycle.
        # Starting both would cause duplicate ES queries and cursor state confusion.
        task_definitions.append((start_performance_monitoring, "performance_monitoring"))
        task_definitions.append((start_performance_watcher, "performance_watcher"))

    # Start watchdog for monitoring
    watchdog_task = asyncio.create_task(_run_watchdog())

    # For the API server, run it directly without safe wrapper (it needs to block)
    # Run in a separate task that we don't await directly
    api_task = asyncio.create_task(_run_response_api())

    # Start other tasks with safe wrapper
    running_tasks = []
    for coro_func, task_name in task_definitions:
        task = asyncio.create_task(_run_safe_task(coro_func, task_name, shutdown_event=_shutdown_event))
        running_tasks.append(task)
        logger.info("task_started", task=task_name)

    logger.info(
        "all_services_started",
        api_url=f"http://0.0.0.0:{settings.backend_port}",
        docs_url=f"http://0.0.0.0:{settings.backend_port}/docs",
    )

    try:
        # Wait for shutdown event instead of gathering forever
        await _shutdown_event.wait()
        logger.info("backend_shutdown_event_triggered")
    except KeyboardInterrupt:
        logger.info("backend_interrupted_by_user")
    except Exception as e:
        logger.error("backend_fatal_error", error=str(e), exc_info=True)
    finally:
        logger.info("backend_shutting_down")
        
        # Persist state before cancelling tasks
        await _persist_state_on_shutdown()
        
        for task in running_tasks:
            task.cancel()
        api_task.cancel()
        watchdog_task.cancel()
        
        # Give tasks a moment to cancel gracefully
        await asyncio.sleep(0.5)
        
        if settings.upstream_enabled:
            await dashboard_monitor.stop_background_monitor()
            await health_monitor.stop_background_check()
        try:
            from pipeline.datausage.ticketing.store import ticket_store
            ticket_store.close()
        except Exception:
            pass
        await close_es_client()
        await close_redis_client()
        logger.info("backend_shutdown_complete")


if __name__ == "__main__":
    asyncio.run(main())
