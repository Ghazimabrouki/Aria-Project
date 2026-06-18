import asyncio

import structlog

from config import get_settings
from pipeline.sender import OpenSOARClient

from response.watcher.context_builder import _build_investigation_context
from response.watcher.investigation_db import (
    _create_investigation,
    _get_known_incident_ids,
    _store_alerts,
    _upsert_local_incident_from_upstream,
)
from response.watcher.ai_runner import _run_ai_engine, _broadcast_new_investigation
from response.watcher.stuck_recovery import (
    _retry_pending_investigations,
    _execute_approved_investigations,
    _auto_approve_all_pending_investigations,
    _check_stuck_investigations,
    _recover_stuck_running_investigations,
)

logger = structlog.get_logger()
settings = get_settings()


async def _get_local_open_incidents_without_investigations() -> list[dict]:
    """Find local open incidents that don't have an active investigation."""
    from sqlalchemy import select, func
    from response.db import AsyncSessionLocal
    from response.models import Incident, Investigation, AlertIncidentLink, Alert

    incidents = []
    try:
        async with AsyncSessionLocal() as session:
            # Subquery: incidents that have investigations
            subq = select(Investigation.incident_id).where(
                Investigation.incident_id.isnot(None)
            ).distinct()

            # Get open incidents NOT in that subquery
            result = await session.execute(
                select(Incident)
                .where(Incident.status == "open")
                .where(Incident.id.not_in(subq))
                .order_by(Incident.created_at.desc())
                .limit(100)
            )
            for inc in result.scalars().all():
                # Fetch linked alerts
                alert_result = await session.execute(
                    select(Alert)
                    .join(AlertIncidentLink, AlertIncidentLink.alert_id == Alert.id)
                    .where(AlertIncidentLink.incident_id == inc.id)
                )
                linked_alerts = alert_result.scalars().all()

                # Also include alerts from incident.alert_ids if M2M is empty
                alert_dicts = []
                if linked_alerts:
                    for a in linked_alerts:
                        alert_dicts.append({
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
                elif inc.alert_ids:
                    for aid in inc.alert_ids:
                        a = await session.get(Alert, aid)
                        if a:
                            alert_dicts.append({
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

                incidents.append({
                    "id": inc.id,
                    "local_incident_id": inc.id,
                    "upstream_incident_id": inc.external_id,
                    "title": inc.title,
                    "description": inc.description,
                    "severity": inc.severity,
                    "status": inc.status,
                    "source_ips": inc.source_ips,
                    "hostnames": inc.hostnames,
                    "tags": inc.tags,
                    "alert_count": len(alert_dicts),
                    "alerts": alert_dicts,
                    "asset_id": inc.asset_id,
                    "created_at": inc.created_at.isoformat() if inc.created_at else None,
                })
    except Exception as e:
        logger.warning("get_local_incidents_failed", error=str(e)[:100])
    return incidents


async def watch_local_incidents(shutdown_event: asyncio.Event = None):
    """
    Local-only watcher loop. Polls local SQLite for open incidents without investigations.
    """
    logger.info("local_incident_watcher_started", interval=settings.incident_watcher_interval)

    await _retry_pending_investigations()

    cycle_count = 0
    while True:
        if shutdown_event and shutdown_event.is_set():
            logger.info("local_incident_watcher_shutdown_requested")
            break

        cycle_count += 1
        try:
            await _retry_pending_investigations()
            await _execute_approved_investigations()
            await _auto_approve_all_pending_investigations()
            await _check_stuck_investigations()
            await _recover_stuck_running_investigations()

            incidents = await _get_local_open_incidents_without_investigations()
            logger.info("local_watcher_scan", fetched=len(incidents))

            new_count = 0
            _whitelist_cache: dict[str, bool] = {}

            async def _cached_is_whitelisted(value: str) -> bool:
                if value in _whitelist_cache:
                    return _whitelist_cache[value]
                try:
                    from core.whitelist import is_whitelisted
                    result = await is_whitelisted(value)
                    _whitelist_cache[value] = result
                    return result
                except Exception as e:
                    logger.warning("watcher_whitelist_check_failed", value=value, error=str(e)[:100])
                    _whitelist_cache[value] = False
                    return False

            for incident in incidents:
                incident_id = incident["id"]
                full_alerts = incident.get("alerts", [])

                # Skip if any alert IP is whitelisted
                whitelisted = False
                for alert in full_alerts:
                    for field in ("source_ip", "dest_ip"):
                        ip = alert.get(field)
                        if ip and await _cached_is_whitelisted(ip):
                            whitelisted = True
                            break
                    if whitelisted:
                        break
                if whitelisted:
                    logger.info(
                        "watcher_incident_skipped_whitelisted",
                        incident_id=incident_id,
                        alert_count=len(full_alerts),
                    )
                    continue

                if len(full_alerts) < settings.incident_min_alerts:
                    logger.debug(
                        "incident_skipped_too_few_alerts",
                        incident_id=incident_id,
                        alert_count=len(full_alerts),
                        min_required=settings.incident_min_alerts,
                    )
                    continue

                context = _build_investigation_context(incident, full_alerts)
                inv_id = await _create_investigation(incident, context, full_alerts)

                if inv_id:
                    new_count += 1
                    try:
                        from api.websocket import ws_manager
                        await ws_manager.broadcast("investigations", {
                            "type": "incident_created",
                            "incident_id": incident_id,
                            "title": incident.get("title", "Unknown"),
                            "severity": incident.get("severity", "medium"),
                            "investigation_id": inv_id,
                        })
                    except Exception:
                        pass
                    await _broadcast_new_investigation(
                        inv_id,
                        incident.get("title", "Unknown"),
                        incident.get("severity", "medium")
                    )
                    await _store_alerts(inv_id, full_alerts)
                    asyncio.create_task(_run_ai_engine(inv_id, context))

            if new_count > 0:
                logger.info("local_watcher_cycle_complete", new_investigations=new_count)

        except Exception as e:
            logger.error("local_watcher_cycle_error", error=str(e))

        await asyncio.sleep(settings.incident_watcher_interval)


async def watch_incidents(shutdown_event: asyncio.Event = None):
    """
    Main watcher loop. Runs indefinitely, polling OpenSOAR for new incidents.
    Called as a background task from main.py.
    """
    if not settings.upstream_enabled:
        return await watch_local_incidents(shutdown_event=shutdown_event)

    reader = OpenSOARClient()
    logger.info("incident_watcher_started", interval=settings.incident_watcher_interval)

    # Process any stuck pending investigations on startup
    await _retry_pending_investigations()

    cycle_count = 0
    # Every FULL_SCAN_INTERVAL cycles, fetch ALL open incidents.
    # Normal cycles only fetch the most recent page (much cheaper).
    FULL_SCAN_INTERVAL = 60  # 60 * 15s = 15 minutes

    while True:
        if shutdown_event and shutdown_event.is_set():
            logger.info("incident_watcher_shutdown_requested")
            break

        cycle_count += 1
        is_full_scan = cycle_count % FULL_SCAN_INTERVAL == 0

        try:
            # Also retry pending investigations that were never processed
            await _retry_pending_investigations()

            # Execute any approved investigations that haven't run yet
            await _execute_approved_investigations()

            # Auto-approve all pending investigations when blanket mode is on
            await _auto_approve_all_pending_investigations()

            # Check for stuck investigations and alert
            await _check_stuck_investigations()

            # Auto-recover stuck running investigations
            await _recover_stuck_running_investigations()

            # Every 5 cycles (~75s), refresh existing investigations with new alerts
            if cycle_count % 5 == 0:
                from response.watcher.investigation_db import _refresh_existing_investigations
                refreshed = await _refresh_existing_investigations(reader)
                if refreshed > 0:
                    logger.info("watcher_refresh_complete", refreshed=refreshed)

            known_ids = await _get_known_incident_ids()

            if is_full_scan:
                # Full scan: paginate through ALL open incidents
                all_incidents = []
                offset = 0
                limit = 100
                while True:
                    incidents_data = await reader.list_incidents(status="open", limit=limit, offset=offset)
                    incidents = incidents_data.get("incidents", [])
                    total = incidents_data.get("total", 0)

                    if not incidents:
                        break

                    all_incidents.extend(incidents)
                    logger.debug("incident_pagination", offset=offset, fetched=len(incidents), total=total)

                    if len(all_incidents) >= total:
                        break
                    offset += limit

                    # Safety limit to prevent infinite loops
                    if offset > 1000:
                        logger.warning("incident_pagination_limit_reached", offset=offset)
                        break

                incidents = all_incidents
                logger.info("watcher_full_scan", total=len(incidents), known=len(known_ids))
            else:
                # Fast path: only fetch most recent 50 open incidents.
                # New/updated incidents are almost always in this set.
                incidents_data = await reader.list_incidents(status="open", limit=50, offset=0)
                incidents = incidents_data.get("incidents", [])
                logger.info("watcher_fast_scan", fetched=len(incidents), known=len(known_ids))

            new_count = 0

            # In-memory cache for whitelist checks during this cycle
            _whitelist_cache: dict[str, bool] = {}

            async def _cached_is_whitelisted(value: str) -> bool:
                if value in _whitelist_cache:
                    return _whitelist_cache[value]
                try:
                    from core.whitelist import is_whitelisted
                    result = await is_whitelisted(value)
                    _whitelist_cache[value] = result
                    return result
                except Exception as e:
                    logger.warning("watcher_whitelist_check_failed", value=value, error=str(e)[:100])
                    _whitelist_cache[value] = False
                    return False

            for incident in incidents:
                incident_id = incident.get("id")
                logger.debug("checking_incident", incident_id=incident_id, in_db=incident_id in known_ids)
                if not incident_id or incident_id in known_ids:
                    continue

                # Fetch full alert details FIRST — upstream alert_count can lie
                linked_alerts_raw = await reader.get_incident_alerts(incident_id)
                full_alerts = []
                for a in linked_alerts_raw:
                    alert_id = a.get("id") if isinstance(a, dict) else a
                    if alert_id:
                        full = await reader.get_alert(str(alert_id))
                        if full:
                            full_alerts.append(full)

                # Skip if any alert IP is whitelisted
                whitelisted = False
                for alert in full_alerts:
                    for field in ("source_ip", "dest_ip"):
                        ip = alert.get(field)
                        if ip and await _cached_is_whitelisted(ip):
                            whitelisted = True
                            break
                    if whitelisted:
                        break
                if whitelisted:
                    logger.info(
                        "watcher_incident_skipped_whitelisted",
                        incident_id=incident_id,
                        alert_count=len(full_alerts),
                    )
                    continue

                # Use ACTUAL fetched alert count, not upstream's potentially stale count
                if len(full_alerts) < settings.incident_min_alerts:
                    logger.debug(
                        "incident_skipped_too_few_alerts",
                        incident_id=incident_id,
                        alert_count=len(full_alerts),
                        upstream_reported=incident.get("alert_count", 0),
                        min_required=settings.incident_min_alerts,
                    )
                    continue

                context = _build_investigation_context(incident, full_alerts)

                # Ensure local Incident shadow record exists
                local_incident_id = await _upsert_local_incident_from_upstream(incident, full_alerts)
                if local_incident_id:
                    incident = {
                        **incident,
                        "local_incident_id": local_incident_id,
                        "upstream_incident_id": incident_id,
                    }

                inv_id = await _create_investigation(incident, context)

                if inv_id:
                    new_count += 1
                    # Broadcast new incident created
                    try:
                        from api.websocket import ws_manager
                        await ws_manager.broadcast("investigations", {
                            "type": "incident_created",
                            "incident_id": incident_id,
                            "title": incident.get("title", "Unknown"),
                            "severity": incident.get("severity", "medium"),
                            "investigation_id": inv_id,
                        })
                    except Exception:
                        pass
                    # Broadcast new investigation created
                    await _broadcast_new_investigation(
                        inv_id,
                        incident.get("title", "Unknown"),
                        incident.get("severity", "medium")
                    )
                    # Store alerts in InvestigationAlert table
                    await _store_alerts(inv_id, full_alerts)
                    # Run AI engine as background task (semaphore controls concurrency)
                    asyncio.create_task(_run_ai_engine(inv_id, context))

            if new_count > 0:
                logger.info("watcher_cycle_complete", new_investigations=new_count)

        except Exception as e:
            logger.error("watcher_cycle_error", error=str(e))

        await asyncio.sleep(settings.incident_watcher_interval)
