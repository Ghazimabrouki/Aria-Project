import uuid
import json
from datetime import datetime, timezone
from typing import Optional

import structlog
from sqlalchemy import insert, select

from response.db import AsyncSessionLocal
from response.models import Investigation, InvestigationAlert

logger = structlog.get_logger()


async def _create_investigation(incident: dict, context: dict, alerts: list[dict] = None) -> Optional[str]:
    """Create an Investigation record in our DB and return its ID."""
    from sqlalchemy import insert
    from config import get_settings
    settings = get_settings()

    # Determine investigation type from alerts
    investigation_type = "security"
    resource_type = None
    resource_context_json = None
    status = "pending"
    source = "general"
    diagnostic_started_at = None

    if alerts:
        for alert in alerts:
            alert_investigation_type = alert.get("investigation_type")
            if alert_investigation_type == "runtime":
                investigation_type = "runtime"
                resource_type = alert.get("runtime_category")
                resource_context_json = alert.get("runtime_context")
                status = "diagnosing"
                source = "falco"
                diagnostic_started_at = datetime.now(timezone.utc)
                break
            elif alert.get("source") == "performance":
                investigation_type = "infrastructure"
                resource_type = alert.get("resource_type")
                status = "diagnosing"
                source = "performance"
                diagnostic_started_at = datetime.now(timezone.utc)
                break

    # Extract target host from context - priority order:
    # 1. First hostname from alerts (most specific)
    # 2. First destination IP from alerts
    # 3. First source IP from alerts (last resort)
    # 4. Ansible remote host from settings
    # 5. "localhost" as ultimate fallback
    target_host = None
    if context.get("hostnames"):
        target_host = context["hostnames"][0]
    elif context.get("dest_ips"):
        target_host = context["dest_ips"][0]
    elif context.get("source_ips"):
        target_host = context["source_ips"][0]

    # Final fallback to ansible_remote_host if nothing extracted
    if not target_host:
        target_host = settings.ansible_remote_host

    # Ultimate fallback
    if not target_host:
        target_host = "localhost"

    # Extract target user from context
    # Priority: context.usernames[0] (first affected user) -> settings.ansible_remote_user -> "root"
    target_user = None
    if context.get("usernames"):
        # Use first username as target user (most likely the affected account)
        target_user = context["usernames"][0]
    if not target_user:
        target_user = settings.ansible_remote_user or "root"

    # Extract primary source IP for source tracking
    source_ips = context.get("source_ips", [])
    source_ip = source_ips[0] if source_ips else None

    inv_id = str(uuid.uuid4())
    incident_id = incident.get("id")
    local_incident_id = incident.get("local_incident_id")
    upstream_incident_id = incident.get("upstream_incident_id")
    if not local_incident_id and not upstream_incident_id:
        # In local-only mode the incident id is the local DB id. Upstream watcher
        # passes upstream incident ids and _upsert_local_incident_from_upstream
        # fills local shadow records separately.
        if incident.get("external_id"):
            local_incident_id = incident.get("id")
            upstream_incident_id = incident.get("external_id")
            incident_id = upstream_incident_id
        else:
            local_incident_id = incident_id

    async with AsyncSessionLocal() as session:
        await session.execute(
            insert(Investigation).values(
                id=inv_id,
                incident_id=incident_id,
                local_incident_id=local_incident_id,
                upstream_incident_id=upstream_incident_id,
                incident_title=incident.get("title", ""),
                incident_severity=incident.get("severity", "medium"),
                incident_status=incident.get("status", "open"),
                status=status,
                source=source,
                investigation_type=investigation_type,
                resource_type=resource_type,
                resource_context_json=resource_context_json,
                ai_summary=None,
                ai_narrative=None,
                ai_risk=None,
                playbook_yaml=None,
                playbook_valid=False,
                target_host=target_host,
                target_user=target_user,
                source_ips=source_ip,
                hostnames=",".join(context.get("hostnames", [])) if context.get("hostnames") else None,
                mitre_tactics=",".join(context.get("mitre_tactics", [])) if context.get("mitre_tactics") else None,
                ai_error=None,
                diagnostic_started_at=diagnostic_started_at,
                asset_id=incident.get("asset_id"),
                created_at=datetime.now(timezone.utc),
            )
        )
        await session.commit()

    # For runtime investigations, generate diagnostic playbook and trigger pipeline
    if investigation_type == "runtime" and resource_context_json:
        try:
            from response.runtime_ai_engine.playbook_generator import generate_runtime_diagnostic_playbook
            playbook_yaml = generate_runtime_diagnostic_playbook(
                runtime_context=resource_context_json,
                host=target_host,
                target_user=target_user,
            )
            # Update investigation with playbook
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(Investigation).where(Investigation.id == inv_id)
                )
                inv = result.scalar_one_or_none()
                if inv:
                    inv.playbook_yaml = playbook_yaml
                    inv.playbook_valid = True
                    await session.commit()
        except Exception as e:
            logger.error("runtime_diagnostic_playbook_generation_failed", investigation_id=inv_id, error=str(e))

        import asyncio
        from pipeline.datausage.performance_orchestrator import _run_diagnostic_pipeline
        asyncio.create_task(_run_diagnostic_pipeline(inv_id, resource_context_json))

    return inv_id


async def _store_alerts(investigation_id: str, alerts: list[dict]):
    """Store alert snapshots in InvestigationAlert table."""
    from sqlalchemy import insert
    async with AsyncSessionLocal() as session:
        for alert in alerts:
            alert_json_str = json.dumps(alert)
            await session.execute(
                insert(InvestigationAlert).values(
                    id=str(uuid.uuid4()),
                    investigation_id=investigation_id,
                    alert_id=alert.get("id", ""),
                    alert_json=alert_json_str,
                    severity=alert.get("severity", "medium"),
                    source=alert.get("source", {}).get("name", "unknown") if isinstance(alert.get("source"), dict) else str(alert.get("source", "")),
                    title=alert.get("title", ""),
                )
            )
        await session.commit()
    logger.info("alerts_stored", investigation_id=investigation_id, count=len(alerts))


async def _upsert_local_incident_from_upstream(incident: dict, alerts: list[dict]) -> Optional[str]:
    """Create or update a local Incident shadow record from upstream OpenSOAR incident data."""
    from sqlalchemy import select, insert, update
    from response.db import AsyncSessionLocal
    from response.models import Incident, AlertIncidentLink
    from datetime import datetime, timezone

    upstream_id = incident.get("id")
    if not upstream_id:
        return None

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Incident).where(Incident.external_id == upstream_id)
            )
            existing = result.scalar_one_or_none()

            source_ips = list({a.get("source_ip") for a in alerts if a.get("source_ip")})
            alert_ids = [a.get("id") for a in alerts if a.get("id")]

            # Check if any source_ip is whitelisted
            incident_whitelisted = False
            try:
                from core.whitelist import is_whitelisted
                for ip in source_ips:
                    if ip and await is_whitelisted(ip):
                        incident_whitelisted = True
                        break
            except Exception:
                pass

            # Derive tags from alerts if not present upstream
            upstream_tags = incident.get("tags") or []
            if not upstream_tags:
                tag_set = set()
                for a in alerts:
                    src = a.get("source", "")
                    if isinstance(src, dict):
                        src = src.get("name", "")
                    if src:
                        tag_set.add(f"source-{src}")
                    sev = a.get("severity", "")
                    if sev:
                        tag_set.add(f"severity-{sev}")
                upstream_tags = sorted(list(tag_set))

            if existing:
                local_id = existing.id
                # Merge alert IDs
                merged_alert_ids = list(set((existing.alert_ids or []) + alert_ids))
                # Merge tags
                merged_tags = list(set((existing.tags or []) + upstream_tags))
                await session.execute(
                    update(Incident)
                    .where(Incident.id == local_id)
                    .values(
                        title=incident.get("title", existing.title),
                        description=incident.get("description", existing.description),
                        severity=incident.get("severity", existing.severity),
                        status=incident.get("status", existing.status),
                        source_ips=source_ips or existing.source_ips,
                        alert_ids=merged_alert_ids,
                        tags=merged_tags,
                        whitelisted=incident_whitelisted or existing.whitelisted,
                        updated_at=datetime.now(timezone.utc),
                    )
                )
            else:
                import uuid
                local_id = str(uuid.uuid4())
                await session.execute(
                    insert(Incident).values(
                        id=local_id,
                        external_id=upstream_id,
                        title=incident.get("title", ""),
                        description=incident.get("description", ""),
                        severity=incident.get("severity", "medium"),
                        status=incident.get("status", "open"),
                        source_ips=source_ips if source_ips else None,
                        alert_ids=alert_ids if alert_ids else None,
                        tags=upstream_tags or None,
                        whitelisted=incident_whitelisted,
                        created_at=datetime.now(timezone.utc),
                        updated_at=datetime.now(timezone.utc),
                    )
                )

            # Create alert links — resolve upstream alert IDs to local Alert.id first
            from response.models import Alert
            for alert in alerts:
                upstream_alert_id = alert.get("id")
                if not upstream_alert_id:
                    continue
                # Try to find local alert by external_id
                local_alert_result = await session.execute(
                    select(Alert.id).where(Alert.external_id == upstream_alert_id)
                )
                local_alert_id = local_alert_result.scalar_one_or_none()
                if not local_alert_id:
                    continue  # Local alert shadow doesn't exist yet
                try:
                    await session.execute(
                        insert(AlertIncidentLink).values(
                            alert_id=local_alert_id,
                            incident_id=local_id,
                            correlation_confidence="medium",
                            correlation_reason="linked via watcher from upstream incident",
                            linked_at=datetime.now(timezone.utc),
                        )
                    )
                except Exception:
                    pass  # Already linked

            await session.commit()
            return local_id
    except Exception as e:
        logger.warning("upsert_local_incident_failed", upstream_id=upstream_id, error=str(e)[:100])
        return None


async def _get_known_incident_ids() -> set[str]:
    """Return set of incident_ids already in our DB.
    
    Checks BOTH Investigation table and Incident table to avoid creating
    duplicate investigations for incidents that were created locally by
    the incident_manager but never got an investigation.
    """
    from sqlalchemy import select
    from response.models import Incident
    async with AsyncSessionLocal() as session:
        # Known from investigations
        inv_result = await session.execute(select(Investigation.incident_id))
        known = {row[0] for row in inv_result.all() if row[0]}
        
        # Also known from local Incident shadows (external_id = upstream incident ID)
        inc_result = await session.execute(select(Incident.external_id))
        for row in inc_result.all():
            if row[0]:
                known.add(row[0])
        
        # Also known from local Incident IDs (for local-only mode)
        inc_id_result = await session.execute(select(Incident.id))
        for row in inc_id_result.all():
            if row[0]:
                known.add(row[0])
        
        return known


async def _refresh_existing_investigations(reader) -> int:
    """Refresh active investigations with new alerts from upstream.
    Returns number of investigations refreshed.
    """
    from sqlalchemy import select, update, func
    from response.db import AsyncSessionLocal
    from response.models import Investigation, InvestigationAlert
    from response.watcher.context_builder import _build_investigation_context
    from response.watcher.ai_runner import _run_ai_engine
    import asyncio

    refreshed = 0
    try:
        async with AsyncSessionLocal() as session:
            # Get active investigations (not terminal states)
            result = await session.execute(
                select(Investigation)
                .where(Investigation.status.in_([
                    "pending", "awaiting_approval", "approved", "running"
                ]))
                .order_by(Investigation.updated_at.asc())
                .limit(20)
            )
            investigations = result.scalars().all()

            for inv in investigations:
                try:
                    # Fetch current upstream alerts
                    alerts_raw = await reader.get_incident_alerts(inv.incident_id)
                    if not alerts_raw:
                        continue

                    # Get currently stored alert IDs
                    stored_result = await session.execute(
                        select(InvestigationAlert.alert_id)
                        .where(InvestigationAlert.investigation_id == inv.id)
                    )
                    stored_ids = {row[0] for row in stored_result.all()}

                    # Find new alerts
                    new_alerts = []
                    current_alert_ids = []
                    for a in alerts_raw:
                        alert_id = a.get("id") if isinstance(a, dict) else a
                        if alert_id:
                            current_alert_ids.append(alert_id)
                            if alert_id not in stored_ids:
                                full = await reader.get_alert(str(alert_id))
                                if full:
                                    new_alerts.append(full)

                    if not new_alerts:
                        continue  # No new alerts

                    # Filter out whitelisted alerts
                    try:
                        from core.whitelist import is_whitelisted
                        filtered_new_alerts = []
                        for alert in new_alerts:
                            src = alert.get("source_ip", "")
                            dst = alert.get("dest_ip", "")
                            if (src and await is_whitelisted(src)) or (dst and await is_whitelisted(dst)):
                                continue
                            filtered_new_alerts.append(alert)
                        new_alerts = filtered_new_alerts
                    except Exception as e:
                        logger.warning("refresh_whitelist_filter_failed", investigation_id=inv.id, error=str(e)[:100])

                    if not new_alerts:
                        continue  # All new alerts were whitelisted

                    # Fetch current upstream incident data for context refresh
                    incident = await reader.get_incident(inv.incident_id)
                    if incident:
                        # Update local incident shadow with merged alert IDs
                        await _upsert_local_incident_from_upstream(incident, alerts_raw)

                    # Store new alert snapshots
                    await _store_alerts(inv.id, new_alerts)

                    # Update investigation's updated_at timestamp
                    await session.execute(
                        update(Investigation)
                        .where(Investigation.id == inv.id)
                        .values(updated_at=datetime.now(timezone.utc))
                    )
                    await session.commit()

                    # Re-run AI if investigation is still pending and we got significant new alerts
                    if inv.status == "pending" and incident:
                        context = _build_investigation_context(incident, alerts_raw)
                        asyncio.create_task(_run_ai_engine(inv.id, context))

                    refreshed += 1
                    logger.info(
                        "investigation_refreshed",
                        investigation_id=inv.id,
                        incident_id=inv.incident_id,
                        new_alerts=len(new_alerts),
                        total_alerts=len(current_alert_ids),
                    )
                except Exception as e:
                    logger.warning("refresh_investigation_failed", investigation_id=inv.id, error=str(e)[:100])

    except Exception as e:
        logger.warning("refresh_existing_investigations_failed", error=str(e)[:100])

    return refreshed
