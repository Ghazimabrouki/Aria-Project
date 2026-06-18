import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Callable

import structlog
from config import get_settings
from pipeline.sender import client
from pipeline.services.dedup import is_duplicate, _is_threat_intel, generate_dedup_key
from pipeline.services.correlator import track_alert
from pipeline.services.noise_learner import track_alert_for_noise, is_auto_noise
from pipeline.enrichment.geoip import enrich_alert
from core.whitelist import check_alert_whitelist
from pipeline.poller.pattern_tracker import (
    _get_pattern_key,
    _load_pattern_tracking,
    _PATTERN_TRACKING,
    _save_pattern_tracking,
    _handle_repeated_alert,
    _THREAT_INTEL_IPS,
)

logger = structlog.get_logger()
SEVERITY_ORDER = {"info": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}

# Event bucketing: collapse repeated identical alerts within time window
_EVENT_BUCKETS: dict = {}
_BUCKET_WINDOW_SECONDS = 300  # 5 minutes


def _get_bucket_key(payload: dict) -> str:
    """Generate a bucket key for event deduplication."""
    source = payload.get("source", "unknown")
    parts = [
        source,
        payload.get("rule_name", "") or payload.get("title", "") or "",
        payload.get("source_ip", "") or "",
        payload.get("dest_ip", "") or "",
        payload.get("severity", "medium"),
    ]
    # For Falco, include container and target context to avoid collapsing distinct events
    if source == "falco":
        meta = payload.get("metadata", {}) or {}
        container_id = meta.get("container_id") or meta.get("container", {}).get("id", "")
        proc_name = payload.get("proc_name", "")
        fd_name = payload.get("fd_name", "")
        parts.extend([container_id, proc_name, fd_name])
    return "|".join(parts)


def _check_bucket(payload: dict) -> int:
    """Check if alert matches a recent bucket. Returns event count (1 = new, >1 = repeat)."""
    from time import time
    now = time()
    key = _get_bucket_key(payload)
    
    # Clean expired buckets
    expired = [k for k, v in _EVENT_BUCKETS.items() if now - v["ts"] > _BUCKET_WINDOW_SECONDS]
    for k in expired:
        del _EVENT_BUCKETS[k]
    
    if key in _EVENT_BUCKETS:
        _EVENT_BUCKETS[key]["count"] += 1
        _EVENT_BUCKETS[key]["ts"] = now
        return _EVENT_BUCKETS[key]["count"]
    
    _EVENT_BUCKETS[key] = {"count": 1, "ts": now}
    return 1


@dataclass
class ProcessResult:
    latest_ts: datetime
    sent: int = 0
    skipped: int = 0
    duplicates: int = 0
    dedup_skipped: int = 0
    map_errors: int = 0
    forward_errors: int = 0
    grouped: int = 0


def _advance_timestamp(source_doc: dict, latest_ts: datetime) -> datetime:
    ts_str = source_doc.get("@timestamp") or source_doc.get("timestamp")
    if ts_str:
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts > latest_ts:
                return ts
        except ValueError:
            pass
    return latest_ts


def _build_clean_payload(es_id: str, source_doc: dict, mapped: bool, payload: dict) -> dict:
    """
    Build clean payload for OpenSOAR.
    Removes ES-specific metadata, sends ONLY normalized data.
    """
    clean = dict(payload)
    if "source_id" not in clean:
        clean["source_id"] = es_id
    if "event_time" not in clean:
        ts = source_doc.get("@timestamp") or source_doc.get("timestamp")
        if ts:
            clean["event_time"] = str(ts)
    return clean


async def _update_alert_external_id(local_alert_id: str, upstream_alert_id: str) -> None:
    """Update local alert with upstream OpenSOAR alert ID."""
    try:
        from response.db import AsyncSessionLocal
        from response.models import Alert
        from sqlalchemy import update
        async with AsyncSessionLocal() as session:
            await session.execute(
                update(Alert).where(Alert.id == local_alert_id).values(external_id=upstream_alert_id)
            )
            await session.commit()
            logger.debug("alert_external_id_updated", local_id=local_alert_id, upstream_id=upstream_alert_id)
    except Exception as e:
        logger.warning("alert_external_id_update_failed", local_id=local_alert_id, error=str(e))


async def _process_alert_data_usage(local_alert_id: str, alert_data: dict, upstream_alert_id: str = None) -> None:
    """Process alert through the full data usage pipeline (observables, AI, incidents, tickets, playbooks, actions)."""
    try:
        from pipeline.datausage.orchestrator import process_alert
        await process_alert(local_alert_id, alert_data, upstream_alert_id)
    except Exception as e:
        logger.error("data_usage_processing_failed", local_alert_id=local_alert_id, upstream_alert_id=upstream_alert_id, error=str(e))


async def _persist_alert_local(source: str, es_id: str, payload: dict, raw_source: Optional[dict] = None) -> Optional[str]:
    """Persist alert to local shadow DB. Returns the local alert ID."""
    try:
        from datetime import datetime, timezone
        from sqlalchemy import select
        from response.db import AsyncSessionLocal
        from response.models import Alert
        from pipeline.enrichment.geoip import enrich_ip

        # Mapper may have corrected the source (e.g. filebeat→suricata)
        actual_source = payload.get("source", source)

        dedup_key = generate_dedup_key(actual_source, payload)
        event_time = payload.get("event_time")
        if event_time:
            try:
                event_time = datetime.fromisoformat(str(event_time).replace("Z", "+00:00"))
            except ValueError:
                event_time = None

        # Phase 3: Pre-compute geo for IPS dashboard (MaxMind only, fast)
        meta = payload.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        src_ip = payload.get("source_ip")
        if src_ip:
            geo = enrich_ip(src_ip)
            if geo and not geo.get("is_private") and geo.get("lat") is not None:
                meta["_geo"] = meta.get("_geo", {})
                meta["_geo"]["source"] = {
                    "country_code": geo.get("country", ""),
                    "country_name": geo.get("country_name", ""),
                    "city": geo.get("city", ""),
                    "region": "",
                    "latitude": float(geo["lat"]),
                    "longitude": float(geo["lon"]),
                }
        dst_ip = payload.get("dest_ip")
        if dst_ip:
            geo = enrich_ip(dst_ip)
            if geo and not geo.get("is_private") and geo.get("lat") is not None:
                meta["_geo"] = meta.get("_geo", {})
                meta["_geo"]["dest"] = {
                    "country_code": geo.get("country", ""),
                    "country_name": geo.get("country_name", ""),
                    "city": geo.get("city", ""),
                    "region": "",
                    "latitude": float(geo["lat"]),
                    "longitude": float(geo["lon"]),
                }

        async with AsyncSessionLocal() as session:
            # Check for existing alert by source + source_id to prevent duplicates
            existing = await session.execute(
                select(Alert.id).where(
                    Alert.source == actual_source,
                    Alert.source_id == es_id,
                ).limit(1)
            )
            if existing.scalar_one_or_none():
                logger.debug("alert_already_exists_local", source=actual_source, es_id=es_id)
                return None

            # Resolve asset_id from hint if multi-server is enabled
            asset_id = None
            from config import get_settings
            settings = get_settings()
            if settings.multi_server_enabled:
                from core.asset_scope import resolve_asset_from_hostname
                hint = payload.get("asset_id_hint", "")
                if hint:
                    try:
                        asset_id = await resolve_asset_from_hostname(
                            hostname=hint,
                            agent_name=meta.get("agent_name") or meta.get("wazuh_agent_name"),
                            agent_id=meta.get("wazuh_agent_id"),
                            session=session,
                        )
                    except Exception:
                        pass

            alert = Alert(
                external_id=payload.get("id"),
                source=actual_source,
                source_id=es_id,
                title=payload.get("title", ""),
                description=payload.get("description", ""),
                severity=payload.get("severity", "low"),
                status="active",
                category=payload.get("category") or meta.get("category", "other"),
                source_ip=src_ip or None,
                dest_ip=dst_ip or None,
                hostname=payload.get("hostname") or None,
                rule_name=payload.get("rule_name") or None,
                tags=payload.get("tags"),
                iocs=payload.get("iocs"),
                observables=payload.get("observables"),
                alert_metadata=meta,
                event_time=event_time,
                dedup_key=dedup_key,
                whitelisted=payload.get("whitelisted", False),
                raw_source_json=json.dumps(raw_source) if raw_source else None,
                asset_id=asset_id,
            )
            session.add(alert)
            await session.commit()
            await session.refresh(alert)
            # Inject asset_id back into downstream payload so incident/investigation
            # creation inherits ownership.
            payload["asset_id"] = asset_id
            logger.debug("alert_persisted_local", alert_id=alert.id, source=actual_source, es_id=es_id, asset_id=asset_id)
            return alert.id
    except Exception as e:
        logger.warning("alert_persist_local_failed", source=source, es_id=es_id, error=str(e))
        return None


async def _link_suricata_to_wazuh(local_alert_id: Optional[str], source: str, payload: dict) -> None:
    """If this is a Suricata alert, try to link it to a recent Wazuh alert by source_ip."""
    if not local_alert_id or source not in ("suricata", "filebeat"):
        return
    try:
        from datetime import datetime, timezone, timedelta
        from sqlalchemy import select
        from response.db import AsyncSessionLocal
        from response.models import Alert

        src_ip = payload.get("source_ip")
        if not src_ip:
            return

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Alert.id, Alert.title)
                .where(
                    Alert.source == "wazuh",
                    Alert.source_ip == src_ip,
                    Alert.created_at >= cutoff,
                )
                .order_by(Alert.created_at.desc())
                .limit(1)
            )
            wazuh_alert = result.first()
            if wazuh_alert:
                metadata = payload.get("metadata") or {}
                metadata["correlated_wazuh_alert_id"] = wazuh_alert.id
                metadata["correlated_wazuh_alert_title"] = wazuh_alert.title
                payload["metadata"] = metadata
                # Update local DB record
                alert = await session.get(Alert, local_alert_id)
                if alert:
                    meta = dict(alert.alert_metadata or {})
                    meta["correlated_wazuh_alert_id"] = wazuh_alert.id
                    meta["correlated_wazuh_alert_title"] = wazuh_alert.title
                    alert.alert_metadata = meta
                    await session.commit()
                logger.debug(
                    "suricata_wazuh_linked",
                    suricata_alert_id=local_alert_id,
                    wazuh_alert_id=wazuh_alert.id,
                    source_ip=src_ip,
                )
    except Exception as e:
        logger.debug("suricata_wazuh_link_failed", error=str(e))


async def process_single_alert(
    es_id: str,
    source_doc: dict,
    source: str,
    mapper: Optional[Callable[[dict], dict]],
    latest_ts: datetime,
) -> ProcessResult:
    settings = get_settings()

    # --- Map to structured OpenSOAR format ---
    mapped = False
    payload = source_doc
    if mapper:
        try:
            payload = mapper(source_doc)
            mapped = True
        except ValueError as e:
            error_str = str(e)
            if "not" in error_str.lower() or "wrong" in error_str.lower():
                logger.warning(
                    "alert_source_validation_failed",
                    source=source,
                    es_id=es_id,
                    reason=error_str,
                )
            else:
                logger.debug(
                    "alert_filtered",
                    source=source,
                    es_id=es_id,
                    reason=error_str,
                )
            return ProcessResult(latest_ts=_advance_timestamp(source_doc, latest_ts), skipped=1)
        except Exception as e:
            logger.warning(
                "mapping_error",
                source=source,
                es_id=es_id,
                error=str(e),
                doc_keys=list(source_doc.keys())[:5],
            )
            return ProcessResult(latest_ts=latest_ts, map_errors=1)

    # --- Set source_id if not set ---
    if not payload.get("source_id"):
        payload["source_id"] = es_id

    # --- Source-specific deduplication ---
    try:
        if await is_duplicate(source, payload):
            logger.debug(
                "alert_dedup_skipped",
                source=source,
                es_id=es_id,
                title=payload.get("title", "")[:50],
            )
            return ProcessResult(latest_ts=_advance_timestamp(source_doc, latest_ts), dedup_skipped=1)
    except Exception as e:
        logger.warning("dedup_check_failed", source=source, es_id=es_id, error=str(e))

    # --- Track alert for noise learning ---
    track_alert_for_noise(payload)

    # --- Check auto-learned noise rules ---
    if is_auto_noise(payload):
        logger.debug(
            "alert_skipped_auto_noise",
            es_id=es_id,
            source=source,
            title=payload.get("title", "")[:50],
        )
        return ProcessResult(latest_ts=_advance_timestamp(source_doc, latest_ts), skipped=1)

    # --- Severity filtering ---
    alert_severity = payload.get("severity", "low")
    min_severity = settings.alert_min_severity

    if SEVERITY_ORDER.get(alert_severity, 0) < SEVERITY_ORDER.get(min_severity, 0):
        logger.debug(
            "alert_skipped_severity",
            es_id=es_id,
            source=source,
            severity=alert_severity,
            min_required=min_severity,
        )
        return ProcessResult(latest_ts=_advance_timestamp(source_doc, latest_ts), skipped=1)

    # --- Build clean payload (no ES metadata) ---
    clean_payload = _build_clean_payload(es_id, source_doc, mapped, payload)

    # --- Event bucketing: collapse repeated identical alerts ---
    event_count = _check_bucket(clean_payload)
    clean_payload.setdefault("metadata", {})
    clean_payload["metadata"]["event_count"] = event_count
    if event_count > 1:
        logger.debug(
            "alert_bucketed",
            source=source,
            es_id=es_id,
            title=clean_payload.get("title", "")[:50],
            event_count=event_count,
        )
        # For buckets beyond the first, we still process for correlation
        # but mark as a repeat so downstream can weight accordingly
        clean_payload["metadata"]["bucketed"] = True

    # --- Track threat intel IPs for context (metadata only, don't inflate description) ---
    if _is_threat_intel(clean_payload):
        rule = clean_payload.get("rule_name", "") or clean_payload.get("title", "")
        src_ip = clean_payload.get("source_ip", "")
        if rule:
            if rule not in _THREAT_INTEL_IPS:
                _THREAT_INTEL_IPS[rule] = set()
            _THREAT_INTEL_IPS[rule].add(src_ip)
            ip_count = len(_THREAT_INTEL_IPS[rule])
            # Store context in metadata instead of polluting the description
            clean_payload.setdefault("metadata", {})
            clean_payload["metadata"]["threat_intel_unique_ips"] = ip_count
            clean_payload["metadata"]["threat_intel_rule"] = rule

    # --- Enrich with IP metadata ---
    clean_payload = enrich_alert(clean_payload)

    # --- Campaign detection ---
    campaign_ctx = track_alert(clean_payload)
    if campaign_ctx:
        # Store campaign context in metadata instead of inflating the description
        clean_payload.setdefault("metadata", {})
        clean_payload["metadata"]["campaign_context"] = campaign_ctx

    # --- Check whitelist ---
    try:
        if await check_alert_whitelist(clean_payload):
            clean_payload["whitelisted"] = True
    except Exception as e:
        logger.warning("whitelist_check_failed", source=source, es_id=es_id, error=str(e))

    # --- Persist to local shadow DB ---
    local_alert_id = await _persist_alert_local(source, es_id, clean_payload, raw_source=source_doc)
    if local_alert_id:
        clean_payload["local_alert_id"] = local_alert_id

    # --- Link Suricata to Wazuh if possible ---
    await _link_suricata_to_wazuh(local_alert_id, source, clean_payload)

    # --- Forward to OpenSOAR ---
    pattern_key = _get_pattern_key(
        source,
        clean_payload.get("source_ip", ""),
        clean_payload.get("rule_name", "") or clean_payload.get("title", ""),
    )

    _load_pattern_tracking()
    existing_tracking = _PATTERN_TRACKING.get(pattern_key)

    if existing_tracking and existing_tracking.get("alert_id"):
        # Update existing alert with occurrence count
        await _handle_repeated_alert(existing_tracking["alert_id"], clean_payload, existing_tracking)
        logger.info(
            "alert_grouped",
            source=source,
            title=clean_payload.get("title", "Untitled Alert")[:80],
            pattern_key=pattern_key,
            occurrence_count=existing_tracking.get("occurrence_count", 1) + 1,
        )
        _PATTERN_TRACKING[pattern_key]["occurrence_count"] = existing_tracking.get("occurrence_count", 1) + 1
        _PATTERN_TRACKING[pattern_key]["last_seen"] = datetime.now(timezone.utc).isoformat()
        _save_pattern_tracking()
        # Grouped/pattern-matched alerts are not newly forwarded; they update an existing alert.
        # Use grouped=1 instead of inflating sent count.
        return ProcessResult(latest_ts=_advance_timestamp(source_doc, latest_ts), sent=0, grouped=1)
    else:
        alert_id = None
        upstream_sent = False

        if settings.upstream_enabled:
            # Forward to upstream OpenSOAR
            for retry_attempt in range(3):
                try:
                    result = await client.send_alert(clean_payload)

                    if isinstance(result, dict) and result.get("status") == "already_exists":
                        logger.debug("alert_duplicate_opensoar", es_id=es_id, source=source)
                        existing_alert_id = result.get("alert_id", "")
                        if local_alert_id and existing_alert_id:
                            asyncio.create_task(_update_alert_external_id(local_alert_id, existing_alert_id))
                        alert_id = existing_alert_id
                        upstream_sent = True
                        break
                    else:
                        alert_id = result.get("alert_id", "") if isinstance(result, dict) else ""
                        logger.info(
                            "alert_forwarded",
                            es_id=es_id,
                            source=source,
                            title=clean_payload.get("title", "Untitled Alert")[:80],
                            severity=clean_payload.get("severity", "unknown"),
                        )

                        if local_alert_id and alert_id:
                            asyncio.create_task(_update_alert_external_id(local_alert_id, alert_id))

                        upstream_sent = True
                        break

                except Exception as e:
                    if retry_attempt < 2:
                        logger.debug(
                            "forward_retry",
                            es_id=es_id,
                            source=source,
                            attempt=retry_attempt + 1,
                            error=str(e)[:100],
                        )
                        await asyncio.sleep(0.5 * (2 ** retry_attempt))
                        continue
                    else:
                        logger.error(
                            "forward_failed",
                            es_id=es_id,
                            source=source,
                            attempts=3,
                            error=str(e)[:100],
                        )

                        try:
                            from pipeline.retry_queue import retry_queue
                            await retry_queue.add(clean_payload, str(e), retry_count=0)
                        except Exception as queue_err:
                            logger.warning("retry_queue_add_error", error=str(queue_err))

                        return ProcessResult(latest_ts=_advance_timestamp(source_doc, latest_ts), forward_errors=1)
        else:
            logger.debug("upstream_disabled_alert_persisted_locally", es_id=es_id, source=source)

        # Track pattern locally (works whether upstream is enabled or not)
        _PATTERN_TRACKING[pattern_key] = {
            "alert_id": alert_id or local_alert_id or es_id,
            "source_ip": clean_payload.get("source_ip", ""),
            "rule_name": clean_payload.get("rule_name", "") or clean_payload.get("title", ""),
            "occurrence_count": 1,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
        }
        _save_pattern_tracking()

        # Always run local data-usage pipeline
        if local_alert_id:
            asyncio.create_task(_process_alert_data_usage(local_alert_id, clean_payload, alert_id))

        # Broadcast new alert to WebSocket subscribers
        try:
            from api.websocket import ws_manager
            await ws_manager.broadcast("performance", {
                "type": "alert_created",
                "alert_id": alert_id or local_alert_id or es_id,
                "title": clean_payload.get("title", "Untitled Alert"),
                "severity": clean_payload.get("severity", "unknown"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass

        return ProcessResult(latest_ts=_advance_timestamp(source_doc, latest_ts), sent=1)
