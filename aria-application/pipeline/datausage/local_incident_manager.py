"""
Local Incident Manager — Pure SQLite incident correlation without upstream OpenSOAR.

Reuses all correlation logic from incident_manager.py but creates/links incidents
directly in the local SQLite database.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

import structlog
from sqlalchemy import select, insert, update

from config import get_settings
from response.db import AsyncSessionLocal
from response.models import Incident, AlertIncidentLink, Alert
from core.whitelist import is_whitelisted

# Per-attack-pattern correlation windows (minutes)
# Brute force: short window (rapid attempts)
# C2/malware: long window (persistent campaigns)
# Reconnaissance: medium window (scanning phases)
_CORRELATION_WINDOWS = {
    "ssh_brute_force": 15,
    "port_scan": 60,
    "malware": 240,           # 4 hours
    "c2": 360,                # 6 hours
    "web_attack": 30,
    "ddos": 15,
    "privilege_escalation": 120,
    "data_exfiltration": 240,
    "lateral_movement": 180,
    "spamhaus": 60,
}
DEFAULT_CORRELATION_WINDOW = 30


def _get_correlation_window(attack_pattern: Optional[str]) -> int:
    """Get correlation window in minutes for an attack pattern."""
    if attack_pattern:
        return _CORRELATION_WINDOWS.get(attack_pattern, DEFAULT_CORRELATION_WINDOW)
    return DEFAULT_CORRELATION_WINDOW


# Re-use correlation logic from upstream incident_manager
from pipeline.datausage.incident_manager import (
    _get_correlation_key,
    _extract_mitre_tactics,
    _extract_attack_pattern,
    _extract_cloud_provider,
    _extract_campaign_type,
    _extract_country,
    detect_kill_chain_progression,
    generate_incident_title,
    generate_incident_tags,
    calculate_incident_severity,
    should_create_incident,
    _is_noise_alert,
    SEVERITY_ORDER,
    _now_utc,
    _incident_cache,
    _processed_alerts,
    _load_incident_cache,
    _save_incident_cache,
    _load_links,
    _save_links,
)

logger = structlog.get_logger()


def _calculate_correlation_confidence(
    alert_payload: dict,
    signals: dict,
    alert_count: int = 1,
) -> int:
    """Calculate evidence-based correlation confidence (0-100).
    
    Factors:
    - Source diversity: network + endpoint = +25
    - Kill chain depth: each phase beyond first = +15 (max +30)
    - Pattern specificity: known attack pattern = +20, generic = +5
    - MITRE technique match: SID-mapped or rule-mapped = +15
    - Alert volume: 2+ alerts = +10, 5+ = +15
    - Time concentration: N/A at single-alert time (recalculated on correlation)
    """
    score = 30  # Base confidence
    
    # Source diversity bonus
    sources = set()
    src = alert_payload.get("source", "")
    if src:
        sources.add(src)
    # Check metadata for cross-source evidence
    metadata = alert_payload.get("metadata", {}) or {}
    if metadata.get("has_endpoint_evidence") or metadata.get("has_network_evidence"):
        sources.add("hybrid")
    if len(sources) >= 2:
        score += 20
    elif src in ("suricata", "wazuh", "falco"):
        score += 10
    
    # Kill chain depth
    kill_chain = signals.get("kill_chain", {})
    if kill_chain.get("detected"):
        phase_count = kill_chain.get("phase_count", 0)
        score += min((phase_count - 1) * 15, 30)
    
    # Pattern specificity
    attack_pattern = signals.get("attack_pattern") or _extract_attack_pattern(alert_payload)
    if attack_pattern:
        score += 20
    else:
        score += 5
    
    # MITRE technique match
    mitre_ids = signals.get("mitre_ids", [])
    if not mitre_ids:
        # Try to extract from metadata
        if metadata.get("mitre_technique_id"):
            mitre_ids = [metadata["mitre_technique_id"]]
    if mitre_ids:
        score += 15
    
    # Alert volume
    if alert_count >= 5:
        score += 15
    elif alert_count >= 2:
        score += 10
    
    # Multi-source from incident_manager signals
    all_sources = signals.get("all_sources", set())
    if len(all_sources) >= 2:
        score += 10
    
    return min(score, 100)


async def _find_local_incident_by_correlation(
    alert_payload: dict, signals: dict, window_minutes: int = None
) -> Optional[Incident]:
    """Find an existing open local incident that matches this alert's correlation key.
    If multi-server is enabled, block mixed-asset linking."""
    settings = get_settings()
    attack_pattern = signals.get("attack_pattern") or _extract_attack_pattern(alert_payload)
    window = window_minutes or _get_correlation_window(attack_pattern)
    corr_key = signals.get("correlation_key") or _get_correlation_key(alert_payload)
    source_ip = alert_payload.get("source_ip") or ""
    alert_asset_id = alert_payload.get("asset_id")
    cutoff = _now_utc() - timedelta(minutes=window)

    try:
        async with AsyncSessionLocal() as session:
            # Strategy 1: match by correlation_key if available (fast, indexed lookup)
            if corr_key:
                result = await session.execute(
                    select(Incident)
                    .where(
                        Incident.status == "open",
                        Incident.correlation_key == corr_key,
                        Incident.created_at >= cutoff,
                    )
                    .order_by(Incident.created_at.desc())
                    .limit(1)
                )
                match = result.scalar_one_or_none()
                if match:
                    # Block mixed-asset linking when asset_id is present
                    if alert_asset_id is not None and match.asset_id is not None and match.asset_id != alert_asset_id:
                        logger.debug("mixed_asset_incident_blocked", incident_id=match.id, alert_asset_id=alert_asset_id, incident_asset_id=match.asset_id)
                        return None
                    return match

            # Strategy 2: fallback to source_ip + attack_pattern matching
            result = await session.execute(
                select(Incident)
                .where(
                    Incident.status == "open",
                    Incident.created_at >= cutoff,
                )
                .order_by(Incident.created_at.desc())
            )
            candidates = result.scalars().all()

            for inc in candidates:
                # Block mixed-asset linking when asset_id is present
                if alert_asset_id is not None and inc.asset_id is not None and inc.asset_id != alert_asset_id:
                    continue

                # Check source_ip overlap
                inc_ips = inc.source_ips or []
                if source_ip and source_ip in inc_ips:
                    # Check attack pattern match in tags
                    if attack_pattern:
                        inc_tags = [t.lower() for t in (inc.tags or [])]
                        if f"attack-{attack_pattern}" in inc_tags:
                            return inc
                    else:
                        return inc

                # Check hostname overlap if no IP match AND alert has no source_ip
                # (e.g. container alerts without IPs)
                hostname = alert_payload.get("hostname")
                inc_hostnames = inc.hostnames or []
                if not source_ip and hostname and hostname in inc_hostnames:
                    return inc

            return None
    except Exception as e:
        logger.warning("find_local_incident_failed", error=str(e)[:100])
        return None


async def _escalate_local_incident(
    incident: Incident, new_severity: str
) -> None:
    """Escalate a local incident's severity if the new alert is more severe."""
    new_score = SEVERITY_ORDER.get(new_severity, 0)
    current_score = SEVERITY_ORDER.get(incident.severity, 0)
    if new_score > current_score:
        try:
            async with AsyncSessionLocal() as session:
                await session.execute(
                    update(Incident)
                    .where(Incident.id == incident.id)
                    .values(severity=new_severity, updated_at=_now_utc())
                )
                await session.commit()
                logger.info(
                    "local_incident_escalated",
                    incident_id=incident.id,
                    old_severity=incident.severity,
                    new_severity=new_severity,
                )
        except Exception as e:
            logger.warning("local_incident_escalation_failed", incident_id=incident.id, error=str(e)[:100])


async def _link_alert_to_local_incident_db(
    incident_id: str, alert_id: str, source_ip: str = ""
) -> bool:
    """Link an alert to a local incident using AlertIncidentLink."""
    try:
        async with AsyncSessionLocal() as session:
            # Resolve alert_id to local Alert.id
            result = await session.execute(select(Alert.id).where(Alert.id == alert_id))
            local_alert_id = result.scalar_one_or_none()
            if not local_alert_id:
                result = await session.execute(
                    select(Alert.id).where(Alert.external_id == alert_id)
                )
                local_alert_id = result.scalar_one_or_none()

            if not local_alert_id:
                logger.debug("alert_not_found_for_link", alert_id=alert_id, incident_id=incident_id)
                return False

            # Update incident alert_ids list
            incident = await session.get(Incident, incident_id)
            if not incident:
                return False

            current_ids = set(incident.alert_ids or [])
            current_ids.add(local_alert_id)
            incident.alert_ids = list(current_ids)

            # Check whitelist
            if not incident.whitelisted:
                alert_result = await session.execute(
                    select(Alert.whitelisted, Alert.source_ip).where(Alert.id == local_alert_id)
                )
                row = alert_result.first()
                if row:
                    alert_whitelisted, alert_source_ip = row
                    if alert_whitelisted or (alert_source_ip and await is_whitelisted(alert_source_ip)):
                        incident.whitelisted = True

            # Create M2M link
            try:
                await session.execute(
                    insert(AlertIncidentLink).values(
                        alert_id=local_alert_id,
                        incident_id=incident_id,
                        correlation_confidence="high",
                        correlation_reason="auto-local-correlation",
                        linked_at=_now_utc(),
                    )
                )
            except Exception:
                pass  # Already linked

            await session.commit()
            logger.debug("alert_linked_to_local_incident", alert_id=local_alert_id, incident_id=incident_id)
            return True
    except Exception as e:
        logger.warning("link_alert_to_local_incident_failed", incident_id=incident_id, alert_id=alert_id, error=str(e)[:100])
        return False


async def create_local_incident(
    signals: dict,
    alert_payload: dict,
    alert_id: str,
    local_alert_id: Optional[str] = None,
    alert_count: int = 1,
) -> Optional[str]:
    """Create a new incident directly in local SQLite (no upstream)."""
    settings = get_settings()
    title = generate_incident_title(signals, alert_payload, alert_count)
    tags = generate_incident_tags(signals, alert_payload)
    # Use evidence-based severity calculation instead of copying alert severity blindly
    from pipeline.datausage.incident_manager import calculate_incident_severity
    severity = calculate_incident_severity([], alert_payload)
    source_ip = alert_payload.get("source_ip", "")
    corr_key = signals.get("correlation_key") or _get_correlation_key(alert_payload)

    description_parts = []
    campaign = signals.get("campaign_type")
    kill_chain = signals.get("kill_chain", {})
    tactics = signals.get("mitre_tactics", [])
    cloud = signals.get("cloud_provider")
    country = signals.get("country")
    dest_ip = alert_payload.get("dest_ip")

    if campaign:
        description_parts.append(f"Attack Type: {campaign}")
    if kill_chain.get("detected"):
        description_parts.append(f"Kill Chain: {' → '.join(kill_chain['phases'])}")
    if tactics:
        description_parts.append(f"MITRE ATT&CK: {', '.join(tactics)}")
    if cloud:
        description_parts.append(f"Infrastructure: {cloud}")
    if country:
        description_parts.append(f"Origin: {country}")
    description_parts.append(f"Source: {source_ip}")
    if dest_ip:
        description_parts.append(f"Target: {dest_ip}")

    description = " | ".join(description_parts)

    # Calculate evidence-based confidence score
    confidence = _calculate_correlation_confidence(alert_payload, signals, alert_count)
    tags.append(f"confidence-{confidence}")
    
    # Build incident metadata for soar_actions
    incident_meta = {
        "confidence": confidence,
        "correlation_reason": signals.get("correlation_reason", "single_alert"),
        "attack_pattern": signals.get("attack_pattern") or _extract_attack_pattern(alert_payload),
        "alert_count_at_creation": alert_count,
    }

    # Check whitelist
    whitelisted = False
    if source_ip and await is_whitelisted(source_ip):
        whitelisted = True

    try:
        async with AsyncSessionLocal() as session:
            incident_id = str(uuid.uuid4())
            incident = Incident(
                id=incident_id,
                external_id=None,
                correlation_key=corr_key,
                title=title,
                description=description,
                severity=severity,
                status="open",
                source_ips=[source_ip] if source_ip else None,
                hostnames=[alert_payload.get("hostname")] if alert_payload.get("hostname") else None,
                alert_ids=[local_alert_id or alert_id],
                tags=tags,
                whitelisted=whitelisted,
                soar_actions=incident_meta,
                asset_id=alert_payload.get("asset_id"),
                created_at=_now_utc(),
                updated_at=_now_utc(),
            )
            session.add(incident)
            await session.commit()

            # Link alert
            link_id = local_alert_id or alert_id
            if link_id:
                await _link_alert_to_local_incident_db(incident_id, link_id, source_ip)

            logger.info(
                "local_incident_created",
                incident_id=incident_id,
                title=title[:100],
                severity=severity,
                confidence=confidence,
                tags=tags,
                source_ip=source_ip,
            )
            return incident_id
    except Exception as e:
        logger.error("local_incident_creation_failed", title=title[:100], error=str(e)[:100])
        return None


async def process_alert_local(
    alert_id: str,
    alert_payload: dict,
    local_alert_id: Optional[str] = None,
) -> dict:
    """Local-only version of process_alert — creates/links incidents in SQLite only."""
    _load_links()
    _load_incident_cache()

    if alert_id in _processed_alerts:
        return {"action": "skipped", "incident_id": "", "reason": "already_processed"}

    if alert_payload.get("whitelisted"):
        logger.info("alert_skipped_whitelisted", alert_id=alert_id, local_alert_id=local_alert_id)
        return {"action": "skipped", "incident_id": "", "reason": "whitelisted"}

    # Route Falco runtime alerts to the runtime security pipeline
    if alert_payload.get("investigation_type") == "runtime":
        from pipeline.datausage.runtime_orchestrator import create_runtime_investigation
        try:
            investigation_id = await create_runtime_investigation(alert_payload, local_alert_id)
            if investigation_id:
                logger.info(
                    "runtime_alert_routed",
                    alert_id=alert_id,
                    local_alert_id=local_alert_id,
                    investigation_id=investigation_id,
                )
                return {
                    "action": "routed_to_runtime",
                    "investigation_id": investigation_id,
                    "reason": "runtime_security_event",
                }
        except Exception as e:
            logger.error("runtime_routing_failed", alert_id=alert_id, error=str(e))
            # Fall through to normal incident processing if runtime routing fails

    corr_key = _get_correlation_key(alert_payload)
    source_ip = alert_payload.get("source_ip") or ""

    mitre_tactics = _extract_mitre_tactics(alert_payload)
    cloud_provider = _extract_cloud_provider(alert_payload)
    campaign_type = _extract_campaign_type(alert_payload)
    country = _extract_country(alert_payload)
    attack_pattern = _extract_attack_pattern(alert_payload)
    kill_chain = detect_kill_chain_progression(mitre_tactics)
    high_risk_tactics = [t for t in mitre_tactics if t in {"Initial Access", "Execution", "Exfiltration", "Impact", "Credential Access", "Lateral Movement", "Command and Control"}]

    title_lower = (alert_payload.get("title") or "").lower()
    is_spamhaus = "spamhaus" in title_lower or "drop" in title_lower or "listed traffic" in title_lower
    is_cins = "cins" in title_lower or "poor reputation" in title_lower

    signals = {
        "mitre_tactics": mitre_tactics,
        "cloud_provider": cloud_provider,
        "campaign_type": campaign_type,
        "country": country,
        "attack_pattern": attack_pattern,
        "kill_chain": kill_chain,
        "high_risk_tactics": high_risk_tactics,
        "source_ip": source_ip,
        "correlation_key": corr_key,
        "is_spamhaus_drop": is_spamhaus,
        "is_cins": is_cins,
    }

    # 1. Check for existing local incident
    existing_incident = await _find_local_incident_by_correlation(alert_payload, signals)
    if existing_incident:
        await _escalate_local_incident(existing_incident, alert_payload.get("severity", "low"))
        link_id = local_alert_id or alert_id
        if link_id:
            await _link_alert_to_local_incident_db(existing_incident.id, link_id, source_ip)

        # Update cache
        _incident_cache[corr_key] = {
            **_incident_cache.get(corr_key, {}),
            "incident_id": existing_incident.id,
            "last_seen": _now_utc().isoformat(),
            "max_severity": alert_payload.get("severity", "low"),
        }
        _save_incident_cache()

        return {
            "action": "linked",
            "incident_id": existing_incident.id,
            "reason": "matched_existing_local_incident",
        }

    # 2. Track alert in cache
    if corr_key not in _incident_cache:
        _incident_cache[corr_key] = {
            "alert_ids": [],
            "incident_id": None,
            "first_seen": _now_utc().isoformat(),
            "last_seen": _now_utc().isoformat(),
            "campaign_type": campaign_type,
            "tactics": set(),
            "sources": set(),
            "max_severity": "low",
            "dest_ips": set(),
            "alert_timestamps": {},
            "correlation_key": corr_key,
            "source_ip": source_ip,
        }
    entry = _incident_cache[corr_key]
    if alert_id not in entry["alert_ids"]:
        entry["alert_ids"].append(alert_id)
    entry["alert_timestamps"][alert_id] = _now_utc().isoformat()
    for t in mitre_tactics:
        entry["tactics"].add(t)
    src = alert_payload.get("source", "")
    if src:
        entry["sources"].add(src)
    if alert_payload.get("dest_ip"):
        entry["dest_ips"].add(alert_payload["dest_ip"])
    current_sev = alert_payload.get("severity", "low")
    if SEVERITY_ORDER.get(current_sev, 0) > SEVERITY_ORDER.get(entry.get("max_severity", "low"), 0):
        entry["max_severity"] = current_sev
    entry["last_seen"] = _now_utc().isoformat()
    _save_incident_cache()
    tracked_count = len(entry["alert_ids"])

    # 3. Decide if we should create incident
    if not should_create_incident(alert_payload, signals, tracked_count):
        logger.debug(
            "alert_tracked_no_incident",
            alert_id=alert_id,
            local_alert_id=local_alert_id,
            source_ip=source_ip,
            severity=alert_payload.get("severity", "low"),
            tracked_count=tracked_count,
        )
        return {"action": "tracked", "incident_id": "", "reason": "waiting_for_more_signals"}

    # 4. Create local incident
    incident_id = await create_local_incident(signals, alert_payload, alert_id, local_alert_id, tracked_count)
    if incident_id:
        _processed_alerts.add(alert_id)
        _save_links()
        _incident_cache[corr_key]["incident_id"] = incident_id
        _save_incident_cache()

        logger.info(
            "local_incident_created_and_linked",
            alert_id=alert_id,
            local_alert_id=local_alert_id,
            incident_id=incident_id,
        )
        return {"action": "created", "incident_id": incident_id, "reason": "new_local_incident_created"}

    return {"action": "failed", "incident_id": "", "reason": "local_incident_creation_failed"}


async def run_local_correlation_cycle() -> int:
    """Background correlation cycle that works purely on local SQLite data."""
    _load_links()
    _load_incident_cache()
    incidents_created = 0

    # Phase: Check tracked correlation keys that haven't been promoted yet
    for corr_key, data in list(_incident_cache.items()):
        if data.get("incident_id"):
            continue

        alert_ids = data.get("alert_ids", [])
        if len(alert_ids) < 2:
            continue

        max_sev = data.get("max_severity", "low")
        tactics = data.get("tactics", set())
        if isinstance(tactics, list):
            tactics = set(tactics)

        kill_chain = detect_kill_chain_progression(list(tactics))
        campaign = data.get("campaign_type")

        should_promote = (
            SEVERITY_ORDER.get(max_sev, 0) >= 2
            or kill_chain["detected"]
            or campaign is not None
            or len(alert_ids) >= 3
        )

        if not should_promote:
            continue

        # Build a synthetic alert payload from the first alert we can find
        first_alert_id = alert_ids[0]
        alert_payload = {}
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(Alert).where(
                        (Alert.id == first_alert_id) | (Alert.external_id == first_alert_id)
                    )
                )
                alert_row = result.scalar_one_or_none()
                if alert_row:
                    alert_payload = {
                        "source_ip": alert_row.source_ip or "",
                        "dest_ip": alert_row.dest_ip or "",
                        "hostname": alert_row.hostname or "",
                        "severity": alert_row.severity or "low",
                        "title": alert_row.title or "",
                        "description": alert_row.description or "",
                        "source": alert_row.source or "",
                        "tags": alert_row.tags or [],
                    }
        except Exception:
            pass

        if not alert_payload:
            continue

        signals = {
            "mitre_tactics": list(tactics),
            "campaign_type": campaign,
            "kill_chain": kill_chain,
            "attack_pattern": None,
            "source_ip": data.get("source_ip", ""),
            "correlation_key": corr_key,
        }

        incident_id = await create_local_incident(signals, alert_payload, first_alert_id, first_alert_id, len(alert_ids))
        if incident_id:
            # Link remaining alerts
            for aid in alert_ids[1:]:
                await _link_alert_to_local_incident_db(incident_id, aid, data.get("source_ip", ""))

            _incident_cache[corr_key]["incident_id"] = incident_id
            _save_incident_cache()
            _save_links()
            incidents_created += 1

            logger.info(
                "local_correlation_cycle_incident_created",
                incident_id=incident_id,
                corr_key=corr_key,
                alerts_linked=len(alert_ids),
            )

    if incidents_created > 0:
        logger.info("local_correlation_cycle_complete", incidents_created=incidents_created)

    return incidents_created
