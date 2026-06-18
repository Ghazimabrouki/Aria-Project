"""
Performance Monitoring Orchestrator.

Coordinates the complete performance monitoring pipeline:
1. Poll metrics from Elasticsearch (Telegraf data)
2. Detect anomalies using hybrid detection (threshold + statistical + AI)
3. Analyze root cause
4. Generate alerts
5. Send to OpenSOAR
6. Create incidents for critical issues

Part of the Server Performance Monitoring System (v1.0).
"""

import asyncio
import structlog
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from config import get_settings
from pipeline.performance_poller import PerformancePoller, HostMetrics
from pipeline.enrichment.anomaly_detector import AnomalyDetector
from pipeline.enrichment.root_cause import analyze_performance_root_cause
from pipeline.alerts.performance_alert import performance_alert_generator
from pipeline.sender import client

logger = structlog.get_logger()

_performance_stats = {
    "polls": 0,
    "hosts_monitored": 0,
    "alerts_generated": 0,
    "alerts_sent": 0,
    "incidents_created": 0,
    "errors": 0,
}


async def run_performance_monitoring_cycle() -> Dict[str, Any]:
    """Run one cycle of performance monitoring."""
    global _performance_stats
    settings = get_settings()

    if not settings.performance_enabled:
        logger.debug("performance_monitoring_disabled")
        return {"action": "skipped", "reason": "disabled"}

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hosts_processed": 0,
        "alerts_generated": 0,
        "alerts_sent": 0,
        "incidents_created": 0,
        "errors": 0,
    }

    component_errors = []

    # Store metrics in Redis for API access
    from core.redis_performance import performance_redis

    try:
        # Use the singleton performance_poller so cursor state is preserved
        # across cycles. Creating a fresh instance each cycle resets the cursor
        # to (now - 5min), which can miss brief spikes.
        from pipeline.performance_poller import performance_poller as poller
        metrics_dict = await poller.poll_once()
    except Exception as e:
        logger.error("performance_poller_failed", error=str(e))
        component_errors.append({"component": "poller", "error": str(e)})
        metrics_dict = {}

    # Store metrics in Redis so API can access them
    if metrics_dict:
        for host, metrics in metrics_dict.items():
            try:
                await performance_redis.store_current_metrics(
                    host,
                    {
                        "hostname": metrics.hostname,
                        "ip": metrics.ip,
                        "cpu_usage_percent": metrics.cpu_usage_percent,
                        "cpu_user_percent": metrics.cpu_user_percent,
                        "cpu_system_percent": metrics.cpu_system_percent,
                        "cpu_iowait_percent": metrics.cpu_iowait_percent,
                        "memory_used_percent": metrics.memory_used_percent,
                        "memory_used_bytes": metrics.memory_used_bytes,
                        "memory_available_bytes": metrics.memory_available_bytes,
                        "disk_devices": metrics.disk_devices,
                        "network_bytes_recv": metrics.network_bytes_recv,
                        "network_bytes_sent": metrics.network_bytes_sent,
                        "load_1": metrics.load_1,
                        "load_5": metrics.load_5,
                        "load_15": metrics.load_15,
                        "n_cpus": metrics.n_cpus,
                        "tcp_established": metrics.tcp_established,
                        "tcp_listen": metrics.tcp_listen,
                        "udp_socket": metrics.udp_socket,
                        "proc_running": metrics.proc_running,
                        "proc_sleeping": metrics.proc_sleeping,
                        "proc_total": metrics.proc_total,
                        "proc_threads": metrics.proc_threads,
                        "disk_dirs": metrics.disk_dirs,
                        "top_processes": metrics.top_processes,
                        "timestamp": metrics.timestamp,
                    },
                )
            except Exception as e:
                logger.error("redis_store_metrics_failed", host=host, error=str(e))

            # Append scalar history points for trending
            try:
                await performance_redis.append_to_history(
                    host, "cpu", float(metrics.cpu_usage_percent)
                )
                await performance_redis.append_to_history(
                    host, "memory", float(metrics.memory_used_percent)
                )
                disk_max = max(
                    (d.get("used_percent", 0.0) for d in metrics.disk_devices),
                    default=0.0,
                )
                await performance_redis.append_to_history(host, "disk", float(disk_max))
                await performance_redis.append_to_history(
                    host, "network", float(metrics.network_bytes_recv)
                )
                await performance_redis.append_to_history(
                    host, "load", float(metrics.load_1)
                )
            except Exception as e:
                logger.warning("append_history_failed", host=host, error=str(e))

    if not metrics_dict:
        logger.info("performance_no_hosts_found")
        return result

    result["hosts_processed"] = len(metrics_dict)
    _performance_stats["hosts_monitored"] += len(metrics_dict)

    try:
        detector = AnomalyDetector()
    except Exception as e:
        logger.error("performance_detector_init_failed", error=str(e))
        component_errors.append({"component": "anomaly_detector", "error": str(e)})
        detector = None

    if not detector:
        logger.warning("performance_anomaly_detection_disabled")
        return result

    for host, metrics in metrics_dict.items():
        try:
            anomalies = await detector.detect_all(metrics)

            if not anomalies:
                continue

            for anomaly in anomalies:
                if not anomaly.is_anomaly:
                    continue

                # Check cooldown to prevent alert spam
                anomaly_type_str = anomaly.anomaly_type.value if anomaly.anomaly_type else "unknown"
                should_alert = await detector.should_create_alert(host, anomaly_type_str)
                if not should_alert:
                    logger.debug(
                        "performance_alert_in_cooldown",
                        host=host,
                        anomaly_type=anomaly_type_str,
                    )
                    continue

                root_cause_result = await analyze_performance_root_cause(
                    metrics=metrics,
                    anomaly_type=anomaly_type_str,
                    current_value=anomaly.value,
                )

                # Resolve asset_id from hostname for per-asset ansible config
                asset_id = None
                try:
                    from core.asset_scope import resolve_asset_from_hostname
                    from response.db import AsyncSessionLocal
                    async with AsyncSessionLocal() as session:
                        asset_id = await resolve_asset_from_hostname(hostname=host, session=session)
                except Exception as e:
                    logger.debug("performance_asset_resolution_failed", host=host, error=str(e))

                alert = performance_alert_generator.generate_alert(
                    host=host,
                    hostname=metrics.hostname,
                    anomaly_result=anomaly,
                    metrics={
                        "cpu_usage_percent": metrics.cpu_usage_percent,
                        "memory_used_percent": metrics.memory_used_percent,
                        "disk_devices": metrics.disk_devices,
                        "network_bytes_recv": metrics.network_bytes_recv,
                    },
                    root_cause=root_cause_result.explanation,
                    confidence=root_cause_result.confidence,
                    evidence=root_cause_result.evidence,
                    affected_process=root_cause_result.affected_process,
                    asset_id=asset_id,
                )

                if not alert:
                    continue

                result["alerts_generated"] += 1
                _performance_stats["alerts_generated"] += 1

                # Broadcast performance alert via WebSocket
                try:
                    from api.websocket import broadcast_performance_alert

                    await broadcast_performance_alert(alert)
                except Exception as e:
                    logger.debug("ws_broadcast_alert_failed", error=str(e))

                # Try to send to upstream OpenSOAR (best effort)
                sent = await _send_alert_to_opensoar(alert)
                if sent:
                    result["alerts_sent"] += 1
                    _performance_stats["alerts_sent"] += 1

                # Create infrastructure investigation and auto-run diagnostics
                try:
                    inv_id = await _create_performance_investigation(
                        alert, host, metrics, anomaly
                    )
                    if inv_id:
                        logger.info(
                            "infrastructure_investigation_created",
                            investigation_id=inv_id,
                            host=host,
                            severity=alert.get("severity"),
                            status="diagnosing",
                        )
                        result["incidents_created"] += 1
                        _performance_stats["incidents_created"] += 1
                except Exception as e:
                    logger.error(
                        "infrastructure_investigation_failed",
                        host=host,
                        error=str(e),
                    )

                await detector.set_alert_cooldown(host, anomaly_type_str)

        except Exception as e:
            logger.error("performance_host_processing_error", host=host, error=str(e))
            result["errors"] += 1
            _performance_stats["errors"] += 1

    _performance_stats["polls"] += 1

    return result


async def _send_alert_to_opensoar(alert: Dict[str, Any]) -> bool:
    """Send performance alert to OpenSOAR and store in Redis history."""
    from config import get_settings
    if not get_settings().upstream_enabled:
        return False
    try:
        result = await client.create_alert("performance", alert)
        if result.get("alert_id"):
            # Add alert ID and timestamp
            alert["id"] = result["alert_id"]
            alert["timestamp"] = datetime.now(timezone.utc).isoformat()
            alert["sent_to_opensoar"] = True

            # Store in Redis history
            try:
                from core.redis_performance import performance_redis

                await performance_redis.store_alert(alert)
            except Exception as e:
                logger.warning("alert_history_store_failed", error=str(e))

            logger.info(
                "performance_alert_sent",
                alert_id=result["alert_id"],
                host=alert.get("host"),
                severity=alert.get("severity"),
            )
            return True
        return False
    except Exception as e:
        logger.error(
            "performance_alert_send_failed", error=str(e), host=alert.get("host")
        )
        return False


async def _create_performance_investigation(
    alert: Dict[str, Any], host: str, metrics: HostMetrics, anomaly
) -> Optional[str]:
    """Create infrastructure investigation in response DB for manual approval."""
    from datetime import datetime, timezone
    from config import get_settings
    from response.db import AsyncSessionLocal
    from response.models import Investigation
    from response.infrastructure_ai_engine import analyze_resource_anomaly

    settings = get_settings()

    # Use the new SRE-mode AI engine for deep analysis
    anomaly_type_str = alert.get("anomaly_type", "unknown")
    current_value = alert.get("metrics", {}).get(
        "cpu", {}
    ).get("current", 0)
    if anomaly_type_str == "memory_high":
        current_value = alert.get("metrics", {}).get("memory", {}).get("current", 0)
    elif anomaly_type_str == "disk_full":
        disk_devices = alert.get("metrics", {}).get("disk", [])
        if disk_devices:
            current_value = max(d.get("used_percent", 0) for d in disk_devices)
    elif anomaly_type_str == "network_high":
        current_value = alert.get("metrics", {}).get("network", {}).get("bytes_recv", 0)

    # Use the actual threshold that triggered the alert (from AnomalyResult),
    # not always the critical threshold. This fixes the mismatch where
    # warning-triggered alerts showed the critical threshold in diagnostics.
    threshold = getattr(anomaly, "threshold", None) or alert.get("metrics", {}).get("cpu", {}).get("critical_threshold", 90)
    severity = alert.get("severity", "medium")

    # Run SRE-mode analysis
    try:
        analysis_result = await analyze_resource_anomaly(
            host=host,
            metrics=metrics,
            anomaly_type=anomaly_type_str,
            current_value=current_value,
            threshold=threshold,
            severity=severity,
            baseline_deviation=alert.get("baseline_deviation"),
        )
    except Exception as e:
        logger.error("infrastructure_ai_analysis_failed", host=host, error=str(e))
        analysis_result = {
            "analysis": {},
            "context": None,
            "playbook_yaml": "",
            "description": f"Analysis failed for {anomaly_type_str} on {host}",
            "resource_context_json": {},
        }

    playbook_yaml = analysis_result.get("playbook_yaml", "")
    description = analysis_result.get("description", "")
    resource_context = analysis_result.get("resource_context_json", {})

    if not playbook_yaml:
        logger.warning(
            "infrastructure_playbook_not_generated",
            host=host,
            anomaly_type=anomaly_type_str,
        )
        return None

    async with AsyncSessionLocal() as session:
        investigation = Investigation(
            incident_title=alert.get(
                "title", f"Infrastructure: {anomaly_type_str} on {host}"
            ),
            incident_severity=severity,
            incident_status="open",
            status="diagnosing",
            incident_id=alert.get("id", ""),
            ai_summary=description,
            playbook_yaml=playbook_yaml,
            playbook_valid=True,
            target_host=host,
            target_user=settings.ansible_remote_user or "root",
            hostnames=host,
            source="performance",
            investigation_type="infrastructure",
            resource_type=resource_context.get("resource_type") if resource_context else None,
            resource_context_json=resource_context,
            asset_id=alert.get("asset_id"),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            diagnostic_started_at=datetime.now(timezone.utc),
        )

        session.add(investigation)
        await session.flush()  # Get the ID before commit

        # Link the alert to the investigation
        from response.models import InvestigationAlert
        import json

        investigation_alert = InvestigationAlert(
            investigation_id=investigation.id,
            alert_id=alert.get("id", ""),
            alert_json=json.dumps(alert),
            severity=alert.get("severity", "medium"),
            source=alert.get("source", "performance"),
            title=alert.get("title", ""),
        )
        session.add(investigation_alert)

        await session.commit()
        await session.refresh(investigation)

        logger.info(
            "infrastructure_investigation_saved",
            investigation_id=investigation.id,
            host=host,
            investigation_type="infrastructure",
        )

        # Broadcast via WebSocket so frontend updates in real-time
        try:
            from api.websocket import broadcast_investigation_change
            await broadcast_investigation_change(
                investigation.id,
                old_status="pending",
                new_status="diagnosing",
                details=f"Infrastructure diagnostic started for {anomaly_type_str} on {host}",
            )
        except Exception as e:
            logger.debug("ws_broadcast_investigation_failed", error=str(e))

        # Auto-trigger the diagnostic pipeline in the background
        asyncio.create_task(
            _run_diagnostic_pipeline(investigation.id, resource_context)
        )

        return investigation.id


async def _run_diagnostic_pipeline(
    investigation_id: str,
    resource_context: Dict[str, Any],
) -> None:
    """
    Run the full diagnostic pipeline for infrastructure or runtime investigations.

    1. Execute diagnostic playbook on target host
    2. Collect raw output
    3. AI interprets the output into structured findings
    4. Update investigation with findings and set status to 'findings_ready'
    """
    from datetime import datetime, timezone
    from response.db import AsyncSessionLocal
    from response.models import Investigation
    from response.infrastructure_ai_engine import interpret_diagnostic_output
    from response.infrastructure_ai_engine.context_builder import ResourceContext as InfraResourceContext
    from response.runtime_ai_engine.diagnostic_interpreter import interpret_runtime_diagnostic
    from response.runtime_ai_engine.context_builder import RuntimeContext
    from response.ansible_exec import execute_diagnostic_playbook
    from sqlalchemy import select

    logger.info(
        "diagnostic_pipeline_started",
        investigation_id=investigation_id,
    )

    # Determine investigation type
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        inv = result.scalar_one_or_none()
        if not inv:
            logger.error("diagnostic_pipeline_investigation_not_found", investigation_id=investigation_id)
            return
        investigation_type = inv.investigation_type

    # Step 1: Run diagnostic playbook
    diagnostic_result = await execute_diagnostic_playbook(investigation_id)
    exit_code = diagnostic_result.get("exit_code", -1)
    raw_output = diagnostic_result.get("output", "")

    # Update investigation with diagnostic output
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        inv = result.scalar_one_or_none()
        if not inv:
            logger.error("diagnostic_pipeline_investigation_not_found", investigation_id=investigation_id)
            return

        inv.diagnostic_output = raw_output
        inv.diagnostic_finished_at = datetime.now(timezone.utc)
        await session.commit()

    # Step 2: AI interprets the diagnostic output
    findings = None
    if resource_context:
        try:
            if investigation_type == "runtime":
                # Runtime security interpretation
                context = RuntimeContext.from_dict(resource_context)
                findings = interpret_runtime_diagnostic(context, raw_output)
            else:
                # Infrastructure interpretation
                ctx_data = dict(resource_context)
                if "severity" not in ctx_data:
                    ctx_data["severity"] = inv.incident_severity if inv else "medium"
                if "anomaly_type" not in ctx_data:
                    ctx_data["anomaly_type"] = ctx_data.get("resource_type", "unknown")
                context = InfraResourceContext(**ctx_data)
                findings = await interpret_diagnostic_output(context, raw_output)
        except Exception as e:
            logger.error(
                "diagnostic_interpretation_failed",
                investigation_id=investigation_id,
                investigation_type=investigation_type,
                error=str(e),
            )

    if not findings:
        findings = {
            "detected_cause": "Diagnostic completed but interpretation unavailable",
            "confidence": 0.0,
            "severity": inv.incident_severity if inv else "medium",
            "impact": "Unknown",
            "is_temporary": False,
            "is_expected": False,
            "technical_explanation": "The diagnostic playbook ran but the AI interpretation step failed. Please review the raw diagnostic output.",
            "evidence": [],
            "recommendations": [
                {
                    "action": "Review raw diagnostic output manually",
                    "priority": 1,
                    "risk": "none",
                    "rationale": "AI interpretation failed",
                }
            ],
            "requires_action": True,
            "expert_summary": "Diagnostic data collected but interpretation unavailable.",
        }

    # Step 3: Update investigation with findings
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        inv = result.scalar_one_or_none()
        if inv:
            inv.findings_json = findings
            inv.ai_error = None
            inv.status = "findings_ready"
            inv.updated_at = datetime.now(timezone.utc)
            await session.commit()

            logger.info(
                "diagnostic_pipeline_complete",
                investigation_id=investigation_id,
                investigation_type=investigation_type,
                cause=findings.get("detected_cause", "")[:80],
                confidence=findings.get("confidence", 0),
                severity=findings.get("severity", "unknown"),
            )

            # Broadcast findings ready
            try:
                from api.websocket import broadcast_investigation_change
                await broadcast_investigation_change(
                    investigation_id,
                    old_status="diagnosing",
                    new_status="findings_ready",
                    details=f"Diagnostic findings available for {inv.incident_title}",
                )
            except Exception as e:
                logger.debug("ws_broadcast_findings_ready_failed", error=str(e))


def _determine_playbook_type(alert: Dict[str, Any], metrics: HostMetrics) -> str:
    """Determine which playbook to generate based on alert type and metrics."""
    anomaly_type = alert.get("anomaly_type", "")

    if anomaly_type == "disk_full":
        # Check which partition and suggest appropriate playbook
        for d in metrics.disk_devices:
            if d.get("used_percent", 0) > 90:
                path = d.get("path", "")
                if path == "/":
                    return "disk_full_root"
                elif "/var/log" in path:
                    return "disk_full_var_log"

        # Default to root cleanup
        return "disk_full_root"

    elif anomaly_type == "cpu_high":
        # Check if we can identify the service
        for p in metrics.top_processes:
            name = p.get("name", "").lower()
            if "nginx" in name:
                return "cpu_high_nginx"
            elif "apache" in name or "httpd" in name:
                return "cpu_high_apache"
            elif "java" in name:
                return "cpu_high_java"
        return "cpu_high_java"

    elif anomaly_type == "memory_high":
        for p in metrics.top_processes:
            name = p.get("name", "").lower()
            if "redis" in name:
                return "memory_high_redis"
            elif "java" in name:
                return "memory_high_java"
        return "memory_high_java"

    # Default
    return "cpu_high_nginx"


def get_performance_stats() -> Dict[str, Any]:
    """Get performance monitoring statistics."""
    return {
        **_performance_stats,
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


async def start_performance_monitoring():
    """Start the performance monitoring loop."""
    settings = get_settings()

    if not settings.performance_enabled:
        logger.info("performance_monitoring_not_enabled")
        return

    logger.info(
        "performance_monitoring_started",
        poll_interval=settings.performance_poll_interval,
    )

    while True:
        try:
            result = await run_performance_monitoring_cycle()

            if result.get("alerts_sent", 0) > 0:
                logger.info("performance_cycle_complete", **result)
            else:
                logger.debug(
                    "performance_cycle_complete", hosts=result.get("hosts_processed", 0)
                )

        except Exception as e:
            logger.error("performance_loop_error", error=str(e))

        await asyncio.sleep(settings.performance_poll_interval)
