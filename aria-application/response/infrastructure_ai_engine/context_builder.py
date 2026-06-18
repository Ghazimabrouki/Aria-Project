"""
Build structured resource context from Telegraf metrics for infrastructure investigations.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

import structlog

from pipeline.performance_poller import HostMetrics

logger = structlog.get_logger()


@dataclass
class ProcessInfo:
    name: str
    pid: int
    cpu_percent: float
    memory_rss: int
    memory_percent: float
    cmdline: str = ""


@dataclass
class MetricsSnapshot:
    cpu_usage_percent: float
    cpu_user_percent: float
    cpu_system_percent: float
    cpu_iowait_percent: float
    memory_used_percent: float
    memory_used_bytes: int
    memory_available_bytes: int
    disk_devices: List[Dict[str, Any]]
    network_bytes_recv: float
    network_bytes_sent: float
    load_1: float
    load_5: float
    load_15: float
    n_cpus: int
    tcp_established: int
    tcp_listen: int
    udp_socket: int
    proc_running: int
    proc_sleeping: int
    proc_total: int
    proc_threads: int


@dataclass
class ResourceContext:
    resource_type: str
    current_value: float
    threshold: float
    unit: str
    affected_host: str
    affected_service: Optional[str]
    affected_process: Optional[Dict[str, Any]]
    top_processes: List[Dict[str, Any]]
    metrics_snapshot: Dict[str, Any]
    historical_trend: str
    baseline_deviation: Optional[str]
    root_cause_confidence: float
    severity: str
    anomaly_type: str


def _classify_trend(
    current_value: float,
    threshold: float,
    metrics_history: Optional[List[float]] = None,
) -> str:
    """Classify whether the anomaly is a spike, persistent, or gradual."""
    if not metrics_history or len(metrics_history) < 3:
        return "unknown"

    # Look at the last 5 data points (2.5 minutes at 30s intervals)
    recent = metrics_history[-5:]
    if len(recent) < 3:
        return "unknown"

    # Check if it's a sudden spike
    if len(recent) >= 2:
        prev_avg = sum(recent[:-1]) / len(recent[:-1])
        if current_value > prev_avg * 1.5:
            return "spike"

    # Check if it's persistent (above threshold for multiple readings)
    above_threshold_count = sum(1 for v in recent if v > threshold)
    if above_threshold_count >= len(recent) * 0.8:
        return "persistent"

    # Gradual increase
    if len(recent) >= 3 and recent[-1] > recent[0] * 1.2:
        return "gradual"

    return "temporary"


def _identify_affected_process(
    metrics: HostMetrics, resource_type: str
) -> Optional[Dict[str, Any]]:
    """Identify the most likely responsible process from top_processes."""
    if not metrics.top_processes:
        return None

    # For CPU: highest cpu_percent
    # For memory: highest memory_percent
    # For disk/network: use first process (heuristic)
    candidates = metrics.top_processes

    if resource_type == "cpu":
        candidates = sorted(
            candidates, key=lambda p: p.get("cpu_percent", 0), reverse=True
        )
    elif resource_type == "memory":
        candidates = sorted(
            candidates, key=lambda p: p.get("memory_percent", 0), reverse=True
        )

    top = candidates[0] if candidates else None
    if not top:
        return None

    return {
        "name": top.get("name", "unknown"),
        "pid": top.get("pid", 0),
        "cpu_percent": top.get("cpu_percent", 0.0),
        "memory_rss": top.get("memory_rss", 0),
        "memory_percent": top.get("memory_percent", 0.0),
        "cmdline": top.get("cmdline", "")[:200],
    }


def _identify_affected_service(
    affected_process: Optional[Dict[str, Any]],
    metrics: HostMetrics,
) -> Optional[str]:
    """Map process name to likely service name."""
    if not affected_process:
        return None

    name = affected_process.get("name", "").lower()

    service_map = {
        "nginx": "nginx",
        "apache": "apache2",
        "httpd": "httpd",
        "java": "java-application",
        "redis-server": "redis",
        "redis": "redis",
        "postgres": "postgresql",
        "postmaster": "postgresql",
        "mysqld": "mysql",
        "mariadbd": "mariadb",
        "dockerd": "docker",
        "containerd": "containerd",
        "node": "node-application",
        "python": "python-application",
        "python3": "python-application",
    }

    for key, service in service_map.items():
        if key in name:
            return service

    # Fallback: check if it's a systemd service
    if name.endswith("d"):
        return name

    return name


def build_resource_context(
    host: str,
    metrics: HostMetrics,
    anomaly_type: str,
    current_value: float,
    threshold: float,
    severity: str,
    metrics_history: Optional[List[float]] = None,
    baseline_deviation: Optional[str] = None,
) -> ResourceContext:
    """Build a complete ResourceContext from anomaly detection results."""

    resource_type = _map_anomaly_type_to_resource(anomaly_type)
    affected_process = _identify_affected_process(metrics, resource_type)
    affected_service = _identify_affected_service(affected_process, metrics)
    trend = _classify_trend(current_value, threshold, metrics_history)

    # Build metrics snapshot
    snapshot = MetricsSnapshot(
        cpu_usage_percent=metrics.cpu_usage_percent,
        cpu_user_percent=metrics.cpu_user_percent,
        cpu_system_percent=metrics.cpu_system_percent,
        cpu_iowait_percent=metrics.cpu_iowait_percent,
        memory_used_percent=metrics.memory_used_percent,
        memory_used_bytes=metrics.memory_used_bytes,
        memory_available_bytes=metrics.memory_available_bytes,
        disk_devices=metrics.disk_devices,
        network_bytes_recv=metrics.network_bytes_recv,
        network_bytes_sent=metrics.network_bytes_sent,
        load_1=metrics.load_1,
        load_5=metrics.load_5,
        load_15=metrics.load_15,
        n_cpus=metrics.n_cpus,
        tcp_established=metrics.tcp_established,
        tcp_listen=metrics.tcp_listen,
        udp_socket=metrics.udp_socket,
        proc_running=metrics.proc_running,
        proc_sleeping=metrics.proc_sleeping,
        proc_total=metrics.proc_total,
        proc_threads=metrics.proc_threads,
    )

    context = ResourceContext(
        resource_type=resource_type,
        current_value=current_value,
        threshold=threshold,
        unit=_get_unit_for_resource(resource_type),
        affected_host=host,
        affected_service=affected_service,
        affected_process=affected_process,
        top_processes=[
            {
                "name": p.get("name", "unknown"),
                "pid": p.get("pid", 0),
                "cpu_percent": p.get("cpu_percent", 0.0),
                "memory_rss": p.get("memory_rss", 0),
                "memory_percent": p.get("memory_percent", 0.0),
            }
            for p in metrics.top_processes[:10]
        ],
        metrics_snapshot=asdict(snapshot),
        historical_trend=trend,
        baseline_deviation=baseline_deviation,
        root_cause_confidence=0.0,  # Will be filled by AI engine
        severity=severity,
        anomaly_type=anomaly_type,
    )

    logger.info(
        "resource_context_built",
        host=host,
        resource_type=resource_type,
        affected_service=affected_service,
        trend=trend,
    )

    return context


def _map_anomaly_type_to_resource(anomaly_type: str) -> str:
    """Map anomaly type string to resource type."""
    mapping = {
        "cpu_high": "cpu",
        "memory_high": "memory",
        "disk_full": "disk",
        "disk_inodes": "disk",
        "network_high": "network",
        "anomaly_detected": "unknown",
        "process_issue": "cpu",
    }
    return mapping.get(anomaly_type, "unknown")


def _get_unit_for_resource(resource_type: str) -> str:
    """Get the unit for a resource type."""
    units = {
        "cpu": "%",
        "memory": "%",
        "disk": "%",
        "network": "bytes/s",
    }
    return units.get(resource_type, "")
