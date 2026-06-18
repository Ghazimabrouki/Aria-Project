"""
Performance Metrics API Routes.

Exposes performance metrics for dashboard visualization.
Part of the Server Performance Monitoring System (v1.0).
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import structlog

from config import get_settings
from pipeline.performance_poller import performance_poller, HostMetrics, PerformancePoller
from core.asset_scope import wrap_query
from response.models import MonitoredAsset
from response.auth import require_auth, CurrentUser

logger = structlog.get_logger()

from api.routes._performance.helpers import _host_matches_asset, _get_asset_or_404, _parse_du_size, _get_disk_heuristics, _resolve_ansible_host

router = APIRouter(prefix="/api/v1/metrics", tags=["performance"])






@router.get("/dashboard")
async def get_dashboard_metrics(
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """Get all hosts with latest metrics for dashboard."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    settings = get_settings()

    if not settings.performance_enabled:
        return {"error": "Performance monitoring disabled", "hosts": []}

    asset = None
    if asset_id and settings.multi_server_enabled:
        asset = await _get_asset_or_404(asset_id)

    try:
        # Try to get from Redis first (shared between main.py and uvicorn)
        try:
            from core.redis_performance import performance_redis

            redis_metrics = await performance_redis.get_all_current_metrics()

            if redis_metrics:
                hosts = []
                for hostname, data in redis_metrics.items():
                    metrics = data.get("metrics", {})
                    # Determine alert status
                    alert_status = "normal"
                    cpu = metrics.get("cpu_usage_percent", 0)
                    mem = metrics.get("memory_used_percent", 0)

                    if (
                        cpu >= settings.performance_cpu_critical
                        or mem >= settings.performance_memory_critical
                    ):
                        alert_status = "critical"
                    elif (
                        cpu >= settings.performance_cpu_warning
                        or mem >= settings.performance_memory_warning
                    ):
                        alert_status = "warning"

                    for disk in metrics.get("disk_devices", []):
                        if disk.get("used_percent", 0) >= settings.performance_disk_critical:
                            alert_status = "critical"
                            break
                        elif disk.get("used_percent", 0) >= settings.performance_disk_warning:
                            alert_status = "warning"
                            break

                    hosts.append(
                        {
                            "hostname": metrics.get("hostname", hostname),
                            "ip": metrics.get("ip") or hostname,
                            "status": alert_status,
                            "last_update": data.get("timestamp", ""),
                            "metrics": {
                                "cpu": {
                                    "current": round(
                                        metrics.get("cpu_usage_percent", 0), 1
                                    ),
                                    "user": round(
                                        metrics.get("cpu_user_percent", 0), 1
                                    ),
                                    "system": round(
                                        metrics.get("cpu_system_percent", 0), 1
                                    ),
                                    "iowait": round(
                                        metrics.get("cpu_iowait_percent", 0), 1
                                    ),
                                },
                                "memory": {
                                    "current": round(
                                        metrics.get("memory_used_percent", 0), 1
                                    ),
                                    "used_mb": round(
                                        metrics.get("memory_used_bytes", 0)
                                        / 1024
                                        / 1024,
                                        1,
                                    ),
                                    "available_mb": round(
                                        metrics.get("memory_available_bytes", 0)
                                        / 1024
                                        / 1024,
                                        1,
                                    ),
                                },
                                "disk": metrics.get("disk_devices", []),
                                "network": {
                                    "in_mb": round(
                                        metrics.get("network_bytes_recv", 0)
                                        / 1024
                                        / 1024,
                                        2,
                                    ),
                                    "out_mb": round(
                                        metrics.get("network_bytes_sent", 0)
                                        / 1024
                                        / 1024,
                                        2,
                                    ),
                                },
                                "load": {
                                    "1m": round(metrics.get("load_1", 0), 2),
                                    "5m": round(metrics.get("load_5", 0), 2),
                                    "15m": round(metrics.get("load_15", 0), 2),
                                    "cpus": metrics.get("n_cpus", 1),
                                },
                                "connections": {
                                    "tcp_established": metrics.get(
                                        "tcp_established", 0
                                    ),
                                    "tcp_listen": metrics.get("tcp_listen", 0),
                                    "udp": metrics.get("udp_socket", 0),
                                },
                            },
                            "processes": {
                                "running": metrics.get("proc_running", 0),
                                "sleeping": metrics.get("proc_sleeping", 0),
                                "total": metrics.get("proc_total", 0),
                                "threads": metrics.get("proc_threads", 0),
                                "top_cpu": metrics.get("top_processes", [])[:5],
                            },
                            "alert_status": alert_status,
                        }
                    )

                if asset:
                    hosts = [h for h in hosts if _host_matches_asset(h.get("hostname") or h.get("ip", ""), asset)]
                return {
                    "hosts": hosts,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "count": len(hosts),
                }
        except Exception as e:
            logger.warning("redis_metrics_failed", error=str(e))

        # Fallback to poller cache (works if same process)
        metrics_dict = performance_poller.get_cached_metrics()

        if not metrics_dict:
            return {"hosts": [], "timestamp": datetime.now(timezone.utc).isoformat()}

        # Build response
        hosts = []
        for hostname, metrics in metrics_dict.items():
            # Determine alert status based on thresholds
            alert_status = "normal"
            if (
                metrics.cpu_usage_percent >= settings.performance_cpu_critical
                or metrics.memory_used_percent >= settings.performance_memory_critical
            ):
                alert_status = "critical"
            elif (
                metrics.cpu_usage_percent >= settings.performance_cpu_warning
                or metrics.memory_used_percent >= settings.performance_memory_warning
            ):
                alert_status = "warning"

            for disk in metrics.disk_devices:
                if disk.get("used_percent", 0) >= settings.performance_disk_critical:
                    alert_status = "critical"
                    break
                elif disk.get("used_percent", 0) >= settings.performance_disk_warning:
                    alert_status = "warning"
                    break

            hosts.append(
                {
                    "hostname": metrics.hostname,
                    "ip": metrics.ip or metrics.hostname,
                    "status": alert_status,
                    "last_update": metrics.timestamp,
                    "metrics": {
                        "cpu": {
                            "current": round(metrics.cpu_usage_percent, 1),
                            "user": round(metrics.cpu_user_percent, 1),
                            "system": round(metrics.cpu_system_percent, 1),
                            "iowait": round(metrics.cpu_iowait_percent, 1),
                        },
                        "memory": {
                            "current": round(metrics.memory_used_percent, 1),
                            "used_mb": round(
                                metrics.memory_used_bytes / 1024 / 1024, 1
                            ),
                            "available_mb": round(
                                metrics.memory_available_bytes / 1024 / 1024, 1
                            ),
                        },
                        "disk": [
                            {
                                "device": d.get("device", "unknown"),
                                "used_percent": round(d.get("used_percent", 0), 1),
                                "used_gb": round(
                                    d.get("used_bytes", 0) / 1024 / 1024 / 1024, 1
                                ),
                                "free_gb": round(
                                    d.get("free_bytes", 0) / 1024 / 1024 / 1024, 1
                                ),
                            }
                            for d in metrics.disk_devices
                        ],
                        "network": {
                            "in_mb": round(metrics.network_bytes_recv / 1024 / 1024, 2),
                            "out_mb": round(
                                metrics.network_bytes_sent / 1024 / 1024, 2
                            ),
                        },
                        "load": {
                            "1m": round(metrics.load_1, 2),
                            "5m": round(metrics.load_5, 2),
                            "15m": round(metrics.load_15, 2),
                            "cpus": metrics.n_cpus,
                        },
                        "connections": {
                            "tcp_established": metrics.tcp_established,
                            "tcp_listen": metrics.tcp_listen,
                            "udp": metrics.udp_socket,
                        },
                    },
                    "processes": {
                        "running": metrics.proc_running,
                        "sleeping": metrics.proc_sleeping,
                        "total": metrics.proc_total,
                        "threads": metrics.proc_threads,
                        "top_cpu": [
                            {
                                "name": p.get("name", "unknown"),
                                "cpu_percent": round(p.get("cpu_percent", 0), 1),
                                "memory_mb": round(
                                    p.get("memory_rss", 0) / 1024 / 1024, 1
                                ),
                                "threads": p.get("num_threads", 0),
                            }
                            for p in metrics.top_processes[:5]
                        ],
                    },
                    "alert_status": alert_status,
                }
            )

        if asset:
            hosts = [h for h in hosts if _host_matches_asset(h.get("hostname") or h.get("ip", ""), asset)]
        return {
            "hosts": hosts,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "count": len(hosts),
        }

    except Exception as e:
        logger.error("dashboard_metrics_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/hosts")
async def list_monitored_hosts(
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """List all monitored hosts."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    settings = get_settings()

    if not settings.performance_enabled:
        return {"hosts": [], "count": 0}

    asset = None
    if asset_id and settings.multi_server_enabled:
        asset = await _get_asset_or_404(asset_id)

    try:
        # Try Redis first
        try:
            from core.redis_performance import performance_redis

            redis_metrics = await performance_redis.get_all_current_metrics()
            if redis_metrics:
                hosts = list(redis_metrics.keys())
                if asset:
                    hosts = [h for h in hosts if _host_matches_asset(h, asset)]
                return {
                    "hosts": hosts,
                    "count": len(hosts),
                    "configured_hosts": settings.performance_hosts_list or "all",
                }
        except Exception as e:
            logger.warning("redis_hosts_failed", error=str(e))

        # Fallback to poller cache
        metrics_dict = performance_poller.get_cached_metrics()
        hosts = list(metrics_dict.keys())

        if asset:
            hosts = [h for h in hosts if _host_matches_asset(h, asset)]

        return {
            "hosts": hosts,
            "count": len(hosts),
            "configured_hosts": settings.performance_hosts_list or "all",
        }

    except Exception as e:
        logger.error("list_hosts_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/thresholds")
async def get_thresholds() -> Dict[str, Any]:
    """Get current threshold configuration."""
    settings = get_settings()

    return {
        "cpu": {
            "warning": settings.performance_cpu_warning,
            "critical": settings.performance_cpu_critical,
        },
        "memory": {
            "warning": settings.performance_memory_warning,
            "critical": settings.performance_memory_critical,
        },
        "disk": {
            "warning": settings.performance_disk_warning,
            "critical": settings.performance_disk_critical,
        },
        "disk_inodes": {
            "warning": settings.performance_disk_inodes_warning,
            "critical": settings.performance_disk_inodes_critical,
        },
        "network_in": {
            "warning": settings.performance_network_in_warning,
            "critical": settings.performance_network_in_critical,
        },
    }

@router.get("/status")
async def get_performance_status() -> Dict[str, Any]:
    """Get performance monitoring system status."""
    settings = get_settings()

    return {
        "enabled": settings.performance_enabled,
        "poll_interval": settings.performance_poll_interval,
        "hosts_configured": settings.performance_hosts_list or "all",
        "anomaly_detection": {
            "enabled": settings.performance_anomaly_detection,
            "use_ai": settings.performance_anomaly_use_ai,
            "use_statistical": settings.performance_anomaly_use_statistical,
            "window_hours": settings.performance_anomaly_window_hours,
        },
        "auto_remediation": {
            "enabled": settings.performance_auto_remediate_enabled,
            "types": settings.performance_auto_remediate_types_list,
        },
    }

@router.get("/health")
async def performance_health() -> Dict[str, Any]:
    """Basic health check for performance monitoring."""
    settings = get_settings()

    return {
        "status": "healthy" if settings.performance_enabled else "disabled",
        "service": "performance_monitoring",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@router.get("/health/detailed")
async def performance_health_detailed() -> Dict[str, Any]:
    """Detailed health check with component status."""
    settings = get_settings()
    components = {}
    overall_status = "healthy"

    # Check Elasticsearch
    try:
        from core.elasticsearch import get_es_client

        client = await get_es_client()
        await client.info()
        components["elasticsearch"] = {"status": "healthy", "message": "connected"}
    except Exception as e:
        components["elasticsearch"] = {"status": "unhealthy", "message": str(e)[:100]}
        overall_status = "degraded"

    # Check Redis
    try:
        from core.redis import get_redis_client

        redis = await get_redis_client()
        await redis.ping()
        components["redis"] = {"status": "healthy", "message": "connected"}
    except Exception as e:
        components["redis"] = {"status": "unhealthy", "message": str(e)[:100]}
        overall_status = "degraded"

    # Check Telegraf indices
    try:
        from core.elasticsearch import get_es_client

        client = await get_es_client()
        result = await client.cat.indices(index="telegraf-*", format="json")
        telegraf_indices = [
            r.get("index", "")
            for r in result
            if "telegraf" in r.get("index", "").lower()
        ]
        components["telegraf"] = {
            "status": "healthy",
            "message": f"{len(telegraf_indices)} indices",
            "indices": telegraf_indices[:5],
        }
    except Exception as e:
        components["telegraf"] = {"status": "unhealthy", "message": str(e)[:100]}
        overall_status = "degraded"

    # Check poller cache
    try:
        cached_metrics = performance_poller.get_cached_metrics()
        components["poller_cache"] = {
            "status": "healthy",
            "cached_hosts": list(cached_metrics.keys()) if cached_metrics else [],
        }
    except Exception as e:
        components["poller_cache"] = {"status": "unknown", "message": str(e)[:100]}

    return {
        "status": overall_status,
        "service": "performance_monitoring",
        "enabled": settings.performance_enabled,
        "components": components,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@router.get("/alerts")
async def get_performance_alerts(
    host: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
) -> Dict[str, Any]:
    """Get performance alert history with optional filtering."""
    try:
        from core.redis_performance import performance_redis

        alerts = await performance_redis.get_alert_history(
            host=host, severity=severity, limit=limit
        )

        return {
            "alerts": alerts,
            "total": len(alerts),
            "filters": {"host": host, "severity": severity, "limit": limit},
        }
    except Exception as e:
        logger.error("get_alerts_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


async def _fetch_live_processes_ansible(host: str) -> List[Dict[str, Any]]:
    """Fetch top processes via Ansible ad-hoc when Telegraf procstat is missing."""
    try:
        import asyncio
        import shutil
        import subprocess
        import os

        if not shutil.which("ansible"):
            return []

        settings = get_settings()
        ssh_key = settings.ansible_ssh_key or ""
        ssh_password = settings.ansible_ssh_password or ""
        ssh_port = settings.ansible_ssh_port or 22
        target_user = settings.ansible_remote_user or "root"

        env = os.environ.copy()
        env["ANSIBLE_HOST_KEY_CHECKING"] = "False"

        # Build extra vars for credentials
        extra_vars = f"ansible_user={target_user} ansible_ssh_port={ssh_port}"
        if ssh_password:
            extra_vars += f" ansible_ssh_pass='{ssh_password}'"
        if ssh_key:
            extra_vars += f" ansible_ssh_private_key_file='{ssh_key}'"

        cmd = [
            "ansible",
            "-i", f"{host},",
            "all",
            "-m", "shell",
            "-a", "ps aux --sort=-%cpu | head -11",
            "-e", extra_vars,
            "--timeout", "15",
        ]

        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            ),
            timeout=20.0,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20.0)
        if proc.returncode != 0:
            return []

        lines = stdout.decode().splitlines()
        processes = []
        for line in lines:
            # Skip ansible summary lines
            if host in line or line.strip().startswith(">>>") or line.strip().startswith("changed="):
                continue
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            try:
                _user, pid, cpu, mem, _vsz, rss, _tty, _stat, _start, _time, command = parts
                processes.append(
                    {
                        "name": command.split()[0] if command else "unknown",
                        "pid": pid,
                        "cpu_percent": float(cpu),
                        "memory_rss": int(rss) * 1024,  # KB -> bytes
                    }
                )
            except Exception:
                continue
        return processes[:10]
    except Exception as e:
        logger.debug("ansible_process_fetch_failed", host=host, error=str(e))
        return []


@router.get("/{host}")
async def get_host_metrics(
    host: str,
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
) -> Dict[str, Any]:
    """Get current metrics for a specific host."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    # Input validation - validate hostname format
    import re

    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*$", host):
        raise HTTPException(status_code=400, detail="Invalid hostname format")

    # Validate length
    if len(host) > 255:
        raise HTTPException(status_code=400, detail="Hostname too long")

    settings = get_settings()

    if not settings.performance_enabled:
        raise HTTPException(status_code=503, detail="Performance monitoring disabled")

    asset = None
    if asset_id and settings.multi_server_enabled:
        asset = await _get_asset_or_404(asset_id)
        if asset and not _host_matches_asset(host, asset):
            raise HTTPException(status_code=404, detail=f"Host {host} not found")

    try:
        # Try Redis first (shared between processes)
        try:
            from core.redis_performance import performance_redis

            redis_data = await performance_redis.get_current_metrics(host)

            if redis_data:
                metrics = redis_data.get("metrics", {})
                # Determine alert status
                alert_status = "normal"
                cpu = metrics.get("cpu_usage_percent", 0) or 0
                mem = metrics.get("memory_used_percent", 0) or 0
                if (
                    cpu >= settings.performance_cpu_critical
                    or mem >= settings.performance_memory_critical
                ):
                    alert_status = "critical"
                elif (
                    cpu >= settings.performance_cpu_warning
                    or mem >= settings.performance_memory_warning
                ):
                    alert_status = "warning"
                for disk in metrics.get("disk_devices", []):
                    if (disk.get("used_percent") or 0) >= settings.performance_disk_critical:
                        alert_status = "critical"
                        break
                    elif (disk.get("used_percent") or 0) >= settings.performance_disk_warning:
                        alert_status = "warning"
                        break
                return {
                    "hostname": metrics.get("hostname", host),
                    "ip": metrics.get("ip") or host,
                    "last_update": redis_data.get("timestamp", ""),
                    "alert_status": alert_status,
                    "cpu": {
                        "usage_percent": round(cpu, 1),
                        "user_percent": round(metrics.get("cpu_user_percent", 0) or 0, 1),
                        "system_percent": round(
                            metrics.get("cpu_system_percent", 0) or 0, 1
                        ),
                        "iowait_percent": round(
                            metrics.get("cpu_iowait_percent", 0) or 0, 1
                        ),
                    },
                    "memory": {
                        "used_percent": round(mem, 1),
                        "used_bytes": metrics.get("memory_used_bytes") or 0,
                        "available_bytes": metrics.get("memory_available_bytes") or 0,
                    },
                    "disk": metrics.get("disk_devices", []),
                    "network": {
                        "bytes_recv": metrics.get("network_bytes_recv") or 0,
                        "bytes_sent": metrics.get("network_bytes_sent") or 0,
                    },
                    "load": {
                        "load_1": metrics.get("load_1", 0) or 0,
                        "load_5": metrics.get("load_5", 0) or 0,
                        "load_15": metrics.get("load_15", 0) or 0,
                        "n_cpus": metrics.get("n_cpus", 0) or 0,
                    },
                    "connections": {
                        "tcp_established": metrics.get("tcp_established", 0) or 0,
                        "tcp_listen": metrics.get("tcp_listen", 0) or 0,
                        "udp_socket": metrics.get("udp_socket", 0) or 0,
                    },
                    "processes": metrics.get("top_processes", []) or await _fetch_live_processes_ansible(host),
                    "procstat_missing": not bool(metrics.get("top_processes", [])),
                    "disk_dirs": metrics.get("disk_dirs", []),
                }
        except Exception as e:
            logger.warning("redis_host_metrics_failed", host=host, error=str(e))

        # Fallback to poller cache
        metrics_dict = performance_poller.get_cached_metrics()

        if host not in metrics_dict:
            raise HTTPException(status_code=404, detail=f"Host {host} not found")

        metrics = metrics_dict[host]

        # Determine alert status
        alert_status = "normal"
        if (
            metrics.cpu_usage_percent >= settings.performance_cpu_critical
            or metrics.memory_used_percent >= settings.performance_memory_critical
        ):
            alert_status = "critical"
        elif (
            metrics.cpu_usage_percent >= settings.performance_cpu_warning
            or metrics.memory_used_percent >= settings.performance_memory_warning
        ):
            alert_status = "warning"
        for disk in metrics.disk_devices:
            if (disk.get("used_percent") or 0) >= settings.performance_disk_critical:
                alert_status = "critical"
                break
            elif (disk.get("used_percent") or 0) >= settings.performance_disk_warning:
                alert_status = "warning"
                break

        return {
            "hostname": metrics.hostname,
            "ip": metrics.ip or metrics.hostname,
            "last_update": metrics.timestamp,
            "alert_status": alert_status,
            "cpu": {
                "usage_percent": round(metrics.cpu_usage_percent, 1),
                "user_percent": round(metrics.cpu_user_percent, 1),
                "system_percent": round(metrics.cpu_system_percent, 1),
                "iowait_percent": round(metrics.cpu_iowait_percent, 1),
            },
            "memory": {
                "used_percent": round(metrics.memory_used_percent, 1),
                "used_bytes": metrics.memory_used_bytes or 0,
                "available_bytes": metrics.memory_available_bytes or 0,
            },
            "disk": metrics.disk_devices,
            "network": {
                "bytes_recv": metrics.network_bytes_recv or 0,
                "bytes_sent": metrics.network_bytes_sent or 0,
            },
            "load": {
                "load_1": metrics.load_1 or 0,
                "load_5": metrics.load_5 or 0,
                "load_15": metrics.load_15 or 0,
                "n_cpus": metrics.n_cpus or 0,
            },
            "connections": {
                "tcp_established": metrics.tcp_established or 0,
                "tcp_listen": metrics.tcp_listen or 0,
                "udp_socket": metrics.udp_socket or 0,
            },
            "processes": metrics.top_processes or await _fetch_live_processes_ansible(host),
            "procstat_missing": not bool(metrics.top_processes),
            "disk_dirs": metrics.disk_dirs if hasattr(metrics, "disk_dirs") else [],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_host_metrics_failed", host=host, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))






async def _fetch_disk_consumers_local(depth: int = 1) -> List[Dict[str, Any]]:
    """Get top disk space consumers for localhost via du on all top-level directories.

    Args:
        depth: 1 = top-level only (/*), 2 = top-level + children for top 5 dirs
    """
    import asyncio
    import os
    import shutil

    skip_prefixes = {"/proc", "/sys", "/dev", "/run"}
    du_cmd = r"du -sh /* 2>/dev/null | grep -vE '^0\s+(/proc|/sys|/dev|/run)'"

    async def _run_du(shell_cmd: str) -> str:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "bash", "-c", shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=20.0,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode()

    def _parse_records(stdout_str: str) -> List[Dict[str, Any]]:
        records = []
        for line in stdout_str.strip().splitlines():
            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue
            size_human, path = parts
            if any(path.startswith(p) for p in skip_prefixes):
                continue
            records.append({
                "path": path,
                "size_human": size_human.replace(",", "."),
                "size_bytes": _parse_du_size(size_human.replace(",", ".")),
            })
        return records

    try:
        stdout_str = ""
        if shutil.which("sudo"):
            try:
                stdout_str = await _run_du(f"sudo -n {du_cmd}")
            except Exception:
                stdout_str = ""
        if not stdout_str:
            stdout_str = await _run_du(du_cmd)

        records = _parse_records(stdout_str)
        records.sort(key=lambda x: x["size_bytes"], reverse=True)
        records = records[:15]

        if depth >= 2 and records:
            # Fetch children for top 5 largest directories (one level deeper)
            top_dirs = [r["path"] for r in records[:5] if r["size_bytes"] > 0]
            if top_dirs:
                # Build a single du command for all top dirs' children
                # Quote paths to handle spaces
                quoted = " ".join(f"{p}/*" for p in top_dirs)
                deep_cmd = rf"du -sh {quoted} 2>/dev/null | grep -vE '^0\s+'"
                try:
                    deep_stdout = await _run_du(deep_cmd)
                    deep_records = _parse_records(deep_stdout)
                    # Group children by parent
                    children_by_parent: Dict[str, List[Dict[str, Any]]] = {}
                    for child in deep_records:
                        child_path = child["path"]
                        # Find which parent this belongs to
                        for parent in top_dirs:
                            if child_path.startswith(parent + "/"):
                                children_by_parent.setdefault(parent, []).append(child)
                                break
                    # Attach sorted children (top 10 per parent)
                    for parent, children in children_by_parent.items():
                        children.sort(key=lambda x: x["size_bytes"], reverse=True)
                        parent_record = next((r for r in records if r["path"] == parent), None)
                        if parent_record:
                            parent_record["children"] = children[:10]
                            parent_record["has_children"] = True
                except Exception as e:
                    logger.debug("disk_consumers_local_deep_failed", error=str(e))

        return records
    except Exception as e:
        logger.debug("disk_consumers_local_failed", error=str(e))
        return []




async def _fetch_disk_consumers_ansible(host: str, depth: int = 1) -> List[Dict[str, Any]]:
    """Fetch top disk consumers via Ansible ad-hoc for remote hosts.

    Args:
        depth: 1 = top-level only (/*), 2 = top-level + children for top 5 dirs
    """
    try:
        import asyncio
        import shutil
        import os

        if not shutil.which("ansible"):
            return []

        settings = get_settings()
        ssh_key = settings.ansible_ssh_key or ""
        ssh_password = settings.ansible_ssh_password or ""
        ssh_port = settings.ansible_ssh_port or 22
        target_user = settings.ansible_remote_user or "root"

        env = os.environ.copy()
        env["ANSIBLE_HOST_KEY_CHECKING"] = "False"

        ssh_password = settings.ansible_ssh_password or ""
        become_password = settings.ansible_become_password or ssh_password
        extra_vars = f"ansible_user={target_user} ansible_ssh_port={ssh_port}"
        if ssh_password:
            extra_vars += f" ansible_ssh_pass='{ssh_password}'"
        if become_password:
            extra_vars += f" ansible_become_pass='{become_password}'"
        if ssh_key:
            extra_vars += f" ansible_ssh_private_key_file='{ssh_key}'"

        du_cmd = r"du -sh /* 2>/dev/null | grep -vE '^0\s+(/proc|/sys|/dev|/run)'"

        target = _resolve_ansible_host(host)

        cmd = [
            "ansible",
            "-i", f"{target},",
            "all",
            "-b",
            "-m", "shell",
            "-a", du_cmd,
            "-e", extra_vars,
            "--timeout", "25",
        ]

        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            ),
            timeout=20.0,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20.0)
        if proc.returncode != 0:
            return []

        def _parse_records(stdout_str: str) -> List[Dict[str, Any]]:
            records = []
            skip_prefixes = {"/proc", "/sys", "/dev", "/run"}
            for line in stdout_str.splitlines():
                # Skip ansible summary lines
                if target in line or host in line or line.strip().startswith(">>>") or line.strip().startswith("changed="):
                    continue
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    size_human, path = parts
                    if any(path.startswith(p) for p in skip_prefixes):
                        continue
                    records.append({
                        "path": path,
                        "size_human": size_human.replace(",", "."),
                        "size_bytes": _parse_du_size(size_human.replace(",", ".")),
                    })
            return records

        records = _parse_records(stdout.decode())
        records.sort(key=lambda x: x["size_bytes"], reverse=True)
        records = records[:15]

        if depth >= 2 and records:
            top_dirs = [r["path"] for r in records[:5] if r["size_bytes"] > 0]
            if top_dirs:
                quoted = " ".join(f"{p}/*" for p in top_dirs)
                deep_cmd = rf"du -sh {quoted} 2>/dev/null | grep -vE '^0\s+'"
                deep_cmd_list = [
                    "ansible",
                    "-i", f"{target},",
                    "all",
                    "-b",
                    "-m", "shell",
                    "-a", deep_cmd,
                    "-e", extra_vars,
                    "--timeout", "30",
                ]
                try:
                    deep_proc = await asyncio.wait_for(
                        asyncio.create_subprocess_exec(
                            *deep_cmd_list,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            env=env,
                        ),
                        timeout=25.0,
                    )
                    deep_stdout, _ = await deep_proc.communicate()
                    if deep_proc.returncode == 0:
                        deep_records = _parse_records(deep_stdout.decode())
                        children_by_parent: Dict[str, List[Dict[str, Any]]] = {}
                        for child in deep_records:
                            child_path = child["path"]
                            for parent in top_dirs:
                                if child_path.startswith(parent + "/"):
                                    children_by_parent.setdefault(parent, []).append(child)
                                    break
                        for parent, children in children_by_parent.items():
                            children.sort(key=lambda x: x["size_bytes"], reverse=True)
                            parent_record = next((r for r in records if r["path"] == parent), None)
                            if parent_record:
                                parent_record["children"] = children[:10]
                                parent_record["has_children"] = True
                except Exception as e:
                    logger.debug("disk_consumers_ansible_deep_failed", host=host, error=str(e))

        return records
    except Exception as e:
        logger.debug("disk_consumers_ansible_failed", host=host, error=str(e))
        return []


async def _get_disk_consumers(host: str, depth: int = 1) -> List[Dict[str, Any]]:
    """Try to get top disk space consumers for a host. Prefers localhost du, falls back to Ansible."""
    import socket
    try:
        local_names = {"127.0.0.1", "localhost", "::1", socket.gethostname(), socket.getfqdn()}
        if host in local_names:
            return await _fetch_disk_consumers_local(depth=depth)
    except Exception:
        pass

    # Try Ansible for remote hosts
    ansible_result = await _fetch_disk_consumers_ansible(host, depth=depth)
    if ansible_result:
        return ansible_result

    return []


@router.get("/{host}/disk-analysis")
async def get_host_disk_analysis(
    host: str,
    depth: int = Query(1, ge=1, le=2, description="Directory depth: 1=top-level, 2=includes children for top 5 dirs")
) -> Dict[str, Any]:
    """Get detailed disk analysis for a host including exact consumers and heuristics."""
    import re

    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*$", host):
        raise HTTPException(status_code=400, detail="Invalid hostname format")

    if len(host) > 255:
        raise HTTPException(status_code=400, detail="Hostname too long")

    settings = get_settings()
    if not settings.performance_enabled:
        raise HTTPException(status_code=503, detail="Performance monitoring disabled")

    # Try Redis first
    disk_devices: List[Dict[str, Any]] = []
    top_processes: List[Dict[str, Any]] = []
    disk_dirs: List[Dict[str, Any]] = []
    timestamp = ""
    try:
        from core.redis_performance import performance_redis
        redis_data = await performance_redis.get_current_metrics(host)
        if redis_data:
            metrics = redis_data.get("metrics", {})
            disk_devices = metrics.get("disk_devices", [])
            top_processes = metrics.get("top_processes", [])
            disk_dirs = metrics.get("disk_dirs", [])
            timestamp = redis_data.get("timestamp", "")
    except Exception as e:
        logger.warning("disk_analysis_redis_failed", host=host, error=str(e))

    # Fallback to poller live cache if Redis missing or stale
    if not disk_dirs:
        cached = performance_poller.get_cached_metrics()
        if host in cached:
            m = cached[host]
            disk_devices = m.disk_devices if m.disk_devices else disk_devices
            top_processes = m.top_processes if m.top_processes else top_processes
            disk_dirs = m.disk_dirs if m.disk_dirs else []
            timestamp = m.timestamp if m.timestamp else timestamp

    # If still no data, trigger a live poll
    if not disk_dirs and not disk_devices:
        try:
            from datetime import datetime, timezone
            poller = PerformancePoller()
            metrics_dict = await poller.poll_once()
            if host in metrics_dict:
                m = metrics_dict[host]
                disk_devices = m.disk_devices
                top_processes = m.top_processes
                disk_dirs = m.disk_dirs
                timestamp = m.timestamp
            else:
                raise HTTPException(status_code=404, detail=f"Host {host} not found")
        except HTTPException:
            raise
        except Exception as e:
            logger.error("disk_analysis_poll_failed", host=host, error=str(e))
            raise HTTPException(status_code=500, detail=f"Failed to poll metrics for {host}")

    # Prefer telegraf disk_dirs if present and depth==1; otherwise fall back to live fetch for deeper analysis
    if disk_dirs and depth == 1:
        # Ensure consistent shape
        normalized_dirs = []
        for d in disk_dirs:
            normalized_dirs.append({
                "path": d.get("path", ""),
                "size_human": d.get("size_human", ""),
                "size_bytes": _parse_du_size(d.get("size_human", "0")),
            })
        normalized_dirs.sort(key=lambda x: x["size_bytes"], reverse=True)
        return {
            "hostname": host,
            "disk_devices": disk_devices,
            "disk_consumers": normalized_dirs,
            "disk_heuristics": [],
            "timestamp": timestamp,
        }

    disk_consumers = await _get_disk_consumers(host, depth=depth)

    # If live fetch returned nothing, fall back to telegraf disk_dirs
    if not disk_consumers and disk_dirs:
        normalized_dirs = []
        for d in disk_dirs:
            normalized_dirs.append({
                "path": d.get("path", ""),
                "size_human": d.get("size_human", ""),
                "size_bytes": _parse_du_size(d.get("size_human", "0")),
            })
        normalized_dirs.sort(key=lambda x: x["size_bytes"], reverse=True)
        disk_consumers = normalized_dirs

    disk_heuristics = _get_disk_heuristics(disk_devices, top_processes)
    return {
        "hostname": host,
        "disk_devices": disk_devices,
        "disk_consumers": disk_consumers,
        "disk_heuristics": disk_heuristics,
        "timestamp": timestamp,
    }


@router.get("/{host}/history")
async def get_host_history(
    host: str, metric: str = "cpu", limit: int = 100
) -> Dict[str, Any]:
    """Get historical metrics for a host."""
    # Input validation
    import re

    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*$", host):
        raise HTTPException(status_code=400, detail="Invalid hostname format")

    # Validate limit
    if limit < 1:
        limit = 1
    if limit > 1000:
        limit = 1000  # Cap at reasonable maximum

    # Validate metric
    valid_metrics = ["cpu", "memory", "disk", "network", "load"]
    if metric not in valid_metrics:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid metric. Must be one of: {', '.join(valid_metrics)}",
        )

    from core.redis_performance import get_performance_metrics_history

    try:
        history = await get_performance_metrics_history(host, metric, limit)

        # Reverse so charts render oldest -> newest left-to-right
        history = list(reversed(history))
        return {
            "host": host,
            "metric": metric,
            "data_points": [
                {"timestamp": point.timestamp, "value": point.value}
                for point in history
            ],
            "count": len(history),
        }

    except Exception as e:
        logger.error("get_history_failed", host=host, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{host}/root-cause")
async def get_root_cause_analysis(host: str) -> Dict[str, Any]:
    """Get AI root cause analysis for a host."""
    # Input validation
    import re

    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*$", host):
        raise HTTPException(status_code=400, detail="Invalid hostname format")

    try:
        from core.redis_performance import performance_redis

        settings = get_settings()

        # Try Redis first
        redis_data = await performance_redis.get_current_metrics(host)

        if not redis_data:
            raise HTTPException(status_code=404, detail=f"Host {host} not found")

        metrics = redis_data.get("metrics", {})

        # Determine current issues based on thresholds
        current_issues = []

        # CPU check
        cpu = metrics.get("cpu_usage_percent", 0)
        if cpu >= settings.performance_cpu_critical:
            current_issues.append(
                {
                    "type": "cpu_high",
                    "severity": "critical",
                    "value": round(cpu, 1),
                    "threshold": settings.performance_cpu_critical,
                    "message": f"CPU usage at {cpu:.1f}%",
                }
            )
        elif cpu >= settings.performance_cpu_warning:
            current_issues.append(
                {
                    "type": "cpu_high",
                    "severity": "warning",
                    "value": round(cpu, 1),
                    "threshold": settings.performance_cpu_warning,
                    "message": f"CPU usage at {cpu:.1f}%",
                }
            )

        # Memory check
        mem_used = metrics.get("memory_used_percent", 0)
        if mem_used >= settings.performance_memory_critical:
            current_issues.append(
                {
                    "type": "memory_high",
                    "severity": "critical",
                    "value": round(mem_used, 1),
                    "threshold": settings.performance_memory_critical,
                    "message": f"Memory usage at {mem_used:.1f}%",
                }
            )
        elif mem_used >= settings.performance_memory_warning:
            current_issues.append(
                {
                    "type": "memory_high",
                    "severity": "warning",
                    "value": round(mem_used, 1),
                    "threshold": settings.performance_memory_warning,
                    "message": f"Memory usage at {mem_used:.1f}%",
                }
            )

        # Disk check
        for disk in metrics.get("disk_devices", []):
            used_pct = disk.get("used_percent", 0)
            path = disk.get("path", "/")
            if used_pct >= settings.performance_disk_critical:
                current_issues.append(
                    {
                        "type": "disk_full",
                        "severity": "critical",
                        "value": round(used_pct, 1),
                        "threshold": settings.performance_disk_critical,
                        "path": path,
                        "message": f"Disk {path} at {used_pct:.1f}%",
                    }
                )
            elif used_pct >= settings.performance_disk_warning:
                current_issues.append(
                    {
                        "type": "disk_full",
                        "severity": "warning",
                        "value": round(used_pct, 1),
                        "threshold": settings.performance_disk_warning,
                        "path": path,
                        "message": f"Disk {path} at {used_pct:.1f}%",
                    }
                )

        # Get recent alerts for context
        recent_alerts = await performance_redis.get_alert_history(host=host, limit=5)

        # Generate AI analysis based on current issues
        root_cause = ""
        recommended_action = ""
        confidence = 0.0

        if current_issues:
            issues_summary = ", ".join([i["message"] for i in current_issues])

            # Generate analysis based on issue type
            if any("cpu" in i["type"] for i in current_issues):
                cpu_issue = next(
                    (i for i in current_issues if "cpu" in i["type"]), None
                )
                top_processes = metrics.get("top_processes", [])
                if cpu_issue and top_processes:
                    top_proc = top_processes[0] if top_processes else {}
                    proc_name = top_proc.get("name", "unknown")
                    root_cause = f"High CPU usage ({cpu_issue['value']}%) likely caused by {proc_name} process consuming excessive resources."
                    recommended_action = f"Identify and restart the {proc_name} process, or scale the service if resource-intensive."
                    confidence = 0.85
                elif cpu_issue:
                    root_cause = (
                        f"High CPU usage ({cpu_issue['value']}%) detected on {host}."
                    )
                    recommended_action = "Review running processes and identify resource-intensive services."
                    confidence = 0.75
                else:
                    root_cause = f"CPU issue detected on {host}."
                    recommended_action = "Review running processes."
                    confidence = 0.70

            elif any("memory" in i["type"] for i in current_issues):
                mem_issue = next(
                    (i for i in current_issues if "memory" in i["type"]), None
                )
                if mem_issue:
                    root_cause = f"High memory usage ({mem_issue['value']}%) indicating possible memory leak or insufficient resources."
                    recommended_action = (
                        "Clear cache, restart memory-intensive services, or add more RAM."
                    )
                    confidence = 0.80
                else:
                    root_cause = f"Memory issue detected on {host}."
                    recommended_action = "Investigate memory usage."
                    confidence = 0.75

            elif any("disk" in i["type"] for i in current_issues):
                disk_issue = next(
                    (i for i in current_issues if "disk" in i["type"]), None
                )
                if disk_issue:
                    root_cause = f"Low disk space on {disk_issue['path']} ({disk_issue['value']}%) - likely caused by accumulated log files, temporary files, or data growth."
                    recommended_action = f"Clean up old logs, remove temporary files, or expand disk storage on {disk_issue['path']}."
                    confidence = 0.90
                else:
                    root_cause = f"Disk space issue detected on {host}."
                    recommended_action = "Investigate disk usage."
                    confidence = 0.85
        else:
            root_cause = "No performance issues detected. System operating within normal parameters."
            recommended_action = "Continue monitoring."
            confidence = 1.0

        top_processes = metrics.get("top_processes", [])

        return {
            "host": host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "current_issues": current_issues,
            "root_cause": root_cause,
            "confidence": confidence,
            "recommended_action": recommended_action,
            "recent_alerts": len(recent_alerts),
            "top_processes": top_processes[:5] if top_processes else [],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_root_cause_failed", host=host, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))












@router.get("/{host}/relationships")
async def get_host_relationships(host: str) -> Dict[str, Any]:
    """Get host metrics + performance alerts + investigations."""
    import re

    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*$", host):
        raise HTTPException(status_code=400, detail="Invalid hostname format")

    settings = get_settings()

    # Get host metrics from Redis first, fallback to poller cache
    host_metrics = None
    try:
        from core.redis_performance import performance_redis
        redis_data = await performance_redis.get_current_metrics(host)
        if redis_data:
            host_metrics = redis_data.get("metrics", {})
    except Exception as e:
        logger.warning("redis_relationships_failed", host=host, error=str(e))
    
    if not host_metrics:
        metrics_dict = performance_poller.get_cached_metrics()
        cached = metrics_dict.get(host)
        if cached:
            host_metrics = cached

    # Get performance alerts for this host
    try:
        from core.redis_performance import performance_redis

        perf_alerts = await performance_redis.get_alert_history(host=host, limit=50)
    except:
        perf_alerts = []

    # Get investigations for this host
    from response.db import AsyncSessionLocal
    from response.models import Investigation
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation).where(Investigation.target_host == host)
        )
        investigations = list(result.scalars().all())

    if isinstance(host_metrics, dict):
        metrics_out = {
            "cpu_usage_percent": host_metrics.get("cpu_usage_percent"),
            "memory_used_percent": host_metrics.get("memory_used_percent"),
            "disk_devices": [
                {"device": d.get("device", "unknown"), "used_percent": d.get("used_percent", 0)}
                for d in host_metrics.get("disk_devices", [])
            ],
        }
    else:
        if host_metrics and hasattr(host_metrics, "disk_devices"):
            metrics_out = {
                "cpu_usage_percent": host_metrics.cpu_usage_percent,
                "memory_used_percent": host_metrics.memory_used_percent,
                "disk_devices": [
                    {"device": d.get("device", "unknown"), "used_percent": d.get("used_percent", 0)}
                    for d in host_metrics.disk_devices
                ],
            }
        else:
            metrics_out = None

    return {
        "host": host,
        "metrics": metrics_out,
        "performance_alerts": {"count": len(perf_alerts), "items": perf_alerts[:5]},
        "investigations": {
            "count": len(investigations),
            "items": [
                {
                    "id": i.id,
                    "status": i.status,
                    "incident_title": i.incident_title[:60],
                    "created_at": i.created_at.isoformat(),
                }
                for i in investigations[:5]
            ],
        },
        "relationships": {
            "metrics": f"/api/v1/metrics/{host}",
            "alerts": f"/api/v1/metrics/{host}/alerts",
            "investigations": f"/api/v1/metrics/{host}/investigations",
            "history": f"/api/v1/metrics/{host}/history",
            "root_cause": f"/api/v1/metrics/{host}/root-cause",
        },
    }


@router.get("/{host}/alerts")
async def get_host_performance_alerts(
    host: str, severity: Optional[str] = Query(None), limit: int = Query(50, le=200)
) -> Dict[str, Any]:
    """Get performance alerts for specific host."""
    import re

    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*$", host):
        raise HTTPException(status_code=400, detail="Invalid hostname format")

    try:
        from core.redis_performance import performance_redis

        alerts = await performance_redis.get_alert_history(
            host=host, severity=severity, limit=limit
        )
        return {"host": host, "alerts": alerts, "total": len(alerts)}
    except Exception as e:
        logger.error("get_host_alerts_failed", host=host, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{host}/investigations")
async def get_host_investigations(
    host: str, limit: int = Query(50, le=200)
) -> Dict[str, Any]:
    """Get investigations triggered by this host."""
    import re

    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*$", host):
        raise HTTPException(status_code=400, detail="Invalid hostname format")

    from response.db import AsyncSessionLocal
    from response.models import Investigation
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation)
            .where(
                Investigation.target_host == host,
                Investigation.investigation_type == "infrastructure",
            )
            .order_by(Investigation.created_at.desc())
            .limit(limit)
        )
        investigations = result.scalars().all()

    return {
        "host": host,
        "investigations": [
            {
                "id": i.id,
                "status": i.status,
                "incident_title": i.incident_title,
                "incident_severity": i.incident_severity,
                "created_at": i.created_at.isoformat(),
                "updated_at": i.updated_at.isoformat(),
            }
            for i in investigations
        ],
        "total": len(investigations),
    }
