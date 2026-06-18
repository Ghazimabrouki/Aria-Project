"""
Performance Alert Generator.

Generates performance alerts from detected anomalies.
Part of the Server Performance Monitoring System (v1.0).
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

import structlog
from config import get_settings
from pipeline.enrichment.anomaly_detector import AnomalyResult, AlertSeverity, AnomalyType

logger = structlog.get_logger()


class PerformanceAlertGenerator:
    """Generates performance alerts from anomaly results."""
    
    ROOT_CAUSE_TEMPLATES = {
        AnomalyType.CPU_HIGH: {
            "template": "High CPU usage detected on host",
            "process_patterns": {
                "nginx": "nginx worker processes consuming high CPU due to slowloris attack or high traffic",
                "java": "Java process consuming high CPU due to possible infinite loop or high load",
                "apache": "Apache worker processes consuming high CPU",
                "postgres": "PostgreSQL query consuming high CPU",
                "mysql": "MySQL query consuming high CPU",
                "redis": "Redis operations consuming high CPU"
            }
        },
        AnomalyType.MEMORY_HIGH: {
            "template": "High memory usage detected on host",
            "process_patterns": {
                "java": "Java heap memory leak or high garbage collection overhead",
                "redis": "Redis dataset consuming high memory",
                "postgres": "PostgreSQL buffer pool consuming high memory",
                "nginx": "nginx worker processes consuming high memory"
            }
        },
        AnomalyType.DISK_FULL: {
            "template": "Disk space running low on host",
            "patterns": {
                "logs": "Application logs consuming excessive disk space",
                "temp": "Temporary files not being cleaned up",
                "data": "Database data files consuming disk space",
                "containers": "Docker containers consuming disk space"
            }
        },
        AnomalyType.DISK_INODES: {
            "template": "Inodes exhausted on host",
            "patterns": {
                "small_files": "Many small files (cache, temp) exhausting inodes"
            }
        },
        AnomalyType.NETWORK_HIGH: {
            "template": "High network traffic detected on host",
            "patterns": {
                "ddos": "Possible DDoS attack - incoming traffic spike",
                "data_transfer": "Large data transfer in progress",
                "backup": "Backup operations causing network spike"
            }
        }
    }
    
    def __init__(self):
        self.settings = get_settings()
    
    def _determine_auto_remediable(self, anomaly_type: str, evidence: List[str]) -> bool:
        """Determine if this anomaly can be auto-remediated."""
        auto_types = self.settings.performance_auto_remediate_types_list
        
        # Check by anomaly type - flexible matching
        # e.g., "disk_full" matches "disk_full_root", "disk_full_var_log"
        for auto_type in auto_types:
            # Check if auto_type is a prefix of anomaly_type or vice versa
            if auto_type in anomaly_type or anomaly_type in auto_type:
                return True
        
        # Check by evidence keywords
        auto_keywords = ["restart", "clear", "clean", "restart service", "truncate", "prune"]
        for keyword in auto_keywords:
            for e in evidence:
                if keyword.lower() in e.lower():
                    return True
        
        return False
    
    def _generate_recommended_action(self, anomaly_type: str, metrics: Dict) -> str:
        """Generate recommended action based on anomaly type."""
        actions = {
            AnomalyType.CPU_HIGH: "Analyze top processes, restart high-CPU service, consider scaling",
            AnomalyType.MEMORY_HIGH: "Analyze memory usage, restart service, clear cache, add swap",
            AnomalyType.DISK_FULL: "Clean old logs, remove temporary files, resize disk partition",
            AnomalyType.DISK_INODES: "Delete small files, clear package cache, remove old logs",
            AnomalyType.NETWORK_HIGH: "Check for attack, rate limit connections, block suspicious IPs"
        }
        
        return actions.get(anomaly_type, "Analyze and determine appropriate action")
    
    def _map_anomaly_type_to_incident_type(self, anomaly_type: str) -> str:
        """Map anomaly type to incident type."""
        mapping = {
            AnomalyType.CPU_HIGH: "cpu_high",
            AnomalyType.MEMORY_HIGH: "memory_high",
            AnomalyType.DISK_FULL: "disk_full",
            AnomalyType.DISK_INODES: "disk_inodes",
            AnomalyType.NETWORK_HIGH: "network_high",
            AnomalyType.STATISTICAL: "anomaly_detected",
            AnomalyType.PROCESS_ISSUE: "process_issue"
        }
        return mapping.get(anomaly_type, "performance_issue")
    
    def generate_alert(
        self,
        host: str,
        hostname: str,
        anomaly_result: AnomalyResult,
        metrics: Dict,
        root_cause: str = "",
        confidence: float = 0.5,
        evidence: List[str] = None,
        affected_process: Dict = None,
        asset_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a performance alert."""
        
        if evidence is None:
            evidence = []
        if affected_process is None:
            affected_process = {}
        
        anomaly_type = anomaly_result.anomaly_type or AnomalyType.PROCESS_ISSUE
        auto_remediable = self._determine_auto_remediable(anomaly_type.value, evidence)
        recommended_action = self._generate_recommended_action(anomaly_type, metrics)
        
        # Build severity mapping
        severity_map = {
            "normal": "low",
            "warning": "medium",
            "critical": "high"
        }
        
        incident_severity = severity_map.get(anomaly_result.severity, "medium")
        
        # Check if meets minimum severity for incident
        min_severity = self.settings.performance_incident_min_severity
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        
        if severity_order.get(incident_severity, 0) < severity_order.get(min_severity, 0):
            # Don't create incident for low severity
            logger.info(
                "alert_below_min_severity",
                severity=incident_severity,
                minimum=min_severity
            )
            return None
        
        # Build tags
        tags = [
            f"host:{host}",
            f"type:{anomaly_type.value}",
            f"severity:{incident_severity}",
            "source:performance"
        ]
        
        # Add process tag if applicable
        if affected_process and affected_process.get("name"):
            tags.append(f"process:{affected_process['name']}")
        
        # Build alert - enhance with partition details for disk alerts
        alert_title = f"Performance Alert - {anomaly_result.reason}"
        
        # For disk alerts, add more context
        if anomaly_type == AnomalyType.DISK_FULL and metrics.get("disk_devices"):
            worst_disk = None
            worst_usage = 0
            for d in metrics.get("disk_devices", []):
                usage = d.get("used_percent", 0)
                if usage > worst_usage:
                    worst_usage = usage
                    worst_disk = d
            
            if worst_disk and worst_disk.get("path"):
                path = worst_disk.get("path", "/")
                fstype = worst_disk.get("fstype", "")
                free_gb = worst_disk.get("free_bytes", 0) / 1024 / 1024 / 1024
                alert_title = f"Performance Alert - Disk {path} ({fstype}) at {worst_usage:.1f}% - {free_gb:.1f}GB free"
        
        alert = {
            "id": str(uuid.uuid4()),
            "source": "performance",
            "title": alert_title,
            "severity": incident_severity,
            "host": host,
            "hostname": hostname,
            "asset_id": asset_id,
            "anomaly_type": self._map_anomaly_type_to_incident_type(anomaly_type),
            
            "metrics": {
                "cpu": {
                    "current": metrics.get("cpu_usage_percent", 0),
                    "warning_threshold": self.settings.performance_cpu_warning,
                    "critical_threshold": self.settings.performance_cpu_critical
                },
                "memory": {
                    "current": metrics.get("memory_used_percent", 0),
                    "warning_threshold": self.settings.performance_memory_warning,
                    "critical_threshold": self.settings.performance_memory_critical
                },
                "disk": metrics.get("disk_devices", []),
                "network": {
                    "bytes_recv": metrics.get("network_bytes_recv", 0)
                },
                "load": {
                    "load1": metrics.get("load_1", 0),
                    "load5": metrics.get("load_5", 0),
                    "load15": metrics.get("load_15", 0),
                    "n_cpus": metrics.get("n_cpus", 0)
                },
                "processes": {
                    "running": metrics.get("proc_running", 0),
                    "sleeping": metrics.get("proc_sleeping", 0),
                    "total": metrics.get("proc_total", 0),
                    "threads": metrics.get("proc_threads", 0)
                },
                "connections": {
                    "tcp_established": metrics.get("tcp_established", 0),
                    "tcp_listen": metrics.get("tcp_listen", 0),
                    "udp_socket": metrics.get("udp_socket", 0)
                }
            },
            
            "root_cause": root_cause or anomaly_result.reason,
            "confidence": confidence,
            "evidence": evidence,
            "affected_process": affected_process,
            
            "recommended_action": recommended_action,
            "auto_remediable": auto_remediable,
            
            "tags": tags,
            
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(
            "performance_alert_generated",
            host=host,
            anomaly_type=anomaly_type.value,
            severity=incident_severity,
            auto_remediable=auto_remediable,
            asset_id=asset_id,
        )
        
        return alert


# Singleton instance
performance_alert_generator = PerformanceAlertGenerator()


def create_performance_alert(
    host: str,
    hostname: str,
    anomaly_result: AnomalyResult,
    metrics: Dict,
    root_cause: str = "",
    confidence: float = 0.5,
    evidence: List[str] = None,
    affected_process: Dict = None,
    asset_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Helper function to create a performance alert."""
    return performance_alert_generator.generate_alert(
        host=host,
        hostname=hostname,
        anomaly_result=anomaly_result,
        metrics=metrics,
        root_cause=root_cause,
        confidence=confidence,
        evidence=evidence,
        affected_process=affected_process,
        asset_id=asset_id,
    )