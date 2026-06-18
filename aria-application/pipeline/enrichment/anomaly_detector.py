"""
Performance Anomaly Detector.

Hybrid anomaly detection: threshold + statistical + AI.
Part of the Server Performance Monitoring System (v1.0).
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

import structlog
from config import get_settings
from pipeline.performance_poller import HostMetrics
from core.redis_performance import performance_redis

logger = structlog.get_logger()


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    NORMAL = "normal"
    WARNING = "warning"
    CRITICAL = "critical"


class AnomalyType(str, Enum):
    """Types of performance anomalies."""
    CPU_HIGH = "cpu_high"
    MEMORY_HIGH = "memory_high"
    DISK_FULL = "disk_full"
    DISK_INODES = "disk_inodes"
    NETWORK_HIGH = "network_high"
    PROCESS_ISSUE = "process_issue"
    STATISTICAL = "statistical"


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    is_anomaly: bool
    severity: str  # normal, warning, critical
    anomaly_type: Optional[str] = None
    reason: str = ""
    value: float = 0.0
    threshold: float = 0.0
    deviation: Optional[float] = None


@dataclass
class PerformanceAlert:
    """Performance alert to be created."""
    source: str = "performance"
    title: str = ""
    severity: str = "warning"
    host: str = ""
    hostname: str = ""
    anomaly_type: str = ""
    
    # What happened
    metrics: Dict[str, Any] = None
    
    # Why (to be filled by root cause analyzer)
    root_cause: str = ""
    confidence: float = 0.0
    evidence: List[str] = None
    affected_process: Dict[str, Any] = None
    
    # Recommended action
    recommended_action: str = ""
    auto_remediable: bool = False
    
    # Tags
    tags: List[str] = None
    
    def __post_init__(self):
        if self.metrics is None:
            self.metrics = {}
        if self.evidence is None:
            self.evidence = []
        if self.affected_process is None:
            self.affected_process = {}
        if self.tags is None:
            self.tags = []


class AnomalyDetector:
    """Hybrid anomaly detector using threshold + statistical + AI methods."""
    
    def __init__(self):
        self.settings = get_settings()
    
    def _check_threshold(
        self,
        current_value: float,
        warning_threshold: float,
        critical_threshold: float
    ) -> Tuple[bool, str, float]:
        """Check if value exceeds threshold."""
        if current_value >= critical_threshold:
            return True, AlertSeverity.CRITICAL, critical_threshold
        elif current_value >= warning_threshold:
            return True, AlertSeverity.WARNING, warning_threshold
        return False, AlertSeverity.NORMAL, warning_threshold
    
    def _check_statistical_anomaly(
        self,
        current_value: float,
        baseline: Optional[Dict]
    ) -> Tuple[bool, str, float]:
        """Check if value deviates statistically from baseline."""
        if not baseline:
            return False, "", 0.0
        
        mean = baseline.get("mean", 0)
        std = baseline.get("std", 0)
        
        if std == 0:
            return False, "", 0.0
        
        deviation = abs(current_value - mean) / std
        
        if deviation > self.settings.performance_anomaly_stddev_threshold:
            # > 3 standard deviations
            severity = AlertSeverity.CRITICAL if deviation > 5 else AlertSeverity.WARNING
            return True, severity, deviation
        
        # Also check p95
        p95 = baseline.get("p95", 0)
        if current_value > p95:
            return True, AlertSeverity.WARNING, p95
        
        return False, "", 0.0
    
    async def detect_cpu_anomaly(self, metrics: HostMetrics) -> AnomalyResult:
        """Detect CPU anomalies."""
        cpu = metrics.cpu_usage_percent
        
        # Check threshold
        is_anomaly, severity, threshold = self._check_threshold(
            cpu,
            self.settings.performance_cpu_warning,
            self.settings.performance_cpu_critical
        )
        
        if is_anomaly:
            return AnomalyResult(
                is_anomaly=True,
                severity=severity,
                anomaly_type=AnomalyType.CPU_HIGH,
                reason=f"CPU at {cpu:.1f}% (threshold: {threshold}%)",
                value=cpu,
                threshold=threshold
            )
        
        # Check statistical if enabled
        if self.settings.performance_anomaly_use_statistical:
            baseline = await performance_redis.get_baseline(metrics.hostname, "cpu")
            if baseline:
                is_stat, stat_severity, deviation = self._check_statistical_anomaly(cpu, baseline)
                if is_stat:
                    return AnomalyResult(
                        is_anomaly=True,
                        severity=stat_severity,
                        anomaly_type=AnomalyType.STATISTICAL,
                        reason=f"CPU at {cpu:.1f}% is {deviation:.1f}σ from baseline ({baseline['mean']:.1f}%)",
                        value=cpu,
                        threshold=baseline["p95"],
                        deviation=deviation
                    )
        
        return AnomalyResult(is_anomaly=False, severity=AlertSeverity.NORMAL)
    
    async def detect_memory_anomaly(self, metrics: HostMetrics) -> AnomalyResult:
        """Detect Memory anomalies."""
        mem = metrics.memory_used_percent
        
        is_anomaly, severity, threshold = self._check_threshold(
            mem,
            self.settings.performance_memory_warning,
            self.settings.performance_memory_critical
        )
        
        if is_anomaly:
            return AnomalyResult(
                is_anomaly=True,
                severity=severity,
                anomaly_type=AnomalyType.MEMORY_HIGH,
                reason=f"Memory at {mem:.1f}% (threshold: {threshold}%)",
                value=mem,
                threshold=threshold
            )
        
        # Statistical check
        if self.settings.performance_anomaly_use_statistical:
            baseline = await performance_redis.get_baseline(metrics.hostname, "memory")
            if baseline:
                is_stat, stat_severity, deviation = self._check_statistical_anomaly(mem, baseline)
                if is_stat:
                    return AnomalyResult(
                        is_anomaly=True,
                        severity=stat_severity,
                        anomaly_type=AnomalyType.STATISTICAL,
                        reason=f"Memory at {mem:.1f}% is {deviation:.1f}σ from baseline",
                        value=mem,
                        threshold=baseline["p95"],
                        deviation=deviation
                    )
        
        return AnomalyResult(is_anomaly=False, severity=AlertSeverity.NORMAL)
    
    async def detect_disk_anomaly(self, metrics: HostMetrics) -> AnomalyResult:
        """Detect Disk anomalies."""
        # Check all disk devices
        worst_device = None
        worst_usage = 0
        
        for device in metrics.disk_devices:
            usage = device.get("used_percent", 0)
            inodes = device.get("inodes_used_percent", 0)
            
            # Check usage
            is_anomaly, severity, threshold = self._check_threshold(
                usage,
                self.settings.performance_disk_warning,
                self.settings.performance_disk_critical
            )
            
            if is_anomaly and usage > worst_usage:
                worst_usage = usage
                worst_device = device.get("device", "unknown")
                result = AnomalyResult(
                    is_anomaly=True,
                    severity=severity,
                    anomaly_type=AnomalyType.DISK_FULL,
                    reason=f"Disk {device.get('device')} at {usage:.1f}% (threshold: {threshold}%)",
                    value=usage,
                    threshold=threshold
                )
            
            # Check inodes
            is_anomaly_inodes, severity_inodes, threshold_inodes = self._check_threshold(
                inodes,
                self.settings.performance_disk_inodes_warning,
                self.settings.performance_disk_inodes_critical
            )
            
            if is_anomaly_inodes and inodes > worst_usage:
                worst_usage = inodes
                worst_device = device.get("device", "unknown")
                result = AnomalyResult(
                    is_anomaly=True,
                    severity=severity_inodes,
                    anomaly_type=AnomalyType.DISK_INODES,
                    reason=f"Inodes on {device.get('device')} at {inodes:.1f}%",
                    value=inodes,
                    threshold=threshold_inodes
                )
        
        if worst_device:
            return result
        
        return AnomalyResult(is_anomaly=False, severity=AlertSeverity.NORMAL)
    
    async def detect_load_anomaly(self, metrics: HostMetrics) -> AnomalyResult:
        """Detect high load average anomalies."""
        load = metrics.load_1
        n_cpus = metrics.n_cpus or 1
        
        normalized_load = load / n_cpus
        
        if normalized_load > 4.0:
            return AnomalyResult(
                is_anomaly=True,
                severity=AlertSeverity.CRITICAL,
                anomaly_type=AnomalyType.PROCESS_ISSUE,
                reason=f"Load average {load:.2f} on {n_cpus} CPUs (normalized: {normalized_load:.2f})",
                value=load,
                threshold=4.0 * n_cpus
            )
        elif normalized_load > 2.5:
            return AnomalyResult(
                is_anomaly=True,
                severity=AlertSeverity.WARNING,
                anomaly_type=AnomalyType.PROCESS_ISSUE,
                reason=f"Load average {load:.2f} on {n_cpus} CPUs (normalized: {normalized_load:.2f})",
                value=load,
                threshold=2.5 * n_cpus
            )
        
        return AnomalyResult(is_anomaly=False, severity=AlertSeverity.NORMAL)
    
    async def detect_network_anomaly(self, metrics: HostMetrics) -> AnomalyResult:
        """Detect Network anomalies."""
        bytes_recv = metrics.network_bytes_recv
        
        # Compute rate using previous history point
        rate = 0.0
        try:
            history = await performance_redis.get_history(metrics.hostname, "network", limit=1)
            if history:
                prev_point = history[0]
                prev_bytes = float(prev_point.value)
                prev_time = datetime.fromisoformat(prev_point.timestamp.replace("Z", "+00:00"))
                curr_time = datetime.fromisoformat(metrics.timestamp.replace("Z", "+00:00")) if metrics.timestamp else datetime.now(timezone.utc)
                delta_seconds = max((curr_time - prev_time).total_seconds(), 1.0)
                rate = max((bytes_recv - prev_bytes) / delta_seconds, 0.0)
        except Exception:
            rate = 0.0
        
        is_anomaly, severity, threshold = self._check_threshold(
            rate,
            self.settings.performance_network_in_warning,
            self.settings.performance_network_in_critical
        )
        
        if is_anomaly:
            return AnomalyResult(
                is_anomaly=True,
                severity=severity,
                anomaly_type=AnomalyType.NETWORK_HIGH,
                reason=f"Network incoming at {rate/1024/1024:.1f} MB/s (threshold: {threshold/1024/1024:.1f} MB/s)",
                value=rate,
                threshold=threshold
            )
        
        return AnomalyResult(is_anomaly=False, severity=AlertSeverity.NORMAL)
    
    async def detect_all(self, metrics: HostMetrics) -> List[AnomalyResult]:
        """Run all anomaly detection methods for a host."""
        results = []
        
        # Run each detector
        cpu_result = await self.detect_cpu_anomaly(metrics)
        if cpu_result.is_anomaly:
            results.append(cpu_result)
        
        mem_result = await self.detect_memory_anomaly(metrics)
        if mem_result.is_anomaly:
            results.append(mem_result)
        
        disk_result = await self.detect_disk_anomaly(metrics)
        if disk_result.is_anomaly:
            results.append(disk_result)
        
        load_result = await self.detect_load_anomaly(metrics)
        if load_result.is_anomaly:
            results.append(load_result)
        
        net_result = await self.detect_network_anomaly(metrics)
        if net_result.is_anomaly:
            results.append(net_result)
        
        return results
    
    def get_worst_severity(self, results: List[AnomalyResult]) -> str:
        """Get worst severity from results."""
        if not results:
            return AlertSeverity.NORMAL
        
        severities = [r.severity for r in results]
        
        if AlertSeverity.CRITICAL in severities:
            return AlertSeverity.CRITICAL
        elif AlertSeverity.WARNING in severities:
            return AlertSeverity.WARNING
        else:
            return AlertSeverity.NORMAL
    
    async def should_create_alert(self, host: str, anomaly_type: str) -> bool:
        """Check if alert should be created (cooldown check)."""
        return not await performance_redis.is_in_cooldown(host, anomaly_type)
    
    async def set_alert_cooldown(self, host: str, anomaly_type: str) -> None:
        """Set cooldown after creating alert."""
        await performance_redis.set_alert_cooldown(host, anomaly_type)


# Singleton instance
anomaly_detector = AnomalyDetector()


# Helper function
async def detect_performance_anomalies(metrics: HostMetrics) -> List[AnomalyResult]:
    """Detect all anomalies for a host's metrics."""
    return await anomaly_detector.detect_all(metrics)