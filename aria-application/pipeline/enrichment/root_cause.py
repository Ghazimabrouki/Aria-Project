"""
Performance Root Cause Analyzer.

Analyzes performance anomalies using AI to determine root cause.
Part of the Server Performance Monitoring System (v1.0).
"""

import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

import structlog
from config import get_settings
from pipeline.performance_poller import HostMetrics
from response.ai_engine import _call_llm

logger = structlog.get_logger()


@dataclass
class RootCauseResult:
    """Result of root cause analysis."""
    explanation: str
    confidence: float
    affected_process: Optional[Dict[str, Any]]
    evidence: List[str]
    remediation_type: str


class RootCauseAnalyzer:
    """Analyzes root cause of performance issues using AI."""
    
    def __init__(self):
        self.settings = get_settings()
    
    async def analyze_cpu_high(
        self,
        metrics: HostMetrics,
        current_value: float
    ) -> RootCauseResult:
        """Analyze high CPU usage root cause."""
        
        prompt = f"""You are a server performance analyst. Analyze this high CPU situation.

Host: {metrics.hostname}
Current CPU: {current_value}%
CPU breakdown: user={metrics.cpu_user_percent}%, system={metrics.cpu_system_percent}%, iowait={metrics.cpu_iowait_percent}%

System state:
- Load average: 1m={metrics.load_1}, 5m={metrics.load_5}, 15m={metrics.load_15} (CPUs: {metrics.n_cpus})
- Processes: running={metrics.proc_running}, sleeping={metrics.proc_sleeping}, total={metrics.proc_total}, threads={metrics.proc_threads}
- Network connections: TCP established={metrics.tcp_established}, listen={metrics.tcp_listen}, UDP={metrics.udp_socket}
- Memory: {metrics.memory_used_percent}%

Based on this data, determine:
1. What is likely causing the high CPU?
2. Which process/service is responsible?
3. What evidence supports this?

Respond in JSON format:
{{
    "explanation": "specific explanation of root cause",
    "confidence": 0.0-1.0,
    "process_name": "name of affected process or null",
    "process_pid": "PID or null", 
    "evidence": ["list of evidence points"],
    "remediation_type": "restart_service|clear_memory|scale|investigate"
}}"""
        
        try:
            result = await asyncio.wait_for(
                _call_llm(prompt),
                timeout=30
            )
            
            # Parse JSON response
            try:
                if isinstance(result, str):
                    import json
                    result = json.loads(result)
                if isinstance(result, dict):
                    return RootCauseResult(
                        explanation=result.get("explanation", "High CPU detected"),
                        confidence=result.get("confidence", 0.5),
                        affected_process={
                            "name": result.get("process_name"),
                            "pid": result.get("process_pid")
                        } if result.get("process_name") else None,
                        evidence=result.get("evidence", []),
                        remediation_type=result.get("remediation_type", "investigate")
                    )
            except (json.JSONDecodeError, AttributeError):
                pass
            
            # Fallback if parsing fails
            return RootCauseResult(
                explanation=str(result)[:200] if result else "High CPU detected",
                confidence=0.3,
                affected_process=None,
                evidence=["AI response received"],
                remediation_type="investigate"
            )
        except asyncio.TimeoutError:
            logger.warning("ai_root_cause_timeout", host=metrics.hostname)
            return RootCauseResult(
                explanation=f"High CPU ({current_value}%) detected on {metrics.hostname}",
                confidence=0.3,
                affected_process=None,
                evidence=[f"CPU at {current_value}%"],
                remediation_type="investigate"
            )
        except Exception as e:
            logger.error("ai_root_cause_failed", host=metrics.hostname, error=str(e))
            return RootCauseResult(
                explanation=f"High CPU ({current_value}%) detected on {metrics.hostname}",
                confidence=0.2,
                affected_process=None,
                evidence=[f"CPU at {current_value}%"],
                remediation_type="investigate"
            )
    
    async def analyze_memory_high(
        self,
        metrics: HostMetrics,
        current_value: float
    ) -> RootCauseResult:
        """Analyze high memory usage root cause."""
        
        prompt = f"""You are a server performance analyst. Analyze this high memory situation.

Host: {metrics.hostname}
Current Memory: {current_value}%
Memory: used={metrics.memory_used_bytes / 1024 / 1024 / 1024:.1f}GB, available={metrics.memory_available_bytes / 1024 / 1024 / 1024:.1f}GB
CPU: {metrics.cpu_usage_percent}%

System state:
- Load average: 1m={metrics.load_1}, 5m={metrics.load_5}, 15m={metrics.load_15} (CPUs: {metrics.n_cpus})
- Processes: running={metrics.proc_running}, sleeping={metrics.proc_sleeping}, total={metrics.proc_total}, threads={metrics.proc_threads}
- Network connections: TCP established={metrics.tcp_established}, listen={metrics.tcp_listen}, UDP={metrics.udp_socket}

Determine:
1. What is likely causing high memory?
2. Which process/service is responsible?
3. What evidence supports this?

Respond in JSON format:
{{
    "explanation": "specific explanation of root cause",
    "confidence": 0.0-1.0,
    "process_name": "name of affected process or null",
    "process_pid": "PID or null",
    "evidence": ["list of evidence points"],
    "remediation_type": "restart_service|clear_cache|scale|investigate"
}}"""
        
        try:
            result = await asyncio.wait_for(
                _call_llm(prompt),
                timeout=30
            )
            
            try:
                if isinstance(result, str):
                    import json
                    result = json.loads(result)
                if isinstance(result, dict):
                    return RootCauseResult(
                        explanation=result.get("explanation", "High memory detected"),
                        confidence=result.get("confidence", 0.5),
                        affected_process={
                            "name": result.get("process_name"),
                            "pid": result.get("process_pid")
                        } if result.get("process_name") else None,
                        evidence=result.get("evidence", []),
                        remediation_type=result.get("remediation_type", "investigate")
                    )
            except (json.JSONDecodeError, AttributeError):
                pass
            
            return RootCauseResult(
                explanation=str(result)[:200] if result else "High memory detected",
                confidence=0.3,
                affected_process=None,
                evidence=["AI response received"],
                remediation_type="investigate"
            )
        except Exception as e:
            logger.error("ai_root_cause_failed", host=metrics.hostname, error=str(e))
            return RootCauseResult(
                explanation=f"High memory ({current_value}%) detected on {metrics.hostname}",
                confidence=0.2,
                affected_process=None,
                evidence=[f"Memory at {current_value}%"],
                remediation_type="investigate"
            )
    
    async def analyze_disk_full(
        self,
        metrics: HostMetrics,
        device: str,
        current_value: float
    ) -> RootCauseResult:
        """Analyze disk full root cause."""
        
        prompt = f"""You are a server performance analyst. Analyze this disk space issue.

Host: {metrics.hostname}
Disk device: {device}
Current usage: {current_value}%

Disk info:
{self._format_disk_info(metrics.disk_devices)}

Determine:
1. What is likely filling the disk?
2. What evidence supports this?
3. What should be cleaned?

Respond in JSON format:
{{
    "explanation": "specific explanation of root cause",
    "confidence": 0.0-1.0,
    "evidence": ["list of evidence points"],
    "remediation_type": "clean_logs|clean_temp|resize_disk|investigate"
}}"""
        
        try:
            result = await asyncio.wait_for(
                _call_llm(prompt),
                timeout=30
            )
            
            try:
                if isinstance(result, str):
                    import json
                    result = json.loads(result)
                if isinstance(result, dict):
                    return RootCauseResult(
                        explanation=result.get("explanation", f"Disk {device} at {current_value}%"),
                        confidence=result.get("confidence", 0.5),
                        affected_process=None,
                        evidence=result.get("evidence", []),
                        remediation_type=result.get("remediation_type", "investigate")
                    )
            except (json.JSONDecodeError, AttributeError):
                pass
            
            return RootCauseResult(
                explanation=str(result)[:200] if result else f"Disk {device} at {current_value}%",
                confidence=0.3,
                affected_process=None,
                evidence=["AI response received"],
                remediation_type="investigate"
            )
        except Exception as e:
            logger.error("ai_root_cause_failed", host=metrics.hostname, error=str(e))
            return RootCauseResult(
                explanation=f"Disk {device} at {current_value}% on {metrics.hostname}",
                confidence=0.2,
                affected_process=None,
                evidence=[f"Disk {device} at {current_value}%"],
                remediation_type="investigate"
            )
    
    async def analyze_anomaly(
        self,
        metrics: HostMetrics,
        anomaly_type: str,
        current_value: float,
        device: str = None
    ) -> RootCauseResult:
        """Main entry point for root cause analysis."""
        
        if not self.settings.performance_anomaly_use_ai:
            # Return simple explanation without AI
            return RootCauseResult(
                explanation=f"{anomaly_type.replace('_', ' ').title()} detected at {current_value}% on {metrics.hostname}",
                confidence=0.3,
                affected_process=None,
                evidence=[f"{anomaly_type} at {current_value}%"],
                remediation_type="investigate"
            )
        
        if "cpu" in anomaly_type.lower():
            return await self.analyze_cpu_high(metrics, current_value)
        elif "memory" in anomaly_type.lower():
            return await self.analyze_memory_high(metrics, current_value)
        elif "disk" in anomaly_type.lower():
            return await self.analyze_disk_full(metrics, device or "unknown", current_value)
        else:
            return RootCauseResult(
                explanation=f"Performance issue detected on {metrics.hostname}",
                confidence=0.2,
                affected_process=None,
                evidence=[f"{anomaly_type} at {current_value}%"],
                remediation_type="investigate"
            )
    
    def _format_process_info(self, processes: List[Dict]) -> str:
        """Format process info for AI prompt."""
        if not processes:
            return "No process data available"
        
        lines = []
        for p in processes[:5]:
            state = p.get("state", "unknown")
            count = p.get("count", 0)
            lines.append(f"- {state}: {count}")
        
        return "\n".join(lines)
    
    def _format_disk_info(self, disks: List[Dict]) -> str:
        """Format disk info for AI prompt."""
        if not disks:
            return "No disk data available"
        
        lines = []
        for d in disks:
            device = d.get("device", "unknown")
            used = d.get("used_percent", 0)
            lines.append(f"- {device}: {used}%")
        
        return "\n".join(lines)


# Singleton instance
root_cause_analyzer = RootCauseAnalyzer()


async def analyze_performance_root_cause(
    metrics: HostMetrics,
    anomaly_type: str,
    current_value: float,
    device: str = None
) -> RootCauseResult:
    """Helper function to analyze root cause."""
    return await root_cause_analyzer.analyze_anomaly(
        metrics=metrics,
        anomaly_type=anomaly_type,
        current_value=current_value,
        device=device
    )