"""
Performance Auto-Approve Rules.

Extends auto_approve.py for performance-specific incidents.
Part of the Server Performance Monitoring System (v1.0).
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import structlog

from config import get_settings
from response.db import AsyncSessionLocal
from response.models import Investigation

logger = structlog.get_logger()

PERFORMANCE_AUTO_APPROVE_TYPES = [
    "cpu_high_nginx",
    "cpu_high_apache",
    "memory_high_redis",
    "disk_full_logs",
    "disk_full_temp",
]


async def should_auto_approve_performance(
    alert_data: Dict[str, Any]
) -> tuple[bool, str]:
    """
    Determine if a performance alert should be auto-approved.
    
    Returns:
        (should_auto_approve, reason)
    """
    settings = get_settings()
    
    if not settings.performance_auto_remediate_enabled:
        return False, "performance_auto_remediate_disabled"
    
    anomaly_type = alert_data.get("anomaly_type", "")
    host = alert_data.get("host", "")
    severity = alert_data.get("severity", "medium")
    auto_remediable = alert_data.get("auto_remediable", False)
    
    if not auto_remediable:
        return False, "not_auto_remediable"
    
    if anomaly_type not in settings.performance_auto_remediate_types_list:
        return False, "anomaly_type_not_in_allowlist"
    
    if severity not in ["medium", "high", "critical"]:
        return False, "severity_too_low"
    
    logger.info(
        "performance_auto_approve_decision",
        host=host,
        anomaly_type=anomaly_type,
        severity=severity,
        decision="auto_approve"
    )
    
    return True, f"auto_approved_{anomaly_type}"


async def create_performance_investigation(
    alert_data: Dict[str, Any],
    playbook: str
) -> Optional[str]:
    """Create an investigation for auto-approved performance alert."""
    
    from response.db import AsyncSessionLocal
    from response.models import Investigation
    
    settings = get_settings()
    
    async with AsyncSessionLocal() as session:
        investigation = Investigation(
            title=f"Performance Auto-Remediate: {alert_data.get('anomaly_type', 'unknown')} on {alert_data.get('host', 'unknown')}",
            description=f"""## Performance Incident

**Host:** {alert_data.get('host')}
**Type:** {alert_data.get('anomaly_type')}
**Severity:** {alert_data.get('severity')}
**Current Value:** {alert_data.get('metrics', {}).get('cpu', {}).get('current', 'N/A')}%
**Threshold:** {alert_data.get('metrics', {}).get('cpu', {}).get('critical_threshold', 'N/A')}%

### Root Cause
{alert_data.get('root_cause', 'Analysis pending')}

### Recommended Action
Auto-approved remediation for known issue pattern.
""",
            status="pending_approval",
            incident_id=alert_data.get("incident_id", ""),
            incident_severity=alert_data.get("severity", "medium"),
            alert_count=1,
            playbook=playbook,
            playbook_valid=True,
            run_status="pending",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        
        session.add(investigation)
        await session.commit()
        await session.refresh(investigation)
        
        logger.info(
            "performance_investigation_created",
            investigation_id=investigation.id,
            alert_id=alert_data.get("id")
        )
        
        return investigation.id


async def apply_auto_approve_for_performance(
    alert_data: Dict[str, Any]
) -> Optional[str]:
    """
    Check if performance alert should be auto-approved and create investigation.
    
    Returns:
        Investigation ID if created, None otherwise
    """
    should_approve, reason = await should_auto_approve_performance(alert_data)
    
    if not should_approve:
        logger.debug("performance_not_auto_approved", reason=reason, host=alert_data.get("host"))
        return None
    
    from pipeline.response.performance_playbook import generate_performance_playbook
    
    playbook = await generate_performance_playbook(
        alert_type=alert_data.get("anomaly_type", ""),
        host=alert_data.get("host", ""),
        metrics=alert_data.get("metrics", {})
    )
    
    if not playbook:
        logger.error("performance_playbook_generation_failed", host=alert_data.get("host"))
        return None
    
    investigation_id = await create_performance_investigation(alert_data, playbook)
    
    if investigation_id:
        from response.ansible_exec import execute_playbook
        asyncio.create_task(execute_playbook(investigation_id))
        
        logger.info("performance_auto_remediation_triggered", investigation_id=investigation_id)
    
    return investigation_id