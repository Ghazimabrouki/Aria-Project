"""
Performance Notifications.

Sends performance alerts to Slack and other channels.
Part of the Server Performance Monitoring System (v1.0).
"""

import asyncio
import structlog
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from config import get_settings
from pipeline.alerts.performance_alert import PerformanceAlertGenerator

logger = structlog.get_logger()

_slack_client = None


def _get_slack_client():
    """Get or create Slack client."""
    global _slack_client
    if _slack_client is None:
        try:
            import aiohttp
            _slack_client = aiohttp.ClientSession()
        except Exception as e:
            logger.warning("slack_client_init_failed", error=str(e))
    return _slack_client


async def send_performance_notification(alert: Dict[str, Any]) -> bool:
    """Send performance alert notification to configured channels."""
    settings = get_settings()
    
    if not settings.performance_notify_slack:
        return False
    
    try:
        await _send_slack_notification(alert, settings)
        return True
    except Exception as e:
        logger.error("performance_notification_failed", error=str(e), host=alert.get("host"))
        return False


async def _send_slack_notification(alert: Dict[str, Any], settings) -> None:
    """Send Slack notification for performance alert."""
    webhook_url = getattr(settings, 'slack_webhook_url', None) or _get_slack_webhook_from_env()
    
    if not webhook_url:
        logger.debug("slack_webhook_not_configured")
        return
    
    severity_emoji = {
        "low": "ℹ️",
        "medium": "⚠️",
        "high": "🔴",
        "critical": "🚨"
    }
    
    emoji = severity_emoji.get(alert.get("severity", "medium"), "⚠️")
    
    color_map = {
        "low": "#36a64f",
        "medium": "#ff9900",
        "high": "#ff6600",
        "critical": "#ff0000"
    }
    color = color_map.get(alert.get("severity", "medium"), "#ff9900")
    
    cpu_current = alert.get("metrics", {}).get("cpu", {}).get("current", "N/A")
    cpu_threshold = alert.get("metrics", {}).get("cpu", {}).get("critical_threshold", "N/A")
    mem_current = alert.get("metrics", {}).get("memory", {}).get("current", "N/A")
    mem_threshold = alert.get("metrics", {}).get("memory", {}).get("critical_threshold", "N/A")
    
    slack_payload = {
        "channel": settings.performance_slack_channel,
        "username": "OpenSOAR Performance Monitor",
        "icon_emoji": ":chart_with_upwards_trend:",
        "attachments": [{
            "color": color,
            "title": f"{emoji} Performance Alert: {alert.get('title', 'Unknown')}",
            "text": alert.get("root_cause", "No root cause information"),
            "fields": [
                {"title": "Host", "value": alert.get("host", "unknown"), "short": True},
                {"title": "Severity", "value": alert.get("severity", "medium").upper(), "short": True},
                {"title": "Type", "value": alert.get("anomaly_type", "unknown"), "short": True},
                {"title": "CPU", "value": f"{cpu_current}% (threshold: {cpu_threshold}%)", "short": True},
                {"title": "Memory", "value": f"{mem_current}% (threshold: {mem_threshold}%)", "short": True},
            ],
            "footer": "OpenSOAR Performance Monitoring",
            "ts": int(datetime.now(timezone.utc).timestamp())
        }]
    }
    
    client = _get_slack_client()
    if client:
        async with client.post(webhook_url, json=slack_payload) as resp:
            if resp.status == 200:
                logger.info("slack_notification_sent", host=alert.get("host"))
            else:
                logger.warning("slack_notification_failed", status=resp.status)


def _get_slack_webhook_from_env() -> Optional[str]:
    """Get Slack webhook URL from environment."""
    import os
    return os.environ.get("SLACK_WEBHOOK_URL")


async def send_resolution_notification(incident_id: str, host: str, alert_type: str) -> bool:
    """Send notification when performance incident is resolved."""
    settings = get_settings()
    
    if not settings.performance_notify_slack:
        return False
    
    try:
        webhook_url = _get_slack_webhook_from_env()
        if not webhook_url:
            return False
        
        client = _get_slack_client()
        if not client:
            return False
        
        slack_payload = {
            "channel": settings.performance_slack_channel,
            "username": "OpenSOAR Performance Monitor",
            "icon_emoji": ":white_check_mark:",
            "text": f"✅ Performance incident resolved: {alert_type} on {host}\nIncident ID: {incident_id}"
        }
        
        async with client.post(webhook_url, json=slack_payload) as resp:
            return resp.status == 200
        
    except Exception as e:
        logger.error("resolution_notification_failed", error=str(e))
        return False