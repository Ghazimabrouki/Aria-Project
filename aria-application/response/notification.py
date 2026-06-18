"""
Notification system for sending alerts when human approval is needed.

Sends notifications to:
- Slack (via webhook)
- Email (via SMTP)

Triggered when AI finishes processing and status changes to awaiting_approval.
"""
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog

from config import get_settings

logger = structlog.get_logger()
settings = get_settings()


async def send_approval_notification(investigation_id: str, incident_title: str,
                                      risk_score: int, attack_type: str, 
                                      target_host: Optional[str], source_ips: list) -> bool:
    """
    Send notification when AI analysis is complete and needs human approval.
    
    Returns True if at least one notification channel succeeded.
    """
    success = False
    
    # Build notification message
    title = f"🚨 Security Incident Needs Approval"
    message = _build_message(investigation_id, incident_title, risk_score, attack_type, 
                            target_host, source_ips)
    
    # Send to Slack
    if settings.slack_webhook_url:
        try:
            slack_success = await _send_slack(settings.slack_webhook_url, title, message)
            if slack_success:
                logger.info("slack_notification_sent", investigation_id=investigation_id)
                success = True
        except Exception as e:
            logger.warning("slack_notification_failed", investigation_id=investigation_id, error=str(e))
    
    # Send to email
    if settings.smtp_host and settings.smtp_from:
        try:
            email_success = await _send_email(
                to_addresses=settings.notification_email.split(",") if hasattr(settings, 'notification_email') and settings.notification_email else ([settings.notification_default_email] if settings.notification_default_email else []),
                subject=title,
                body=message
            )
            if email_success:
                logger.info("email_notification_sent", investigation_id=investigation_id)
                success = True
        except Exception as e:
            logger.warning("email_notification_failed", investigation_id=investigation_id, error=str(e))
    
    return success


def _build_message(investigation_id: str, incident_title: str, 
                   risk_score: int, attack_type: str,
                   target_host: Optional[str], source_ips: list) -> str:
    """Build formatted notification message."""
    
    risk_emoji = "🔴" if risk_score >= 70 else "🟡" if risk_score >= 40 else "🟢"
    
    message = f"""
*OpenSOAR Incident Approval Required*

*Investigation ID:* `{investigation_id}`
*Incident:* {incident_title}

*Risk Score:* {risk_emoji} {risk_score}/100
*Attack Type:* {attack_type.replace('_', ' ').title()}
*Target Host:* {target_host or 'Unknown'}
*Attacker IPs:* {', '.join(source_ips[:3]) if source_ips else 'Unknown'}

*Action Required:* Review and approve the remediation playbook.

*OpenSOAR URL:* {settings.notification_base_url}/investigations/{investigation_id}/approve

---
_This is an automated notification from OpenSOAR Backend_
"""
    return message.strip()


async def _send_slack(webhook_url: str, title: str, message: str) -> bool:
    """Send notification to Slack."""
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": title}
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": message}
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View in OpenSOAR"},
                    "style": "primary",
                    "url": f"{settings.notification_base_url}/investigations"
                }
            ]
        }
    ]
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(webhook_url, json={"blocks": blocks})
        return resp.status_code == 200


async def _send_email(to_addresses: list, subject: str, body: str) -> bool:
    """Send notification via email."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    msg = MIMEMultipart()
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(to_addresses)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    
    try:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port or 587)
        if settings.smtp_user and settings.smtp_password:
            server.starttls()
            server.login(settings.smtp_user, settings.smtp_password)
        server.sendmail(settings.smtp_from, to_addresses, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        logger.warning("smtp_error", error=str(e))
        return False


async def send_remediation_complete_notification(investigation_id: str, 
                                                 incident_title: str,
                                                 fix_status: str,
                                                 details: str) -> bool:
    """Send notification when remediation is complete."""
    
    status_emoji = "✅" if fix_status == "likely_fixed" else "⚠️" if fix_status == "inconclusive" else "❌"
    
    message = f"""
*Remediation {fix_status.upper()}*

*Investigation:* {incident_title}
*Status:* {status_emoji} {fix_status}
*Details:* {details}

*View in OpenSOAR:* {settings.notification_base_url}/investigations/{investigation_id}
"""
    
    success = False
    
    if settings.slack_webhook_url:
        try:
            await _send_slack(settings.slack_webhook_url, "Remediation Complete", message.strip())
            success = True
        except Exception as e:
            logger.debug("remediation_notification_error", error=str(e))
    
    return success


async def send_pipeline_failure_notification(stage: str, error: str, details: str = "") -> bool:
    """Send notification when a pipeline stage fails."""
    
    message = f"""
*⚠️ Pipeline Failure Alert*

*Stage:* {stage}
*Error:* {error}
*Details:* {details if details else 'No additional details'}

*Time:* {datetime.now(timezone.utc).isoformat()}
*Server:* {settings.notification_base_url}
"""
    
    success = False
    
    if settings.slack_webhook_url:
        try:
            await _send_slack(settings.slack_webhook_url, "Pipeline Failure", message.strip())
            success = True
            logger.info("pipeline_failure_notification_sent", stage=stage, error=error[:100])
        except Exception as e:
            logger.warning("pipeline_failure_notification_failed", stage=stage, error=str(e))
    
    # Also send email if configured
    if settings.smtp_host and settings.smtp_from:
        try:
            await _send_email(
                to_addresses=settings.notification_email_to or settings.smtp_from,
                subject=f"[ALERT] Pipeline Failure - {stage}",
                body=message.strip()
            )
        except Exception as e:
            logger.warning("pipeline_failure_email_failed", stage=stage, error=str(e))
    
    return success


async def send_stuck_investigation_alert(investigation_id: str, status: str, 
                                          hours_stuck: float, severity: str) -> bool:
    """Send detailed notification when an investigation is stuck for too long."""
    
    # Get full investigation details
    from response.db import AsyncSessionLocal
    from sqlalchemy import select
    from response.models import Investigation
    
    emoji = "🔴" if severity == "high" else "🟡" if severity == "medium" else "🟢"
    
    # Fetch full details from DB
    inv = None
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Investigation).where(Investigation.id == investigation_id)
            )
            inv = result.scalar_one_or_none()
    except Exception as e:
        logger.warning("failed_to_fetch_investigation", error=str(e))
    
    # Build detailed message
    title = f"⏰ Investigation Needs Approval - {severity.upper()}"
    
    if inv:
        # AI Summary
        ai_summary = inv.ai_summary[:300] + "..." if inv.ai_summary and len(inv.ai_summary) > 300 else inv.ai_summary or "No summary"
        
        # Playbook preview
        playbook_preview = ""
        if inv.playbook_yaml:
            playbook_lines = inv.playbook_yaml.split('\n')[:15]
            playbook_preview = "```yaml\n" + "\n".join(playbook_lines) + "\n```"
            if len(inv.playbook_yaml.split('\n')) > 15:
                playbook_preview += "\n*... (full playbook in OpenSOAR)*"
        
        # Risk and context
        risk_info = f"*{inv.ai_risk or 'No risk assessment'}*"
        
        message = f"""
*Investigation ID:* `{investigation_id}`
*Severity:* {emoji} {severity.upper()}
*Status:* {status}
*Time Stuck:* {hours_stuck:.1f} hours
*Target Host:* {inv.target_host or 'Unknown'}
*Source IPs:* {inv.source_ips[:100] if inv.source_ips else 'Unknown'}

*AI Summary:*
{ai_summary}

*Risk Assessment:*
{risk_info}

*Playbook Preview:*
{playbook_preview}

*Action Required:* Review and approve the playbook to remediate this incident.
"""
    else:
        message = f"""
*Investigation ID:* `{investigation_id}`
*Severity:* {emoji} {severity.upper()}
*Status:* {status}
*Time Stuck:* {hours_stuck:.1f} hours

*Action Required:* Review in OpenSOAR.
"""
    
    success = False
    
    if settings.slack_webhook_url:
        try:
            # Use our approval UI - shows full details + Approve/Decline buttons
            approval_url = f"{settings.backend_url}/approve/{investigation_id}"
            
            # Create rich Slack message with action buttons
            blocks = [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": title}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message.strip()}
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "✅ Review & Approve", "emoji": True},
                            "style": "primary",
                            "url": approval_url
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "📊 Stats", "emoji": True},
                            "url": f"{settings.backend_url}/monitor/stats"
                        }
                    ]
                }
            ]
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(settings.slack_webhook_url, json={"blocks": blocks})
                if resp.status_code == 200:
                    success = True
                    logger.info("stuck_investigation_alert_sent", investigation_id=investigation_id, hours=hours_stuck)
        except Exception as e:
            logger.warning("stuck_investigation_alert_failed", investigation_id=investigation_id, error=str(e))
    
    # Also send email if configured
    if settings.smtp_host and settings.smtp_from:
        try:
            await _send_email(
                to_addresses=settings.notification_email_to or settings.smtp_from,
                subject=f"[ACTION REQUIRED] Investigation Needs Approval - {investigation_id[:8]}",
                body=message.strip()
            )
        except Exception as e:
            logger.warning("stuck_investigation_email_failed", investigation_id=investigation_id, error=str(e))
    
    return success


async def send_auto_approve_notification(investigation_id: str, result) -> bool:
    """
    Send notification when an investigation is auto-approved and playbook is executing.
    
    Args:
        investigation_id: Investigation ID
        result: AutoApproveResult from auto_approve.py
    """
    if not settings.auto_approve_notify_on_auto:
        return False
    
    # Get investigation details for notification
    from response.db import AsyncSessionLocal
    from response.models import Investigation
    from sqlalchemy import select
    
    async with AsyncSessionLocal() as session:
        result_db = await session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        inv = result_db.scalar_one_or_none()
        
        if not inv:
            return False
        
        incident_title = inv.incident_title or "Unknown"
        target_host = inv.target_host or "Unknown"
    
    # Build notification message
    title = "✅ Investigation Auto-Approved"
    
    confidence_emoji = "🟢" if result.confidence > 0.8 else "🟡" if result.confidence > 0.5 else "⚪"
    
    message = f"""
*Investigation Auto-Approved & Executing*

*Investigation ID:* `{investigation_id}`
*Incident:* {incident_title}

*Decision Source:* {result.decision_source}
*Confidence:* {confidence_emoji} {result.confidence:.0%}
*Reason:* {result.reason}

*Target Host:* {target_host}

*View in OpenSOAR:* {settings.notification_base_url}/investigations/{investigation_id}

---
_This incident was automatically approved and remediation is now executing._
"""
    
    success = False
    
    if settings.slack_webhook_url:
        try:
            blocks = [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": title}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message.strip()}
                }
            ]
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(settings.slack_webhook_url, json={"blocks": blocks})
                if resp.status_code == 200:
                    success = True
                    logger.info("auto_approve_notification_sent", investigation_id=investigation_id)
        except Exception as e:
            logger.warning("auto_approve_notification_failed", investigation_id=investigation_id, error=str(e))
    
    return success