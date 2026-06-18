"""
Auto-Approve System.

Hybrid approach combining:
1. Static guardrails - never auto-approve
2. Static pass - always auto-approve  
3. Dynamic learning - adapt based on history
4. AI confidence - optional AI evaluation

Decision flow:
  AI completes → Static Guardrails → Static Pass → Dynamic → AI Confidence → Decision
"""

import asyncio
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any

import structlog

from config import get_settings
from response.db import AsyncSessionLocal
from response.models import Investigation

logger = structlog.get_logger()


def _get_settings():
    """Get settings - call this to avoid module-level loading issues."""
    return get_settings()


class AutoApproveResult:
    """Result of auto-approve decision."""
    
    def __init__(
        self,
        should_auto_approve: bool,
        reason: str,
        confidence: float = 0.0,
        decision_source: str = "static",
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.should_auto_approve = should_auto_approve
        self.reason = reason
        self.confidence = confidence
        self.decision_source = decision_source
        self.metadata = metadata or {}


async def should_auto_approve(investigation_id: str) -> AutoApproveResult:
    """
    Determine if investigation should be auto-approved.
    
    Returns:
        AutoApproveResult with decision details
    """
    settings = _get_settings()
    
    if not settings.auto_approve_enabled:
        return AutoApproveResult(
            should_auto_approve=False,
            reason="auto_approve_disabled",
            decision_source="disabled"
        )
    
    # Blanket auto-approve: bypass ALL guardrails/criteria and approve everything
    if getattr(settings, "auto_approve_all_enabled", False):
        return AutoApproveResult(
            should_auto_approve=True,
            reason="auto_approve_all_enabled",
            confidence=1.0,
            decision_source="all_enabled"
        )
    
    async with AsyncSessionLocal() as session:
        from sqlalchemy import select
        result = await session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        investigation = result.scalar_one_or_none()
        
        if not investigation:
            return AutoApproveResult(
                should_auto_approve=False,
                reason="investigation_not_found",
                decision_source="error"
            )
        
        return await _evaluate_investigation(investigation)


async def _evaluate_investigation(inv: Investigation) -> AutoApproveResult:
    """Evaluate an investigation for auto-approve."""
    settings = _get_settings()
    
    # Extract severity and risk_score from incident
    severity = (inv.incident_severity or "medium").lower()
    risk_score = _estimate_risk_from_investigation(inv)
    attack_type = _extract_attack_type(inv)
    alert_count = await _count_alerts_async(inv)
    
    logger.info(
        "auto_approve_evaluation",
        investigation_id=inv.id,
        severity=severity,
        risk_score=risk_score,
        attack_type=attack_type,
        alert_count=alert_count
    )
    
    # 1. Check static guardrails (never auto-approve)
    guardrail_result = _check_guardrails(
        severity=severity,
        risk_score=risk_score,
        attack_type=attack_type,
        investigation=inv
    )
    if guardrail_result.should_block:
        return AutoApproveResult(
            should_auto_approve=False,
            reason=guardrail_result.reason,
            confidence=1.0,
            decision_source="guardrail",
            metadata=guardrail_result.metadata
        )
    
    # 2. Check static pass criteria (always auto-approve)
    static_pass = _check_static_pass(
        severity=severity,
        risk_score=risk_score,
        alert_count=alert_count
    )
    if static_pass:
        logger.info(
            "auto_approve_static_pass",
            investigation_id=inv.id,
            reason="meets_static_criteria"
        )
        
        # Log decision for audit
        await _log_decision(
            investigation_id=inv.id,
            decision=True,
            reason="static_pass",
            source="static"
        )
        
        return AutoApproveResult(
            should_auto_approve=True,
            reason="meets_static_criteria",
            confidence=0.95,
            decision_source="static",
            metadata={"severity": severity, "risk_score": risk_score}
        )
    
    # 3. Dynamic learning (if enabled and has enough data)
    dynamic_result = None
    if settings.auto_approve_dynamic_enabled:
        try:
            dynamic_result = await _check_dynamic(
                severity=severity,
                risk_score=risk_score,
                attack_type=attack_type,
                alert_count=alert_count
            )
        except Exception as e:
            logger.warning("dynamic_check_error", error=str(e))
    
    if dynamic_result and dynamic_result.should_approve is not None:
            logger.info(
                "auto_approve_dynamic",
                investigation_id=inv.id,
                decision=dynamic_result.should_approve,
                source="dynamic"
            )
            
            await _log_decision(
                investigation_id=inv.id,
                decision=dynamic_result.should_approve,
                reason=f"dynamic_{dynamic_result.reason}",
                source="dynamic"
            )
            
            return AutoApproveResult(
                should_auto_approve=dynamic_result.should_approve,
                reason=f"dynamic_{dynamic_result.reason}",
                confidence=dynamic_result.confidence,
                decision_source="dynamic",
                metadata=dynamic_result.metadata
            )
    
    # 4. AI confidence (if enabled)
    if settings.auto_approve_ai_enabled:
        ai_result = await _check_ai_confidence(inv)
        if ai_result.should_approve is not None:
            logger.info(
                "auto_approve_ai",
                investigation_id=inv.id,
                confidence=ai_result.confidence,
                threshold=settings.auto_approve_ai_threshold
            )
            
            await _log_decision(
                investigation_id=inv.id,
                decision=ai_result.should_approve,
                reason=f"ai_confidence_{ai_result.confidence}",
                source="ai"
            )
            
            return AutoApproveResult(
                should_auto_approve=ai_result.should_approve,
                reason=f"ai_confidence_{ai_result.confidence:.2f}",
                confidence=ai_result.confidence,
                decision_source="ai",
                metadata=ai_result.metadata
            )
    
    # No criteria met - requires human review
    logger.info(
        "auto_approve_human_required",
        investigation_id=inv.id,
        reason="does_not_meet_criteria"
    )
    
    await _log_decision(
        investigation_id=inv.id,
        decision=False,
        reason="no_criteria_met",
        source="none"
    )
    
    return AutoApproveResult(
        should_auto_approve=False,
        reason="does_not_meet_criteria",
        confidence=0.0,
        decision_source="none",
        metadata={"severity": severity, "risk_score": risk_score}
    )


class GuardrailResult:
    """Result of guardrail check."""
    def __init__(self, should_block: bool, reason: str, metadata: Optional[Dict] = None):
        self.should_block = should_block
        self.reason = reason
        self.metadata = metadata or {}


def _check_guardrails(severity: str, risk_score: float, attack_type: str, investigation: Investigation = None) -> GuardrailResult:
    """Check static guardrails - never auto-approve these."""
    settings = _get_settings()

    # Block if investigation is in manual_review_required status
    if investigation and investigation.status == "manual_review_required":
        return GuardrailResult(
            should_block=True,
            reason="manual_review_required_blocked",
            metadata={"status": investigation.status}
        )

    # Check severity
    blocked_severities = [s.lower() for s in settings.auto_approve_block_severities]
    if severity in blocked_severities:
        return GuardrailResult(
            should_block=True,
            reason=f"severity_{severity}_blocked",
            metadata={"severity": severity}
        )
    
    # Check risk score
    if risk_score > settings.auto_approve_block_risk_score:
        return GuardrailResult(
            should_block=True,
            reason=f"risk_score_{risk_score}_exceeds_threshold_{settings.auto_approve_block_risk_score}",
            metadata={"risk_score": risk_score, "threshold": settings.auto_approve_block_risk_score}
        )
    
    # Check attack type
    blocked_types = [t.lower() for t in settings.auto_approve_block_attack_types]
    if attack_type and any(t in attack_type.lower() for t in blocked_types):
        return GuardrailResult(
            should_block=True,
            reason=f"attack_type_{attack_type}_blocked",
            metadata={"attack_type": attack_type}
        )
    
    # Check for suspicious authentication patterns in investigation
    if investigation:
        auth_pattern_result = _check_suspicious_auth_patterns(investigation)
        if auth_pattern_result.should_block:
            return auth_pattern_result
    
    return GuardrailResult(should_block=False, reason="pass")


def _check_suspicious_auth_patterns(inv: Investigation) -> GuardrailResult:
    """
    Check for suspicious authentication patterns that should block auto-approve.
    Analyzes the investigation's ai_summary for auth-related risk indicators.
    """
    settings = _get_settings()
    
    # Get the investigation's alert count and context
    ai_summary = inv.ai_summary or ""
    incident_title = inv.incident_title or ""
    
    # Check for suspicious patterns in title/summary
    suspicious_patterns = [
        "brute force",
        "failed login",
        "authentication failure",
        "failed attempt",
        "invalid user",
        "compromised account",
        "privilege escalation",
        "unauthorized access",
    ]
    
    combined_text = (ai_summary + " " + incident_title).lower()
    
    for pattern in suspicious_patterns:
        if pattern in combined_text:
            # Check if there's also successful login in same context (potential compromise)
            if "authentication success" in combined_text or "login session opened" in combined_text:
                return GuardrailResult(
                    should_block=True,
                    reason="suspicious_auth_pattern_blocked",
                    metadata={
                        "pattern": pattern,
                        "details": "Failed auth followed by successful login - potential compromised account"
                    }
                )
    
    # Check ai_narrative for suspicious patterns
    ai_narrative = inv.ai_narrative or ""
    if ai_narrative:
        narrative_lower = ai_narrative.lower()
        if any(p in narrative_lower for p in ["brute force", "credential stuffing", "password spray"]):
            return GuardrailResult(
                should_block=True,
                reason="attack_type_blocked",
                metadata={"attack_type": "authentication_attack"}
            )
    
    return GuardrailResult(should_block=False, reason="pass")


def _check_static_pass(severity: str, risk_score: float, alert_count: int) -> bool:
    """Check if meets static pass criteria - always auto-approve."""
    settings = _get_settings()
    
    # Check severity in allowed list
    allowed_severities = [s.lower() for s in settings.auto_approve_severities]
    if severity not in allowed_severities:
        return False
    
    # Check risk score below threshold
    if risk_score > settings.auto_approve_max_risk_score:
        return False
    
    # Check alert count below threshold
    if alert_count > settings.auto_approve_max_alerts:
        return False
    
    return True


class DynamicResult:
    """Result of dynamic learning check."""
    def __init__(self, should_approve: Optional[bool], reason: str, confidence: float = 0.5, metadata: Optional[Dict] = None):
        self.should_approve = should_approve
        self.reason = reason
        self.confidence = confidence
        self.metadata = metadata or {}


async def _check_dynamic(
    severity: str,
    risk_score: float,
    attack_type: str,
    alert_count: int
) -> DynamicResult:
    """Check dynamic learning criteria."""
    
    try:
        from response.confidence_tracker import get_approval_recommendation
        result = await get_approval_recommendation(
            severity=severity,
            risk_score=risk_score,
            attack_type=attack_type,
            alert_count=alert_count
        )
        return result
    except Exception as e:
        logger.warning("dynamic_check_failed", error=str(e))
        return DynamicResult(should_approve=None, reason="error")


class AIConfidenceResult:
    """Result of AI confidence check."""
    def __init__(self, should_approve: Optional[bool], confidence: float, metadata: Optional[Dict] = None):
        self.should_approve = should_approve
        self.confidence = confidence
        self.metadata = metadata or {}


async def _check_ai_confidence(inv: Investigation) -> AIConfidenceResult:
    """
    Evaluate playbook quality and incident context to determine auto-approve confidence.

    Scoring (0.0 - 1.0):
    - Playbook validity:        +0.25 (valid YAML + Ansible structure)
    - Playbook completeness:    +0.25 (has all 4 phases: contain, harden, forensics, verify)
    - Risk level:               +0.30 (lower risk = safer to auto-approve)
    - Summary quality:          +0.20 (substantial AI analysis, not fallback)

    Thresholds:
    - >= 0.85: auto-approve
    - >= 0.50: high-priority queue (fast human review)
    - <  0.50: requires human review
    """
    settings = _get_settings()
    score = 0.0
    metadata = {}

    playbook = inv.playbook_yaml or ""
    summary = inv.ai_summary or ""
    narrative = inv.ai_narrative or ""
    severity = (inv.incident_severity or "medium").lower()

    # 1. Playbook validity (+0.25)
    if inv.playbook_valid:
        score += 0.25
        metadata["playbook_valid"] = True
    else:
        metadata["playbook_valid"] = False
        # Invalid playbook = never auto-approve
        return AIConfidenceResult(should_approve=False, confidence=0.0, metadata=metadata)

    # 2. Playbook completeness (+0.25)
    # Check for the 4 required phases in the playbook
    phases = {
        "containment": any(k in playbook.lower() for k in ["block", "drop", "deny", "isolate", "quarantine"]),
        "hardening": any(k in playbook.lower() for k in ["harden", "secure", "disable", "remove", "patch"]),
        "forensics": any(k in playbook.lower() for k in ["evidence", "audit", "log", "capture", "collect"]),
        "verification": any(k in playbook.lower() for k in ["verify", "check", "confirm", "validate"]),
    }
    phase_score = sum(phases.values()) / 4.0  # 0.0 to 1.0
    score += phase_score * 0.25
    metadata["phases"] = phases
    metadata["phase_score"] = phase_score

    # 3. Risk level (+0.30) — lower risk = higher auto-approve confidence
    risk_map = {"low": 0.30, "medium": 0.20, "high": 0.10, "critical": 0.0}
    risk_contribution = risk_map.get(severity, 0.10)
    score += risk_contribution
    metadata["risk_contribution"] = risk_contribution

    # Block critical severity regardless of other factors
    if severity == "critical":
        metadata["blocked_reason"] = "critical_severity"
        return AIConfidenceResult(should_approve=False, confidence=score, metadata=metadata)

    # 4. Summary quality (+0.20)
    # Check if this is a real AI analysis or a fallback
    combined_text = f"{summary} {narrative}"
    is_fallback = any(marker in combined_text.lower() for marker in [
        "fallback analysis", "llm unavailable", "llm timeout", "no alert details available"
    ])
    if is_fallback:
        metadata["is_fallback"] = True
        # Fallback = reduced confidence
        score += 0.05
    else:
        metadata["is_fallback"] = False
        # Real AI output = full confidence
        score += 0.20

    # Round to 2 decimals
    score = round(score, 2)
    metadata["final_score"] = score

    # Decision
    threshold = settings.auto_approve_ai_threshold
    if score >= threshold:
        return AIConfidenceResult(should_approve=True, confidence=score, metadata=metadata)
    elif score >= settings.auto_approve_ai_high_priority_threshold:
        # High priority queue — don't auto-approve, but flag for fast review
        return AIConfidenceResult(should_approve=False, confidence=score, metadata=metadata)
    else:
        return AIConfidenceResult(should_approve=False, confidence=score, metadata=metadata)


def _estimate_risk_from_investigation(inv: Investigation) -> float:
    """Estimate risk score from investigation data."""
    # Parse numeric risk score from AI risk text (e.g., "Risk Score: 78.5/100")
    if hasattr(inv, 'ai_risk') and inv.ai_risk:
        import re
        match = re.search(r'[Rr]isk\s+[Ss]core[:\s]+(\d+(?:\.\d+)?)', inv.ai_risk)
        if match:
            return float(match.group(1))
        # Fallback: keyword-based scoring
        risk_lower = inv.ai_risk.lower()
        if 'critical' in risk_lower:
            return 85.0
        if 'high' in risk_lower:
            return 70.0
        if 'medium' in risk_lower:
            return 45.0
        if 'low' in risk_lower:
            return 25.0
    
    # Use severity-based estimate
    severity_map = {"low": 20, "medium": 40, "high": 60, "critical": 80}
    return severity_map.get(inv.incident_severity or "medium", 40)


def _extract_attack_type(inv: Investigation) -> str:
    """Extract attack type from investigation."""
    # Use title to identify attack type
    title = (inv.incident_title or "").lower()
    
    attack_types = {
        "ransomware": ["ransomware", "ransom"],
        "c2": ["c2", "command and control", "callback", "beacon"],
        "data_exfiltration": ["exfiltration", "data theft", "data transfer"],
        "privilege_escalation": ["privilege escalation", "root", "admin"],
        "lateral_movement": ["lateral movement", "lateral", "psexec", "winrm"],
        "brute_force": ["brute force", "brute", "ssh brute"],
        "malware": ["malware", "trojan", "virus"],
        "web_attack": ["sql injection", "xss", "injection"],
    }
    
    for attack_type, keywords in attack_types.items():
        if any(kw in title for kw in keywords):
            return attack_type
    
    return "unknown"


def _count_alerts(inv: Investigation) -> int:
    """Count alerts in investigation from alert_ids field."""
    alert_ids = inv.alert_ids or []
    if isinstance(alert_ids, list):
        return len(alert_ids)
    # Fallback: try to parse from comma-separated string
    if isinstance(alert_ids, str):
        return len([x for x in alert_ids.split(",") if x.strip()])
    return 1


async def _count_alerts_async(inv: Investigation) -> int:
    """Count alerts in investigation by querying the database."""
    from sqlalchemy import select, func
    from response.models import InvestigationAlert
    from response.db import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(func.count(InvestigationAlert.id)).where(
                InvestigationAlert.investigation_id == inv.id
            )
        )
        return result.scalar() or 0


async def _log_decision(
    investigation_id: str,
    decision: bool,
    reason: str,
    source: str
) -> None:
    """Log decision for audit trail."""
    try:
        from response.decision_logger import log_approval_decision
        await log_approval_decision(
            investigation_id=investigation_id,
            decision=decision,
            reason=reason,
            source=source
        )
    except Exception as e:
        logger.warning("failed_to_log_decision", error=str(e))


async def apply_auto_approve(investigation_id: str) -> AutoApproveResult:
    """
    Main entry point - apply auto-approve to an investigation.
    
    If approved, triggers playbook execution immediately.
    """
    result = await should_auto_approve(investigation_id)
    
    if result.should_auto_approve:
        # Update investigation with auto-approve info
        async with AsyncSessionLocal() as session:
            from sqlalchemy import update
            await session.execute(
                update(Investigation)
                .where(Investigation.id == investigation_id)
                .values(
                    status="approved",
                    updated_at=datetime.now(timezone.utc)
                )
            )
            await session.commit()
        
        # Trigger playbook execution
        from response.ansible_exec import execute_playbook
        asyncio.create_task(execute_playbook(investigation_id))
        
        logger.info(
            "investigation_auto_approved",
            investigation_id=investigation_id,
            reason=result.reason,
            confidence=result.confidence
        )
        
        # Send notification
        try:
            from response.notification import send_auto_approve_notification
            await send_auto_approve_notification(investigation_id, result)
        except Exception as e:
            logger.warning("auto_approve_notification_failed", error=str(e))
    
    return result