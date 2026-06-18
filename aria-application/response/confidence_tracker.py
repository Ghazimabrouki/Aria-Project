"""
Confidence Tracker.

Tracks approval patterns to enable dynamic learning.
Stores decision history and calculates adaptive thresholds.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List

import structlog

from config import get_settings

logger = structlog.get_logger()
settings = get_settings()

DECISION_HISTORY_FILE = Path("data/artifacts/approval_history.json")
ADAPTIVE_THRESHOLDS_FILE = Path("data/artifacts/adaptive_thresholds.json")

# In-memory cache
_decision_history: List[Dict[str, Any]] = []
_adaptive_thresholds: Dict[str, Any] = {
    "severity_thresholds": {
        "low": 30,
        "medium": 40,
        "high": 50,
        "critical": 60
    },
    "last_updated": None,
    "total_approvals": 0,
    "total_declines": 0
}


def _load_decision_history() -> List[Dict[str, Any]]:
    """Load decision history from disk."""
    global _decision_history
    if not _decision_history and DECISION_HISTORY_FILE.exists():
        try:
            data = json.loads(DECISION_HISTORY_FILE.read_text())
            _decision_history = data if isinstance(data, list) else []
        except Exception:
            _decision_history = []
    return _decision_history


def _save_decision_history() -> None:
    """Persist decision history to disk."""
    try:
        DECISION_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Keep only last 1000 decisions
        history_to_save = _decision_history[-1000:]
        DECISION_HISTORY_FILE.write_text(json.dumps(history_to_save))
    except Exception as e:
        logger.warning("failed_to_save_decision_history", error=str(e))


def _load_adaptive_thresholds() -> Dict[str, Any]:
    """Load adaptive thresholds from disk."""
    global _adaptive_thresholds
    if not _adaptive_thresholds.get("last_updated") and ADAPTIVE_THRESHOLDS_FILE.exists():
        try:
            data = json.loads(ADAPTIVE_THRESHOLDS_FILE.read_text())
            _adaptive_thresholds = data
        except Exception:
            pass
    return _adaptive_thresholds


def _save_adaptive_thresholds() -> None:
    """Persist adaptive thresholds to disk."""
    try:
        ADAPTIVE_THRESHOLDS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _adaptive_thresholds["last_updated"] = datetime.now(timezone.utc).isoformat()
        ADAPTIVE_THRESHOLDS_FILE.write_text(json.dumps(_adaptive_thresholds))
    except Exception as e:
        logger.warning("failed_to_save_adaptive_thresholds", error=str(e))


async def record_approval_decision(
    investigation_id: str,
    severity: str,
    risk_score: float,
    attack_type: str,
    alert_count: int,
    was_auto_approved: bool,
    human_approved: bool,
    execution_success: bool = None
) -> None:
    """
    Record an approval decision for learning.
    
    Args:
        investigation_id: Investigation ID
        severity: Incident severity
        risk_score: Calculated risk score
        attack_type: Detected attack type
        alert_count: Number of alerts
        was_auto_approved: True if auto-approved
        human_approved: True if human approved after auto-approve
        execution_success: True if playbook execution succeeded
    """
    global _decision_history, _adaptive_thresholds
    
    _load_decision_history()
    
    decision = {
        "investigation_id": investigation_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "risk_score": risk_score,
        "attack_type": attack_type,
        "alert_count": alert_count,
        "was_auto_approved": was_auto_approved,
        "human_approved": human_approved,
        "execution_success": execution_success,
        "outcome": "success" if execution_success else ("failed" if execution_success is False else "pending")
    }
    
    _decision_history.append(decision)
    
    # Update counts
    if was_auto_approved:
        _adaptive_thresholds["total_approvals"] = _adaptive_thresholds.get("total_approvals", 0) + 1
    if human_approved:
        _adaptive_thresholds["total_declines"] = _adaptive_thresholds.get("total_declines", 0) + 1
    
    _save_decision_history()
    
    # Recalculate thresholds if enough new data
    if len(_decision_history) >= settings.auto_approve_min_approvals_for_learning:
        await _recalculate_adaptive_thresholds()
    
    logger.info(
        "approval_decision_recorded",
        investigation_id=investigation_id,
        was_auto_approved=was_auto_approved,
        total_approvals=_adaptive_thresholds.get("total_approvals", 0)
    )


async def _recalculate_adaptive_thresholds() -> None:
    """Recalculate adaptive thresholds based on history."""
    global _adaptive_thresholds
    
    history = _load_decision_history()
    if len(history) < settings.auto_approve_min_approvals_for_learning:
        return
    
    # Calculate approval rates by severity
    severity_stats = {}
    for sev in ["low", "medium", "high", "critical"]:
        sev_decisions = [d for d in history if d.get("severity") == sev]
        if sev_decisions:
            approved = sum(1 for d in sev_decisions if d.get("human_approved"))
            total = len(sev_decisions)
            approval_rate = approved / total if total > 0 else 0
            
            # Adjust threshold based on approval rate
            # Higher approval rate = can be more aggressive (higher threshold)
            if approval_rate > 0.9:
                adjustment = 10
            elif approval_rate > 0.7:
                adjustment = 5
            elif approval_rate < 0.5:
                adjustment = -5
            else:
                adjustment = 0
            
            severity_stats[sev] = {
                "approval_rate": approval_rate,
                "adjustment": adjustment,
                "count": total
            }
    
    # Update thresholds
    base_thresholds = {
        "low": 30,
        "medium": 40,
        "high": 50,
        "critical": 60
    }
    
    new_thresholds = {}
    for sev, stats in severity_stats.items():
        base = base_thresholds.get(sev, 40)
        new_thresholds[sev] = max(10, min(90, base + stats["adjustment"]))
    
    _adaptive_thresholds["severity_thresholds"] = new_thresholds
    _save_adaptive_thresholds()
    
    logger.info(
        "adaptive_thresholds_updated",
        thresholds=new_thresholds,
        total_decisions=len(history)
    )


async def get_approval_recommendation(
    severity: str,
    risk_score: float,
    attack_type: str,
    alert_count: int
) -> Optional[Dict[str, Any]]:
    """
    Get approval recommendation based on learned patterns.
    
    Returns:
        Dict with should_approve, reason, confidence, metadata
    """
    if not settings.auto_approve_dynamic_enabled:
        return None
    
    history = _load_decision_history()
    if len(history) < settings.auto_approve_min_approvals_for_learning:
        # Not enough data yet - return None to fall back to static
        return None
    
    thresholds = _load_adaptive_thresholds()
    severity_thresholds = thresholds.get("severity_thresholds", {})
    
    # Get threshold for this severity
    threshold = severity_thresholds.get(severity, 40)
    
    # Calculate confidence based on historical patterns
    # Look at similar investigations
    similar = [
        d for d in history
        if d.get("severity") == severity
        and abs(d.get("risk_score", 0) - risk_score) < 20
    ]
    
    if similar:
        success_count = sum(1 for d in similar if d.get("execution_success") == True)
        total = len(similar)
        success_rate = success_count / total if total > 0 else 0.5
        
        # If risk score is below adaptive threshold and high success rate, recommend approve
        if risk_score < threshold and success_rate > 0.7:
            return {
                "should_approve": True,
                "reason": f"risk_{risk_score}_below_threshold_{threshold}_success_rate_{success_rate:.2f}",
                "confidence": min(0.9, 0.5 + (success_rate * 0.4)),
                "metadata": {
                    "threshold": threshold,
                    "success_rate": success_rate,
                    "similar_count": total
                }
            }
        elif risk_score > threshold or success_rate < 0.5:
            return {
                "should_approve": False,
                "reason": f"risk_{risk_score}_above_threshold_{threshold}_or_low_success_rate_{success_rate:.2f}",
                "confidence": min(0.9, 0.5 + ((1 - success_rate) * 0.4)),
                "metadata": {
                    "threshold": threshold,
                    "success_rate": success_rate,
                    "similar_count": total
                }
            }
    
    # Not enough confidence - return None
    return None


async def get_learning_stats() -> Dict[str, Any]:
    """Get learning statistics."""
    history = _load_decision_history()
    thresholds = _load_adaptive_thresholds()
    
    total = len(history)
    auto_approved = sum(1 for d in history if d.get("was_auto_approved"))
    human_approved = sum(1 for d in history if d.get("human_approved"))
    successful = sum(1 for d in history if d.get("execution_success") == True)
    
    return {
        "total_decisions": total,
        "auto_approved": auto_approved,
        "human_approved": human_approved,
        "successful_executions": successful,
        "success_rate": f"{(successful / auto_approved * 100):.1f}%" if auto_approved > 0 else "N/A",
        "adaptive_thresholds": thresholds.get("severity_thresholds", {}),
        "last_updated": thresholds.get("last_updated")
    }


async def clear_history() -> None:
    """Clear decision history (for testing)."""
    global _decision_history, _adaptive_thresholds
    _decision_history = []
    _adaptive_thresholds = {
        "severity_thresholds": {
            "low": 30,
            "medium": 40,
            "high": 50,
            "critical": 60
        },
        "last_updated": None,
        "total_approvals": 0,
        "total_declines": 0
    }
    
    if DECISION_HISTORY_FILE.exists():
        DECISION_HISTORY_FILE.unlink()
    if ADAPTIVE_THRESHOLDS_FILE.exists():
        ADAPTIVE_THRESHOLDS_FILE.unlink()
    
    logger.info("approval_history_cleared")