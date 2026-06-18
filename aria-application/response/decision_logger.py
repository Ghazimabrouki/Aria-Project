"""
Decision Logger.

Logs all auto-approve decisions for audit trail and debugging.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

import structlog

logger = structlog.get_logger()

DECISION_LOG_FILE = Path("data/artifacts/decision_log.json")

_decision_log: list = []


def _load_log() -> list:
    """Load decision log from disk."""
    global _decision_log
    if not _decision_log and DECISION_LOG_FILE.exists():
        try:
            data = json.loads(DECISION_LOG_FILE.read_text())
            _decision_log = data if isinstance(data, list) else []
        except Exception:
            _decision_log = []
    return _decision_log


def _save_log() -> None:
    """Persist decision log to disk."""
    try:
        DECISION_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Keep last 5000 decisions
        log_to_save = _decision_log[-5000:]
        DECISION_LOG_FILE.write_text(json.dumps(log_to_save, indent=2))
    except Exception as e:
        logger.warning("failed_to_save_decision_log", error=str(e))


async def log_approval_decision(
    investigation_id: str,
    decision: bool,
    reason: str,
    source: str,
    confidence: float = 0.0,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log an approval decision for audit trail.
    
    Args:
        investigation_id: Investigation ID
        decision: True if approved, False if requires human
        reason: Reason for decision
        source: static | dynamic | ai | guardrail | none
        confidence: Confidence score (0.0-1.0)
        metadata: Additional metadata
    """
    global _decision_log
    
    _load_log()
    
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "investigation_id": investigation_id,
        "decision": "approved" if decision else "human_review",
        "reason": reason,
        "source": source,
        "confidence": confidence,
        "metadata": metadata or {}
    }
    
    _decision_log.append(entry)
    _save_log()
    
    logger.info(
        "approval_decision_logged",
        investigation_id=investigation_id,
        decision=entry["decision"],
        reason=reason,
        source=source
    )


async def log_execution_result(
    investigation_id: str,
    success: bool,
    exit_code: Optional[int] = None,
    error: Optional[str] = None
) -> None:
    """
    Log playbook execution result.
    
    This should be called after playbook execution completes
    to track success/failure for learning.
    """
    global _decision_log
    
    _load_log()
    
    # Find the original decision entry and update it
    for entry in reversed(_decision_log):
        if entry.get("investigation_id") == investigation_id:
            entry["execution_result"] = "success" if success else "failed"
            entry["exit_code"] = exit_code
            entry["execution_timestamp"] = datetime.now(timezone.utc).isoformat()
            if error:
                entry["error"] = error
            break
    
    _save_log()
    
    logger.info(
        "execution_result_logged",
        investigation_id=investigation_id,
        success=success,
        exit_code=exit_code
    )


async def get_decision_history(
    investigation_id: Optional[str] = None,
    limit: int = 100
) -> list:
    """
    Get decision history.
    
    Args:
        investigation_id: Optional filter by investigation ID
        limit: Maximum number of entries to return
    
    Returns:
        List of decision entries
    """
    log = _load_log()
    
    if investigation_id:
        log = [e for e in log if e.get("investigation_id") == investigation_id]
    
    return log[-limit:]


async def get_decision_stats() -> Dict[str, Any]:
    """
    Get decision statistics.
    
    Returns:
        Dict with statistics about decisions
    """
    log = _load_log()
    
    total = len(log)
    approved = sum(1 for e in log if e.get("decision") == "approved")
    human_review = sum(1 for e in log if e.get("decision") == "human_review")
    
    # Source breakdown
    source_counts = {}
    for entry in log:
        source = entry.get("source", "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
    
    # Execution results
    successful = sum(1 for e in log if e.get("execution_result") == "success")
    failed = sum(1 for e in log if e.get("execution_result") == "failed")
    
    return {
        "total_decisions": total,
        "auto_approved": approved,
        "human_review_required": human_review,
        "auto_approve_rate": f"{(approved / total * 100):.1f}%" if total > 0 else "N/A",
        "by_source": source_counts,
        "execution_success": successful,
        "execution_failed": failed,
        "execution_success_rate": f"{(successful / (successful + failed) * 100):.1f}%" if (successful + failed) > 0 else "N/A"
    }


async def get_investigation_decision(investigation_id: str) -> Optional[Dict[str, Any]]:
    """Get the most recent decision for an investigation."""
    log = _load_log()
    
    for entry in reversed(log):
        if entry.get("investigation_id") == investigation_id:
            return entry
    
    return None