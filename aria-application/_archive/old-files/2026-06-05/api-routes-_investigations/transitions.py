"""Investigation workflow state transitions."""

# Allowed state transitions
_ALLOWED_TRANSITIONS = {
    "pending": {"running", "declined"},
    "running": {"awaiting_approval", "completed", "completed_with_warnings", "failed"},
    "awaiting_approval": {"approved", "declined", "regeneration_requested", "reviewed_no_action", "decision_approved"},
    "approved": {"running"},
    "decision_approved": {"archived", "regeneration_requested", "reviewed_no_action", "declined"},
    "completed": {"archived"},
    "completed_with_warnings": {"archived"},
    "failed": {"archived", "approved", "regeneration_requested", "decision_approved"},
    "declined": {"archived", "regeneration_requested"},
    "manual_review_required": {"declined", "archived", "regeneration_requested", "reviewed_no_action", "decision_approved", "approved"},
    "regeneration_requested": {"pending", "archived"},
    "reviewed_no_action": {"archived"},
}


def _validate_status_transition(current: str, desired: str) -> bool:
    """Validate if a status transition is allowed."""
    allowed = _ALLOWED_TRANSITIONS.get(current, set())
    return desired in allowed
