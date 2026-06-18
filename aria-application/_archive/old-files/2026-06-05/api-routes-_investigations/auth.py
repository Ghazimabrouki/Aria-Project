"""Authorization and request-context helpers for investigation routes."""

import json

from fastapi import HTTPException

from response.models import InvestigationAlert

# ── RBAC / Admin authorization helpers ───────────────────────────────────────

def _validate_admin_access(
    decided_by: str,
    admin_secret_header: str | None = None,
) -> str:
    """
    Internal trusted mode admin validation.
    
    Requires X-ARIA-Admin-Secret header matching settings.aria_admin_secret.
    In production/internal mode, if the admin secret is empty/default/changeme,
    admin endpoints are blocked.
    
    Returns the validated actor label. Never logs the secret.
    """
    from config import get_settings
    settings = get_settings()
    expected = (settings.aria_admin_secret or "").strip()
    
    if not expected or expected.lower() in ("", "changeme", "default", "admin"):
        raise HTTPException(
            status_code=403,
            detail="Admin access is disabled because aria_admin_secret is not configured or uses a default value. Set a strong secret in settings.",
        )
    
    provided = (admin_secret_header or "").strip()
    if not provided:
        raise HTTPException(
            status_code=403,
            detail="Admin action requires X-ARIA-Admin-Secret header.",
        )
    if provided != expected:
        raise HTTPException(
            status_code=403,
            detail="Invalid admin secret.",
        )
    
    return decided_by or "admin"


def _audit_ctx(request) -> dict:
    """Extract audit context from a FastAPI request.
    
    Handles direct function calls in tests where request may be a Depends placeholder.
    """
    if request is None:
        return {}
    if not hasattr(request, "client"):
        return {}
    return {
        "source_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent") if hasattr(request, "headers") else None,
        "request_id": request.headers.get("x-request-id") if hasattr(request, "headers") else None,
    }


def _get_alert_payload(alert: InvestigationAlert) -> dict:
    """Safely extract alert payload from InvestigationAlert.
    
    Supports both alert_json (current) and alert_snapshot (legacy).
    """
    raw = getattr(alert, "alert_json", None) or getattr(alert, "alert_snapshot", None) or "{}"
    if isinstance(raw, str):
        try:
            return json.loads(raw) or {}
        except Exception:
            return {}
    if isinstance(raw, dict):
        return raw
    return {}


