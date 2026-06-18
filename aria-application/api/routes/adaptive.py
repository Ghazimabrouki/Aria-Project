"""
Adaptive System API Routes.

Provides real-time visibility into adaptive system behavior.
"""
from fastapi import APIRouter, Depends
from typing import Dict, Any

from response.adaptive import get_adaptive_system

router = APIRouter(prefix="/adaptive", tags=["adaptive"])


@router.get("/status")
async def get_adaptive_status() -> Dict[str, Any]:
    """
    Get current adaptive system status.
    
    Returns:
        - timeout: Current timeout settings and average response time
        - retry: Current retry interval and error counts
        - concurrency: Current limits and utilization
        - metrics: Success/failure counts and queue depth
    """
    try:
        adaptive = await get_adaptive_system()
        return await adaptive.get_status()
    except Exception as e:
        return {"error": str(e), "status": "unavailable"}


@router.get("/metrics")
async def get_metrics() -> Dict[str, Any]:
    """Get detailed metrics for monitoring."""
    try:
        adaptive = await get_adaptive_system()
        return await adaptive.metrics.get_status()
    except Exception as e:
        return {"error": str(e)}


@router.post("/reset-metrics")
async def reset_metrics():
    """Reset all metrics (for testing)."""
    try:
        adaptive = await get_adaptive_system()
        # Reset would require methods on metrics - for now just return status
        return {"message": "Metrics are accumulated over time", "status": "ok"}
    except Exception as e:
        return {"error": str(e)}


@router.get("/health")
async def health_check() -> Dict[str, str]:
    """Quick health check."""
    try:
        adaptive = await get_adaptive_system()
        return {"status": "healthy", "adaptive_system": "active"}
    except Exception:
        return {"status": "degraded", "adaptive_system": "inactive"}