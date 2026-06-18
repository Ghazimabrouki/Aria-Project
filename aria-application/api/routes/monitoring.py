"""
Monitoring API endpoints for the Response Intelligence Layer.

Provides real-time status of investigations, playbook runs, and system health.
"""
import asyncio
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from response.db import AsyncSessionLocal
from response.models import Investigation, PlaybookRun, FixVerification
from response.notification import logger
from response.auth import require_auth, CurrentUser
from config import get_settings

router = APIRouter(prefix="/monitor", tags=["monitoring"])

settings = get_settings()


def _validate_admin_secret(header: str | None) -> None:
    """Validate X-ARIA-Admin-Secret header for admin actions."""
    secret = settings.aria_admin_secret
    bad_defaults = {"", "changeme", "default", "admin"}
    if not secret or secret.lower() in bad_defaults:
        raise HTTPException(status_code=403, detail="Admin access is disabled because aria_admin_secret is not configured or uses a default value.")
    if not header:
        raise HTTPException(status_code=403, detail="X-ARIA-Admin-Secret header is required.")
    if header != secret:
        raise HTTPException(status_code=403, detail="Invalid admin secret.")


class InvestigationStatusSummary(BaseModel):
    status: str
    count: int


class SystemStats(BaseModel):
    total_investigations: int
    status_breakdown: list[InvestigationStatusSummary]
    completed_rate: float
    failed_rate: float
    avg_resolution_time_minutes: Optional[float]


class InvestigationMetrics(BaseModel):
    investigation_id: str
    status: str
    target_host: Optional[str]
    target_user: Optional[str]
    risk_score: Optional[int]
    attack_type: Optional[str]
    created_at: datetime
    updated_at: datetime
    playbook_status: Optional[str]
    verification_status: Optional[str]


def _parse_risk(risk_str: Optional[str]) -> Optional[int]:
    """Parse risk score from string to int."""
    if not risk_str:
        return None
    try:
        return int(risk_str)
    except (ValueError, TypeError):
        return None


@router.get("/stats", response_model=SystemStats)
async def get_system_stats():
    """Get overall system statistics."""
    async with AsyncSessionLocal() as session:
        # Get counts by status
        result = await session.execute(
            select(Investigation.status, func.count(Investigation.id))
            .group_by(Investigation.status)
        )
        status_counts = {row[0]: row[1] for row in result.all()}
        
        total = sum(status_counts.values())
        completed = status_counts.get("completed", 0)
        failed = status_counts.get("failed", 0)
        
        # Calculate rates
        completed_rate = (completed / total * 100) if total > 0 else 0
        failed_rate = (failed / total * 100) if total > 0 else 0
        
        # Build breakdown
        breakdown = [
            InvestigationStatusSummary(status=status, count=count)
            for status, count in status_counts.items()
        ]
        
        # Calculate average resolution time for completed/archived investigations
        avg_resolution = None
        result_times = await session.execute(
            select(Investigation.updated_at, Investigation.created_at)
            .where(Investigation.status.in_(["completed", "archived"]))
        )
        resolution_times = []
        for row in result_times.all():
            if row[0] and row[1]:
                duration = (row[0] - row[1]).total_seconds() / 60
                if duration > 0:
                    resolution_times.append(duration)
        
        if resolution_times:
            avg_resolution = sum(resolution_times) / len(resolution_times)
        
        return SystemStats(
            total_investigations=total,
            status_breakdown=breakdown,
            completed_rate=round(completed_rate, 1),
            failed_rate=round(failed_rate, 1),
            avg_resolution_time_minutes=round(avg_resolution, 1) if avg_resolution else None,
        )


@router.get("/investigations", response_model=list[InvestigationMetrics])
async def list_investigations(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
):
    """List investigations with optional status filter."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    async with AsyncSessionLocal() as session:
        try:
            query = (
                select(Investigation)
                .options(selectinload(Investigation.run))
                .options(selectinload(Investigation.verification))
                .order_by(Investigation.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            
            if status:
                query = query.where(Investigation.status == status)
            if asset_id:
                query = query.where(Investigation.asset_id == asset_id)
            
            result = await session.execute(query)
            investigations = result.scalars().all()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
        
        metrics = []
        for inv in investigations:
            playbook_status = None
            try:
                if inv.run:
                    playbook_status = inv.run.status
            except Exception:
                pass
            
            verification_status = None
            try:
                if inv.verification:
                    verification_status = inv.verification.status
            except Exception:
                pass
            
            metrics.append(InvestigationMetrics(
                investigation_id=inv.id,
                status=inv.status,
                target_host=inv.target_host,
                target_user=inv.target_user,
                risk_score=_parse_risk(inv.ai_risk),
                attack_type=None,
                created_at=inv.created_at,
                updated_at=inv.updated_at,
                playbook_status=playbook_status,
                verification_status=verification_status,
            ))
        
        return metrics


@router.get("/investigations/{investigation_id}")
async def get_investigation_detail(investigation_id: str):
    """Get detailed information about a specific investigation."""
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(
                select(Investigation)
                .options(selectinload(Investigation.run))
                .options(selectinload(Investigation.verification))
                .options(selectinload(Investigation.approval))
                .where(Investigation.id == investigation_id)
            )
            inv = result.scalar_one_or_none()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
        
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        
        return {
            "id": inv.id,
            "status": inv.status,
            "incident_title": inv.incident_title,
            "incident_id": inv.incident_id,
            "target_host": inv.target_host,
            "target_user": inv.target_user,
            "source_ips": inv.source_ips,
            "risk_score": _parse_risk(inv.ai_risk),
            "ai_summary": inv.ai_summary,
            "ai_error": inv.ai_error,
            "playbook_valid": inv.playbook_valid,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
            "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
            "playbook_run": {
                "status": inv.run.status if inv.run else None,
                "exit_code": inv.run.exit_code if inv.run else None,
                "started_at": inv.run.started_at.isoformat() if inv.run and inv.run.started_at else None,
                "finished_at": inv.run.finished_at.isoformat() if inv.run and inv.run.finished_at else None,
            } if inv.run else None,
            "verification": {
                "status": inv.verification.status if inv.verification else None,
                "new_alerts_found": inv.verification.new_alerts_found if inv.verification else None,
                "checked_at": inv.verification.checked_at.isoformat() if inv.verification and inv.verification.checked_at else None,
            } if inv.verification else None,
        }


@router.get("/playbook-runs")
async def list_playbook_runs(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
):
    """List recent playbook executions."""
    async with AsyncSessionLocal() as session:
        query = (
            select(PlaybookRun)
            .order_by(PlaybookRun.started_at.desc())
            .limit(limit)
        )
        
        if status:
            query = query.where(PlaybookRun.status == status)
        
        result = await session.execute(query)
        runs = result.scalars().all()
        
        return [
            {
                "id": r.id,
                "investigation_id": r.investigation_id,
                "status": r.status,
                "exit_code": r.exit_code,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            }
            for r in runs
        ]


@router.get("/health")
async def health_check():
    """Basic health check for the monitoring system."""
    async with AsyncSessionLocal() as session:
        try:
            # Simple DB query to verify connectivity
            await session.execute(select(Investigation.id).limit(1))
            db_status = "ok"
        except Exception as e:
            db_status = f"error: {str(e)}"
        
        return {
            "status": "healthy" if db_status == "ok" else "degraded",
            "database": db_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@router.get("/pipeline-health")
async def pipeline_health():
    """Comprehensive health check for all pipeline stages."""
    from config import get_settings
    import httpx
    
    settings = get_settings()
    health = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stages": {}
    }
    
    # 1. Database
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(select(Investigation.id).limit(1))
        health["stages"]["database"] = {"status": "healthy", "message": "connected"}
    except Exception as e:
        health["stages"]["database"] = {"status": "unhealthy", "message": str(e)[:100]}
    
    # 2. Redis
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        await redis.ping()
        health["stages"]["redis"] = {"status": "healthy", "message": "connected"}
    except Exception as e:
        health["stages"]["redis"] = {"status": "unhealthy", "message": str(e)[:100]}
    
    # 3. Elasticsearch
    try:
        # Create a fresh ES client for health check to avoid cross-event-loop issues
        from config import get_settings
        from elasticsearch import AsyncElasticsearch
        settings = get_settings()
        client_kwargs = {
            "hosts": [settings.elasticsearch_url],
            "basic_auth": (settings.elasticsearch_user, settings.elasticsearch_password),
            "ssl_show_warn": False,
        }
        if not settings.elasticsearch_use_ssl:
            import ssl
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            client_kwargs["ssl_context"] = ssl_ctx
        es = AsyncElasticsearch(**client_kwargs)
        try:
            await es.info()
            health["stages"]["elasticsearch"] = {"status": "healthy", "message": "connected"}
        finally:
            await es.close()
    except Exception as e:
        health["stages"]["elasticsearch"] = {"status": "unhealthy", "message": str(e)[:100]}
    
    # 4. OpenSOAR Connection
    if settings.upstream_enabled:
        try:
            from pipeline.sender import OpenSOARClient
            client = OpenSOARClient()
            auth_ok = await client.authenticate()
            health["stages"]["opensoar"] = {
                "status": "healthy" if auth_ok else "unhealthy",
                "message": "connected" if auth_ok else "auth failed"
            }
        except Exception as e:
            health["stages"]["opensoar"] = {"status": "unhealthy", "message": str(e)[:100]}
    else:
        health["stages"]["opensoar"] = {"status": "disabled", "message": "Upstream mode disabled"}
    
    # 5. Forwarder Status
    _forwarder_sources = ["wazuh", "falco", "filebeat"]
    if settings.suricata_index_pattern and settings.suricata_index_pattern != settings.filebeat_index_pattern:
        _forwarder_sources.append("suricata")
    health["stages"]["forwarder"] = {
        "status": "running",
        "message": "Forwarder polls ES indices",
        "sources": _forwarder_sources
    }
    
    # 6. Performance Monitoring
    if settings.performance_enabled:
        health["stages"]["performance_monitoring"] = {
            "status": "running",
            "message": f"Polls {settings.telegraf_index_pattern} every {settings.performance_poll_interval}s"
        }
    else:
        health["stages"]["performance_monitoring"] = {"status": "disabled", "message": "Disabled in config"}
    
    # 7. Incident Watcher
    health["stages"]["incident_watcher"] = {
        "status": "running",
        "message": f"Polls OpenSOAR every {settings.incident_watcher_interval}s"
    }
    
    # 8. Response Intelligence (AI + Playbook)
    health["stages"]["response_intelligence"] = {
        "status": "running",
        "message": "AI investigation + Ansible remediation"
    }
    
    # Determine overall status
    unhealthy_stages = [k for k, v in health["stages"].items() if v.get("status") == "unhealthy"]
    health["overall_status"] = "healthy" if not unhealthy_stages else "degraded"
    health["unhealthy_stages"] = unhealthy_stages
    
    return health


async def _check_source_has_data_in_es(source: str) -> tuple[bool, Optional[str]]:
    """Check if Elasticsearch contains any documents for a given alert source.
    Returns (has_data, latest_timestamp_or_none).
    """
    try:
        from core.elasticsearch import get_es_client
        from config import get_settings
        es = await get_es_client()
        settings = get_settings()

        index_patterns = {
            "wazuh": settings.wazuh_index_pattern,
            "falco": settings.falco_index_pattern,
            "filebeat": settings.filebeat_index_pattern,
            "suricata": settings.suricata_index_pattern,
        }
        index = index_patterns.get(source, "*")

        resp = await es.search(
            index=index,
            body={
                "sort": [{"@timestamp": "desc"}],
                "size": 1,
                "_source": ["@timestamp"],
            },
            size=1,
        )
        hits = resp.get("hits", {}).get("hits", [])
        if hits:
            ts = hits[0].get("_source", {}).get("@timestamp")
            return True, ts
        return False, None
    except Exception as e:
        logger.warning("es_source_check_failed", source=source, error=str(e))
        return False, None


async def _check_redis_cursor_freshness(source: str, max_age_seconds: float = 3600) -> tuple[str, Optional[str]]:
    """Check if a forwarder cursor is fresh and forwarder is active. Returns (status, detail)."""
    try:
        from core import get_redis_client
        import json
        redis = await get_redis_client()

        # Check forwarder activity via last_run in stats
        stats_key = f"opensoar:forwarder:stats:{source}"
        stats_raw = await redis.get(stats_key)
        last_run_age = float("inf")
        if stats_raw:
            stats = json.loads(stats_raw)
            last_run = stats.get("last_run")
            if last_run:
                try:
                    run_dt = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                    last_run_age = (datetime.now(timezone.utc) - run_dt).total_seconds()
                except Exception:
                    pass

        cursor_key = f"opensoar:cursor:{source}"
        cursor_raw = await redis.get(cursor_key)
        if not cursor_raw:
            # No cursor but forwarder is active
            if last_run_age < max_age_seconds * 3:
                return "running", f"Polling active, no cursor yet"
            return "stopped", "No cursor found"

        cursor_str = cursor_raw.decode() if isinstance(cursor_raw, bytes) else cursor_raw
        cursor_dt = datetime.fromisoformat(cursor_str.replace("Z", "+00:00"))
        cursor_age = (datetime.now(timezone.utc) - cursor_dt).total_seconds()

        # Forwarder is active if either cursor moved recently OR forwarder ran recently
        forwarder_active = last_run_age < max_age_seconds * 3
        cursor_fresh = cursor_age < max_age_seconds

        if cursor_fresh:
            return "running", f"Cursor fresh: {cursor_age/60:.1f}m ago"
        elif forwarder_active:
            # Forwarder is polling actively — cursor age just means no new docs in ES
            if cursor_age > max_age_seconds * 4:
                return "idle", f"Polling active, no new docs for {cursor_age/3600:.1f}h"
            return "running", f"Polling active, cursor {cursor_age/60:.1f}m old"
        elif cursor_age > max_age_seconds * 4:
            # Before marking as stopped/error, check if ES even has data for this source
            has_data, latest_ts = await _check_source_has_data_in_es(source)
            if not has_data:
                return "idle", "No data in Elasticsearch"
            return "stopped", f"Cursor stale: {cursor_age/3600:.1f}h ago"
        else:
            return "error", f"Cursor lagging: {cursor_age/60:.1f}m ago"
    except Exception as e:
        return "error", f"Cursor check failed: {str(e)[:80]}"



async def _check_performance_metrics_freshness(max_age_seconds: float = 300) -> tuple[str, Optional[str]]:
    """Check if performance metrics are fresh in Redis."""
    try:
        from core.redis_performance import performance_redis
        metrics = await performance_redis.get_all_current_metrics()
        if not metrics:
            return "idle", "No metrics in Redis yet"
        newest_age = float("inf")
        for hostname, data in metrics.items():
            ts_str = data.get("timestamp", "")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - ts).total_seconds()
                    if age < newest_age:
                        newest_age = age
                except Exception:
                    pass
        if newest_age == float("inf"):
            return "error", "No valid timestamps"
        if newest_age > max_age_seconds * 4:
            return "stopped", f"Data stale: {newest_age/60:.1f}m ago"
        elif newest_age > max_age_seconds:
            return "error", f"Data lagging: {newest_age/60:.1f}m ago"
        return "running", f"Data fresh: {newest_age/60:.1f}m ago"
    except Exception as e:
        return "error", f"Metrics check failed: {str(e)[:80]}"


async def _check_watcher_activity(max_age_seconds: float = 1800) -> tuple[str, Optional[str]]:
    """Check if incident watcher is active by looking at recent upstream investigations."""
    try:
        from response.db import AsyncSessionLocal
        from response.models import Investigation
        from sqlalchemy import select, func
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(func.count(Investigation.id)).where(
                    Investigation.created_at >= cutoff,
                    Investigation.source != "performance"
                )
            )
            recent_count = result.scalar_one()
            if recent_count > 0:
                return "running", f"{recent_count} new investigations recently"
            # Also check if any investigation was updated recently (stuck recovery, etc.)
            result2 = await session.execute(
                select(func.count(Investigation.id)).where(
                    Investigation.updated_at >= cutoff,
                    Investigation.source != "performance"
                )
            )
            updated_count = result2.scalar_one()
            if updated_count > 0:
                return "running", f"{updated_count} investigations updated recently"
            # Check if upstream is down - if so, watcher can't do much (only in upstream mode)
            if settings.upstream_enabled:
                try:
                    from pipeline.sender import OpenSOARClient
                    client = OpenSOARClient()
                    auth_ok = await client.authenticate()
                    if not auth_ok:
                        return "error", "Upstream unreachable; watcher idle"
                except Exception:
                    return "error", "Upstream unreachable; watcher idle"
            return "running", "No new incidents (normal)"
    except Exception as e:
        return "error", f"Watcher check failed: {str(e)[:80]}"


async def _check_correlation_activity(max_age_seconds: float = 3600) -> tuple[str, Optional[str]]:
    """Check if incident correlation is active."""
    try:
        from response.db import AsyncSessionLocal
        from response.models import Incident
        from sqlalchemy import select, func
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(func.count(Incident.id)).where(Incident.created_at >= cutoff)
            )
            recent_count = result.scalar_one()
            if recent_count > 0:
                return "running", f"{recent_count} incidents correlated recently"
            return "running", "No new incidents to correlate"
    except Exception as e:
        return "error", f"Correlation check failed: {str(e)[:80]}"


async def _check_auto_transitions_activity(max_age_seconds: float = 3600) -> tuple[str, Optional[str]]:
    """Check if auto transitions are active."""
    try:
        from response.db import AsyncSessionLocal
        from response.models import Investigation
        from sqlalchemy import select, func
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(func.count(Investigation.id)).where(
                    Investigation.updated_at >= cutoff,
                    Investigation.status.in_(["archived", "completed"])
                )
            )
            recent_count = result.scalar_one()
            if recent_count > 0:
                return "running", f"{recent_count} transitions recently"
            return "running", "Idle (no pending transitions)"
    except Exception as e:
        return "error", f"Transitions check failed: {str(e)[:80]}"


async def _check_retry_queue_status() -> tuple[str, Optional[str]]:
    """Check retry queue status."""
    try:
        from pipeline.retry_queue import retry_queue
        stats = await retry_queue.get_stats()
        pending = stats.get("pending_count", 0)
        if pending > 50:
            return "error", f"{pending} alerts backlog"
        elif pending > 10:
            return "running", f"{pending} alerts queued"
        return "running", f"{pending} pending"
    except Exception as e:
        return "error", f"Queue check failed: {str(e)[:80]}"


async def _check_backup_status() -> tuple[str, Optional[str]]:
    """Check if database backups are happening."""
    try:
        import glob
        import os
        from pathlib import Path
        from config import get_settings
        settings = get_settings()
        backup_dir = Path(settings.backup_dir) if hasattr(settings, "backup_dir") else Path("backups")
        if not backup_dir.exists():
            return "stopped", "Backup directory missing"
        backups = sorted(glob.glob(str(backup_dir / "investigations_*.db")))
        if not backups:
            return "stopped", "No backups found"
        newest = max(backups, key=os.path.getmtime)
        mtime = datetime.fromtimestamp(os.path.getmtime(newest), tz=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - mtime).total_seconds() / 3600
        if age_hours > 48:
            return "error", f"Last backup {age_hours:.0f}h ago"
        return "running", f"Last backup {age_hours:.0f}h ago"
    except Exception as e:
        return "error", f"Backup check failed: {str(e)[:80]}"


async def _check_db_health() -> tuple[str, float]:
    """Check database health and return latency."""
    import time
    start = time.time()
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(select(Investigation.id).limit(1))
        latency_ms = (time.time() - start) * 1000
        return "running", latency_ms
    except Exception:
        return "stopped", (time.time() - start) * 1000


@router.get("/services-status")
async def get_services_status():
    """Get status of all background services running in main.py with real health checks."""
    from config import get_settings
    import time

    settings = get_settings()
    check_start = time.time()

    # Build dynamic source checks
    source_checks = [
        ("wazuh", settings.opensoar_poll_interval * 3),
        ("falco", settings.opensoar_poll_interval * 3),
        ("filebeat", settings.opensoar_poll_interval * 3),
    ]
    if settings.suricata_index_pattern and settings.suricata_index_pattern != settings.filebeat_index_pattern:
        source_checks.append(("suricata", settings.opensoar_poll_interval * 3))

    # Run all health checks concurrently
    check_tasks = [
        _check_db_health(),
        *[ _check_redis_cursor_freshness(src, max_age_seconds=age) for src, age in source_checks ],
        _check_watcher_activity(),
        _check_correlation_activity(),
        _check_auto_transitions_activity(),
        _check_retry_queue_status(),
        _check_backup_status(),
        _check_performance_metrics_freshness() if settings.performance_enabled else asyncio.sleep(0),
    ]
    checks = await asyncio.gather(*check_tasks, return_exceptions=True)

    db_status, db_latency = checks[0] if not isinstance(checks[0], Exception) else ("error", 999)
    source_results = {}
    for i, (src, _) in enumerate(source_checks):
        source_results[src] = checks[1 + i] if not isinstance(checks[1 + i], Exception) else ("error", "Check failed")
    wazuh_status, wazuh_detail = source_results.get("wazuh", ("error", "Check failed"))
    falco_status, falco_detail = source_results.get("falco", ("error", "Check failed"))
    filebeat_status, filebeat_detail = source_results.get("filebeat", ("error", "Check failed"))
    suricata_status, suricata_detail = source_results.get("suricata", ("idle", "Merged with filebeat"))
    watcher_status, watcher_detail = checks[len(source_checks) + 1] if not isinstance(checks[len(source_checks) + 1], Exception) else ("error", "Check failed")
    correlation_status, correlation_detail = checks[len(source_checks) + 2] if not isinstance(checks[len(source_checks) + 2], Exception) else ("error", "Check failed")
    transitions_status, transitions_detail = checks[len(source_checks) + 3] if not isinstance(checks[len(source_checks) + 3], Exception) else ("error", "Check failed")
    retry_status, retry_detail = checks[len(source_checks) + 4] if not isinstance(checks[len(source_checks) + 4], Exception) else ("error", "Check failed")
    backup_status, backup_detail = checks[len(source_checks) + 5] if not isinstance(checks[len(source_checks) + 5], Exception) else ("error", "Check failed")
    perf_status, perf_detail = ("disabled", None) if not settings.performance_enabled else (
        checks[len(source_checks) + 6] if not isinstance(checks[len(source_checks) + 6], Exception) else ("error", "Check failed")
    )

    # Determine overall forwarder status from individual sources
    forwarder_sources = {"wazuh": wazuh_status, "falco": falco_status, "filebeat": filebeat_status}
    if settings.suricata_index_pattern and settings.suricata_index_pattern != settings.filebeat_index_pattern:
        forwarder_sources["suricata"] = suricata_status
    active_sources = sum(1 for s in forwarder_sources.values() if s == "running")
    idle_sources = sum(1 for s in forwarder_sources.values() if s == "idle")
    error_sources = sum(1 for s in forwarder_sources.values() if s == "error")
    stopped_sources = sum(1 for s in forwarder_sources.values() if s == "stopped")
    if not settings.opensoar_enabled and not getattr(settings, "local_ingestion_enabled", True):
        forwarder_status = "disabled"
        forwarder_detail = "Forwarding disabled in config"
    elif error_sources > 0:
        forwarder_status = "error"
        stale = [k for k, v in forwarder_sources.items() if v in ("error", "stopped")]
        forwarder_detail = f"Stale sources: {', '.join(stale)}"
    elif stopped_sources > 0:
        forwarder_status = "stopped"
        stale = [k for k, v in forwarder_sources.items() if v == "stopped"]
        forwarder_detail = f"Stopped sources: {', '.join(stale)}"
    elif active_sources == 0 and idle_sources > 0:
        # All sources idle = polling but no new data in ES — this is normal
        forwarder_status = "running"
        forwarder_detail = f"All {len(forwarder_sources)} sources up-to-date (no new alerts)"
    elif active_sources < len(forwarder_sources):
        forwarder_status = "running"
        inactive = [k for k, v in forwarder_sources.items() if v not in ("running",)]
        forwarder_detail = f"{active_sources}/{len(forwarder_sources)} active, {len(inactive)} idle"
    else:
        forwarder_status = "running"
        forwarder_detail = f"{active_sources}/{len(forwarder_sources)} sources active"

    services = {
        "api_server": {
            "name": "API Server",
            "status": "running",
            "latency_ms": round((time.time() - check_start) * 1000, 1),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "description": f"FastAPI HTTP server on port {settings.backend_port}"
        },
        "forwarder": {
            "name": "Alert Forwarder",
            "status": forwarder_status,
            "latency_ms": round(db_latency, 1),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "poll_interval": settings.opensoar_poll_interval,
            "sources": list(forwarder_sources.keys()),
            "source_status": forwarder_sources,
            "details": forwarder_detail,
            "description": "Polls Elasticsearch and forwards alerts to OpenSOAR"
        },
        "incident_watcher": {
            "name": "Incident Watcher",
            "status": watcher_status,
            "latency_ms": round(db_latency, 1),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "poll_interval": settings.incident_watcher_interval,
            "details": watcher_detail,
            "description": "Polls OpenSOAR for new incidents"
        },
        "incident_correlation": {
            "name": "Incident Correlation",
            "status": correlation_status,
            "latency_ms": round(db_latency, 1),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "interval": settings.incident_correlation_interval,
            "details": correlation_detail,
            "description": "Correlates related incidents"
        },
        "auto_transitions": {
            "name": "Auto Transitions",
            "status": transitions_status,
            "latency_ms": round(db_latency, 1),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "details": transitions_detail,
            "description": "Automatic investigation state transitions"
        },
        "retry_queue": {
            "name": "Retry Queue",
            "status": retry_status,
            "latency_ms": round(db_latency, 1),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "details": retry_detail,
            "description": "Retries failed operations"
        },
        "backup": {
            "name": "Database Backup",
            "status": backup_status,
            "latency_ms": 0,
            "last_check": datetime.now(timezone.utc).isoformat(),
            "details": backup_detail,
            "description": "Periodic SQLite backups"
        },
        "health_monitor": {
            "name": "Health Monitor",
            "status": "running" if db_status == "running" else db_status,
            "latency_ms": round(db_latency, 1),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "description": "Background health checks"
        },
        "performance_monitoring": {
            "name": "Performance Monitoring",
            "status": perf_status,
            "latency_ms": round(db_latency, 1),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "poll_interval": settings.performance_poll_interval,
            "details": perf_detail,
            "description": "Server metrics monitoring via Telegraf/ES"
        },
        "performance_watcher": {
            "name": "Performance Watcher",
            "status": perf_status,
            "latency_ms": round(db_latency, 1),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "details": perf_detail,
            "description": "Performance alert cooldown management"
        }
    }

    # Count actual statuses
    status_counts = {"running": 0, "error": 0, "stopped": 0, "disabled": 0}
    for svc in services.values():
        status_counts[svc["status"]] = status_counts.get(svc["status"], 0) + 1

    return {
        "services": services,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_running": status_counts.get("running", 0),
        "total_error": status_counts.get("error", 0),
        "total_stopped": status_counts.get("stopped", 0),
        "total_disabled": status_counts.get("disabled", 0),
    }


class StuckInvestigation(BaseModel):
    investigation_id: str
    status: str
    severity: str
    hours_stuck: float
    created_at: datetime
    updated_at: datetime


@router.get("/stuck-investigations")
async def get_stuck_investigations(
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
):
    """Get list of stuck investigations with time stuck."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    from datetime import timedelta
    
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    async with AsyncSessionLocal() as session:
        stmt = (
            select(Investigation)
            .where(Investigation.status.in_(["awaiting_approval", "pending", "running"]))
        )
        if asset_id:
            stmt = stmt.where(Investigation.asset_id == asset_id)
        result = await session.execute(stmt)
        investigations = result.scalars().all()
        
        stuck_list = []
        for inv in investigations:
            hours_stuck = 0
            if inv.status == "awaiting_approval":
                hours_stuck = (now - inv.created_at).total_seconds() / 3600
                threshold = settings.stuck_investigation_hours
            elif inv.status == "running":
                hours_stuck = (now - inv.updated_at).total_seconds() / 3600
                threshold = settings.stuck_running_minutes / 60
            elif inv.status == "pending":
                hours_stuck = (now - inv.created_at).total_seconds() / 3600
                threshold = settings.stuck_pending_hours
            
            # Only include if past threshold
            if hours_stuck >= threshold:
                stuck_list.append(StuckInvestigation(
                    investigation_id=inv.id,
                    status=inv.status,
                    severity=inv.incident_severity,
                    hours_stuck=round(hours_stuck, 2),
                    created_at=inv.created_at,
                    updated_at=inv.updated_at
                ))
        
        # Sort by hours stuck (most stuck first)
        stuck_list.sort(key=lambda x: x.hours_stuck, reverse=True)
        
        return {
            "count": len(stuck_list),
            "stuck_investigations": [
                {
                    "id": s.investigation_id,
                    "status": s.status,
                    "severity": s.severity,
                    "hours_stuck": s.hours_stuck,
                    "created_at": s.created_at.isoformat(),
                    "updated_at": s.updated_at.isoformat()
                }
                for s in stuck_list
            ]
        }


class ExecutionStats(BaseModel):
    total_runs: int
    successful: int
    failed: int
    success_rate: float
    avg_duration_minutes: float


@router.get("/execution-stats", response_model=ExecutionStats)
async def get_execution_stats():
    """Get Ansible execution statistics."""
    async with AsyncSessionLocal() as session:
        # Get all playbook runs with finished_at
        result = await session.execute(
            select(PlaybookRun)
            .where(PlaybookRun.finished_at.isnot(None))
        )
        runs = result.scalars().all()
        
        total = len(runs)
        if total == 0:
            return ExecutionStats(
                total_runs=0,
                successful=0,
                failed=0,
                success_rate=0,
                avg_duration_minutes=0
            )
        
        successful = sum(1 for r in runs if r.status == "completed")
        failed = total - successful
        success_rate = (successful / total * 100) if total > 0 else 0
        
        # Calculate avg duration
        durations = []
        for r in runs:
            if r.started_at and r.finished_at:
                duration = (r.finished_at - r.started_at).total_seconds() / 60
                if duration > 0:
                    durations.append(duration)
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        return ExecutionStats(
            total_runs=total,
            successful=successful,
            failed=failed,
            success_rate=round(success_rate, 2),
            avg_duration_minutes=round(avg_duration, 2)
        )


@router.post("/reset-cursor/{source}")
async def reset_cursor(
    source: str,
    hours_ago: int = Query(24, description="Reset cursor to N hours ago"),
    x_aria_admin_secret: Optional[str] = Query(None, alias="X-ARIA-Admin-Secret"),
):
    """Reset cursor for a source to reprocess missed alerts."""
    _validate_admin_secret(x_aria_admin_secret)
    from datetime import timedelta
    
    _valid_sources = ["wazuh", "falco", "filebeat"]
    if settings.suricata_index_pattern and settings.suricata_index_pattern != settings.filebeat_index_pattern:
        _valid_sources.append("suricata")
    if source not in _valid_sources:
        raise HTTPException(status_code=400, detail=f"Invalid source. Must be: {', '.join(_valid_sources)}")
    
    new_cursor = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    
    # Reset both Redis and file-based cursor
    from pipeline.poller import _set_cursor
    await _set_cursor(source, new_cursor)
    
    logger.info("cursor_reset", source=source, hours_ago=hours_ago, new_cursor=new_cursor.isoformat())
    
    return {
        "source": source,
        "new_cursor": new_cursor.isoformat(),
        "message": f"Cursor reset to {hours_ago} hours ago. Next poll will fetch alerts from that time."
    }


@router.get("/auto-approve-stats")
async def get_auto_approve_stats():
    """Get auto-approve system statistics."""
    try:
        from response.decision_logger import get_decision_stats
        stats = await get_decision_stats()
        return stats
    except Exception as e:
        logger.warning("auto_approve_stats_failed", error=str(e))
        return {
            "total_decisions": 0,
            "auto_approved": 0,
            "human_review_required": 0,
            "auto_approve_rate": "N/A",
            "error": str(e)
        }


@router.get("/auto-approve-config")
async def get_auto_approve_config():
    """Get current auto-approve configuration."""
    from config import get_settings
    s = get_settings()
    
    return {
        "enabled": s.auto_approve_enabled,
        "method": s.auto_approve_method,
        "static": {
            "severities": s.auto_approve_severities,
            "max_risk_score": s.auto_approve_max_risk_score,
            "max_alerts": s.auto_approve_max_alerts
        },
        "guardrails": {
            "block_severities": s.auto_approve_block_severities,
            "block_risk_score": s.auto_approve_block_risk_score,
            "block_attack_types": s.auto_approve_block_attack_types
        },
        "dynamic": {
            "enabled": s.auto_approve_dynamic_enabled,
            "min_approvals": s.auto_approve_min_approvals_for_learning
        },
        "ai": {
            "enabled": s.auto_approve_ai_enabled,
            "threshold": s.auto_approve_ai_threshold
        },
            "notifications": {
            "on_auto": s.auto_approve_notify_on_auto,
            "on_fallback": s.auto_approve_notify_on_fallback
        }
    }


@router.get("/retry-queue-stats")
async def get_retry_queue_stats():
    """Get retry queue statistics."""
    try:
        from pipeline.retry_queue import retry_queue
        stats = await retry_queue.get_stats()
        return {
            "status": "ok",
            **stats
        }
    except Exception as e:
        logger.warning("retry_queue_stats_failed", error=str(e))
        return {
            "status": "error",
            "pending_count": 0,
            "by_retry_count": {},
            "error": str(e)
        }


@router.get("/forwarder-status")
async def get_forwarder_status():
    """Get current forwarder status per source - shows ES polling status."""
    from config import get_settings
    from datetime import timedelta
    
    s = get_settings()
    
    # Get forwarder stats from Redis (if available)
    forwarder_info = {
        "wazuh": {
            "enabled": True,
            "index_pattern": s.wazuh_index_pattern,
            "last_cursor": None,
            "alerts_forwarded": 0,
            "errors": 0,
            "status": "unknown"
        },
        "falco": {
            "enabled": True,
            "index_pattern": s.falco_index_pattern,
            "last_cursor": None,
            "alerts_forwarded": 0,
            "errors": 0,
            "status": "unknown"
        },
        "filebeat": {
            "enabled": True,
            "index_pattern": s.filebeat_index_pattern,
            "last_cursor": None,
            "alerts_forwarded": 0,
            "errors": 0,
            "status": "unknown"
        },
    }
    if s.suricata_index_pattern and s.suricata_index_pattern != s.filebeat_index_pattern:
        forwarder_info["suricata"] = {
            "enabled": True,
            "index_pattern": s.suricata_index_pattern,
            "last_cursor": None,
            "alerts_forwarded": 0,
            "errors": 0,
            "status": "unknown"
        }
    
    # Try to get actual cursor from Redis
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        
        for source in forwarder_info.keys():
            cursor_key = f"opensoar:cursor:{source}"
            cursor = await redis.get(cursor_key)
            if cursor:
                forwarder_info[source]["last_cursor"] = cursor
                forwarder_info[source]["status"] = "running"
            
            # Get stats from forwarder
            stats_key = f"opensoar:forwarder:{source}:stats"
            stats_data = await redis.get(stats_key)
            if stats_data:
                import json
                stats = json.loads(stats_data)
                forwarder_info[source]["alerts_forwarded"] = stats.get("alerts_forwarded", 0)
                forwarder_info[source]["errors"] = stats.get("errors", 0)
    except Exception as e:
        logger.warning("forwarder_status_redis_error", error=str(e))
    
    # Add performance monitoring status
    if s.performance_enabled:
        forwarder_info["performance"] = {
            "enabled": True,
            "index_pattern": s.telegraf_index_pattern,
            "last_poll": None,
            "hosts": [],
            "alerts_generated": 0,
            "status": "running"
        }
        
        try:
            from pipeline.performance_poller import performance_poller
            cached = performance_poller.get_cached_metrics()
            if cached:
                forwarder_info["performance"]["hosts"] = list(cached.keys())
                forwarder_info["performance"]["last_poll"] = datetime.now(timezone.utc).isoformat()
            
            from core.redis_performance import performance_redis
            # Get alert count from recent alerts
            alerts = await performance_redis.get_alert_history(limit=100)
            forwarder_info["performance"]["alerts_generated"] = len(alerts)
        except Exception as e:
            logger.warning("forwarder_status_perf_error", error=str(e))
    
    # Get pipeline stats
    pipeline_health = await get_pipeline_health_internal()
    
    return {
        "sources": forwarder_info,
        "pipeline": pipeline_health,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


async def get_pipeline_health_internal():
    """Internal helper to get pipeline health without circular imports."""
    result = {}
    # Check Redis
    try:
        from core import get_redis_client
        redis = await get_redis_client()
        ping_result = await redis.ping()
        result["redis"] = "healthy" if ping_result else "unhealthy"
    except Exception:
        result["redis"] = "unknown"
    
    # Check ES with a fresh client to avoid cross-event-loop issues
    try:
        from config import get_settings
        from elasticsearch import AsyncElasticsearch
        settings = get_settings()
        client_kwargs = {
            "hosts": [settings.elasticsearch_url],
            "basic_auth": (settings.elasticsearch_user, settings.elasticsearch_password),
            "ssl_show_warn": False,
        }
        if not settings.elasticsearch_use_ssl:
            import ssl
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            client_kwargs["ssl_context"] = ssl_ctx
        es = AsyncElasticsearch(**client_kwargs)
        try:
            await es.info()
            result["elasticsearch"] = "healthy"
        finally:
            await es.close()
    except Exception as e:
        result["elasticsearch"] = "unknown"
        result["error"] = str(e)[:100]
    
    # Forwarder status is inferred from other checks
    if result.get("redis") == "healthy" and result.get("elasticsearch") == "healthy":
        result["forwarder"] = "running"
    else:
        result["forwarder"] = "stopped"
    
    return result


@router.get("/services/{service}/logs")
async def get_service_logs(service: str, limit: int = Query(50, le=200)):
    """Get logs from a specific service."""
    import os
    log_file = "data/artifacts/backend.log"
    
    if not os.path.exists(log_file):
        return {"logs": [], "total": 0}
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    service_logs = [l.strip() for l in lines if service.lower() in l.lower()][-limit:]
    
    return {
        "service": service,
        "logs": service_logs,
        "total": len(service_logs)
    }


@router.get("/services/{service}/errors")
async def get_service_errors(service: str, limit: int = Query(20, le=100)):
    """Get errors from a service with linked investigations."""
    import os
    import re
    log_file = "data/artifacts/backend.log"
    
    if not os.path.exists(log_file):
        return {"errors": [], "total": 0, "related_investigation_ids": []}
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    error_lines = [l.strip() for l in lines if "[error]" in l.lower() and service.lower() in l.lower()][-limit:]
    
    investigation_ids = []
    for line in error_lines:
        match = re.search(r'investigation_id=([a-f0-9-]+)', line)
        if match:
            investigation_ids.append(match.group(1))
    
    return {
        "service": service,
        "errors": error_lines,
        "total": len(error_lines),
        "related_investigation_ids": list(set(investigation_ids))
    }


@router.get("/logs/recent")
async def get_recent_logs(limit: int = Query(50, le=200), level: Optional[str] = Query(None)):
    """Get recent backend logs."""
    import os
    log_file = "data/artifacts/backend.log"
    
    if not os.path.exists(log_file):
        return {"logs": [], "total": 0}
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    if level:
        logs = [l.strip() for l in lines if f"[{level.lower()}]" in l.lower()][-limit:]
    else:
        logs = [l.strip() for l in lines][-limit:]
    
    return {
        "logs": logs,
        "total": len(logs),
        "filters": {"level": level}
    }


@router.get("/investigations/{investigation_id}/dependencies")
async def get_investigation_dependencies(investigation_id: str):
    """Get dependency info for an investigation (what triggered it, what runs after it)."""
    from response.db import AsyncSessionLocal
    from response.models import Investigation
    from sqlalchemy import select
    
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        inv = result.scalar_one_or_none()
        
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")
        
        return {
            "investigation_id": investigation_id,
            "incident_id": inv.incident_id,
            "target_host": inv.target_host,
            "status": inv.status,
            "created_at": inv.created_at.isoformat(),
            "dependencies": {
                "triggers": f"/api/v1/incidents/{inv.incident_id}" if inv.incident_id else None,
                "host_metrics": f"/api/v1/metrics/{inv.target_host}" if inv.target_host else None,
                "alerts": f"/api/v1/incidents/{inv.incident_id}/alerts" if inv.incident_id else None
            }
        }