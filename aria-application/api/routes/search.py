"""
Unified Search API - Search across all entities using SQLite FTS5.
Falls back to ILIKE if FTS5 is unavailable or query parsing fails.
"""
from fastapi import APIRouter, HTTPException, Query, Request, Depends
from typing import Optional
import asyncio
import structlog

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import AsyncSessionLocal
from response.search_fts import (
    parse_fts5_query,
    search_alerts_fts,
    search_incidents_fts,
    search_investigations_fts,
    search_archives_fts,
    search_alerts_ilike,
    search_incidents_ilike,
    search_investigations_ilike,
    search_archives_ilike,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/search", tags=["search"])

import os
from response.auth import require_auth, CurrentUser

# Simple in-memory rate limiting: IP -> [timestamps]
_rate_limit_store: dict = {}
MAX_SEARCH_PER_WINDOW = int(os.environ.get("SEARCH_RATE_LIMIT_MAX", "10"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("SEARCH_RATE_LIMIT_WINDOW", "10"))


def _check_rate_limit(request: Request) -> bool:
    """Return True if request is allowed, False if rate limited."""
    if os.environ.get("SEARCH_RATE_LIMIT_ENABLED", "").lower() in ("0", "false", "no"):
        return True
    client_ip = request.client.host if request.client else "unknown"
    now = asyncio.get_event_loop().time()
    timestamps = _rate_limit_store.get(client_ip, [])
    # Keep only timestamps within the window
    timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW_SECONDS]
    if len(timestamps) >= MAX_SEARCH_PER_WINDOW:
        _rate_limit_store[client_ip] = timestamps
        return False
    timestamps.append(now)
    _rate_limit_store[client_ip] = timestamps
    return True


async def _search_with_fallback(
    session: AsyncSession,
    q: str,
    limit: int,
    severity: Optional[str],
    source: Optional[str],
    date_from: Optional[str],
    date_to: Optional[str],
    asset_id: Optional[str] = None,
):
    """Try FTS5 first, fall back to ILIKE on any error."""
    try:
        fts_query = parse_fts5_query(q)
        if not fts_query:
            return {"alerts": [], "incidents": [], "investigations": [], "archives": []}

        # Execute sequentially to avoid SQLAlchemy async session concurrency issues
        alerts = await search_alerts_fts(session, fts_query, limit, severity, source, date_from, date_to, asset_id)
        incidents = await search_incidents_fts(session, fts_query, limit, severity, date_from, date_to, asset_id)
        investigations = await search_investigations_fts(session, fts_query, limit, severity, date_from, date_to, asset_id)
        archives = await search_archives_fts(session, fts_query, limit, severity, date_from, date_to, asset_id)
        return {
            "alerts": alerts,
            "incidents": incidents,
            "investigations": investigations,
            "archives": archives,
        }
    except Exception as e:
        logger.warning("fts5_search_failed_falling_back", error=str(e), query=q)

    # ILIKE fallback
    alerts = await search_alerts_ilike(session, q, limit, severity, source, asset_id)
    incidents = await search_incidents_ilike(session, q, limit, severity, asset_id)
    investigations = await search_investigations_ilike(session, q, limit, severity, asset_id)
    archives = await search_archives_ilike(session, q, limit, severity, asset_id)
    return {
        "alerts": alerts,
        "incidents": incidents,
        "investigations": investigations,
        "archives": archives,
    }


@router.get("")
async def search_all(
    request: Request,
    q: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(10, le=50),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset (alerts, incidents, investigations only)"),
    user: CurrentUser = Depends(require_auth),
):
    """Search across alerts, incidents, investigations, and archives.

    Archives are filtered by asset_id via JOIN with the Investigation table.
    All entity types are scoped when asset_id is provided.
    """
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    if not _check_rate_limit(request):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please slow down.")

    try:
        async with AsyncSessionLocal() as session:
            results = await asyncio.wait_for(
                _search_with_fallback(session, q, limit, severity, source, date_from, date_to, asset_id),
                timeout=5.0,
            )
    except asyncio.TimeoutError:
        logger.warning("search_timeout", query=q)
        raise HTTPException(status_code=504, detail="Search query timed out. Please try a simpler query.")
    except Exception as e:
        logger.warning("search_failed", error=str(e), query=q)
        raise HTTPException(status_code=500, detail="Search failed. Please try again.")

    return {
        "query": q,
        "results": results,
        "counts": {
            "alerts": len(results["alerts"]),
            "incidents": len(results["incidents"]),
            "investigations": len(results["investigations"]),
            "archives": len(results["archives"]),
        }
    }


@router.get("/ips/{ip}")
async def search_by_ip(
    request: Request,
    ip: str,
    limit: int = Query(20, le=50),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset (alerts, incidents, investigations only)"),
    user: CurrentUser = Depends(require_auth),
):
    """Find all entities with this IP."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    if not _check_rate_limit(request):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    results = {"alerts": [], "incidents": [], "investigations": [], "archives": []}

    async with AsyncSessionLocal() as session:
        # Local alerts by IP
        try:
            alert_sql = """
                SELECT a.* FROM alerts a
                WHERE (a.source_ip = :ip OR a.dest_ip = :ip
                   OR CAST(a.iocs AS TEXT) LIKE :pattern)
                {asset_filter}
                ORDER BY a.created_at DESC
                LIMIT :limit
            """
            alert_params = {"ip": ip, "pattern": f"%{ip}%", "limit": limit}
            if asset_id:
                alert_sql = alert_sql.format(asset_filter="AND a.asset_id = :asset_id")
                alert_params["asset_id"] = asset_id
            else:
                alert_sql = alert_sql.format(asset_filter="")
            alert_result = await session.execute(text(alert_sql), alert_params)
            rows = alert_result.mappings().all()
            results["alerts"] = [
                {
                    "id": r["id"],
                    "title": r["title"] or "",
                    "description": r["description"] or "",
                    "severity": r["severity"],
                    "status": r["status"],
                    "source_ip": r["source_ip"],
                    "dest_ip": r["dest_ip"],
                    "hostname": r["hostname"],
                    "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                }
                for r in rows
            ]
        except Exception as e:
            logger.warning("search_ip_alerts_failed", error=str(e))

        # Local incidents by IP
        try:
            incident_sql = """
                SELECT i.* FROM incidents i
                WHERE CAST(i.source_ips AS TEXT) LIKE :pattern
                {asset_filter}
                ORDER BY i.created_at DESC
                LIMIT :limit
            """
            incident_params = {"pattern": f"%{ip}%", "limit": limit}
            if asset_id:
                incident_sql = incident_sql.format(asset_filter="AND i.asset_id = :asset_id")
                incident_params["asset_id"] = asset_id
            else:
                incident_sql = incident_sql.format(asset_filter="")
            incident_result = await session.execute(text(incident_sql), incident_params)
            rows = incident_result.mappings().all()
            results["incidents"] = [
                {
                    "id": r["id"],
                    "title": r["title"] or "",
                    "description": r["description"] or "",
                    "severity": r["severity"],
                    "status": r["status"],
                    "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                }
                for r in rows
            ]
        except Exception as e:
            logger.warning("search_ip_incidents_failed", error=str(e))

        # Local investigations by IP
        try:
            inv_sql = """
                SELECT inv.* FROM investigations inv
                WHERE (inv.source_ips LIKE :pattern OR inv.target_host = :ip)
                {asset_filter}
                ORDER BY inv.created_at DESC
                LIMIT :limit
            """
            inv_params = {"pattern": f"%{ip}%", "ip": ip, "limit": limit}
            if asset_id:
                inv_sql = inv_sql.format(asset_filter="AND inv.asset_id = :asset_id")
                inv_params["asset_id"] = asset_id
            else:
                inv_sql = inv_sql.format(asset_filter="")
            inv_result = await session.execute(text(inv_sql), inv_params)
            rows = inv_result.mappings().all()
            results["investigations"] = [
                {
                    "id": r["id"],
                    "title": r["incident_title"] or f"Investigation {r['id']}",
                    "status": r["status"],
                    "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                }
                for r in rows
            ]
        except Exception as e:
            logger.warning("search_ip_investigations_failed", error=str(e))

        # Local archives by IP (not scoped by asset_id — Archive has no asset_id column)
        try:
            archive_result = await session.execute(
                text("""
                    SELECT ar.* FROM archives ar
                    WHERE ar.source_ips LIKE :pattern
                    ORDER BY ar.archived_at DESC
                    LIMIT :limit
                """),
                {"pattern": f"%{ip}%", "limit": limit},
            )
            rows = archive_result.mappings().all()
            results["archives"] = [
                {
                    "id": r["id"],
                    "title": r["incident_title"] or f"Archive {r['id']}",
                    "status": r["fix_status"],
                    "created_at": r["archived_at"].isoformat() if r["archived_at"] else None,
                }
                for r in rows
            ]
        except Exception as e:
            logger.warning("search_ip_archives_failed", error=str(e))

    return {
        "ip": ip,
        "results": results,
        "counts": {
            "alerts": len(results["alerts"]),
            "incidents": len(results["incidents"]),
            "investigations": len(results["investigations"]),
            "archives": len(results["archives"]),
        }
    }


@router.get("/domains/{domain}")
async def search_by_domain(
    request: Request,
    domain: str,
    limit: int = Query(20, le=50),
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset (alerts, incidents, investigations only)"),
    user: CurrentUser = Depends(require_auth),
):
    """Find all entities with this domain."""
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)

    if not _check_rate_limit(request):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    results = {"alerts": [], "incidents": [], "investigations": [], "archives": []}
    pattern = f"%{domain}%"

    async with AsyncSessionLocal() as session:
        # Local alerts
        try:
            alert_sql = """
                SELECT a.* FROM alerts a
                WHERE (a.title LIKE :pattern OR a.description LIKE :pattern
                   OR a.hostname LIKE :pattern OR CAST(a.iocs AS TEXT) LIKE :pattern)
                {asset_filter}
                ORDER BY a.created_at DESC
                LIMIT :limit
            """
            alert_params = {"pattern": pattern, "limit": limit}
            if asset_id:
                alert_sql = alert_sql.format(asset_filter="AND a.asset_id = :asset_id")
                alert_params["asset_id"] = asset_id
            else:
                alert_sql = alert_sql.format(asset_filter="")
            alert_result = await session.execute(text(alert_sql), alert_params)
            rows = alert_result.mappings().all()
            results["alerts"] = [
                {
                    "id": r["id"],
                    "title": r["title"] or "",
                    "description": r["description"] or "",
                    "severity": r["severity"],
                    "status": r["status"],
                    "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                }
                for r in rows
            ]
        except Exception as e:
            logger.warning("search_domain_alerts_failed", error=str(e))

        # Local incidents
        try:
            incident_sql = """
                SELECT i.* FROM incidents i
                WHERE (i.title LIKE :pattern OR i.description LIKE :pattern
                   OR CAST(i.hostnames AS TEXT) LIKE :pattern)
                {asset_filter}
                ORDER BY i.created_at DESC
                LIMIT :limit
            """
            incident_params = {"pattern": pattern, "limit": limit}
            if asset_id:
                incident_sql = incident_sql.format(asset_filter="AND i.asset_id = :asset_id")
                incident_params["asset_id"] = asset_id
            else:
                incident_sql = incident_sql.format(asset_filter="")
            incident_result = await session.execute(text(incident_sql), incident_params)
            rows = incident_result.mappings().all()
            results["incidents"] = [
                {
                    "id": r["id"],
                    "title": r["title"] or "",
                    "description": r["description"] or "",
                    "severity": r["severity"],
                    "status": r["status"],
                    "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                }
                for r in rows
            ]
        except Exception as e:
            logger.warning("search_domain_incidents_failed", error=str(e))

        # Local investigations
        try:
            inv_sql = """
                SELECT inv.* FROM investigations inv
                WHERE (inv.incident_title LIKE :pattern
                   OR inv.ai_summary LIKE :pattern
                   OR inv.hostnames LIKE :pattern)
                {asset_filter}
                ORDER BY inv.created_at DESC
                LIMIT :limit
            """
            inv_params = {"pattern": pattern, "limit": limit}
            if asset_id:
                inv_sql = inv_sql.format(asset_filter="AND inv.asset_id = :asset_id")
                inv_params["asset_id"] = asset_id
            else:
                inv_sql = inv_sql.format(asset_filter="")
            inv_result = await session.execute(text(inv_sql), inv_params)
            rows = inv_result.mappings().all()
            results["investigations"] = [
                {
                    "id": r["id"],
                    "title": r["incident_title"] or f"Investigation {r['id']}",
                    "status": r["status"],
                    "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                }
                for r in rows
            ]
        except Exception as e:
            logger.warning("search_domain_investigations_failed", error=str(e))

        # Local archives (not scoped by asset_id)
        try:
            archive_result = await session.execute(
                text("""
                    SELECT ar.* FROM archives ar
                    WHERE ar.incident_title LIKE :pattern
                       OR ar.hostnames LIKE :pattern
                       OR ar.fix_detail LIKE :pattern
                    ORDER BY ar.archived_at DESC
                    LIMIT :limit
                """),
                {"pattern": pattern, "limit": limit},
            )
            rows = archive_result.mappings().all()
            results["archives"] = [
                {
                    "id": r["id"],
                    "title": r["incident_title"] or f"Archive {r['id']}",
                    "status": r["fix_status"],
                    "created_at": r["archived_at"].isoformat() if r["archived_at"] else None,
                }
                for r in rows
            ]
        except Exception as e:
            logger.warning("search_domain_archives_failed", error=str(e))

    return {
        "domain": domain,
        "results": results,
        "counts": {
            "alerts": len(results["alerts"]),
            "incidents": len(results["incidents"]),
            "investigations": len(results["investigations"]),
            "archives": len(results["archives"]),
        }
    }


@router.get("/investigations/{investigation_id}/trace")
async def trace_investigation(investigation_id: str):
    """Full trace of an investigation from source to archive."""
    from response.models import Investigation, Archive
    from sqlalchemy import select

    trace = {
        "investigation_id": investigation_id,
        "steps": []
    }

    async with AsyncSessionLocal() as session:
        # Step 1: Get investigation
        result = await session.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        inv = result.scalar_one_or_none()

        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found")

        trace["steps"].append({
            "step": "investigation_created",
            "incident_id": inv.incident_id,
            "target_host": inv.target_host,
            "status": inv.status,
            "created_at": inv.created_at.isoformat()
        })

        # Step 2: Get linked incident
        if inv.incident_id:
            from config import get_settings
            if get_settings().upstream_enabled:
                try:
                    from pipeline.sender import client
                    os_incident = await client.get_incident(inv.incident_id)
                    trace["steps"].append({
                        "step": "incident_found",
                        "title": os_incident.get("title") if os_incident else None,
                        "severity": os_incident.get("severity") if os_incident else None
                    })
                except:
                    trace["steps"].append({
                        "step": "incident_lookup_failed",
                        "incident_id": inv.incident_id
                    })
            else:
                trace["steps"].append({
                    "step": "incident_lookup_skipped",
                    "reason": "upstream_disabled",
                    "incident_id": inv.incident_id
                })

        # Step 3: Check for archive
        result = await session.execute(
            select(Archive).where(Archive.investigation_id == investigation_id)
        )
        archive = result.scalar_one_or_none()

        if archive:
            trace["steps"].append({
                "step": "archived",
                "archive_id": archive.id,
                "fix_status": archive.fix_status,
                "archived_at": archive.archived_at.isoformat()
            })

        # Step 4: Add navigation links
        trace["navigation"] = {
            "incident": f"/api/v1/incidents/{inv.incident_id}" if inv.incident_id else None,
            "alerts": f"/api/v1/incidents/{inv.incident_id}/alerts" if inv.incident_id else None,
            "timeline": f"/api/v1/investigations/{investigation_id}/timeline"
        }

    return trace

