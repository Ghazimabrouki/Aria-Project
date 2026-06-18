"""
SQLite FTS5 full-text search helpers for alerts, incidents, investigations, and archives.

Provides:
- FTS5 virtual table creation and trigger setup
- Backfill of existing data
- Query parsing (user query → FTS5 syntax)
- Search functions with BM25 ranking
- ILIKE fallback for when FTS5 is unavailable
"""

import asyncio
import re
from typing import Optional, List, Dict, Any

from sqlalchemy import text, select, or_, cast, String
from sqlalchemy.ext.asyncio import AsyncSession

from response.db import engine
from response.models import Alert, Incident, Investigation, Archive

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# FTS5 schema definitions
# ---------------------------------------------------------------------------

FTS5_TABLES = {
    "alerts_fts": {
        "source_table": "alerts",
        "columns": ["title", "description", "rule_name", "hostname", "source_ip", "source", "category"],
    },
    "incidents_fts": {
        "source_table": "incidents",
        "columns": ["title", "description", "source_ips", "hostnames", "rule_ids", "tags"],
    },
    "investigations_fts": {
        "source_table": "investigations",
        "columns": ["incident_title", "ai_summary", "ai_narrative", "ai_risk", "target_host", "source_ips", "hostnames", "mitre_tactics"],
    },
    "archives_fts": {
        "source_table": "archives",
        "columns": ["incident_title", "source_ips", "hostnames", "mitre_tactics", "fix_detail"],
    },
}

TOKENIZER = "porter unicode61"


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

async def init_fts5_tables():
    """Create FTS5 virtual tables and triggers if they don't exist.
    
    Recreates tables that lack contentless_delete=1 (required for DELETE triggers).
    """
    from sqlalchemy import text
    async with engine.begin() as conn:
        for fts_name, meta in FTS5_TABLES.items():
            source = meta["source_table"]
            cols = meta["columns"]
            col_str = ", ".join(cols)

            # Check if existing virtual table needs recreation (missing contentless_delete=1)
            needs_recreate = False
            result = await conn.execute(
                text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:name"),
                {"name": fts_name}
            )
            existing = result.scalar_one_or_none()
            if existing and "contentless_delete=1" not in existing.lower():
                needs_recreate = True
                # Drop triggers first to avoid dangling references
                for trig in ["insert", "update", "delete"]:
                    await conn.execute(text(f"DROP TRIGGER IF EXISTS {source}_fts_{trig}"))
                await conn.execute(text(f"DROP TABLE IF EXISTS {fts_name}"))
                logger.info("fts5_table_recreated", table=fts_name, reason="missing_contentless_delete")

            # Create FTS5 virtual table with contentless_delete support
            create_sql = f"""
                CREATE VIRTUAL TABLE IF NOT EXISTS {fts_name} USING fts5(
                    {col_str},
                    tokenize='{TOKENIZER}',
                    content='',
                    contentless_delete=1
                )
            """
            await conn.execute(text(create_sql))

            # Drop existing triggers to avoid duplicates on re-init
            for trig in ["insert", "update", "delete"]:
                await conn.execute(text(f"DROP TRIGGER IF EXISTS {source}_fts_{trig}"))

            # INSERT trigger
            insert_vals = ", ".join([f"new.{c}" for c in cols])
            await conn.execute(text(f"""
                CREATE TRIGGER {source}_fts_insert AFTER INSERT ON {source} BEGIN
                    INSERT INTO {fts_name}(rowid, {col_str})
                    VALUES (new.rowid, {insert_vals});
                END
            """))

            # UPDATE trigger
            old_vals = ", ".join([f"old.{c}" for c in cols])
            new_vals = ", ".join([f"new.{c}" for c in cols])
            await conn.execute(text(f"""
                CREATE TRIGGER {source}_fts_update AFTER UPDATE ON {source} BEGIN
                    DELETE FROM {fts_name} WHERE rowid = old.rowid;
                    INSERT INTO {fts_name}(rowid, {col_str})
                    VALUES (new.rowid, {new_vals});
                END
            """))

            # DELETE trigger
            await conn.execute(text(f"""
                CREATE TRIGGER {source}_fts_delete AFTER DELETE ON {source} BEGIN
                    DELETE FROM {fts_name} WHERE rowid = old.rowid;
                END
            """))

    logger.info("fts5_tables_initialized")


async def backfill_fts5():
    """Backfill existing data into FTS5 tables."""
    async with engine.begin() as conn:
        for fts_name, meta in FTS5_TABLES.items():
            source = meta["source_table"]
            cols = meta["columns"]
            col_str = ", ".join(cols)

            # Delete all existing FTS5 rows for this table to avoid duplicates
            await conn.execute(text(f"DELETE FROM {fts_name}"))

            # Re-insert all rows
            await conn.execute(text(f"""
                INSERT INTO {fts_name}(rowid, {col_str})
                SELECT rowid, {col_str} FROM {source}
            """))

    logger.info("fts5_backfill_complete")


# ---------------------------------------------------------------------------
# Query parsing
# ---------------------------------------------------------------------------

def parse_fts5_query(q: str) -> str:
    """
    Convert a user search string into a safe FTS5 MATCH expression.

    Supports:
      - plain words     -> "word" (AND by default)
      - "exact phrase"  -> preserved as phrase
      - prefix*         -> preserved as prefix query
      - -word           -> NOT "word"
      - word1 OR word2  -> preserved OR
    """
    if not q or not q.strip():
        return ""

    # Split on whitespace but preserve quoted phrases
    raw_tokens = _split_query(q)
    tokens = []

    for tok in raw_tokens:
        t = tok.strip()
        if not t:
            continue

        # Preserve explicit OR/AND operators
        upper = t.upper()
        if upper == "OR" or upper == "AND":
            tokens.append(upper)
            continue

        # NOT operator
        if t.startswith("-") and len(t) > 1:
            inner = t[1:]
            tokens.append(f'NOT {_escape_fts5_token(inner)}')
            continue

        # Prefix query
        if t.endswith("*") and len(t) > 1:
            tokens.append(_escape_fts5_token(t[:-1]) + "*")
            continue

        # Phrase query (already quoted by user)
        if t.startswith('"') and t.endswith('"') and len(t) > 2:
            tokens.append(t)
            continue

        # Regular token -> wrap in quotes
        tokens.append(_escape_fts5_token(t))

    return " ".join(tokens)


def _split_query(q: str) -> List[str]:
    """Split query into tokens, respecting double-quoted phrases."""
    tokens = []
    current = []
    in_quote = False

    for ch in q:
        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
        elif ch.isspace() and not in_quote:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(ch)

    if current:
        tokens.append("".join(current))

    return tokens


def _escape_fts5_token(t: str) -> str:
    """Escape a token for safe use inside FTS5 MATCH."""
    # Escape internal double quotes
    safe = t.replace('"', '""')
    return f'"{safe}"'


# ---------------------------------------------------------------------------
# Search helpers
# ---------------------------------------------------------------------------

def _normalize_bm25(scores: List[float]) -> List[float]:
    """Convert BM25 scores (lower=better) to 0-1 relevance (higher=better)."""
    if not scores:
        return []
    min_s = min(scores)
    max_s = max(scores)
    if max_s == min_s:
        return [1.0] * len(scores)
    return [max(0.0, min(1.0, 1.0 - (s - min_s) / (max_s - min_s))) for s in scores]


async def search_alerts_fts(
    session: AsyncSession,
    fts_query: str,
    limit: int = 10,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search alerts via FTS5 with optional filters."""
    params: Dict[str, Any] = {"query": fts_query, "limit": limit}

    filters = []
    if severity:
        filters.append("a.severity = :severity")
        params["severity"] = severity
    if source:
        filters.append("a.source = :source")
        params["source"] = source
    if date_from:
        filters.append("a.created_at >= :date_from")
        params["date_from"] = date_from
    if date_to:
        filters.append("a.created_at <= :date_to")
        params["date_to"] = date_to
    if asset_id:
        filters.append("a.asset_id = :asset_id")
        params["asset_id"] = asset_id

    where_clause = " AND ".join(filters)
    if where_clause:
        where_clause = " AND " + where_clause

    sql = text(f"""
        SELECT a.*, bm25(alerts_fts) as rank
        FROM alerts_fts
        JOIN alerts a ON alerts_fts.rowid = a.rowid
        WHERE alerts_fts MATCH :query
        {where_clause}
        ORDER BY rank
        LIMIT :limit
    """)

    result = await session.execute(sql, params)
    rows = result.mappings().all()
    scores = [r["rank"] or 0.0 for r in rows]
    relevances = _normalize_bm25(scores)

    return [_alert_row_to_dict(r, relevances[i]) for i, r in enumerate(rows)]


async def search_incidents_fts(
    session: AsyncSession,
    fts_query: str,
    limit: int = 10,
    severity: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"query": fts_query, "limit": limit}

    filters = []
    if severity:
        filters.append("i.severity = :severity")
        params["severity"] = severity
    if date_from:
        filters.append("i.created_at >= :date_from")
        params["date_from"] = date_from
    if date_to:
        filters.append("i.created_at <= :date_to")
        params["date_to"] = date_to
    if asset_id:
        filters.append("i.asset_id = :asset_id")
        params["asset_id"] = asset_id

    where_clause = " AND ".join(filters)
    if where_clause:
        where_clause = " AND " + where_clause

    sql = text(f"""
        SELECT i.*, bm25(incidents_fts) as rank
        FROM incidents_fts
        JOIN incidents i ON incidents_fts.rowid = i.rowid
        WHERE incidents_fts MATCH :query
        {where_clause}
        ORDER BY rank
        LIMIT :limit
    """)

    result = await session.execute(sql, params)
    rows = result.mappings().all()
    scores = [r["rank"] or 0.0 for r in rows]
    relevances = _normalize_bm25(scores)

    return [_incident_row_to_dict(r, relevances[i]) for i, r in enumerate(rows)]


async def search_investigations_fts(
    session: AsyncSession,
    fts_query: str,
    limit: int = 10,
    severity: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"query": fts_query, "limit": limit}

    filters = []
    if severity:
        filters.append("inv.incident_severity = :severity")
        params["severity"] = severity
    if date_from:
        filters.append("inv.created_at >= :date_from")
        params["date_from"] = date_from
    if date_to:
        filters.append("inv.created_at <= :date_to")
        params["date_to"] = date_to
    if asset_id:
        filters.append("inv.asset_id = :asset_id")
        params["asset_id"] = asset_id

    where_clause = " AND ".join(filters)
    if where_clause:
        where_clause = " AND " + where_clause

    sql = text(f"""
        SELECT inv.*, bm25(investigations_fts) as rank
        FROM investigations_fts
        JOIN investigations inv ON investigations_fts.rowid = inv.rowid
        WHERE investigations_fts MATCH :query
        {where_clause}
        ORDER BY rank
        LIMIT :limit
    """)

    result = await session.execute(sql, params)
    rows = result.mappings().all()
    scores = [r["rank"] or 0.0 for r in rows]
    relevances = _normalize_bm25(scores)

    return [_investigation_row_to_dict(r, relevances[i]) for i, r in enumerate(rows)]


async def search_archives_fts(
    session: AsyncSession,
    fts_query: str,
    limit: int = 10,
    severity: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"query": fts_query, "limit": limit}

    filters = []
    if severity:
        filters.append("ar.severity = :severity")
        params["severity"] = severity
    if date_from:
        filters.append("ar.archived_at >= :date_from")
        params["date_from"] = date_from
    if date_to:
        filters.append("ar.archived_at <= :date_to")
        params["date_to"] = date_to

    where_clause = " AND ".join(filters)
    if where_clause:
        where_clause = " AND " + where_clause

    if asset_id:
        sql = text(f"""
            SELECT ar.*, bm25(archives_fts) as rank
            FROM archives_fts
            JOIN archives ar ON archives_fts.rowid = ar.rowid
            JOIN investigations inv ON ar.investigation_id = inv.id
            WHERE archives_fts MATCH :query
            {where_clause}
            AND inv.asset_id = :asset_id
            ORDER BY rank
            LIMIT :limit
        """)
        params["asset_id"] = asset_id
    else:
        sql = text(f"""
            SELECT ar.*, bm25(archives_fts) as rank
            FROM archives_fts
            JOIN archives ar ON archives_fts.rowid = ar.rowid
            WHERE archives_fts MATCH :query
            {where_clause}
            ORDER BY rank
            LIMIT :limit
        """)

    result = await session.execute(sql, params)
    rows = result.mappings().all()
    scores = [r["rank"] or 0.0 for r in rows]
    relevances = _normalize_bm25(scores)

    return [_archive_row_to_dict(r, relevances[i]) for i, r in enumerate(rows)]


# ---------------------------------------------------------------------------
# Fallback ILIKE search (used when FTS5 fails or is unavailable)
# ---------------------------------------------------------------------------

def _escape_like(s: str) -> str:
    """Escape SQL LIKE wildcards."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def search_alerts_ilike(
    session: AsyncSession,
    q: str,
    limit: int = 10,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    pattern = f"%{_escape_like(q)}%"

    conditions = [
        Alert.title.ilike(pattern),
        Alert.description.ilike(pattern),
        Alert.rule_name.ilike(pattern),
        Alert.hostname.ilike(pattern),
        Alert.source_ip.ilike(pattern),
        Alert.source.ilike(pattern),
        Alert.category.ilike(pattern),
        cast(Alert.tags, String).ilike(pattern),
    ]

    stmt = (
        select(Alert)
        .where(or_(*conditions))
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )

    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if source:
        stmt = stmt.where(Alert.source == source)
    if asset_id:
        stmt = stmt.where(Alert.asset_id == asset_id)

    result = await session.execute(stmt)
    alerts = result.scalars().all()
    return [_alert_model_to_dict(a, 1.0) for a in alerts]


async def search_incidents_ilike(
    session: AsyncSession,
    q: str,
    limit: int = 10,
    severity: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    pattern = f"%{_escape_like(q)}%"

    conditions = [
        Incident.title.ilike(pattern),
        Incident.description.ilike(pattern),
        cast(Incident.source_ips, String).ilike(pattern),
        cast(Incident.hostnames, String).ilike(pattern),
        cast(Incident.rule_ids, String).ilike(pattern),
        cast(Incident.tags, String).ilike(pattern),
    ]

    stmt = (
        select(Incident)
        .where(or_(*conditions))
        .order_by(Incident.created_at.desc())
        .limit(limit)
    )

    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if asset_id:
        stmt = stmt.where(Incident.asset_id == asset_id)

    result = await session.execute(stmt)
    incidents = result.scalars().all()
    return [_incident_model_to_dict(i, 1.0) for i in incidents]


async def search_investigations_ilike(
    session: AsyncSession,
    q: str,
    limit: int = 10,
    severity: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    pattern = f"%{_escape_like(q)}%"

    conditions = [
        Investigation.incident_title.ilike(pattern),
        Investigation.ai_summary.ilike(pattern),
        Investigation.ai_narrative.ilike(pattern),
        Investigation.ai_risk.ilike(pattern),
        Investigation.target_host.ilike(pattern),
        Investigation.source_ips.ilike(pattern),
        Investigation.hostnames.ilike(pattern),
        Investigation.mitre_tactics.ilike(pattern),
    ]

    stmt = (
        select(Investigation)
        .where(or_(*conditions))
        .order_by(Investigation.created_at.desc())
        .limit(limit)
    )

    if severity:
        stmt = stmt.where(Investigation.incident_severity == severity)
    if asset_id:
        stmt = stmt.where(Investigation.asset_id == asset_id)

    result = await session.execute(stmt)
    invs = result.scalars().all()
    return [_investigation_model_to_dict(i, 1.0) for i in invs]


async def search_archives_ilike(
    session: AsyncSession,
    q: str,
    limit: int = 10,
    severity: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    pattern = f"%{_escape_like(q)}%"

    conditions = [
        Archive.incident_title.ilike(pattern),
        Archive.source_ips.ilike(pattern),
        Archive.hostnames.ilike(pattern),
        Archive.mitre_tactics.ilike(pattern),
        Archive.fix_detail.ilike(pattern),
    ]

    stmt = (
        select(Archive)
        .where(or_(*conditions))
        .order_by(Archive.archived_at.desc())
        .limit(limit)
    )

    if severity:
        stmt = stmt.where(Archive.severity == severity)
    if asset_id:
        stmt = stmt.join(Investigation, Archive.investigation_id == Investigation.id).where(Investigation.asset_id == asset_id)

    result = await session.execute(stmt)
    archives = result.scalars().all()
    return [_archive_model_to_dict(a, 1.0) for a in archives]


# ---------------------------------------------------------------------------
# Row / model to dict converters
# ---------------------------------------------------------------------------

def _alert_row_to_dict(row, relevance: float) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "external_id": row["external_id"],
        "source": row["source"],
        "source_id": row["source_id"],
        "title": row["title"] or "",
        "description": row["description"] or "",
        "severity": row["severity"],
        "status": row["status"],
        "category": row["category"],
        "source_ip": row["source_ip"],
        "dest_ip": row["dest_ip"],
        "hostname": row["hostname"],
        "rule_name": row["rule_name"],
        "tags": row["tags"] or [],
        "iocs": row["iocs"] or {},
        "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], 'isoformat') else row["created_at"],
        "updated_at": row["updated_at"].isoformat() if hasattr(row["updated_at"], 'isoformat') else row["updated_at"],
        "relevance": round(relevance, 3),
    }


def _alert_model_to_dict(alert: Alert, relevance: float) -> Dict[str, Any]:
    return {
        "id": alert.id,
        "external_id": alert.external_id,
        "source": alert.source,
        "source_id": alert.source_id,
        "title": alert.title or "",
        "description": alert.description or "",
        "severity": alert.severity,
        "status": alert.status,
        "category": alert.category,
        "source_ip": alert.source_ip,
        "dest_ip": alert.dest_ip,
        "hostname": alert.hostname,
        "rule_name": alert.rule_name,
        "tags": alert.tags or [],
        "iocs": alert.iocs or {},
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
        "relevance": round(relevance, 3),
    }


def _incident_row_to_dict(row, relevance: float) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "external_id": row["external_id"],
        "title": row["title"] or "",
        "description": row["description"] or "",
        "severity": row["severity"],
        "status": row["status"],
        "source_ips": row["source_ips"] or [],
        "hostnames": row["hostnames"] or [],
        "rule_ids": row["rule_ids"] or [],
        "alert_ids": row["alert_ids"] or [],
        "tags": row["tags"] or [],
        "assigned_to": row["assigned_to"],
        "assigned_username": row["assigned_username"],
        "alert_count": len(row["alert_ids"] or []),
        "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], 'isoformat') else row["created_at"],
        "updated_at": row["updated_at"].isoformat() if hasattr(row["updated_at"], 'isoformat') else row["updated_at"],
        "relevance": round(relevance, 3),
    }


def _incident_model_to_dict(incident: Incident, relevance: float) -> Dict[str, Any]:
    return {
        "id": incident.id,
        "external_id": incident.external_id,
        "title": incident.title or "",
        "description": incident.description or "",
        "severity": incident.severity,
        "status": incident.status,
        "source_ips": incident.source_ips or [],
        "hostnames": incident.hostnames or [],
        "rule_ids": incident.rule_ids or [],
        "alert_ids": incident.alert_ids or [],
        "tags": incident.tags or [],
        "assigned_to": incident.assigned_to,
        "assigned_username": incident.assigned_username,
        "alert_count": len(incident.alert_ids or []),
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        "relevance": round(relevance, 3),
    }


def _investigation_row_to_dict(row, relevance: float) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["incident_title"] or f"Investigation {row['id']}",
        "status": row["status"],
        "incident_id": row["incident_id"],
        "incident_severity": row["incident_severity"],
        "target_host": row["target_host"],
        "ai_summary": row["ai_summary"],
        "created_at": row["created_at"].isoformat() if hasattr(row["created_at"], 'isoformat') else row["created_at"],
        "updated_at": row["updated_at"].isoformat() if hasattr(row["updated_at"], 'isoformat') else row["updated_at"],
        "relevance": round(relevance, 3),
    }


def _investigation_model_to_dict(inv: Investigation, relevance: float) -> Dict[str, Any]:
    return {
        "id": inv.id,
        "title": inv.incident_title or f"Investigation {inv.id}",
        "status": inv.status,
        "incident_id": inv.incident_id,
        "incident_severity": inv.incident_severity,
        "target_host": inv.target_host,
        "ai_summary": inv.ai_summary,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
        "relevance": round(relevance, 3),
    }


def _archive_row_to_dict(row, relevance: float) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "investigation_id": row["investigation_id"],
        "incident_id": row["incident_id"],
        "title": row["incident_title"] or f"Archive {row['id']}",
        "status": row["fix_status"],
        "severity": row["severity"],
        "created_at": row["archived_at"].isoformat() if hasattr(row["archived_at"], 'isoformat') else row["archived_at"],
        "relevance": round(relevance, 3),
    }


def _archive_model_to_dict(archive: Archive, relevance: float) -> Dict[str, Any]:
    return {
        "id": archive.id,
        "investigation_id": archive.investigation_id,
        "incident_id": archive.incident_id,
        "title": archive.incident_title or f"Archive {archive.id}",
        "status": archive.fix_status,
        "severity": archive.severity,
        "created_at": archive.archived_at.isoformat() if archive.archived_at else None,
        "relevance": round(relevance, 3),
    }
