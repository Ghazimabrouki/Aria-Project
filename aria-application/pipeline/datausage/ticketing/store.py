"""
Ticket Store.
SQLite persistence layer for tickets and ticket history.
"""

import sqlite3
import json
import structlog
import os
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pathlib import Path

from pipeline.datausage.ticketing.models import (
    Ticket, TicketHistory, TicketCreate, TicketUpdate,
    TicketStatus, TicketPriority, TicketSeverity, TicketAction,
)

logger = structlog.get_logger()

TICKET_DB_PATH = Path("data/artifacts/tickets.db")


class TicketStore:
    def __init__(self):
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            TICKET_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(TICKET_DB_PATH))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tickets (
                id TEXT PRIMARY KEY,
                incident_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                assigned_to TEXT,
                source_ip TEXT,
                mitre_tactics TEXT,
                alert_ids TEXT,
                campaign_id TEXT,
                auto_created INTEGER,
                ai_summary TEXT,
                observable_ids TEXT,
                actions_taken TEXT,
                tags TEXT,
                created_at TEXT,
                updated_at TEXT,
                closed_at TEXT,
                closed_reason TEXT
            );

            CREATE TABLE IF NOT EXISTS ticket_history (
                id TEXT PRIMARY KEY,
                ticket_id TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT,
                actor TEXT,
                metadata TEXT,
                created_at TEXT,
                FOREIGN KEY (ticket_id) REFERENCES tickets(id)
            );

            CREATE TABLE IF NOT EXISTS ticket_config (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
            CREATE INDEX IF NOT EXISTS idx_tickets_priority ON tickets(priority);
            CREATE INDEX IF NOT EXISTS idx_tickets_severity ON tickets(severity);
            CREATE INDEX IF NOT EXISTS idx_tickets_incident_id ON tickets(incident_id);
            CREATE INDEX IF NOT EXISTS idx_tickets_source_ip ON tickets(source_ip);
            CREATE INDEX IF NOT EXISTS idx_history_ticket_id ON ticket_history(ticket_id);
        """)
        conn.commit()
        logger.info("ticket_store_initialized", db_path=str(TICKET_DB_PATH))

    def create_ticket(self, ticket_create: TicketCreate) -> Ticket:
        now = datetime.now(timezone.utc).isoformat()
        severity = ticket_create.severity
        priority = ticket_create.priority or self._calculate_priority(severity, ticket_create.mitre_tactics, ticket_create.campaign_id)

        ticket = Ticket(
            incident_id=ticket_create.incident_id,
            title=ticket_create.title,
            description=ticket_create.description,
            severity=severity,
            priority=priority,
            assigned_to=ticket_create.assigned_to,
            source_ip=ticket_create.source_ip,
            mitre_tactics=ticket_create.mitre_tactics,
            alert_ids=ticket_create.alert_ids,
            campaign_id=ticket_create.campaign_id,
            auto_created=ticket_create.auto_created,
            tags=ticket_create.tags,
            created_at=now,
            updated_at=now,
        )

        conn = self._get_conn()
        conn.execute(
            """INSERT INTO tickets (id, incident_id, title, description, severity, status, priority,
               assigned_to, source_ip, mitre_tactics, alert_ids, campaign_id, auto_created,
               ai_summary, observable_ids, actions_taken, tags, created_at, updated_at, closed_at, closed_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ticket.id, ticket.incident_id, ticket.title, ticket.description,
                ticket.severity.value, ticket.status.value, ticket.priority.value,
                ticket.assigned_to, ticket.source_ip, json.dumps(ticket.mitre_tactics),
                json.dumps(ticket.alert_ids), ticket.campaign_id, int(ticket.auto_created),
                ticket.ai_summary, json.dumps(ticket.observable_ids),
                json.dumps(ticket.actions_taken), json.dumps(ticket.tags),
                ticket.created_at, ticket.updated_at, ticket.closed_at, ticket.closed_reason,
            ),
        )

        self._add_history(ticket.id, TicketAction.CREATED, f"Ticket created: {ticket.title}", actor="system", metadata={
            "severity": ticket.severity.value,
            "priority": ticket.priority.value,
            "auto_created": ticket.auto_created,
        })

        conn.commit()
        logger.info("ticket_created", ticket_id=ticket.id, title=ticket.title[:60], priority=priority.value)
        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[Ticket]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not row:
            return None
        return self._row_to_ticket(row)

    def list_tickets(
        self,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_to: Optional[str] = None,
        incident_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Ticket]:
        conn = self._get_conn()
        query = "SELECT * FROM tickets WHERE 1=1"
        params: list = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if priority:
            query += " AND priority = ?"
            params.append(priority)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if assigned_to:
            query += " AND assigned_to = ?"
            params.append(assigned_to)
        if incident_id:
            query += " AND incident_id = ?"
            params.append(incident_id)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)

        query += " ORDER BY CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 WHEN 'P4' THEN 4 END, created_at DESC"
        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [self._row_to_ticket(r) for r in rows]

    def update_ticket(self, ticket_id: str, update: TicketUpdate) -> Optional[Ticket]:
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            return None

        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_conn()
        changes = []
        params: list = []

        if update.status is not None:
            old_status = ticket.status.value
            ticket.status = update.status
            changes.append(f"status: {old_status} -> {update.status.value}")
            if update.status == TicketStatus.CLOSED:
                ticket.closed_at = now
            elif update.status == TicketStatus.OPEN and old_status == TicketStatus.CLOSED:
                ticket.closed_at = None
                self._add_history(ticket_id, TicketAction.REOPENED, "Ticket reopened", actor="system")

        if update.priority is not None:
            old_priority = ticket.priority.value
            ticket.priority = update.priority
            changes.append(f"priority: {old_priority} -> {update.priority.value}")
            if update.priority.value in ("P1", "P2") and old_priority in ("P3", "P4"):
                self._add_history(ticket_id, TicketAction.ESCALATION, f"Escalated to {update.priority.value}", actor="system")

        if update.assigned_to is not None:
            ticket.assigned_to = update.assigned_to
            changes.append(f"assigned_to: {update.assigned_to}")

        if update.ai_summary is not None:
            ticket.ai_summary = update.ai_summary
            changes.append("ai_summary added")

        if update.closed_reason is not None:
            ticket.closed_reason = update.closed_reason
            changes.append(f"closed_reason: {update.closed_reason}")

        if update.tags is not None:
            ticket.tags = update.tags
            changes.append("tags updated")

        if not changes:
            return ticket

        ticket.updated_at = now

        conn.execute(
            """UPDATE tickets SET status=?, priority=?, assigned_to=?, ai_summary=?,
               closed_at=?, closed_reason=?, tags=?, updated_at=? WHERE id=?""",
            (
                ticket.status.value, ticket.priority.value, ticket.assigned_to,
                ticket.ai_summary, ticket.closed_at, ticket.closed_reason,
                json.dumps(ticket.tags), ticket.updated_at, ticket_id,
            ),
        )

        self._add_history(
            ticket_id,
            TicketAction.STATUS_CHANGE,
            ", ".join(changes),
            actor="system",
        )

        conn.commit()
        logger.info("ticket_updated", ticket_id=ticket_id, changes=", ".join(changes))
        return ticket

    def add_alert_to_ticket(self, ticket_id: str, alert_id: str) -> bool:
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            return False

        if alert_id in ticket.alert_ids:
            return False

        ticket.alert_ids.append(alert_id)
        ticket.updated_at = datetime.now(timezone.utc).isoformat()

        conn = self._get_conn()
        conn.execute(
            "UPDATE tickets SET alert_ids=?, updated_at=? WHERE id=?",
            (json.dumps(ticket.alert_ids), ticket.updated_at, ticket_id),
        )

        self._add_history(
            ticket_id,
            TicketAction.ALERT_LINKED,
            f"Alert linked: {alert_id}",
            actor="system",
            metadata={"alert_id": alert_id},
        )

        conn.commit()
        return True

    def add_history(
        self,
        ticket_id: str,
        action: TicketAction,
        detail: str,
        actor: str = "system",
        metadata: Optional[dict] = None,
    ) -> TicketHistory:
        return self._add_history(ticket_id, action, detail, actor, metadata)

    def _add_history(
        self,
        ticket_id: str,
        action: TicketAction,
        detail: str,
        actor: str = "system",
        metadata: Optional[dict] = None,
    ) -> TicketHistory:
        history = TicketHistory(
            ticket_id=ticket_id,
            action=action,
            detail=detail,
            actor=actor,
            metadata=metadata or {},
        )

        conn = self._get_conn()
        conn.execute(
            """INSERT INTO ticket_history (id, ticket_id, action, detail, actor, metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                history.id, history.ticket_id, history.action.value,
                history.detail, history.actor, json.dumps(history.metadata),
                history.created_at,
            ),
        )
        return history

    def get_history(self, ticket_id: str, limit: int = 50) -> List[TicketHistory]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM ticket_history WHERE ticket_id = ? ORDER BY created_at DESC LIMIT ?",
            (ticket_id, limit),
        ).fetchall()
        return [self._row_to_history(r) for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
        by_status = {}
        for row in conn.execute("SELECT status, COUNT(*) as cnt FROM tickets GROUP BY status"):
            by_status[row["status"]] = row["cnt"]
        by_priority = {}
        for row in conn.execute("SELECT priority, COUNT(*) as cnt FROM tickets GROUP BY priority"):
            by_priority[row["priority"]] = row["cnt"]
        open_count = by_status.get("open", 0) + by_status.get("investigating", 0)
        auto_created = conn.execute("SELECT COUNT(*) FROM tickets WHERE auto_created = 1").fetchone()[0]

        closed_tickets = conn.execute("SELECT closed_at FROM tickets WHERE closed_at IS NOT NULL").fetchall()
        resolution_times = []
        for row in closed_tickets:
            if row["closed_at"]:
                try:
                    closed = datetime.fromisoformat(row["closed_at"])
                    created = datetime.fromisoformat(row["closed_at"])
                    resolution_times.append((closed - created).total_seconds() / 3600)
                except ValueError:
                    pass

        avg_resolution = sum(resolution_times) / len(resolution_times) if resolution_times else 0

        return {
            "total": total,
            "open": open_count,
            "by_status": by_status,
            "by_priority": by_priority,
            "auto_created": auto_created,
            "avg_resolution_hours": round(avg_resolution, 1),
        }

    def _calculate_priority(self, severity: TicketSeverity, mitre_tactics: List[str], campaign_id: Optional[str]) -> TicketPriority:
        if severity == TicketSeverity.CRITICAL:
            return TicketPriority.P1
        if severity == TicketSeverity.HIGH:
            return TicketPriority.P2
        if severity == TicketSeverity.MEDIUM:
            kill_chain_tactics = {"initial-access", "execution", "persistence", "exfiltration", "impact"}
            if any(t.lower() in kill_chain_tactics for t in mitre_tactics):
                return TicketPriority.P2
            return TicketPriority.P3
        if campaign_id:
            return TicketPriority.P3
        return TicketPriority.P4

    def _row_to_ticket(self, row: sqlite3.Row) -> Ticket:
        return Ticket(
            id=row["id"],
            incident_id=row["incident_id"],
            title=row["title"],
            description=row["description"] or "",
            severity=TicketSeverity(row["severity"]),
            status=TicketStatus(row["status"]),
            priority=TicketPriority(row["priority"]),
            assigned_to=row["assigned_to"],
            source_ip=row["source_ip"],
            mitre_tactics=json.loads(row["mitre_tactics"]) if row["mitre_tactics"] else [],
            alert_ids=json.loads(row["alert_ids"]) if row["alert_ids"] else [],
            campaign_id=row["campaign_id"],
            auto_created=bool(row["auto_created"]),
            ai_summary=row["ai_summary"],
            observable_ids=json.loads(row["observable_ids"]) if row["observable_ids"] else [],
            actions_taken=json.loads(row["actions_taken"]) if row["actions_taken"] else [],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            closed_at=row["closed_at"],
            closed_reason=row["closed_reason"],
        )

    def _row_to_history(self, row: sqlite3.Row) -> TicketHistory:
        return TicketHistory(
            id=row["id"],
            ticket_id=row["ticket_id"],
            action=TicketAction(row["action"]),
            detail=row["detail"] or "",
            actor=row["actor"] or "system",
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_at=row["created_at"],
        )

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None


ticket_store = TicketStore()
