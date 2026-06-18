"""
Ticket Lifecycle.
State machine for ticket transitions with auto-transitions and validation.
"""

import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta

from pipeline.datausage.ticketing.models import (
    TicketStatus, TicketAction, TicketUpdate,
)
from pipeline.datausage.ticketing.store import ticket_store

logger = structlog.get_logger()

VALID_TRANSITIONS = {
    TicketStatus.OPEN: {TicketStatus.INVESTIGATING, TicketStatus.CLOSED},
    TicketStatus.INVESTIGATING: {TicketStatus.CONTAINED, TicketStatus.OPEN, TicketStatus.RESOLVED},
    TicketStatus.CONTAINED: {TicketStatus.RESOLVED, TicketStatus.INVESTIGATING},
    TicketStatus.RESOLVED: {TicketStatus.CLOSED, TicketStatus.INVESTIGATING},
    TicketStatus.CLOSED: {TicketStatus.OPEN},
}

AUTO_TRANSITION_RULES = [
    {
        "name": "stale_open_escalate",
        "from_status": TicketStatus.OPEN,
        "hours_threshold": 24,
        "action": "escalate_priority",
        "description": "Open tickets with no activity for 24h get priority escalated",
    },
    {
        "name": "investigating_all_resolved",
        "from_status": TicketStatus.INVESTIGATING,
        "condition": "all_alerts_resolved",
        "to_status": TicketStatus.CONTAINED,
        "description": "When all linked alerts are resolved, move to contained",
    },
    {
        "name": "contained_no_new_alerts",
        "from_status": TicketStatus.CONTAINED,
        "hours_threshold": 48,
        "to_status": TicketStatus.RESOLVED,
        "description": "Contained tickets with no new alerts for 48h auto-resolve",
    },
    {
        "name": "resolved_no_recurrence",
        "from_status": TicketStatus.RESOLVED,
        "hours_threshold": 168,
        "to_status": TicketStatus.CLOSED,
        "description": "Resolved tickets with 7 days no recurrence auto-close",
    },
]


def can_transition(current: TicketStatus, target: TicketStatus) -> bool:
    return target in VALID_TRANSITIONS.get(current, set())


def get_allowed_transitions(current: TicketStatus) -> List[TicketStatus]:
    return list(VALID_TRANSITIONS.get(current, set()))


async def transition_ticket(ticket_id: str, new_status: TicketStatus, reason: str = "", actor: str = "system") -> Optional[Any]:
    ticket = ticket_store.get_ticket(ticket_id)
    if not ticket:
        logger.error("transition_ticket_not_found", ticket_id=ticket_id)
        return None

    if ticket.status == new_status:
        return ticket

    if not can_transition(ticket.status, new_status):
        allowed = get_allowed_transitions(ticket.status)
        logger.warning(
            "invalid_ticket_transition",
            ticket_id=ticket_id,
            current=ticket.status.value,
            requested=new_status.value,
            allowed=[s.value for s in allowed],
        )
        return None

    update = TicketUpdate(status=new_status, closed_reason=reason if new_status == TicketStatus.CLOSED else None)
    result = ticket_store.update_ticket(ticket_id, update)

    if result:
        ticket_store.add_history(
            ticket_id,
            TicketAction.STATUS_CHANGE,
            f"Transitioned: {ticket.status.value} -> {new_status.value}. Reason: {reason}",
            actor=actor,
            metadata={"from": ticket.status.value, "to": new_status.value, "reason": reason},
        )
        logger.info(
            "ticket_transitioned",
            ticket_id=ticket_id,
            from_status=ticket.status.value,
            to_status=new_status.value,
            reason=reason,
        )

    return result


async def reopen_ticket(ticket_id: str, reason: str = "Recurrence detected", actor: str = "system") -> Optional[Any]:
    ticket = ticket_store.get_ticket(ticket_id)
    if not ticket:
        return None

    if ticket.status == TicketStatus.CLOSED:
        update = TicketUpdate(status=TicketStatus.OPEN, closed_reason=None)
        result = ticket_store.update_ticket(ticket_id, update)
        if result:
            ticket_store.add_history(
                ticket_id,
                TicketAction.REOPENED,
                f"Ticket reopened. Reason: {reason}",
                actor=actor,
                metadata={"reason": reason},
            )
            logger.info("ticket_reopened", ticket_id=ticket_id, reason=reason)
        return result
    return None


async def escalate_ticket(ticket_id: str, actor: str = "system") -> Optional[Any]:
    ticket = ticket_store.get_ticket(ticket_id)
    if not ticket:
        return None

    priority_order = {"P4": 3, "P3": 2, "P2": 1, "P1": 0}
    current_priority = priority_order.get(ticket.priority.value, 3)

    if current_priority == 0:
        return ticket

    new_priorities = ["P1", "P2", "P3"]
    new_priority = new_priorities[current_priority - 1]

    from pipeline.datausage.ticketing.models import TicketPriority
    update = TicketUpdate(priority=TicketPriority(new_priority))
    result = ticket_store.update_ticket(ticket_id, update)

    if result:
        logger.info("ticket_escalated", ticket_id=ticket_id, new_priority=new_priority)

    return result


async def run_auto_transitions() -> Dict[str, int]:
    now = datetime.now(timezone.utc)
    processed = 0

    open_tickets = ticket_store.list_tickets(status=TicketStatus.OPEN.value)
    for ticket in open_tickets:
        try:
            created = datetime.fromisoformat(ticket.created_at)
            age_hours = (now - created).total_seconds() / 3600
            if age_hours >= 24 and ticket.priority.value not in ("P1",):
                await escalate_ticket(ticket.id)
                processed += 1
        except (ValueError, TypeError):
            pass

    contained_tickets = ticket_store.list_tickets(status=TicketStatus.CONTAINED.value)
    for ticket in contained_tickets:
        try:
            updated = datetime.fromisoformat(ticket.updated_at)
            age_hours = (now - updated).total_seconds() / 3600
            if age_hours >= 48:
                await transition_ticket(ticket.id, TicketStatus.RESOLVED, "Auto-resolved: 48h no new alerts")
                processed += 1
        except (ValueError, TypeError):
            pass

    resolved_tickets = ticket_store.list_tickets(status=TicketStatus.RESOLVED.value)
    for ticket in resolved_tickets:
        try:
            updated = datetime.fromisoformat(ticket.updated_at)
            age_hours = (now - updated).total_seconds() / 3600
            if age_hours >= 168:
                await transition_ticket(ticket.id, TicketStatus.CLOSED, "Auto-closed: 7 days no recurrence")
                processed += 1
        except (ValueError, TypeError):
            pass

    if processed > 0:
        logger.info("auto_transitions_processed", count=processed)

    return {"processed": processed}
