"""
Ticket Routing Rules.
Smart ticket creation and assignment logic based on alert/incident context.
"""

import structlog
from typing import Optional, Dict, Any, List

from pipeline.datausage.ticketing.models import (
    TicketCreate, TicketSeverity, TicketPriority,
)
from pipeline.datausage.ticketing.store import ticket_store

logger = structlog.get_logger()


AUTO_CREATE_RULES = [
    {
        "name": "critical_severity",
        "condition": lambda d: d.get("severity") == "critical",
        "severity": TicketSeverity.CRITICAL,
        "priority": TicketPriority.P1,
        "auto_create": True,
    },
    {
        "name": "high_severity",
        "condition": lambda d: d.get("severity") == "high",
        "severity": TicketSeverity.HIGH,
        "priority": TicketPriority.P2,
        "auto_create": True,
    },
    {
        "name": "mitre_kill_chain",
        "condition": lambda d: any(
            t.lower() in {"initial-access", "exfiltration", "impact", "command-and-control"}
            for t in d.get("mitre_tactics", [])
        ),
        "severity": TicketSeverity.HIGH,
        "priority": TicketPriority.P1,
        "auto_create": True,
    },
    {
        "name": "cloud_provider",
        "condition": lambda d: bool(d.get("cloud_provider")),
        "severity": None,
        "priority": TicketPriority.P2,
        "auto_create": True,
        "tags": ["cloud"],
    },
    {
        "name": "campaign_detected",
        "condition": lambda d: bool(d.get("campaign_context")),
        "severity": TicketSeverity.HIGH,
        "priority": TicketPriority.P1,
        "auto_create": True,
        "tags": ["campaign"],
    },
    {
        "name": "multi_source",
        "condition": lambda d: len(d.get("sources_seen", [])) >= 2,
        "severity": TicketSeverity.MEDIUM,
        "priority": TicketPriority.P2,
        "auto_create": True,
        "tags": ["multi-source"],
    },
]

SKIP_TICKET_RULES = [
    {
        "name": "ai_benign",
        "condition": lambda d: d.get("ai_triage_determination") == "benign",
    },
    {
        "name": "low_no_context",
        "condition": lambda d: (
            d.get("severity") == "low"
            and not d.get("mitre_tactics")
            and not d.get("campaign_context")
            and not d.get("cloud_provider")
        ),
    },
]

ASSIGNMENT_RULES = [
    {
        "condition": lambda d: any(t.lower().replace(" ", "-") == "initial-access" for t in d.get("mitre_tactics", [])),
        "team": "network-team",
    },
    {
        "condition": lambda d: any(t.lower().replace(" ", "-") == "exfiltration" for t in d.get("mitre_tactics", [])),
        "team": "incident-response",
    },
    {
        "condition": lambda d: any(t.lower().replace(" ", "-") == "privilege-escalation" for t in d.get("mitre_tactics", [])),
        "team": "endpoint-team",
    },
    {
        "condition": lambda d: any(t.lower().replace(" ", "-") == "persistence" for t in d.get("mitre_tactics", [])),
        "team": "endpoint-team",
    },
    {
        "condition": lambda d: bool(d.get("cloud_provider")),
        "team": "cloud-team",
        "tag": lambda d: f"cloud:{d.get('cloud_provider', '')}",
    },
    {
        "condition": lambda d: d.get("source") == "falco",
        "team": "container-team",
    },
]


def should_skip_ticket(alert_data: dict) -> bool:
    for rule in SKIP_TICKET_RULES:
        if rule["condition"](alert_data):
            logger.debug("ticket_skipped", rule=rule["name"])
            return True
    return False


def evaluate_auto_create(alert_data: dict) -> Optional[dict]:
    for rule in AUTO_CREATE_RULES:
        if rule["condition"](alert_data):
            return rule
    return None


def determine_assignment(alert_data: dict) -> Optional[str]:
    for rule in ASSIGNMENT_RULES:
        if rule["condition"](alert_data):
            return rule["team"]
    return None


def determine_tags(alert_data: dict) -> List[str]:
    tags = []
    for rule in AUTO_CREATE_RULES:
        if rule["condition"](alert_data) and "tags" in rule:
            tags.extend(rule["tags"])

    cloud = alert_data.get("cloud_provider")
    if cloud:
        tags.append(f"cloud:{cloud}")

    source = alert_data.get("source")
    if source:
        tags.append(f"source:{source}")

    return list(set(tags))


async def create_ticket_from_alert(alert_id: str, alert_data: dict, incident_id: Optional[str] = None) -> Optional[str]:
    if should_skip_ticket(alert_data):
        return None

    rule = evaluate_auto_create(alert_data)
    if not rule:
        return None

    title = alert_data.get("title", "Security Alert")
    description = alert_data.get("description", "")
    severity = rule["severity"] or TicketSeverity(alert_data.get("severity", "medium"))
    priority = rule.get("priority")
    tags = determine_tags(alert_data)
    assigned_team = determine_assignment(alert_data)

    if incident_id:
        title = f"Incident-linked: {title}"

    ticket_create = TicketCreate(
        incident_id=incident_id,
        title=title,
        description=description,
        severity=severity,
        priority=priority,
        assigned_to=assigned_team,
        source_ip=alert_data.get("source_ip"),
        mitre_tactics=alert_data.get("mitre_tactics", []),
        alert_ids=[alert_id],
        campaign_id=alert_data.get("campaign_id"),
        auto_created=True,
        tags=tags,
    )

    ticket = ticket_store.create_ticket(ticket_create)
    logger.info(
        "ticket_auto_created_from_alert",
        ticket_id=ticket.id,
        alert_id=alert_id,
        rule=rule["name"],
        priority=ticket.priority.value,
    )

    return ticket.id


async def create_ticket_from_incident(incident: dict) -> Optional[str]:
    incident_id = incident.get("id")
    title = incident.get("title", "Security Incident")
    description = incident.get("description", "")
    severity = incident.get("severity", "medium")
    tags = incident.get("tags", [])

    severity_map = {
        "critical": TicketSeverity.CRITICAL,
        "high": TicketSeverity.HIGH,
        "medium": TicketSeverity.MEDIUM,
        "low": TicketSeverity.LOW,
    }

    ticket_create = TicketCreate(
        incident_id=incident_id,
        title=f"Incident: {title}",
        description=description,
        severity=severity_map.get(severity, TicketSeverity.MEDIUM),
        auto_created=True,
        tags=tags,
    )

    ticket = ticket_store.create_ticket(ticket_create)
    logger.info(
        "ticket_auto_created_from_incident",
        ticket_id=ticket.id,
        incident_id=incident_id,
    )

    return ticket.id
