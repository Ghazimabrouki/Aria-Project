"""
Ticket Models.
Pydantic models for ticket management.
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import uuid


class TicketStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class TicketPriority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class TicketSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TicketAction(str, Enum):
    CREATED = "created"
    STATUS_CHANGE = "status_change"
    COMMENT = "comment"
    ESCALATION = "escalation"
    AUTO_RESOLVED = "auto_resolved"
    ALERT_LINKED = "alert_linked"
    INCIDENT_LINKED = "incident_linked"
    ACTION_EXECUTED = "action_executed"
    PLAYBOOK_TRIGGERED = "playbook_triggered"
    AI_TRIAGED = "ai_triaged"
    REOPENED = "reopened"


class Ticket(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: Optional[str] = None
    title: str
    description: str = ""
    severity: TicketSeverity = TicketSeverity.MEDIUM
    status: TicketStatus = TicketStatus.OPEN
    priority: TicketPriority = TicketPriority.P3
    assigned_to: Optional[str] = None
    source_ip: Optional[str] = None
    mitre_tactics: List[str] = []
    alert_ids: List[str] = []
    campaign_id: Optional[str] = None
    auto_created: bool = False
    ai_summary: Optional[str] = None
    observable_ids: List[str] = []
    actions_taken: List[str] = []
    tags: List[str] = []
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    closed_at: Optional[str] = None
    closed_reason: Optional[str] = None


class TicketHistory(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ticket_id: str
    action: TicketAction
    detail: str = ""
    actor: str = "system"
    metadata: Dict[str, Any] = {}
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TicketCreate(BaseModel):
    incident_id: Optional[str] = None
    title: str
    description: str = ""
    severity: TicketSeverity = TicketSeverity.MEDIUM
    priority: Optional[TicketPriority] = None
    assigned_to: Optional[str] = None
    source_ip: Optional[str] = None
    mitre_tactics: List[str] = []
    alert_ids: List[str] = []
    campaign_id: Optional[str] = None
    auto_created: bool = False
    tags: List[str] = []


class TicketUpdate(BaseModel):
    status: Optional[TicketStatus] = None
    priority: Optional[TicketPriority] = None
    assigned_to: Optional[str] = None
    ai_summary: Optional[str] = None
    closed_reason: Optional[str] = None
    tags: Optional[List[str]] = None
