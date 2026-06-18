"""
ORM models for the Response Intelligence Layer.
All 6 tables defined here.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, func, JSON, Table, Column
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from response.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Investigation(Base):
    """
    One investigation per OpenSOAR incident.
    Lifecycle: pending → awaiting_approval → approved/declined → running → completed/failed → archived
    """
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String(36), index=True)
    local_incident_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    upstream_incident_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    incident_title: Mapped[str] = mapped_column(Text, default="")
    incident_severity: Mapped[str] = mapped_column(String(20), default="medium")
    incident_status: Mapped[str] = mapped_column(String(20), default="open")

    # Investigation lifecycle status
    status: Mapped[str] = mapped_column(
        String(30),
        default="pending",
        index=True,
        # values: pending | awaiting_approval | approved | declined |
        #         running | completed | completed_with_warnings | failed | archived |
        #         manual_review_required | regeneration_requested | reviewed_no_action
    )

    # AI outputs
    ai_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_narrative: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_risk: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    playbook_yaml: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    playbook_valid: Mapped[bool] = mapped_column(default=False)

    # Target for Ansible
    target_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    target_user: Mapped[str] = mapped_column(String(100), default="root")
    target_os: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # linux | windows | unknown

    # Extracted context (stored as comma-separated for easy search)
    source_ips: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hostnames: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre_tactics: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(50), default="general")  # performance | security | general

    # Investigation type discrimination: security vs infrastructure vs runtime
    investigation_type: Mapped[str] = mapped_column(
        String(20), default="security", index=True
    )  # security | infrastructure | runtime

    # Resource context for infrastructure investigations
    resource_type: Mapped[Optional[str]] = mapped_column(String(30), nullable=True, index=True)  # cpu | memory | disk | network
    resource_context_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Diagnostic findings — structured AI interpretation of diagnostic output
    findings_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    diagnostic_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # raw Ansible stdout
    diagnostic_started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    diagnostic_finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Staged remediation artifacts
    evidence_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    rollback_playbook: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Error tracking
    ai_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Execution reliability: phase-level completion tracking
    completion_quality: Mapped[str] = mapped_column(String(20), default="unknown")
    # values: unknown | success | warning | failed
    failed_phase: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    # e.g. evidence | containment | verification
    warning_phases: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    # e.g. ["hardening", "forensics"]
    verification_status: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    # values: pending | passed | failed | skipped

    # AI quality tracking
    ai_quality_status: Mapped[str] = mapped_column(String(20), default="unknown")
    # values: unknown | passed | weak | failed
    ai_quality_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Verification plan for state-based fix verification
    verification_plan_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # e.g. {"type": "iptables_rule", "chain": "INPUT", "source": "192.0.2.1", "jump": "DROP"}

    # Post-rollback verification result (remote state confirmation after rollback)
    post_rollback_verification_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # e.g. {"status": "passed", "command": "iptables -S INPUT | grep 192.0.2.1", "exit_code": 1, "stdout": "", "stderr": ""}

    # Admin override / manual remediation metadata
    manual_override_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # Stores admin override context when normal planner cannot generate safe remediation.
    # Fields: status, admin_reason, business_justification, target_scope_confirmation,
    #         expected_impact, rollback_plan_yaml, verification_plan_yaml,
    #         risk_level, confirmation_text, created_at, updated_at,
    #         validation_result {valid, executable, reasons, blocked_tasks}

    # Multi-server asset ownership (nullable for backward compatibility)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    # Audit trail
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    # Relationships
    alerts: Mapped[list["InvestigationAlert"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    approval: Mapped[Optional["PlaybookApproval"]] = relationship(
        back_populates="investigation", uselist=False, cascade="all, delete-orphan"
    )
    run: Mapped[Optional["PlaybookRun"]] = relationship(
        back_populates="investigation", uselist=False, cascade="all, delete-orphan"
    )
    verification: Mapped[Optional["FixVerification"]] = relationship(
        back_populates="investigation", uselist=False, cascade="all, delete-orphan"
    )
    archive: Mapped[Optional["Archive"]] = relationship(
        back_populates="investigation", uselist=False, cascade="all, delete-orphan"
    )
    audit_events: Mapped[list["InvestigationAuditEvent"]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
        order_by="InvestigationAuditEvent.created_at.desc()",
    )


class InvestigationAuditEvent(Base):
    """Audit trail events for an investigation lifecycle."""
    __tablename__ = "investigation_audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(30))
    # created | ai_completed | playbook_generated | awaiting_approval |
    # approved | declined | regeneration_requested | reviewed_no_action |
    # running | completed | failed | archived | safety_blocked |
    # quality_blocked | execution_started | execution_completed |
    # verification_passed | verification_failed | playbook_edited |
    # manual_remediation_created | manual_remediation_playbook_edited |
    # manual_remediation_validated | manual_remediation_approved |
    # manual_remediation_declined | manual_remediation_executed |
    # manual_remediation_completed | manual_remediation_failed |
    # force_declined | reopened
    actor: Mapped[str] = mapped_column(String(100), default="system")
    # system | analyst | ai_engine
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    operator_label: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    auth_mode: Mapped[Optional[str]] = mapped_column(String(30), nullable=True, default="internal_trusted")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped["Investigation"] = relationship(back_populates="audit_events")


class AriaAlert(Base):
    """Internal ARIA alerting system for SOC workflow anomalies."""
    __tablename__ = "aria_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    alert_type: Mapped[str] = mapped_column(String(30), index=True)
    # unsafe_playbook | missing_rollback | ai_quality_failed | ai_quality_weak |
    # execution_failed | worker_stale | manual_review_required | regeneration_requested
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    # low | medium | high | critical
    investigation_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    acknowledged: Mapped[bool] = mapped_column(default=False)
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class InvestigationAlert(Base):
    """Snapshot of each OpenSOAR alert linked to an investigation."""
    __tablename__ = "investigation_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[str] = mapped_column(String(36), index=True)
    alert_json: Mapped[str] = mapped_column(Text)  # full alert object as JSON string
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    source: Mapped[str] = mapped_column(String(50), default="")
    title: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    investigation: Mapped["Investigation"] = relationship(back_populates="alerts")


class PlaybookApproval(Base):
    """Analyst approval or decline of the AI-generated playbook."""
    __tablename__ = "playbook_approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), unique=True
    )
    decision: Mapped[str] = mapped_column(String(20))  # approved | declined | decision_approved
    decided_by: Mapped[str] = mapped_column(String(255), default="analyst")
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # If analyst edited the playbook before approving, the edited version is stored here
    edited_playbook: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Admin override fields — separate from normal approval
    override: Mapped[bool] = mapped_column(default=False)
    override_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    override_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    override_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    original_safety_tier: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    original_blocked_reasons: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    feature_flag_used: Mapped[bool] = mapped_column(default=False)

    investigation: Mapped["Investigation"] = relationship(back_populates="approval")


class PlaybookRun(Base):
    """Ansible playbook execution result."""
    __tablename__ = "playbook_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), unique=True
    )
    status: Mapped[str] = mapped_column(
        String(20), default="running"
        # values: running | completed | failed | skipped
    )
    output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Staged remediation tracking
    current_phase: Mapped[str] = mapped_column(
        String(30), default="pending"
        # values: pending | evidence | dry_run | containment | hardening | forensics | verification | rollback | failed
    )
    phases_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Execution reliability
    completion_quality: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    # values: success | warning | failed
    failed_phase: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    warning_phases: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Verification plan for state-based fix verification
    verification_plan_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Baseline capture before execution (remote state snapshot)
    baseline_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    investigation: Mapped["Investigation"] = relationship(back_populates="run")


class FixVerification(Base):
    """Result of re-checking Elasticsearch after playbook execution."""
    __tablename__ = "fix_verifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), unique=True
    )
    status: Mapped[str] = mapped_column(
        String(20), default="checking"
        # values: checking | likely_fixed | not_fixed | inconclusive
    )
    new_alerts_found: Mapped[int] = mapped_column(Integer, default=0)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    investigation: Mapped["Investigation"] = relationship(back_populates="verification")


class FixVerificationJob(Base):
    """Persistent queue for fix verifications that must survive process restarts."""
    __tablename__ = "fix_verification_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(
        String(20), default="pending"
        # values: pending | running | completed | failed
    )
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class Archive(Base):
    """
    Permanent record of a fully resolved investigation.
    full_context_json contains everything: incident, alerts, AI output, run, verification.
    """
    __tablename__ = "archives"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), unique=True
    )
    incident_id: Mapped[str] = mapped_column(String(36), index=True)
    full_context_json: Mapped[str] = mapped_column(Text)

    # Indexed fields for search (denormalized from full_context)
    source_ips: Mapped[Optional[str]] = mapped_column(Text, nullable=True, index=True)
    hostnames: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitre_tactics: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    fix_status: Mapped[str] = mapped_column(String(30), default="unknown")
    # likely_fixed | not_fixed | inconclusive | declined | unknown | playbook_failed_but_quiet | playbook_failed_problem_worse | verified

    incident_title: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fix_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    archived_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )

    investigation: Mapped["Investigation"] = relationship(back_populates="archive")


class AssistantConversation(Base):
    """Persistent conversation thread for the AI assistant."""
    __tablename__ = "assistant_conversations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(Text, default="New Conversation")
    focus_entity_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    # investigation | incident | alert | system | None
    focus_entity_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    messages: Mapped[list["AssistantMessage"]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="AssistantMessage.created_at",
    )


class AssistantMessage(Base):
    """Single message within an assistant conversation."""
    __tablename__ = "assistant_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    conversation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assistant_conversations.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(20))  # user | assistant | action
    content: Mapped[str] = mapped_column(Text)
    actions_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sources_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    conversation: Mapped["AssistantConversation"] = relationship(back_populates="messages")


# ── Alert & Incident Shadow Store ─────────────────────────────────────────────

class Alert(Base):
    """Local shadow copy of an alert from any source."""
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    external_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    source: Mapped[str] = mapped_column(String(50), index=True)  # wazuh | suricata | falco | filebeat
    source_id: Mapped[str] = mapped_column(String(100), index=True)  # ES doc ID

    title: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)  # active | processed | archived
    category: Mapped[str] = mapped_column(String(50), default="other", index=True)  # authentication | network | malware | system | other

    source_ip: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    dest_ip: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    rule_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    iocs: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    observables: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    alert_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    raw_source_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    event_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    dedup_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    whitelisted: Mapped[bool] = mapped_column(default=False, index=True)

    # Multi-server asset ownership (nullable for backward compatibility)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    incidents: Mapped[list["Incident"]] = relationship(
        secondary="alert_incident_links", back_populates="alerts"
    )


class Incident(Base):
    """Local shadow copy of an incident with full lifecycle management."""
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    external_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    correlation_key: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)

    title: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    status: Mapped[str] = mapped_column(
        String(20),
        default="open",
        index=True,
    )  # open | investigating | resolved | archived

    source_ips: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    hostnames: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    rule_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    alert_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    resolved_by: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # auto | analyst
    soar_actions: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Assignment and categorization
    assigned_to: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    assigned_username: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    whitelisted: Mapped[bool] = mapped_column(default=False, index=True)

    # Audit trail
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Multi-server asset ownership (nullable for backward compatibility)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)

    alerts: Mapped[list["Alert"]] = relationship(
        secondary="alert_incident_links", back_populates="incidents"
    )


class AlertIncidentLink(Base):
    """Many-to-many link between alerts and incidents with correlation confidence."""
    __tablename__ = "alert_incident_links"

    alert_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    correlation_confidence: Mapped[str] = mapped_column(
        String(20), default="low"
    )  # high | medium | low | manual
    correlation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class WhitelistEntry(Base):
    """IPs, subnets, or domains that should never be blocked."""
    __tablename__ = "whitelist_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    type: Mapped[str] = mapped_column(String(20), index=True)  # ip | subnet | domain
    value: Mapped[str] = mapped_column(String(255), index=True)
    label: Mapped[str] = mapped_column(String(50), default="trusted")  # internal | trusted | admin
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class OperatorRun(Base):
    """Log of AI Operator executions."""
    __tablename__ = "operator_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    prompt: Mapped[str] = mapped_column(Text)
    intent: Mapped[str] = mapped_column(String(50), default="unknown")
    playbook_yaml: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="medium")  # low | medium | high
    target_hosts: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending | approved | running | completed | failed
    result_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    approval_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class OperatorSession(Base):
    """Persistent session for AI Operator conversations."""
    __tablename__ = "operator_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(Text, default="New Session")
    target_hosts: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    messages: Mapped[list["OperatorMessage"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", lazy="selectin"
    )


class OperatorMessage(Base):
    """Single message within an AI Operator session."""
    __tablename__ = "operator_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("operator_sessions.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(20))  # user | assistant | system | reasoning
    content: Mapped[str] = mapped_column(Text)
    playbook_yaml: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    execution_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    run_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    result_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    session: Mapped["OperatorSession"] = relationship(back_populates="messages")


class WorkerHeartbeat(Base):
    """Heartbeat record for background worker tasks."""
    __tablename__ = "worker_heartbeats"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    worker_name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="unknown")
    # values: running | warning | failed | unknown
    last_success_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class AriaAccount(Base):
    """ARIA login account: super_admin or server_user scoped to one asset."""
    __tablename__ = "aria_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30), index=True)  # super_admin | server_user
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(default=True, index=True)
    is_banned: Mapped[bool] = mapped_column(default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class MonitoredAsset(Base):
    """Manually added monitored server / VM asset."""
    __tablename__ = "monitored_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    asset_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    environment: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True, index=True)

    # Per-source configuration (index patterns + host identity fields)
    source_config_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # e.g. {"wazuh": {"index_pattern": "wazuh-alerts-4.x-*", "agent_name": "web1", "agent_id": "001"},
    #       "falco": {"index_pattern": "falco-events-*", "host_name": "web1"},
    #       "telegraf": {"index_pattern": "telegraf-*", "host_name": "web1"},
    #       "filebeat": {"index_pattern": "filebeat-*", "host_name": "web1"},
    #       "suricata": {"index_pattern": "suricata-*", "host_name": "web1"}}

    # Ansible / remediation configuration (secret refs, never raw values)
    ansible_config_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # e.g. {"ansible_host": "192.168.1.10", "ansible_user": "root", "ansible_port": 22,
    #       "auth_type": "private_key", "ssh_key_ref": "/keys/web1.pem",
    #       "password_secret_ref": "ARIA_ASSET_WEB1_ANSIBLE_PASSWORD",
    #       "become_method": "sudo", "become_password_secret_ref": "...",
    #       "remediation_enabled": false}

    remediation_enabled: Mapped[bool] = mapped_column(default=False, index=True)
    validation_status: Mapped[str] = mapped_column(String(20), default="pending")
    # pending | ok | partial | missing | error
    last_validated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
