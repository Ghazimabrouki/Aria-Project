"""Pydantic schemas for investigation routes."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

# ── Pydantic schemas ──────────────────────────────────────────────────────────


class InvestigationSummary(BaseModel):
    id: str
    incident_id: str
    local_incident_id: Optional[str] = None
    upstream_incident_id: Optional[str] = None
    incident_title: str
    incident_severity: str
    status: str
    source: str
    investigation_type: str = "security"
    ai_summary: Optional[str]
    playbook_valid: bool
    target_host: Optional[str]
    source_ips: Optional[str]
    mitre_tactics: Optional[str]
    playbook_safety_status: str = "safe"
    rollback_safety_status: str = "safe"
    is_safe_to_display: bool = True
    has_remediation_action: bool = False
    execution_mode: str = "none"
    is_executable: bool = False
    blocked_reasons: list[str] = Field(default_factory=list)
    safety_tier: str = "safe"
    hard_block_reasons: list[str] = Field(default_factory=list)
    completion_quality: str = "unknown"
    failed_phase: Optional[str] = None
    warning_phases: Optional[list] = None
    verification_status: Optional[str] = None
    ai_quality_status: str = "unknown"
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertSummary(BaseModel):
    alert_id: str
    severity: str
    source: str
    title: str
    description: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    rule_name: Optional[str] = None
    tags: list = Field(default_factory=list)
    iocs: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)
    created_at: Optional[str] = None
    raw: dict = Field(default_factory=dict)

    model_config = {"from_attributes": True}


class TruthReport(BaseModel):
    observed_facts: list[str] = Field(default_factory=list)
    inferred_findings: list[str] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    final_classification: str = "inconclusive"
    confidence: str = "low"
    evidence_quality: str = "unknown"


class InvestigationDetail(BaseModel):
    id: str
    incident_id: str
    local_incident_id: Optional[str] = None
    upstream_incident_id: Optional[str] = None
    incident_title: str
    incident_severity: str
    incident_status: str
    status: str
    source: str
    investigation_type: str = "security"
    resource_context_json: Optional[dict] = None
    ai_summary: Optional[str]
    ai_narrative: Optional[str]
    ai_risk: Optional[str]
    playbook_yaml: Optional[str]
    playbook_valid: bool
    target_host: Optional[str]
    target_user: str
    target_os: Optional[str]
    source_ips: Optional[str]
    hostnames: Optional[str]
    mitre_tactics: Optional[str]
    ai_error: Optional[str]
    evidence_json: Optional[dict]
    rollback_playbook: Optional[str]
    created_at: datetime
    updated_at: datetime
    alerts: list[AlertSummary]
    approval: Optional[dict]
    run: Optional[dict]
    verification: Optional[dict]
    workflow: Optional[dict] = None
    playbook_summary: Optional[dict] = None
    playbook_safety_status: str = "safe"
    rollback_safety_status: str = "safe"
    is_safe_to_display: bool = True
    has_remediation_action: bool = False
    execution_mode: str = "none"
    is_executable: bool = False
    blocked_reasons: list[str] = Field(default_factory=list)
    completion_quality: str = "unknown"
    failed_phase: Optional[str] = None
    warning_phases: Optional[list] = None
    verification_status: Optional[str] = None
    ai_quality_status: str = "unknown"
    ai_quality_json: Optional[dict] = None
    verification_plan_json: Optional[dict] = None
    post_rollback_verification_json: Optional[dict] = None
    truth_report: Optional[TruthReport] = None
    analyst_actions: list[str] = Field(default_factory=list)
    admin_actions: list[str] = Field(default_factory=list)
    safety_tier: str = "safe"
    hard_block_reasons: list[str] = Field(default_factory=list)
    audit_events: list[dict] = Field(default_factory=list)
    asset_id: Optional[str] = None

    model_config = {"from_attributes": True}


class ApproveRequest(BaseModel):
    decided_by: str = "analyst"


class DeclineRequest(BaseModel):
    decided_by: str = "analyst"
    reason: Optional[str] = None


class RegenerateRequest(BaseModel):
    decided_by: str = "analyst"
    reason: Optional[str] = None


class MarkReviewedRequest(BaseModel):
    decided_by: str = "analyst"
    reason: Optional[str] = None


class EditPlaybookRequest(BaseModel):
    playbook_yaml: str


class StatsResponse(BaseModel):
    pending: int
    awaiting_approval: int
    approved: int
    decision_approved: int = 0
    declined: int
    running: int
    completed: int
    completed_with_warnings: int = 0
    failed: int
    archived: int
    manual_review_required: int = 0
    regeneration_requested: int = 0
    reviewed_no_action: int = 0
    total: int


class CreateManualInvestigationRequest(BaseModel):
    incident_id: str
    target_host: Optional[str] = None
    target_user: Optional[str] = "root"
    created_by: Optional[str] = "analyst"




class RollbackRequest(BaseModel):
    decided_by: str = "analyst"
    reason: str
