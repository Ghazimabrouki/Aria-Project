import { getAdminSecret, clearAdminSecret, AdminSecretRequiredError, requestAdminSecret } from "@/lib/admin-secret";

export const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8001";
export const API_VERSION = "/api/v1";

// ==================== ALERT TYPES ====================
export interface AlertIOCs {
  ips?: string[];
  hashes?: string[];
  domains?: string[];
  urls?: string[];
  [key: string]: string[] | undefined;
}

export interface Alert {
  id: string;
  source: string;
  source_id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "active" | "processed" | "archived";
  source_ip: string | null;
  dest_ip: string | null;
  hostname: string;
  rule_name: string;
  iocs: AlertIOCs;
  tags: string[];
  whitelisted?: boolean;
  created_at: string;
  updated_at: string;
  // Legacy fields for backwards compatibility
  alert_id?: string;
  timestamp?: string;
  rule_level?: number;
  rule_description?: string;
  agent_name?: string;
  agent_ip?: string;
  incident_id?: string;
  investigation_id?: string;
}

export interface AlertRelationships {
  incidents: {
    type: string;
    count: number;
    items: { id: string; title: string; status?: string }[];
    link: string;
  };
  similar: {
    type: string;
    count: number;
    items: { id: string; title: string; severity?: string; source_ip?: string | null }[];
    link: string;
  };
}

export interface AlertDetailResponse {
  data: Alert;
  relationships: AlertRelationships;
  actions: {
    view_incidents?: string;
    view_similar?: string;
  };
}

export interface AlertListResponse {
  alerts: Alert[];
  total: number;
  limit: number;
  offset: number;
}

// ==================== INCIDENT TYPES ====================
export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "open" | "investigating" | "resolved" | "archived" | "closed";
  assigned_to: string | null;
  assigned_username: string | null;
  tags: string[];
  source_ips?: string[];
  hostnames?: string[];
  whitelisted?: boolean;
  alert_count: number;
  resolved_by?: string | null;
  closed_at: string | null;
  resolved_at?: string | null;
  archived_at?: string | null;
  created_at: string;
  updated_at: string;
  investigation?: { id: string; status: string } | null;
  // Legacy fields
  incident_id?: string;
  investigation_id?: string;
}

export interface IncidentRelationships {
  alerts: {
    type: string;
    count: number;
    items: Alert[];
    link: string;
  };
  investigation: {
    type: string;
    exists: boolean;
    item: {
      id: string;
      status: string;
      ai_summary: string | null;
      has_playbook: boolean;
    } | null;
    link: string | null;
  };
}

export interface IncidentDetailResponse {
  data: Incident;
  relationships: IncidentRelationships;
}

export interface IncidentListResponse {
  incidents: Incident[];
  total: number;
  limit: number;
  offset: number;
}

export interface TimelineEvent {
  type?: string;
  event?: string;
  timestamp: string;
  description?: string;
  details?: string;
  investigation_id?: string;
  playbook_generated?: boolean;
  decided_by?: string;
  fix_verified?: boolean;
  severity?: string;
}

export interface IncidentTimeline {
  incident_id: string;
  total_events: number;
  events: TimelineEvent[];
}

// ==================== INVESTIGATION TYPES ====================
export interface Investigation {
  id: string;
  incident_id: string;
  local_incident_id?: string | null;
  upstream_incident_id?: string | null;
  incident_title: string;
  incident_severity?: string;
  incident_status?: string;
  status: "pending" | "running" | "executing" | "awaiting_approval" | "approved" | "decision_approved" | "declined" | "completed" | "completed_with_warnings" | "failed" | "archived" | "diagnosing" | "findings_ready" | "acknowledged" | "escalated" | "manual_review_required";
  severity?: "critical" | "high" | "medium" | "low";
  source?: string;
  source_ips?: string | string[];
  ai_summary?: string;
  ai_narrative?: string;
  ai_risk?: string;
  playbook_yaml?: string;
  playbook_valid?: boolean;
  playbook_error?: string | null;
  has_playbook?: boolean;
  target_host?: string;
  target_user?: string;
  target_os?: string;
  hostnames?: string;
  mitre_tactics?: string;
  ai_error?: string | null;
  evidence_json?: any;
  rollback_playbook?: string | null;
  created_at: string;
  updated_at: string;
  alerts?: {
    alert_id: string;
    severity: string;
    source: string;
    title: string;
    description?: string | null;
    source_ip?: string | null;
    dest_ip?: string | null;
    hostname?: string | null;
    rule_name?: string | null;
    tags?: string[];
    iocs?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
    created_at?: string | null;
    raw?: Record<string, unknown>;
  }[];
  asset_id?: string | null;
  approval?: {
    decision: string;
    decided_by: string;
    decided_at: string;
    reason?: string;
    edited_playbook?: string;
    override?: boolean;
    override_by?: string;
    override_at?: string;
    override_reason?: string;
    original_blocked_reasons?: string;
    feature_flag_used?: boolean;
  } | null;
  run?: {
    status: string;
    exit_code?: number;
    output?: string;
    started_at: string;
    finished_at?: string;
    current_phase?: string;
    phases?: Record<string, {
      status: string;
      exit_code: number;
      finished_at: string;
      output_preview: string;
    }>;
  } | null;
  verification?: {
    status: string;
    new_alerts_found?: number;
    checked_at: string;
    detail?: string;
  } | null;
  workflow?: {
    current_stage: WorkflowStage;
    stages: WorkflowStage[];
  } | null;
  playbook_summary?: PlaybookSummary | null;
  playbook_safety_status?: "safe" | "unsafe";
  rollback_safety_status?: "safe" | "unsafe" | "missing";
  is_safe_to_display?: boolean;
  has_remediation_action?: boolean;
  execution_mode?: "none" | "diagnostic_only" | "remediation";
  is_executable?: boolean;
  blocked_reasons?: string[];
  completion_quality?: "unknown" | "success" | "warning" | "failed";
  failed_phase?: string | null;
  warning_phases?: string[] | null;
  verification_status?: string | null;
  ai_quality_status?: "unknown" | "passed" | "weak" | "failed";
  ai_quality_json?: Record<string, unknown> | null;
  verification_plan_json?: Record<string, unknown> | null;
  post_rollback_verification_json?: {
    status: "passed" | "failed" | "skipped";
    command?: string;
    exit_code?: number;
    stdout?: string;
    stderr?: string;
    timestamp?: string;
    reason?: string;
  } | null;
  truth_report?: {
    observed_facts: string[];
    inferred_findings: string[];
    unsupported_claims: string[];
    recommended_next_steps: string[];
    final_classification: string;
    confidence: string;
    evidence_quality: string;
  } | null;
  analyst_actions?: string[];
  admin_actions?: string[];
  audit_events?: {
    event_type: string;
    actor: string;
    details?: string;
    created_at: string;
  }[];
  // Legacy fields
  investigation_id?: string;
  summary?: string;
  playbook?: Playbook;
  ai_analysis?: AIAnalysis;
  // Infrastructure fields
  investigation_type?: "security" | "infrastructure" | "runtime";
  resource_context_json?: ResourceContext | null;
}

export interface WorkflowStage {
  key: string;
  label: string;
  status: "pending" | "current" | "completed" | "failed" | string;
  timestamp?: string | null;
  details?: string;
}

export interface PlaybookSummary {
  what_it_will_do: string[];
  why_needed: string;
  target: string;
  expected_impact: string;
  rollback_possible: boolean;
  rollback_summary: string;
  verification_checks: string[];
  requires_approval: boolean;
  high_impact: boolean;
  task_count: number;
}

// ==================== INFRASTRUCTURE TYPES ====================

export interface ProcessInfo {
  name: string;
  pid: number;
  cpu_percent: number;
  memory_rss: number;
  memory_percent: number;
  cmdline?: string;
}

export interface MetricsSnapshot {
  cpu_usage_percent: number;
  cpu_user_percent: number;
  cpu_system_percent: number;
  cpu_iowait_percent: number;
  memory_used_percent: number;
  memory_used_bytes: number;
  memory_available_bytes: number;
  disk_devices: Array<{
    path: string;
    fstype: string;
    used_percent: number;
    free_bytes: number;
  }>;
  network_bytes_recv: number;
  network_bytes_sent: number;
  load_1: number;
  load_5: number;
  load_15: number;
  n_cpus: number;
  tcp_established: number;
  tcp_listen: number;
  udp_socket: number;
  proc_running: number;
  proc_sleeping: number;
  proc_total: number;
  proc_threads: number;
}

export interface ResourceContext {
  resource_type: "cpu" | "memory" | "disk" | "network";
  current_value: number;
  threshold: number;
  unit: string;
  affected_host: string;
  affected_service?: string;
  affected_process?: ProcessInfo;
  top_processes: ProcessInfo[];
  metrics_snapshot: MetricsSnapshot;
  historical_trend: string;
  baseline_deviation?: string;
  root_cause_confidence: number;
  severity: string;
  anomaly_type: string;
}

export interface SuggestedAction {
  action: string;
  risk: string;
  expected_outcome: string;
  system_impact: string;
  rollback_feasible: boolean;
}

export interface InfrastructureInvestigation {
  id: string;
  incident_id: string;
  incident_title: string;
  incident_severity: string;
  incident_status: string;
  status: string;
  source: string;
  investigation_type: "infrastructure";
  asset_id?: string | null;
  target_host?: string;
  target_user?: string;
  target_os?: string;
  target_asset?: {
    asset_id: string;
    name: string;
    enabled: boolean;
    remediation_enabled: boolean;
    ansible_host?: string;
    ansible_user?: string;
    ansible_port?: number;
  } | null;
  ai_summary?: string;
  playbook_yaml?: string;
  playbook_valid?: boolean;
  resource_context?: ResourceContext;
  findings_json?: DiagnosticFindings | null;
  diagnostic_output?: string | null;
  suggested_actions?: SuggestedAction[];
  evidence_json?: Record<string, unknown> | null;
  rollback_playbook?: string | null;
  ai_error?: string | null;
  created_at: string;
  updated_at: string;
  alerts?: Array<{
    alert_id: string;
    severity: string;
    source: string;
    title: string;
  }>;
  approval?: {
    decision: string;
    decided_by: string;
    decided_at: string;
    reason?: string;
    override?: boolean;
    override_by?: string;
    override_at?: string;
    override_reason?: string;
    original_blocked_reasons?: string;
    feature_flag_used?: boolean;
  } | null;
  run?: {
    status: string;
    exit_code?: number;
    output?: string;
    current_phase?: string;
    phases_json?: Record<string, unknown>;
    started_at?: string;
    finished_at?: string;
  } | null;
}

export interface InfrastructureInvestigationListResponse {
  investigations: Array<{
    id: string;
    incident_id: string;
    incident_title: string;
    incident_severity: string;
    status: string;
    investigation_type: string;
    target_host?: string;
    resource_type?: string;
    affected_service?: string;
    current_value?: number;
    threshold?: number;
    unit?: string;
    created_at: string;
    updated_at: string;
  }>;
  total: number;
  offset: number;
  limit: number;
}

export interface RuntimeInvestigation {
  id: string;
  incident_id: string;
  incident_title: string;
  incident_severity: string;
  incident_status: string;
  status: string;
  source: string;
  investigation_type: string;
  asset_id?: string | null;
  target_host?: string;
  target_user?: string;
  target_os?: string;
  target_asset?: {
    asset_id: string;
    name: string;
    enabled: boolean;
    remediation_enabled: boolean;
    ansible_host?: string;
    ansible_user?: string;
    ansible_port?: number;
  } | null;
  ai_summary?: string;
  playbook_yaml?: string;
  playbook_valid?: boolean;
  resource_context?: {
    runtime_category?: string;
    rule_name?: string;
    priority?: string;
    severity?: string;
    hostname?: string;
    proc_name?: string;
    proc_cmdline?: string;
    proc_pid?: number;
    proc_ppid?: number;
    proc_pname?: string;
    proc_exepath?: string;
    proc_ancestors?: string[];
    proc_tty?: string;
    user_name?: string;
    user_uid?: number;
    user_loginuid?: number;
    fd_name?: string;
    fd_type?: string;
    fd_sip?: string;
    fd_sport?: number;
    fd_dip?: string;
    fd_dport?: number;
    fd_rip?: string;
    fd_rport?: number;
    fd_lip?: string;
    fd_lport?: number;
    container_id?: string;
    container_name?: string;
    container_image_repository?: string;
    container_image_tag?: string;
    k8s_ns_name?: string;
    k8s_pod_name?: string;
    evt_type?: string;
    evt_category?: string;
    output_message?: string;
    falco_tags?: string[];
    mitre_techniques?: string[];
    is_intervention_required?: boolean;
    is_expected_admin_activity?: boolean;
  };
  findings_json?: {
    detected_cause?: string;
    confidence?: number;
    severity?: string;
    impact?: string;
    is_temporary?: boolean;
    is_expected?: boolean;
    technical_explanation?: string;
    evidence?: Array<{
      source: string;
      finding: string;
      timestamp: string;
    }>;
    recommendations?: Array<{
      action: string;
      priority: number;
      risk: string;
      rationale: string;
    }>;
    requires_intervention?: boolean;
    expert_summary?: string;
    threat_assessment?: string;
    runtime_category?: string;
  };
  diagnostic_output?: string;
  context_sections?: Record<string, Record<string, unknown>>;
  classification_context?: Record<string, unknown>;
  alert_payloads?: Array<Record<string, unknown>>;
  raw_snapshots?: Array<Record<string, unknown>>;
  evidence_summary?: {
    what_happened?: string;
    evidence_count: number;
    evidence: Array<Record<string, unknown>>;
  };
  diagnostic_summary?: {
    label: string;
    artifact_type: string;
    is_remediation: boolean;
    status?: string;
    exit_code?: number;
    started_at?: string;
    finished_at?: string;
    message: string;
    error?: string | null;
    // Human-readable diagnostic interpretation
    target_context?: "host" | "container" | "kubernetes";
    target?: string;
    main_finding?: string;
    conclusion?: string;
    confidence?: number;
    threat_assessment?: string;
    checked_items?: Array<{
      name: string;
      status: "checked" | "failed" | "not_available";
      result: string;
      important_values?: Record<string, unknown>;
    }>;
    evidence_extracted?: {
      file_exists?: boolean | null;
      file_permissions?: string | null;
      file_hash?: string | null;
      service_status?: string | null;
      failed_units_count?: number | null;
      recent_errors_count?: number | null;
      process_running?: boolean | null;
      container_inspected?: boolean | null;
      command_execution_status?: string | null;
    };
    diagnostic_gaps?: string[];
    meaning?: string;
    next_steps?: string[];
  };
  playbook_summary?: {
    diagnostic_playbook_yaml?: string;
    remediation_playbook_yaml?: string;
    current_playbook_label: string;
    current_playbook_is_remediation: boolean;
  };
  playbook_phases?: Record<string, unknown>;
  remediation_plan?: {
    decision?: string;
    decision_reason?: string;
    confidence?: number;
    target_context?: string;
    scope?: string;
    scope_reason?: string;
    affected_scope?: string;
    target_host?: string;
    target_container?: string;
    target_pod?: string;
    target_namespace?: string;
    target_process?: string;
    target_user?: string;
    target_file?: string;
    target_service?: string;
    target_network_endpoint?: Record<string, unknown>;
    evidence_gaps?: string[];
    corrective_actions?: Array<Record<string, unknown>>;
    rollback_actions?: Array<Record<string, unknown>>;
    verification_checks?: string[];
    approval_required?: boolean;
    destructive_action?: boolean;
    actual_remediation_available?: boolean;
    next_manual_steps?: string[];
    legacy_inconsistent_state?: boolean;
  };
  remediation_summary?: {
    actual_remediation_available: boolean;
    approval_required: boolean;
    corrective_actions: Array<Record<string, unknown>>;
    rollback_actions: Array<Record<string, unknown>>;
    message: string;
  };
  outcome_summary?: {
    final_state: string;
    decision?: string;
    fixed: boolean;
    unresolved_risk: boolean;
    message?: string;
    next_action?: string;
  };
  verification?: {
    status?: string;
    new_alerts_found?: number;
    checked_at?: string;
    detail?: string;
  };
  run?: {
    status?: string;
    exit_code?: number;
    output?: string;
    started_at?: string;
    finished_at?: string;
    current_phase?: string;
    phases?: Record<string, unknown>;
  } | null;
  available_actions?: {
    acknowledge: boolean;
    escalate: boolean;
    approve_run: boolean;
    decline: boolean;
    rediagnose: boolean;
    archive: boolean;
    reason?: string;
    create_manual_remediation?: boolean;
    edit_manual_playbook?: boolean;
    validate_manual_playbook?: boolean;
    approve_manual_remediation?: boolean;
    force_decline?: boolean;
    reopen?: boolean;
  };
  manual_override_json?: {
    status?: string;
    admin_reason?: string;
    business_justification?: string;
    target_scope_confirmation?: string;
    expected_impact?: string;
    rollback_plan_yaml?: string;
    verification_plan_yaml?: string;
    risk_level?: string;
    confirmation_text?: string | null;
    created_at?: string;
    updated_at?: string;
    validation_result?: {
      valid?: boolean;
      executable?: boolean;
      reasons?: string[];
      blocked_tasks?: string[];
      risk_level?: string;
      can_approve?: boolean;
    };
  };
  suggested_actions?: Array<{
    action: string;
    priority: number;
    risk: string;
    rationale: string;
  }>;
  evidence_json?: unknown;
  rollback_playbook?: string;
  ai_error?: string;
  created_at: string;
  updated_at: string;
  alerts?: Array<{
    alert_id: string;
    severity: string;
    source: string;
    title: string;
  }>;
}

export interface RuntimeInvestigationListResponse {
  investigations: Array<{
    id: string;
    incident_id: string;
    incident_title: string;
    incident_severity: string;
    status: string;
    investigation_type: string;
    target_host?: string;
    resource_type?: string;
    rule_name?: string;
    proc_name?: string;
    user_name?: string;
    file_path?: string;
    container?: string;
    decision?: string;
    target_context?: string;
    signature?: string;
    occurrence_count?: number;
    first_seen?: string;
    last_seen?: string;
    latest_status?: string;
    latest_decision?: string;
    created_at: string;
    updated_at: string;
  }>;
  total: number;
  offset: number;
  limit: number;
}

export interface FalcoEvent {
  id: string;
  timestamp: string;
  priority: string;
  rule: string;
  hostname: string;
  output: string;
  proc_name?: string;
  proc_cmdline?: string;
  user_name?: string;
  fd_name?: string;
  container_name?: string;
  tags: string[];
}

export interface DiagnosticFindings {
  detected_cause: string;
  confidence: number;
  severity: string;
  impact: string;
  is_temporary: boolean;
  is_expected: boolean;
  technical_explanation: string;
  evidence: Array<{
    source: string;
    finding: string;
    timestamp: string;
  }>;
  recommendations: Array<{
    action: string;
    priority: number;
    risk: string;
    rationale: string;
  }>;
  requires_action: boolean;
  expert_summary: string;
}

export interface InvestigationStats {
  pending: number;
  awaiting_approval?: number;
  manual_review_required?: number;
  approved?: number;
  declined?: number;
  running?: number;
  completed?: number;
  completed_with_warnings?: number;
  failed?: number;
  diagnosing?: number;
  findings_ready?: number;
  acknowledged?: number;
  escalated?: number;
  archived: number;
  regeneration_requested?: number;
  reviewed_no_action?: number;
  total: number;
}

export interface AriaAlert {
  id: string;
  alert_type: string;
  severity: "low" | "medium" | "high" | "critical";
  investigation_id?: string;
  incident_id?: string;
  title: string;
  description?: string;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
  created_at: string;
}

export interface AriaAlertListResponse {
  alerts: AriaAlert[];
  total: number;
  offset: number;
  limit: number;
}

export interface AriaAlertStats {
  total_unacknowledged: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
}

export interface InvestigationListResponse {
  investigations: Investigation[];
  total: number;
  offset: number;
  limit: number;
}

export interface InvestigationTimeline {
  investigation_id: string;
  events: TimelineEvent[];
}

export interface PlaybookYamlResponse {
  yaml: string;
  valid: boolean;
  investigation_id: string;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  steps: PlaybookStep[];
  status: "pending" | "approved" | "declined" | "executed";
}

export interface PlaybookStep {
  id: string;
  order: number;
  action: string;
  description: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  output?: string;
}

export interface AIAnalysis {
  threat_assessment: string;
  confidence: number;
  indicators: string[];
  recommendations: string[];
  timeline: TimelineEvent[];
}

// ==================== ARCHIVE TYPES ====================
export interface Archive {
  id: string;
  investigation_id?: string;
  incident_id: string;
  incident_title?: string;
  severity: "critical" | "high" | "medium" | "low";
  fix_status: "likely_fixed" | "not_fixed" | "unknown" | "declined" | "inconclusive" | "playbook_failed_but_quiet" | "playbook_failed_problem_worse" | "verified";
  fix_detail?: string;
  source_ips?: string | string[];
  mitre_tactics?: string;
  full_context?: Record<string, unknown>;
  archived_at: string;
  // Legacy fields
  archive_id?: string;
  summary?: string;
  resolution?: string;
  lessons_learned?: string;
}

export interface ArchiveStats {
  total_archived: number;
  fix_success_rate_pct: number;
  by_fix_status: {
    likely_fixed?: number;
    not_fixed?: number;
    unknown?: number;
    declined?: number;
    inconclusive?: number;
    playbook_failed_but_quiet?: number;
    playbook_failed_problem_worse?: number;
    verified?: number;
  };
  by_severity: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  };
}

export interface ArchiveListResponse {
  archives: Archive[];
  total: number;
}

export interface ArchiveDetailResponse {
  id: string;
  investigation_id?: string;
  incident_id: string;
  incident_title?: string;
  severity: string;
  fix_status: string;
  fix_detail?: string;
  full_context: {
    investigation?: Investigation;
    incident?: Incident;
    alerts?: Alert[];
    ai_investigation?: Record<string, unknown>;
    approval?: Record<string, unknown> | null;
    playbook_run?: Record<string, unknown> | null;
    fix_verification?: Record<string, unknown> | null;
    archived_at?: string;
  };
  archived_at: string;
}

// ==================== PIPELINE TYPES ====================
export interface PipelineStatus {
  running: boolean;
  poll_interval: number;
  batch_size: number;
  description: string;
}

export interface PipelineSource {
  source: string;
  cursor: string | null;
  documents_tracked: number;
  index_pattern: string;
  status?: "running" | "stopped" | "degraded";
  processed_count?: number;
  error_count?: number;
  sent_count?: number;
  skipped_count?: number;
  last_run?: string;
  cycles?: number;
}

export interface PipelineSourcesResponse {
  sources: PipelineSource[];
}

export interface AlertTraceStep {
  step: string;
  timestamp?: string;
  error?: string;
  count?: number;
  incident_ids?: string[];
  investigation_ids?: string[];
  source?: string;
  source_id?: string;
}

export interface AlertTrace {
  alert_id: string;
  steps: AlertTraceStep[];
}

// ==================== DASHBOARD TYPES ====================
export interface DashboardSummary {
  alerts: {
    total: number;
    active?: number;
    critical?: number;
    links: { list: string; by_severity: string };
  };
  incidents: {
    total: number;
    open: number;
    by_severity?: Record<string, number>;
    links: { list: string; by_status: string };
  };
  investigations: {
    total: number;
    active?: number;
    by_status: Record<string, number>;
    links: { list: string; stats: string; awaiting_approval: string; running: string };
  };
  archives: {
    total: number;
    links: { list: string; stats: string };
  };
  navigation: { label: string; path: string; icon: string }[];
}

export interface QuickStats {
  alerts: number;
  critical_alerts?: number;
  incidents: number;
  investigations: number;
  archives: number;
  pending_approvals?: number;
  whitelisted_alerts?: number;
  whitelisted_incidents?: number;
  alerts_delta_pct?: number | null;
  critical_alerts_delta_pct?: number | null;
  whitelisted_alerts_delta_pct?: number | null;
}

export interface DashboardStats {
  total_alerts: number;
  critical_alerts: number;
  open_incidents: number;
  active_investigations: number;
  pending_approvals: number;
  alerts_trend: TrendData[];
  incidents_by_severity: SeverityCount[];
  recent_activity: ActivityItem[];
}

export interface TrendData {
  timestamp: string;
  count: number;
}

export interface SeverityCount {
  severity: string;
  count: number;
}

export interface ActivityItem {
  id: string;
  type: "alert" | "incident" | "investigation" | "archive";
  message: string;
  timestamp: string;
}

export interface AriaAlertStats {
  total: number;
  by_severity: Record<string, number>;
  unacknowledged: number;
}

export interface SourceBreakdownItem {
  source: string;
  count: number;
}

export interface SourceBreakdown {
  range: string;
  sources: SourceBreakdownItem[];
  runtime_excluded: Record<string, number>;
}

export interface MitreTechnique {
  technique_id: string | null;
  technique: string;
  count: number;
}

export interface MitreTactic {
  tactic: string;
  count: number;
  techniques: MitreTechnique[];
}

export interface MitreCoverage {
  range: string;
  tactics: MitreTactic[];
}

export interface ResponseMetrics {
  range: string;
  mttd_seconds: number | null;
  mttr_seconds: number | null;
  operational_mttr_seconds: number | null;
  sample_size: {
    mttd: number;
    mttr: number;
    operational_mttr: number;
  };
  notes: string[];
}

export interface GeoThreatPoint {
  country: string;
  country_code: string | null;
  city: string;
  latitude: number;
  longitude: number;
  count: number;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  top_ip: string | null;
}

export interface GeoThreats {
  range: string;
  points: GeoThreatPoint[];
  unresolved_count: number;
}

// ==================== METRICS TYPES ====================
export interface HostCPU {
  current?: number;
  user?: number;
  system?: number;
  iowait?: number;
  usage_percent?: number;
  user_percent?: number;
  system_percent?: number;
  iowait_percent?: number;
}

export interface HostMemory {
  current?: number;
  used_mb?: number;
  available_mb?: number;
  used_percent?: number;
  used_bytes?: number;
  available_bytes?: number;
}

export interface HostDisk {
  device: string;
  used_percent: number;
  used_gb?: number;
  free_gb?: number;
  used_bytes?: number;
  free_bytes?: number;
  path?: string;
  fstype?: string;
  inodes_used_percent?: number;
}

export interface HostNetwork {
  in_mb?: number;
  out_mb?: number;
  bytes_recv?: number;
  bytes_sent?: number;
}

export interface HostLoad {
  "1m"?: number;
  "5m"?: number;
  "15m"?: number;
  cpus?: number;
  load_1?: number;
  load_5?: number;
  load_15?: number;
  n_cpus?: number;
}

export interface HostConnections {
  tcp_established: number;
  tcp_listen: number;
  udp: number;
  tcp_timewait?: number;
  udp_socket?: number;
}

export interface HostProcess {
  name: string;
  cpu: number;
  mem_mb?: number;
  mem_percent?: number;
  pid?: number | string;
}

export interface HostMetrics {
  cpu: HostCPU;
  memory: HostMemory;
  disk: HostDisk[];
  network: HostNetwork;
  load: HostLoad;
  connections: HostConnections;
}

export interface HostProcesses {
  top_cpu: HostProcess[];
  top_memory?: HostProcess[];
  process_states?: { state: string; count: number }[];
}

export interface MetricHost {
  hostname: string;
  ip: string | null;
  status: "normal" | "warning" | "critical";
  last_update: string;
  metrics: HostMetrics;
  processes?: HostProcesses | any;
}

export interface MetricsDashboardResponse {
  hosts: MetricHost[];
  timestamp: string;
}

export interface MetricsHostListResponse {
  hosts: string[];
  count: number;
  configured_hosts?: string | string[];
}

export interface MetricsHostDetailResponse {
  hostname: string;
  ip: string | null;
  timestamp: string;
  metrics?: {
    cpu: {
      usage_percent: number;
      user_percent: number;
      system_percent: number;
      iowait_percent: number;
    };
    memory: {
      used_percent: number;
      used_bytes: number;
      used_mb?: number;
      available_bytes: number;
      available_mb?: number;
    };
    disk: {
      device: string;
      used_percent: number;
      used_bytes: number;
      used_gb?: number;
      free_bytes: number;
      free_gb?: number;
    }[];
    disk_dirs?: { path: string; size_human: string }[];
    network: {
      bytes_recv?: number;
      bytes_sent?: number;
      in_mb?: number;
      out_mb?: number;
    };
    load: {
      load_1: number;
      load_5: number;
      load_15: number;
      n_cpus: number;
    };
    connections: {
      tcp_established: number;
      tcp_timewait: number;
      tcp_listen: number;
      udp_socket: number;
    };
  };
  processes?:
    | {
        total: number;
        running: number;
        sleeping: number;
        top_cpu: any[];
        top_memory: any[];
      }
    | any[];
  alert_status?: string;
  triggered_by?: string;
  procstat_missing?: boolean;
}

export interface MetricsHistoryResponse {
  host: string;
  metric: string;
  data_points: {
    timestamp: string;
    value: number;
  }[];
  count: number;
}

export interface MetricsRootCauseResponse {
  host: string;
  timestamp: string;
  current_issues: {
    type: string;
    severity: string;
    value: number;
    threshold: number;
    path?: string;
    message: string;
  }[];
  root_cause: string;
  confidence: number;
  recommended_action: string;
  recent_alerts: number;
  top_processes: any[];
}

export interface MetricsThresholds {
  cpu: { warning: number; critical: number };
  memory: { warning: number; critical: number };
  disk: { warning: number; critical: number };
  disk_inodes: { warning: number; critical: number };
  network_in: { warning: number; critical: number };
  network_out?: { warning: number; critical: number };
}

export interface DiskConsumer {
  path: string;
  size_human: string;
  size_bytes?: number;
  percent_of_total?: number;
  children?: DiskConsumer[];
  has_children?: boolean;
}

export interface MetricsDiskAnalysisResponse {
  hostname: string;
  disk_devices: {
    device: string;
    path: string;
    fstype?: string;
    used_percent: number;
    used_bytes: number;
    free_bytes: number;
    inodes_used_percent?: number;
  }[];
  disk_consumers: DiskConsumer[];
  disk_heuristics: string[];
  timestamp: string;
}

export interface MetricsStatusResponse {
  enabled: boolean;
  poll_interval: number;
  hosts_configured: string | string[];
  anomaly_detection: {
    enabled: boolean;
    use_ai: boolean;
    use_statistical: boolean;
    window_hours: number;
  };
  auto_remediation: {
    enabled: boolean;
    types: string[];
  };
}

export interface MetricsHealthResponse {
  status: string;
  service?: string;
  timestamp: string;
}

export interface MetricsAlertResponse {
  alerts: {
    id: string;
    source?: string;
    title?: string;
    severity: string;
    host?: string;
    hostname?: string;
    anomaly_type?: string;
    metrics?: any;
    root_cause?: string;
    confidence?: number;
    evidence?: string[];
    affected_process?: any;
    recommended_action?: string;
    tags?: string[];
    created_at?: string;
    [key: string]: any;
  }[];
  total: number;
  host?: string;
  filters?: Record<string, any>;
}

// Legacy type for backwards compatibility
export interface MetricData {
  host: string;
  timestamp: string;
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
}

export interface MetricsDashboard {
  hosts: MetricData[];
  timestamp: string;
}

// ==================== MONITORING TYPES ====================
export interface ServiceStatus {
  name: string;
  status: "running" | "stopped" | "error" | "disabled" | "idle";
  port?: number;
  poll_interval?: number;
  interval?: number;
  description?: string;
  sources?: string[];
  source_status?: Record<string, string>;
  latency_ms?: number;
  last_check?: string;
  details?: string;
}

export interface ServicesStatus {
  services: Record<string, ServiceStatus>;
  timestamp: string;
  total_running: number;
  total_error: number;
  total_stopped: number;
  total_disabled: number;
}

export interface ServiceHealth {
  name: string;
  status: "healthy" | "degraded" | "down";
  latency_ms: number;
  last_check: string;
  details?: string;
}

export interface ServiceLogsResponse {
  service: string;
  logs: string[];
  total: number;
}

export interface ServiceErrorsResponse {
  service: string;
  errors: string[];
  total: number;
  related_investigation_ids: string[];
}

export interface StuckInvestigationItem {
  id: string;
  status: string;
  severity: string;
  hours_stuck: number;
  created_at: string;
  updated_at: string;
}

export interface StuckInvestigationsResponse {
  count: number;
  stuck_investigations: StuckInvestigationItem[];
}

export interface MonitorHealth {
  status: string;
  database: string;
  timestamp: string;
}

// ==================== SEARCH TYPES ====================
export interface SearchInvestigation {
  id: string;
  title: string;
  status: string;
  created_at?: string;
}

export interface SearchResponse {
  query: string;
  results: {
    alerts: Alert[];
    incidents: Incident[];
    investigations: SearchInvestigation[];
    archives: SearchInvestigation[];
  };
  counts: {
    alerts: number;
    incidents: number;
    investigations: number;
    archives: number;
  };
}

export interface IPSearchResponse {
  ip: string;
  results: {
    alerts: Alert[];
    incidents: Incident[];
    investigations?: SearchInvestigation[];
    archives?: SearchInvestigation[];
  };
  counts: {
    alerts: number;
    incidents: number;
    investigations?: number;
    archives?: number;
  };
}

export interface DomainSearchResponse {
  domain: string;
  results: {
    alerts: Alert[];
    incidents: Incident[];
    investigations?: SearchInvestigation[];
    archives?: SearchInvestigation[];
  };
  counts: {
    alerts: number;
    incidents: number;
    investigations?: number;
    archives?: number;
  };
}

export interface SearchResult {
  type: "alert" | "incident" | "investigation" | "archive";
  id: string;
  title: string;
  description: string;
  timestamp: string;
  relevance: number;
}

// ==================== IPS MAP TYPES ====================
export interface IPSAttackSource {
  ip: string;
  port: number;
  country: string;
  country_name: string;
  city: string;
  region?: string;
  isp?: string;
  asn?: string;
  lat: number;
  lon: number;
  org?: string;
}

export interface IPSAttackDestination {
  ip: string;
  port: number;
  country: string;
  country_name: string;
  city?: string;
}

export interface IPSAttack {
  event_id: string;
  timestamp: string;
  source: IPSAttackSource;
  destination: IPSAttackDestination;
  severity: string;
  alert_name: string;
  category: string;
  protocol: string;
  signature_id?: string;
}

export interface IPSPath {
  id: string;
  from: { lat: number; lon: number; city: string; region: string; country: string };
  to: { lat: number; lon: number; city: string; region: string; country: string };
  severity: string;
  timestamp: string;
  lifecycle?: string;
}

export interface IPSMapDataResponse {
  attacks: IPSAttack[];
  paths: IPSPath[];
  count: number;
  timestamp: string;
}

export interface IPSLiveEvent {
  event_id: string;
  timestamp: string;
  alert_source: string;
  source_ip: string;
  source_city: string;
  source_country: string;
  source_country_code: string;
  dest_ip: string;
  dest_city: string;
  dest_country: string;
  severity: string;
  alert_name: string;
  category: string;
  protocol: string;
  lifecycle?: string;
}

export interface IPSLiveEventsResponse {
  events: IPSLiveEvent[];
  count: number;
  total: number;
  timestamp: string;
}

export interface IPSEventsResponse {
  events: IPSLiveEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface IPSStatisticsResponse {
  total_attacks: number;
  unique_sources: number;
  unique_targets: number;
  active_events: number;
  by_severity: Record<string, number>;
  by_category: { category: string; count: number }[];
  by_protocol: { protocol: string; count: number }[];
  by_lifecycle: { lifecycle: string; count: number }[];
  top_countries: { code: string; count: number; name?: string }[];
  top_isps: { isp: string; count: number }[];
  top_sources?: { ip: string; count: number; country?: string; country_name?: string }[];
  timestamp: string;
}

export interface IPSCountriesResponse {
  countries: { code: string; name: string; count: number; percentage: number }[];
  total: number;
}

export interface IPSFiltersResponse {
  severities: string[];
  categories: string[];
  protocols: string[];
  countries: string[];
  sources: string[];
}

export interface IPSSummaryResponse {
  total: number;
  active: number;
  unique_sources: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

// Legacy types for backwards compatibility
export interface AttackSource {
  ip: string;
  country: string;
  countryName: string;
  city?: string;
  lat: number;
  lon: number;
  isp?: string;
}

export interface AttackDestination {
  ip: string;
  country: string;
  countryName: string;
}

export interface AttackEvent {
  id: string;
  timestamp: string;
  source: AttackSource;
  destination: AttackDestination;
  severity: string;
  alertName: string;
}

export interface IPSMapData {
  attacks: AttackEvent[];
  count: number;
}

export interface IPSStatistics {
  total_attacks: number;
  unique_sources: number;
  active_events: number;
  by_severity: Record<string, number>;
  top_countries: { code: string; count: number }[];
}

// ==================== AI ASSISTANT TYPES ====================
export interface AssistantContext {
  available_sources: {
    name: string;
    description: string;
    endpoint: string;
  }[];
  query_tips: string[];
}

export interface AssistantHealth {
  status: string;
  llm_enabled: boolean;
  model?: string | null;
  sources?: string;
}

export interface AssistantSourcesResponse {
  sources: Record<string, number>;
  connection_status?: Record<string, string>;
}

export interface AssistantAction {
  type: string;
  label: string;
  params: Record<string, any>;
  description?: string;
}

export interface AssistantQueryRequest {
  question: string;
  conversation_id?: string;
  context?: Record<string, any>;
  sources?: string[];
  asset_id?: string;
}

export interface AssistantQueryResponse {
  answer: string;
  conversation_id: string;
  sources: Record<string, any>[];
  statistics?: {
    archives: number;
    active_investigations: number;
    live_alerts: number;
    live_incidents: number;
    performance_metrics: number;
    pipeline_sources: number;
    system_health: number;
    deep_entities?: number;
  };
  record_count: number;
  actions: AssistantAction[];
}

export interface AssistantConversation {
  id: string;
  title: string;
  focus_entity_type?: string | null;
  focus_entity_id?: string | null;
  created_at: string;
  updated_at: string;
  message_count?: number;
}

export interface AssistantConversationMessage {
  id: string;
  role: "user" | "assistant" | "action";
  content: string;
  actions?: AssistantAction[] | null;
  sources?: Record<string, any>[] | null;
  created_at: string;
}

export interface AssistantConversationDetail extends AssistantConversation {
  messages: AssistantConversationMessage[];
}

// ==================== LEGACY TYPES (for backwards compatibility) ====================
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

// ==================== API FUNCTIONS ====================

function extractErrorMessage(error: any): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message || "Request failed";
  if (error?.detail != null) {
    if (typeof error.detail === "string") return error.detail;
    if (Array.isArray(error.detail)) {
      return error.detail.map((d: any) => {
        if (typeof d === "string") return d;
        if (d?.msg) return d.msg;
        if (d?.message) return d.message;
        return JSON.stringify(d);
      }).join("; ");
    }
    if (typeof error.detail === "object") {
      if (error.detail?.message) return error.detail.message;
      if (error.detail?.msg) return error.detail.msg;
      return JSON.stringify(error.detail);
    }
  }
  if (error?.message != null && typeof error.message === "string") return error.message;
  if (error?.error != null && typeof error.error === "string") return error.error;
  if (error?.error?.message != null && typeof error.error.message === "string") return error.error.message;
  try {
    return JSON.stringify(error);
  } catch {
    return "Request failed";
  }
}

interface FetchAPIOptions extends RequestInit {
  adminSecret?: string;
  adminRequired?: boolean;
}

function isAdminSecretError(detail: string): boolean {
  if (!detail) return false;
  const lower = detail.toLowerCase();
  return (
    lower.includes("admin secret") ||
    lower.includes("x-aria-admin-secret") ||
    lower.includes("admin access is disabled")
  );
}

async function fetchAPI<T>(endpoint: string, options?: FetchAPIOptions): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string> || {}),
  };
  // Inject JWT token if available
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("aria_auth_token");
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }
  const secret = options?.adminSecret ?? (options?.adminRequired ? getAdminSecret() : null);
  if (secret) {
    headers["X-ARIA-Admin-Secret"] = secret;
  }

  const doFetch = async (): Promise<T> => {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
      cache: "no-store",
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: `HTTP ${response.status}` }));
      const message = extractErrorMessage(error) || `HTTP ${response.status}`;

      // Global admin-secret interceptor: on 403 with admin-secret message,
      // prompt user and retry exactly once.
      if (response.status === 403 && isAdminSecretError(message)) {
        clearAdminSecret();
        const newSecret = await requestAdminSecret(message);
        headers["X-ARIA-Admin-Secret"] = newSecret;
        return doFetch();
      }

      throw new Error(message);
    }

    return response.json();
  };

  try {
    return await doFetch();
  } catch (err: any) {
    if (err instanceof AdminSecretRequiredError) {
      throw err;
    }
    if (err.name === "TypeError" || err.message?.includes("fetch")) {
      throw new Error(
        "Operator backend is unreachable. Check that the API service is running on port 8001.",
        { cause: err }
      );
    }
    throw err;
  }
}



// Dashboard
export const dashboardAPI = {
  getSummary: (range?: string, asset_id?: string) =>
    fetchAPI<DashboardSummary>(
      `${API_VERSION}/dashboard/summary${range || asset_id ? `?${new URLSearchParams({ ...(range ? { range } : {}), ...(asset_id ? { asset_id } : {}) }).toString()}` : ""}`
    ),
  getQuickStats: (range?: string, asset_id?: string) =>
    fetchAPI<QuickStats>(
      `${API_VERSION}/dashboard/quick-stats${range || asset_id ? `?${new URLSearchParams({ ...(range ? { range } : {}), ...(asset_id ? { asset_id } : {}) }).toString()}` : ""}`
    ),
  getTrends: (range?: string, asset_id?: string) =>
    fetchAPI<{ range: string; buckets: { time: string; count: number }[] }>(
      `${API_VERSION}/dashboard/trends${range || asset_id ? `?${new URLSearchParams({ ...(range ? { range } : {}), ...(asset_id ? { asset_id } : {}) }).toString()}` : ""}`
    ),
  getSourceBreakdown: (range?: string, asset_id?: string) =>
    fetchAPI<SourceBreakdown>(
      `${API_VERSION}/dashboard/source-breakdown${range || asset_id ? `?${new URLSearchParams({ ...(range ? { range } : {}), ...(asset_id ? { asset_id } : {}) }).toString()}` : ""}`
    ),
  getMitreCoverage: (range?: string, asset_id?: string) =>
    fetchAPI<MitreCoverage>(
      `${API_VERSION}/dashboard/mitre-coverage${range || asset_id ? `?${new URLSearchParams({ ...(range ? { range } : {}), ...(asset_id ? { asset_id } : {}) }).toString()}` : ""}`
    ),
  getResponseMetrics: (range?: string, asset_id?: string) =>
    fetchAPI<ResponseMetrics>(
      `${API_VERSION}/dashboard/response-metrics${range || asset_id ? `?${new URLSearchParams({ ...(range ? { range } : {}), ...(asset_id ? { asset_id } : {}) }).toString()}` : ""}`
    ),
  getGeoThreats: (range?: string, asset_id?: string) =>
    fetchAPI<GeoThreats>(
      `${API_VERSION}/dashboard/geo-threats${range || asset_id ? `?${new URLSearchParams({ ...(range ? { range } : {}), ...(asset_id ? { asset_id } : {}) }).toString()}` : ""}`
    ),
};

// Alerts
export const alertsAPI = {
  list: (params?: { 
    limit?: number; 
    offset?: number; 
    status?: string; 
    severity?: string; 
    source?: string;
    hostname?: string;
    whitelisted?: boolean;
    mitre_technique?: string;
    tactic?: string;
    asset_id?: string;
    // Legacy params
    page?: number; 
    page_size?: number; 
    level?: number;
    time_from?: string;
    time_to?: string;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit != null) searchParams.set("limit", params.limit.toString());
    if (params?.offset != null) searchParams.set("offset", params.offset.toString());
    if (params?.status != null) searchParams.set("status", params.status);
    if (params?.severity != null) searchParams.set("severity", params.severity);
    if (params?.source != null) searchParams.set("source", params.source);
    if (params?.hostname != null) searchParams.set("hostname", params.hostname);
    if (params?.whitelisted != null) searchParams.set("whitelisted", params.whitelisted.toString());
    if (params?.mitre_technique != null) searchParams.set("mitre_technique", params.mitre_technique);
    if (params?.tactic != null) searchParams.set("tactic", params.tactic);
    if (params?.asset_id != null) searchParams.set("asset_id", params.asset_id);
    if (params?.time_from != null) searchParams.set("time_from", params.time_from);
    if (params?.time_to != null) searchParams.set("time_to", params.time_to);
    // Legacy
    if (params?.page != null) searchParams.set("page", params.page.toString());
    if (params?.page_size != null) searchParams.set("page_size", params.page_size.toString());
    if (params?.level != null) searchParams.set("level", params.level.toString());
    return fetchAPI<AlertListResponse>(`${API_VERSION}/alerts?${searchParams}`);
  },
  get: (id: string) => fetchAPI<AlertDetailResponse>(`${API_VERSION}/alerts/${id}`),
  getIncidents: (id: string) => fetchAPI<{ incidents: Incident[]; total: number }>(`${API_VERSION}/alerts/${id}/incidents`),
  getSimilar: (id: string) => fetchAPI<{ alerts: Alert[]; total: number; match_criteria?: { source_ip?: string; rule_name?: string } }>(`${API_VERSION}/alerts/${id}/similar`),
};

// Incidents
export const incidentsAPI = {
  list: (params?: { 
    limit?: number; 
    offset?: number; 
    status?: string; 
    severity?: string;
    assignee?: string;
    whitelisted?: boolean;
    asset_id?: string;
    // Legacy
    page?: number; 
    page_size?: number;
    time_from?: string;
    time_to?: string;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit != null) searchParams.set("limit", params.limit.toString());
    if (params?.offset != null) searchParams.set("offset", params.offset.toString());
    if (params?.status != null) searchParams.set("status", params.status);
    if (params?.severity != null) searchParams.set("severity", params.severity);
    if (params?.assignee != null) searchParams.set("assignee", params.assignee);
    if (params?.whitelisted != null) searchParams.set("whitelisted", params.whitelisted.toString());
    if (params?.asset_id != null) searchParams.set("asset_id", params.asset_id);
    if (params?.time_from != null) searchParams.set("time_from", params.time_from);
    if (params?.time_to != null) searchParams.set("time_to", params.time_to);
    // Legacy
    if (params?.page != null) searchParams.set("page", params.page.toString());
    if (params?.page_size != null) searchParams.set("page_size", params.page_size.toString());
    return fetchAPI<IncidentListResponse>(`${API_VERSION}/incidents?${searchParams}`);
  },
  get: (id: string) => fetchAPI<IncidentDetailResponse>(`${API_VERSION}/incidents/${id}`),
  getAlerts: (id: string) => fetchAPI<{ alerts: Alert[]; total: number }>(`${API_VERSION}/incidents/${id}/alerts`),
  getTimeline: (id: string) => fetchAPI<IncidentTimeline>(`${API_VERSION}/incidents/${id}/timeline`),
  getInvestigations: (id: string) => fetchAPI<{ investigations: Investigation[]; total: number }>(`${API_VERSION}/incidents/${id}/investigations`),
  getByAlert: (alertId: string) => fetchAPI<{ incidents: Incident[]; total: number }>(`${API_VERSION}/incidents/by-alert/${alertId}`),
  update: (id: string, updates: Partial<Incident>) => 
    fetchAPI<{ data: Incident }>(`${API_VERSION}/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),
  createManual: (data: {
    title: string;
    description: string;
    severity: "critical" | "high" | "medium" | "low";
    alert_ids: string[];
    source_ips?: string[];
    hostnames?: string[];
    tags?: string[];
    assigned_to?: string;
    created_by?: string;
  }) => fetchAPI<{ data: Incident; alerts: { id: string; title: string; severity: string; source: string; source_ip?: string; hostname?: string }[]; source: string }>(`${API_VERSION}/incidents/manual`, { method: "POST", body: JSON.stringify(data) }),
};

// Investigations
export const investigationsAPI = {
  list: (params?: { 
    limit?: number; 
    offset?: number; 
    status?: string;
    source?: string;
    severity?: string;
    investigation_type?: string;
    asset_id?: string;
    // Legacy
    page?: number; 
    page_size?: number;
    time_from?: string;
    time_to?: string;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit != null) searchParams.set("limit", params.limit.toString());
    if (params?.offset != null) searchParams.set("offset", params.offset.toString());
    if (params?.status != null) searchParams.set("status", params.status);
    if (params?.source != null) searchParams.set("source", params.source);
    if (params?.severity != null) searchParams.set("severity", params.severity);
    if (params?.investigation_type != null) searchParams.set("investigation_type", params.investigation_type);
    if (params?.asset_id != null) searchParams.set("asset_id", params.asset_id);
    if (params?.time_from != null) searchParams.set("time_from", params.time_from);
    if (params?.time_to != null) searchParams.set("time_to", params.time_to);
    // Legacy
    if (params?.page != null) searchParams.set("page", params.page.toString());
    if (params?.page_size != null) searchParams.set("page_size", params.page_size.toString());
    return fetchAPI<InvestigationListResponse>(`${API_VERSION}/investigations?${searchParams}`);
  },
  get: (id: string) => fetchAPI<Investigation>(`${API_VERSION}/investigations/${id}`),
  getStats: (asset_id?: string) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<InvestigationStats>(`${API_VERSION}/investigations/stats${params}`);
  },
  getPlaybookYaml: (id: string) => fetchAPI<PlaybookYamlResponse>(`${API_VERSION}/investigations/${id}/playbook/yaml`),
  updatePlaybook: (id: string, yaml: string) => 
    fetchAPI<{ message: string }>(`${API_VERSION}/investigations/${id}/playbook`, {
      method: "PUT",
      body: JSON.stringify({ playbook_yaml: yaml }),
    }),
  approve: (id: string, decidedBy: string) =>
    fetchAPI<{ message: string; investigation_id: string }>(`${API_VERSION}/investigations/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy }),
    }),
  decline: (id: string, decidedBy: string, reason?: string) =>
    fetchAPI<{ message: string; investigation_id: string }>(`${API_VERSION}/investigations/${id}/decline`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy, reason }),
    }),
  execute: (id: string, adminSecret?: string) =>
    fetchAPI<{ message: string }>(`${API_VERSION}/investigations/${id}/execute`, {
      method: "POST",
      body: JSON.stringify({ decided_by: "admin" }),
      adminSecret,
      adminRequired: true,
    }),
  getTimeline: (id: string) => fetchAPI<InvestigationTimeline>(`${API_VERSION}/investigations/${id}/timeline`),
  getRunStatus: (id: string) => fetchAPI<{
    status: string;
    exit_code: number | null;
    output: string;
    started_at: string;
    finished_at: string | null;
    current_phase: string;
    phases: Record<string, {
      status: string;
      exit_code: number;
      finished_at: string;
      output_preview: string;
    }>;
  }>(`${API_VERSION}/investigations/${id}/run-status`),
  getEvidenceFiles: (id: string) => fetchAPI<{
    investigation_id: string;
    collected_at: string | null;
    exit_code: number | null;
    target_path: string | null;
    local_path: string | null;
    archive_path: string | null;
    archive_exists: boolean;
    archive_size_bytes: number | null;
    file_count: number;
    files: {
      name: string;
      relative_path: string;
      size_bytes: number;
      modified_at: string;
    }[];
  }>(`${API_VERSION}/investigations/${id}/evidence-files`),
  archive: (id: string) =>
    fetchAPI<{ message: string; investigation_id: string }>(`${API_VERSION}/investigations/${id}/archive`, {
      method: "POST",
    }),
  requestRegeneration: (id: string, decidedBy: string, reason?: string) =>
    fetchAPI<{ message: string; investigation_id: string; status: string }>(`${API_VERSION}/investigations/${id}/request-regeneration`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy, reason }),
    }),
  markReviewed: (id: string, decidedBy: string, reason?: string) =>
    fetchAPI<{ message: string; investigation_id: string; status: string }>(`${API_VERSION}/investigations/${id}/mark-reviewed`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy, reason }),
    }),
  rollback: (id: string, decidedBy: string, reason: string, adminSecret?: string) =>
    fetchAPI<{
      message: string;
      investigation_id: string;
      status: string;
      exit_code: number;
      output: string;
      verification: {
        status: string;
        command: string;
        exit_code: number;
        stdout: string;
        stderr: string;
        timestamp: string;
      };
    }>(`${API_VERSION}/investigations/${id}/rollback`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy, reason }),
      adminSecret,
      adminRequired: true,
    }),
  createManual: (data: {
    incident_id: string;
    target_host?: string;
    target_user?: string;
    created_by?: string;
  }) => fetchAPI<{ investigation_id: string; incident_id: string; incident_title: string; incident_severity: string; status: string; source: string; target_host: string; target_user: string }>(`${API_VERSION}/investigations/manual`, { method: "POST", body: JSON.stringify(data) }),
};

// ARIA Internal Alerts
export const ariaAlertsAPI = {
  list: (params?: {
    acknowledged?: boolean;
    severity?: string;
    alert_type?: string;
    investigation_id?: string;
    limit?: number;
    offset?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.acknowledged != null) searchParams.set("acknowledged", params.acknowledged.toString());
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.alert_type) searchParams.set("alert_type", params.alert_type);
    if (params?.investigation_id) searchParams.set("investigation_id", params.investigation_id);
    if (params?.limit != null) searchParams.set("limit", params.limit.toString());
    if (params?.offset != null) searchParams.set("offset", params.offset.toString());
    return fetchAPI<AriaAlertListResponse>(`${API_VERSION}/aria-alerts?${searchParams}`);
  },
  getStats: (asset_id?: string) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<AriaAlertStats>(`${API_VERSION}/aria-alerts/stats${params}`);
  },
  acknowledge: (id: string, acknowledgedBy: string, adminSecret?: string) =>
    fetchAPI<AriaAlert>(`${API_VERSION}/aria-alerts/${id}/acknowledge`, {
      method: "POST",
      body: JSON.stringify({ acknowledged_by: acknowledgedBy }),
      adminSecret,
      adminRequired: true,
    }),
  delete: (id: string, adminSecret?: string) =>
    fetchAPI<{ message: string; alert_id: string }>(`${API_VERSION}/aria-alerts/${id}`, {
      method: "DELETE",
      adminSecret,
      adminRequired: true,
    }),
};

// Infrastructure Investigations
export const infrastructureAPI = {
  list: (params?: {
    limit?: number;
    offset?: number;
    status?: string;
    severity?: string;
    resource_type?: string;
    host?: string;
    decision?: string;
    container?: string;
    time_from?: string;
    time_to?: string;
    asset_id?: string;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit != null) searchParams.set("limit", params.limit.toString());
    if (params?.offset != null) searchParams.set("offset", params.offset.toString());
    if (params?.status != null) searchParams.set("status", params.status);
    if (params?.severity != null) searchParams.set("severity", params.severity);
    if (params?.resource_type != null) searchParams.set("resource_type", params.resource_type);
    if (params?.host != null) searchParams.set("host", params.host);
    if (params?.decision != null) searchParams.set("decision", params.decision);
    if (params?.container != null) searchParams.set("container", params.container);
    if (params?.time_from != null) searchParams.set("time_from", params.time_from);
    if (params?.time_to != null) searchParams.set("time_to", params.time_to);
    if (params?.asset_id != null) searchParams.set("asset_id", params.asset_id);
    return fetchAPI<InfrastructureInvestigationListResponse>(`${API_VERSION}/infrastructure/investigations?${searchParams}`);
  },
  get: (id: string) => fetchAPI<InfrastructureInvestigation>(`${API_VERSION}/infrastructure/investigations/${id}`),
  getResourceContext: (id: string) => fetchAPI<ResourceContext>(`${API_VERSION}/infrastructure/investigations/${id}/resource-context`),
  getSuggestedActions: (id: string) => fetchAPI<{ investigation_id: string; actions: SuggestedAction[] }>(`${API_VERSION}/infrastructure/investigations/${id}/suggested-actions`),
  acknowledge: (id: string) =>
    fetchAPI<{ status: string; investigation_id: string }>(`${API_VERSION}/infrastructure/investigations/${id}/acknowledge`, {
      method: "POST",
    }),
  escalate: (id: string) =>
    fetchAPI<{ status: string; investigation_id: string }>(`${API_VERSION}/infrastructure/investigations/${id}/escalate`, {
      method: "POST",
    }),
  getStats: () => fetchAPI<{ total: number; by_status: Record<string, number> }>(`${API_VERSION}/infrastructure/investigations/stats`),
  archive: (id: string) =>
    fetchAPI<{ status: string; investigation_id: string }>(`${API_VERSION}/infrastructure/investigations/${id}/archive`, {
      method: "POST",
    }),
  getTimeline: (id: string) =>
    fetchAPI<{ investigation_id: string; events: Array<{ type: string; timestamp: string; description: string; [key: string]: unknown }> }>(
      `${API_VERSION}/infrastructure/investigations/${id}/timeline`
    ),
};

// Runtime Security
export const runtimeAPI = {
  list: (params?: {
    limit?: number;
    offset?: number;
    status?: string;
    severity?: string;
    resource_type?: string;
    host?: string;
    decision?: string;
    container?: string;
    time_from?: string;
    time_to?: string;
    asset_id?: string;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit != null) searchParams.set("limit", params.limit.toString());
    if (params?.offset != null) searchParams.set("offset", params.offset.toString());
    if (params?.status != null) searchParams.set("status", params.status);
    if (params?.severity != null) searchParams.set("severity", params.severity);
    if (params?.resource_type != null) searchParams.set("resource_type", params.resource_type);
    if (params?.host != null) searchParams.set("host", params.host);
    if (params?.decision != null) searchParams.set("decision", params.decision);
    if (params?.container != null) searchParams.set("container", params.container);
    if (params?.time_from != null) searchParams.set("time_from", params.time_from);
    if (params?.time_to != null) searchParams.set("time_to", params.time_to);
    if (params?.asset_id != null) searchParams.set("asset_id", params.asset_id);
    return fetchAPI<RuntimeInvestigationListResponse>(`${API_VERSION}/runtime/investigations?${searchParams}`);
  },
  get: (id: string) => fetchAPI<RuntimeInvestigation>(`${API_VERSION}/runtime/investigations/${id}`),
  getStats: () => fetchAPI<{ total: number; by_status: Record<string, number>; by_category: Record<string, number> }>(`${API_VERSION}/runtime/investigations/stats`),
  acknowledge: (id: string, decidedBy = "analyst") =>
    fetchAPI<{ status: string; investigation_id: string; message?: string }>(`${API_VERSION}/runtime/investigations/${id}/acknowledge`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy }),
    }),
  escalate: (id: string, decidedBy = "analyst", reason?: string) =>
    fetchAPI<{ status: string; investigation_id: string; remediation_generated: boolean; decision?: string; message?: string }>(`${API_VERSION}/runtime/investigations/${id}/escalate`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy, ...(reason ? { reason } : {}) }),
    }),
  approve: (id: string, decidedBy = "analyst") =>
    fetchAPI<{ status: string; investigation_id: string; message?: string }>(`${API_VERSION}/runtime/investigations/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy }),
    }),
  decline: (id: string, decidedBy = "analyst", reason?: string) =>
    fetchAPI<{ status: string; investigation_id: string; message?: string }>(`${API_VERSION}/runtime/investigations/${id}/decline`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy, ...(reason ? { reason } : {}) }),
    }),
  diagnose: (id: string) =>
    fetchAPI<{ status: string; investigation_id: string; message?: string }>(`${API_VERSION}/runtime/investigations/${id}/diagnose`, {
      method: "POST",
    }),
  archive: (id: string) =>
    fetchAPI<{ status: string; investigation_id: string; message?: string }>(`${API_VERSION}/runtime/investigations/${id}/archive`, {
      method: "POST",
    }),
  getTimeline: (id: string) =>
    fetchAPI<{ investigation_id: string; events: Array<{ type: string; timestamp: string; description: string; [key: string]: unknown }> }>(
      `${API_VERSION}/runtime/investigations/${id}/timeline`
    ),
  listEvents: (params?: { limit?: number; offset?: number; priority?: string; rule?: string; host?: string; asset_id?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit != null) searchParams.set("limit", params.limit.toString());
    if (params?.offset != null) searchParams.set("offset", params.offset.toString());
    if (params?.priority != null) searchParams.set("priority", params.priority);
    if (params?.rule != null) searchParams.set("rule", params.rule);
    if (params?.host != null) searchParams.set("host", params.host);
    if (params?.asset_id != null) searchParams.set("asset_id", params.asset_id);
    return fetchAPI<{ events: FalcoEvent[]; total: number; offset: number; limit: number }>(`${API_VERSION}/runtime/events?${searchParams}`);
  },
  getEvent: (id: string) => fetchAPI<FalcoEvent>(`${API_VERSION}/runtime/events/${id}`),
  listRules: () => fetchAPI<{ rules: Array<{ name: string; count: number }> }>(`${API_VERSION}/runtime/rules`),
  manualRemediation: {
    create: (id: string, data: {
      admin_reason: string;
      business_justification: string;
      target_scope_confirmation: string;
      expected_impact: string;
      rollback_plan_yaml: string;
      verification_plan_yaml: string;
      decided_by?: string;
    }) => fetchAPI<{ status: string; investigation_id: string; message?: string }>(
      `${API_VERSION}/runtime/investigations/${id}/manual-remediation`,
      { method: "POST", body: JSON.stringify(data) }
    ),
    updatePlaybook: (id: string, playbook_yaml: string, decidedBy = "analyst") => fetchAPI<{ status: string; investigation_id: string; message?: string }>(
      `${API_VERSION}/runtime/investigations/${id}/manual-remediation/playbook`,
      { method: "PATCH", body: JSON.stringify({ playbook_yaml, decided_by: decidedBy }) }
    ),
    validate: (id: string) => fetchAPI<{
      valid: boolean;
      executable: boolean;
      reasons: string[];
      blocked_tasks: string[];
      risk_level: string;
      can_approve: boolean;
      status: string;
      investigation_id: string;
    }>(`${API_VERSION}/runtime/investigations/${id}/manual-remediation/validate`, { method: "POST" }),
    approveRun: (id: string, confirmation_text: string, decidedBy = "analyst") => fetchAPI<{ status: string; investigation_id: string; message?: string }>(
      `${API_VERSION}/runtime/investigations/${id}/manual-remediation/approve-run`,
      { method: "POST", body: JSON.stringify({ confirmation_text, decided_by: decidedBy }) }
    ),
    forceDecline: (id: string, reason: string, decidedBy = "analyst") => fetchAPI<{ status: string; investigation_id: string; message?: string }>(
      `${API_VERSION}/runtime/investigations/${id}/force-decline`,
      { method: "POST", body: JSON.stringify({ reason, decided_by: decidedBy }) }
    ),
    reopen: (id: string, reason: string, decidedBy = "analyst") => fetchAPI<{ status: string; investigation_id: string; message?: string }>(
      `${API_VERSION}/runtime/investigations/${id}/reopen`,
      { method: "POST", body: JSON.stringify({ reason, decided_by: decidedBy }) }
    ),
  },
};

// Archives
export const archivesAPI = {
  list: (params?: { 
    limit?: number; 
    offset?: number; 
    fix_status?: string;
    severity?: string;
    search?: string;
    time_from?: string;
    time_to?: string;
    asset_id?: string;
    // Legacy
    page?: number; 
    page_size?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set("limit", params.limit.toString());
    if (params?.offset) searchParams.set("offset", params.offset.toString());
    if (params?.fix_status) searchParams.set("fix_status", params.fix_status);
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.search) searchParams.set("search", params.search);
    if (params?.time_from) searchParams.set("time_from", params.time_from);
    if (params?.time_to) searchParams.set("time_to", params.time_to);
    if (params?.asset_id) searchParams.set("asset_id", params.asset_id);
    // Legacy
    if (params?.page) searchParams.set("page", params.page.toString());
    if (params?.page_size) searchParams.set("page_size", params.page_size.toString());
    return fetchAPI<ArchiveListResponse>(`${API_VERSION}/archives?${searchParams}`);
  },
  get: (id: string) => fetchAPI<ArchiveDetailResponse>(`${API_VERSION}/archives/${id}`),
  getStats: (asset_id?: string) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<ArchiveStats>(`${API_VERSION}/archives/stats${params}`);
  },
  getAlerts: (id: string) => fetchAPI<{ alerts: Alert[]; total: number }>(`${API_VERSION}/archives/${id}/alerts`),
  getByInvestigation: (investigationId: string) => fetchAPI<{ exists: boolean; archive_id?: string; investigation_id?: string; incident_id?: string; incident_title?: string; fix_status?: string; fix_detail?: string; archived_at?: string }>(`${API_VERSION}/archives/by-investigation/${investigationId}`),
  downloadPDF: async (archiveId: string) => {
    const response = await fetch(`${API_BASE}${API_VERSION}/reports/archives/${archiveId}/pdf`);
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: `HTTP ${response.status}` }));
      throw new Error(error.detail || `HTTP ${response.status}`);
    }
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `archive-report-${archiveId}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  },
};

// Pipeline
export const pipelineAPI = {
  getStatus: () => fetchAPI<PipelineStatus>(`${API_VERSION}/pipeline/status`),
  getSources: () => fetchAPI<PipelineSourcesResponse>(`${API_VERSION}/pipeline/sources`),
  getCursors: () => fetchAPI<{ cursors: Record<string, string | null> }>(`${API_VERSION}/pipeline/cursors`),
  getCursorStatus: () => fetchAPI<{
    cursors: Record<string, { redis_present: boolean; redis_value: string | null; file_present: boolean; file_value: string | null; cursor_dir: string }>;
    cursor_dir: string;
    seen_ids_dir: string;
    dedup_mode: string;
    sources: string[];
  }>(`${API_VERSION}/settings/pipeline/cursors`),
  resetCursor: (source: string, confirmation: string, adminSecret?: string) =>
    fetchAPI<{ status: string; message: string; result: any }>(`${API_VERSION}/settings/pipeline/cursors/${source}/reset`, {
      method: "POST",
      body: JSON.stringify({ confirmation }),
      adminSecret,
      adminRequired: true,
    }),
  traceAlert: (alertId: string) => fetchAPI<AlertTrace>(`${API_VERSION}/pipeline/trace/alert/${alertId}`),
  // Legacy
  getStats: (asset_id?: string) =>
    fetchAPI<{
      total_processed: number;
      error_rate: number;
      avg_processing_time: number;
      sources_monitored?: string[];
      poll_interval?: number;
      total_alerts?: number;
      total_incidents?: number;
      total_investigations?: number;
      local_alerts?: number;
      local_investigations?: number;
      total_errors?: number;
      total_sent?: number;
      total_skipped?: number;
      last_activity?: string | null;
      asset_id?: string | null;
    }>(`${API_VERSION}/pipeline/stats${asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : ""}`),
};

// Metrics (Hardware Resources)
export const metricsAPI = {
  // Get all hosts dashboard
  getDashboard: (asset_id?: string | null) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<MetricsDashboardResponse>(`${API_VERSION}/metrics/dashboard${params}`);
  },
  // List monitored hosts
  getHosts: (asset_id?: string | null) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<MetricsHostListResponse>(`${API_VERSION}/metrics/hosts${params}`);
  },
  // Get single host metrics
  getHost: (host: string, asset_id?: string | null) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<MetricsHostDetailResponse>(`${API_VERSION}/metrics/${host}${params}`);
  },
  // Get host disk analysis
  getHostDiskAnalysis: (host: string, depth?: number) => {
    const searchParams = new URLSearchParams();
    if (depth != null) searchParams.set("depth", depth.toString());
    const query = searchParams.toString() ? `?${searchParams}` : "";
    return fetchAPI<MetricsDiskAnalysisResponse>(`${API_VERSION}/metrics/${host}/disk-analysis${query}`);
  },
  // Get host history
  getHostHistory: (host: string, params?: { metric?: string; limit?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.metric) searchParams.set("metric", params.metric);
    if (params?.limit) searchParams.set("limit", params.limit.toString());
    const query = searchParams.toString() ? `?${searchParams}` : "";
    return fetchAPI<MetricsHistoryResponse>(`${API_VERSION}/metrics/${host}/history${query}`);
  },
  // Get root cause analysis
  getRootCause: (host: string) => fetchAPI<MetricsRootCauseResponse>(`${API_VERSION}/metrics/${host}/root-cause`),
  // Get thresholds
  getThresholds: () => fetchAPI<MetricsThresholds>(`${API_VERSION}/metrics/thresholds`),
  // Get status
  getStatus: () => fetchAPI<MetricsStatusResponse>(`${API_VERSION}/metrics/status`),
  // Get health
  getHealth: () => fetchAPI<MetricsHealthResponse>(`${API_VERSION}/metrics/health`),
  // Get detailed health
  getHealthDetailed: () => fetchAPI<{
    status: string;
    service: string;
    enabled: boolean;
    components: Record<string, { status: string; message?: string; indices?: string[]; cached_hosts?: string[] }>;
    timestamp: string;
  }>(`${API_VERSION}/metrics/health/detailed`),
  // Get performance alerts
  getAlerts: (params?: { limit?: number; severity?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set("limit", params.limit.toString());
    if (params?.severity) searchParams.set("severity", params.severity);
    const query = searchParams.toString() ? `?${searchParams}` : "";
    return fetchAPI<MetricsAlertResponse>(`${API_VERSION}/metrics/alerts${query}`);
  },
  // Get host relationships
  getHostRelationships: (host: string) => fetchAPI<{
    host: string;
    metrics: MetricsHostDetailResponse["metrics"];
    performance_alerts: { count: number; items: { id: string; type: string; severity: string }[] };
    investigations: { count: number; items: { id: string; status: string }[] };
    relationships: Record<string, string>;
  }>(`${API_VERSION}/metrics/${host}/relationships`),
  // Get host alerts
  getHostAlerts: (host: string) => fetchAPI<MetricsAlertResponse>(`${API_VERSION}/metrics/${host}/alerts`),
  // Get host investigations
  getHostInvestigations: (host: string) => fetchAPI<{ investigations: Investigation[]; total: number }>(`${API_VERSION}/metrics/${host}/investigations`),
  // Legacy
  getHostMetrics: (host: string, timeRange?: string) => {
    const params = timeRange ? `?time_range=${timeRange}` : "";
    return fetchAPI<MetricData[]>(`/api/metrics/hosts/${host}${params}`);
  },
  getOverview: () =>
    fetchAPI<{ total_hosts: number; avg_cpu: number; avg_memory: number; critical_hosts: string[] }>(
      "/api/metrics/overview"
    ),
};

// Monitoring
export const monitoringAPI = {
  getServicesStatus: () => fetchAPI<ServicesStatus>("/monitor/services-status"),
  getHealth: () => fetchAPI<MonitorHealth>("/monitor/health"),
  getPipelineHealth: () => fetchAPI<{ status: string }>("/monitor/pipeline-health"),
  getStuckInvestigations: () => fetchAPI<StuckInvestigationsResponse>("/monitor/stuck-investigations"),
  getServiceLogs: (service: string) => fetchAPI<ServiceLogsResponse>(`/monitor/services/${service}/logs`),
  getServiceErrors: (service: string) => fetchAPI<ServiceErrorsResponse>(`/monitor/services/${service}/errors`),
  // Legacy
  getService: (name: string) => fetchAPI<ServiceHealth>(`/api/monitoring/services/${name}`),
};

// Search
export const searchAPI = {
  search: (query: string, limit?: number, filters?: { severity?: string; source?: string; date_from?: string; date_to?: string; asset_id?: string }) => {
    const params = new URLSearchParams({ q: query });
    if (limit) params.set("limit", limit.toString());
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.source) params.set("source", filters.source);
    if (filters?.date_from) params.set("date_from", filters.date_from);
    if (filters?.date_to) params.set("date_to", filters.date_to);
    if (filters?.asset_id) params.set("asset_id", filters.asset_id);
    return fetchAPI<SearchResponse>(`${API_VERSION}/search?${params}`);
  },
  searchByIP: (ip: string, asset_id?: string) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<IPSearchResponse>(`${API_VERSION}/search/ips/${ip}${params}`);
  },
  searchByDomain: (domain: string, asset_id?: string) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<DomainSearchResponse>(`${API_VERSION}/search/domains/${domain}${params}`);
  },
};

// IPS Map & Attack Visualization
export const ipsAPI = {
  // Get map data with animated paths
  getMapData: (params?: { limit?: number; time_range?: number; severity?: string; country?: string; lifecycle?: string; category?: string; source?: string; protocol?: string; asset_id?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set("limit", params.limit.toString());
    if (params?.time_range) searchParams.set("time_range", params.time_range.toString());
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.country) searchParams.set("country", params.country);
    if (params?.lifecycle) searchParams.set("lifecycle", params.lifecycle);
    if (params?.category) searchParams.set("category", params.category);
    if (params?.source) searchParams.set("source", params.source);
    if (params?.protocol) searchParams.set("protocol", params.protocol);
    if (params?.asset_id) searchParams.set("asset_id", params.asset_id);
    const query = searchParams.toString() ? `?${searchParams}` : "";
    return fetchAPI<IPSMapDataResponse>(`${API_VERSION}/ips/map-data${query}`);
  },
  // Get live events table
  getLiveEvents: (params?: { time_range?: number; severity?: string; country?: string; lifecycle?: string; limit?: number; category?: string; source?: string; protocol?: string; asset_id?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.time_range) searchParams.set("time_range", params.time_range.toString());
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.country) searchParams.set("country", params.country);
    if (params?.lifecycle) searchParams.set("lifecycle", params.lifecycle);
    if (params?.limit) searchParams.set("limit", String(params.limit));
    if (params?.category) searchParams.set("category", params.category);
    if (params?.source) searchParams.set("source", params.source);
    if (params?.protocol) searchParams.set("protocol", params.protocol);
    if (params?.asset_id) searchParams.set("asset_id", params.asset_id);
    const query = searchParams.toString() ? `?${searchParams}` : "";
    return fetchAPI<IPSLiveEventsResponse>(`${API_VERSION}/ips/events/live${query}`);
  },
  // Get paginated events
  getEvents: (params?: { limit?: number; offset?: number; time_range?: number; severity?: string; country?: string; protocol?: string; category?: string; lifecycle?: string; source?: string; asset_id?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.set("limit", params.limit.toString());
    if (params?.offset) searchParams.set("offset", params.offset.toString());
    if (params?.time_range) searchParams.set("time_range", params.time_range.toString());
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.country) searchParams.set("country", params.country);
    if (params?.protocol) searchParams.set("protocol", params.protocol);
    if (params?.category) searchParams.set("category", params.category);
    if (params?.lifecycle) searchParams.set("lifecycle", params.lifecycle);
    if (params?.source) searchParams.set("source", params.source);
    if (params?.asset_id) searchParams.set("asset_id", params.asset_id);
    const query = searchParams.toString() ? `?${searchParams}` : "";
    return fetchAPI<IPSEventsResponse>(`${API_VERSION}/ips/events${query}`);
  },
  // Get statistics
  getStatistics: (params?: { time_range?: number; severity?: string; country?: string; lifecycle?: string; category?: string; source?: string; protocol?: string; asset_id?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.time_range) searchParams.set("time_range", params.time_range.toString());
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.country) searchParams.set("country", params.country);
    if (params?.lifecycle) searchParams.set("lifecycle", params.lifecycle);
    if (params?.category) searchParams.set("category", params.category);
    if (params?.source) searchParams.set("source", params.source);
    if (params?.protocol) searchParams.set("protocol", params.protocol);
    if (params?.asset_id) searchParams.set("asset_id", params.asset_id);
    const query = searchParams.toString() ? `?${searchParams}` : "";
    return fetchAPI<IPSStatisticsResponse>(`${API_VERSION}/ips/statistics${query}`);
  },
  // Get countries breakdown
  getCountries: (asset_id?: string) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<IPSCountriesResponse>(`${API_VERSION}/ips/countries${params}`);
  },
  // Get industry statistics
  getIndustryStats: (asset_id?: string) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<{ industries: { industry: string; count: number; percentage: number }[]; total: number }>(`${API_VERSION}/ips/statistics/industries${params}`);
  },
  // Get target statistics
  getTargetStats: (asset_id?: string) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<{ targets: { ip: string; count: number; percentage: number }[]; total: number }>(`${API_VERSION}/ips/statistics/targets${params}`);
  },
  // Get attack type statistics
  getAttackTypeStats: (asset_id?: string) => {
    const params = asset_id ? `?asset_id=${encodeURIComponent(asset_id)}` : "";
    return fetchAPI<{ attack_types: { type: string; count: number }[]; total: number }>(`${API_VERSION}/ips/statistics/attack-types${params}`);
  },
  // Get available filters
  getFilters: (params?: { time_range?: number; severity?: string; country?: string; lifecycle?: string; category?: string; source?: string; protocol?: string; asset_id?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.time_range) searchParams.set("time_range", params.time_range.toString());
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.country) searchParams.set("country", params.country);
    if (params?.lifecycle) searchParams.set("lifecycle", params.lifecycle);
    if (params?.category) searchParams.set("category", params.category);
    if (params?.source) searchParams.set("source", params.source);
    if (params?.protocol) searchParams.set("protocol", params.protocol);
    if (params?.asset_id) searchParams.set("asset_id", params.asset_id);
    const query = searchParams.toString() ? `?${searchParams}` : "";
    return fetchAPI<IPSFiltersResponse>(`${API_VERSION}/ips/filters${query}`);
  },
  // Get quick summary
  getSummary: (params?: { time_range?: number; severity?: string; country?: string; lifecycle?: string; category?: string; source?: string; protocol?: string; asset_id?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.time_range) searchParams.set("time_range", params.time_range.toString());
    if (params?.severity) searchParams.set("severity", params.severity);
    if (params?.country) searchParams.set("country", params.country);
    if (params?.lifecycle) searchParams.set("lifecycle", params.lifecycle);
    if (params?.category) searchParams.set("category", params.category);
    if (params?.source) searchParams.set("source", params.source);
    if (params?.protocol) searchParams.set("protocol", params.protocol);
    if (params?.asset_id) searchParams.set("asset_id", params.asset_id);
    const query = searchParams.toString() ? `?${searchParams}` : "";
    return fetchAPI<IPSSummaryResponse>(`${API_VERSION}/ips/summary${query}`);
  },
  // Get health
  getStatus: () => fetchAPI<{ status: string; events_stored: number; unique_sources: number; total_processed: number }>(`${API_VERSION}/ips/status`),
  // Get detailed health
  getStatusDetailed: () => fetchAPI<{
    status: string;
    events: { stored: number; max_events: number; retention_minutes: number };
    statistics: {
      total: number;
      unique_sources: number;
      unique_targets: number;
      by_severity: Record<string, number>;
      by_category: Record<string, number>;
    };
    timestamp: string;
  }>(`${API_VERSION}/ips/status/detailed`),
  // Submit single event
  submitEvent: (event: {
    source_ip: string;
    dest_ip: string;
    src_port?: number;
    dst_port?: number;
    severity: string;
    alert_name: string;
    category?: string;
    protocol?: string;
    signature_id?: string;
  }) => fetchAPI<{ status: string; event_id: string }>(`${API_VERSION}/ips/event`, {
    method: "POST",
    body: JSON.stringify(event),
  }),
  // Submit bulk events
  submitBulkEvents: (events: {
    source_ip: string;
    dest_ip: string;
    severity: string;
    alert_name: string;
  }[]) => fetchAPI<{ status: string; events_count: number }>(`${API_VERSION}/ips/events/bulk`, {
    method: "POST",
    body: JSON.stringify(events),
  }),
  // Clear events
  clearEvents: () => fetchAPI<{ status: string }>(`${API_VERSION}/ips/events`, { method: "DELETE" }),
  // Get single event
  getEvent: (eventId: string) => fetchAPI<IPSAttack>(`${API_VERSION}/ips/${eventId}`),
  // Get related alert/incident/investigation links for an event
  getEventLinks: (eventId: string) =>
    fetchAPI<{ event_id: string; alert_id?: string; incident_id?: string; investigation_id?: string }>(
      `${API_VERSION}/ips/event/${eventId}/links`
    ),
};

export const aiAPI = {
  getContext: (signal?: AbortSignal) =>
    fetchAPI<AssistantContext & { supported_actions: { type: string; label: string; description: string; requires_confirmation: boolean }[] }>(
      `${API_VERSION}/assistant/context`,
      { signal }
    ),
  getSources: (signal?: AbortSignal) =>
    fetchAPI<AssistantSourcesResponse>(`${API_VERSION}/assistant/sources`, { signal }),
  getHealth: (signal?: AbortSignal) =>
    fetchAPI<AssistantHealth>(`${API_VERSION}/assistant/health`, { signal }),
  query: (request: AssistantQueryRequest, signal?: AbortSignal) =>
    fetchAPI<AssistantQueryResponse>(`${API_VERSION}/assistant/query`, {
      method: "POST",
      body: JSON.stringify(request),
      signal,
    }),
  executeAction: (request: { action_type: string; params: Record<string, any>; decided_by?: string }, signal?: AbortSignal) =>
    fetchAPI<{ success: boolean; error?: string; status_code?: number; data?: any }>(`${API_VERSION}/assistant/actions`, {
      method: "POST",
      body: JSON.stringify(request),
      signal,
    }),
  listConversations: (limit?: number, signal?: AbortSignal) =>
    fetchAPI<{ conversations: AssistantConversation[] }>(
      `${API_VERSION}/assistant/conversations?limit=${limit || 50}`,
      { signal }
    ),
  createConversation: (request?: { title?: string; focus_entity_type?: string; focus_entity_id?: string }, signal?: AbortSignal) =>
    fetchAPI<AssistantConversation>(`${API_VERSION}/assistant/conversations`, {
      method: "POST",
      body: JSON.stringify(request || {}),
      signal,
    }),
  getConversation: (id: string, signal?: AbortSignal) =>
    fetchAPI<AssistantConversationDetail>(`${API_VERSION}/assistant/conversations/${id}`, {
      signal,
    }),
  deleteConversation: (id: string, signal?: AbortSignal) =>
    fetchAPI<{ status: string; conversation_id: string }>(`${API_VERSION}/assistant/conversations/${id}`, {
      method: "DELETE",
      signal,
    }),
};

// ── AI Operator ───────────────────────────────────────────────────────────────

export interface OperatorSession {
  id: string;
  title: string;
  target_hosts: string[] | null;
  asset_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface OperatorMessage {
  id: string;
  role: "user" | "assistant" | "system" | "reasoning";
  content: string;
  playbook_yaml?: string;
  execution_summary?: string;
  risk_level?: string;
  run_id?: string;
  status?: string;
  result?: {
    exit_code?: number;
    output?: string;
    stderr?: string;
    analysis?: {
      outcome: string;
      explanation: string;
      key_changes: string[];
      recommendations: string[];
    };
    executed_at?: string;
    // Plan metadata stored here before execution
    steps?: string[];
    destructive_actions?: string[];
    estimated_duration?: string;
    intent?: string;
    // Rollback metadata for state-changing actions
    rollback?: {
      action: string;
      command: string;
      target_ip: string;
      target_host: string;
      risk_level: string;
    };
    // Structured data extracted from command outputs
    parsed_data?: {
      disk_usage?: Array<{ filesystem: string; size: string; used: string; available: string; use_percent: string; mounted_on: string }>;
      memory_usage?: { mem?: Record<string, string>; swap?: Record<string, string> };
      top_processes?: Array<{ user: string; pid: string; cpu: string; mem: string; command: string }>;
      service_status?: { service: string; active_state: string; status_text: string; main_pid: string };
      iptables_rules?: string[];
      failed_tasks?: Array<{ name?: string; task?: string; host?: string; error?: string }>;
      unreachable_hosts?: Array<{ host?: string; error?: string } | string>;
      changed_tasks?: Array<{ name?: string; host?: string }>;
      ok_tasks?: Array<{ name?: string; host?: string }>;
      raw_outputs?: Array<{ cmd: string; output: string }>;
      firewall_changes?: string[];
    };
  } | null;
  created_at: string;
}

export interface OperatorSessionDetail extends OperatorSession {
  messages: OperatorMessage[];
}

export interface OperatorSendMessageRequest {
  prompt: string;
  require_approval?: boolean;
  asset_id?: string;
}

export interface OperatorSendMessageResponse {
  message_id: string;
  run_id: string;
  session_id: string;
  status: string;
  intent: string;
  risk_level: string;
  reasoning: string;
  steps: string[];
  execution_summary: string;
  destructive_actions: string[];
  estimated_duration: string;
  playbook_yaml: string;
}

export interface OperatorRunStatus {
  run_id: string;
  status: string;
  intent: string;
  risk_level: string;
  explanation: string;
  result: OperatorMessage["result"];
  created_at: string;
  updated_at: string;
}

export const operatorAPI = {
  // Inventory
  listInventoryHosts: () =>
    fetchAPI<{
      hosts: Array<{ alias: string; host: string; user: string }>;
      count: number;
      state: string;
      readable: boolean;
      message: string;
      has_inventory: boolean;
      valid_for_execution: boolean;
    }>(`${API_VERSION}/operator/inventory/hosts`),
  // Sessions
  createSession: (request?: { title?: string; target_hosts?: string[]; asset_id?: string }) =>
    fetchAPI<OperatorSession>(`${API_VERSION}/operator/sessions`, {
      method: "POST",
      body: JSON.stringify(request || {}),
    }),
  listSessions: (limit?: number) =>
    fetchAPI<{ sessions: OperatorSession[] }>(`${API_VERSION}/operator/sessions?limit=${limit || 50}`),
  getSession: (id: string) => fetchAPI<OperatorSessionDetail>(`${API_VERSION}/operator/sessions/${id}`),
  deleteSession: (id: string) =>
    fetchAPI<{ message: string }>(`${API_VERSION}/operator/sessions/${id}`, { method: "DELETE" }),
  // Messaging
  sendMessage: (sessionId: string, prompt: string, requireApproval?: boolean, assetId?: string) =>
    fetchAPI<OperatorSendMessageResponse>(`${API_VERSION}/operator/sessions/${sessionId}/message`, {
      method: "POST",
      body: JSON.stringify({ prompt, require_approval: requireApproval ?? true, asset_id: assetId || undefined }),
    }),
  // Execution
  approveRun: (runId: string, decidedBy?: string) =>
    fetchAPI<{ success: boolean; run_id: string; status: string }>(
      `${API_VERSION}/operator/runs/${runId}/approve`,
      { method: "POST", body: JSON.stringify({ decided_by: decidedBy || "analyst" }) }
    ),
  getRunStatus: (runId: string) =>
    fetchAPI<OperatorRunStatus>(`${API_VERSION}/operator/runs/${runId}/status`),
  // Legacy single-shot
  runLegacy: (request: { prompt: string; target_hosts?: string[]; require_approval?: boolean; asset_id?: string }) =>
    fetchAPI<OperatorSendMessageResponse>(`${API_VERSION}/operator/run`, {
      method: "POST",
      body: JSON.stringify(request),
    }),
};

export interface WhitelistEntry {
  id: string;
  type: "ip" | "subnet" | "domain";
  value: string;
  label: string;
  description?: string;
  created_at?: string;
}

export interface WhitelistListResponse {
  entries: WhitelistEntry[];
  total: number;
}

export const whitelistAPI = {
  list: (params?: { type?: string; label?: string }) => {
    const qs = new URLSearchParams();
    if (params?.type) qs.append("type", params.type);
    if (params?.label) qs.append("label", params.label);
    const query = qs.toString();
    return fetchAPI<WhitelistListResponse>(`${API_VERSION}/whitelist${query ? `?${query}` : ""}`);
  },
  create: (body: { type: string; value: string; label: string; description?: string }) =>
    fetchAPI<{ success: boolean; entry: WhitelistEntry }>(`${API_VERSION}/whitelist`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  delete: (id: string) =>
    fetchAPI<{ success: boolean; id: string }>(`${API_VERSION}/whitelist/${id}`, { method: "DELETE" }),
  check: (value: string) =>
    fetchAPI<{ value: string; whitelisted: boolean }>(`${API_VERSION}/whitelist/check?value=${encodeURIComponent(value)}`),
  batchCheck: (values: string[]) =>
    fetchAPI<{ results: Record<string, boolean> }>(`${API_VERSION}/whitelist/check-batch`, {
      method: "POST",
      body: JSON.stringify({ values }),
    }),
};


// ==================== SETTINGS TYPES ====================

export interface SettingsValue {
  key: string;
  value: any;
  type: string;
  secret: boolean;
}

export interface SettingsSection {
  section: string;
  values: SettingsValue[];
}

export interface SettingsResponse {
  sections: SettingsSection[];
}

export interface SettingsPreviewRequest {
  changes: Record<string, any>;
}

export interface SettingsPreviewItem {
  key: string;
  old: any;
  new: any;
  type: string;
}

export interface SettingsPreviewResponse {
  preview: SettingsPreviewItem[];
  masked: boolean;
}

export interface SettingsUpdateRequest {
  changes: Record<string, any>;
  reload?: boolean;
}

export interface SettingsUpdateResult {
  applied: string[];
  requires_restart: string[];
  errors: string[];
  warnings: string[];
}

export interface RuntimeReloadResult {
  applied: string[];
  failed: string[];
  requires_restart: string[];
  warnings: string[];
}

export interface TestConnectionResult {
  status: "success" | "warning" | "failed";
  latency_ms: number;
  last_checked: string;
  message: string;
  recommended_action?: string;
}


export interface SettingsOverviewCard {
  status: string;
  detail?: string;
}

export interface SettingsOverview {
  security: SettingsOverviewCard;
  data_sources: SettingsOverviewCard;
  redis: SettingsOverviewCard;
  ai: SettingsOverviewCard;
  ansible: SettingsOverviewCard;
  workflow: SettingsOverviewCard;
  monitoring: SettingsOverviewCard;
  pipeline: SettingsOverviewCard;
  assets?: SettingsOverviewCard;
}

// ==================== SETTINGS API ====================

export const settingsAPI = {
  get: () => fetchAPI<SettingsResponse>(`${API_VERSION}/settings`),
  preview: (body: SettingsPreviewRequest) =>
    fetchAPI<SettingsPreviewResponse>(`${API_VERSION}/settings/preview`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  update: (body: SettingsUpdateRequest, adminSecret?: string) =>
    fetchAPI<SettingsUpdateResult>(`${API_VERSION}/settings`, {
      method: "PATCH",
      body: JSON.stringify(body),
      adminSecret,
      adminRequired: true,
    }),
  reload: (adminSecret?: string) =>
    fetchAPI<RuntimeReloadResult>(`${API_VERSION}/settings/reload`, {
      method: "POST",
      adminSecret,
      adminRequired: true,
    }),
  setEnvVar: (key: string, value: string, adminSecret?: string) =>
    fetchAPI<{ saved: boolean; key: string; restart_required: boolean; message: string }>(
      `${API_VERSION}/settings/env-var`,
      {
        method: "POST",
        body: JSON.stringify({ key, value }),
        adminSecret,
        adminRequired: true,
      }
    ),
  testElasticsearch: (body?: Record<string, any>) =>
    fetchAPI<TestConnectionResult>(`${API_VERSION}/settings/test/elasticsearch`, {
      method: "POST",
      body: JSON.stringify(body || {}),
    }),
  testRedis: (body?: Record<string, any>) =>
    fetchAPI<TestConnectionResult>(`${API_VERSION}/settings/test/redis`, {
      method: "POST",
      body: JSON.stringify(body || {}),
    }),
  testAI: (body?: Record<string, any>) =>
    fetchAPI<TestConnectionResult>(`${API_VERSION}/settings/test/ai`, {
      method: "POST",
      body: JSON.stringify(body || {}),
    }),
  testAnsiblePreflight: (body?: Record<string, any>) =>
    fetchAPI<TestConnectionResult>(`${API_VERSION}/settings/test/ansible-preflight`, {
      method: "POST",
      body: JSON.stringify(body || {}),
    }),
  getOverview: () => fetchAPI<SettingsOverview>(`${API_VERSION}/settings/overview`),
};



// ==================== ASSET TYPES ====================

export interface SourceConfig {
  index_pattern?: string;
  host_name?: string;
  agent_name?: string;
  agent_id?: string;
}

export interface AnsibleConfig {
  ansible_host?: string;
  ansible_user?: string;
  ansible_port?: number;
  auth_type?: "password" | "private_key" | "local";
  ssh_key_ref?: string;
  password_secret_ref?: string;
  become_method?: string;
  become_password_secret_ref?: string;
  remediation_enabled?: boolean;
}

export interface MonitoredAsset {
  id: string;
  asset_id: string;
  name: string;
  hostname?: string;
  ip_address?: string;
  environment?: string;
  description?: string;
  enabled: boolean;
  source_config_json: Record<string, SourceConfig>;
  ansible_config_json: AnsibleConfig;
  remediation_enabled: boolean;
  validation_status: string;
  last_validated_at?: string;
  last_seen_at?: string;
  created_at: string;
  updated_at: string;
}

export interface AssetListResponse {
  assets: MonitoredAsset[];
  total: number;
}

export interface SourceCheckRequest {
  source: string;
  index_pattern?: string;
  host_name?: string;
  agent_name?: string;
  agent_id?: string;
}

export interface SourceCheckResponse {
  source: string;
  status: "ok" | "missing" | "warning" | "error";
  count: number;
  last_seen?: string;
  sample_fields?: Record<string, any>;
  message: string;
}

// ==================== ASSETS API ====================

export const assetsAPI = {
  list: (includeDisabled?: boolean, asset_id?: string) => {
    const params = new URLSearchParams();
    if (includeDisabled) params.set("include_disabled", "true");
    if (asset_id) params.set("asset_id", asset_id);
    const query = params.toString();
    return fetchAPI<AssetListResponse>(`${API_VERSION}/assets${query ? `?${query}` : ""}`);
  },
  get: (assetId: string) => fetchAPI<MonitoredAsset>(`${API_VERSION}/assets/${assetId}`),
  create: (body: Partial<MonitoredAsset>, adminSecret?: string) =>
    fetchAPI<MonitoredAsset>(`${API_VERSION}/assets`, {
      method: "POST",
      body: JSON.stringify(body),
      adminSecret,
      adminRequired: true,
    }),
  update: (assetId: string, body: Partial<MonitoredAsset>, adminSecret?: string) =>
    fetchAPI<MonitoredAsset>(`${API_VERSION}/assets/${assetId}`, {
      method: "PATCH",
      body: JSON.stringify(body),
      adminSecret,
      adminRequired: true,
    }),
  delete: (assetId: string, adminSecret?: string) =>
    fetchAPI<void>(`${API_VERSION}/assets/${assetId}`, {
      method: "DELETE",
      adminSecret,
      adminRequired: true,
    }),
  checkSource: (body: SourceCheckRequest, adminSecret?: string) =>
    fetchAPI<SourceCheckResponse>(`${API_VERSION}/assets/check-source`, {
      method: "POST",
      body: JSON.stringify(body),
      adminSecret,
      adminRequired: true,
    }),
  validate: (assetId: string, adminSecret?: string) =>
    fetchAPI<{ asset_id: string; validation_status: string; checks: SourceCheckResponse[] }>(
      `${API_VERSION}/assets/${assetId}/validate`,
      { method: "POST", adminSecret, adminRequired: true }
    ),
  getAnsible: (assetId: string) =>
    fetchAPI<{
      asset_id: string;
      ansible: AnsibleConfig;
      readiness: {
        ansible_host_configured: boolean;
        ansible_user_configured: boolean;
        auth_type: string;
        ssh_key_configured: boolean;
        password_configured: boolean;
        become_password_configured: boolean;
        remediation_enabled: boolean;
        asset_enabled: boolean;
        uses_global_fallback?: boolean;
      };
    }>(
      `${API_VERSION}/assets/${assetId}/ansible`
    ),
  updateAnsible: (assetId: string, body: AnsibleConfig, adminSecret?: string) =>
    fetchAPI<{ asset_id: string; ansible: AnsibleConfig }>(`${API_VERSION}/assets/${assetId}/ansible`, {
      method: "PATCH",
      body: JSON.stringify(body),
      adminSecret,
      adminRequired: true,
    }),
  testConnection: (assetId: string, adminSecret?: string, body?: AnsibleConfig) =>
    fetchAPI<{ status: string; message: string; output?: string; error?: string; uses_global_fallback?: boolean }>(
      `${API_VERSION}/assets/${assetId}/ansible/test-connection`,
      { method: "POST", adminSecret, adminRequired: true, body: body ? JSON.stringify(body) : undefined }
    ),
};

// ==================== AUTH API ====================

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user: {
    id: string;
    username: string;
    email?: string | null;
    role: "super_admin" | "server_user";
    asset_id?: string | null;
    scope_all_assets: boolean;
    is_active: boolean;
    is_banned: boolean;
    created_at?: string | null;
    last_login_at?: string | null;
  };
}

export interface MeResponse {
  user: LoginResponse["user"];
}

export const authAPI = {
  login: (username: string, password: string) =>
    fetchAPI<LoginResponse>(`${API_VERSION}/auth/login`, {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => fetchAPI<MeResponse>(`${API_VERSION}/auth/me`),
};

// ==================== ACCOUNTS API ====================

export interface Account {
  id: string;
  username: string;
  email?: string | null;
  role: string;
  asset_id?: string | null;
  asset_name?: string | null;
  is_active: boolean;
  is_banned: boolean;
  created_at?: string | null;
  updated_at?: string | null;
  last_login_at?: string | null;
}

export interface AccountListResponse {
  accounts: Account[];
  total: number;
}

export const accountsAPI = {
  list: (params?: { search?: string; role?: string; asset_id?: string; limit?: number; offset?: number }) =>
    fetchAPI<AccountListResponse>(
      `${API_VERSION}/accounts?${new URLSearchParams(params as Record<string, string> || {}).toString()}`
    ),
  create: (body: { username: string; password: string; email?: string | null; role: string; asset_id?: string | null; is_active?: boolean }) =>
    fetchAPI<Account>(`${API_VERSION}/accounts`, { method: "POST", body: JSON.stringify(body) }),
  update: (id: string, body: Partial<{ username: string; email?: string | null; role: string; asset_id?: string | null; is_active?: boolean; is_banned?: boolean }>) =>
    fetchAPI<Account>(`${API_VERSION}/accounts/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  resetPassword: (id: string, new_password: string) =>
    fetchAPI<{ message: string }>(`${API_VERSION}/accounts/${id}/reset-password`, { method: "POST", body: JSON.stringify({ new_password }) }),
  ban: (id: string) =>
    fetchAPI<{ message: string }>(`${API_VERSION}/accounts/${id}/ban`, { method: "POST" }),
  unban: (id: string) =>
    fetchAPI<{ message: string }>(`${API_VERSION}/accounts/${id}/unban`, { method: "POST" }),
  delete: (id: string) =>
    fetchAPI<void>(`${API_VERSION}/accounts/${id}`, { method: "DELETE" }),
  ensureDefaultAccount: (assetId: string) =>
    fetchAPI<{ created: boolean; username: string; password?: string; message: string }>(
      `${API_VERSION}/accounts/assets/${assetId}/ensure-default-account`,
      { method: "POST" }
    ),
};
