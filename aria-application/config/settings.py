from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, AliasChoices
from typing import Optional, List
from functools import lru_cache

# Load .env into os.environ so per-asset credential lookups (os.environ.get)
# work consistently alongside pydantic-settings field parsing.
from dotenv import load_dotenv
load_dotenv(dotenv_path=".env", override=False)


def _parse_comma_list(value: str) -> List[str]:
    """Parse comma-separated string to list."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    elasticsearch_url: str = "https://localhost:9200"
    elasticsearch_user: str = "elastic"
    elasticsearch_password: str
    elasticsearch_use_ssl: bool = True

    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cache_size: int = 2000

    wazuh_index_pattern: str = "wazuh-alerts-4.x-*"
    falco_index_pattern: str = "falco-*"
    telegraf_index_pattern: str = "telegraf-*"
    filebeat_index_pattern: str = "filebeat-*"
    suricata_index_pattern: str = "suricata-*"

    llm_provider: str = "auto"
    llm_model: str = "auto"
    openai_api_key: Optional[str] = None
    openai_org_id: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    google_api_key: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    nvidia_api_key: Optional[str] = None
    ollama_host: str = "http://localhost:11434"
    ollama_timeout: int = 60
    llm_enabled: bool = True
    llm_fallback_to_pyrca: bool = True

    # ════════════════════════════════════════════════════════════════════════
    # UPSTREAM OPENSOAR SETTINGS (deprecated, kept for backward compatibility)
    # ════════════════════════════════════════════════════════════════════════
    opensoar_enabled: bool = False
    opensoar_url: str = "http://localhost:8080"
    opensoar_username: str = "admin"
    opensoar_password: str = ""
    opensoar_webhook_secret: Optional[str] = None
    opensoar_poll_interval: int = 10
    opensoar_batch_size: int = 50
    opensoar_lookback_minutes: int = 60  # dead code, kept for compat
    opensoar_first_run_lookback_hours: int = 24
    opensoar_min_severity: str = "low"

    # ════════════════════════════════════════════════════════════════════════
    # PER-SOURCE POLL INTERVALS (seconds, >=5)
    # ════════════════════════════════════════════════════════════════════════
    wazuh_poll_interval_seconds: int = 10
    falco_poll_interval_seconds: int = 10
    filebeat_poll_interval_seconds: int = 10
    suricata_poll_interval_seconds: int = 10

    # ════════════════════════════════════════════════════════════════════════
    # LOCAL-ONLY MODE SETTINGS
    # ════════════════════════════════════════════════════════════════════════
    local_ingestion_enabled: bool = True
    notification_base_url: str = "http://localhost:8001"
    notification_default_email: str = ""
    incident_auto_create_enabled: bool = True
    incident_correlation_window_minutes: int = 30
    local_only_mode: bool = False
    max_concurrent_investigations: int = 10

    # Real-time settings
    incident_watcher_interval: int = 15
    incident_correlation_interval: int = 30  # 30 seconds instead of 60

    backend_port: int = 8001

    sigma_rules_path: str = "config/sigma_rules"

    # Ansible Configuration
    ansible_enabled: bool = False
    ansible_inventory_path: Optional[str] = "/etc/ansible/inventory"
    ansible_playbooks_path: str = "app/ai_pipeline/remediation/playbooks"

    # SSH Connection (all configurable via .env)
    ansible_remote_host: Optional[str] = None  # Target host IP or hostname
    ansible_remote_user: str = "root"  # SSH username
    ansible_ssh_port: int = 22  # SSH port
    ansible_ssh_key: Optional[str] = None  # Path to SSH private key
    ansible_ssh_password: Optional[str] = None  # SSH password
    ansible_timeout: int = 300  # Connection timeout in seconds

    # AI Operator timeouts (seconds)
    operator_reasoning_timeout: int = 15  # LLM intent-analysis timeout
    operator_playbook_timeout: int = 30  # LLM playbook-generation timeout
    operator_summary_timeout: int = 20  # LLM summary-generation timeout
    operator_execution_timeout: int = 60  # Ansible run timeout per operator execution
    operator_plan_cache_ttl_seconds: int = 600  # Deterministic plan cache TTL

    # ════════════════════════════════════════════════════════════════════════
    # OPERATOR PROTECTED IP ALLOWLIST
    # ════════════════════════════════════════════════════════════════════════
    # IPs/CIDRs that the AI Operator must NEVER block via block_ip.
    # These defaults cover RFC1918, loopback, link-local, and ULA ranges.
    operator_protected_ips: str = ""  # comma-separated extra IPs
    operator_protected_cidrs: str = (
        "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,"
        "::1/128,fc00::/7,fe80::/10"
    )
    operator_protected_hostnames: str = ""  # comma-separated hostnames
    operator_allow_private_ip_block: bool = False  # SAFE OVERRIDE: never enable in production

    @property
    def operator_protected_ips_list(self) -> List[str]:
        return _parse_comma_list(self.operator_protected_ips)

    @property
    def operator_protected_cidrs_list(self) -> List[str]:
        return _parse_comma_list(self.operator_protected_cidrs)

    @property
    def operator_protected_hostnames_list(self) -> List[str]:
        return _parse_comma_list(self.operator_protected_hostnames)

    # Privilege Escalation
    ansible_become_method: str = "sudo"  # sudo, su, pbrun, etc.
    ansible_become_password: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("ARIA_ANSIBLE_BECOME_PASSWORD", "ansible_become_password"),
        description="Become password for Ansible privilege escalation. Never logged or stored in DB."
    )

    # Response Intelligence Layer
    backend_api_key: str = ""
    backend_url: str = "http://localhost:8001"  # Public URL for Slack links

    # ════════════════════════════════════════════════════════════════════════
    # CORS / SECURITY
    # ════════════════════════════════════════════════════════════════════════
    cors_origins: str = "http://localhost:3000"  # comma-separated allowed origins

    # ════════════════════════════════════════════════════════════════════════
    # RATE LIMITING
    # ════════════════════════════════════════════════════════════════════════
    rate_limit_enabled: bool = True
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 60
    rate_limit_sensitive_max_requests: int = 10

    incident_min_alerts: int = 1  # min linked alerts to trigger investigation
    fix_verify_wait_minutes: int = 5  # wait after playbook before re-checking
    fix_verify_window_minutes: int = 10  # how long to watch for new alerts

    # Stuck investigation alerts
    stuck_investigation_hours: int = 2  # Alert when awaiting_approval > this many hours
    stuck_running_minutes: int = 30  # Alert when running > this many minutes
    stuck_pending_hours: int = 1  # Alert when pending > this many hours
    running_investigation_timeout_minutes: int = (
        30  # Auto-recover running after this many minutes
    )

    # Neo4j (Phase 2 - disabled by default)
    neo4j_enabled: bool = False
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    # Notification settings
    slack_webhook_url: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_from: Optional[str] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    notification_email: Optional[str] = None
    notification_email_to: Optional[str] = None

    # ════════════════════════════════════════════════════════════════════════
    # MULTI-SERVER FEATURE FLAG
    # ════════════════════════════════════════════════════════════════════════
    multi_server_enabled: bool = False

    # ════════════════════════════════════════════════════════════════════════
    # RBAC / ADMIN AUTHORIZATION
    # ════════════════════════════════════════════════════════════════════════
    aria_admin_users: str = ""  # Comma-separated usernames with admin role
    aria_admin_secret: str = ""  # Shared secret for admin endpoint authorization

    @property
    def aria_admin_users_list(self) -> List[str]:
        """Get admin users as list."""
        return _parse_comma_list(self.aria_admin_users)

    # ════════════════════════════════════════════════════════════════════════
    # AUTO-APPROVE SYSTEM
    # ════════════════════════════════════════════════════════════════════════

    # Enable/disable auto-approve
    auto_approve_enabled: bool = False

    # When true, bypass ALL guardrails/criteria and auto-approve EVERY investigation immediately
    auto_approve_all_enabled: bool = False

    # Method: static | dynamic | ai | hybrid (recommended)
    auto_approve_method: str = "hybrid"

    # ─── Static Rules ───
    # Severities that can be auto-approved (before risk check)
    auto_approve_severities: list = ["low"]
    # Max risk_score for auto-approve (0-100 scale)
    auto_approve_max_risk_score: int = 25
    # Max alert count for auto-approve
    auto_approve_max_alerts: int = 10

    # ─── Static Guardrails (NEVER auto-approve) ───
    # Severities that require human approval
    auto_approve_block_severities: list = ["critical"]
    # Risk score threshold that blocks auto-approve
    auto_approve_block_risk_score: int = 75
    # Attack types that require human approval
    auto_approve_block_attack_types: list = [
        "ransomware",
        "c2",
        "data_exfiltration",
        "privilege_escalation",
        "lateral_movement",
    ]

    # ─── Dynamic Learning ───
    # Enable dynamic learning from approval patterns
    auto_approve_dynamic_enabled: bool = True
    # Minimum approvals needed before adapting thresholds
    auto_approve_min_approvals_for_learning: int = 10
    # How often to recalculate thresholds (hours)
    auto_approve_recalculation_interval_hours: int = 24

    # ─── AI Confidence (Optional) ───
    # Use AI to evaluate playbook quality
    auto_approve_ai_enabled: bool = False
    # Confidence threshold for auto-approve (0.0-1.0)
    auto_approve_ai_threshold: float = 0.85
    # Confidence threshold for high-priority queue (0.5-0.85)
    auto_approve_ai_high_priority_threshold: float = 0.50

    # ─── Notifications ───
    # Send notification when auto-approved
    auto_approve_notify_on_auto: bool = True
    # Send notification when auto-approve fails (triggers human)
    auto_approve_notify_on_fallback: bool = True

    # ════════════════════════════════════════════════════════════════════════
    # ADMIN OVERRIDE SETTINGS
    # ════════════════════════════════════════════════════════════════════════
    aria_allow_admin_soft_override: bool = False

    # ════════════════════════════════════════════════════════════════════════
    # STAGED REMEDIATION SETTINGS (Phase 3)
    # ════════════════════════════════════════════════════════════════════════
    staged_remediation_enabled: bool = True
    staged_remediation_evidence_first: bool = True
    staged_remediation_dry_run_first: bool = True
    staged_remediation_auto_rollback_on_failure: bool = False
    staged_remediation_phase_delay_seconds: int = 5

    # ════════════════════════════════════════════════════════════════════════
    # PATH SETTINGS
    # ════════════════════════════════════════════════════════════════════════
    playbook_dir: str = "data/playbooks"
    cursor_dir: str = "data/cursors"
    seen_ids_dir: str = "data/seen_ids"
    pattern_tracking_file: str = "data/artifacts/pattern_tracking.json"
    backup_dir: str = "data/backups"
    db_path: str = "data/investigations.db"

    # ════════════════════════════════════════════════════════════════════════
    # BACKUP SETTINGS
    # ════════════════════════════════════════════════════════════════════════
    backup_enabled: bool = True
    backup_interval_hours: int = 24
    backup_retention_days: int = 30
    backup_location: str = "data/backups"

    # ════════════════════════════════════════════════════════════════════════
    # PERFORMANCE MONITORING (Server Metrics)
    # ════════════════════════════════════════════════════════════════════════

    # Enable/Disable performance monitoring
    performance_enabled: bool = True

    # Enable/Disable dynamic playbook generation
    performance_playbook_enabled: bool = True

    # Polling settings
    performance_poll_interval: int = 15  # seconds
    performance_batch_size: int = 100

    # Hosts to monitor (comma-separated in .env, empty = all from telegraf)
    performance_hosts: Optional[str] = ""

    @property
    def performance_hosts_list(self) -> List[str]:
        """Get performance hosts as list."""
        return _parse_comma_list(self.performance_hosts)

    # ─── Thresholds ───
    # CPU thresholds (percentage)
    performance_cpu_warning: int = 70
    performance_cpu_critical: int = 90

    # Memory thresholds (percentage)
    performance_memory_warning: int = 75
    performance_memory_critical: int = 85

    # Disk thresholds (percentage)
    performance_disk_warning: int = 80
    performance_disk_critical: int = 90

    # Disk inodes thresholds (percentage)
    performance_disk_inodes_warning: int = 80
    performance_disk_inodes_critical: int = 90

    # Network thresholds (bytes per second)
    performance_network_in_warning: int = 100000000  # 100MB/s
    performance_network_in_critical: int = 500000000  # 500MB/s

    # ─── Anomaly Detection ───
    performance_anomaly_detection: bool = True
    performance_anomaly_window_hours: int = 24  # baseline window
    performance_anomaly_use_ai: bool = True
    performance_anomaly_use_statistical: bool = True
    performance_anomaly_stddev_threshold: float = 3.0

    # ─── Alert Settings ───
    performance_alert_cooldown_minutes: int = 30
    performance_incident_min_severity: str = "warning"

    # ─── Auto-Remediation ───
    performance_auto_remediate_enabled: bool = (
        False  # Disabled - requires manual approval
    )
    performance_auto_remediate_types: Optional[str] = (
        "cpu_high_nginx,cpu_high_java,cpu_high_apache,memory_high_java,memory_high_redis,disk_full_root,disk_full_var_log,disk_full_docker"
    )

    @property
    def performance_auto_remediate_types_list(self) -> List[str]:
        """Get auto-remediate types as list."""
        return _parse_comma_list(self.performance_auto_remediate_types)

    # ─── Notification ───
    performance_notify_slack: bool = True
    performance_slack_channel: str = "#server-performance"

    # ─── IPS Visualization ───
    ips_default_dest_ip: Optional[str] = None
    ips_home_base_lat: float = 36.8065
    ips_home_base_lon: float = 10.1815
    ips_home_base_label: str = "Protected Network"

    # ════════════════════════════════════════════════════════════════════════
    # SAFETY POLICY (JSON-encoded configurable rules)
    # ════════════════════════════════════════════════════════════════════════
    safety_policy_json: Optional[str] = None

    # ════════════════════════════════════════════════════════════════════════
    # BACKWARD-COMPATIBLE PROPERTY ALIASES
    # ════════════════════════════════════════════════════════════════════════
    @property
    def cors_origins_list(self) -> List[str]:
        """Get CORS origins as list."""
        return _parse_comma_list(self.cors_origins)

    @property
    def upstream_enabled(self) -> bool:
        """Alias for opensoar_enabled."""
        return self.opensoar_enabled

    @property
    def alert_poll_interval(self) -> int:
        """Alias for opensoar_poll_interval."""
        return self.opensoar_poll_interval

    @property
    def es_batch_size(self) -> int:
        """Alias for opensoar_batch_size."""
        return self.opensoar_batch_size

    @property
    def alert_first_run_lookback_hours(self) -> int:
        """Alias for opensoar_first_run_lookback_hours."""
        return self.opensoar_first_run_lookback_hours

    @property
    def alert_min_severity(self) -> str:
        """Alias for opensoar_min_severity."""
        return self.opensoar_min_severity


@lru_cache()
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    """Clear cached settings and reload from .env."""
    get_settings.cache_clear()
    return get_settings()
