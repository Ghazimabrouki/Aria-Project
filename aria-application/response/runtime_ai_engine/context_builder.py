"""
Runtime Security Context Builder.

Extracts structured runtime context from Falco alert documents.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger()


# ── Runtime Categories ───────────────────────────────────────────────────────

RUNTIME_CATEGORIES = {
    "process_execution": {
        "rules": [r".*exec.*", r"Run shell.*", r"Terminal shell.*", r".*bash.*", r".*sh\s"],
        "evt_types": ["execve", "execveat"],
        "tags": ["process", "shell"],
    },
    "file_access": {
        "rules": [r"Read sensitive.*", r".*sensitive file.*", r"Write below.*", r".*write.*below.*"],
        "evt_types": ["openat", "open", "openat2", "creat", "write", "writev"],
        "tags": ["filesystem", "file"],
    },
    "privilege_escalation": {
        "rules": [r".*sudo.*", r".*su\s.*", r".*pkexec.*", r".*setuid.*", r".*setgid.*", r".*chmod.*"],
        "evt_types": ["execve", "setuid", "setgid", "setresuid"],
        "tags": ["privilege", "privilege_escalation"],
    },
    "persistence": {
        "rules": [r"Systemd.*", r".*cron.*", r".*rc\.local.*", r".*bashrc.*", r".*profile.*", r".*ssh.*config.*"],
        "evt_types": ["openat", "open", "execve", "write"],
        "tags": ["persistence"],
    },
    "service_change": {
        "rules": [r".*service.*", r".*systemctl.*", r".*systemd.*", r"Critical Linux Service.*"],
        "evt_types": ["execve"],
        "tags": ["service", "systemd"],
    },
    "package_manager": {
        "rules": [r"Package Manager.*", r".*apt.*", r".*yum.*", r".*dnf.*", r".*snap.*", r".*dpkg.*"],
        "evt_types": ["execve"],
        "tags": ["package"],
    },
    "credential_access": {
        "rules": [r".*shadow.*", r".*passwd.*", r".*credential.*", r".*secret.*", r".*token.*", r".*key.*"],
        "evt_types": ["openat", "open", "read", "readv"],
        "tags": ["credentials", "mitre_credential_access"],
    },
    "container_runtime": {
        "rules": [r".*container.*", r".*docker.*", r".*kubernetes.*", r".*k8s.*"],
        "evt_types": ["execve", "openat", "connect"],
        "tags": ["container"],
    },
    "network_behavior": {
        "rules": [r".*connection.*", r".*egress.*", r".*ingress.*", r".*outbound.*"],
        "evt_types": ["connect", "accept", "socket", "bind"],
        "tags": ["network"],
    },
    "crypto_mining": {
        "rules": [r".*miner.*", r".*xmrig.*", r".*stratum.*", r".*cryptonight.*"],
        "evt_types": ["execve", "connect"],
        "tags": ["crypto", "mining"],
    },
}


# ── Severity Mapping ─────────────────────────────────────────────────────────

FALCO_PRIORITY_TO_SEVERITY = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "high",
    "error": "high",
    "warning": "medium",
    "notice": "low",
    "informational": "info",
    "info": "info",
    "debug": "info",
}


def _classify_runtime_category(rule_name: str, evt_type: str, tags: List[str]) -> str:
    """Classify a Falco event into a runtime category."""
    rule_lower = rule_name.lower()
    tags_lower = [t.lower() for t in tags]
    evt_lower = (evt_type or "").lower()

    scores: Dict[str, int] = {}

    for category, config in RUNTIME_CATEGORIES.items():
        score = 0
        # Rule name match
        for pattern in config["rules"]:
            if __import__("re").search(pattern.lower(), rule_lower):
                score += 3
        # Event type match
        if evt_lower in [e.lower() for e in config["evt_types"]]:
            score += 2
        # Tag match
        for tag in config["tags"]:
            if tag.lower() in tags_lower:
                score += 2
        if score > 0:
            scores[category] = score

    if scores:
        return max(scores, key=scores.get)
    return "unknown"


def _map_severity(priority: str, tags: List[str], category: str) -> str:
    """Map Falco priority to runtime severity with rule-aware boosting."""
    base = FALCO_PRIORITY_TO_SEVERITY.get(priority.lower(), "medium")

    tags_lower = [t.lower() for t in tags]
    boost = 0

    # Boost for MITRE tags
    if any(t.startswith("mitre_") or t.startswith("t") for t in tags_lower):
        boost += 1
    if any(t in ["persistence", "privilege", "privilege_escalation", "credential_access"] for t in tags_lower):
        boost += 1
    if category in ["persistence", "privilege_escalation", "credential_access"]:
        boost += 1

    severity_levels = ["info", "low", "medium", "high", "critical"]
    idx = severity_levels.index(base)
    idx = min(idx + boost, len(severity_levels) - 1)
    return severity_levels[idx]


def _extract_mitre_techniques(tags: List[str]) -> List[str]:
    """Extract MITRE technique IDs from Falco tags."""
    techniques = []
    for tag in tags:
        if isinstance(tag, str):
            # Match T#### format
            import re
            matches = re.findall(r"T\d{4}(?:\.\d{3})?", tag, re.IGNORECASE)
            techniques.extend(matches)
    return techniques


def _is_intervention_required(category: str, priority: str, user_name: str, proc_tty: Optional[int]) -> bool:
    """Determine if this runtime event requires active intervention."""
    priority_lower = priority.lower()
    cat_lower = category.lower()

    # Always intervene for persistence and privilege escalation
    if cat_lower in ["persistence", "privilege_escalation", "crypto_mining"]:
        return True

    # Credential access at Warning+ always needs investigation
    if cat_lower == "credential_access" and priority_lower in ["warning", "error", "critical", "alert", "emergency"]:
        return True

    # Service changes by non-root
    if cat_lower == "service_change" and user_name != "root":
        return True

    # File access by non-root without TTY (likely automated)
    if cat_lower == "file_access" and user_name != "root" and not proc_tty:
        return True

    # High+ priority always needs attention
    if priority_lower in ["critical", "alert", "emergency"]:
        return True

    return False


def _is_expected_admin_activity(category: str, priority: str, user_name: str, proc_tty: Optional[int]) -> bool:
    """Check if this is expected administrative activity.

    Conservative check for obvious expected-admin patterns at ingestion time.
    More nuanced analysis happens in the diagnostic interpreter which has
    access to diagnostic output (dpkg logs, apt history, etc.).
    """
    if priority.lower() not in ["notice", "informational", "info"]:
        return False

    # Package manager by root is generally expected admin activity
    # (TTY check removed — cron, Ansible, scripts often run without TTY)
    if category == "package_manager" and user_name == "root":
        return True

    # Service changes by root are expected admin activity
    if category == "service_change" and user_name == "root":
        return True

    return False


# ── RuntimeContext Dataclass ─────────────────────────────────────────────────

@dataclass
class RuntimeContext:
    resource_type: str = "runtime"
    runtime_category: str = "unknown"
    rule_name: str = ""
    priority: str = ""
    severity: str = "medium"

    # Host context
    hostname: str = ""
    environment: str = ""
    asset_role: str = ""

    # Process context
    proc_name: str = ""
    proc_cmdline: str = ""
    proc_exepath: str = ""
    proc_pid: int = 0
    proc_pname: str = ""
    proc_ppid: int = 0
    proc_tty: Optional[int] = None
    proc_ancestors: List[str] = field(default_factory=list)

    # User context
    user_name: str = ""
    user_uid: int = 0
    user_loginuid: int = 0

    # File context
    fd_name: Optional[str] = None
    fd_type: Optional[str] = None

    # Network context
    fd_sip: Optional[str] = None
    fd_sport: Optional[int] = None
    fd_dip: Optional[str] = None
    fd_dport: Optional[int] = None
    fd_rip: Optional[str] = None
    fd_rport: Optional[int] = None
    fd_lip: Optional[str] = None
    fd_lport: Optional[int] = None

    # Container context
    container_id: str = ""
    container_name: str = ""
    container_image_repository: Optional[str] = None
    container_image_tag: Optional[str] = None

    # K8s context
    k8s_ns_name: Optional[str] = None
    k8s_pod_name: Optional[str] = None

    # Event context
    evt_type: str = ""
    evt_category: str = ""
    evt_time: str = ""
    timestamp: str = ""

    # Falco output
    output_message: str = ""
    falco_tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    falco_uuid: str = ""
    source_id: str = ""

    # Classification
    is_intervention_required: bool = False
    is_expected_admin_activity: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for JSON storage."""
        return {
            "resource_type": self.resource_type,
            "runtime_category": self.runtime_category,
            "rule_name": self.rule_name,
            "priority": self.priority,
            "severity": self.severity,
            "hostname": self.hostname,
            "environment": self.environment,
            "asset_role": self.asset_role,
            "proc_name": self.proc_name,
            "proc_cmdline": self.proc_cmdline,
            "proc_exepath": self.proc_exepath,
            "proc_pid": self.proc_pid,
            "proc_pname": self.proc_pname,
            "proc_ppid": self.proc_ppid,
            "proc_tty": self.proc_tty,
            "proc_ancestors": self.proc_ancestors,
            "user_name": self.user_name,
            "user_uid": self.user_uid,
            "user_loginuid": self.user_loginuid,
            "fd_name": self.fd_name,
            "fd_type": self.fd_type,
            "fd_sip": self.fd_sip,
            "fd_sport": self.fd_sport,
            "fd_dip": self.fd_dip,
            "fd_dport": self.fd_dport,
            "fd_rip": self.fd_rip,
            "fd_rport": self.fd_rport,
            "fd_lip": self.fd_lip,
            "fd_lport": self.fd_lport,
            "container_id": self.container_id,
            "container_name": self.container_name,
            "container_image_repository": self.container_image_repository,
            "container_image_tag": self.container_image_tag,
            "k8s_ns_name": self.k8s_ns_name,
            "k8s_pod_name": self.k8s_pod_name,
            "evt_type": self.evt_type,
            "evt_category": self.evt_category,
            "evt_time": self.evt_time,
            "timestamp": self.timestamp,
            "output_message": self.output_message,
            "falco_tags": self.falco_tags,
            "mitre_techniques": self.mitre_techniques,
            "falco_uuid": self.falco_uuid,
            "source_id": self.source_id,
            "is_intervention_required": self.is_intervention_required,
            "is_expected_admin_activity": self.is_expected_admin_activity,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuntimeContext":
        """Deserialize from dict."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ── Builder Function ─────────────────────────────────────────────────────────

def build_runtime_context(falco_doc: Dict[str, Any]) -> RuntimeContext:
    """Build a RuntimeContext from a raw Falco Elasticsearch document."""
    of = falco_doc.get("output_fields", {}) or {}

    rule_name = falco_doc.get("rule", "Unknown Rule")
    priority = falco_doc.get("priority", "warning")
    tags = falco_doc.get("tags", []) or []
    evt_type = of.get("evt_type", "")

    category = _classify_runtime_category(rule_name, evt_type, tags)
    severity = _map_severity(priority, tags, category)
    mitre_techniques = _extract_mitre_techniques(tags)

    user_name = of.get("user_name", "")
    proc_tty = of.get("proc_tty")

    is_intervention = _is_intervention_required(category, priority, user_name, proc_tty)
    is_expected_admin = _is_expected_admin_activity(category, priority, user_name, proc_tty)

    # Extract ancestor names
    ancestors = []
    for i in range(2, 5):
        key = f"proc_aname[{i}]"
        val = of.get(key)
        if val and val not in ["<NA>", "", None]:
            ancestors.append(str(val))

    # Recover corrupted numeric proc_name from proc_exepath when possible
    _proc_name = of.get("proc_name", "") or ""
    _proc_cmdline = of.get("proc_cmdline", "") or ""
    _proc_exepath = of.get("proc_exepath", "") or ""
    if isinstance(_proc_name, str) and _proc_name.isdigit() and _proc_exepath:
        recovered = _proc_exepath.split("/")[-1]
        if recovered:
            _proc_name = recovered
            if isinstance(_proc_cmdline, str) and _proc_cmdline.strip() and _proc_cmdline.strip()[0].isdigit():
                import re
                recovered_cmdline = re.sub(r"^(\d+\b)", recovered, _proc_cmdline.strip(), count=1)
                if recovered_cmdline != _proc_cmdline.strip():
                    _proc_cmdline = recovered_cmdline

    ctx = RuntimeContext(
        runtime_category=category,
        rule_name=rule_name,
        priority=priority,
        severity=severity,
        hostname=of.get("evt_hostname", falco_doc.get("hostname", "unknown")),
        environment=of.get("environment", ""),
        asset_role=of.get("asset_role", ""),
        proc_name=_proc_name,
        proc_cmdline=_proc_cmdline,
        proc_exepath=_proc_exepath,
        proc_pid=of.get("proc_pid", 0) or 0,
        proc_pname=of.get("proc_pname", ""),
        proc_ppid=of.get("proc_ppid", 0) or 0,
        proc_tty=proc_tty,
        proc_ancestors=ancestors,
        user_name=user_name,
        user_uid=of.get("user_uid", 0) or 0,
        user_loginuid=of.get("user_loginuid", 0) or 0,
        fd_name=of.get("fd_name") if of.get("fd_name") not in ["<NA>", "", None] else None,
        fd_type=of.get("fd_type") if of.get("fd_type") not in ["<NA>", "", None] else None,
        fd_sip=of.get("fd_sip") if of.get("fd_sip") not in ["<NA>", "", None] else None,
        fd_sport=of.get("fd_sport") or None,
        fd_dip=of.get("fd_dip") if of.get("fd_dip") not in ["<NA>", "", None] else None,
        fd_dport=of.get("fd_dport") or None,
        fd_rip=of.get("fd_rip") if of.get("fd_rip") not in ["<NA>", "", None] else None,
        fd_rport=of.get("fd_rport") or None,
        fd_lip=of.get("fd_lip") if of.get("fd_lip") not in ["<NA>", "", None] else None,
        fd_lport=of.get("fd_lport") or None,
        container_id=of.get("container_id", "host"),
        container_name=of.get("container_name", "host"),
        container_image_repository=of.get("container_image_repository") or None,
        container_image_tag=of.get("container_image_tag") or None,
        k8s_ns_name=of.get("k8s_ns_name") if of.get("k8s_ns_name") not in ["<NA>", "", None] else None,
        k8s_pod_name=of.get("k8s_pod_name") if of.get("k8s_pod_name") not in ["<NA>", "", None] else None,
        evt_type=evt_type,
        evt_category=of.get("evt_category", ""),
        evt_time=str(falco_doc.get("time", "")),
        timestamp=str(falco_doc.get("@timestamp", "")),
        output_message=falco_doc.get("output", ""),
        falco_tags=tags,
        mitre_techniques=mitre_techniques,
        falco_uuid=falco_doc.get("uuid", ""),
        source_id=falco_doc.get("_id", ""),
        is_intervention_required=is_intervention,
        is_expected_admin_activity=is_expected_admin,
    )

    logger.info(
        "runtime_context_built",
        rule=rule_name,
        category=category,
        severity=severity,
        host=ctx.hostname,
        process=ctx.proc_name,
        intervention=is_intervention,
        expected_admin=is_expected_admin,
    )

    return ctx
