"""Configurable safety policy for playbook validation.

Loads from settings (SAFETY_POLICY_JSON) with fallback to built-in safe defaults.
Supports both legacy dict-based format and new rule-based format (version 2).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

import structlog

logger = structlog.get_logger()

# ── Valid values ─────────────────────────────────────────────────────────────

VALID_CATEGORIES = [
    "firewall",
    "system_service",
    "filesystem",
    "package_manager",
    "ssh",
    "sudoers_pam",
    "rollback",
    "ai_quality",
    "verification",
    "custom",
]
VALID_MATCH_TYPES = ["regex", "contains", "exact"]
VALID_TIERS = ["soft_block"]
VALID_APPLIES_TO = ["playbook", "rollback", "both"]


# ── Legacy pattern constants (kept as module fallbacks) ──────────────────────

_HANGING_COMMANDS = [
    r"\btail\s+-f\b",
    r"\bwatch\b",
    r"\btop\b",
    r"\bhtop\b",
    r"\bvmstat\s+\d+\b",
    r"\biostat\s+\d+\b",
    r"\bsar\s+\d+\b",
    r"\bping\b",
    r"\bnc\s+-l\b",
    r"\bnetcat\s+-l\b",
    r"\bwhile\s+true\b",
    r"\bfor\s+\(\(\s*;\s*;\s*\)\)\b",
    r"\bsleep\s+\d{4,}\b",
]

_DISRUPTIVE_SYSTEMCTL = [
    r"\bisolate\b",
    r"\breboot\b",
    r"\bshutdown\b",
    r"\bhalt\b",
    r"\bpoweroff\b",
    r"\bstop\s+.*\bssh\b",
    r"\bstop\s+.*\bsshd\b",
    r"\bstop\s+.*\bnetwork\b",
    r"\bdisable\s+.*\bssh\b",
    r"\bdisable\s+.*\bsshd\b",
]

_DESTRUCTIVE_FILE_OPS = [
    r"\brm\s+-rf\b",
    r"\brm\s+-rf\s+/\b",
    r"\brm\s+-rf\s+\*/\b",
    r"\bmkfs\b",
    r"\bdd\b.*\bif=\b",
]

_UNRESOLVED_JINJA_FIREWALL = [
    r"iptables\s+.*-s\s+['\"]?\{\{\s*",
    r"iptables\s+.*--source\s+['\"]?\{\{\s*",
    r"nft\s+.*saddr\s+\{\{\s*",
    r"ufw\s+.*from\s+\{\{\s*",
]

_NUCLEAR_ROLLBACK = [
    r"iptables\s+-[Ff]",
    r"iptables\s+-[Xx]",
    r"iptables\s+-[Pp]\s+\w+\s+ACCEPT",
    r"nft\s+flush\s+ruleset",
    r"ufw\s+reset",
    r"ufw\s+--force\s+reset",
    r"firewalld\s+.*reload",
    r"systemctl\s+restart\s+firewalld",
]

_SUDOERS_PATHS = [
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/pam.d/",
    "/etc/polkit-1/",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/",
    "/etc/ssh/",
]

_HOST_ISOLATION_PATHS = [
    "/etc/hosts.deny",
    "/etc/hosts.allow",
]

_GENERIC_UPDATERS = [
    r"\bapt\b.*\b(upgrade|dist-upgrade|full-upgrade)\b",
    r"\bapt-get\b.*\b(upgrade|dist-upgrade|full-upgrade)\b",
    r"\bdnf\b.*\bupdate\b",
    r"\byum\b.*\bupdate\b",
    r"\bpacman\b.*\b-Syu\b",
    r"\bzypper\b.*\bupdate\b",
]

_BROAD_CHMOD_TARGETS = [
    r"\bchmod\b.*\b-R\b.*\s+/\b",
    r"\bchown\b.*\b-R\b.*\s+/\b",
    r"\bchmod\b.*\s+/etc\b",
    r"\bchown\b.*\s+/etc\b",
    r"\bchmod\b.*\s+/usr\b",
    r"\bchown\b.*\s+/usr\b",
    r"\bchmod\b.*\s+/var\b",
    r"\bchown\b.*\s+/var\b",
    r"\bchmod\b.*\s+777\b",
    r"\bchmod\b.*\s+666\b",
]

_EMPTY_FIREWALL_SOURCES = [
    r"-s\s+\{\{\s*",
    r"source:\s*\{\{\s*",
    r"source_ip:\s*\{\{\s*",
    r"0\.0\.0\.0/0",
]

_CONTAINER_HOST_MISMATCH = [
    r"\bsystemctl\b",
    r"\bservice\b",
    r"\bapt\b",
    r"\bapt-get\b",
    r"\bdnf\b",
    r"\byum\b",
    r"\bmodprobe\b",
    r"\binsmod\b",
    r"\brkmod\b",
]

_HARD_BLOCK_CLASSIFIERS = [
    r"rm\s+-rf",
    r"mkfs\b",
    r"dd\b.*\bif=",
    r"sudoers",
    r"/etc/pam\.d/",
    r"/etc/polkit-1/",
    r"isolate\b",
    r"\breboot\b",
    r"\bshutdown\b",
    r"\bhalt\b",
    r"\bpoweroff\b",
    r"iptables\s+-[Ff]",
    r"iptables\s+-[Xx]",
    r"nft\s+flush\s+ruleset",
    r"ufw\s+reset",
    r"ufw\s+--force\s+reset",
    r"stop\s+.*\bssh\b",
    r"stop\s+.*\bsshd\b",
    r"stop\s+.*\bnetwork\b",
    r"disable\s+.*\bssh\b",
    r"disable\s+.*\bsshd\b",
    r"chmod\b.*\b-R\b.*\s+/\b",
    r"chown\b.*\b-R\b.*\s+/\b",
    r"chmod\b.*\s+777\b",
    r"chmod\b.*\s+666\b",
    r"AI QUALITY FAILED",
    r"HARD BLOCK:.*unresolved Jinja2",
    r"HARD BLOCK:.*firewall source is unresolved",
    r"unresolved Jinja2 variable",
    r"HARD BLOCK:.*Modification of sudoers/PAM/SSH policy",
    r"HARD BLOCK:.*Modification of host access control",
    r"HARD BLOCK:.*Direct modification of hosts\.deny",
    r"HARD BLOCK:.*Automated sed edit of sshd_config",
    r"HARD BLOCK:.*Service module stops/restarts critical service",
    r"HARD BLOCK:.*Shell command restarts SSH service",
]

_SOFT_BLOCK_CLASSIFIERS = [
    r"ROLLBACK REQUIRED",
    r"ROLLBACK IMPRECISE",
    r"Generic full-system update",
    r"Hanging/indefinite command",
    r"Empty or (insufficient|missing playbook)",
    r"diagnostic-only",
]


# ── Rule builder ─────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_rule(
    name: str,
    description: str,
    tier: str,
    category: str,
    match_type: str,
    pattern: str,
    reason_message: str,
    applies_to: str = "both",
    is_default: bool = True,
    enabled: bool = True,
    rule_id: str | None = None,
    created_by: str = "system",
) -> dict[str, Any]:
    return {
        "id": rule_id or str(uuid.uuid4()),
        "name": name,
        "description": description,
        "tier": tier,
        "enabled": enabled,
        "category": category,
        "match_type": match_type,
        "pattern": pattern,
        "reason_message": reason_message,
        "applies_to": applies_to,
        "created_by": created_by,
        "is_default": is_default,
        "updated_at": _now(),
    }


def _build_default_rules() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build default hard-block and soft-block rules from legacy constants."""
    hard: list[dict[str, Any]] = []
    soft: list[dict[str, Any]] = []

    # Hanging commands
    for pattern in _HANGING_COMMANDS:
        hard.append(
            _make_rule(
                name=f"Block hanging command",
                description="Prevent indefinite commands that hang Ansible",
                tier="soft_block",
                category="system_service",
                match_type="regex",
                pattern=pattern,
                reason_message="Warning: Hanging/indefinite command detected. Ansible will wait forever for this task to complete.",
                applies_to="both",
                rule_id=f"system-hanging-{hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:8]}",
            )
        )

    # Disruptive systemctl
    for pattern in _DISRUPTIVE_SYSTEMCTL:
        hard.append(
            _make_rule(
                name=f"Block disruptive systemctl",
                description="Prevent disruptive system state changes",
                tier="soft_block",
                category="system_service",
                match_type="regex",
                pattern=pattern,
                reason_message="Warning: Disruptive systemctl command detected. Commands like isolate, reboot, shutdown, or stopping SSH/network are too dangerous for automated remediation.",
                applies_to="both",
                rule_id=f"system-disruptive-{hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:8]}",
            )
        )

    # Destructive file ops
    for pattern in _DESTRUCTIVE_FILE_OPS:
        hard.append(
            _make_rule(
                name=f"Block destructive file operation",
                description="Prevent data destruction",
                tier="soft_block",
                category="filesystem",
                match_type="regex",
                pattern=pattern,
                reason_message="Warning: Destructive file operation detected. rm -rf, mkfs, or dd can destroy data.",
                applies_to="both",
                rule_id=f"system-destructive-{hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:8]}",
            )
        )

    # Unresolved Jinja firewall
    for pattern in _UNRESOLVED_JINJA_FIREWALL:
        hard.append(
            _make_rule(
                name=f"Block unresolved Jinja firewall source",
                description="Prevent firewall rules with unresolved Jinja2 variables",
                tier="soft_block",
                category="firewall",
                match_type="regex",
                pattern=pattern,
                reason_message="Warning: Firewall source is unresolved Jinja2 variable. Regenerate a safe playbook with an explicit validated source IP.",
                applies_to="both",
                rule_id=f"system-jinja-fw-{hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:8]}",
            )
        )

    # Nuclear rollback
    for pattern in _NUCLEAR_ROLLBACK:
        hard.append(
            _make_rule(
                name=f"Block nuclear rollback",
                description="Prevent overly broad rollback patterns",
                tier="soft_block",
                category="rollback",
                match_type="regex",
                pattern=pattern,
                reason_message="Warning: Nuclear rollback detected. This destroys all firewall rules, not just the one added by remediation.",
                applies_to="rollback",
                rule_id=f"system-nuclear-{hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:8]}",
            )
        )

    # Sudoers / PAM / SSH policy paths
    for path in _SUDOERS_PATHS:
        hard.append(
            _make_rule(
                name=f"Block edit of {path}",
                description="Prevent automated changes to authentication policy files",
                tier="soft_block",
                category="sudoers_pam",
                match_type="contains",
                pattern=path,
                reason_message="Warning: Modification of sudoers/PAM/SSH policy file detected. Automated changes to authentication policy are too dangerous.",
                applies_to="both",
                rule_id=f"system-sudoers-{path.replace('/', '_').replace('.', '_')}",
            )
        )

    # Host isolation paths
    for path in _HOST_ISOLATION_PATHS:
        hard.append(
            _make_rule(
                name=f"Block edit of {path}",
                description="Prevent automated changes to host access control",
                tier="soft_block",
                category="system_service",
                match_type="contains",
                pattern=path,
                reason_message="Warning: Modification of host access control file detected. Automated changes to hosts.deny/hosts.allow are not permitted.",
                applies_to="both",
                rule_id=f"system-isolation-{path.replace('/', '_').replace('.', '_')}",
            )
        )

    # SSH restart via shell
    hard.append(
        _make_rule(
            name="Block SSH restart via shell",
            description="Prevent shell commands that restart SSH",
            tier="soft_block",
            category="ssh",
            match_type="regex",
            pattern=r"\bservice\s+ssh\b|\bservice\s+sshd\b|\bsystemctl\s+restart\s+ssh|\bsystemctl\s+restart\s+sshd",
            reason_message="Warning: Shell command restarts SSH service. Automated SSH service restart is not permitted.",
            applies_to="both",
            rule_id="system-ssh-restart-shell",
        )
    )

    # sshd_config sed edit
    hard.append(
        _make_rule(
            name="Block sshd_config sed edit",
            description="Prevent automated sed edits of sshd_config",
            tier="soft_block",
            category="ssh",
            match_type="regex",
            pattern=r"sshd_config.*sed|sed.*sshd_config",
            reason_message="Warning: Automated sed edit of sshd_config detected. SSH configuration changes must be reviewed manually.",
            applies_to="both",
            rule_id="system-sshd-sed",
        )
    )

    # hosts.deny / hosts.allow shell modification
    hard.append(
        _make_rule(
            name="Block hosts.deny shell modification",
            description="Prevent shell commands modifying hosts.deny",
            tier="soft_block",
            category="system_service",
            match_type="contains",
            pattern="/etc/hosts.deny",
            reason_message="Warning: Direct modification of hosts.deny/hosts.allow detected. Use explicit firewall rules with validated source IPs only.",
            applies_to="both",
            rule_id="system-hosts-deny-shell",
        )
    )
    hard.append(
        _make_rule(
            name="Block hosts.allow shell modification",
            description="Prevent shell commands modifying hosts.allow",
            tier="soft_block",
            category="system_service",
            match_type="contains",
            pattern="/etc/hosts.allow",
            reason_message="Warning: Direct modification of hosts.deny/hosts.allow detected. Use explicit firewall rules with validated source IPs only.",
            applies_to="both",
            rule_id="system-hosts-allow-shell",
        )
    )

    # Service module critical service stop/restart
    hard.append(
        _make_rule(
            name="Block critical service stop/restart via service module",
            description="Prevent service module from stopping/restarting SSH or network",
            tier="soft_block",
            category="ssh",
            match_type="regex",
            pattern=r"name:\s*(ssh|sshd|network|networking|network\.service|NetworkManager)\b.*\bstate:\s*(stopped|reloaded|restarted)",
            reason_message="Warning: Service module stops/restarts critical service. Automated restart of SSH or network services is not permitted.",
            applies_to="both",
            rule_id="system-service-ssh-stop",
        )
    )

    # File module dangerous mode
    hard.append(
        _make_rule(
            name="Block dangerous file permissions",
            description="Prevent setting dangerous file permissions",
            tier="soft_block",
            category="filesystem",
            match_type="regex",
            pattern=r"mode:\s*0?777",
            reason_message="Warning: Dangerous file permission 0777 detected.",
            applies_to="both",
            rule_id="system-file-mode-777",
        )
    )
    hard.append(
        _make_rule(
            name="Block dangerous file permissions 666",
            description="Prevent setting dangerous file permissions",
            tier="soft_block",
            category="filesystem",
            match_type="regex",
            pattern=r"mode:\s*0?666",
            reason_message="Warning: Dangerous file permission 0666 detected.",
            applies_to="both",
            rule_id="system-file-mode-666",
        )
    )

    # iptables module empty/unresolved source
    hard.append(
        _make_rule(
            name="Block iptables module with empty or Jinja source",
            description="Prevent iptables module DROP/REJECT without explicit safe source",
            tier="soft_block",
            category="firewall",
            match_type="regex",
            pattern=r"ansible\.builtin\.iptables.*jump:\s*(drop|reject)(?!.*source:\s*\S)",
            reason_message="Warning: iptables DROP/REJECT without explicit safe source.",
            applies_to="both",
            rule_id="system-iptables-empty-source",
        )
    )
    hard.append(
        _make_rule(
            name="Block iptables module with Jinja2 source",
            description="Prevent iptables module with unresolved Jinja2 source",
            tier="soft_block",
            category="firewall",
            match_type="regex",
            pattern=r"source:\s*\{\{",
            reason_message="Warning: iptables DROP/REJECT uses unresolved Jinja2 source. Regenerate a safe playbook with an explicit validated source IP.",
            applies_to="both",
            rule_id="system-iptables-jinja-source",
        )
    )

    # Soft block: generic updaters
    for pattern in _GENERIC_UPDATERS:
        soft.append(
            _make_rule(
                name=f"Soft block generic updater",
                description="Flag generic full-system updates",
                tier="soft_block",
                category="package_manager",
                match_type="regex",
                pattern=pattern,
                reason_message="Generic full-system update command detected. apt/dnf/yum upgrade is not a targeted remediation action.",
                applies_to="both",
                rule_id=f"system-updater-{hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:8]}",
            )
        )

    # Soft block: broad chmod
    for pattern in _BROAD_CHMOD_TARGETS:
        soft.append(
            _make_rule(
                name=f"Soft block broad chmod/chown",
                description="Flag broad permission changes",
                tier="soft_block",
                category="filesystem",
                match_type="regex",
                pattern=pattern,
                reason_message="Broad chmod/chown target detected. Recursive or broad permission changes on system paths are dangerous.",
                applies_to="both",
                rule_id=f"system-chmod-{hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:8]}",
            )
        )

    # Soft block: empty/broad firewall sources
    for pattern in _EMPTY_FIREWALL_SOURCES:
        soft.append(
            _make_rule(
                name=f"Soft block empty/broad firewall source",
                description="Flag empty or overly broad firewall sources",
                tier="soft_block",
                category="firewall",
                match_type="regex",
                pattern=pattern,
                reason_message="Firewall rule with empty or broad source detected. Use explicit attacker IP only.",
                applies_to="both",
                rule_id=f"system-empty-fw-{hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:8]}",
            )
        )

    # Soft block: container host mismatch
    for pattern in _CONTAINER_HOST_MISMATCH:
        soft.append(
            _make_rule(
                name=f"Soft block container host mismatch",
                description="Flag host-level commands targeting containers",
                tier="soft_block",
                category="system_service",
                match_type="regex",
                pattern=pattern,
                reason_message="Host-level command targeting a container. Containers do not support systemctl, apt, dnf, or kernel module operations.",
                applies_to="both",
                rule_id=f"system-container-{hashlib.md5(pattern.encode(), usedforsecurity=False).hexdigest()[:8]}",
            )
        )

    return hard, soft


# ── Policy builders ──────────────────────────────────────────────────────────

def _default_policy() -> dict[str, Any]:
    from config.settings import get_settings

    settings = get_settings()
    hard_rules, soft_rules = _build_default_rules()

    policy = {
        "version": 2,
        "require_rollback_for_mutating": True,
        "require_verification_plan": True,
        "admin_soft_override_enabled": getattr(settings, "aria_allow_admin_soft_override", False),
        "soft_block_rules": hard_rules + soft_rules,
    }
    _rebuild_old_structures(policy)
    return policy


def _rebuild_old_structures(policy: dict[str, Any]) -> None:
    """Rebuild legacy dict structures from new rule lists for backward compat."""
    soft_rules = [r for r in policy.get("soft_block_rules", []) if r.get("enabled")]

    def _old_key(rule: dict[str, Any]) -> str:
        cat = rule.get("category", "custom")
        mt = rule.get("match_type", "regex")
        pat = rule.get("pattern", "")
        name = rule.get("name", "")
        # Derive old category key from rule properties
        if cat == "system_service" and "Hanging" in rule.get("reason_message", ""):
            return "hanging_commands"
        if cat == "system_service" and "Disruptive" in rule.get("reason_message", ""):
            return "disruptive_systemctl"
        if cat == "filesystem" and "Destructive" in rule.get("reason_message", ""):
            return "destructive_file_ops"
        if cat == "filesystem" and "chmod" in rule.get("reason_message", ""):
            return "broad_chmod_targets"
        if cat == "filesystem" and "Dangerous file permission" in rule.get("reason_message", ""):
            return "dangerous_file_modes"
        if cat == "firewall" and "Jinja" in rule.get("reason_message", ""):
            return "unresolved_jinja_firewall"
        if cat == "firewall" and ("empty" in rule.get("reason_message", "").lower() or "broad" in rule.get("reason_message", "").lower()):
            return "empty_firewall_sources"
        if cat == "rollback":
            return "nuclear_rollback"
        if cat == "sudoers_pam":
            return "sudoers_paths"
        if cat == "system_service" and "isolation" in rule.get("reason_message", "").lower():
            return "host_isolation_paths"
        if cat == "ssh":
            return "ssh_restart"
        if cat == "package_manager":
            return "generic_updaters"
        if cat == "system_service" and "container" in rule.get("reason_message", "").lower():
            return "container_host_mismatch"
        return cat

    soft_dict: dict[str, list[str]] = {}
    for rule in soft_rules:
        key = _old_key(rule)
        soft_dict.setdefault(key, []).append(rule["pattern"])

    toggles = {
        "block_unresolved_jinja_firewall_sources": any(
            r.get("category") == "firewall" and "jinja" in r.get("reason_message", "").lower()
            for r in soft_rules
        ),
        "block_sshd_config_edits": any(
            r.get("category") == "sudoers_pam" and "/etc/ssh" in r.get("pattern", "")
            for r in soft_rules
        ),
        "block_ssh_restart": any(
            r.get("category") == "ssh" for r in soft_rules
        ),
        "block_system_isolation": any(
            r.get("category") == "system_service" and "isolation" in r.get("reason_message", "").lower()
            for r in soft_rules
        ),
        "block_generic_package_updates": any(
            r.get("category") == "package_manager" for r in soft_rules
        ),
        "block_nuclear_rollback": any(
            r.get("category") == "rollback" for r in soft_rules
        ),
    }

    policy["soft_block"] = {"rules": soft_dict, "toggles": toggles}


def _convert_old_policy(old: dict[str, Any]) -> dict[str, Any]:
    """Convert legacy policy dict to version-2 rule-based policy."""
    default = _default_policy()
    soft_rules = list(default["soft_block_rules"])

    toggles = old.get("soft_block", {}).get("toggles", {})

    # Apply toggle overrides to default rules
    for rule in soft_rules:
        msg = rule.get("reason_message", "")
        cat = rule.get("category", "")
        if cat == "firewall" and "jinja" in msg.lower():
            rule["enabled"] = toggles.get("block_unresolved_jinja_firewall_sources", True)
        if cat == "sudoers_pam" and "/etc/ssh" in rule.get("pattern", ""):
            rule["enabled"] = toggles.get("block_sshd_config_edits", True)
        if cat == "ssh":
            rule["enabled"] = toggles.get("block_ssh_restart", True)
        if cat == "system_service" and "isolation" in msg.lower():
            rule["enabled"] = toggles.get("block_system_isolation", True)
        if cat == "rollback":
            rule["enabled"] = toggles.get("block_nuclear_rollback", True)
        if rule.get("category") == "package_manager":
            rule["enabled"] = toggles.get("block_generic_package_updates", True)

    result = {
        "version": 2,
        "require_rollback_for_mutating": old.get("require_rollback_for_mutating", True),
        "require_verification_plan": old.get("require_verification_plan", True),
        "admin_soft_override_enabled": old.get("admin_soft_override_enabled", False),
        "soft_block_rules": soft_rules,
    }
    _rebuild_old_structures(result)
    return result


# ── Public API ───────────────────────────────────────────────────────────────

@lru_cache()
def _cached_get_safety_policy(safety_policy_json: str | None) -> dict[str, Any]:
    if safety_policy_json:
        try:
            parsed = json.loads(safety_policy_json)
            if parsed.get("version") == 2:
                # Ensure old structures are present
                if "soft_block" not in parsed:
                    _rebuild_old_structures(parsed)
                return parsed
            return _convert_old_policy(parsed)
        except Exception:
            logger.warning("safety_policy_parse_failed", raw=safety_policy_json[:200])
    return _default_policy()


def get_safety_policy() -> dict[str, Any]:
    """Load safety policy from settings, falling back to defaults."""
    from config.settings import get_settings

    settings = get_settings()
    raw = getattr(settings, "safety_policy_json", None)
    return _cached_get_safety_policy(raw)


def clear_safety_policy_cache() -> None:
    _cached_get_safety_policy.cache_clear()


def serialize_policy(policy: dict[str, Any]) -> str:
    # Serialize as compact single-line string for safe .env storage
    return json.dumps(policy, separators=(",", ":"))


# ── Validation ───────────────────────────────────────────────────────────────

def validate_safety_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Validate a safety policy and return errors if invalid."""
    errors: list[str] = []

    hard_rules = policy.get("hard_block_rules", [])
    soft_rules = policy.get("soft_block_rules", [])

    if not isinstance(hard_rules, list):
        errors.append("hard_block_rules must be a list.")
        hard_rules = []
    if not isinstance(soft_rules, list):
        errors.append("soft_block_rules must be a list.")
        soft_rules = []

    enabled_hard = [r for r in hard_rules if r.get("enabled")]
    if not enabled_hard:
        errors.append("At least one hard-block rule must be enabled.")

    all_rules = hard_rules + soft_rules
    seen_ids: set[str] = set()

    for rule in all_rules:
        rid = rule.get("id", "")
        name = rule.get("name", rid or "unknown")

        if not rid:
            errors.append(f"Rule '{name}' is missing an id.")
        elif rid in seen_ids:
            errors.append(f"Duplicate rule id: {rid}")
        else:
            seen_ids.add(rid)

        if not rule.get("pattern", "").strip():
            errors.append(f"Rule '{name}' has an empty pattern.")

        if not rule.get("reason_message", "").strip():
            errors.append(f"Rule '{name}' has an empty reason_message.")

        tier = rule.get("tier", "")
        if tier not in VALID_TIERS:
            errors.append(f"Rule '{name}' has invalid tier: {tier}")

        cat = rule.get("category", "")
        if cat not in VALID_CATEGORIES:
            errors.append(f"Rule '{name}' has invalid category: {cat}")

        mt = rule.get("match_type", "")
        if mt not in VALID_MATCH_TYPES:
            errors.append(f"Rule '{name}' has invalid match_type: {mt}")

        applies = rule.get("applies_to", "")
        if applies not in VALID_APPLIES_TO:
            errors.append(f"Rule '{name}' has invalid applies_to: {applies}")

        if mt == "regex":
            try:
                re.compile(rule.get("pattern", ""))
            except re.error as e:
                errors.append(f"Rule '{name}' has invalid regex: {e}")

    return {"valid": len(errors) == 0, "errors": errors}


def _merge_policy(base: Any, override: Any) -> Any:
    """Deep-merge override into base (dicts merge, lists replaced)."""
    if isinstance(base, dict) and isinstance(override, dict):
        result = dict(base)
        for k, v in override.items():
            result[k] = _merge_policy(result.get(k), v) if k in result else v
        return result
    return override


def _rule_fingerprint(rule: dict[str, Any]) -> str:
    """Stable content fingerprint for soft-matching rules across ID changes."""
    return "|".join([
        rule.get("tier", ""),
        rule.get("category", ""),
        rule.get("match_type", ""),
        rule.get("pattern", ""),
        rule.get("applies_to", ""),
    ])


def compute_policy_diff(old_policy: dict[str, Any], new_policy: dict[str, Any]) -> dict[str, Any]:
    """Compute granular diff between two safety policies.

    Returns added, removed, edited, enabled_changed, tier_changed entries
    with old/new values for each rule id.
    """
    old_hard = {r["id"]: r for r in old_policy.get("hard_block_rules", []) if r.get("id")}
    old_soft = {r["id"]: r for r in old_policy.get("soft_block_rules", []) if r.get("id")}
    new_hard = {r["id"]: r for r in new_policy.get("hard_block_rules", []) if r.get("id")}
    new_soft = {r["id"]: r for r in new_policy.get("soft_block_rules", []) if r.get("id")}

    old_all = {**old_hard, **old_soft}
    new_all = {**new_hard, **new_soft}

    # Build fingerprint maps for soft-matching when IDs differ (e.g., old randomized hashes)
    old_by_fp: dict[str, str] = {}
    new_by_fp: dict[str, str] = {}
    for rid, rule in old_all.items():
        old_by_fp[_rule_fingerprint(rule)] = rid
    for rid, rule in new_all.items():
        new_by_fp[_rule_fingerprint(rule)] = rid

    # Reconcile: map new IDs to old IDs when content matches
    id_map: dict[str, str] = {}  # new_id -> old_id
    for rid, rule in new_all.items():
        if rid in old_all:
            id_map[rid] = rid
        else:
            fp = _rule_fingerprint(rule)
            if fp in old_by_fp:
                id_map[rid] = old_by_fp[fp]

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    edited: list[dict[str, Any]] = []
    enabled_changed: list[dict[str, Any]] = []
    tier_changed: list[dict[str, Any]] = []

    for rid, rule in new_all.items():
        mapped_old_id = id_map.get(rid)
        if mapped_old_id is None or mapped_old_id not in old_all:
            added.append({"id": rid, "rule": rule})
            continue

        old_rule = old_all[mapped_old_id]
        # Tier changed
        if old_rule.get("tier") != rule.get("tier"):
            tier_changed.append({
                "id": rid,
                "name": rule.get("name", rid),
                "old_tier": old_rule.get("tier"),
                "new_tier": rule.get("tier"),
                "old": old_rule,
                "new": rule,
            })
            continue  # tier change is major; don't also report as edited

        # Enabled changed
        if bool(old_rule.get("enabled", True)) != bool(rule.get("enabled", True)):
            enabled_changed.append({
                "id": rid,
                "name": rule.get("name", rid),
                "old_enabled": bool(old_rule.get("enabled", True)),
                "new_enabled": bool(rule.get("enabled", True)),
                "tier": rule.get("tier"),
                "old": old_rule,
                "new": rule,
            })

        # Edited fields (ignore updated_at)
        fields_changed = []
        for field in ["name", "description", "category", "match_type", "pattern", "reason_message", "applies_to"]:
            if old_rule.get(field) != rule.get(field):
                fields_changed.append({
                    "field": field,
                    "old": old_rule.get(field),
                    "new": rule.get(field),
                })
        if fields_changed:
            edited.append({
                "id": rid,
                "name": rule.get("name", rid),
                "tier": rule.get("tier"),
                "fields_changed": fields_changed,
                "old": old_rule,
                "new": rule,
            })

    # Removed = old rules that have no matching new rule
    mapped_old_ids = set(id_map.values())
    for rid, rule in old_all.items():
        if rid not in mapped_old_ids:
            removed.append({"id": rid, "rule": rule})

    modified = bool(added or removed or edited or enabled_changed or tier_changed)

    counts = {
        "added": len(added),
        "removed": len(removed),
        "edited": len(edited),
        "enabled_changed": len(enabled_changed),
        "tier_changed": len(tier_changed),
        
        "soft_block_changes": sum(1 for ch in (added + edited + enabled_changed + tier_changed) if ch.get("tier") == "soft_block" or ch.get("rule", {}).get("tier") == "soft_block"),
    }

    return {
        "modified": modified,
        "added": added,
        "removed": removed,
        "edited": edited,
        "enabled_changed": enabled_changed,
        "tier_changed": tier_changed,
        "counts": counts,
    }
