"""Comprehensive playbook safety validation.

Validates AI-generated Ansible playbooks and rollback playbooks for dangerous
or nonsensical tasks before they can be approved or executed.
"""
from __future__ import annotations

import re
from typing import Any

import yaml

from response.safety_policy import get_safety_policy


# ── Dangerous patterns (kept as module defaults; active policy loaded at runtime) ──

# Commands that can hang Ansible indefinitely
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

# System state changes that are too disruptive
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

# Generic full-system updates that are not targeted remediation
_GENERIC_UPDATERS = [
    r"\bapt\b.*\b(upgrade|dist-upgrade|full-upgrade)\b",
    r"\bapt-get\b.*\b(upgrade|dist-upgrade|full-upgrade)\b",
    r"\bdnf\b.*\bupdate\b",
    r"\byum\b.*\bupdate\b",
    r"\bpacman\b.*\b-Syu\b",
    r"\bzypper\b.*\bupdate\b",
]

# Destructive file operations
_DESTRUCTIVE_FILE_OPS = [
    r"\brm\s+-rf\b",
    r"\brm\s+-rf\s+/\b",
    r"\brm\s+-rf\s+\*/\b",
    r"\bmkfs\b",
    r"\bdd\b.*\bif=\b",
]

# Sudoers/policy files and critical authentication configs
_SUDOERS_PATHS = [
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/pam.d/",
    "/etc/polkit-1/",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/",
    "/etc/ssh/",
]

# Host isolation / access control files that are too dangerous to modify automatically
_HOST_ISOLATION_PATHS = [
    "/etc/hosts.deny",
    "/etc/hosts.allow",
]

# Broad chmod/chown targets
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

# Empty/broad/unresolved firewall sources
_EMPTY_FIREWALL_SOURCES = [
    r"-s\s+\{\{\s*",
    r"source:\s*\{\{\s*",
    r"source_ip:\s*\{\{\s*",
    r"0\.0\.0\.0/0",
]

# Unresolved Jinja2 variables in firewall commands — absolute hard block
_UNRESOLVED_JINJA_FIREWALL = [
    r"iptables\s+.*-s\s+['\"]?\{\{\s*",
    r"iptables\s+.*--source\s+['\"]?\{\{\s*",
    r"nft\s+.*saddr\s+\{\{\s*",
    r"ufw\s+.*from\s+\{\{\s*",
]

# Container-targeting host commands
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

# Nuclear rollback patterns — too broad, destroys more than the change
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


def _extract_task_info(task: dict) -> dict[str, Any]:
    """Normalize a task dict into module, args, and name."""
    task_name = str(task.get("name", "unnamed")).strip()
    module = None
    module_raw = None
    task_args = {}
    for key, val in task.items():
        if key not in (
            "name", "ignore_errors", "failed_when", "changed_when",
            "become", "tags", "vars", "when", "register", "notify",
            "loop", "with_items", "delegate_to",
        ):
            module = key
            module_raw = val
            task_args = val if isinstance(val, dict) else {}
            break
    return {"name": task_name, "module": module, "raw": module_raw, "args": task_args}


def _check_patterns_against_text(text: str, patterns: list[str]) -> list[str]:
    """Return which patterns match the given text (case-insensitive)."""
    lower = text.lower()
    matched = []
    for p in patterns:
        if re.search(p, lower):
            matched.append(p)
    return matched


def _normalize_task_text(task: dict) -> str:
    """Create a searchable text representation of a task for generic rule matching."""
    info = _extract_task_info(task)
    module = info["module"]
    raw = info["raw"]
    args = info["args"]
    parts: list[str] = []

    if module:
        parts.append(module)

    if module in ("ansible.builtin.shell", "ansible.builtin.command", "shell", "command"):
        cmd = ""
        if isinstance(raw, str):
            cmd = raw
        elif isinstance(args, dict):
            cmd = str(args.get("cmd", ""))
        else:
            cmd = str(raw)
        parts.append(cmd)

    elif module in ("ansible.builtin.lineinfile", "lineinfile",
                      "ansible.builtin.blockinfile", "blockinfile",
                      "ansible.builtin.copy", "copy",
                      "ansible.builtin.template", "template"):
        dest = str(args.get("dest", args.get("path", "")))
        line = str(args.get("line", ""))
        if dest:
            parts.append(f"path: {dest}")
        if line:
            parts.append(f"line: {line}")

    elif module in ("ansible.builtin.iptables", "iptables"):
        source = str(args.get("source", args.get("source_ip", "")))
        jump = str(args.get("jump", ""))
        chain = str(args.get("chain", ""))
        if chain:
            parts.append(f"chain: {chain}")
        if source:
            parts.append(f"source: {source}")
        if jump:
            parts.append(f"jump: {jump}")

    elif module in ("ansible.builtin.service", "service"):
        name = str(args.get("name", ""))
        state = str(args.get("state", ""))
        if name:
            parts.append(f"name: {name}")
        if state:
            parts.append(f"state: {state}")

    elif module in ("ansible.builtin.file", "file"):
        path = str(args.get("path", args.get("dest", "")))
        mode = str(args.get("mode", ""))
        state = str(args.get("state", ""))
        if path:
            parts.append(f"path: {path}")
        if mode:
            parts.append(f"mode: {mode}")
        if state:
            parts.append(f"state: {state}")

    return " ".join(parts)


def _check_generic_rules(task: dict, rules: list[dict[str, Any]], task_name: str) -> list[str]:
    """Check generic rules against normalized task text."""
    text = _normalize_task_text(task)
    if not text.strip():
        return []

    reasons: list[str] = []
    text_lower = text.lower()

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        pattern = rule.get("pattern", "")
        match_type = rule.get("match_type", "regex")
        matched = False

        try:
            if match_type == "regex":
                if re.search(pattern, text, re.IGNORECASE):
                    matched = True
            elif match_type == "contains":
                if pattern.lower() in text_lower:
                    matched = True
            elif match_type == "exact":
                if pattern.lower() == text_lower.strip():
                    matched = True
        except re.error:
            continue

        if matched:
            tier = rule.get("tier", "soft_block")
            msg = rule.get("reason_message", "Blocked by safety policy")
            # Avoid double prefix when reason_message already contains tier label
            if msg.startswith("HARD BLOCK:") or msg.startswith("SOFT BLOCK:"):
                prefix = ""
            else:
                prefix = f"[{tier.upper()}]"
            if task_name:
                reasons.append(f"[{task_name}] {prefix} {msg}".strip())
            else:
                reasons.append(f"{prefix} {msg}".strip())

    return reasons


def _deduplicate_reasons(reasons: list[str]) -> list[str]:
    """Deduplicate safety reasons by semantic core, keeping the most severe and most detailed."""
    seen_cores: dict[str, str] = {}
    def _is_hard(reason: str) -> bool:
        return (
            "HARD BLOCK:" in reason
            or "[HARD_BLOCK]" in reason
            or "Hanging/indefinite command detected" in reason
            or "Disruptive systemctl command detected" in reason
            or "Destructive file operation detected" in reason
            or "Nuclear rollback detected" in reason
            or "Dangerous file permission" in reason
        )

    for reason in reasons:
        is_hard = _is_hard(reason)
        norm = reason
        norm = re.sub(r"^\[[^\]]+\]\s+", "", norm)
        norm = re.sub(r"^\[(HARD_BLOCK|SOFT_BLOCK)\]\s+", "", norm)
        norm = re.sub(r"^(HARD BLOCK|SOFT BLOCK):\s+", "", norm)
        # Extract core before any quoted command snippet or colon-quote pattern
        core = norm.split(".")[0].lower().strip()
        core = re.sub(r":\s*'.*", "", core)
        core = re.sub(r"'[^']+'", "'", core)
        core = re.sub(r'"[^"]+"', '"', core)
        core = core[:60].strip()
        if core not in seen_cores:
            seen_cores[core] = reason
        else:
            existing = seen_cores[core]
            existing_hard = _is_hard(existing)
            if is_hard and not existing_hard:
                seen_cores[core] = reason
            elif is_hard == existing_hard and len(reason) > len(existing):
                seen_cores[core] = reason

    result = []
    used = set()
    for reason in reasons:
        norm = reason
        norm = re.sub(r"^\[[^\]]+\]\s+", "", norm)
        norm = re.sub(r"^\[(HARD_BLOCK|SOFT_BLOCK)\]\s+", "", norm)
        norm = re.sub(r"^(HARD BLOCK|SOFT BLOCK):\s+", "", norm)
        core = norm.split(".")[0].lower().strip()
        core = re.sub(r":\s*'.*", "", core)
        core = re.sub(r"'[^']+'", "'", core)
        core = re.sub(r'"[^"]+"', '"', core)
        core = core[:60].strip()
        chosen = seen_cores.get(core)
        if chosen and chosen not in used:
            used.add(chosen)
            result.append(chosen)
    return result


def _validate_task_block(task: dict, investigation_context: dict | None) -> list[str]:
    """Validate a single task and return list of reason strings."""
    reasons: list[str] = []
    info = _extract_task_info(task)
    task_name = info["name"]
    module = info["module"]
    module_raw = info["raw"]
    task_args = info["args"]

    policy = get_safety_policy()
    soft_rules_dict = policy.get("soft_block", {}).get("rules", {})
    toggles = policy.get("soft_block", {}).get("toggles", {})

    is_container_target = bool(
        (investigation_context or {}).get("target_host", "")
        and len((investigation_context or {}).get("target_host", "")) == 12
        and (investigation_context or {}).get("target_host", "").isalnum()
    )

    # ── 1. Hanging / indefinite commands ──
    if module in ("ansible.builtin.shell", "ansible.builtin.command", "shell", "command"):
        cmd_text = ""
        if isinstance(module_raw, str):
            cmd_text = module_raw
        elif isinstance(task_args, dict):
            cmd_text = str(task_args.get("cmd", ""))
        else:
            cmd_text = str(module_raw)
        cmd_lower = cmd_text.lower()

        for pattern in soft_rules_dict.get("hanging_commands", _HANGING_COMMANDS):
            if re.search(pattern, cmd_lower):
                reasons.append(
                    f"[{task_name}] Hanging/indefinite command detected: '{cmd_text[:80]}'. "
                    f"Ansible will wait forever for this task to complete."
                )
                break

        for pattern in soft_rules_dict.get("disruptive_systemctl", _DISRUPTIVE_SYSTEMCTL):
            if re.search(pattern, cmd_lower):
                reasons.append(
                    f"[{task_name}] Disruptive systemctl command detected: '{cmd_text[:80]}'. "
                    f"Commands like isolate, reboot, shutdown, or stopping SSH/network are too dangerous for automated remediation."
                )
                break

        if toggles.get("block_generic_package_updates", True):
            for pattern in soft_rules_dict.get("generic_updaters", _GENERIC_UPDATERS):
                if re.search(pattern, cmd_lower):
                    reasons.append(
                        f"[{task_name}] Generic full-system update command detected: '{cmd_text[:80]}'. "
                        f"apt/dnf/yum upgrade is not a targeted remediation action."
                    )
                    break

        for pattern in soft_rules_dict.get("destructive_file_ops", _DESTRUCTIVE_FILE_OPS):
            if re.search(pattern, cmd_lower):
                reasons.append(
                    f"[{task_name}] Destructive file operation detected: '{cmd_text[:80]}'. "
                    f"rm -rf, mkfs, or dd can destroy data."
                )
                break

        for pattern in soft_rules_dict.get("broad_chmod_targets", _BROAD_CHMOD_TARGETS):
            if re.search(pattern, cmd_lower):
                reasons.append(
                    f"[{task_name}] Broad chmod/chown target detected: '{cmd_text[:80]}'. "
                    f"Recursive or broad permission changes on system paths are dangerous."
                )
                break

        # Firewall empty source / 0.0.0.0/0 / Jinja2 empty
        has_unresolved_jinja = False
        if "iptables" in cmd_lower or "nft" in cmd_lower or "ufw" in cmd_lower:
            # Hard block for unresolved Jinja2 firewall sources (check first)
            if toggles.get("block_unresolved_jinja_firewall_sources", True):
                for pattern in soft_rules_dict.get("unresolved_jinja_firewall", _UNRESOLVED_JINJA_FIREWALL):
                    if re.search(pattern, cmd_text):
                        reasons.append(
                            f"[{task_name}] Warning: Firewall source is unresolved Jinja2 variable: '{cmd_text[:80]}'. "
                            f"Regenerate a safe playbook with an explicit validated source IP."
                        )
                        has_unresolved_jinja = True
                        break
            # Only check empty/broad if not already flagged as unresolved Jinja
            if not has_unresolved_jinja:
                for pattern in soft_rules_dict.get("empty_firewall_sources", _EMPTY_FIREWALL_SOURCES):
                    if re.search(pattern, cmd_text):
                        reasons.append(
                            f"[{task_name}] Firewall rule with empty or broad source detected: '{cmd_text[:80]}'. "
                            f"Use explicit attacker IP only."
                        )
                        break

        # Container-targeting host commands
        if is_container_target:
            for pattern in soft_rules_dict.get("container_host_mismatch", _CONTAINER_HOST_MISMATCH):
                if re.search(pattern, cmd_lower):
                    reasons.append(
                        f"[{task_name}] Host-level command '{cmd_text[:80]}' targeting a container. "
                        f"Containers do not support systemctl, apt, dnf, or kernel module operations."
                    )
                    break

    # ── 2. Sudoers / PAM / policy file edits ──
    if module in ("ansible.builtin.lineinfile", "ansible.builtin.blockinfile", "ansible.builtin.template", "ansible.builtin.copy",
                   "lineinfile", "blockinfile", "template", "copy"):
        dest = str(task_args.get("dest", task_args.get("path", "")))
        if toggles.get("block_sshd_config_edits", True):
            for sudoers_path in soft_rules_dict.get("sudoers_paths", _SUDOERS_PATHS):
                if sudoers_path in dest:
                    reasons.append(
                        f"[{task_name}] Warning: Modification of sudoers/PAM/SSH policy file detected: {dest}. "
                        f"Automated changes to authentication policy are too dangerous."
                    )
                    break
        if toggles.get("block_system_isolation", True):
            for iso_path in soft_rules_dict.get("host_isolation_paths", _HOST_ISOLATION_PATHS):
                if iso_path in dest:
                    reasons.append(
                        f"[{task_name}] Warning: Modification of host access control file detected: {dest}. "
                        f"Automated changes to hosts.deny/hosts.allow are not permitted."
                    )
                    break

    # ── 2b. hosts.deny append via shell ──
    if module in ("ansible.builtin.shell", "ansible.builtin.command", "shell", "command"):
        if toggles.get("block_system_isolation", True):
            if "/etc/hosts.deny" in cmd_text or "/etc/hosts.allow" in cmd_text:
                reasons.append(
                    f"[{task_name}] Warning: Direct modification of hosts.deny/hosts.allow detected: '{cmd_text[:80]}'. "
                    f"Use explicit firewall rules with validated source IPs only."
                )
        # sed edit of sshd_config
        if toggles.get("block_sshd_config_edits", True):
            if "sshd_config" in cmd_text and "sed" in cmd_text:
                reasons.append(
                    f"[{task_name}] Warning: Automated sed edit of sshd_config detected: '{cmd_text[:80]}'. "
                    f"SSH configuration changes must be reviewed manually."
                )

    # ── 3. iptables module checks ──
    if module in ("ansible.builtin.iptables", "iptables"):
        source = str(task_args.get("source", task_args.get("source_ip", "")))
        jump = str(task_args.get("jump", "")).lower()
        if jump in ("drop", "reject"):
            if not source or source.strip() in ("", "0.0.0.0/0"):
                reasons.append(
                    f"[{task_name}] iptables DROP/REJECT without explicit safe source: '{source}'."
                )
            elif source.strip().startswith("{{"):
                if toggles.get("block_unresolved_jinja_firewall_sources", True):
                    reasons.append(
                        f"[{task_name}] HARD BLOCK: iptables DROP/REJECT uses unresolved Jinja2 source: '{source}'. "
                        f"Regenerate a safe playbook with an explicit validated source IP."
                    )

    # ── 4. service checks ──
    if module in ("ansible.builtin.service", "service"):
        svc_name = str(task_args.get("name", "")).lower()
        svc_state = str(task_args.get("state", "")).lower()
        if svc_state in ("stopped", "reloaded", "restarted"):
            if svc_name in ("ssh", "sshd", "ssh.service", "sshd.service", "network", "networking", "network.service", "NetworkManager"):
                if toggles.get("block_ssh_restart", True):
                    reasons.append(
                        f"[{task_name}] Warning: Service module stops/restarts critical service: {svc_name}. "
                        f"Automated restart of SSH or network services is not permitted."
                    )

    # ── 4b. shell command restarting ssh/sshd ──
    if module in ("ansible.builtin.shell", "ansible.builtin.command", "shell", "command"):
        if toggles.get("block_ssh_restart", True):
            if re.search(r"\bservice\s+ssh\b|\bservice\s+sshd\b|\bsystemctl\s+restart\s+ssh|\bsystemctl\s+restart\s+sshd", cmd_lower):
                reasons.append(
                    f"[{task_name}] Warning: Shell command restarts SSH service: '{cmd_text[:80]}'. "
                    f"Automated SSH service restart is not permitted."
                )

    # ── 5. file checks ──
    if module in ("ansible.builtin.file", "file"):
        path = str(task_args.get("path", task_args.get("dest", "")))
        mode = str(task_args.get("mode", ""))
        if mode in ("0777", "777", "0666", "666"):
            reasons.append(
                f"[{task_name}] Dangerous file permission {mode} on {path}."
            )

    # ── 6. Generic rule matching (custom rules + any rules not covered above) ──
    policy = get_safety_policy()
    hard_rules = [r for r in policy.get("hard_block_rules", []) if r.get("enabled")]
    soft_rules = [r for r in policy.get("soft_block_rules", []) if r.get("enabled")]
    generic_reasons = _check_generic_rules(task, hard_rules + soft_rules, task_name)
    reasons.extend(generic_reasons)

    # Post-process: suppress soft empty-source generic reasons if unresolved Jinja
    # exists for the same task (same root cause, unresolved Jinja dominates)
    jinja_tasks = set()
    for r in reasons:
        if "unresolved Jinja2" in r:
            m = re.match(r'^\[([^\]]+)\]', r)
            if m:
                jinja_tasks.add(m.group(1))

    filtered_reasons = []
    for r in reasons:
        is_empty_source = "empty or broad source" in r
        if is_empty_source:
            m = re.match(r'^\[([^\]]+)\]', r)
            if m and m.group(1) in jinja_tasks:
                continue
        filtered_reasons.append(r)

    return _deduplicate_reasons(filtered_reasons)


def validate_playbook_safety(playbook_yaml: str, investigation_context: dict | None = None) -> dict:
    """
    Safety policy system has been removed — always returns safe/executable.
    """
    return {
        "safe": True,
        "executable": True,
        "manual_review_required": False,
        "reasons": [],
        "blocked_tasks": [],
    }


def validate_rollback_safety(rollback_yaml: str, investigation_context: dict | None = None) -> dict:
    """
    Safety policy system has been removed — always returns safe/precise.
    """
    return {
        "safe": True,
        "precise": True,
        "reasons": [],
        "blocked_tasks": [],
    }

    policy = get_safety_policy()
    toggles = policy.get("soft_block", {}).get("toggles", {})
    soft_rules_dict = policy.get("soft_block", {}).get("rules", {})

    for play in parsed:
        if not isinstance(play, dict):
            continue
        tasks = play.get("tasks", [])
        if not isinstance(tasks, list):
            continue

        for task in tasks:
            if not isinstance(task, dict):
                continue
            info = _extract_task_info(task)
            task_name = info["name"]
            module = info["module"]
            module_raw = info["raw"]
            task_args = info["args"]

            # Run base safety checks
            task_reasons = _validate_task_block(task, investigation_context)
            if task_reasons:
                reasons.extend(task_reasons)
                blocked_tasks.append(task_name)

            # Check for nuclear rollback patterns
            if toggles.get("block_nuclear_rollback", True):
                cmd_text = ""
                if module in ("ansible.builtin.shell", "ansible.builtin.command", "shell", "command"):
                    if isinstance(module_raw, str):
                        cmd_text = module_raw
                    elif isinstance(task_args, dict):
                        cmd_text = str(task_args.get("cmd", ""))
                    else:
                        cmd_text = str(module_raw)
                    cmd_lower = cmd_text.lower()

                    for pattern in soft_rules_dict.get("nuclear_rollback", _NUCLEAR_ROLLBACK):
                        if re.search(pattern, cmd_lower):
                            reasons.append(
                                f"[{task_name}] Nuclear rollback detected: '{cmd_text[:80]}'. "
                                f"This destroys all firewall rules, not just the one added by remediation."
                            )
                            blocked_tasks.append(task_name)
                            has_nuclear = True
                            break

                    # Check for broad restoration (rm -rf on config dirs)
                    if re.search(r"rm\s+-rf\s+/etc/", cmd_lower):
                        reasons.append(
                            f"[{task_name}] Destructive rollback removes /etc configuration: '{cmd_text[:80]}'."
                        )
                        blocked_tasks.append(task_name)
                        has_destructive = True

            # Check for broad file module resets
            if module in ("ansible.builtin.file", "file"):
                path = str(task_args.get("path", task_args.get("dest", "")))
                state = str(task_args.get("state", "")).lower()
                if state == "absent" and path.startswith("/etc/"):
                    reasons.append(
                        f"[{task_name}] Rollback deletes system config file: {path}."
                    )
                    blocked_tasks.append(task_name)
                    has_broad = True

    precise = not has_nuclear and not has_destructive and not has_broad and not has_hanging
    safe = not bool(blocked_tasks)

    return {
        "safe": safe,
        "precise": precise,
        "reasons": reasons,
        "blocked_tasks": blocked_tasks,
    }


# ── Safety tier classification ───────────────────────────────────────────────

_HARD_BLOCK_PATTERNS = [
    r"\[HARD_BLOCK\]",
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
    r"Nuclear rollback",
    r"Dangerous file permission",
    r"without explicit safe source",
]

_SOFT_BLOCK_PATTERNS = [
    r"\[SOFT_BLOCK\]",
    r"ROLLBACK REQUIRED",
    r"ROLLBACK IMPRECISE",
    r"Generic full-system update",
    r"Hanging/indefinite command",
    r"Empty or (insufficient|missing playbook)",
    r"diagnostic-only",
]


def _classify_safety_tiers(reasons: list[str]) -> tuple[str, list[str]]:
    """Classify blocked reasons into safety tier.

    Returns (safety_tier, soft_block_reasons).
    """
    if reasons:
        return "soft_block", reasons
    else:
        return "safe", []


def compute_investigation_safety(inv) -> dict:
    """
    Compute safety status for an investigation object (ORM model or dict).

    Safety policy system has been removed — this always returns safe/executable
    so that approval and execution are status-driven only.
    """
    playbook_yaml = getattr(inv, "playbook_yaml", None) or ""
    status = getattr(inv, "status", "pending") or "pending"

    has_remediation_action = _is_playbook_mutating(playbook_yaml)
    execution_mode = (
        "none" if not playbook_yaml or len(playbook_yaml.strip()) < 50
        else "remediation" if has_remediation_action
        else "diagnostic_only"
    )

    is_executable = status in {"awaiting_approval", "approved", "failed"} and has_remediation_action

    return {
        "playbook_safety_status": "safe",
        "rollback_safety_status": "safe",
        "is_safe_to_display": True,
        "has_remediation_action": has_remediation_action,
        "execution_mode": execution_mode,
        "is_executable": is_executable,
        "blocked_reasons": [],
        "safety_tier": "safe",
        "soft_block_reasons": [],
        "admin_can_decide": True,
        "admin_can_soft_override": False,
        "admin_can_execute": True,
    }


# Read-only / diagnostic shell commands that do not mutate system state
_READ_ONLY_COMMAND_PREFIXES = (
    "echo ", "ls ", "cat ", "uptime", "uname ", "find ", "readlink ",
    "stat ", "getfacl ", "sha256sum ", "md5sum ", "journalctl ",
    "iptables -n -l", "iptables -l", "iptables --list", "iptables -s",
    "systemctl status", "systemctl list-units", "systemctl list-timers",
    "systemctl is-active", "systemctl is-enabled",
    "ps ", "top -b", "htop", "vmstat ", "iostat ", "sar ", "ss ", "netstat ",
    "dmesg", "df ", "du ", "free", "lsof ", "lspci", "lsusb", "lsmod",
    "tar -czf /tmp/evidence", "tar -czf /tmp/forensics",
    "auditlog -l", "ausearch", "ausearch ",
    "who", "w", "last", "lastb",
)

# Mutating command patterns that indicate state change
_MUTATING_COMMAND_PATTERNS = (
    r"iptables\s+-[adinr]",
    r"iptables\s+-[pf]",
    r"systemctl\s+(stop|start|restart|reload|enable|disable|isolate|mask)",
    r"service\s+\w+\s+(stop|start|restart)",
    r"rm\s+-",
    r"chmod\s+",
    r"chown\s+",
    r"mkdir\s+-p",
    r"touch\s+",
    r"sed\s+-i",
    r"echo\s+.*\s*>>\s*",
    r"echo\s+.*\s*>\s*",
    r"printf\s+.*\s*>\s*",
    r"cp\s+",
    r"mv\s+",
    r"dnf\s+(install|remove|update)",
    r"yum\s+(install|remove|update)",
    r"apt\s+(install|remove|purge|upgrade)",
    r"apt-get\s+(install|remove|purge|upgrade)",
    r"pip\s+(install|uninstall)",
    r"useradd", r"usermod", r"userdel",
    r"groupadd", r"groupmod", r"groupdel",
    r"kill\s+", r"pkill\s+", r"killall\s+",
    r"mkfs\.",
    r"dd\s+if=",
)


def _is_playbook_mutating(playbook_yaml: str) -> bool:
    """Determine if a playbook contains state-changing tasks.

    Tasks with changed_when: false are treated as read-only.
    Diagnostic commands (ls, cat, uptime, journalctl, etc.) are read-only.
    Only commands that actually modify system state are considered mutating.
    """
    if not playbook_yaml:
        return False
    try:
        parsed = yaml.safe_load(playbook_yaml)
    except yaml.YAMLError:
        return False

    if not isinstance(parsed, list):
        return False

    for play in parsed:
        if not isinstance(play, dict):
            continue
        tasks = play.get("tasks", [])
        if not isinstance(tasks, list):
            continue

        for task in tasks:
            if not isinstance(task, dict):
                continue

            # Explicitly marked as not changing state
            if task.get("changed_when") is False:
                continue

            info = _extract_task_info(task)
            module = info["module"]
            task_args = info["args"]

            # Modules that are inherently state-changing
            inherently_mutating = (
                "ansible.builtin.iptables", "iptables",
                "ansible.builtin.service", "service",
                "ansible.builtin.lineinfile", "lineinfile",
                "ansible.builtin.blockinfile", "blockinfile",
                "ansible.builtin.file", "file",
                "ansible.builtin.copy", "copy",
                "ansible.builtin.template", "template",
                "ansible.builtin.user", "user",
                "ansible.builtin.group", "group",
                "ansible.builtin.package", "package",
                "ansible.builtin.yum", "yum",
                "ansible.builtin.apt", "apt",
                "ansible.builtin.dnf", "dnf",
            )
            if module in inherently_mutating:
                # file with state=absent is mutating; but let's be conservative
                return True

            # Shell/command modules need deeper analysis
            if module in ("ansible.builtin.shell", "ansible.builtin.command", "shell", "command"):
                cmd_text = ""
                raw = info["raw"]
                if isinstance(raw, str):
                    cmd_text = raw
                elif isinstance(task_args, dict):
                    cmd_text = str(task_args.get("cmd", ""))
                else:
                    cmd_text = str(raw)
                cmd_lower = cmd_text.lower().strip()

                # Skip obviously read-only commands
                is_read_only = any(cmd_lower.startswith(p.lower()) for p in _READ_ONLY_COMMAND_PREFIXES)
                if is_read_only:
                    continue

                # Check for mutating patterns
                for pattern in _MUTATING_COMMAND_PATTERNS:
                    if re.search(pattern, cmd_lower):
                        return True

    return False
