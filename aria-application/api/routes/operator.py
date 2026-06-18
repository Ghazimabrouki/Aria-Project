"""
AI Operator API — Session-based intelligent system operations.

Workflow:
  1. User sends natural language request in a session
  2. AI interprets intent, reasons about steps, generates an Ansible playbook
  3. Frontend shows human-readable execution summary (NOT raw Ansible)
  4. User approves
  5. Ansible playbook is validated and executed
  6. AI analyzes raw execution output
  7. Frontend shows natural language explanation of results
"""

import asyncio
import json
import os
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any

import structlog
import yaml

from fastapi import APIRouter, HTTPException, Query, Depends
from response.auth import require_auth, CurrentUser
from pydantic import BaseModel
from sqlalchemy import select, func

from response.db import AsyncSessionLocal
from response.models import (
    OperatorRun, OperatorSession, OperatorMessage,
    Alert, Incident, Investigation,
    MonitoredAsset,
)
from response.ai_engine.llm_clients import _call_llm
from config import get_settings

settings = get_settings()
logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/operator", tags=["operator"])


# ── Inventory resolution ──────────────────────────────────────────────────────


def _resolve_target_from_inventory(target_alias: str) -> tuple[str, str]:
    """
    Read config/ansible_inventory to resolve a host alias to
    (ansible_host_ip_or_name, ansible_user).
    Returns ('', '') if the file is missing or the alias is not found.
    NO fallback to the alias itself.
    """
    inv_path = Path("config/ansible_inventory")
    if not inv_path.exists():
        return "", ""
    try:
        content = inv_path.read_text()
    except Exception:
        return "", ""
    for line in content.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("[") or line_stripped.startswith("#"):
            continue
        parts = line_stripped.split()
        if not parts:
            continue
        alias = parts[0]
        if alias == target_alias:
            host = target_alias
            user = "root"
            for part in parts[1:]:
                if part.startswith("ansible_host="):
                    host = part.split("=", 1)[1]
                elif part.startswith("ansible_user="):
                    user = part.split("=", 1)[1]
            return host, user
    return "", ""


async def _resolve_target_from_inventory_async(target_alias: str) -> tuple[str, str]:
    """
    Async version that also checks MonitoredAsset table when the alias
    is not found in the static inventory file.
    """
    host, user = _resolve_target_from_inventory(target_alias)
    if host:
        return host, user

    # Fallback: check MonitoredAsset table
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(MonitoredAsset).where(
                    (MonitoredAsset.asset_id == target_alias)
                    | (MonitoredAsset.hostname == target_alias)
                    | (MonitoredAsset.ip_address == target_alias)
                )
            )
            asset = result.scalar_one_or_none()
            if asset and asset.enabled:
                cfg = asset.ansible_config_json or {}
                resolved_host = cfg.get("ansible_host") or asset.hostname or asset.ip_address or target_alias
                resolved_user = cfg.get("ansible_user") or "root"
                return resolved_host, resolved_user
    except Exception:
        pass
    return "", ""


def _get_first_target_from_inventory() -> tuple[str, str]:
    """
    Read config/ansible_inventory and return the first host alias found
    under any [group] section, along with its resolved (host, user).
    Returns ('', '') if inventory is missing or empty — NO fallback to localhost.
    """
    inv_path = Path("config/ansible_inventory")
    if not inv_path.exists():
        return "", ""
    try:
        content = inv_path.read_text()
    except Exception:
        return "", ""
    for line in content.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("[") or line_stripped.startswith("#"):
            continue
        parts = line_stripped.split()
        if not parts:
            continue
        alias = parts[0]
        # Skip vars lines like ansible_password=...
        if "=" in alias and "ansible_" in alias:
            continue
        return _resolve_target_from_inventory(alias)
    return "", ""


async def _get_inventory_hosts_async() -> List[Dict[str, str]]:
    """
    Read config/ansible_inventory AND MonitoredAsset table and return all host
    aliases with resolved info.
    Returns a list of dicts: [{"alias": "...", "host": "...", "user": "..."}]
    """
    inv_path = Path("config/ansible_inventory")
    hosts: List[Dict[str, str]] = []
    seen_aliases: set[str] = set()

    # Static inventory file
    if inv_path.exists():
        try:
            content = inv_path.read_text()
            for line in content.splitlines():
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith("[") or line_stripped.startswith("#"):
                    continue
                parts = line_stripped.split()
                if not parts:
                    continue
                alias = parts[0]
                if "=" in alias and "ansible_" in alias:
                    continue
                resolved_host, resolved_user = _resolve_target_from_inventory(alias)
                if alias not in seen_aliases:
                    seen_aliases.add(alias)
                    hosts.append({"alias": alias, "host": resolved_host, "user": resolved_user})
        except Exception:
            pass

    # MonitoredAsset table (modern per-asset config)
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(MonitoredAsset).where(MonitoredAsset.enabled == True))
            assets = result.scalars().all()
            for asset in assets:
                alias = asset.asset_id or asset.hostname or asset.ip_address
                if not alias or alias in seen_aliases:
                    continue
                cfg = asset.ansible_config_json or {}
                resolved_host = cfg.get("ansible_host") or asset.hostname or asset.ip_address or alias
                resolved_user = cfg.get("ansible_user") or "root"
                seen_aliases.add(alias)
                hosts.append({"alias": alias, "host": resolved_host, "user": resolved_user})
    except Exception as e:
        logger.warning("operator_inventory_asset_query_failed", error=str(e))

    return hosts


def _get_inventory_hosts() -> List[Dict[str, str]]:
    """
    Synchronous wrapper for backward compatibility.
    WARN: This only reads the static inventory file, NOT MonitoredAssets.
    Prefer _get_inventory_hosts_async() in async contexts.
    """
    inv_path = Path("config/ansible_inventory")
    hosts: List[Dict[str, str]] = []
    if not inv_path.exists():
        return hosts
    try:
        content = inv_path.read_text()
    except Exception:
        return hosts
    for line in content.splitlines():
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("[") or line_stripped.startswith("#"):
            continue
        parts = line_stripped.split()
        if not parts:
            continue
        alias = parts[0]
        if "=" in alias and "ansible_" in alias:
            continue
        resolved_host, resolved_user = _resolve_target_from_inventory(alias)
        hosts.append({"alias": alias, "host": resolved_host, "user": resolved_user})
    return hosts


async def _get_inventory_status_async() -> Dict[str, Any]:
    """
    Check the Ansible inventory (static file + MonitoredAssets) and return
    a detailed status dict.
    """
    hosts = await _get_inventory_hosts_async()
    if hosts:
        return {
            "state": "ok",
            "readable": True,
            "hosts": hosts,
            "message": f"Found {len(hosts)} host(s) in inventory.",
        }

    inv_path = Path("config/ansible_inventory")
    if not inv_path.exists():
        return {
            "state": "missing",
            "readable": False,
            "hosts": [],
            "message": "Ansible inventory file not found at config/ansible_inventory",
        }
    try:
        content = inv_path.read_text()
    except Exception as e:
        logger.error("inventory_read_failed", path=str(inv_path), error=str(e))
        return {
            "state": "unreadable",
            "readable": False,
            "hosts": [],
            "message": f"Cannot read Ansible inventory file: {e}",
        }

    has_group = any(line.strip().startswith("[") and line.strip().endswith("]") for line in content.splitlines())
    if not has_group:
        return {
            "state": "malformed",
            "readable": True,
            "hosts": [],
            "message": "Inventory file has no [group] sections. Expected INI format.",
        }

    return {
        "state": "empty",
        "readable": True,
        "hosts": [],
        "message": "Inventory file exists but contains no host entries.",
    }


async def _validate_targets_against_inventory_async(target_hosts: List[str]) -> tuple[bool, str, List[str]]:
    """
    Strictly validate target host aliases against the inventory (static + MonitoredAssets).
    Returns (is_valid, error_message, valid_targets).
    Rejects 'all', '*', and empty strings for security.
    """
    status = await _get_inventory_status_async()
    if status["state"] != "ok":
        return False, f"Inventory unavailable: {status['message']}", []

    if not target_hosts:
        return False, "No target hosts specified.", []

    # Security: block dangerous pseudo-groups
    blocked = [h for h in target_hosts if h.lower() in ("all", "*", "")]
    if blocked:
        return False, f"Blocked dangerous target(s): {', '.join(blocked)}. 'all' and '*' are not permitted.", []

    valid_aliases = {h["alias"] for h in status["hosts"]}
    valid_hosts = {h["host"] for h in status["hosts"]}
    valid = []
    invalid = []
    for h in target_hosts:
        if h in valid_aliases or h in valid_hosts:
            valid.append(h)
        else:
            invalid.append(h)

    if invalid:
        error_msg = f"Unknown target host(s): {', '.join(invalid)}. Valid targets: {', '.join(sorted(valid_aliases))}"
        # Add helpful hint when target looks like an IP address
        for inv in invalid:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", inv):
                error_msg += f"\n\nHint: Use the inventory alias (e.g. '{sorted(valid_aliases)[0] if valid_aliases else 'ghazi'}') instead of the IP address."
                break
        return False, error_msg, valid

    return True, "", valid


def _validate_targets_against_inventory(target_hosts: List[str]) -> tuple[bool, str, List[str]]:
    """
    Synchronous wrapper for backward compatibility.
    WARN: Only checks the static inventory file, NOT MonitoredAssets.
    Prefer _validate_targets_against_inventory_async() in async contexts.
    """
    status = _get_inventory_status()
    if status["state"] != "ok":
        return False, f"Inventory unavailable: {status['message']}", []

    if not target_hosts:
        return False, "No target hosts specified.", []

    blocked = [h for h in target_hosts if h.lower() in ("all", "*", "")]
    if blocked:
        return False, f"Blocked dangerous target(s): {', '.join(blocked)}. 'all' and '*' are not permitted.", []

    valid_aliases = {h["alias"] for h in status["hosts"]}
    valid = [h for h in target_hosts if h in valid_aliases]
    invalid = [h for h in target_hosts if h not in valid_aliases]

    if invalid:
        error_msg = f"Unknown target host(s): {', '.join(invalid)}. Valid targets: {', '.join(sorted(valid_aliases))}"
        for inv in invalid:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", inv):
                error_msg += f"\n\nHint: Use the inventory alias (e.g. '{sorted(valid_aliases)[0] if valid_aliases else 'ghazi'}') instead of the IP address."
                break
        return False, error_msg, valid

    return True, "", valid


async def _validate_asset_id(asset_id: Optional[str]) -> Optional[MonitoredAsset]:
    """
    Validate asset_id when multi_server_enabled is True.
    Returns the MonitoredAsset if valid, None if no asset_id.
    Raises HTTPException for invalid/disabled assets or 'all'.
    """
    if not asset_id:
        return None
    if asset_id.lower() == "all":
        raise HTTPException(status_code=400, detail="asset_id='all' is not permitted for security reasons.")
    if not settings.multi_server_enabled:
        return None
    async with AsyncSessionLocal() as db_session:
        result = await db_session.execute(
            select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
        )
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=400, detail=f"Asset '{asset_id}' not found.")
        if not asset.enabled:
            raise HTTPException(status_code=400, detail=f"Asset '{asset_id}' is disabled.")
        return asset


# Common unquoted shell patterns that need quotes to work correctly
_SHELL_QUOTE_FIXES = [
    # grep patterns
    (r'grep\s+Failed\s+password\s+', 'grep "Failed password" '),
    (r'grep\s+Invalid\s+user\s+', 'grep "Invalid user" '),
    (r'grep\s+Failed\s+password', 'grep "Failed password"'),
    (r'grep\s+Invalid\s+user', 'grep "Invalid user"'),
]


def _sanitize_shell_commands(playbook_yaml: str) -> str:
    """
    Fix common unquoted shell patterns in playbook YAML.
    The LLM often copies natural language into shell commands without quotes,
    causing grep to interpret words as filenames.
    """
    for pattern, replacement in _SHELL_QUOTE_FIXES:
        playbook_yaml = re.sub(pattern, replacement, playbook_yaml)
    return playbook_yaml


def _normalize_playbook_hosts(playbook_yaml: str) -> str:
    """
    Replace any `hosts: <name>` with `hosts: target` so the playbook
    matches the dynamic inventory's [target] group.

    Uses YAML parsing for robustness (handles multi-line hosts, lists, dicts)
    then dumps back to YAML. Comments are lost but playbooks become correct.
    """
    # Pre-process: fix unquoted shell commands before YAML parsing
    playbook_yaml = _sanitize_shell_commands(playbook_yaml)

    try:
        parsed = yaml.safe_load(playbook_yaml)
        if not isinstance(parsed, list):
            return playbook_yaml
        modified = False
        for play in parsed:
            if isinstance(play, dict) and "hosts" in play:
                current = play["hosts"]
                # Normalize scalar hosts (string/None) and list hosts
                if current != "target":
                    play["hosts"] = "target"
                    modified = True
        if not modified:
            return playbook_yaml
        # Harden diagnostic tasks so "not found" doesn't show as Partial Success
        _harden_diagnostic_tasks(parsed)

        # Dump back to YAML with reasonable formatting
        return yaml.dump(
            parsed,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
        )
    except Exception:
        # Fallback: if YAML parsing fails, return original for validation to catch
        return playbook_yaml


# Known diagnostic commands that should never fail the playbook
_DIAGNOSTIC_PATTERNS = [
    # Package / version checks
    "dpkg -l", "dpkg --status", "dpkg -s",
    "rpm -q", "rpm -qa", "which ", "whereis ",
    # Service status (NOT restart/start/stop)
    "systemctl status", "systemctl list-", "systemctl is-",
    "service ",
    # Resource monitoring
    "free ", "df ", "du ", "vmstat", "iostat", "sar ",
    # Process info
    "ps ", "top ", "htop", "pgrep", "pidof", "pstree",
    # Network diagnostic
    "iptables -L", "iptables -S", "nft list",
    "netstat", "ss ", "lsof", "ip ", "ifconfig", "route ",
    # File / content inspection
    "ls ", "cat ", "grep ", "find ", "head ", "tail ", "less ", "more ",
    "stat ", "file ", "md5sum", "sha256sum",
    # Container / orchestration status
    "docker ps", "docker images", "docker stats", "docker info",
    "docker inspect", "docker network ls", "docker volume ls",
    "kubectl get", "kubectl describe", "kubectl top",
    # Version checks (often write to stderr — need failed_when: false)
    "nginx -v", "nginx -t", "node -v", "python -V", "python3 -V",
    "java -version", "go version", "rustc -V", "gcc -v", "php -v",
    # Port / connectivity checks
    "nmap ", "nc -", "telnet ", "curl -", "wget -", "ping ", "traceroute",
    # Security / audit diagnostics
    "crontab", "journalctl", "last", "lastb", "who ", "whoami",
    "getent ", "id ", "groups ", "passwd -S",
    "auditctl", "ausearch", "aureport",
    "chkrootkit", "rkhunter",
    # Log analysis
    "awk ", "sed ", "cut ", "sort ", "uniq ", "wc ",
]

# Short commands that are exact matches (not prefixes)
_DIAGNOSTIC_EXACT = {"w", "whoami"}


# State-changing patterns — these must NEVER have failed_when: false
# because a silent failure could leave the system in an unsafe state
_STATE_CHANGING_PATTERNS = [
    # Firewall / network changes
    "iptables -A ", "iptables -D ", "iptables -I ", "iptables -P ",
    "iptables --append", "iptables --delete", "iptables --insert",
    "nft add", "nft delete", "nft insert",
    "firewall-cmd --add", "firewall-cmd --remove", "firewall-cmd --reload",
    "ufw allow", "ufw deny", "ufw delete",
    # Package management
    "apt install", "apt-get install", "apt remove", "apt-get remove",
    "yum install", "yum remove", "dnf install", "dnf remove",
    "pip install", "pip uninstall", "npm install", "gem install",
    # Service state changes
    "systemctl restart", "systemctl start", "systemctl stop",
    "systemctl enable", "systemctl disable",
    "service ",
    # Process termination
    "kill ", "pkill ", "killall ",
    # File system changes
    "rm ", "rm -", "mkdir ", "rmdir ", "touch ", "cp ", "mv ",
    "chmod ", "chown ", "chgrp ",
    # User management
    "useradd ", "userdel ", "usermod ", "groupadd ", "groupdel",
    "passwd ",
    # Docker / container changes
    "docker run", "docker stop", "docker rm", "docker rmi",
    "docker kill", "docker restart", "docker pull",
    # Redirects that modify files
    "> /", ">>",
    # Other dangerous
    "mkfs", "fdisk", "parted", "dd if=",
]


def _harden_diagnostic_tasks(parsed: list) -> None:
    """
    Inject `failed_when: false` and `changed_when: false` into
    diagnostic tasks so 'not found' / 'no matches' answers don't
    mark the playbook as Partial Success.

    No restrictions on state-changing commands — the engineer decides what to run.
    """
    for play in parsed:
        if not isinstance(play, dict):
            continue
        tasks = play.get("tasks", [])
        if not isinstance(tasks, list):
            continue
        for task in tasks:
            if not isinstance(task, dict):
                continue
            # Keep ignore_errors if the LLM added it — engineer's choice
            # Determine the shell/command being run
            # Support both short (shell) and FQCN (ansible.builtin.shell) module names
            cmd = ""
            for key in ("shell", "command", "raw", "ansible.builtin.shell", "ansible.builtin.command", "ansible.builtin.raw"):
                if key in task:
                    val = task[key]
                    # FQCN modules may have args as dicts (e.g., cmd: "...")
                    if isinstance(val, dict) and "cmd" in val:
                        cmd = val["cmd"]
                    elif isinstance(val, str):
                        cmd = val
                    else:
                        cmd = str(val)
                    break
            if not cmd:
                continue
            # Check if this looks like a diagnostic/gathering command
            is_diagnostic = (
                cmd in _DIAGNOSTIC_EXACT
                or any(cmd.startswith(p) or (" " + p) in cmd for p in _DIAGNOSTIC_PATTERNS)
            )
            if is_diagnostic:
                task.setdefault("failed_when", False)
                task.setdefault("changed_when", False)


# Ansible task-level directives (keywords that are NOT module names).
# Every valid task must have at least one key that is NOT in this set.
_TASK_DIRECTIVES = {
    "name", "vars", "when", "failed_when", "changed_when", "check_mode",
    "delegate_to", "delegate_facts", "run_once", "ignore_errors", "loop",
    "with_items", "with_dict", "with_fileglob", "with_lines", "with_sequence",
    "with_random_choice", "with_first_found", "with_indexed_items",
    "with_flattened", "with_together", "with_subelements", "with_nested",
    "with_cartesian", "register", "tags", "notify", "listen", "become",
    "become_user", "become_method", "become_flags", "remote_user",
    "environment", "no_log", "throttle", "timeout", "delay", "retries",
    "until", "any_errors_fatal", "connection", "module_defaults",
    "collections", "args", "always_run", "diff", "async", "poll",
    "debugger", "import_playbook", "hosts", "gather_facts", "roles",
    "pre_tasks", "post_tasks", "handlers", "vars_files", "vars_prompt",
    "force_handlers", "max_fail_percentage", "serial", "strategy", "order",
    "ignore_unreachable", "block", "rescue", "always",
}


def _task_has_module(task: dict) -> bool:
    """Check if an Ansible task dict contains at least one module/action key."""
    if not isinstance(task, dict):
        return False
    for key in task.keys():
        # FQCN modules contain a dot (e.g., ansible.builtin.shell)
        if "." in key:
            return True
        # Non-directive keys are module names
        if key not in _TASK_DIRECTIVES:
            return True
    return False


def _validate_tasks(tasks: list, path: str = "tasks") -> tuple[bool, str]:
    """Recursively validate that every task has a module/action."""
    for j, task in enumerate(tasks):
        if not isinstance(task, dict):
            continue
        if "block" in task:
            block_tasks = task.get("block", [])
            if isinstance(block_tasks, list):
                valid, err = _validate_tasks(block_tasks, f"{path}[{j}].block")
                if not valid:
                    return False, err
            rescue_tasks = task.get("rescue", [])
            if isinstance(rescue_tasks, list):
                valid, err = _validate_tasks(rescue_tasks, f"{path}[{j}].rescue")
                if not valid:
                    return False, err
            always_tasks = task.get("always", [])
            if isinstance(always_tasks, list):
                valid, err = _validate_tasks(always_tasks, f"{path}[{j}].always")
                if not valid:
                    return False, err
            continue
        if not _task_has_module(task):
            task_name = task.get("name", f"task {j}")
            return False, (
                f"Task '{task_name}' in {path} has no valid Ansible module. "
                f"Every task must have an action such as 'shell', 'command', 'debug', 'fail', 'copy', etc."
            )
    return True, ""


def _escape_docker_go_templates(playbook_yaml: str) -> str:
    """Escape Docker Go templates so Ansible doesn't parse them as Jinja2."""
    lines = playbook_yaml.splitlines()
    fixed: list[str] = []
    for line in lines:
        lowered = line.lower()
        if "docker" in lowered and "--format" in lowered and ("shell:" in line or "command:" in line):
            # Already escaped?
            if "{% raw %}" in line:
                fixed.append(line)
                continue
            # Wrap the entire command value in raw tags
            for prefix in ("shell:", "command:"):
                if prefix in line:
                    before, _, after = line.partition(prefix)
                    cmd = after.strip().strip('"').strip("'")
                    if "{{" in cmd:
                        line = f'{before}{prefix} "{{% raw %}}{cmd}{{% endraw %}}"'
                    break
        fixed.append(line)
    return "\n".join(fixed)


def _fix_common_yaml_errors(playbook_yaml: str) -> str:
    """
    Auto-fix frequent LLM YAML mistakes that break ansible-playbook parsing.
    """
    lines = playbook_yaml.splitlines()
    fixed: list[str] = []

    # Regex to detect compact inline module syntax that LLMs love to generate:
    #   debug: msg="something: with colons"
    #   debug: var=some_var
    #   shell: cmd="some command"
    compact_debug_re = re.compile(r'^(\s*-?\s*)debug:\s*msg=(".*?")\s*$')
    compact_debug_var_re = re.compile(r'^(\s*-?\s*)debug:\s*var=(\S+)\s*$')
    compact_shell_cmd_re = re.compile(r'^(\s*-?\s*)shell:\s*cmd=(".*?")\s*$')

    for line in lines:
        # Fix debug: msg="..."
        m = compact_debug_re.match(line)
        if m:
            indent = m.group(1)
            msg_val = m.group(2)
            fixed.append(f"{indent}debug:")
            fixed.append(f"{indent}  msg: {msg_val}")
            continue

        # Fix debug: var=...
        m = compact_debug_var_re.match(line)
        if m:
            indent = m.group(1)
            var_val = m.group(2)
            fixed.append(f"{indent}debug:")
            fixed.append(f"{indent}  var: {var_val}")
            continue

        # Fix shell: cmd="..."
        m = compact_shell_cmd_re.match(line)
        if m:
            indent = m.group(1)
            cmd_val = m.group(2)
            fixed.append(f"{indent}shell: {cmd_val}")
            continue

        fixed.append(line)

    return "\n".join(fixed)


def _validate_playbook_yaml(playbook_yaml: str) -> tuple[bool, str]:
    """
    Quick YAML validation for operator playbooks.
    Returns (is_valid, error_message).
    """
    if not playbook_yaml.strip():
        return False, "Playbook is empty"
    try:
        parsed = yaml.safe_load(playbook_yaml)
    except Exception as e:
        return False, f"YAML syntax error: {e}"
    if parsed is None:
        return False, "YAML parsed to None — likely empty or malformed"
    if not isinstance(parsed, list):
        return False, "Playbook must be a YAML list of plays"
    if len(parsed) == 0:
        return False, "Playbook has no plays"
    for i, play in enumerate(parsed):
        if not isinstance(play, dict):
            return False, f"Play {i} is not a dictionary"
        if "hosts" not in play:
            return False, f"Play {i} is missing required 'hosts' key"
        # Validate every task has a module
        for task_list_key in ("tasks", "pre_tasks", "post_tasks", "handlers"):
            task_list = play.get(task_list_key, [])
            if isinstance(task_list, list) and task_list:
                valid, err = _validate_tasks(task_list, f"play[{i}].{task_list_key}")
                if not valid:
                    return False, err
    return True, ""


_LOCAL_ANSWER_SYSTEM_PROMPT = """
You are ARIA, an advanced SOC analyst assistant for the OpenSOAR security operations platform.
The user asked a question about the system. Use ONLY the provided system data to answer.
Be concise, actionable, and specific. Include actual numbers, timestamps, and IDs when available.
If the data does not contain the answer, say so clearly — do not hallucinate.
"""


async def _execute_local_query(prompt: str, asset_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Answer a user question using only local OpenSOAR data (no SSH, no Ansible).
    Fetches investigations, alerts, incidents, archives, performance metrics, etc.
    Returns a dict matching the operator result structure.
    """
    from response.assistant import _fetch_all_system_data, _prioritize_records, _format_context_for_prompt

    try:
        data, statistics, config = await _fetch_all_system_data(prompt, focus_entity=None)
        if asset_id:
            data = [
                r for r in data
                if r.get("asset_id") is None or r.get("asset_id") == asset_id
            ]
        prioritized = _prioritize_records(prompt, data)
        context_text = _format_context_for_prompt(prioritized[:50])

        llm_prompt = (
            f"{_LOCAL_ANSWER_SYSTEM_PROMPT}\n\n"
            f"User question: {prompt}\n\n"
            f"System data:\n{context_text}\n\n"
            f"Answer directly and concisely."
        )
        answer = await _call_llm(llm_prompt)

        return {
            "analysis": {
                "outcome": "success",
                "explanation": answer.strip(),
                "key_changes": [],
                "recommendations": [],
            },
            "record_count": len(data),
            "statistics": statistics,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {
            "analysis": {
                "outcome": "failure",
                "explanation": f"Failed to fetch local data: {str(e)}",
                "key_changes": [],
                "recommendations": ["Check backend logs for details."],
            },
            "record_count": 0,
            "statistics": {},
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }


# ── System context gathering ──────────────────────────────────────────────────


async def _get_system_context(target_hosts: List[str], asset_id: Optional[str] = None) -> str:
    """
    Gather recent alerts, incidents, investigations, and past operator runs
    to give the AI situational awareness.
    """
    lines: List[str] = []
    since = datetime.now(timezone.utc) - timedelta(hours=24)

    async with AsyncSessionLocal() as session:
        # Recent critical/high alerts
        try:
            stmt = (
                select(Alert)
                .where(Alert.severity.in_(["critical", "high"]))
                .where(Alert.created_at >= since)
            )
            if asset_id:
                stmt = stmt.where(Alert.asset_id == asset_id)
            stmt = stmt.order_by(Alert.created_at.desc()).limit(5)
            alert_result = await session.execute(stmt)
            alerts = alert_result.scalars().all()
            if alerts:
                lines.append("Recent critical/high alerts (last 24h):")
                for a in alerts:
                    lines.append(f"  - [{a.severity.upper()}] {a.title} (host: {a.hostname or 'unknown'}, src: {a.source_ip or 'N/A'})")
        except Exception:
            pass

        # Recent open incidents
        try:
            stmt = (
                select(Incident)
                .where(Incident.status == "open")
            )
            if asset_id:
                stmt = stmt.where(Incident.asset_id == asset_id)
            stmt = stmt.order_by(Incident.created_at.desc()).limit(5)
            incident_result = await session.execute(stmt)
            incidents = incident_result.scalars().all()
            if incidents:
                lines.append("Open incidents:")
                for i in incidents:
                    lines.append(f"  - [{i.severity.upper()}] {i.title}")
        except Exception:
            pass

        # Recent operator runs on same targets
        try:
            stmt = (
                select(OperatorRun)
                .where(OperatorRun.target_hosts.overlap(target_hosts) if target_hosts else True)
            )
            if asset_id:
                stmt = stmt.where(OperatorRun.asset_id == asset_id)
            stmt = stmt.order_by(OperatorRun.created_at.desc()).limit(3)
            run_result = await session.execute(stmt)
            runs = run_result.scalars().all()
            if runs:
                lines.append("Recent operator runs on these targets:")
                for r in runs:
                    lines.append(f"  - {r.intent} → {r.status} ({r.risk_level} risk)")
        except Exception:
            pass

    if not lines:
        return "No recent system context available."
    return "\n".join(lines)


# ── Pydantic schemas ──────────────────────────────────────────────────────────


class CreateSessionRequest(BaseModel):
    title: Optional[str] = None
    target_hosts: Optional[List[str]] = None
    asset_id: Optional[str] = None


class SendMessageRequest(BaseModel):
    prompt: str
    require_approval: bool = True
    asset_id: Optional[str] = None


class ApproveRunRequest(BaseModel):
    decided_by: str = "analyst"


# ── LLM Prompts ───────────────────────────────────────────────────────────────


_REASONING_SYSTEM_PROMPT = """
You are an expert infrastructure and security engineer assisting in a continuous conversation.

Your job is to:
1. Analyze the intent of the user's CURRENT request
2. Use the conversation history to resolve pronouns and ambiguous references (e.g., "install it" refers to whatever was discussed before)
3. Identify the target system(s) involved
4. Break down the operation into clear, logical steps (shell commands or Ansible tasks)
5. Assess the risk level (low/medium/high)

Respond ONLY with a JSON object in this exact schema:
{
  "intent": "brief description of what the user wants",
  "target_systems": ["host1", "host2"],
  "steps": [
    "Run 'df -h' to check disk usage on the target host",
    "Analyze the output to identify the largest consumers"
  ],
  "risk_level": "low|medium|high",
  "execution_mode": "local|remote|hybrid",
  "reasoning": "Your thought process and analysis"
}

Execution mode classification (CRITICAL):
- "local" — the answer can be found in the OpenSOAR backend data (investigations, alerts, incidents, archives, pipeline status, performance metrics, IPS events). Use this when the user asks about counts, statuses, summaries, or historical data that we already store locally.
- "remote" — the request requires executing commands on the remote target host via Ansible (iptables, free, df, systemctl, package install, reading remote log files). Use this for any operation that changes system state or reads data only available on the remote server.
- "hybrid" — the request needs BOTH remote command execution AND local data correlation (e.g., "Check auth.log for IP 1.2.3.4 and tell me if we have any alerts for it").
- When in doubt, default to "remote".

Risk assessment rules:
- "high" if the action modifies system state (blocks IPs, deletes files, restarts services, changes firewall rules)
- "medium" if it reads sensitive data or runs diagnostic commands that could impact performance
- "low" if it is purely informational (checking status, listing processes, reading logs)

FIREWALL / IP-BLOCKING RULES (CRITICAL):
- ALWAYS assume the target uses `iptables` (available on virtually all Linux systems).
- NEVER plan `firewall-cmd` or `ufw` steps unless you have explicit evidence from conversation history that firewalld/ufw is installed and active.
- For blocking an IP, the step must be: `iptables -A INPUT -s <ip> -j DROP`
- For checking firewall status, the step must be: `iptables -L -n -v`

PORT LISTING RULES (CRITICAL):
- ALWAYS use `ss -tulnp` for listing open ports. NEVER use `netstat`.

CRITICAL CONTEXT RESOLUTION:
- You are in a CONTINUOUS SESSION. The user may refer to things mentioned in previous messages.
- If the user says "install it", "restart it", "check it", "block it", "fix that", "what about that IP", "show me more", etc., you MUST look at the conversation history and determine the EXACT noun they mean.
- If the user asks a follow-up like "what processes" after asking about RAM, they mean processes on the SAME host from the previous request.
- NEVER use placeholders like <package_name>, <service_name>, or <ip_address> in your steps. Always use the actual resolved name (e.g., "nginx", "1.1.1.111").
- Do NOT ask the user to clarify—just infer from context and be specific.
- Default to the same target host as the previous request if none is specified.
"""


_PLAYBOOK_SYSTEM_PROMPT = """
You are an expert Ansible automation engineer. Given a user's request and the planned steps, generate a valid Ansible playbook.

Rules:
- The playbook MUST use `hosts: target` (the inventory will map [target] to the actual host)
- Use `become: yes` when elevated privileges are needed
- Use `failed_when: false` and `changed_when: false` ONLY for diagnostic/gathering tasks (checking status, listing info, version checks). NEVER use these on state-changing tasks.
- State-changing tasks (block IPs, install packages, restart services, delete files, modify configs) must FAIL the playbook if they fail — do NOT add `failed_when: false` to them.
- Prefer `command` or `shell` modules for system operations
- For system memory overview: `shell: free -m`
- For CPU-consuming processes: `shell: ps aux --sort=-%cpu | head -n 6`
- For memory-consuming processes: `shell: ps aux --sort=-%mem | head -n 6`
- NEVER use `top -bn1` — its output format is inconsistent and hard to parse
- For listing LISTENING ports: `shell: ss -tulnp` (NOT `netstat`)
- For ACTIVE network connections (all states): `shell: ss -tunap` (NOT `ss -tulnp` which only shows listeners)
- For checking if a service is running: `shell: systemctl status <service>` (e.g., `systemctl status sshd`)
- For checking if a command exists: `shell: command -v <name>`
- For reading log files: FIRST check what log files exist (`shell: ls /var/log/ | grep -E 'auth|secure'`), THEN read the correct one
- For auth failure logs: use `shell: grep -E 'Failed password|Invalid user|authentication failure' /var/log/auth.log | tail -n 50` (Debian/Ubuntu) or `/var/log/secure` (RHEL). NEVER invent log file paths.
- NEVER use Docker's `--format` flag with Go templates like `{{.Names}}` in shell commands — Ansible interprets `{{` as Jinja2 and the playbook will crash. Use plain `docker ps` or pipe to `awk` instead.
- For filtering logs by time: use `awk` with `date` comparisons or `journalctl --since '1 hour ago'` if systemd journal is available
- Add `gather_facts: no` to playbooks that only run simple shell commands (speeds up execution)
- Keep playbooks concise but complete (2-8 tasks)
- NEVER use `ignore_errors: yes`; use `failed_when: false` instead (but ONLY on diagnostic tasks)

YAML FORMAT RULES (CRITICAL — follow exactly to avoid syntax errors):
- ALWAYS use expanded YAML format with one key per line and 2-space indentation.
- NEVER use compact inline syntax like `debug: msg='...'` or `shell: cmd='...'`.
- Correct expanded format example:
  ```yaml
  - name: Check ports
    shell: ss -tulnp
    register: ports
    failed_when: false
    changed_when: false
  - name: Show ports
    debug:
      var: ports.stdout_lines
  ```
- When using `debug`, always use the expanded form with `var:` or `msg:` on its own indented line.
- Do NOT add unnecessary `debug` tasks — `shell` and `command` output is automatically captured and returned.
- If a shell command contains colons, quotes, or Jinja2 `{{ }}`, put the entire command on its own line after `shell:` — do NOT inline it with other keys.

FIREWALL / IP-BLOCKING RULES (CRITICAL):
- ALWAYS use `iptables` for firewall operations. `iptables` is available on virtually all Linux systems.
- NEVER use `firewall-cmd`, `ufw`, or `nft` unless the playbook FIRST verifies the tool is installed with `command -v <tool>`.
- For blocking an IP: `shell: iptables -A INPUT -s <ip> -j DROP`
- For checking firewall status: `shell: iptables -L -n -v`
- For unblocking an IP: `shell: iptables -D INPUT -s <ip> -j DROP`
- ALWAYS validate IP addresses before using them. Each octet must be 0-255. If the IP is invalid, use the `fail` module to report the error instead of running iptables.

FILE PATH RULES (CRITICAL):
- NEVER use placeholder paths like `/path/to/file` or `/tmp/example`. Use real, specific paths.
- If the user asks for a file by name only (e.g. "create mahdi.txt"), write it to the current working directory (`./mahdi.txt` or just `mahdi.txt`).
- If writing file content with `shell: echo`, use a real path: `shell: echo "value" > ./filename`.

CRITICAL: When the user asks to retrieve, capture, or write real system data (logs, process lists, file contents, network connections, etc.), NEVER use placeholder text, hardcoded echo strings, or dummy data. Always use the actual system command that retrieves real data (e.g., `grep ... /var/log/auth.log`, `ps aux`, `ss -tulnp`, `cat /path/to/file`).

When writing multi-line content to a file, use the `copy` module with `content:` (NOT `shell: echo`):
```yaml
- copy:
    content: "{{ registered_var.stdout }}"
    dest: /path/to/file
```

If the conversation history shows a previous attempt failed (e.g., service not found, package not installed), adjust the playbook to fix the root cause first.

Respond in this exact format:

VALIDATION_NOTES: <brief notes about the playbook>

```yaml
---
- name: <playbook name>
  hosts: target
  ...
```
"""


_SUMMARY_SYSTEM_PROMPT = """
You are a technical writer translating an Ansible playbook into human-readable operational steps.

Given an Ansible playbook and conversation history, produce a clear, bullet-point summary of what the system is about to do.

Rules:
- Write in the imperative mood (e.g., "Restart the nginx service", "Check disk usage")
- One bullet point per major task — describe the EFFECT, not the Ansible module
- Include estimated target hosts
- Mention any destructive or state-changing actions clearly
- Do NOT mention Ansible module names (no "shell module", "command module", "ansible.builtin.")
- Keep it concise: 3-8 bullet points maximum

Respond in this exact format:

ESTIMATED_DURATION: <e.g. ~30 seconds>

SUMMARY:
• Step 1
• Step 2
• Step 3

DESTRUCTIVE_ACTIONS:
- action 1
- action 2
"""


_ANALYSIS_SYSTEM_PROMPT = """
You are a senior infrastructure engineer analyzing the results of an automated system operation.

Given the Ansible execution output AND the extracted system data (if available), produce a clear natural language explanation of what happened.

CRITICAL OUTCOME RULES:
- If the user asked an INFORMATIONAL question (e.g., "is X installed?", "what ports are open?", "check status of Y") and the playbook successfully discovered the answer — even if the answer is "not found", "not installed", or "command not found" — the OUTCOME is **success**. The system successfully gathered the information the user requested.
- Only use **partial** if a STATE-CHANGING action (restart service, install package, block IP, delete file) failed or was skipped when it should have executed. If the user only asked to check/restart IF installed, and the service wasn't installed so restart was correctly skipped, this is still **success**.
- Only use **failure** if the playbook itself crashed, SSH failed, or a required state-changing action could not complete.

Rules:
- State whether the operation succeeded or failed
- Summarize what changed on the system or what was discovered
- If extracted system data is provided (disk usage, RAM, processes, etc.), use the ACTUAL NUMBERS in your explanation
- If the user asked a specific question (e.g., "how many GBs left", "what processes consume RAM"), ANSWER IT DIRECTLY using the extracted data
- If there were errors, explain them in plain English and suggest next steps
- If the operation was informational, summarize the key findings with specific numbers/facts
- Keep it concise but informative (3-8 sentences)
- Use a professional but approachable tone
- NEVER repeat raw Ansible output or JSON verbatim; translate it into plain English with specific values

Respond in this exact format:

OUTCOME: <success|partial|failure>

EXPLANATION:
<Your natural language explanation with specific numbers...>

KEY_CHANGES:
- change 1
- change 2

RECOMMENDATIONS:
- suggestion 1
- suggestion 2
"""


# ── JSON extraction helper ────────────────────────────────────────────────────


def _extract_json(raw: str) -> Dict[str, Any]:
    """Extract JSON object from LLM response text."""
    raw = raw.strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        raw = raw[start : end + 1]
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


# Regex to find absolute and relative file paths in shell commands
_FILE_PATH_RE = re.compile(
    r'(?:\s|>|>>|<|\'|\")((?:/[^\s\'\";|<>]+)|(?:\./[^\s\'\";|<>]+))'
)
# Also match paths after common file-related keywords
_FILE_KEYWORD_RE = re.compile(
    r'\b(?:cat|tail|head|less|more|grep|awk|sed|find|rm|cp|mv|touch|'
    r'echo|printf|tee|install|source|\.\s+)(?:\s+["\']?)([^\s\'\";|<>]+)',
    re.IGNORECASE,
)


# Paths to ignore when extracting file references (system/ansible artifacts)
_ignored_path_patterns = [
    "data/playbooks",
    "/usr/bin/python",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "ansible.cfg",
    "inventory",
    "/dev/null",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/proc/",
    "/sys/",
]


def _is_ignored_path(path: str) -> bool:
    """Filter out system/ansible artifacts that aren't user-referenced files."""
    lower = path.lower()
    return any(p in lower for p in _ignored_path_patterns)


def _extract_file_paths_from_messages(messages: List[OperatorMessage]) -> List[str]:
    """Scan previous messages for file paths referenced in commands or outputs.

    Prioritizes paths from user messages and playbook commands over result outputs,
    and filters out system/ansible artifact paths.
    """
    user_paths: List[str] = []
    playbook_paths: List[str] = []
    output_paths: List[str] = []
    seen = set()

    def _add(paths_list: List[str], path: str) -> None:
        if path and path not in seen and "/" in path and not path.startswith("http") and not _is_ignored_path(path):
            seen.add(path)
            paths_list.append(path)

    for m in messages:
        # User message content (highest priority)
        if m.content:
            for match in _FILE_PATH_RE.finditer(m.content):
                _add(user_paths, match.group(1).strip('"\'').rstrip(";|"))
            for match in _FILE_KEYWORD_RE.finditer(m.content):
                _add(user_paths, match.group(1).strip('"\'').rstrip(";|"))

        # Playbook YAML (medium priority)
        if m.playbook_yaml:
            for match in _FILE_PATH_RE.finditer(m.playbook_yaml):
                _add(playbook_paths, match.group(1).strip('"\'').rstrip(";|"))
            for match in _FILE_KEYWORD_RE.finditer(m.playbook_yaml):
                _add(playbook_paths, match.group(1).strip('"\'').rstrip(";|"))

        # Result outputs (lowest priority)
        if m.result_json and isinstance(m.result_json, dict):
            output_text = m.result_json.get("output", "") + "\n"
            analysis = m.result_json.get("analysis", {})
            if isinstance(analysis, dict):
                output_text += analysis.get("explanation", "") + "\n"
            for match in _FILE_PATH_RE.finditer(output_text):
                _add(output_paths, match.group(1).strip('"\'').rstrip(";|"))
            for match in _FILE_KEYWORD_RE.finditer(output_text):
                _add(output_paths, match.group(1).strip('"\'').rstrip(";|"))

    combined = user_paths + playbook_paths + output_paths
    return combined[-6:]  # Keep last 6 unique paths


def _is_follow_up_file_request(prompt: str) -> bool:
    """Detect prompts that reference a file without naming it explicitly."""
    p = prompt.lower()
    follow_phrases = [
        "that file", "the file", "this file", "in it", "what is in",
        "display it", "show it", "read it", "contents of it",
        "what does it contain", "what is inside", "inside it",
    ]
    # Must contain a follow-up phrase AND no explicit absolute/relative path
    has_follow_phrase = any(fp in p for fp in follow_phrases)
    has_explicit_path = "/" in prompt or "./" in prompt
    return has_follow_phrase and not has_explicit_path


def _build_conversation_context(messages: List[OperatorMessage]) -> str:
    """
    Build a rich conversation-history string from previous session messages.
    Includes the last 12 messages to stay within token limits.
    Preserves context about what was executed, on which host, and what was discovered.
    """
    if not messages:
        return "No previous conversation."

    lines: List[str] = ["--- PREVIOUS CONVERSATION IN THIS SESSION ---"]
    for m in messages[-12:]:
        if m.role == "user":
            lines.append(f"User asked: {m.content}")
        elif m.role == "reasoning":
            lines.append(f"AI thought: {m.content[:200]}")
        elif m.role == "assistant":
            summary = m.execution_summary or ""
            status = m.status or ""
            playbook = m.playbook_yaml or ""
            result = ""
            if m.result_json and isinstance(m.result_json, dict):
                analysis = m.result_json.get("analysis", {})
                if analysis and isinstance(analysis, dict):
                    result = analysis.get("explanation", "")[:200]
                elif m.result_json.get("output"):
                    result = m.result_json["output"][:200]
            # Extract shell commands from previous playbook for context
            cmds = []
            if playbook:
                for line in playbook.splitlines():
                    if "shell:" in line or "command:" in line:
                        cmd = line.split(":", 1)[1].strip().strip('"').strip("'")
                        cmds.append(cmd)
            cmd_note = f" | Commands: {'; '.join(cmds[:2])}" if cmds else ""
            lines.append(
                f"AI executed ({status}): {summary[:150]}{cmd_note}\n"
                f"  Result: {result}"
            )
    # Append recently-referenced file paths so the LLM knows what "that file" means
    recent_paths = _extract_file_paths_from_messages(messages)
    if recent_paths:
        lines.append("--- RECENTLY REFERENCED FILES ---")
        for i, path in enumerate(recent_paths, 1):
            lines.append(f"  {i}. {path}")
    lines.append("--- END OF PREVIOUS CONVERSATION ---")
    return "\n".join(lines)


# ── LLM orchestration ─────────────────────────────────────────────────────────


async def _reason_about_request(
    prompt: str, target_hosts: List[str], context: str = "", history: str = ""
) -> Dict[str, Any]:
    """Step 1: Analyze intent and create a plan."""
    llm_prompt = (
        f"{_REASONING_SYSTEM_PROMPT}\n\n"
        f"System context:\n{context}\n\n"
        f"{history}\n\n"
        f"User request: {prompt}\n\n"
        f"Target hosts: {target_hosts}\n\n"
        f"Respond with JSON only."
    )
    raw = await _call_llm(llm_prompt)
    parsed = _extract_json(raw)
    execution_mode = parsed.get("execution_mode", "remote")
    if execution_mode not in ("local", "remote", "hybrid"):
        execution_mode = "remote"
    return {
        "intent": parsed.get("intent", "unknown"),
        "target_systems": parsed.get("target_systems", target_hosts),
        "steps": parsed.get("steps", []),
        "risk_level": parsed.get("risk_level", "medium"),
        "execution_mode": execution_mode,
        "reasoning": parsed.get("reasoning", ""),
    }


# Pre-built playbook templates have been removed so the LLM always generates
# playbooks dynamically. This preserves full flexibility — the user can ask for
# arbitrary operations and the AI will produce the appropriate Ansible tasks.


def _match_playbook_template(prompt: str) -> dict | None:
    """
    Legacy stub: pre-built playbook templates have been removed.
    The LLM now generates all playbooks dynamically for full flexibility.
    Returns None so callers fall back to LLM generation.
    """
    return None


def _apply_template_variables(template: dict, prompt: str) -> str:
    """
    Legacy stub: pre-built playbook templates have been removed.
    Returns empty string as a safe fallback.
    """
    return template.get("playbook_yaml", "")


async def _generate_playbook(
    prompt: str, steps: List[str], target_hosts: List[str], context: str = "", history: str = ""
) -> Dict[str, Any]:
    """Step 2: Generate Ansible playbook from the plan."""

    # Always use the LLM so the user can ask for arbitrary operations.
    # Pre-built templates are disabled to preserve full flexibility.

    steps_text = "\n".join(f"- {s}" for s in steps)
    llm_prompt = (
        f"{_PLAYBOOK_SYSTEM_PROMPT}\n\n"
        f"System context:\n{context}\n\n"
        f"{history}\n\n"
        f"User request: {prompt}\n\n"
        f"Planned steps:\n{steps_text}\n\n"
        f"Target hosts: {target_hosts}\n\n"
        f"Respond with the format above."
    )
    raw = await _call_llm(llm_prompt)

    # Extract YAML from markdown code block
    yaml_match = re.search(r"```yaml\n(.*?)\n```", raw, re.DOTALL)
    playbook_yaml = yaml_match.group(1).strip() if yaml_match else ""

    # Extract validation notes
    notes_match = re.search(r"VALIDATION_NOTES:\s*(.+?)(?:\n```|\Z)", raw, re.DOTALL)
    validation_notes = notes_match.group(1).strip() if notes_match else ""

    # Fallback: try JSON extraction if markdown block not found
    if not playbook_yaml:
        parsed = _extract_json(raw)
        playbook_yaml = parsed.get("playbook_yaml", "")
        validation_notes = parsed.get("validation_notes", "")

    # CRITICAL: Strip AI hallucinated annotations that leaked into the YAML block.
    # The LLM sometimes puts VALIDATION_NOTES, NOTES, or markdown headers INSIDE
    # the ```yaml fence instead of before it, breaking YAML parsing.
    annotation_markers = [
        r"^VALIDATION_NOTES:.*$",
        r"^VALIDATION\s+NOTES:.*$",
        r"^NOTES?:.*$",
        r"^NOTE:.*$",
        r"^WARNING:.*$",
        r"^##\s+ROLLBACK.*$",
        r"^##\s+VERIFICATION.*$",
        r"^##\s+STRUCTURED\s+METADATA.*$",
        r"^##\s+REMEDIATION\s+PLAYBOOK.*$",
    ]
    for pattern in annotation_markers:
        parts = re.split(pattern, playbook_yaml, flags=re.MULTILINE | re.IGNORECASE)
        if len(parts) > 1:
            playbook_yaml = parts[0].rstrip()
            logger.warning("operator_playbook_stripped_annotation", pattern=pattern)

    # Post-process: fix frequent LLM YAML mistakes and Docker templates before returning
    playbook_yaml = _fix_common_yaml_errors(playbook_yaml)
    playbook_yaml = _escape_docker_go_templates(playbook_yaml)

    return {
        "playbook_yaml": playbook_yaml,
        "validation_notes": validation_notes,
    }


async def _generate_execution_summary(playbook_yaml: str, history: str = "") -> Dict[str, Any]:
    """Step 3: Convert playbook to human-readable summary."""
    if not playbook_yaml.strip():
        return {
            "summary": "No playbook generated.",
            "destructive_actions": [],
            "estimated_duration": "N/A",
        }
    llm_prompt = (
        f"{_SUMMARY_SYSTEM_PROMPT}\n\n"
        f"{history}\n\n"
        f"Ansible playbook:\n```yaml\n{playbook_yaml}\n```\n\n"
        f"Respond with the format above."
    )
    raw = await _call_llm(llm_prompt)

    # Extract fields using regex
    duration_match = re.search(r"ESTIMATED_DURATION:\s*(.+?)(?:\n\n|\Z)", raw, re.DOTALL)
    summary_match = re.search(r"SUMMARY:\s*(.+?)(?:\n\nDESTRUCTIVE_ACTIONS:|\n\n|\Z)", raw, re.DOTALL)
    destructive_match = re.search(r"DESTRUCTIVE_ACTIONS:\s*(.+?)(?:\n\n|\Z)", raw, re.DOTALL)

    summary = summary_match.group(1).strip() if summary_match else "No summary available."
    destructive = []
    if destructive_match:
        destructive = [line.strip().lstrip("-• ") for line in destructive_match.group(1).strip().splitlines() if line.strip()]
    duration = duration_match.group(1).strip() if duration_match else "Unknown"

    # Fallback to JSON
    if not summary:
        parsed = _extract_json(raw)
        summary = parsed.get("summary", "No summary available.")
        destructive = parsed.get("destructive_actions", [])
        duration = parsed.get("estimated_duration", "Unknown")

    return {
        "summary": summary,
        "destructive_actions": destructive,
        "estimated_duration": duration,
    }


# ── Output parsers ────────────────────────────────────────────────────────────


def _parse_df_output(output: str) -> List[Dict[str, str]]:
    """Parse 'df -h' output into structured disk info."""
    lines = [l for l in output.splitlines() if l.startswith("/dev") or l.startswith("tmpfs") or l.startswith("overlay")]
    results = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 6:
            results.append({
                "filesystem": parts[0],
                "size": parts[1],
                "used": parts[2],
                "available": parts[3],
                "use_percent": parts[4],
                "mounted_on": parts[5],
            })
    return results


def _parse_free_output(output: str) -> Dict[str, str]:
    """Parse 'free -h' output into structured memory info."""
    lines = [l.strip() for l in output.splitlines() if l.strip().startswith("Mem:") or l.strip().startswith("Swap:")]
    result = {}
    for line in lines:
        parts = line.split()
        if len(parts) >= 4:
            key = parts[0].rstrip(":").lower()
            result[key] = {
                "total": parts[1],
                "used": parts[2],
                "free": parts[3],
                "shared": parts[4] if len(parts) > 4 else "",
                "buff_cache": parts[5] if len(parts) > 5 else "",
                "available": parts[6] if len(parts) > 6 else "",
            }
    return result


def _parse_ps_output(output: str) -> List[Dict[str, str]]:
    """Parse 'ps aux', 'ps -eo', or 'top -bn1' output into structured process list."""
    lines = output.splitlines()
    if not lines:
        return []
    # Find header line
    header_idx = -1
    for i, line in enumerate(lines):
        if "PID" in line and ("%CPU" in line or "%MEM" in line or "CPU" in line):
            header_idx = i
            break
    if header_idx == -1:
        return []

    header = lines[header_idx]
    # Detect format: top (has TIME+ or COMMAND at end, cols: PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND)
    is_top = "TIME+" in header or ("PR" in header and "NI" in header and "VIRT" in header)
    is_ps_aux = not is_top and ("VSZ" in header or "RSS" in header or "STAT" in header)

    results = []
    for line in lines[header_idx + 1:]:
        line = line.strip()
        if not line or line.startswith("top -") or line.startswith("Tasks:") or line.startswith("%Cpu") or line.startswith("MiB ") or line.startswith("KiB "):
            continue
        if is_top:
            # top -bn1 format: PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND
            parts = line.split(None, 11)
            if len(parts) >= 12 and parts[0].isdigit():
                results.append({
                    "pid": parts[0],
                    "user": parts[1],
                    "cpu": parts[8],
                    "mem": parts[9],
                    "command": parts[11],
                })
            elif len(parts) >= 10 and parts[0].isdigit():
                # Fallback if command is missing
                results.append({
                    "pid": parts[0],
                    "user": parts[1],
                    "cpu": parts[8],
                    "mem": parts[9],
                    "command": "",
                })
        elif is_ps_aux:
            # ps aux format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
            parts = line.split(None, 10)
            if len(parts) >= 11 and parts[1].isdigit():
                results.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "cpu": parts[2],
                    "mem": parts[3],
                    "command": parts[10],
                })
        else:
            # ps -eo format: PID USER %CPU %MEM CMD
            parts = line.split(None, 4)
            if len(parts) >= 5 and parts[0].isdigit():
                results.append({
                    "pid": parts[0],
                    "user": parts[1],
                    "cpu": parts[2],
                    "mem": parts[3],
                    "command": parts[4],
                })
            elif len(parts) >= 4 and parts[0].isdigit():
                results.append({
                    "pid": parts[0],
                    "user": parts[1],
                    "cpu": parts[2],
                    "mem": parts[3],
                    "command": "",
                })
    return results[:10]


def _parse_systemctl_status(output: str) -> Dict[str, str]:
    """Parse 'systemctl status <service>' output."""
    result = {"active_state": "unknown", "status_text": "", "main_pid": "", "not_found": False}
    lower = output.lower()
    # Detect common "not found" / "does not exist" patterns
    if any(phrase in lower for phrase in (
        "could not be found", "does not exist", "unit ", "service not found",
        "no such file or directory", "failed to get properties",
    )):
        result["not_found"] = True
        result["active_state"] = "not_found"
        # Try to extract a helpful snippet
        for line in output.splitlines():
            if any(p in line.lower() for p in ("could not be found", "does not exist", "unit ")):
                result["status_text"] = line.strip()
                break
        return result
    for line in output.splitlines():
        if "Active:" in line:
            result["active_state"] = line.split("Active:", 1)[1].strip().split()[0].lower()
            result["status_text"] = line.split("Active:", 1)[1].strip()
        if "Main PID:" in line:
            result["main_pid"] = line.split("Main PID:", 1)[1].strip().split()[0]
    return result


def _parse_ss_output(output: str) -> List[Dict[str, str]]:
    """Parse 'ss -tulnp' or 'ss -tunap' output into structured socket info."""
    results = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Netid") or line.startswith("State"):
            continue
        # Format: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        proto = parts[0]
        state = parts[1]
        local_addr_port = parts[4]
        process_field = parts[5] if len(parts) > 5 else ""
        # Extract just the port
        port = ""
        if ":" in local_addr_port:
            port = local_addr_port.rsplit(":", 1)[-1]
        # Extract process name from users:((...)) field
        proc_name = ""
        if "users:" in process_field:
            # Try various ss output formats:
            # users:(("name",pid=123,fd=4))
            # users:((name,pid=123,fd=4))
            # users:((-,pid=123,fd=4))
            # users:(("name"))
            m = re.search(r'users:\(\(["\']?([^"\',)]+)["\']?', process_field)
            if m:
                proc_name = m.group(1).strip()
            if not proc_name or proc_name == "-":
                m = re.search(r'pid=(\d+)', process_field)
                if m:
                    proc_name = f"pid={m.group(1)}"
        results.append({
            "protocol": proto,
            "state": state,
            "local_address": local_addr_port,
            "port": port,
            "process": proc_name or process_field,
        })
    return results


def _parse_iptables_rules(output: str) -> List[Dict[str, str]]:
    """Parse 'iptables -L -n -v' output into structured rule list."""
    results = []
    current_chain = ""
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Chain "):
            current_chain = line.split()[1] if len(line.split()) > 1 else ""
            continue
        if line.startswith("pkts") or line.startswith("target"):
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        # Format: pkts bytes target prot opt in out source destination
        results.append({
            "chain": current_chain,
            "target": parts[2],
            "prot": parts[3],
            "opt": parts[4],
            "source": parts[7],
            "destination": parts[8],
        })
    return results


def _parse_auth_log(output: str) -> List[Dict[str, str]]:
    """Parse auth.log / secure log lines into structured auth failure events."""
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # SSH failed password
        m = re.search(r'Failed password for (invalid user )?(\S+) from (\S+) port (\d+)', line)
        if m:
            results.append({
                "timestamp": line.split()[0] if line[0:4].isdigit() or line[0:4] == "2026" else "",
                "event": "failed_password",
                "user": m.group(2),
                "source_ip": m.group(3),
                "port": m.group(4),
                "raw": line,
            })
            continue
        # Invalid user
        m = re.search(r'Invalid user (\S*) from (\S+) port (\d+)', line)
        if m:
            results.append({
                "timestamp": line.split()[0] if line[0:4].isdigit() or line[0:4] == "2026" else "",
                "event": "invalid_user",
                "user": m.group(1) or "(blank)",
                "source_ip": m.group(2),
                "port": m.group(3),
                "raw": line,
            })
            continue
        # PAM authentication failure
        m = re.search(r'authentication failure.*rhost=(\S+)', line)
        if m:
            user_m = re.search(r'user=(\S+)', line)
            results.append({
                "timestamp": line.split()[0] if line[0:4].isdigit() or line[0:4] == "2026" else "",
                "event": "pam_failure",
                "user": user_m.group(1) if user_m else "unknown",
                "source_ip": m.group(1),
                "port": "",
                "raw": line,
            })
            continue
    return results


def _parse_ansible_json_output(json_text: str) -> Dict[str, Any]:
    """
    Parse Ansible JSON callback output into structured data.
    The JSON callback emits a single JSON object with 'plays', 'stats', etc.
    """
    parsed: Dict[str, Any] = {}
    try:
        data = json.loads(json_text.strip() or "{}")
    except json.JSONDecodeError:
        return parsed

    if not isinstance(data, dict):
        return parsed

    plays = data.get("plays", [])
    if not isinstance(plays, list):
        return parsed

    for play in plays:
        tasks = play.get("tasks", [])
        if not isinstance(tasks, list):
            continue
        for task in tasks:
            task_info = task.get("task", {})
            task_name = task_info.get("name", "")
            hosts = task.get("hosts", {})
            if not isinstance(hosts, dict):
                continue
            for host_name, host_result in hosts.items():
                if not isinstance(host_result, dict):
                    continue

                cmd = ""
                if isinstance(host_result.get("cmd"), str):
                    cmd = host_result["cmd"]
                elif isinstance(host_result.get("cmd"), list):
                    cmd = " ".join(str(c) for c in host_result["cmd"])

                stdout = host_result.get("stdout", "")
                stdout_lines = host_result.get("stdout_lines", [])
                if not stdout and stdout_lines:
                    stdout = "\n".join(str(l) for l in stdout_lines)

                stderr = host_result.get("stderr", "")
                stderr_lines = host_result.get("stderr_lines", [])
                if not stderr and stderr_lines:
                    stderr = "\n".join(str(l) for l in stderr_lines)

                # Use stderr as fallback when stdout is empty (e.g. systemctl not-found)
                effective_output = stdout.strip() if stdout.strip() else stderr.strip()

                # FAILED / UNREACHABLE TASKS: capture error, skip structured parsing
                if host_result.get("unreachable") or host_result.get("failed"):
                    error_msg = effective_output or stderr.strip() or "Task failed (no output)"
                    parsed.setdefault("failed_tasks", [])
                    parsed["failed_tasks"].append({
                        "task": task_name,
                        "host": host_name,
                        "cmd": cmd[:80] if len(cmd) <= 80 else cmd[:77] + "...",
                        "error": error_msg[:500],
                    })
                    continue

                # --- Route to parsers (only for successful tasks) ---

                # iptables state changes (block/unblock IP)
                if "iptables" in cmd and ("-A " in cmd or "-D " in cmd or "-I " in cmd):
                    parsed.setdefault("firewall_changes", [])
                    action = "Blocked" if "-A " in cmd else "Unblocked" if "-D " in cmd else "Modified"
                    ip_match = re.search(r'-s\s+([\d./]+)', cmd)
                    ip = ip_match.group(1) if ip_match else "unknown"
                    target_match = re.search(r'-j\s+(\w+)', cmd)
                    target = target_match.group(1) if target_match else "DROP"
                    out = effective_output or stdout.strip()
                    if out:
                        parsed["firewall_changes"].append(f"{action} IP {ip} (target: {target}) — output: {out[:200]}")
                    else:
                        parsed["firewall_changes"].append(f"{action} IP {ip} (target: {target})")
                    continue

                if not effective_output:
                    continue

                # Disk usage
                if "df -h" in cmd or ("Filesystem" in effective_output and "Size" in effective_output):
                    parsed.setdefault("disk_usage", [])
                    parsed["disk_usage"].extend(_parse_df_output(effective_output))
                    continue

                # Memory usage
                if "free" in cmd and ("Mem:" in effective_output or "Swap:" in effective_output):
                    parsed["memory_usage"] = _parse_free_output(effective_output)
                    continue

                # Top processes
                if "ps aux" in cmd or "ps -eo" in cmd or ("PID" in effective_output and "%CPU" in effective_output):
                    parsed.setdefault("top_processes", [])
                    parsed["top_processes"].extend(_parse_ps_output(effective_output))
                    continue

                # Service status
                if "systemctl status" in cmd:
                    svc_match = re.search(r'systemctl status ([a-zA-Z0-9_-]+)', cmd)
                    if svc_match:
                        parsed["service_status"] = {
                            "service": svc_match.group(1),
                            **_parse_systemctl_status(effective_output),
                        }
                    continue

                # iptables rules
                if "iptables -L" in cmd or ("Chain INPUT" in effective_output and "policy" in effective_output):
                    parsed["iptables_rules"] = _parse_iptables_rules(effective_output)
                    continue

                # Open ports
                if "ss -tulnp" in cmd or "ss -tunap" in cmd or "Netid" in effective_output or ("LISTEN" in effective_output and ("tcp" in effective_output or "udp" in effective_output)):
                    parsed["open_ports"] = _parse_ss_output(effective_output)
                    continue

                # Auth / security logs
                if "auth.log" in cmd or "secure" in cmd or "Failed password" in effective_output or "Invalid user" in effective_output or "authentication failure" in effective_output:
                    parsed["auth_failures"] = _parse_auth_log(effective_output)
                    continue

                # File reads (skip if content looks like an error message)
                if any(cmd.startswith(p) or (" " + p) in cmd for p in ["cat ", "tail ", "head ", "less ", "more "]):
                    # Don't treat shell errors as file contents
                    if effective_output.startswith("tail: cannot open") or effective_output.startswith("cat: ") or effective_output.startswith("head: "):
                        continue
                    parsed["raw_file_content"] = effective_output
                    continue

                # Catch-all: preserve raw output for any unrecognized command
                # so engineers always see what happened
                if effective_output:
                    parsed.setdefault("raw_outputs", [])
                    display_cmd = cmd[:80] if len(cmd) <= 80 else cmd[:77] + "..."
                    parsed["raw_outputs"].append({"cmd": display_cmd, "output": effective_output})

    return parsed


def _build_simple_analysis(exit_code: int, parsed_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    For common diagnostic commands, build a rich natural-language analysis
    directly from parsed data without calling the LLM.
    Supports compound playbooks by combining multiple parsed sections.
    Works even with partial failures (non-zero exit code) so successful tasks
    are still formatted nicely.
    Returns None if no recognized command type is present.
    """
    sections: list[str] = []
    recommendations: list[str] = []
    has_content = False

    # FAILED TASKS — show first so engineer sees what broke
    failed_tasks = parsed_data.get("failed_tasks", [])
    if failed_tasks:
        has_content = True
        lines = [f"❌ **Failed Tasks** ({len(failed_tasks)})\n"]
        for ft in failed_tasks:
            lines.append(f"- **{ft.get('task', 'Unnamed')}** on `{ft.get('host', '?')}`")
            err = ft.get("error", "Unknown error")
            lines.append(f"  ```")
            for ln in err.splitlines()[:5]:
                lines.append(f"  {ln}")
            if len(err.splitlines()) > 5:
                lines.append(f"  ... ({len(err.splitlines()) - 5} more lines)")
            lines.append(f"  ```")
        sections.append("\n".join(lines))

    if exit_code != 0 and not failed_tasks:
        sections.append(f"⚠️ Playbook finished with exit code {exit_code}.\n")

    # Memory usage (free -m)
    mem = parsed_data.get("memory_usage", {})
    if mem and "mem" in mem:
        has_content = True
        m = mem["mem"]
        total = m.get("total", "?")
        used = m.get("used", "?")
        free = m.get("free", "?")
        used_pct = "?"
        try:
            used_pct = f"{round(int(used) / int(total) * 100)}%"
        except Exception:
            pass
        status = "healthy"
        try:
            if int(used) / int(total) > 0.9:
                status = "critical"
            elif int(used) / int(total) > 0.8:
                status = "high"
            elif int(used) / int(total) > 0.7:
                status = "moderate"
        except Exception:
            pass
        lines = [
            "**Memory Status**\n",
            f"- Total: {total}",
            f"- Used: {used} ({used_pct})",
            f"- Free: {free}",
        ]
        if status == "critical":
            lines.append("\n⚠️ Memory usage is critically high.")
            recommendations.append("Consider restarting heavy processes or adding RAM.")
        elif status == "high":
            lines.append("\n⚠️ Memory usage is high.")
            recommendations.append("Consider restarting heavy processes or adding RAM.")
        sections.append("\n".join(lines))

    # Disk usage (df -h)
    disks = parsed_data.get("disk_usage", [])
    if disks:
        has_content = True
        lines = ["**Disk Usage Summary**\n"]
        warnings = []
        for d in disks[:6]:
            mount = d.get("mounted_on", "?")
            pct = d.get("use_percent", "0%").replace("%", "")
            size = d.get("size", "?")
            used = d.get("used", "?")
            lines.append(f"- `{mount}`: {d.get('use_percent', '?')} used ({used} / {size})")
            try:
                if int(pct) >= 90:
                    warnings.append(f"`{mount}` is critically full ({pct}%).")
                elif int(pct) >= 80:
                    warnings.append(f"`{mount}` is nearly full ({pct}%).")
            except Exception:
                pass
        if warnings:
            lines.append("\n**Warnings:**\n" + "\n".join(f"⚠️ {w}" for w in warnings))
            recommendations.append("Clean up logs, old packages, or Docker images to free space.")
        sections.append("\n".join(lines))

    # Top processes (ps / top)
    procs = parsed_data.get("top_processes", [])
    if procs:
        has_content = True
        lines = ["**Top Processes by Resource Usage**\n"]
        for i, p in enumerate(procs[:8], 1):
            cmd = p.get("command", "?")[:50]
            pid = p.get("pid", "?")
            cpu = p.get("cpu", "?")
            mem = p.get("mem", "?")
            user = p.get("user", "?")
            lines.append(f"{i}. `{cmd}` — PID {pid} | CPU {cpu}% | MEM {mem}% | User: {user}")
        sections.append("\n".join(lines))
        recommendations.append("Monitor top consumers if CPU/MEM stay elevated.")

    # Firewall changes (block/unblock IP actions)
    changes = parsed_data.get("firewall_changes", [])
    if changes:
        has_content = True
        lines = ["**Firewall Changes**\n"]
        for c in changes:
            lines.append(f"- {c}")
        sections.append("\n".join(lines))

    # iptables rules
    rules = parsed_data.get("iptables_rules", [])
    if rules:
        has_content = True
        drop_rules = [r for r in rules if r.get("target", "").upper() == "DROP"]
        accept_rules = [r for r in rules if r.get("target", "").upper() == "ACCEPT"]
        lines = ["**Firewall Rules (iptables)**\n"]
        if drop_rules:
            lines.append(f"\n🔒 **DROP rules** ({len(drop_rules)} found):")
            for r in drop_rules[:8]:
                src = r.get("source", "?")
                dst = r.get("destination", "?")
                prot = r.get("prot", "all")
                lines.append(f"  - `{src}` → `{dst}` (prot: {prot})")
        if accept_rules:
            lines.append(f"\n✅ **ACCEPT rules** ({len(accept_rules)} found):")
            for r in accept_rules[:8]:
                src = r.get("source", "?")
                dst = r.get("destination", "?")
                prot = r.get("prot", "all")
                lines.append(f"  - `{src}` → `{dst}` (prot: {prot})")
        sections.append("\n".join(lines))

    # Service status
    svc = parsed_data.get("service_status", {})
    if svc:
        has_content = True
        active = svc.get("active_state", "unknown")
        if svc.get("not_found"):
            sections.append(
                f"❓ Service **{svc.get('service', '?')}** was not found on the target host.\n\n"
                f"The service may not be installed or may use a different name.\n"
                f"{svc.get('status_text', '')}"
            )
            recommendations.append("Verify the service name or install the package.")
        else:
            emoji = "✅" if active == "active" else "❌" if active == "inactive" else "⚠️"
            sections.append(
                f"{emoji} Service **{svc.get('service', '?')}** is `{active}`.\n\n"
                f"{svc.get('status_text', '')}"
            )

    # Open ports (ss -tulnp)
    if "open_ports" in parsed_data:
        has_content = True
        ports = parsed_data["open_ports"]
        lines = ["**Open Ports & Listening Services**\n"]
        tcp_listeners = [p for p in ports if p.get("protocol") in ("tcp", "tcp6")]
        udp_listeners = [p for p in ports if p.get("protocol") in ("udp", "udp6")]
        if tcp_listeners:
            lines.append(f"\n🔌 **TCP** ({len(tcp_listeners)} listeners):")
            for p in tcp_listeners[:12]:
                proc = p.get("process", "unknown")
                port = p.get("port", "?")
                addr = p.get("local_address", "?")
                lines.append(f"  - Port `{port}` on `{addr}` → `{proc}`")
        if udp_listeners:
            lines.append(f"\n📡 **UDP** ({len(udp_listeners)} listeners):")
            for p in udp_listeners[:12]:
                proc = p.get("process", "unknown")
                port = p.get("port", "?")
                addr = p.get("local_address", "?")
                lines.append(f"  - Port `{port}` on `{addr}` → `{proc}`")
        if not tcp_listeners and not udp_listeners:
            lines.append("\nNo listening sockets found.")
        sections.append("\n".join(lines))

    # Auth failures
    auth_failures = parsed_data.get("auth_failures", [])
    if auth_failures:
        has_content = True
        lines = ["**Authentication Failures**\n"]
        # Group by source IP
        by_ip: Dict[str, List[Dict[str, str]]] = {}
        for e in auth_failures:
            ip = e.get("source_ip", "unknown")
            by_ip.setdefault(ip, []).append(e)
        for ip, events in by_ip.items():
            lines.append(f"\n🚨 **{ip}** — {len(events)} attempt(s):")
            for e in events[:10]:
                user = e.get("user", "?")
                event_type = e.get("event", "unknown")
                port = e.get("port", "")
                detail = f"port {port}" if port else ""
                if event_type == "failed_password":
                    lines.append(f"  - ❌ Failed password for `{user}` {detail}")
                elif event_type == "invalid_user":
                    lines.append(f"  - ❌ Invalid user `{user}` {detail}")
                elif event_type == "pam_failure":
                    lines.append(f"  - ❌ PAM auth failure for `{user}` {detail}")
                else:
                    lines.append(f"  - {e.get('raw', '')[:120]}")
            if len(events) > 10:
                lines.append(f"  ... ({len(events) - 10} more)")
        if len(by_ip) > 1:
            lines.append(f"\n**Total:** {len(auth_failures)} failure(s) from {len(by_ip)} source IP(s).")
        recommendations.append("Consider blocking repeat offender IPs with iptables if they are not legitimate.")
        sections.append("\n".join(lines))

    # Raw file contents (cat, tail, head, less, more)
    if "raw_file_content" in parsed_data:
        has_content = True
        content = parsed_data["raw_file_content"]
        lines = ["**File Contents**\n", "```"]
        for line in content.splitlines()[:50]:
            lines.append(line)
        if len(content.splitlines()) > 50:
            lines.append(f"... ({len(content.splitlines()) - 50} more lines)")
        lines.append("```")
        sections.append("\n".join(lines))

    # Generic raw outputs for unrecognized commands
    raw_outputs = parsed_data.get("raw_outputs", [])
    if raw_outputs:
        has_content = True
        for entry in raw_outputs:
            cmd = entry.get("cmd", "?")
            out = entry.get("output", "")
            lines = [f"**Command:** `{cmd}`\n", "```"]
            for line in out.splitlines()[:40]:
                lines.append(line)
            if len(out.splitlines()) > 40:
                lines.append(f"... ({len(out.splitlines()) - 40} more lines)")
            lines.append("```")
            sections.append("\n".join(lines))

    if not has_content:
        return None

    return {
        "outcome": "success",
        "explanation": "\n\n".join(sections),
        "key_changes": [],
        "recommendations": recommendations,
    }


def _build_fallback_analysis(exit_code: int, parsed_data: Dict[str, Any], raw_json_output: str) -> Dict[str, Any]:
    """Build a readable analysis when the LLM is unavailable or output is unrecognized.

    Uses parsed structured data if available, otherwise extracts human-readable
    snippets from the raw Ansible JSON callback output.
    """
    # Try structured fast path first
    if parsed_data:
        simple = _build_simple_analysis(exit_code, parsed_data)
        if simple:
            return simple

    # Extract readable task results from raw JSON
    lines: list[str] = []

    try:
        data = json.loads(raw_json_output.strip() or "{}")
    except json.JSONDecodeError:
        data = {}

    # Show failed tasks first
    failed_lines: list[str] = []
    if isinstance(data, dict):
        for play in data.get("plays", []):
            for task in play.get("tasks", []):
                task_name = task.get("task", {}).get("name", "Unnamed task")
                for host_name, host_result in task.get("hosts", {}).items():
                    if not isinstance(host_result, dict):
                        continue
                    if host_result.get("unreachable") or host_result.get("failed"):
                        stdout = host_result.get("stdout", "")
                        stderr = host_result.get("stderr", "")
                        effective = stdout.strip() if stdout.strip() else stderr.strip()
                        failed_lines.append(f"❌ **{task_name}** failed on `{host_name}`")
                        failed_lines.append("```")
                        for ln in (effective or "No output").splitlines()[:10]:
                            failed_lines.append(ln)
                        if len((effective or "").splitlines()) > 10:
                            failed_lines.append(f"... ({len(effective.splitlines()) - 10} more lines)")
                        failed_lines.append("```\n")

    if failed_lines:
        lines.append(f"❌ **Failed Tasks** ({len(failed_lines) // 3})\n")
        lines.extend(failed_lines)

    if exit_code != 0 and not failed_lines:
        lines.append(f"⚠️ Playbook finished with exit code {exit_code}.\n")
    elif exit_code == 0 and not failed_lines:
        lines.append("✅ Playbook executed successfully.\n")

    # Show successful tasks
    if isinstance(data, dict):
        for play in data.get("plays", []):
            for task in play.get("tasks", []):
                task_name = task.get("task", {}).get("name", "Unnamed task")
                for host_name, host_result in task.get("hosts", {}).items():
                    if not isinstance(host_result, dict):
                        continue
                    if host_result.get("unreachable") or host_result.get("failed"):
                        continue
                    stdout = host_result.get("stdout", "")
                    stdout_lines = host_result.get("stdout_lines", [])
                    if not stdout and stdout_lines:
                        stdout = "\n".join(str(l) for l in stdout_lines)
                    stderr = host_result.get("stderr", "")
                    stderr_lines = host_result.get("stderr_lines", [])
                    if not stderr and stderr_lines:
                        stderr = "\n".join(str(l) for l in stderr_lines)
                    effective = stdout.strip() if stdout.strip() else stderr.strip()
                    if effective:
                        lines.append(f"**{task_name}** (`{host_name}`)")
                        lines.append("```")
                        for ln in effective.splitlines()[:30]:
                            lines.append(ln)
                        if len(effective.splitlines()) > 30:
                            lines.append(f"... ({len(effective.splitlines()) - 30} more lines)")
                        lines.append("```\n")

    if len(lines) <= 1:
        # Nothing useful extracted — show a compact summary
        lines.append("No stdout/stderr captured from tasks.")

    return {
        "outcome": "success" if exit_code == 0 else "failure",
        "explanation": "\n".join(lines),
        "key_changes": [],
        "recommendations": [],
    }


async def _analyze_execution_result(output: str, exit_code: int, parsed_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Step 4: Analyze raw Ansible output and produce natural language explanation."""
    status = "success" if exit_code == 0 else "failure"

    # Fast path: for common diagnostics, skip the LLM entirely
    if parsed_data:
        simple = _build_simple_analysis(exit_code, parsed_data)
        if simple:
            return simple

    # Truncate very long outputs
    truncated = output[:8000] if len(output) > 8000 else output

    parsed_section = ""
    if parsed_data:
        parsed_section = f"Extracted system data:\n```json\n{json.dumps(parsed_data, indent=2, ensure_ascii=False)}\n```\n\n"

    llm_prompt = (
        f"{_ANALYSIS_SYSTEM_PROMPT}\n\n"
        f"Exit code: {exit_code} ({status})\n\n"
        f"{parsed_section}"
        f"Ansible output:\n```\n{truncated}\n```\n\n"
        f"Respond with the format above."
    )
    raw = await _call_llm(llm_prompt)

    # Extract fields using regex
    outcome_match = re.search(r"OUTCOME:\s*(\w+)", raw)
    explanation_match = re.search(r"EXPLANATION:\s*(.+?)(?:\n\nKEY_CHANGES:|\n\n|\Z)", raw, re.DOTALL)
    key_changes_match = re.search(r"KEY_CHANGES:\s*(.+?)(?:\n\nRECOMMENDATIONS:|\n\n|\Z)", raw, re.DOTALL)
    recommendations_match = re.search(r"RECOMMENDATIONS:\s*(.+?)(?:\n\n|\Z)", raw, re.DOTALL)

    outcome = outcome_match.group(1).strip().lower() if outcome_match else status
    explanation = explanation_match.group(1).strip() if explanation_match else f"Execution finished with exit code {exit_code}."
    key_changes = []
    if key_changes_match:
        key_changes = [line.strip().lstrip("-• ") for line in key_changes_match.group(1).strip().splitlines() if line.strip()]
    recommendations = []
    if recommendations_match:
        recommendations = [line.strip().lstrip("-• ") for line in recommendations_match.group(1).strip().splitlines() if line.strip()]

    # Fallback to JSON
    if not explanation:
        parsed = _extract_json(raw)
        outcome = parsed.get("outcome", status)
        explanation = parsed.get("explanation", f"Execution finished with exit code {exit_code}.")
        key_changes = parsed.get("key_changes", [])
        recommendations = parsed.get("recommendations", [])

    # POST-PROCESSING: Override LLM mislabeling
    # If Ansible exit code is 0 and PLAY RECAP shows failed=0, the playbook succeeded.
    # "partial" is often incorrectly chosen by the LLM when diagnostic commands
    # return "not found" — but that IS the correct informational result.
    if exit_code == 0 and outcome == "partial":
        # Check Ansible recap for actual failures
        recap = re.search(r"PLAY RECAP.*?(\n\n|\Z)", output, re.DOTALL)
        if recap:
            recap_text = recap.group(0)
            # If no hosts are marked as failed, this was a full success
            if "failed=0" in recap_text and "unreachable=0" in recap_text:
                outcome = "success"
                # If the explanation mentions "not found" for a diagnostic,
                # soften the language
                if "not found" in explanation.lower() or "not installed" in explanation.lower():
                    explanation = (
                        f"{explanation}\n\n"
                        f"✅ The playbook executed successfully and discovered the requested information. "
                        f"'Not found' is the correct answer to your question."
                    )

    return {
        "outcome": outcome,
        "explanation": explanation,
        "key_changes": key_changes,
        "recommendations": recommendations,
    }


# ── Inventory endpoints ───────────────────────────────────────────────────────


@router.get("/inventory/hosts")
async def list_inventory_hosts():
    """Return all available Ansible inventory hosts for the operator.

    Response clearly distinguishes:
      - inventory missing
      - inventory unreadable
      - inventory malformed
      - inventory empty
      - hosts found
    """
    status = await _get_inventory_status_async()
    logger.info(
        "operator_inventory_check",
        state=status["state"],
        host_count=len(status["hosts"]),
    )
    return {
        "hosts": status["hosts"],
        "count": len(status["hosts"]),
        "state": status["state"],
        "readable": status["readable"],
        "message": status["message"],
        "has_inventory": status["state"] == "ok" and len(status["hosts"]) > 0,
        "valid_for_execution": status["state"] == "ok" and len(status["hosts"]) > 0,
    }


# ── Session endpoints ─────────────────────────────────────────────────────────


async def _validate_asset_for_operator(asset_id: Optional[str]) -> Optional[str]:
    """Validate asset_id for operator. Blocks 'all' and disabled assets."""
    if not asset_id:
        return None
    settings = get_settings()
    if not settings.multi_server_enabled:
        return None
    if asset_id.lower() == "all":
        raise HTTPException(status_code=400, detail="asset_id='all' is not allowed for operator sessions.")
    from response.db import AsyncSessionLocal
    from response.models import MonitoredAsset
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
        )
        asset = result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=400, detail=f"Invalid asset_id: {asset_id}")
        if not asset.enabled:
            raise HTTPException(status_code=400, detail=f"Asset {asset_id} is disabled.")
        if not asset.remediation_enabled:
            raise HTTPException(status_code=400, detail=f"Asset {asset_id} does not have remediation enabled.")
    return asset_id


@router.post("/sessions")
async def create_session(request: CreateSessionRequest):
    """Create a new AI Operator session.

    Strict enforcement: target_hosts must be non-empty and every alias must exist
    in the Ansible inventory. Empty or invalid targets are rejected immediately.
    """
    target_hosts = request.target_hosts or []
    await _validate_asset_for_operator(request.asset_id)
    is_valid, validation_error, valid_targets = await _validate_targets_against_inventory_async(target_hosts)

    if not is_valid:
        logger.warning("operator_create_session_rejected", targets=target_hosts, error=validation_error)
        raise HTTPException(status_code=400, detail=validation_error)

    async with AsyncSessionLocal() as session:
        op_session = OperatorSession(
            title=request.title or "New Session",
            target_hosts=valid_targets,
            asset_id=request.asset_id,
        )
        session.add(op_session)
        await session.commit()
        await session.refresh(op_session)
        return {
            "session_id": op_session.id,
            "title": op_session.title,
            "target_hosts": op_session.target_hosts,
            "asset_id": op_session.asset_id,
            "created_at": op_session.created_at.isoformat(),
        }


@router.get("/sessions")
async def list_sessions(
    limit: int = 50,
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
):
    """List recent operator sessions."""
    from sqlalchemy import select
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    async with AsyncSessionLocal() as session:
        stmt = select(OperatorSession).order_by(OperatorSession.updated_at.desc())
        if asset_id:
            stmt = stmt.where(OperatorSession.asset_id == asset_id)
        result = await session.execute(stmt.limit(limit))
        sessions = result.scalars().all()
        return {
            "sessions": [
                {
                    "id": s.id,
                    "title": s.title,
                    "target_hosts": s.target_hosts,
                    "asset_id": s.asset_id,
                    "created_at": s.created_at.isoformat(),
                    "updated_at": s.updated_at.isoformat(),
                }
                for s in sessions
            ]
        }


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """Get a session with all its messages."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(OperatorSession)
            .where(OperatorSession.id == session_id)
            .options(selectinload(OperatorSession.messages))
        )
        op_session = result.scalar_one_or_none()
        if not op_session:
            raise HTTPException(status_code=404, detail="Session not found")

        return {
            "id": op_session.id,
            "title": op_session.title,
            "target_hosts": op_session.target_hosts,
            "asset_id": op_session.asset_id,
            "created_at": op_session.created_at.isoformat(),
            "updated_at": op_session.updated_at.isoformat(),
            "messages": [
                {
                    "id": m.id,
                    "role": m.role,
                    "content": m.content,
                    "playbook_yaml": m.playbook_yaml,
                    "execution_summary": m.execution_summary,
                    "risk_level": m.risk_level,
                    "run_id": m.run_id,
                    "status": m.status,
                    "result": m.result_json,
                    "metadata": m.metadata_json,
                    "created_at": m.created_at.isoformat(),
                }
                for m in sorted(op_session.messages, key=lambda x: x.created_at)
            ],
        }


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a session and all its messages."""
    from sqlalchemy import select
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(OperatorSession).where(OperatorSession.id == session_id))
        op_session = result.scalar_one_or_none()
        if not op_session:
            raise HTTPException(status_code=404, detail="Session not found")
        await session.delete(op_session)
        await session.commit()
        return {"message": "Session deleted"}


# ── Message / Run endpoints ───────────────────────────────────────────────────


@router.post("/sessions/{session_id}/message")
async def send_message(session_id: str, request: SendMessageRequest):
    """
    Process a user message in a session.

    This triggers the full AI reasoning pipeline:
      1. Intent analysis & planning
      2. Ansible playbook generation
      3. Human-readable execution summary
      4. Persist everything and return for user approval
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(OperatorSession)
            .where(OperatorSession.id == session_id)
            .options(selectinload(OperatorSession.messages))
        )
        op_session = result.scalar_one_or_none()
        if not op_session:
            raise HTTPException(status_code=404, detail="Session not found")

    target_hosts = op_session.target_hosts or []
    asset_id = request.asset_id or op_session.asset_id
    await _validate_asset_for_operator(asset_id)

    prompt = request.prompt

    # ── Strict inventory & target validation ──
    # MUST happen before any LLM call to prevent wasting resources on fake hosts.
    is_valid, validation_error, valid_targets = await _validate_targets_against_inventory_async(target_hosts)
    if not is_valid:
        logger.warning("operator_invalid_targets", session_id=session_id, targets=target_hosts, error=validation_error)
        raise HTTPException(
            status_code=400,
            detail=validation_error,
        )
    # Use only strictly validated targets
    target_hosts = valid_targets

    # Build conversation history from previous messages in this session
    previous_messages = sorted(op_session.messages, key=lambda x: x.created_at)
    conversation_history = _build_conversation_context(previous_messages)

    # Follow-up file reference resolution: if the user says "display what in that file"
    # without naming a path, inject the most recent file path from conversation history.
    if _is_follow_up_file_request(prompt):
        recent_paths = _extract_file_paths_from_messages(previous_messages)
        if recent_paths:
            most_recent = recent_paths[-1]
            prompt = f"{prompt} (file: {most_recent})"

    # Gather system context for richer AI reasoning
    system_context = await _get_system_context(target_hosts, asset_id)

    # Save user message
    async with AsyncSessionLocal() as session:
        user_msg = OperatorMessage(
            session_id=session_id,
            role="user",
            content=prompt,
        )
        session.add(user_msg)
        await session.commit()

    # ── Step 1: Reasoning ──
    logger.info("operator_reasoning_start", session_id=session_id, prompt=prompt, targets=target_hosts)
    try:
        reasoning = await asyncio.wait_for(
            _reason_about_request(prompt, target_hosts, system_context, conversation_history),
            timeout=60,
        )
    except asyncio.TimeoutError:
        logger.error("operator_reasoning_timeout", session_id=session_id)
        raise HTTPException(status_code=504, detail="AI reasoning timed out after 60 seconds. The LLM may be overloaded or unreachable.")
    except Exception as e:
        logger.error("operator_reasoning_failed", session_id=session_id, error=str(e))
        raise HTTPException(status_code=503, detail=f"AI reasoning failed: {str(e)}")

    # Save reasoning message
    async with AsyncSessionLocal() as session:
        reasoning_msg = OperatorMessage(
            session_id=session_id,
            role="reasoning",
            content=reasoning.get("reasoning", ""),
        )
        session.add(reasoning_msg)
        await session.commit()

    execution_mode = reasoning.get("execution_mode", "remote")

    # ── LOCAL QUERY BRANCH ──
    if execution_mode == "local":
        # Skip playbook generation — answer from local data directly
        local_result = await _execute_local_query(prompt, asset_id)
        local_explanation = local_result.get("analysis", {}).get("explanation", "No answer generated.")

        # Persist a completed run (no approval needed for read-only local queries)
        async with AsyncSessionLocal() as session:
            run = OperatorRun(
                prompt=prompt,
                intent=reasoning.get("intent", "unknown"),
                playbook_yaml=None,
                explanation=local_explanation,
                risk_level="low",
                target_hosts=target_hosts,
                asset_id=asset_id,
                status="completed",
                result_json=local_result,
            )
            session.add(run)
            await session.commit()
            await session.refresh(run)

        async with AsyncSessionLocal() as session:
            assistant_msg = OperatorMessage(
                session_id=session_id,
                role="assistant",
                content=reasoning.get("reasoning", ""),
                playbook_yaml=None,
                execution_summary=local_explanation,
                risk_level="low",
                run_id=run.id,
                status="completed",
                result_json=local_result,
            )
            session.add(assistant_msg)
            await session.commit()
            await session.refresh(assistant_msg)

        return {
            "message_id": assistant_msg.id,
            "run_id": run.id,
            "session_id": session_id,
            "status": "completed",
            "intent": reasoning.get("intent", "unknown"),
            "risk_level": "low",
            "reasoning": reasoning.get("reasoning", ""),
            "steps": reasoning.get("steps", []),
            "execution_summary": local_explanation,
            "destructive_actions": [],
            "estimated_duration": "~1 second",
            "playbook_yaml": None,
        }

    # ── REMOTE / HYBRID BRANCH (Ansible playbook) ──
    # For hybrid, we currently execute the remote Ansible part first.
    # Future enhancement: gather remote data, then correlate with local data.

    # ── Step 2: Playbook generation ──
    logger.info("operator_playbook_generation_start", session_id=session_id)
    try:
        playbook_result = await asyncio.wait_for(
            _generate_playbook(
                prompt, reasoning.get("steps", []), target_hosts, system_context, conversation_history
            ),
            timeout=60,
        )
    except asyncio.TimeoutError:
        logger.error("operator_playbook_generation_timeout", session_id=session_id)
        raise HTTPException(status_code=504, detail="Playbook generation timed out after 60 seconds. The LLM may be overloaded or unreachable.")
    except Exception as e:
        logger.error("operator_playbook_generation_failed", session_id=session_id, error=str(e))
        raise HTTPException(status_code=503, detail=f"Playbook generation failed: {str(e)}")

    playbook_yaml = playbook_result.get("playbook_yaml", "")

    # Normalize hosts to 'target' so the playbook matches the dynamic inventory
    if playbook_yaml.strip():
        playbook_yaml = _normalize_playbook_hosts(playbook_yaml)

    # Validate playbook; retry once with feedback if validation fails
    if playbook_yaml.strip():
        is_valid, validation_error = _validate_playbook_yaml(playbook_yaml)
        if not is_valid:
            # Retry with explicit feedback about the error
            retry_history = (
                f"{conversation_history}\n\n"
                f"PREVIOUS ATTEMPT FAILED: {validation_error}\n"
                f"Please regenerate the playbook fixing this error."
            )
            try:
                playbook_result = await asyncio.wait_for(
                    _generate_playbook(
                        prompt, reasoning.get("steps", []), target_hosts, system_context, retry_history
                    ),
                    timeout=60,
                )
                playbook_yaml = playbook_result.get("playbook_yaml", "")
                if playbook_yaml.strip():
                    playbook_yaml = _normalize_playbook_hosts(playbook_yaml)
            except asyncio.TimeoutError:
                logger.warning("operator_playbook_retry_timeout", session_id=session_id)
            except Exception:
                pass  # Keep the original failed playbook

    # ── Step 3: Execution summary ──
    summary_result = {"summary": "", "destructive_actions": [], "estimated_duration": "Unknown"}
    if playbook_yaml.strip():
        steps = reasoning.get("steps", [])
        if len(steps) <= 2:
            # Fast path: simple playbooks don't need an LLM summary
            summary_result = {
                "summary": "\n".join(f"• {step}" for step in steps),
                "destructive_actions": reasoning.get("risk_level", "medium") == "high",
                "estimated_duration": "~15 seconds",
            }
        else:
            try:
                summary_result = await asyncio.wait_for(
                    _generate_execution_summary(playbook_yaml, conversation_history),
                    timeout=30,
                )
            except asyncio.TimeoutError:
                logger.warning("operator_summary_timeout", session_id=session_id)
            except Exception:
                pass  # Non-critical; continue without summary

    # Determine approval requirement — engineer mode: auto-run everything
    risk_level = reasoning.get("risk_level", "medium")
    needs_approval = request.require_approval or not playbook_yaml.strip()

    # Persist run record
    async with AsyncSessionLocal() as session:
        run = OperatorRun(
            prompt=prompt,
            intent=reasoning.get("intent", "unknown"),
            playbook_yaml=playbook_yaml if playbook_yaml else None,
            explanation=summary_result.get("summary", ""),
            risk_level=risk_level,
            target_hosts=target_hosts,
            asset_id=asset_id,
            status="pending" if needs_approval else "running",
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)

    # Save assistant message — store plan metadata in result_json so it is
    # available to the frontend immediately; execution analysis will be merged
    # in later by _execute_and_analyze.
    plan_metadata = {
        "steps": reasoning.get("steps", []),
        "destructive_actions": summary_result.get("destructive_actions", []),
        "estimated_duration": summary_result.get("estimated_duration", "Unknown"),
        "intent": reasoning.get("intent", "unknown"),
    }
    async with AsyncSessionLocal() as session:
        assistant_msg = OperatorMessage(
            session_id=session_id,
            role="assistant",
            content=reasoning.get("reasoning", ""),
            playbook_yaml=playbook_yaml if playbook_yaml else None,
            execution_summary=summary_result.get("summary", ""),
            risk_level=risk_level,
            run_id=run.id,
            status="pending_approval" if needs_approval else "running",
            result_json=plan_metadata,
        )
        session.add(assistant_msg)
        await session.commit()
        await session.refresh(assistant_msg)

    # Auto-execute low risk immediately
    if not needs_approval and playbook_yaml.strip():
        asyncio.create_task(
            _execute_and_analyze(run.id, playbook_yaml, target_hosts, assistant_msg.id, session_id, asset_id)
        )

    return {
        "message_id": assistant_msg.id,
        "run_id": run.id,
        "session_id": session_id,
        "status": "pending_approval" if needs_approval else "running",
        "intent": reasoning.get("intent", "unknown"),
        "risk_level": risk_level,
        "reasoning": reasoning.get("reasoning", ""),
        "steps": reasoning.get("steps", []),
        "execution_summary": summary_result.get("summary", ""),
        "destructive_actions": summary_result.get("destructive_actions", []),
        "estimated_duration": summary_result.get("estimated_duration", "Unknown"),
        "playbook_yaml": playbook_yaml,
    }


@router.post("/runs/{run_id}/approve")
async def approve_run(run_id: str, request: ApproveRunRequest):
    """Approve a pending operator run and trigger execution."""
    from sqlalchemy import select, update

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(OperatorRun).where(OperatorRun.id == run_id))
        run = result.scalar_one_or_none()
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        if run.status not in ("pending",):
            raise HTTPException(status_code=400, detail=f"Run status is '{run.status}', not pending")

        # Update run status
        await session.execute(
            update(OperatorRun)
            .where(OperatorRun.id == run_id)
            .values(status="running", updated_at=datetime.now(timezone.utc))
        )
        await session.commit()

    # Find the associated message and update its status
    async with AsyncSessionLocal() as session:
        from sqlalchemy import select as sa_select
        msg_result = await session.execute(
            sa_select(OperatorMessage).where(OperatorMessage.run_id == run_id)
        )
        msg = msg_result.scalar_one_or_none()
        if msg:
            msg.status = "running"
            await session.commit()

    # Re-validate asset before execution
    if run.asset_id:
        await _validate_asset_for_operator(run.asset_id)

    # Trigger execution in background
    if run.playbook_yaml:
        asyncio.create_task(
            _execute_and_analyze(
                run.id, run.playbook_yaml, run.target_hosts or [],
                msg.id if msg else None, msg.session_id if msg else None,
                run.asset_id
            )
        )

    return {
        "success": True,
        "run_id": run_id,
        "status": "running",
    }


@router.get("/runs/{run_id}/status")
async def get_run_status(run_id: str):
    """Poll execution status and results for a run."""
    from sqlalchemy import select
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(OperatorRun).where(OperatorRun.id == run_id))
        run = result.scalar_one_or_none()
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")

        return {
            "run_id": run.id,
            "status": run.status,
            "intent": run.intent,
            "risk_level": run.risk_level,
            "explanation": run.explanation,
            "result": run.result_json,
            "created_at": run.created_at.isoformat(),
            "updated_at": run.updated_at.isoformat(),
        }


# ── Execution & Analysis ──────────────────────────────────────────────────────


async def _execute_and_analyze(
    run_id: str,
    playbook_yaml: str,
    target_hosts: List[str],
    message_id: Optional[str],
    session_id: Optional[str],
    asset_id: Optional[str] = None,
) -> None:
    """
    Execute the Ansible playbook and then analyze the results with the LLM.
    Updates the run record and message with the natural language explanation.
    Uses a 60-second timeout for operator runs and ensures DB is updated even on crashes.
    """
    from response.ansible_exec import _write_playbook, _write_inventory, _run_ansible, _test_ssh_connection
    from sqlalchemy import select, update
    import asyncio.subprocess

    target_alias = target_hosts[0] if target_hosts else ""
    if not target_alias:
        raise RuntimeError("No target host specified for execution.")

    # Re-validate asset before any dangerous execution
    if asset_id:
        await _validate_asset_for_operator(asset_id)

    # Resolve host config from asset if available
    host_config = None
    if asset_id and settings.multi_server_enabled:
        try:
            async with AsyncSessionLocal() as db_session:
                result = await db_session.execute(
                    select(MonitoredAsset).where(MonitoredAsset.asset_id == asset_id)
                )
                asset = result.scalar_one_or_none()
                if asset and asset.enabled:
                    host_config = asset.ansible_config_json
        except Exception:
            pass

    resolved_host, resolved_user = await _resolve_target_from_inventory_async(target_alias)
    if not resolved_host:
        raise RuntimeError(
            f"Target alias '{target_alias}' could not be resolved from inventory. "
            "The inventory may have changed since the run was created."
        )

    ssh_port = str(getattr(settings, "ansible_ssh_port", 22) or 22)
    logger.info(
        "operator_execution_start",
        run_id=run_id,
        session_id=session_id,
        target_alias=target_alias,
        resolved_host=resolved_host,
        resolved_user=resolved_user,
        ssh_port=ssh_port,
    )

    exit_code = -1
    output = ""
    analysis: Dict[str, Any] = {}
    parsed_data: Dict[str, Any] = {}

    try:
        # Reject empty playbooks immediately
        if not playbook_yaml or not playbook_yaml.strip():
            raise RuntimeError("Playbook is empty — nothing to execute.")

        # Validate playbook YAML before any network operations
        playbook_yaml = _normalize_playbook_hosts(playbook_yaml)
        is_valid, validation_error = _validate_playbook_yaml(playbook_yaml)
        if not is_valid:
            raise RuntimeError(f"Playbook validation failed: {validation_error}")

        # Quick SSH connectivity pre-check (supports both key-based and password auth)
        ssh_ok, ssh_err = await _test_ssh_connection(resolved_host, resolved_user, host_config)
        if not ssh_ok:
            if ssh_err == "timeout":
                raise RuntimeError("SSH pre-check timed out after 15s. Target host may be unreachable or authentication is hanging.")
            raise RuntimeError(f"SSH pre-check failed: {ssh_err}")

        playbook_path = _write_playbook(f"operator_{run_id}", playbook_yaml)
        inventory_path = _write_inventory(f"operator_{run_id}", resolved_host, resolved_user, host_config)

        # Use JSON callback for reliable machine-readable output parsing
        from response.ansible_exec import _run_ansible_json
        exit_code, json_output, stderr_output = await _run_ansible_json(playbook_path, inventory_path, timeout=60, host_config=host_config)
        output = json_output  # Store raw JSON output for persistence and debugging

        # Parse structured data from JSON callback output
        parsed_data = _parse_ansible_json_output(json_output)

        # Analyze results with LLM (only if structured parsing didn't produce output)
        try:
            analysis = await asyncio.wait_for(
                _analyze_execution_result(json_output, exit_code, parsed_data),
                timeout=45,
            )
        except asyncio.TimeoutError:
            logger.warning("operator_analysis_timeout", run_id=run_id)
            analysis = _build_fallback_analysis(exit_code, parsed_data, json_output)
        except Exception:
            analysis = _build_fallback_analysis(exit_code, parsed_data, json_output)
    except Exception as e:
        exit_code = -1
        output = str(e)
        stderr_output = ""
        error_msg = str(e).lower()
        logger.error("operator_execution_failed", run_id=run_id, error=str(e))
        if "playbook validation failed" in error_msg or "yaml" in error_msg:
            recommendations = [
                "The AI-generated playbook had invalid YAML syntax.",
                "Try rephrasing your request, or check the raw playbook for syntax errors.",
            ]
        elif "ssh pre-check failed" in error_msg or "ssh" in error_msg:
            recommendations = [
                "Verify the target host is reachable and SSH credentials are correct.",
                "Check ANSIBLE_REMOTE_USER and ANSIBLE_SSH_PASSWORD in settings.",
            ]
        elif "timed out" in error_msg:
            recommendations = [
                "The connection to the target host timed out.",
                "Verify the host is online and the SSH port is open.",
            ]
        else:
            recommendations = ["Verify the target host is reachable and SSH credentials are correct."]
        analysis = {
            "outcome": "failure",
            "explanation": f"Execution failed: {str(e)}",
            "key_changes": [],
            "recommendations": recommendations,
        }
    finally:
        # GUARANTEED DB UPDATE — even if anything above crashed,
        # the run record and message will never stay stuck as "running"
        status = "completed" if exit_code == 0 else "failed"
        logger.info("operator_execution_finished", run_id=run_id, status=status, exit_code=exit_code)
        execution_result = {
            "exit_code": exit_code,
            "output": output,
            "stderr": stderr_output,
            "parsed_data": parsed_data,
            "analysis": analysis,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            async with AsyncSessionLocal() as session:
                await session.execute(
                    update(OperatorRun)
                    .where(OperatorRun.id == run_id)
                    .values(
                        status=status,
                        result_json=execution_result,
                        updated_at=datetime.now(timezone.utc),
                    )
                )
                await session.commit()
        except Exception as db_err:
            # If DB update itself fails, log but don't crash further
            import logging
            logging.getLogger(__name__).error(f"Failed to update operator run {run_id}: {db_err}")

        try:
            if message_id:
                async with AsyncSessionLocal() as session:
                    from sqlalchemy import select as sa_select
                    msg_res = await session.execute(
                        sa_select(OperatorMessage).where(OperatorMessage.id == message_id)
                    )
                    msg_obj = msg_res.scalar_one_or_none()
                    existing = msg_obj.result_json or {} if msg_obj else {}
                    merged = {**existing, **execution_result}
                    await session.execute(
                        update(OperatorMessage)
                        .where(OperatorMessage.id == message_id)
                        .values(
                            status=status,
                            result_json=merged,
                        )
                    )
                    await session.commit()
        except Exception as db_err:
            import logging
            logging.getLogger(__name__).error(f"Failed to update operator message {message_id}: {db_err}")

    # Broadcast via WebSocket if possible
    try:
        from api.websocket import broadcast_investigation_change
        asyncio.create_task(
            broadcast_investigation_change(
                run_id, "running", status,
                analysis.get("explanation", f"Run {status}")
            )
        )
    except Exception:
        pass


# ── Legacy endpoints (backward compatibility) ─────────────────────────────────


@router.post("/run")
async def run_operator_legacy(request: SendMessageRequest):
    """
    Legacy single-shot operator endpoint.
    Creates an implicit session, runs the pipeline, and returns the result.
    """
    # Create implicit session
    session_resp = await create_session(CreateSessionRequest())
    session_id = session_resp["session_id"]

    # Forward to the new session-based endpoint
    return await send_message(session_id, request)


@router.get("/runs")
async def list_operator_runs(
    limit: int = 50,
    asset_id: Optional[str] = Query(None, description="Filter by monitored asset"),
    user: CurrentUser = Depends(require_auth),
):
    """List recent operator runs."""
    from sqlalchemy import select
    from api.routes._shared import validate_asset_id, enforce_asset_scope
    asset_id = await validate_asset_id(asset_id)
    asset_id = await enforce_asset_scope(user, asset_id)
    async with AsyncSessionLocal() as session:
        stmt = select(OperatorRun).order_by(OperatorRun.created_at.desc())
        if asset_id:
            stmt = stmt.where(OperatorRun.asset_id == asset_id)
        result = await session.execute(stmt.limit(limit))
        runs = result.scalars().all()
        return {
            "runs": [
                {
                    "id": r.id,
                    "prompt": r.prompt,
                    "intent": r.intent,
                    "risk_level": r.risk_level,
                    "status": r.status,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in runs
            ]
        }


@router.get("/runs/{run_id}")
async def get_operator_run(run_id: str):
    """Get operator run details."""
    from sqlalchemy import select
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(OperatorRun).where(OperatorRun.id == run_id))
        run = result.scalar_one_or_none()
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        return {
            "id": run.id,
            "prompt": run.prompt,
            "intent": run.intent,
            "playbook_yaml": run.playbook_yaml,
            "explanation": run.explanation,
            "risk_level": run.risk_level,
            "target_hosts": run.target_hosts,
            "asset_id": run.asset_id,
            "status": run.status,
            "result": run.result_json,
            "created_at": run.created_at.isoformat() if run.created_at else None,
            "updated_at": run.updated_at.isoformat() if run.updated_at else None,
        }
