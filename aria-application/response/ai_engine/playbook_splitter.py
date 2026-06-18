"""
Playbook Phase Splitter.

Splits an AI-generated monolithic Ansible playbook into phase-specific
playbooks for staged remediation execution.

Phases:
  1. containment  — block IPs, isolate systems, kill processes
  2. hardening    — configure services, update rules, restrict access
  3. forensics    — collect evidence, audit logs, capture state
  4. verification — confirm fixes, check health, validate state
"""

import re

import structlog
import yaml

logger = structlog.get_logger()

# Keywords that map tasks to phases (checked against task names in lower case)
_PHASE_KEYWORDS = {
    "containment": [
        "block", "drop", "isolate", "quarantine", "disable", "stop", "kill",
        "deny", "reject", "remove", "delete", "flush", "clear", "terminate",
        "shutdown", "prevent", "restrict", "ban", "blacklist",
    ],
    "hardening": [
        "harden", "configure", "update", "patch", "limit", "restrict",
        "enable", "set", "modify", "tune", "secure", "lock", "enforce",
        "install", "upgrade", "renew", "rotate", "change", "reset",
    ],
    "forensics": [
        "collect", "audit", "grep", "save", "capture", "snapshot",
        "archive", "copy", "backup", "dump", "extract", "gather",
        "record", "document", "list", "show", "display", "find",
        "scan", "inspect", "review", "examine",
    ],
    "verification": [
        "verify", "check", "confirm", "test", "validate", "ensure",
        "assert", "poll", "wait", "monitor", "watch", "inspect",
        "health", "status", "ping", "connect",
    ],
}


def split_playbook_into_phases(playbook_yaml: str) -> dict[str, str]:
    """
    Split a monolithic Ansible playbook into 4 phase playbooks.

    Returns dict with keys: containment, hardening, forensics, verification.
    Each value is a valid Ansible playbook YAML string.
    """
    if not playbook_yaml or not playbook_yaml.strip():
        return {
            "containment": _noop_playbook("containment"),
            "hardening": _noop_playbook("hardening"),
            "forensics": _noop_playbook("forensics"),
            "verification": _noop_playbook("verification"),
        }

    try:
        parsed = yaml.safe_load(playbook_yaml)
        if not isinstance(parsed, list):
            logger.warning("playbook_splitter_not_list")
            return _fallback_split(playbook_yaml)
    except yaml.YAMLError as e:
        logger.warning("playbook_splitter_yaml_error", error=str(e))
        return _fallback_split(playbook_yaml)

    phases = {
        "containment": [],
        "hardening": [],
        "forensics": [],
        "verification": [],
        "unknown": [],
    }

    for play in parsed:
        if not isinstance(play, dict):
            continue

        tasks = play.get("tasks", [])
        if not tasks:
            # A play without tasks might be a meta-play; keep it with unknown
            phases["unknown"].append(play)
            continue

        for task in tasks:
            phase = _classify_task(task)
            phases[phase].append((play, task))

    # Build phase playbooks
    result = {}
    for phase in ("containment", "hardening", "forensics", "verification"):
        phase_plays = _rebuild_plays(phases[phase], phase)
        if phase_plays:
            result[phase] = yaml.safe_dump(phase_plays, sort_keys=False, default_flow_style=False)
        else:
            result[phase] = ""

    # Distribute unknown tasks into phases that need more content,
    # or keep them if all phases are well-populated
    unknown_tasks = phases["unknown"]
    if unknown_tasks:
        result = _distribute_unknown_plays(result, unknown_tasks, playbook_yaml)

    # If a phase is empty, add a no-op placeholder so ansible-playbook doesn't fail
    for phase in ("containment", "hardening", "forensics", "verification"):
        if not result.get(phase, "").strip():
            result[phase] = _noop_playbook(phase)

    return result


def _classify_task(task: dict) -> str:
    """Classify a single task into a phase based on its name and module."""
    if not isinstance(task, dict):
        return "unknown"

    # Task name is the primary signal
    task_name = ""
    for key in task:
        if key in ("name", "vars", "when", "ignore_errors", "failed_when",
                   "changed_when", "register", "loop", "with_items", "tags",
                   "become", "delegate_to"):
            continue
        task_name = task.get("name", "")
        break

    name_lower = (task_name or "").lower()

    # Check phase keywords in order of specificity
    # Special cases that override general keyword matching
    if "fail2ban" in name_lower:
        return "hardening"

    for phase, keywords in _PHASE_KEYWORDS.items():
        for kw in keywords:
            if kw in name_lower:
                return phase

    # Module-based fallback
    module = _get_task_module(task)
    if module in ("ansible.builtin.iptables", "ansible.builtin.firewalld",
                  "ansible.builtin.service", "ansible.builtin.systemd"):
        # Check if it's a stopping/disabling action
        for key in task:
            if key in ("name", "vars", "when"):
                continue
            mod_dict = task.get(key, {})
            if isinstance(mod_dict, dict):
                state = mod_dict.get("state", "")
                if state in ("stopped", "absent", "disabled"):
                    return "containment"
                elif state in ("started", "present", "enabled"):
                    return "hardening"

    return "unknown"


def _get_task_module(task: dict) -> str:
    """Extract the module name from a task dict."""
    for key in task:
        if key not in ("name", "vars", "when", "ignore_errors", "failed_when",
                       "changed_when", "register", "loop", "with_items", "tags",
                       "become", "delegate_to"):
            return key
    return ""


def _rebuild_plays(tasks_with_plays: list, phase: str) -> list:
    """Rebuild play structures from classified tasks."""
    if not tasks_with_plays:
        return []

    # Group tasks by their original play structure
    plays_map: dict[int, dict] = {}
    for play, task in tasks_with_plays:
        play_id = id(play)
        if play_id not in plays_map:
            # Clone the play without tasks
            new_play = {k: v for k, v in play.items() if k != "tasks"}
            new_play["tasks"] = []
            plays_map[play_id] = new_play
        plays_map[play_id]["tasks"].append(task)

    return list(plays_map.values())


def _distribute_unknown_plays(
    result: dict[str, str],
    unknown_plays: list,
    original_yaml: str,
) -> dict[str, str]:
    """Distribute unknown plays into phases that have the least content."""
    # Count tasks per phase
    phase_counts = {}
    for phase in ("containment", "hardening", "forensics", "verification"):
        yaml_text = result.get(phase, "")
        if not yaml_text.strip() or yaml_text.strip() == _noop_playbook(phase).strip():
            phase_counts[phase] = 0
        else:
            try:
                parsed = yaml.safe_load(yaml_text)
                count = sum(len(p.get("tasks", [])) for p in parsed if isinstance(p, dict))
                phase_counts[phase] = count
            except yaml.YAMLError:
                phase_counts[phase] = 0

    # Distribute unknown plays to the phase with fewest tasks
    for play in unknown_plays:
        if isinstance(play, tuple):
            # It's a (play, task) from classification
            play_struct, task = play
            play_id = id(play_struct)
        else:
            # It's a standalone play
            play_struct = play
            play_id = id(play_struct)

        min_phase = min(phase_counts, key=phase_counts.get)
        phase_counts[min_phase] += 1

        # Append to the phase's YAML
        phase_yaml = result.get(min_phase, "")
        if phase_yaml.strip() == _noop_playbook(min_phase).strip():
            phase_yaml = ""

        try:
            if phase_yaml.strip():
                phase_parsed = yaml.safe_load(phase_yaml)
            else:
                phase_parsed = []

            if isinstance(play, tuple):
                # Find or create the play
                found = False
                for p in phase_parsed:
                    if isinstance(p, dict) and p.get("hosts") == play_struct.get("hosts"):
                        p.setdefault("tasks", []).append(task)
                        found = True
                        break
                if not found:
                    new_play = {k: v for k, v in play_struct.items() if k != "tasks"}
                    new_play["tasks"] = [task]
                    phase_parsed.append(new_play)
            else:
                phase_parsed.append(play)

            result[min_phase] = yaml.safe_dump(phase_parsed, sort_keys=False, default_flow_style=False)
        except yaml.YAMLError:
            logger.warning("playbook_splitter_distribute_failed", phase=min_phase)

    return result


def _fallback_split(playbook_yaml: str) -> dict[str, str]:
    """Fallback: split by task count when YAML parsing fails."""
    # Try to extract task blocks by regex
    task_blocks = re.findall(r'^\s+- name:.*?\n(?=\s+- name:|\Z)', playbook_yaml, re.MULTILINE | re.DOTALL)
    if not task_blocks:
        # Can't split — return full playbook in containment, empty others
        return {
            "containment": playbook_yaml,
            "hardening": _noop_playbook("hardening"),
            "forensics": _noop_playbook("forensics"),
            "verification": _noop_playbook("verification"),
        }

    total = len(task_blocks)
    chunk_size = max(1, total // 4)

    def _extract_header(yaml_text: str) -> str:
        """Extract play header (hosts, become, gather_facts, vars)."""
        lines = yaml_text.split('\n')
        header_lines = []
        in_tasks = False
        for line in lines:
            if line.strip().startswith('tasks:'):
                in_tasks = True
                break
            header_lines.append(line)
        return '\n'.join(header_lines)

    header = _extract_header(playbook_yaml)
    if not header.strip():
        header = "---\n- name: Staged remediation phase\n  hosts: target\n  become: yes\n  gather_facts: no\n"

    phases = {}
    for i, phase in enumerate(("containment", "hardening", "forensics", "verification")):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i < 3 else total
        chunk = task_blocks[start:end]
        if chunk:
            phases[phase] = header + "  tasks:\n" + ''.join(chunk)
        else:
            phases[phase] = _noop_playbook(phase)

    return phases


def _noop_playbook(phase: str) -> str:
    """Generate a no-op playbook for an empty phase so ansible-playbook doesn't fail."""
    return f"""---
- name: "Phase {phase.title()} - no tasks"
  hosts: target
  gather_facts: no
  tasks:
    - name: "No {phase} tasks required"
      ansible.builtin.debug:
        msg: "Phase {phase} has no tasks for this incident"
"""


def generate_rollback_playbook(containment_yaml: str) -> str:
    """
    Generate a rollback playbook from a containment phase playbook.

    Only generates rollback for well-understood, reversible tasks:
    - iptables DROP → iptables DELETE
    - service stopped → service started
    - file absent → restore not supported (warn)
    """
    if not containment_yaml or not containment_yaml.strip():
        return ""

    try:
        parsed = yaml.safe_load(containment_yaml)
        if not isinstance(parsed, list):
            return ""
    except yaml.YAMLError:
        return ""

    rollback_tasks = []

    for play in parsed:
        if not isinstance(play, dict):
            continue
        for task in play.get("tasks", []):
            if not isinstance(task, dict):
                continue

            rollback_task = _invert_task(task)
            if rollback_task:
                rollback_tasks.append(rollback_task)

    if not rollback_tasks:
        return ""

    rollback_play = {
        "name": "Rollback - Reverse containment actions",
        "hosts": play.get("hosts", "target"),
        "become": play.get("become", True),
        "gather_facts": play.get("gather_facts", False),
        "tasks": rollback_tasks,
    }

    return yaml.safe_dump([rollback_play], sort_keys=False, default_flow_style=False)


def _invert_task(task: dict) -> dict | None:
    """Invert a single containment task for rollback. Returns None if not reversible."""
    if not isinstance(task, dict):
        return None

    task_name = task.get("name", "")
    name_lower = task_name.lower()

    # Find the module key
    module = None
    module_dict = None
    for key in task:
        if key not in ("name", "vars", "when", "ignore_errors", "failed_when",
                       "changed_when", "register", "loop", "with_items", "tags",
                       "become", "delegate_to"):
            module = key
            module_dict = task[key]
            break

    rollback_name = f"Rollback: {task_name}" if task_name else "Rollback task"
    rollback = {"name": rollback_name, "ignore_errors": True}

    # Handle string-valued modules (shell, command)
    if isinstance(module_dict, str):
        # shell/command that blocks IPs → unblock them
        if module in ("ansible.builtin.shell", "ansible.builtin.command", "shell", "command"):
            cmd_str = str(module_dict)
            if "iptables" in cmd_str and ("-A " in cmd_str or "-I " in cmd_str):
                rollback_cmd = cmd_str.replace("-A ", "-D ").replace("-I ", "-D ")
                if module.startswith("ansible.builtin."):
                    rollback[module] = rollback_cmd
                else:
                    rollback[f"ansible.builtin.{module}"] = rollback_cmd
                return rollback
        logger.debug("rollback_string_module_not_reversible", task_name=task_name, module=module)
        return None

    if not module or not isinstance(module_dict, dict):
        return None

    # iptables DROP → iptables DELETE
    if module in ("ansible.builtin.iptables", "iptables"):
        if module_dict.get("jump") == "DROP":
            rollback_module = dict(module_dict)
            rollback_module["state"] = "absent"
            # Keep jump for absent state so iptables module can match the exact rule
            rollback[module] = rollback_module
            return rollback

    # service stopped → service started
    if module in ("ansible.builtin.service", "service"):
        state = module_dict.get("state", "")
        if state == "stopped":
            rollback_module = dict(module_dict)
            rollback_module["state"] = "started"
            rollback[module] = rollback_module
            return rollback
        if state == "disabled":
            rollback_module = dict(module_dict)
            rollback_module["state"] = "enabled"
            rollback[module] = rollback_module
            return rollback

    # systemd stopped → systemd started
    if module in ("ansible.builtin.systemd", "systemd"):
        state = module_dict.get("state", "")
        if state == "stopped":
            rollback_module = dict(module_dict)
            rollback_module["state"] = "started"
            rollback[module] = rollback_module
            return rollback
        if state == "disabled":
            rollback_module = dict(module_dict)
            rollback_module["state"] = "enabled"
            rollback[module] = rollback_module
            return rollback

    # firewalld rich rule → absent
    if module in ("ansible.builtin.firewalld", "firewalld"):
        rollback_module = dict(module_dict)
        rollback_module["state"] = "absent"
        rollback[module] = rollback_module
        return rollback

    # shell/command dict with cmd key that blocks IPs → unblock them
    if module in ("ansible.builtin.shell", "ansible.builtin.command", "shell", "command"):
        cmd_str = str(module_dict.get("cmd", ""))
        if "iptables" in cmd_str and ("-A " in cmd_str or "-I " in cmd_str):
            rollback_cmd = cmd_str.replace("-A ", "-D ").replace("-I ", "-D ")
            rollback[module] = {"cmd": rollback_cmd}
            return rollback

    logger.debug("rollback_task_not_reversible", task_name=task_name, module=module)
    return None
