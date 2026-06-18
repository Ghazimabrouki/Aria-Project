"""
Runtime Security Diagnostic Playbook Generator.

Generates read-only diagnostic playbooks for Falco runtime events.
All tasks are safe — they only collect evidence, never modify the system.
"""

from typing import Dict, Any, List, Optional

import structlog

logger = structlog.get_logger()


def generate_runtime_diagnostic_playbook(
    runtime_context: Dict[str, Any],
    host: str,
    target_user: str = "root",
) -> str:
    """Generate a diagnostic playbook for a runtime security event."""
    category = runtime_context.get("runtime_category", "unknown")
    rule_name = runtime_context.get("rule_name", "Unknown Rule")
    proc_name = runtime_context.get("proc_name", "")
    proc_pid = runtime_context.get("proc_pid", 0)
    proc_cmdline = runtime_context.get("proc_cmdline", "")
    fd_name = runtime_context.get("fd_name")
    user_name = runtime_context.get("user_name", "")
    container_id = runtime_context.get("container_id", "host")
    container_name = runtime_context.get("container_name", "host")

    tasks = []

    # ── Universal evidence collection ──
    tasks.append(_make_task(
        "Runtime — event overview",
        f"echo 'Rule: {rule_name}' && echo 'Host: {host}' && echo 'Category: {category}' && echo 'Time: $(date -Iseconds)'"
    ))

    # ── Category-specific diagnostics ──
    if category == "process_execution":
        tasks.extend(_build_process_diagnostics(proc_name, proc_pid, proc_cmdline))

    elif category == "file_access":
        tasks.extend(_build_file_diagnostics(fd_name, proc_name, proc_pid))

    elif category == "privilege_escalation":
        tasks.extend(_build_privesc_diagnostics(user_name, proc_name, proc_pid))

    elif category == "persistence":
        tasks.extend(_build_persistence_diagnostics(fd_name, proc_name, proc_pid))

    elif category == "service_change":
        tasks.extend(_build_service_diagnostics(proc_cmdline, proc_name))

    elif category == "package_manager":
        tasks.extend(_build_package_diagnostics(proc_name, proc_cmdline))

    elif category == "credential_access":
        tasks.extend(_build_credential_diagnostics(fd_name, proc_name, proc_pid, user_name))

    elif category == "container_runtime":
        tasks.extend(_build_container_diagnostics(container_id, container_name, proc_name))

    elif category == "network_behavior":
        tasks.extend(_build_network_diagnostics(proc_name, proc_pid))

    else:
        # Generic runtime diagnostics for unknown categories
        tasks.extend(_build_generic_runtime_diagnostics(proc_name, proc_pid, user_name))

    # ── Container context (if not host) ──
    if container_id and container_id != "host":
        tasks.extend(_build_container_context_diagnostics(container_id, container_name))

    # ── System-wide context ──
    tasks.extend(_build_system_context_diagnostics())

    # Build YAML
    playbook = _build_playbook_yaml(rule_name, host, target_user, tasks)

    logger.info(
        "runtime_diagnostic_playbook_generated",
        rule=rule_name,
        category=category,
        host=host,
        task_count=len(tasks),
    )

    return playbook


def _make_task(name: str, command: str) -> Dict[str, Any]:
    """Create a safe diagnostic task."""
    return {
        "name": name,
        "ansible.builtin.shell": command,
        "changed_when": False,
        "failed_when": False,
    }


def _build_process_diagnostics(proc_name: str, proc_pid: int, proc_cmdline: str) -> List[Dict[str, Any]]:
    """Diagnostics for process execution events."""
    tasks = []
    pid = proc_pid or "$(pgrep -f '{proc_cmdline[:50]}' | head -1)" if proc_cmdline else ""

    tasks.append(_make_task(
        "Process — current process tree",
        "ps auxf && echo '---' && pstree -p"
    ))

    if proc_pid:
        tasks.append(_make_task(
            f"Process — details for PID {proc_pid}",
            f"cat /proc/{proc_pid}/cmdline 2>/dev/null | tr '\\0' ' ' && echo '' && "
            f"ls -la /proc/{proc_pid}/fd/ 2>/dev/null | head -20 && echo '---' && "
            f"cat /proc/{proc_pid}/status 2>/dev/null | grep -E 'Uid|Gid|Cap' && echo '---' && "
            f"cat /proc/{proc_pid}/maps 2>/dev/null | wc -l && echo 'memory maps count'"
        ))
        tasks.append(_make_task(
            f"Process — open files for PID {proc_pid}",
            f"lsof -p {proc_pid} 2>/dev/null || echo 'lsof not available'"
        ))

    tasks.append(_make_task(
        "Process — recent executions",
        "last -20 2>/dev/null && echo '---' && w"
    ))

    tasks.append(_make_task(
        "Process — audit log for execve",
        "ausearch -ts recent -k execve 2>/dev/null | tail -30 || echo 'auditd not available'"
    ))

    return tasks


def _build_file_diagnostics(fd_name: Optional[str], proc_name: str, proc_pid: int) -> List[Dict[str, Any]]:
    """Diagnostics for file access events."""
    tasks = []

    if fd_name:
        tasks.append(_make_task(
            f"File — details for {fd_name}",
            f"ls -la {fd_name} 2>/dev/null && echo '---' && "
            f"stat {fd_name} 2>/dev/null && echo '---' && "
            f"getfacl {fd_name} 2>/dev/null || echo 'getfacl not available' && echo '---' && "
            f"sha256sum {fd_name} 2>/dev/null || echo 'sha256sum not available'"
        ))

        tasks.append(_make_task(
            f"File — ACL and SELinux context for {fd_name}",
            f"ls -Z {fd_name} 2>/dev/null || echo 'SELinux not available'"
        ))

    tasks.append(_make_task(
        "File — recent file changes",
        "find /etc /usr/bin /usr/sbin /var -type f -mmin -60 2>/dev/null | head -30 || echo 'No recent changes'"
    ))

    if proc_pid:
        tasks.append(_make_task(
            f"File — process working directory for PID {proc_pid}",
            f"readlink /proc/{proc_pid}/cwd 2>/dev/null && echo '---' && "
            f"readlink /proc/{proc_pid}/exe 2>/dev/null"
        ))

    return tasks


def _build_privesc_diagnostics(user_name: str, proc_name: str, proc_pid: int) -> List[Dict[str, Any]]:
    """Diagnostics for privilege escalation events."""
    tasks = []

    tasks.append(_make_task(
        "Privilege — sudo configuration",
        "cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20 && echo '---' && "
        "ls -la /etc/sudoers.d/ 2>/dev/null"
    ))

    if user_name:
        tasks.append(_make_task(
            f"Privilege — user info for {user_name}",
            f"id {user_name} 2>/dev/null && echo '---' && "
            f"getent passwd {user_name} 2>/dev/null && echo '---' && "
            f"sudo -l -U {user_name} 2>/dev/null || echo 'sudo -l failed'"
        ))

    tasks.append(_make_task(
        "Privilege — recent login attempts",
        "lastb -20 2>/dev/null && echo '---' && last -20 2>/dev/null"
    ))

    tasks.append(_make_task(
        "Privilege — SUID binaries",
        "find / -perm -4000 -type f 2>/dev/null | head -20"
    ))

    tasks.append(_make_task(
        "Privilege — capabilities",
        "getcap -r /usr/bin /usr/sbin /bin /sbin 2>/dev/null | head -20 || echo 'getcap not available'"
    ))

    if proc_pid:
        tasks.append(_make_task(
            f"Privilege — process capabilities for PID {proc_pid}",
            f"cat /proc/{proc_pid}/status 2>/dev/null | grep -i cap"
        ))

    return tasks


def _build_persistence_diagnostics(fd_name: Optional[str], proc_name: str, proc_pid: int) -> List[Dict[str, Any]]:
    """Diagnostics for persistence events."""
    tasks = []

    if fd_name:
        tasks.append(_make_task(
            f"Persistence — file details for {fd_name}",
            f"ls -la {fd_name} 2>/dev/null && echo '---' && "
            f"stat {fd_name} 2>/dev/null && echo '---' && "
            f"sha256sum {fd_name} 2>/dev/null || echo 'sha256sum not available'"
        ))

    tasks.append(_make_task(
        "Persistence — systemd units",
        "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -20"
    ))

    tasks.append(_make_task(
        "Persistence — cron jobs",
        "cat /etc/crontab 2>/dev/null && echo '---' && "
        "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null && echo '---' && "
        "crontab -l 2>/dev/null || echo 'no crontab for current user'"
    ))

    tasks.append(_make_task(
        "Persistence — startup files",
        "ls -la /etc/rc.local /etc/profile.d/ ~/.bashrc ~/.bash_profile /etc/bash.bashrc 2>/dev/null"
    ))

    tasks.append(_make_task(
        "Persistence — SSH authorized keys",
        "find /home -name 'authorized_keys' -o -name 'authorized_keys2' 2>/dev/null | xargs -I{} sh -c 'echo \"=== {} ===\" && ls -la {} && cat {}' 2>/dev/null | head -40"
    ))

    return tasks


def _build_service_diagnostics(proc_cmdline: str, proc_name: str) -> List[Dict[str, Any]]:
    """Diagnostics for service change events."""
    tasks = []

    # Extract service name from systemctl command if possible
    service_name = ""
    if proc_cmdline and "systemctl" in proc_cmdline:
        parts = proc_cmdline.split()
        for i, part in enumerate(parts):
            if part in ["start", "stop", "restart", "enable", "disable", "status"] and i + 1 < len(parts):
                service_name = parts[i + 1]
                break

    if service_name:
        tasks.append(_make_task(
            f"Service — status for {service_name}",
            f"systemctl status {service_name} --no-pager 2>/dev/null && echo '---' && "
            f"systemctl cat {service_name} 2>/dev/null | head -40"
        ))

        tasks.append(_make_task(
            f"Service — journal for {service_name}",
            f"journalctl -u {service_name} --since '1 hour ago' --no-pager 2>/dev/null | tail -30 || echo 'journalctl not available'"
        ))

    tasks.append(_make_task(
        "Service — all failed units",
        "systemctl list-units --failed --no-pager --no-legend 2>/dev/null"
    ))

    tasks.append(_make_task(
        "Service — recent systemd activity",
        "journalctl --since '1 hour ago' --no-pager 2>/dev/null | grep -E 'systemd|service' | tail -20 || echo 'journalctl not available'"
    ))

    return tasks


def _build_package_diagnostics(proc_name: str, proc_cmdline: str) -> List[Dict[str, Any]]:
    """Diagnostics for package manager events."""
    tasks = []

    tasks.append(_make_task(
        "Package — recent dpkg activity",
        "tail -30 /var/log/dpkg.log 2>/dev/null || echo 'dpkg.log not available'"
    ))

    tasks.append(_make_task(
        "Package — recent apt history",
        "tail -30 /var/log/apt/history.log 2>/dev/null || echo 'apt history not available'"
    ))

    tasks.append(_make_task(
        "Package — recently installed packages",
        "dpkg -l | grep '^ii' | tail -20 2>/dev/null || echo 'dpkg not available'"
    ))

    tasks.append(_make_task(
        "Package — apt sources",
        "cat /etc/apt/sources.list 2>/dev/null | grep -v '^#' | grep -v '^$' && echo '---' && "
        "ls -la /etc/apt/sources.list.d/ 2>/dev/null"
    ))

    return tasks


def _build_credential_diagnostics(
    fd_name: Optional[str], proc_name: str, proc_pid: int, user_name: str
) -> List[Dict[str, Any]]:
    """Diagnostics for credential access events."""
    tasks = []

    if fd_name:
        tasks.append(_make_task(
            f"Credential — file integrity for {fd_name}",
            f"ls -la {fd_name} 2>/dev/null && echo '---' && "
            f"stat {fd_name} 2>/dev/null && echo '---' && "
            f"sha256sum {fd_name} 2>/dev/null || echo 'sha256sum not available'"
        ))

    tasks.append(_make_task(
        "Credential — password file status",
        "ls -la /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null"
    ))

    tasks.append(_make_task(
        "Credential — recent user changes",
        "lastlog 2>/dev/null | head -20 && echo '---' && "
        "getent passwd | tail -10 2>/dev/null"
    ))

    tasks.append(_make_task(
        "Credential — failed login attempts",
        "lastb -20 2>/dev/null || echo 'lastb not available'"
    ))

    if proc_pid:
        tasks.append(_make_task(
            f"Credential — process details for PID {proc_pid}",
            f"cat /proc/{proc_pid}/cmdline 2>/dev/null | tr '\\0' ' ' && echo '' && "
            f"cat /proc/{proc_pid}/status 2>/dev/null | grep -E 'Uid|Gid'"
        ))

    return tasks


def _build_container_diagnostics(container_id: str, container_name: str, proc_name: str) -> List[Dict[str, Any]]:
    """Diagnostics for container runtime events."""
    tasks = []

    if container_id and container_id != "host":
        tasks.append(_make_task(
            f"Container — inspect {container_id}",
            f"docker inspect {container_id} 2>/dev/null || echo 'docker not available'"
        ))

        tasks.append(_make_task(
            f"Container — logs for {container_id}",
            f"docker logs --tail 30 {container_id} 2>/dev/null || echo 'docker not available'"
        ))

    tasks.append(_make_task(
        "Container — running containers",
        "docker ps --no-trunc 2>/dev/null || echo 'docker not available'"
    ))

    tasks.append(_make_task(
        "Container — container runtime info",
        "crictl ps 2>/dev/null || echo 'crictl not available'"
    ))

    return tasks


def _build_network_diagnostics(proc_name: str, proc_pid: int) -> List[Dict[str, Any]]:
    """Diagnostics for network behavior events."""
    tasks = []

    tasks.append(_make_task(
        "Network — active connections",
        "ss -tunapl 2>/dev/null | head -30 || netstat -tunapl 2>/dev/null | head -30 || echo 'ss/netstat not available'"
    ))

    tasks.append(_make_task(
        "Network — listening ports",
        "ss -tlnp 2>/dev/null | head -20 || echo 'ss not available'"
    ))

    if proc_pid:
        tasks.append(_make_task(
            f"Network — connections for PID {proc_pid}",
            f"ss -tp 2>/dev/null | grep 'pid={proc_pid}' | head -20 || echo 'no connections found'"
        ))

    tasks.append(_make_task(
        "Network — iptables rules",
        "iptables -L -n -v --line-numbers 2>/dev/null | head -40 || echo 'iptables not available'"
    ))

    return tasks


def _build_generic_runtime_diagnostics(proc_name: str, proc_pid: int, user_name: str) -> List[Dict[str, Any]]:
    """Generic diagnostics for unknown runtime categories."""
    tasks = []

    tasks.append(_make_task(
        "Runtime — process overview",
        "ps aux --sort=-%cpu | head -20"
    ))

    if proc_pid:
        tasks.append(_make_task(
            f"Runtime — process details for PID {proc_pid}",
            f"cat /proc/{proc_pid}/cmdline 2>/dev/null | tr '\\0' ' ' && echo '' && "
            f"cat /proc/{proc_pid}/status 2>/dev/null | head -20"
        ))

    tasks.append(_make_task(
        "Runtime — logged-in users",
        "w && echo '---' && who"
    ))

    tasks.append(_make_task(
        "Runtime — recent system events",
        "dmesg | tail -20 2>/dev/null || echo 'dmesg not available'"
    ))

    return tasks


def _build_container_context_diagnostics(container_id: str, container_name: str) -> List[Dict[str, Any]]:
    """Container-specific context diagnostics."""
    tasks = []

    tasks.append(_make_task(
        f"Container — cgroups for {container_id}",
        f"cat /proc/self/cgroup 2>/dev/null && echo '---' && "
        f"ls -la /sys/fs/cgroup/ 2>/dev/null | head -10"
    ))

    tasks.append(_make_task(
        "Container — namespace info",
        "ls -la /proc/self/ns/ 2>/dev/null || echo 'namespace info not available'"
    ))

    return tasks


def _build_system_context_diagnostics() -> List[Dict[str, Any]]:
    """System-wide context diagnostics (always included)."""
    return [
        _make_task(
            "System — uptime and load",
            "uptime && uname -a"
        ),
        _make_task(
            "System — failed systemd units",
            "systemctl list-units --failed --no-pager --no-legend 2>/dev/null || true"
        ),
        _make_task(
            "System — recent errors",
            "journalctl -p err --since '10 minutes ago' --no-pager 2>/dev/null | tail -20 || dmesg | tail -20"
        ),
    ]


def _build_playbook_yaml(rule_name: str, host: str, target_user: str, tasks: List[Dict[str, Any]]) -> str:
    """Build the final playbook YAML string."""
    import yaml

    playbook = [{
        "name": f"Runtime Diagnostic — {rule_name} on {host}",
        "hosts": host,
        "become": True,
        "gather_facts": False,
        "vars": {
            "rule_name": rule_name,
            "diagnostic_type": "runtime_security",
        },
        "tasks": tasks,
    }]

    return yaml.dump(playbook, default_flow_style=False, sort_keys=False, allow_unicode=True)
