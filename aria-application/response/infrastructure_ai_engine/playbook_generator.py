"""
Pure diagnostic Ansible playbook generator for infrastructure investigations.

Ansible is used ONLY for data collection — like an expert SRE SSHing into
a server to gather evidence. No remediation, no mitigation, no changes.

Rules:
- Read-only diagnostics only
- No destructive commands (no rm, kill, iptables, systemctl restart, etc.)
- changed_when: false for all tasks
- failed_when: false for all tasks
"""

from typing import Dict, Any, List

import structlog
import yaml

logger = structlog.get_logger()


# Dangerous patterns that must NEVER appear in diagnostic playbooks
FORBIDDEN_PATTERNS = [
    "rm -rf",
    "rm -f",
    "kill -9",
    "killall",
    "pkill -9",
    "pkill",
    "iptables",
    "ufw",
    "nftables",
    "systemctl restart",
    "systemctl stop",
    "systemctl start",
    "systemctl reload",
    # Note: "service " removed — diagnostic playbooks use `service xxx status` which is read-only
    "ip link set",
    "ifconfig.*down",
    "mkfs.",
    "fdisk",
    "parted",
    "dd if=",
    ":(){ :|:& };:",  # fork bomb
    "echo .* > /proc",
    "echo .* > /sys",
    "sysctl -w",
]


def _is_safe_command(cmd: str) -> bool:
    """Check if a shell/command string contains forbidden patterns."""
    cmd_lower = cmd.lower()
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.lower() in cmd_lower:
            return False
    return True


def _build_diagnostic_tasks(
    resource_type: str,
    affected_service: str,
) -> List[Dict[str, Any]]:
    """Build comprehensive diagnostic tasks that gather evidence."""
    tasks = []

    # ── FAST SNAPSHOT FIRST: capture process list before spike subsides ──
    if resource_type == "cpu":
        tasks.append({
            "name": "CPU — top processes by CPU usage",
            "ansible.builtin.shell": "ps -eo pid,pcpu,pmem,comm --no-headers | sort -k2 -rn | head -15",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "CPU — process tree with CPU times",
            "ansible.builtin.shell": "ps -eo pid,ppid,pcpu,time,comm --no-headers | sort -k3 -rn | head -15",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "CPU — pidstat snapshot",
            "ansible.builtin.shell": "pidstat 1 2 2>/dev/null || echo 'pidstat not available'",
            "changed_when": False,
            "failed_when": False,
        })

    elif resource_type == "memory":
        tasks.append({
            "name": "Memory — top processes by RSS",
            "ansible.builtin.shell": "ps -eo pid,pmem,rss,vsz,comm --no-headers | sort -k3 -rn | head -15",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Memory — top processes by %MEM",
            "ansible.builtin.shell": "ps -eo pid,pmem,rss,vsz,comm --no-headers | sort -k2 -rn | head -15",
            "changed_when": False,
            "failed_when": False,
        })

    # ── Universal system overview ──
    tasks.append({
        "name": "System overview — uptime and load",
        "ansible.builtin.shell": "uptime && uname -a",
        "changed_when": False,
        "failed_when": False,
    })
    tasks.append({
        "name": "Logged-in users and recent activity",
        "ansible.builtin.shell": "w && last -5",
        "changed_when": False,
        "failed_when": False,
    })
    tasks.append({
        "name": "Failed systemd units",
        "ansible.builtin.shell": "systemctl list-units --failed --no-pager --no-legend 2>/dev/null || true",
        "changed_when": False,
        "failed_when": False,
    })
    tasks.append({
        "name": "Recent error logs",
        "ansible.builtin.shell": "journalctl -p err --since '10 minutes ago' --no-pager 2>/dev/null | tail -20 || dmesg | tail -20",
        "changed_when": False,
        "failed_when": False,
    })

    # ── Resource-specific deep diagnostics ──
    if resource_type == "cpu":
        tasks.append({
            "name": "CPU — vmstat snapshot",
            "ansible.builtin.shell": "vmstat 1 3",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "CPU — I/O wait and block stats",
            "ansible.builtin.shell": "iostat -x 1 2 2>/dev/null || echo 'iostat not available'",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "CPU — interrupt and context switch stats",
            "ansible.builtin.shell": "cat /proc/interrupts | head -5 && cat /proc/stat | grep 'ctxt\\|intr' | head -3",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "CPU — kernel messages",
            "ansible.builtin.shell": "dmesg | tail -20",
            "changed_when": False,
            "failed_when": False,
        })

    elif resource_type == "memory":
        tasks.append({
            "name": "Memory — detailed usage",
            "ansible.builtin.shell": "free -m && free -h",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Memory — /proc/meminfo",
            "ansible.builtin.shell": "cat /proc/meminfo | head -15",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Memory — slab and cache details",
            "ansible.builtin.shell": "slabtop -o -s c 2>/dev/null | head -15 || echo 'slabtop not available'",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Memory — OOM killer history",
            "ansible.builtin.shell": "dmesg | grep -i 'out of memory\\|oom-killer\\|killed process' | tail -10 || echo 'No OOM events found'",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Memory — vmstat memory stats",
            "ansible.builtin.shell": "vmstat -s | head -20",
            "changed_when": False,
            "failed_when": False,
        })

    elif resource_type == "disk":
        tasks.append({
            "name": "Disk — filesystem usage",
            "ansible.builtin.shell": "df -h && df -i",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Disk — top directories by size",
            "ansible.builtin.shell": "du -sh /var/log /tmp /var/cache /home 2>/dev/null | sort -rh | head -10",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Disk — large files",
            "ansible.builtin.shell": "find /var/log /tmp -type f -size +50M 2>/dev/null | head -10 || echo 'No large files found'",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Disk — I/O stats",
            "ansible.builtin.shell": "iostat -x 1 2 2>/dev/null || echo 'iostat not available'",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Disk — block device info",
            "ansible.builtin.shell": "lsblk && cat /proc/diskstats | awk '{print $3, $6, $10}' | head -10",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Disk — open file descriptors",
            "ansible.builtin.shell": "lsof 2>/dev/null | wc -l || echo 'lsof not available'",
            "changed_when": False,
            "failed_when": False,
        })

    elif resource_type == "network":
        tasks.append({
            "name": "Network — connections and listeners",
            "ansible.builtin.shell": "ss -tunapl 2>/dev/null | head -20 || netstat -tunapl 2>/dev/null | head -20",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Network — interface statistics",
            "ansible.builtin.shell": "ip -s link 2>/dev/null | head -30 || ifconfig 2>/dev/null | head -30",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Network — protocol statistics",
            "ansible.builtin.shell": "netstat -s 2>/dev/null | head -30 || nstat 2>/dev/null | head -20 || echo 'netstat/nstat not available'",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Network — routing table",
            "ansible.builtin.shell": "ip route 2>/dev/null || route -n 2>/dev/null || echo 'route not available'",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Network — connection tracking",
            "ansible.builtin.shell": "conntrack -L 2>/dev/null | wc -l || cat /proc/net/nf_conntrack_count 2>/dev/null || echo 'conntrack not available'",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": "Network — ARP table",
            "ansible.builtin.shell": "ip neigh 2>/dev/null | head -10 || arp -n 2>/dev/null | head -10",
            "changed_when": False,
            "failed_when": False,
        })

    # ── Service-specific diagnostics (if known) ──
    if affected_service and affected_service != "unknown":
        tasks.append({
            "name": f"Service — {affected_service} status",
            "ansible.builtin.shell": f"systemctl status {affected_service} --no-pager 2>/dev/null || service {affected_service} status 2>/dev/null || echo 'Service status unavailable'",
            "changed_when": False,
            "failed_when": False,
        })
        tasks.append({
            "name": f"Service — {affected_service} recent logs",
            "ansible.builtin.shell": f"journalctl -u {affected_service} --since '10 minutes ago' --no-pager 2>/dev/null | tail -20 || echo 'No service logs available'",
            "changed_when": False,
            "failed_when": False,
        })

    return tasks


def generate_safe_playbook(
    resource_type: str,
    affected_service: str,
    mitigation_action: str = "investigate",
    host: str = "target",
) -> str:
    """
    Generate a pure diagnostic Ansible playbook for infrastructure investigation.

    This playbook collects evidence only — no remediation, no changes.
    """
    tasks = _build_diagnostic_tasks(resource_type, affected_service)

    playbook = [{
        "name": f"Infrastructure Diagnostic — {resource_type.upper()} on {host}",
        "hosts": host,
        "become": True,
        "gather_facts": False,
        "vars": {
            "resource_type": resource_type,
            "affected_service": affected_service,
        },
        "tasks": tasks,
    }]

    yaml_str = yaml.safe_dump(playbook, sort_keys=False, default_flow_style=False)

    # Final safety check: ensure no forbidden patterns
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.lower() in yaml_str.lower():
            logger.error(
                "diagnostic_playbook_forbidden_pattern_detected",
                pattern=pattern,
                resource_type=resource_type,
            )
            raise ValueError(f"Generated playbook contains forbidden pattern: {pattern}")

    return yaml_str
