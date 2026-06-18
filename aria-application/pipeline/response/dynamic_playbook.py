"""
Dynamic AI-Driven Playbook Generator.

Generates Ansible playbooks dynamically based on:
- Root cause analysis results
- Actual processes from Telegraf procstat data
- Specific partition/filesystem affected
- Evidence from AI analysis

Part of the Server Performance Monitoring System (v1.0).
"""

import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

import structlog
from config import get_settings

logger = structlog.get_logger()


@dataclass
class PlaybookContext:
    """Context for dynamic playbook generation."""
    host: str
    anomaly_type: str
    current_value: float
    threshold: float
    remediation_type: str
    affected_process: Optional[Dict[str, str]]
    evidence: List[str]
    top_processes: List[Dict[str, Any]]
    disk_device: Optional[str]
    disk_path: Optional[str]


def _sanitize_for_ansible(text: str) -> str:
    """Sanitize text for use in Ansible tasks."""
    if not text:
        return ""
    return re.sub(r'[^a-zA-Z0-9_\- ]', '', text)[:100]


def _generate_process_tasks(context: PlaybookContext) -> List[Dict[str, Any]]:
    """Generate tasks based on affected process."""
    tasks = []
    
    if not context.affected_process:
        return []
    
    process_name = context.affected_process.get("name", "")
    process_pid = context.affected_process.get("pid", "")
    
    if not process_name:
        return []
    
    process_lower = process_name.lower()
    
    if "nginx" in process_lower or "apache" in process_lower or "httpd" in process_lower:
        tasks.extend([
            {
                "name": f"Check {process_name} status",
                "command": f"systemctl status {process_name} || true",
                "register": f"{process_name}_status",
                "failed_when": False,
                "changed_when": False
            },
            {
                "name": f"Get {process_name} connection count",
                "shell": f"netstat -tnp 2>/dev/null | grep {process_name} | wc -l",
                "register": f"{process_name}_conns",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": f"Graceful reload {process_name}",
                "command": f"systemctl reload {process_name}",
                "when": f"{process_name}_status.rc == 0",
                "failed_when": False,
                "changed_when": True
            }
        ])
    
    elif "redis" in process_lower or "memcached" in process_lower:
        tasks.extend([
            {
                "name": f"Get {process_name} memory info",
                "command": f"{process_name}-cli info memory",
                "register": f"{process_name}_mem",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": f"Flush expired keys in {process_name}",
                "command": f"{process_name}-cli FLUSHDB",
                "changed_when": True,
                "failed_when": False
            },
            {
                "name": f"Save {process_name} snapshot",
                "command": f"{process_name}-cli BGSAVE",
                "changed_when": False,
                "failed_when": False
            }
        ])
    
    elif "java" in process_lower or "tomcat" in process_lower or "jetty" in process_lower:
        tasks.extend([
            {
                "name": "Find Java processes with high CPU",
                "shell": "ps -eo pid,pcpu,comm --no-headers | sort -k2 -rn | head -5",
                "register": "java_procs",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": "Trigger Java garbage collection",
                "shell": "for pid in $(pgrep java); do jcmd $pid GC.run 2>/dev/null || true; done",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": "Restart Java application",
                "shell": "pkill -SIGTERM java || true; sleep 5; systemctl restart tomcat || true",
                "failed_when": False,
                "changed_when": True
            }
        ])
    
    elif "mysql" in process_lower or "mariadb" in process_lower or "postgres" in process_lower:
        db_name = "mysql" if "mysql" in process_lower else "postgresql"
        tasks.extend([
            {
                "name": f"Get {process_name} query list",
                "shell": f"{db_name}-admin processlist | head -20",
                "register": "slow_queries",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": f"Flush tables in {process_name}",
                "shell": f"{db_name}-admin flush-tables",
                "changed_when": True,
                "failed_when": False
            },
            {
                "name": f"Optimize tables in {process_name}",
                "shell": f"{db_name}-admin optimize -a",
                "changed_when": True,
                "failed_when": False
            }
        ])
    
    else:
        tasks.extend([
            {
                "name": f"Identify {process_name} process details",
                "shell": f"ps aux | grep -E '[{process_name[0]}]{process_name[1:]}' | head -5",
                "register": "process_details",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": f"Check {process_name} resource usage",
                "shell": f"pidstat -p $(pgrep -f {process_name}) 1 1 || true",
                "register": "process_stats",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": f"Restart {process_name} service",
                "shell": f"systemctl restart {process_name} || true",
                "changed_when": True,
                "failed_when": False
            }
        ])
    
    return tasks


def _generate_disk_tasks(context: PlaybookContext) -> List[Dict[str, Any]]:
    """Generate tasks for disk space issues."""
    tasks = []
    
    disk_path = context.disk_path or "/"
    device = context.disk_device or "unknown"
    
    if "log" in context.evidence or "logs" in context.evidence:
        tasks.extend([
            {
                "name": "List large log files",
                "shell": f"find /var/log -type f -size +100M -exec ls -lh {{}} \\; 2>/dev/null | head -20",
                "register": "large_logs",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": "Truncate old log files",
                "shell": f"find /var/log -type f -name '*.log' -mtime +7 -exec truncate -s 0 {{}} \\; 2>/dev/null || true",
                "changed_when": True,
                "failed_when": False
            },
            {
                "name": "Compress rotated logs",
                "shell": "find /var/log -type f -name '*.log.[0-9]' ! -name '*.gz' -exec gzip {{}} \\; 2>/dev/null || true",
                "changed_when": True,
                "failed_when": False
            },
            {
                "name": "Clean old journal logs",
                "command": "journalctl --vacuum-time=7d",
                "changed_when": True,
                "failed_when": False
            }
        ])
    
    if "temp" in context.evidence or "tmp" in context.evidence:
        tasks.extend([
            {
                "name": "Clean /tmp directory",
                "shell": "find /tmp -type f -atime +1 -delete 2>/dev/null || true",
                "changed_when": True
            },
            {
                "name": "Clean /var/tmp directory",
                "shell": "find /var/tmp -type f -atime +1 -delete 2>/dev/null || true",
                "changed_when": True,
                "failed_when": False
            }
        ])
    
    if "docker" in context.evidence or "container" in context.evidence:
        tasks.extend([
            {
                "name": "Get Docker disk usage",
                "shell": "docker system df",
                "register": "docker_df",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": "Remove stopped containers",
                "shell": "docker container prune -f",
                "changed_when": True,
                "failed_when": False
            },
            {
                "name": "Remove unused images",
                "shell": "docker image prune -a -f --filter 'until=168h'",
                "changed_when": True,
                "failed_when": False
            },
            {
                "name": "Remove build cache",
                "shell": "docker builder prune -f",
                "changed_when": True,
                "failed_when": False
            }
        ])
    
    if "apt" in context.evidence or "package" in context.evidence:
        tasks.extend([
            {
                "name": "Clean apt cache",
                "shell": "apt-get clean && apt-get autoclean && rm -rf /var/cache/apt/archives/*",
                "changed_when": True,
                "failed_when": False
            }
        ])
    
    tasks.extend([
        {
            "name": f"Get disk usage for {disk_path}",
            "shell": f"df -BG {disk_path} | tail -1",
            "register": "disk_after",
            "changed_when": False
        },
        {
            "name": "Report freed space",
            "debug": {"msg": f"Disk cleanup completed. Usage after: {{ disk_after.stdout }}"}
        }
    ])
    
    return tasks


def _generate_memory_tasks(context: PlaybookContext) -> List[Dict[str, Any]]:
    """Generate tasks for memory issues."""
    tasks = []
    
    if context.top_processes:
        top_proc = context.top_processes[0]
        proc_name = top_proc.get("name", "")
        
        tasks.extend([
            {
                "name": f"Get memory details for top process",
                "shell": f"ps -eo pid,vsz,rss,pmem,comm --no-headers | grep -i '{proc_name}' | head -5",
                "register": "mem_details",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": "Clear page cache",
                "shell": "sync && echo 3 > /proc/sys/vm/drop_caches",
                "become": True,
                "changed_when": True,
                "failed_when": False
            },
            {
                "name": "Clear slab cache",
                "shell": "sync && echo 2 > /proc/sys/vm/drop_caches",
                "become": True,
                "changed_when": True,
                "failed_when": False
            }
        ])
    
    if "redis" in str(context.evidence).lower() or "cache" in str(context.evidence).lower():
        tasks.extend([
            {
                "name": "Flush Redis database",
                "command": "redis-cli FLUSHDB",
                "changed_when": True,
                "failed_when": False
            },
            {
                "name": "Save Redis snapshot",
                "command": "redis-cli BGSAVE",
                "changed_when": False,
                "failed_when": False
            }
        ])
    
    tasks.extend([
        {
            "name": "Get memory info after cleanup",
            "shell": "free -h",
            "register": "mem_after",
            "changed_when": False
        },
        {
            "name": "Report memory status",
            "debug": {"msg": "Memory after cleanup: {{ mem_after.stdout }}"}
        }
    ])
    
    return tasks


def _generate_cpu_tasks(context: PlaybookContext) -> List[Dict[str, Any]]:
    """Generate tasks for CPU issues."""
    tasks = []
    
    if context.top_processes:
        tasks.extend([
            {
                "name": "Get top CPU consuming processes",
                "shell": "ps -eo pid,pcpu,comm --no-headers | sort -k2 -rn | head -10",
                "register": "top_cpu_procs",
                "changed_when": False
            },
            {
                "name": "Get process tree for top processes",
                "shell": "ps -eo pid,ppid,comm --no-headers | head -20",
                "register": "proc_tree",
                "changed_when": False,
                "failed_when": False
            }
        ])
    
    if "restart" in context.remediation_type:
        tasks.extend([
            {
                "name": "Identify service to restart",
                "shell": "systemctl list-units --type=service --state=running | head -20",
                "register": "running_services",
                "changed_when": False,
                "failed_when": False
            }
        ])
    
    if "scale" in context.remediation_type:
        tasks.extend([
            {
                "name": "Check if auto-scaling is available",
                "shell": "which kubectl || which docker",
                "register": "scaler_available",
                "changed_when": False,
                "failed_when": False
            }
        ])
    
    tasks.append({
        "name": "Report CPU status",
        "debug": {"msg": f"CPU issue on {context.host}: {context.current_value}% usage"}
    })
    
    return tasks


def _yaml_value(value: str) -> str:
    """Quote a string for YAML if it contains special characters."""
    if not value:
        return '""'
    # Characters that require quoting in YAML plain scalars
    special_chars = ":#{}[]|>&*!?,'\"\n\r"
    if any(c in value for c in special_chars):
        # Escape double quotes and wrap in double quotes
        escaped = value.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{escaped}"'
    return value


def _build_playbook_yaml(
    name: str,
    hosts: str,
    tasks: List[Dict[str, Any]],
    vars: Optional[Dict[str, Any]] = None,
    become: bool = True
) -> str:
    """Build Ansible playbook YAML from task definitions."""
    lines = [
        "---",
        f"- name: {_yaml_value(name)}",
        f"  hosts: {hosts}",
        "  gather_facts: yes",
    ]
    
    if become:
        lines.append("  become: yes")
    
    if vars:
        lines.append("  vars:")
        for k, v in vars.items():
            if isinstance(v, str):
                lines.append(f"    {k}: {_yaml_value(v)}")
            elif isinstance(v, bool):
                lines.append(f"    {k}: {str(v).lower()}")
            elif isinstance(v, int):
                lines.append(f"    {k}: {v}")
    
    lines.append("  tasks:")
    
    for task in tasks:
        task_name = task.get("name", "Unnamed task")
        lines.append(f"    - name: {_yaml_value(task_name)}")
        
        if "debug" in task:
            msg = task["debug"].get("msg", "")
            lines.append(f"      debug:")
            lines.append(f"        msg: {_yaml_value(msg)}")
            continue
        
        for key in ["shell", "command"]:
            if key in task:
                cmd = task[key]
                lines.append(f"      {key}: {_yaml_value(cmd)}")
                break
        
        if task.get("register"):
            lines.append(f"      register: {task['register']}")
        
        if task.get("changed_when") is not None:
            lines.append(f"      changed_when: {str(task['changed_when']).lower()}")
        
        if task.get("failed_when") is not None:
            lines.append(f"      failed_when: {str(task['failed_when']).lower()}")
        
        if task.get("when"):
            lines.append(f"      when: {task['when']}")
        
        if task.get("become"):
            lines.append(f"      become: yes")
    
    return "\n".join(lines)


async def generate_dynamic_playbook(
    context: PlaybookContext,
    root_cause_result: Optional[Any] = None
) -> Optional[str]:
    """
    Generate a dynamic Ansible playbook based on root cause analysis.
    
    Uses:
    - Root cause analysis (remediation_type, evidence)
    - Actual processes from procstat
    - Specific partition/filesystem
    - Evidence from AI analysis
    """
    settings = get_settings()
    
    if not settings.performance_playbook_enabled:
        logger.info("playbook_generation_disabled")
        return None
    
    tasks = []
    playbook_name = f"Performance Remediation: {context.anomaly_type.replace('_', ' ').title()}"
    
    if context.remediation_type == "restart_service":
        tasks.extend(_generate_process_tasks(context))
    
    elif context.remediation_type == "clear_memory":
        tasks.extend(_generate_memory_tasks(context))
    
    elif context.remediation_type in ["clean_logs", "clean_temp", "resize_disk"]:
        tasks.extend(_generate_disk_tasks(context))
    
    elif context.remediation_type == "scale":
        tasks.extend(_generate_cpu_tasks(context))
    
    elif context.remediation_type == "investigate":
        tasks = [
            {
                "name": "Gather system information",
                "shell": "uname -a && hostname && uptime",
                "register": "system_info",
                "changed_when": False
            },
            {
                "name": "Get top processes by CPU",
                "shell": "ps -eo pid,pcpu,pmem,comm --no-headers | sort -k2 -rn | head -10",
                "register": "top_procs",
                "changed_when": False
            },
            {
                "name": "Get memory usage",
                "shell": "free -h",
                "register": "mem_info",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": "Get disk usage",
                "shell": "df -h",
                "register": "disk_info",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": "Get network connections",
                "shell": "netstat -tun | wc -l",
                "register": "net_conns",
                "changed_when": False,
                "failed_when": False
            },
            {
                "name": "Report investigation results",
                "debug": {
                    "msg": f"Investigation for {context.anomaly_type} on {context.host}. Current: {context.current_value}%, Threshold: {context.threshold}%"
                }
            }
        ]
    
    if not tasks:
        logger.warning("no_tasks_generated", remediation_type=context.remediation_type)
        return None
    
    playbook_yaml = _build_playbook_yaml(
        name=playbook_name,
        hosts=context.host,
        tasks=tasks,
        become=True
    )
    
    logger.info(
        "dynamic_playbook_generated",
        host=context.host,
        anomaly_type=context.anomaly_type,
        remediation_type=context.remediation_type,
        task_count=len(tasks)
    )
    
    return playbook_yaml


def get_available_remediation_types() -> List[str]:
    """Get list of available remediation types."""
    return [
        "restart_service",
        "clear_memory",
        "clean_logs",
        "clean_temp",
        "resize_disk",
        "scale",
        "investigate"
    ]