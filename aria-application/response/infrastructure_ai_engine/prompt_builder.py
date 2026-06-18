"""
SRE-focused prompt builder for infrastructure resource anomaly analysis.

The AI behaves as an expert Site Reliability Engineer, not a SOC analyst.
"""

from typing import Dict, Any, List, Optional

from .context_builder import ResourceContext


SYSTEM_PROMPT = """You are an expert Site Reliability Engineer (SRE) analyzing a system resource anomaly.

Your job is to understand WHY a resource is stressed, WHICH process or service is responsible,
and WHAT safe corrective actions can be taken. You are NOT a security analyst. Do NOT treat
this as a threat or attack.

RULES:
1. Explain clearly what is happening and why
2. Provide context and reasoning for every conclusion
3. Suggest SAFE corrective actions only — prefer remediation over pure diagnostics
4. Distinguish between immediate mitigation and long-term optimization
5. Always identify the responsible process, service, or workload
6. Assess whether the behavior is normal, abnormal, or expected
7. Determine if it's a temporary spike or persistent issue
8. Evaluate impact on system performance and availability
9. If a service restart or process management would fix the issue, suggest it explicitly
10. Include at least one verification task to confirm the fix worked

DO NOT:
- Use security terminology (attacker, threat, IOC, MITRE, exploit, malware)
- Suggest kill -9 blindly (graceful restart preferred)
- Suggest iptables/ufw/firewall changes (risk of SSH lockout)
- Suggest rm -rf without explicit file verification first
- Assume this is an attack or intrusion
- Suggest actions that would cause downtime without warning
- Give generic "investigate manually" responses — be specific

RESPONSE FORMAT — CRITICAL:
You MUST respond with a single valid JSON object. No markdown, no code fences, no prose outside JSON.
The JSON must be parseable by Python json.loads().
"""


def build_sre_analysis_prompt(
    context: ResourceContext,
    metrics_history: Optional[List[float]] = None,
) -> str:
    """Build an SRE-focused analysis prompt from resource context."""

    snapshot = context.metrics_snapshot
    affected = context.affected_process or {}
    top_procs = context.top_processes or []

    proc_table = "\n".join(
        f"  - {p.get('name', 'unknown')} (PID {p.get('pid', 0)}): "
        f"CPU={p.get('cpu_percent', 0):.1f}%, MEM={p.get('memory_rss', 0) / 1024 / 1024:.1f}MB"
        for p in top_procs[:5]
    )

    disk_info = ""
    if snapshot.get("disk_devices"):
        disk_info = "\n".join(
            f"  - {d.get('path', '/')} ({d.get('fstype', '')}): "
            f"{d.get('used_percent', 0):.1f}% used, "
            f"{d.get('free_bytes', 0) / 1024 / 1024 / 1024:.1f}GB free"
            for d in snapshot["disk_devices"][:3]
        )

    history_str = ""
    if metrics_history and len(metrics_history) >= 3:
        recent = metrics_history[-10:]
        history_str = f"Recent {context.resource_type} readings: {', '.join(f'{v:.1f}' for v in recent)}"

    prompt = f"""{SYSTEM_PROMPT}

RESOURCE ANOMALY CONTEXT:
- Host: {context.affected_host}
- Resource Type: {context.resource_type.upper()}
- Current Value: {context.current_value:.1f} {context.unit}
- Threshold: {context.threshold:.1f} {context.unit}
- Severity: {context.severity}
- Historical Trend: {context.historical_trend}
- Baseline Deviation: {context.baseline_deviation or 'unknown'}

AFFECTED PROCESS:
- Name: {affected.get('name', 'unknown')}
- PID: {affected.get('pid', 'unknown')}
- CPU Usage: {affected.get('cpu_percent', 0):.1f}%
- Memory RSS: {affected.get('memory_rss', 0) / 1024 / 1024:.1f} MB
- Command: {affected.get('cmdline', 'unknown')[:150]}

TOP PROCESSES:
{proc_table}

SYSTEM METRICS SNAPSHOT:
- CPU: {snapshot.get('cpu_usage_percent', 0):.1f}% (user={snapshot.get('cpu_user_percent', 0):.1f}%, system={snapshot.get('cpu_system_percent', 0):.1f}%, iowait={snapshot.get('cpu_iowait_percent', 0):.1f}%)
- Memory: {snapshot.get('memory_used_percent', 0):.1f}% used ({snapshot.get('memory_used_bytes', 0) / 1024 / 1024 / 1024:.1f}GB / {snapshot.get('memory_available_bytes', 0) / 1024 / 1024 / 1024:.1f}GB available)
- Load Average: {snapshot.get('load_1', 0):.2f} / {snapshot.get('load_5', 0):.2f} / {snapshot.get('load_15', 0):.2f} (CPUs: {snapshot.get('n_cpus', 0)})
- Connections: TCP established={snapshot.get('tcp_established', 0)}, listen={snapshot.get('tcp_listen', 0)}, UDP={snapshot.get('udp_socket', 0)}
- Processes: running={snapshot.get('proc_running', 0)}, sleeping={snapshot.get('proc_sleeping', 0)}, total={snapshot.get('proc_total', 0)}, threads={snapshot.get('proc_threads', 0)}

DISK STATUS:
{disk_info or 'No disk issues detected'}

{history_str}

YOUR TASK:
1. Identify the root cause: which process/service/workload is responsible?
2. Determine if this is normal, abnormal, or expected behavior
3. Assess if it's a temporary spike or persistent issue
4. Evaluate impact on system performance and availability
5. Suggest safe corrective actions with risk assessment

REQUIRED JSON RESPONSE:
{{
    "resource_impacted": "cpu|memory|disk|network",
    "responsible_process": {{
        "name": "process name",
        "pid": 1234,
        "cpu_percent": 78.5,
        "memory_rss_mb": 512
    }},
    "responsible_service": "nginx|postgresql|docker|...",
    "issue_start_time": "ISO timestamp or estimate",
    "behavior_classification": "temporary_spike|persistent|expected|abnormal",
    "impact_assessment": "Specific impact on system performance and availability",
    "root_cause": "Clear explanation of what is happening and why",
    "confidence": 0.0-1.0,
    "explanation": "Detailed reasoning for analysts",
    "immediate_mitigation": {{
        "action": "Specific safe action to take now",
        "risk": "Low|Medium|High — explanation",
        "expected_outcome": "What will happen after this action",
        "system_impact": "Impact on running services/users",
        "rollback_feasible": true
    }},
    "long_term_optimization": {{
        "action": "Configuration or architecture change",
        "risk": "Low|Medium|High — explanation",
        "expected_outcome": "Long-term benefit",
        "system_impact": "Impact during implementation"
    }},
    "suggested_playbook_tasks": [
        {{
            "name": "Diagnostic task name",
            "module": "ansible.builtin.shell|command|service|...",
            "args": "command or args",
            "purpose": "diagnostic|mitigation|verification"
        }}
    ]
}}
"""
    return prompt
