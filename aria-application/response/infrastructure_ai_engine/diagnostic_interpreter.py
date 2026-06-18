"""
Diagnostic Results Interpreter.

Hybrid rule-based + AI fallback interpretation.

1. Rule-based interpretation (primary): parses ps/top output and computes
   findings deterministically. Fast, accurate, no hallucination.
2. AI fallback: only used when data is ambiguous or log analysis is needed.
"""

import asyncio
import json
import re
from typing import Dict, Any, Optional
from datetime import datetime, timezone

import structlog

from config import get_settings
from response.ai_engine.llm_clients import _call_llm
from .context_builder import ResourceContext

logger = structlog.get_logger()


def _extract_task_stdout(diagnostic_output: str, task_name: str) -> str:
    """Extract stdout from a specific Ansible task by name."""
    pattern = rf'TASK \[{re.escape(task_name)}\].*?"stdout":\s*"(.*?)"'
    match = re.search(pattern, diagnostic_output, re.DOTALL)
    if match:
        raw = match.group(1)
        try:
            return json.loads(f'"{raw}"')
        except Exception:
            return raw.replace('\\n', '\n').replace('\\t', '\t')
    # Try stdout_lines fallback
    pattern_lines = rf'TASK \[{re.escape(task_name)}\].*?"stdout_lines":\s*(\[.*?\])'
    match_lines = re.search(pattern_lines, diagnostic_output, re.DOTALL)
    if match_lines:
        try:
            lines = json.loads(match_lines.group(1))
            return '\n'.join(lines)
        except Exception:
            pass
    return ""


def _extract_top_cpu_processes(diagnostic_output: str) -> list[dict]:
    """Extract top CPU-consuming processes from ps output."""
    stdout = _extract_task_stdout(diagnostic_output, "CPU — top processes by CPU usage")
    processes = []
    if stdout:
        for line in stdout.strip().split('\n')[:15]:
            parts = line.split()
            # Format: PID CPU% MEM% COMMAND...
            if len(parts) >= 4:
                try:
                    processes.append({
                        "pid": parts[0],
                        "cpu_percent": float(parts[1]),
                        "mem_percent": float(parts[2]),
                        "name": ' '.join(parts[3:]),
                    })
                except ValueError:
                    continue
    return processes


def _extract_top_memory_processes(diagnostic_output: str) -> list[dict]:
    """Extract top memory-consuming processes from ps output."""
    stdout = _extract_task_stdout(diagnostic_output, "Memory — top processes by RSS")
    if not stdout:
        stdout = _extract_task_stdout(diagnostic_output, "Memory — top processes by %MEM")
    processes = []
    if stdout:
        for line in stdout.strip().split('\n')[:15]:
            parts = line.split()
            # Format: PID %MEM RSS VSZ COMMAND... (5 columns)
            if len(parts) >= 5:
                try:
                    processes.append({
                        "pid": parts[0],
                        "mem_percent": float(parts[1]),
                        "rss_mb": int(parts[2]) / 1024,
                        "name": ' '.join(parts[4:]),
                    })
                except ValueError:
                    continue
            # Fallback 4-column format
            elif len(parts) >= 4:
                try:
                    processes.append({
                        "pid": parts[0],
                        "mem_percent": float(parts[1]),
                        "rss_mb": int(parts[2]) / 1024,
                        "name": ' '.join(parts[3:]),
                    })
                except ValueError:
                    continue
    return processes


def _extract_load_average(diagnostic_output: str) -> str:
    """Extract load average from uptime output."""
    stdout = _extract_task_stdout(diagnostic_output, "System overview — uptime and load")
    if stdout:
        first_line = stdout.strip().split('\n')[0]
        match = re.search(r'load average[s]?:\s*([\d.,]+),?\s*([\d.,]+),?\s*([\d.,]+)', first_line)
        if match:
            return f"{match.group(1)} / {match.group(2)} / {match.group(3)}"
    return ""


def _extract_disk_usage(diagnostic_output: str) -> list[dict]:
    """Extract filesystem usage from df output. Filters Docker overlay mounts."""
    stdout = _extract_task_stdout(diagnostic_output, "Disk — filesystem usage")
    mounts = []
    seen_mounts = set()
    if stdout:
        for line in stdout.strip().split('\n')[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 6:
                try:
                    mount = parts[5]
                    # Skip Docker overlay mounts — they are virtual layers sharing the same underlying disk
                    if "/var/lib/docker/overlay2/" in mount or "/var/lib/docker/containers/" in mount:
                        continue
                    # Deduplicate by mount point
                    if mount in seen_mounts:
                        continue
                    seen_mounts.add(mount)
                    use_percent = float(parts[4].replace('%', ''))
                    mounts.append({
                        "filesystem": parts[0],
                        "size": parts[1],
                        "used": parts[2],
                        "available": parts[3],
                        "use_percent": use_percent,
                        "mount": mount,
                    })
                except ValueError:
                    continue
    return sorted(mounts, key=lambda x: x["use_percent"], reverse=True)


def _extract_large_directories(diagnostic_output: str) -> list[dict]:
    """Extract top directories by size from du output."""
    stdout = _extract_task_stdout(diagnostic_output, "Disk — top directories by size")
    dirs = []
    if stdout:
        for line in stdout.strip().split('\n')[:10]:
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                dirs.append({"size": parts[0], "path": parts[1]})
    return dirs


def _extract_large_files(diagnostic_output: str) -> list[dict]:
    """Extract large files from find output."""
    stdout = _extract_task_stdout(diagnostic_output, "Disk — large files")
    files = []
    if stdout and "No large files" not in stdout:
        for line in stdout.strip().split('\n')[:10]:
            if line.strip() and not line.startswith("find:"):
                files.append({"path": line.strip()})
    return files


def _extract_failed_services(diagnostic_output: str) -> list[str]:
    """Extract failed systemd units."""
    stdout = _extract_task_stdout(diagnostic_output, "Failed systemd units")
    if stdout:
        return [l.strip() for l in stdout.strip().split('\n') if l.strip()][:10]
    return []


def _extract_recent_errors(diagnostic_output: str) -> list[str]:
    """Extract recent error log lines."""
    stdout = _extract_task_stdout(diagnostic_output, "Recent error logs")
    if stdout:
        return [l.strip() for l in stdout.strip().split('\n') if l.strip()][:10]
    return []


def _build_evidence_items(processes: list[dict], load_avg: str, errors: list[str], failed_svcs: list[str]) -> list[dict]:
    """Build structured evidence list from extracted data."""
    evidence = []
    for p in processes[:5]:
        evidence.append({
            "source": "ps output",
            "finding": f"{p['name']} (PID {p['pid']}): CPU={p.get('cpu_percent', 0):.1f}%, MEM={p.get('mem_percent', 0):.1f}%",
            "timestamp": "",
        })
    if load_avg:
        evidence.append({
            "source": "uptime",
            "finding": f"Load average: {load_avg}",
            "timestamp": "",
        })
    for err in errors[:3]:
        evidence.append({
            "source": "journalctl",
            "finding": err[:120],
            "timestamp": "",
        })
    for svc in failed_svcs[:3]:
        evidence.append({
            "source": "systemctl",
            "finding": f"Failed unit: {svc}",
            "timestamp": "",
        })
    return evidence


def _build_disk_recommendations(mount_point: str, large_dirs: list[dict]) -> list[dict]:
    """Generate data-aware disk recommendations based on actual du output."""
    # Normalize mount point: avoid double slashes like //var/log
    if mount_point == "/":
        mp = ""
    else:
        mp = mount_point.rstrip("/")

    recommendations = []

    # ── Data-aware recommendations from actual du output ──
    for d in large_dirs[:3]:
        path = d["path"]
        size = d["size"]
        path_lower = path.lower()

        if "/home" in path_lower:
            recommendations.append({
                "action": (
                    f"`/home` is consuming **{size}** — investigate user data: `du -sh {path}/* 2>/dev/null | sort -rh | head -10`. "
                    f"Check for large downloads, build artifacts, or abandoned project directories. "
                    f"Look for `.cache`, `.local/share`, and old backups."
                ),
                "priority": 1,
                "risk": "low",
                "rationale": f"/home is the largest disk consumer at {size}",
            })
        elif "/var/log" in path_lower:
            recommendations.append({
                "action": (
                    f"`/var/log` is consuming **{size}** — logs are the primary growth driver. "
                    f"Check rotation: `ls -lhS {path}/*.log* 2>/dev/null | head -10`. "
                    f"Run `sudo logrotate -f /etc/logrotate.conf` to force rotation. "
                    f"If a single log is ballooning, identify the source process: `lsof {path}/*.log 2>/dev/null | head -5`."
                ),
                "priority": 1,
                "risk": "low",
                "rationale": f"Log files are growing uncontrollably at {size}",
            })
        elif "/tmp" in path_lower:
            recommendations.append({
                "action": (
                    f"`/tmp` is consuming **{size}** — likely temp files or aborted downloads. "
                    f"List largest: `ls -lhS {path} 2>/dev/null | head -10`. "
                    f"Safe to purge old files: `find {path} -type f -atime +1 -delete` (files not accessed in 24h). "
                    f"Check for Docker/container temp layers if applicable."
                ),
                "priority": 1,
                "risk": "low",
                "rationale": f"Temp directory has accumulated {size} of data",
            })
        elif "/var/cache" in path_lower:
            recommendations.append({
                "action": (
                    f"`/var/cache` is consuming **{size}** — package and application caches. "
                    f"Clean apt cache: `apt-get clean` and `apt-get autoclean`. "
                    f"Check application-specific caches under `{path}`."
                ),
                "priority": 2,
                "risk": "low",
                "rationale": f"Package caches can grow large; currently at {size}",
            })
        else:
            recommendations.append({
                "action": (
                    f"`{path}` is consuming **{size}** — investigate contents: `du -sh {path}/* 2>/dev/null | sort -rh | head -10`. "
                    f"Identify what application or user owns this space."
                ),
                "priority": 1,
                "risk": "low",
                "rationale": f"This directory is a significant disk consumer at {size}",
            })

    # ── Generic disk diagnostics (always included as fallback) ──
    recommendations.append({
        "action": (
            f"Find files larger than 100MB: `find {mp or '/'} -xdev -type f -size +100M -exec ls -lh {{}} \\; 2>/dev/null | sort -k5 -rh | head -10`. "
            f"Also check for deleted files still held open: `lsof +L1 {mp or '/'} 2>/dev/null | head -10` — these consume space but are invisible to `df`."
        ),
        "priority": 2,
        "risk": "low",
        "rationale": "Large files and unlinked open files are common causes of unexpected disk growth",
    })

    recommendations.append({
        "action": (
            f"Clean system caches: `apt-get clean` (Debian/Ubuntu) or `yum clean all` (RHEL/CentOS). "
            f"Clear old journal logs: `journalctl --vacuum-time=3d` or `journalctl --vacuum-size=100M`. "
            f"Remove old kernels: `dpkg -l 'linux-*' | grep ^ii` then `apt-get purge` old versions."
        ),
        "priority": 3,
        "risk": "low",
        "rationale": "Package caches and old kernels can consume multiple gigabytes of disk space",
    })

    return recommendations


def _build_expert_recommendations(
    process_name: str,
    pid: str,
    resource_type: str,
    value: float,
    host: str,
) -> list[dict]:
    """Generate expert-level, process-specific actionable recommendations."""
    name_lower = process_name.lower()
    recommendations = []

    # ── Stress-ng / synthetic load generators ──
    if "stress" in name_lower:
        recommendations.append({
            "action": (
                f"Verify if this stress-ng run is intentional (load test, benchmark, or chaos engineering). "
                f"If NOT intentional: check for unauthorized access via `last`, `w`, and audit logs. "
                f"Check cron jobs (`crontab -l`), systemd timers (`systemctl list-timers`), and running tmux/screen sessions. "
                f"Kill with `kill -TERM {pid}` or `pkill -f stress-ng` if unintended."
            ),
            "priority": 1,
            "risk": "low",
            "rationale": "stress-ng is a synthetic load generator — high CPU is expected if intentional, suspicious if not",
        })
        recommendations.append({
            "action": f"Monitor all stress-ng instances: `pgrep -a stress-ng` and `ps -eo pid,ppid,pcpu,comm | grep stress`",
            "priority": 2,
            "risk": "none",
            "rationale": "Map the full process tree to identify who launched it",
        })

    # ── Java ──
    elif "java" in name_lower:
        recommendations.append({
            "action": (
                f"Check JVM heap usage: `jmap -heap {pid}` and GC pressure: `jstat -gcutil {pid} 1s 5`. "
                f"Review application logs for OutOfMemoryError or excessive GC. "
                f"Verify `-Xmx` setting matches available RAM. Consider heap dump if memory leak suspected: `jmap -dump:live,format=b,file=/tmp/heap.hprof {pid}`"
            ),
            "priority": 1,
            "risk": "low",
            "rationale": "Java processes often spike from GC pressure, thread leaks, or heap exhaustion",
        })
        recommendations.append({
            "action": f"Check thread count and blocked threads: `jstack {pid} | grep -c 'java.lang.Thread.State'` and review for deadlocks",
            "priority": 2,
            "risk": "low",
            "rationale": "Thread leaks and lock contention are common causes of Java CPU spikes",
        })

    # ── Python ──
    elif "python" in name_lower:
        recommendations.append({
            "action": (
                f"Identify the script: `readlink -f /proc/{pid}/exe` and `cat /proc/{pid}/cmdline`. "
                f"Check for runaway loops or unhandled exceptions in application logs. "
                f"Profile with `py-spy top --pid {pid}` (if available) or strace: `strace -cp {pid}` to find syscalls consuming CPU."
            ),
            "priority": 1,
            "risk": "low",
            "rationale": "Python spikes often come from tight loops, heavy I/O, or blocking operations",
        })
        recommendations.append({
            "action": f"Check memory and open files: `pmap -x {pid} | tail -5` and `lsof -p {pid} | wc -l`",
            "priority": 2,
            "risk": "none",
            "rationale": "File descriptor leaks and memory bloat often accompany CPU spikes",
        })

    # ── Node.js ──
    elif "node" in name_lower:
        recommendations.append({
            "action": (
                f"Check event loop lag: `kill -USR1 {pid}` to enable inspector, then profile. "
                f"Review heap usage: `node --heapsnapshot-near-heap-limit` if configured. "
                f"Check for blocking sync operations, infinite loops, or unhandled promise rejections in logs."
            ),
            "priority": 1,
            "risk": "low",
            "rationale": "Node.js is single-threaded; one blocking operation spikes the entire process",
        })

    # ── Falco ──
    elif "falco" in name_lower:
        recommendations.append({
            "action": (
                f"Falco is a security monitor. High CPU usually means excessive syscalls or noisy rules. "
                f"Check rule match volume: `grep -c 'Notice|Warning|Error' /var/log/falco.log` (last 10 min). "
                f"Review active rules: `falco -L | grep -c 'enabled'` and consider disabling noisy rules in `/etc/falco/falco_rules.yaml`. "
                f"Enable syscall buffering (`syscall_buf_size_preset`) if not already set."
            ),
            "priority": 1,
            "risk": "low",
            "rationale": "Falco CPU correlates with syscall volume and rule complexity",
        })

    # ── Telegraf ──
    elif "telegraf" in name_lower:
        recommendations.append({
            "action": (
                f"Telegraf is a metrics collector. High CPU usually means aggressive collection intervals or misconfigured plugins. "
                f"Review `/etc/telegraf/telegraf.conf` for `interval` and `flush_interval` settings. "
                f"Check plugin load: `telegraf --config /etc/telegraf/telegraf.conf --test` to see which plugins are active. "
                f"Consider increasing collection interval or disabling unused inputs."
            ),
            "priority": 1,
            "risk": "low",
            "rationale": "Telegraf CPU scales with plugin count and collection frequency",
        })

    # ── Prometheus ──
    elif "prometheus" in name_lower:
        recommendations.append({
            "action": (
                f"Prometheus CPU spikes from high cardinality, expensive recording rules, or compaction. "
                f"Check `prometheus_build_info` and scrape count. Review `/var/lib/prometheus/queries.active`. "
                f"Look for high-cardinality labels and recording rules in `/etc/prometheus/prometheus.yml`."
            ),
            "priority": 1,
            "risk": "low",
            "rationale": "Prometheus CPU correlates with target count, series cardinality, and rule evaluation load",
        })

    # ── Suricata ──
    elif "suricata" in name_lower:
        recommendations.append({
            "action": (
                f"Suricata is a network IDS. High CPU comes from high traffic volume or complex rules. "
                f"Check `suricatactl stats` or `/var/log/suricata/stats.log` for drop rate and rule match count. "
                f"Review `/etc/suricata/suricata.yaml` for `detect-engine.profile` and `af-packet` settings."
            ),
            "priority": 1,
            "risk": "low",
            "rationale": "Suricata CPU scales with traffic volume, rule set size, and inspection depth",
        })

    # ── Disk-specific recommendations (process-based args are re-purposed as mount/dir) ──
    if resource_type == "disk":
        mount_point = process_name  # re-purposed parameter
        return _build_disk_recommendations(mount_point, [])

    # ── Generic / catch-all ──
    else:
        recommendations.append({
            "action": (
                f"Inspect the process immediately: `cat /proc/{pid}/cmdline` and `ls -la /proc/{pid}/fd/` to understand what it is doing. "
                f"Check logs: `journalctl -u {process_name} --since '10 minutes ago'` or `dmesg | grep {process_name}`. "
                f"Profile with `perf top -p {pid}` or `strace -cp {pid}` to identify hot code paths or excessive syscalls."
            ),
            "priority": 1,
            "risk": "low",
            "rationale": f"This process is consuming significant {resource_type.upper()} and requires immediate triage",
        })
        recommendations.append({
            "action": (
                f"Check resource limits and cgroups: `cat /proc/{pid}/limits` and `cat /proc/{pid}/cgroup`. "
                f"Verify if the process has memory/CPU limits set via systemd, Docker, or Kubernetes."
            ),
            "priority": 2,
            "risk": "none",
            "rationale": "Resource limits prevent runaway processes from consuming all system resources",
        })

    # ── Universal follow-up for ALL active spikes ──
    if resource_type == "cpu":
        recommendations.append({
            "action": f"Set up monitoring: `watch -n 2 'ps -eo pid,pcpu,comm | grep {process_name}'` to track if the spike persists or recurs",
            "priority": 3,
            "risk": "none",
            "rationale": "Continuous monitoring confirms whether the fix worked or if the issue is recurring",
        })
    elif resource_type == "memory":
        recommendations.append({
            "action": f"Track memory trend: `watch -n 5 'pmap -x {pid} | tail -1'` to see if RSS is growing (indicates a leak)",
            "priority": 3,
            "risk": "none",
            "rationale": "Growing RSS over time confirms a memory leak vs. a one-time allocation spike",
        })

    return recommendations


def _aggregate_processes_by_name(processes: list[dict], resource_type: str) -> list[dict]:
    """Aggregate multiple instances of the same process name.

    Example: two stress-ng-vm PIDs at 21% each → one entry at 42%.
    """
    agg: dict[str, dict] = {}
    for p in processes:
        name = p.get("name", "unknown")
        if name not in agg:
            agg[name] = {
                "name": name,
                "pid": p.get("pid", 0),
                "cpu_percent": 0.0,
                "mem_percent": 0.0,
                "rss_mb": 0.0,
            }
        agg[name]["cpu_percent"] += p.get("cpu_percent", 0.0)
        agg[name]["mem_percent"] += p.get("mem_percent", 0.0)
        agg[name]["rss_mb"] += p.get("rss_mb", 0.0)

    result = list(agg.values())
    if resource_type == "cpu":
        result.sort(key=lambda x: x["cpu_percent"], reverse=True)
    else:
        result.sort(key=lambda x: x["mem_percent"], reverse=True)
    return result


def _is_baseline_process(process_name: str, current_value: float, context: ResourceContext) -> bool:
    """Check if a process is a baseline (always high, didn't change during spike).

    A process is baseline if it was also present in the detection-time snapshot
    with a value within ±10 percentage points of its current value.
    Example: java at 26% now and java at 26% during spike = baseline.
    """
    if not context.top_processes:
        return False

    for p in context.top_processes:
        if p.get("name", "").lower() == process_name.lower():
            if context.resource_type == "cpu":
                original = p.get("cpu_percent", 0)
            else:
                original = p.get("memory_percent", 0)
            # If current is within 10 points of original, it's baseline
            return abs(current_value - original) < 10

    # Not found in original snapshot → not baseline (either new or finished)
    return False


def _resolve_culprit(
    top_agg: dict,
    context: ResourceContext,
    max_value: float,
    low_threshold: float,
) -> tuple[str, int, str]:
    """Resolve the true culprit by detecting baseline processes.

    Returns (culprit_name, culprit_pid, explanation).
    """
    top_name = top_agg["name"]
    top_pid = top_agg["pid"]
    original = context.affected_process

    # If current top is low AND different from context → use context (finished process)
    if original and original.get("name") and original.get("name").lower() != top_name.lower() and max_value < low_threshold:
        return original["name"], original["pid"], "original_process_finished"

    # If current top is a baseline (didn't change during spike) → it didn't cause it
    if _is_baseline_process(top_name, max_value, context):
        if original and original.get("name") and original.get("name").lower() != top_name.lower():
            # We know the original culprit from detection time
            return original["name"], original["pid"], "baseline_process_detected"
        else:
            # No original culprit known — short-lived process finished
            return top_name, top_pid, "short_lived_process_finished"

    # Current top is the real culprit
    return top_name, top_pid, "current_top_confirmed"


def _rule_based_interpretation(
    context: ResourceContext,
    diagnostic_output: str,
) -> Optional[dict]:
    """
    Deterministic interpretation of diagnostic output.

    Uses AGGREGATED process data + baseline detection to avoid blaming
    long-running processes like java that are always at 26%.
    """
    resource_type = context.resource_type
    reported_value = context.current_value
    threshold = context.threshold
    host = context.affected_host

    if resource_type == "cpu":
        processes = _extract_top_cpu_processes(diagnostic_output)
        if not processes:
            return None

        agg = _aggregate_processes_by_name(processes, "cpu")
        top = agg[0] if agg else {"name": "unknown", "pid": 0, "cpu_percent": 0.0}
        max_cpu = top["cpu_percent"]
        total_cpu = sum(p["cpu_percent"] for p in agg[:5])
        load_avg = _extract_load_average(diagnostic_output)
        errors = _extract_recent_errors(diagnostic_output)
        failed_svcs = _extract_failed_services(diagnostic_output)

        culprit_name, culprit_pid, reason = _resolve_culprit(top, context, max_cpu, 15)

        # Case 1: Active
        if max_cpu >= reported_value - 20:
            contributors = [p for p in agg if p["cpu_percent"] >= max_cpu * 0.3]
            if len(contributors) == 1:
                cause = f"{culprit_name} (PID {culprit_pid}) consuming {top['cpu_percent']:.1f}% CPU"
            else:
                names = ", ".join(f"{p['name']} ({p['cpu_percent']:.1f}%)" for p in contributors[:3])
                cause = f"Multiple processes: {names}"

            return {
                "detected_cause": cause,
                "confidence": 0.9,
                "severity": context.severity,
                "impact": f"CPU resource on {host}",
                "is_temporary": False,
                "is_expected": False,
                "technical_explanation": (
                    f"The top CPU process is {top['name']} (PID {top['pid']}) at {top['cpu_percent']:.1f}%, "
                    f"close to the reported spike of {reported_value:.1f}%. "
                    f"Top 5 processes together account for {total_cpu:.1f}% CPU."
                ),
                "evidence": _build_evidence_items(processes, load_avg, errors, failed_svcs),
                "recommendations": _build_expert_recommendations(
                    culprit_name, str(culprit_pid), "cpu", reported_value, host
                ),
                "requires_action": True,
                "expert_summary": f"CPU spike confirmed: {culprit_name} (PID {culprit_pid}) at {top['cpu_percent']:.1f}% is the primary contributor on {host}.",
            }

        # Case 2: Reduced but still active
        if max_cpu >= 15:
            if reason == "baseline_process_detected":
                detected_cause = f"{culprit_name} (PID {culprit_pid}) caused the spike but has since finished or reduced"
                tech = (
                    f"The current top process ({top['name']} at {top['cpu_percent']:.1f}%) is a baseline process "
                    f"that was also present during the spike. The actual culprit ({culprit_name}) has since finished or reduced."
                )
                expert_summary = f"CPU spike of {reported_value:.1f}% on {host}: {culprit_name} caused it but has finished. Current top process ({top['name']}) is baseline."
                recommendations = _build_expert_recommendations(culprit_name, str(culprit_pid), "cpu", reported_value, host)
            else:
                detected_cause = f"{culprit_name} (PID {culprit_pid}) is still active but reduced from {reported_value:.1f}% to {top['cpu_percent']:.1f}% CPU"
                tech = (
                    f"The spike has partially subsided but {top['name']} is still consuming "
                    f"{top['cpu_percent']:.1f}% CPU (aggregated across all instances)."
                )
                expert_summary = f"CPU spike on {host}: {culprit_name} (PID {culprit_pid}) reduced from {reported_value:.1f}% to {top['cpu_percent']:.1f}% but is still active."
                recommendations = _build_expert_recommendations(culprit_name, str(culprit_pid), "cpu", reported_value, host)

            return {
                "detected_cause": detected_cause,
                "confidence": 0.9,
                "severity": context.severity,
                "impact": f"CPU on {host} is still elevated",
                "is_temporary": False,
                "is_expected": False,
                "technical_explanation": tech,
                "evidence": _build_evidence_items(processes, load_avg, errors, failed_svcs),
                "recommendations": recommendations,
                "requires_action": True,
                "expert_summary": expert_summary,
            }

        # Case 3: Truly subsided
        detected_cause = f"{culprit_name} (PID {culprit_pid}) caused the spike but has since finished or reduced"
        expert_summary = f"CPU spike of {reported_value:.1f}% on {host} was caused by {culprit_name} (PID {culprit_pid}). Process has since finished or reduced to {top['cpu_percent']:.1f}%."
        recommendations = _build_expert_recommendations(culprit_name, str(culprit_pid), "cpu", reported_value, host) if reason != "current_top_confirmed" else []

        return {
            "detected_cause": detected_cause,
            "confidence": 0.95,
            "severity": context.severity,
            "impact": f"CPU on {host} was elevated but has returned to normal",
            "is_temporary": True,
            "is_expected": False,
            "technical_explanation": (
                f"The diagnostic captured process data after the spike ended. "
                f"The highest CPU process is {top['name']} at {top['cpu_percent']:.1f}%, "
                f"well below the reported {reported_value:.1f}%. "
                f"Load average ({load_avg or 'unknown'}) may still reflect recent activity."
            ),
            "evidence": _build_evidence_items(processes, load_avg, errors, failed_svcs),
            "recommendations": recommendations,
            "requires_action": False,
            "expert_summary": expert_summary,
        }

    elif resource_type == "memory":
        processes = _extract_top_memory_processes(diagnostic_output)
        if not processes:
            return None

        agg = _aggregate_processes_by_name(processes, "memory")
        top = agg[0] if agg else {"name": "unknown", "pid": 0, "mem_percent": 0.0, "rss_mb": 0.0}
        max_mem = top["mem_percent"]
        total_mem = sum(p["mem_percent"] for p in agg[:5])
        load_avg = _extract_load_average(diagnostic_output)
        errors = _extract_recent_errors(diagnostic_output)
        failed_svcs = _extract_failed_services(diagnostic_output)

        culprit_name, culprit_pid, reason = _resolve_culprit(top, context, max_mem, 20)

        # Case 1: Active
        if max_mem >= reported_value - 20:
            contributors = [p for p in agg if p["mem_percent"] >= max_mem * 0.3]
            if len(contributors) == 1:
                cause = f"{culprit_name} (PID {culprit_pid}) consuming {top['mem_percent']:.1f}% memory ({top['rss_mb']:.0f}MB RSS)"
            else:
                names = ", ".join(f"{p['name']} ({p['mem_percent']:.1f}%)" for p in contributors[:3])
                cause = f"Multiple processes: {names}"

            return {
                "detected_cause": cause,
                "confidence": 0.9,
                "severity": context.severity,
                "impact": f"Memory resource on {host}",
                "is_temporary": False,
                "is_expected": False,
                "technical_explanation": (
                    f"The top memory process is {top['name']} (PID {top['pid']}) at {top['mem_percent']:.1f}% "
                    f"({top['rss_mb']:.0f}MB RSS), close to the reported spike of {reported_value:.1f}%. "
                    f"Top 5 processes together account for {total_mem:.1f}% memory."
                ),
                "evidence": _build_evidence_items(processes, load_avg, errors, failed_svcs),
                "recommendations": _build_expert_recommendations(
                    culprit_name, str(culprit_pid), "memory", reported_value, host
                ),
                "requires_action": True,
                "expert_summary": f"Memory spike confirmed: {culprit_name} (PID {culprit_pid}) at {top['mem_percent']:.1f}% is the primary contributor on {host}.",
            }

        # Case 2: Reduced but still active
        if max_mem >= 20:
            if reason == "baseline_process_detected":
                detected_cause = f"{culprit_name} (PID {culprit_pid}) caused the spike but has since finished or reduced"
                tech = (
                    f"The current top process ({top['name']} at {top['mem_percent']:.1f}%) is a baseline process "
                    f"that was also present during the spike. The actual culprit ({culprit_name}) has since finished or reduced."
                )
                expert_summary = f"Memory spike of {reported_value:.1f}% on {host}: {culprit_name} caused it but has finished. Current top process ({top['name']}) is baseline."
                recommendations = _build_expert_recommendations(culprit_name, str(culprit_pid), "memory", reported_value, host)
            else:
                detected_cause = f"{culprit_name} (PID {culprit_pid}) is still active but reduced from {reported_value:.1f}% to {top['mem_percent']:.1f}% memory ({top['rss_mb']:.0f}MB RSS)"
                tech = (
                    f"The spike has partially subsided but {top['name']} is still consuming "
                    f"{top['mem_percent']:.1f}% memory ({top['rss_mb']:.0f}MB RSS) aggregated across all instances."
                )
                expert_summary = f"Memory spike on {host}: {culprit_name} (PID {culprit_pid}) reduced from {reported_value:.1f}% to {top['mem_percent']:.1f}% but is still consuming significant memory."
                recommendations = _build_expert_recommendations(culprit_name, str(culprit_pid), "memory", reported_value, host)

            return {
                "detected_cause": detected_cause,
                "confidence": 0.9,
                "severity": context.severity,
                "impact": f"Memory on {host} is still elevated",
                "is_temporary": False,
                "is_expected": False,
                "technical_explanation": tech,
                "evidence": _build_evidence_items(processes, load_avg, errors, failed_svcs),
                "recommendations": recommendations,
                "requires_action": True,
                "expert_summary": expert_summary,
            }

        # Case 3: Truly subsided
        detected_cause = f"{culprit_name} (PID {culprit_pid}) caused the spike but has since finished or reduced"
        expert_summary = f"Memory spike of {reported_value:.1f}% on {host} was caused by {culprit_name} (PID {culprit_pid}). Process has since finished or reduced to {top['mem_percent']:.1f}%."
        recommendations = _build_expert_recommendations(culprit_name, str(culprit_pid), "memory", reported_value, host) if reason != "current_top_confirmed" else []

        return {
            "detected_cause": detected_cause,
            "confidence": 0.95,
            "severity": context.severity,
            "impact": f"Memory on {host} was elevated but has returned to normal",
            "is_temporary": True,
            "is_expected": False,
            "technical_explanation": (
                f"The diagnostic captured process data after the spike ended. "
                f"The highest memory process is {top['name']} at {top['mem_percent']:.1f}% "
                f"({top['rss_mb']:.0f}MB RSS), well below the reported {reported_value:.1f}%."
            ),
            "evidence": _build_evidence_items(processes, load_avg, errors, failed_svcs),
            "recommendations": recommendations,
            "requires_action": False,
            "expert_summary": expert_summary,
        }

    elif resource_type == "disk":
        mounts = _extract_disk_usage(diagnostic_output)
        if not mounts:
            return None

        top = mounts[0]
        use_pct = top["use_percent"]
        large_dirs = _extract_large_directories(diagnostic_output)

        # Build disk-specific evidence
        evidence = []
        for m in mounts[:5]:
            evidence.append({
                "source": "df output",
                "finding": f"{m['mount']}: {m['use_percent']:.0f}% used ({m['used']} / {m['size']})",
                "timestamp": "",
            })
        for d in large_dirs[:5]:
            evidence.append({
                "source": "du output",
                "finding": f"{d['path']}: {d['size']}",
                "timestamp": "",
            })

        mount_point = top["mount"]
        # Enrich detected_cause with the top disk consumer if available
        if large_dirs:
            top_dir = large_dirs[0]
            detected_cause = f"Filesystem {mount_point} at {use_pct:.0f}% usage — {top_dir['path']} is the largest directory ({top_dir['size']})"
        else:
            detected_cause = f"Filesystem {mount_point} at {use_pct:.0f}% usage"

        # Case 1: Active (still near or above threshold)
        if use_pct >= reported_value - 10:
            return {
                "detected_cause": detected_cause,
                "confidence": 0.92,
                "severity": context.severity,
                "impact": f"Disk space on {host}",
                "is_temporary": False,
                "is_expected": False,
                "technical_explanation": (
                    f"The diagnostic shows {mount_point} is at {use_pct:.0f}% usage, "
                    f"close to the reported spike of {reported_value:.0f}%. "
                    f"This is a critical disk space condition requiring immediate attention."
                ),
                "evidence": evidence,
                "recommendations": _build_disk_recommendations(mount_point, large_dirs),
                "requires_action": True,
                "expert_summary": f"Disk usage alert confirmed: {mount_point} at {use_pct:.0f}% on {host}. Immediate cleanup or expansion required.",
            }

        # Case 2: Reduced but still high
        if use_pct >= 70:
            return {
                "detected_cause": detected_cause,
                "confidence": 0.9,
                "severity": context.severity,
                "impact": f"Disk space on {host} is still elevated",
                "is_temporary": False,
                "is_expected": False,
                "technical_explanation": (
                    f"The diagnostic shows {mount_point} at {use_pct:.0f}% usage, "
                    f"reduced from the reported {reported_value:.0f}% but still above safe levels (70%)."
                ),
                "evidence": evidence,
                "recommendations": _build_disk_recommendations(mount_point, large_dirs),
                "requires_action": True,
                "expert_summary": f"Disk usage on {host}: {mount_point} reduced from {reported_value:.0f}% to {use_pct:.0f}%, still requires cleanup.",
            }

        # Case 3: Subsided
        return {
            "detected_cause": detected_cause,
            "confidence": 0.95,
            "severity": context.severity,
            "impact": f"Disk space on {host} has returned to normal",
            "is_temporary": True,
            "is_expected": False,
            "technical_explanation": (
                f"The diagnostic shows {mount_point} at {use_pct:.0f}% usage, "
                f"well below the reported {reported_value:.0f}%. "
                f"Disk space has been freed up or the alert was transient."
            ),
            "evidence": evidence,
            "recommendations": [],
            "requires_action": False,
            "expert_summary": f"Disk usage alert on {host} has subsided: {mount_point} is now at {use_pct:.0f}% (was {reported_value:.0f}%).",
        }

    # Unknown resource type — fall back to AI
    return None


# ─── AI Fallback (only for ambiguous cases) ─────────────────────────────────

SYSTEM_PROMPT = """You are an expert SRE interpreting Linux server diagnostics.

RULES:
1. ONLY use evidence below. Never invent data.
2. If NO high CPU/memory/disk processes are visible, state EXPLICITLY: "Spike has subsided — no active high-consuming processes."
3. Name exact processes, PIDs, and CPU% when identifying culprits.
4. Do NOT blame SSH sessions, users, or generic causes without evidence.
5. Do NOT suggest destructive actions. Interpret only.
6. Respond with ONLY a valid JSON object. No markdown, no prose."""


def _build_ai_prompt(context: ResourceContext, diagnostic_output: str) -> str:
    """Build compact prompt for AI fallback on ambiguous cases."""
    processes = (
        _extract_top_cpu_processes(diagnostic_output)
        if context.resource_type == "cpu"
        else _extract_top_memory_processes(diagnostic_output)
    )
    load_avg = _extract_load_average(diagnostic_output)
    errors = _extract_recent_errors(diagnostic_output)[:3]
    failed_svcs = _extract_failed_services(diagnostic_output)[:3]

    proc_lines = "\n".join(
        f"  - {p['name']} (PID {p['pid']}): CPU={p.get('cpu_percent', 0):.1f}%, MEM={p.get('mem_percent', 0):.1f}%"
        for p in processes[:8]
    )

    error_lines = "\n".join(f"  - {e[:100]}" for e in errors)
    svc_lines = "\n".join(f"  - {s}" for s in failed_svcs)

    prompt = f"""{SYSTEM_PROMPT}

ANOMALY: {context.resource_type.upper()} at {context.current_value:.1f}{context.unit} on {context.affected_host} (threshold: {context.threshold:.1f}{context.unit})

TOP PROCESSES:
{proc_lines or "  (no process data)"}

LOAD AVERAGE: {load_avg or "unknown"}

RECENT ERRORS:
{error_lines or "  (none)"}

FAILED SERVICES:
{svc_lines or "  (none)"}

TASK: Is the spike active? List ALL significant contributors with exact PIDs and resource %.

OUTPUT — ONLY JSON:
{{"detected_cause":"...","confidence":0.0,"severity":"...","impact":"...","is_temporary":false,"is_expected":false,"technical_explanation":"...","evidence":[{{"source":"...","finding":"..."}}],"recommendations":[{{"action":"...","priority":1,"risk":"low"}}],"requires_action":false,"expert_summary":"..."}}
"""
    return prompt


def _parse_findings(raw_response: str) -> Dict[str, Any]:
    """Parse the LLM response into structured DiagnosticFindings."""
    if not raw_response or not raw_response.strip():
        return _fallback_findings("AI returned empty response")

    text = raw_response.strip()

    # Try to extract JSON from markdown/code fences
    for fence in ("```json", "```"):
        if fence in text:
            parts = text.split(fence)
            for part in parts[1:]:
                candidate = part.strip().strip("`").strip()
                if candidate.startswith("{"):
                    text = candidate
                    break

    # Try direct JSON parse first
    try:
        findings = json.loads(text)
        if isinstance(findings, dict) and "detected_cause" in findings:
            return _normalize_findings(findings)
    except json.JSONDecodeError:
        pass

    # Fallback: use brace counting to find the outermost JSON object
    start = text.find("{")
    if start != -1:
        brace_count = 0
        in_string = False
        escape_next = False
        for i, ch in enumerate(text[start:], start=start):
            if escape_next:
                escape_next = False
                continue
            if ch == "\\":
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if not in_string:
                if ch == "{":
                    brace_count += 1
                elif ch == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        try:
                            findings = json.loads(text[start:i + 1])
                            if isinstance(findings, dict) and "detected_cause" in findings:
                                return _normalize_findings(findings)
                        except json.JSONDecodeError:
                            pass
                        break

    logger.warning("diagnostic_interpreter_parse_failed", raw_preview=text[:300], text_len=len(text))
    return _fallback_findings("Could not parse AI response into structured findings")


def _normalize_findings(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize and validate the parsed findings."""
    defaults = {
        "detected_cause": "Unknown — interpretation unavailable",
        "confidence": 0.0,
        "severity": "medium",
        "impact": "Unknown",
        "is_temporary": False,
        "is_expected": False,
        "technical_explanation": "",
        "evidence": [],
        "recommendations": [],
        "requires_action": True,
        "expert_summary": "Diagnostic interpretation unavailable.",
    }

    result = dict(defaults)
    result.update(findings)

    if result["severity"] not in ("low", "medium", "high", "critical"):
        result["severity"] = "medium"

    try:
        result["confidence"] = max(0.0, min(1.0, float(result["confidence"])))
    except (ValueError, TypeError):
        result["confidence"] = 0.0

    if not isinstance(result["evidence"], list):
        result["evidence"] = []
    result["evidence"] = [e for e in result["evidence"] if isinstance(e, dict)]

    if not isinstance(result["recommendations"], list):
        result["recommendations"] = []
    result["recommendations"] = [r for r in result["recommendations"] if isinstance(r, dict)]

    return result


def _fallback_findings(reason: str) -> Dict[str, Any]:
    """Return fallback findings when AI interpretation fails."""
    return {
        "detected_cause": f"Diagnostic completed but {reason}",
        "confidence": 0.0,
        "severity": "medium",
        "impact": "Unknown",
        "is_temporary": False,
        "is_expected": False,
        "technical_explanation": f"The AI interpretation step failed: {reason}. Please review the raw diagnostic output manually.",
        "evidence": [],
        "recommendations": [
            {
                "action": "Review raw diagnostic output manually",
                "priority": 1,
                "risk": "none",
                "rationale": "AI interpretation failed",
            }
        ],
        "requires_action": True,
        "expert_summary": "Diagnostic data collected but interpretation unavailable.",
    }


async def interpret_diagnostic_results(
    context: ResourceContext,
    diagnostic_output: str,
) -> Dict[str, Any]:
    """
    Interpret diagnostic playbook output.

    Tries rule-based interpretation first (fast, accurate, deterministic).
    Falls back to AI only for ambiguous cases.
    """
    # ── Phase 1: Rule-based (primary) ──
    rule_result = _rule_based_interpretation(context, diagnostic_output)
    if rule_result is not None:
        logger.info(
            "diagnostic_rule_based_interpretation",
            host=context.affected_host,
            resource_type=context.resource_type,
            cause=rule_result["detected_cause"][:80],
            confidence=rule_result["confidence"],
        )
        return rule_result

    # ── Phase 2: AI fallback (ambiguous cases) ──
    logger.info(
        "diagnostic_ai_fallback",
        host=context.affected_host,
        resource_type=context.resource_type,
        reason="rule_based_ambiguous",
    )

    settings = get_settings()
    prompt = _build_ai_prompt(context, diagnostic_output)

    try:
        raw_response = await asyncio.wait_for(
            _call_llm(prompt),
            timeout=getattr(settings, "llm_timeout", getattr(settings, "ollama_timeout", 60)),
        )
    except asyncio.TimeoutError:
        logger.warning("diagnostic_interpreter_timeout", host=context.affected_host)
        return _fallback_findings("AI interpretation timed out")
    except Exception as e:
        logger.error("diagnostic_interpreter_failed", host=context.affected_host, error=str(e))
        return _fallback_findings(f"AI interpretation error: {e}")

    findings = _parse_findings(raw_response)

    logger.info(
        "diagnostic_interpretation_complete",
        host=context.affected_host,
        cause=findings["detected_cause"][:80],
        confidence=findings["confidence"],
        severity=findings["severity"],
        requires_action=findings["requires_action"],
    )

    return findings
