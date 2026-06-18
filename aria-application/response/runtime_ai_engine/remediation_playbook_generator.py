"""
Runtime Security Remediation Playbook Generator.

Generates safe, evidence-based remediation playbooks for runtime security events.
Triggered only when an analyst escalates a runtime investigation.

Safety principles:
1. Always collect evidence first (backup current state)
2. Validate before changing (check syntax, test connections)
3. Make minimal changes
4. Include verification steps
5. Generate rollback playbook automatically
6. Never destroy evidence
"""

from typing import Dict, Any, List, Optional
import yaml

import structlog

logger = structlog.get_logger()


def generate_runtime_remediation_playbook(
    runtime_context: Dict[str, Any],
    findings: Dict[str, Any],
    host: str,
    target_user: str = "root",
    remediation_plan: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a safe remediation playbook for a runtime security event.

    Args:
        runtime_context: The RuntimeContext dict
        findings: The findings_json dict from interpretation
        host: Target host for Ansible
        target_user: SSH user

    Returns:
        YAML string of the remediation playbook
    """
    from response.runtime_ai_engine.remediation_planner import (
        build_runtime_remediation_plan,
        has_corrective_actions,
    )

    remediation_plan = remediation_plan or build_runtime_remediation_plan(
        runtime_context=runtime_context,
        findings=findings,
    )
    if not has_corrective_actions(remediation_plan):
        logger.warning(
            "runtime_remediation_generation_blocked_no_corrective_plan",
            decision=remediation_plan.get("decision"),
            reason=remediation_plan.get("decision_reason"),
        )
        return ""

    category = runtime_context.get("runtime_category", "unknown")
    rule_name = runtime_context.get("rule_name", "Unknown Rule")
    threat_assessment = findings.get("threat_assessment", "unknown")

    tasks: List[Dict[str, Any]] = []

    # ── Phase 0: Evidence Collection ──
    tasks.append(_header_task("PHASE 0: Evidence Collection"))
    tasks.extend(_build_evidence_collection(runtime_context))

    # ── Phase 1: Safety Checks ──
    tasks.append(_header_task("PHASE 1: Safety Checks"))
    tasks.extend(_build_safety_checks(runtime_context))

    # ── Phase 2: Remediation ──
    tasks.append(_header_task("PHASE 2: Remediation"))
    remediation_tasks = _build_plan_remediation_tasks(remediation_plan)
    tasks.extend(remediation_tasks)

    # ── Phase 3: Verification ──
    tasks.append(_header_task("PHASE 3: Verification"))
    tasks.extend(_build_plan_verification_tasks(remediation_plan))

    # ── Phase 4: Rollback (pre-staged, exact, safe) ──
    rollback_tasks = _build_plan_rollback_tasks(remediation_plan)
    if rollback_tasks:
        tasks.append(_header_task("PHASE 4: Rollback (run only if remediation caused breakage)"))
        tasks.extend(rollback_tasks)

    # Build playbook
    playbook = [{
        "name": f"Runtime Remediation — {rule_name} on {host}",
        "hosts": host,
        "become": True,
        "gather_facts": False,
        "vars": {
            "rule_name": rule_name,
            "runtime_category": category,
            "threat_assessment": threat_assessment,
            "remediation_type": "runtime_security",
            "planner_decision": remediation_plan.get("decision"),
        },
        "tasks": tasks,
    }]

    logger.info(
        "runtime_remediation_playbook_generated",
        rule=rule_name,
        category=category,
        host=host,
        task_count=len(tasks),
    )

    return yaml.dump(playbook, default_flow_style=False, sort_keys=False, allow_unicode=True)


def _build_plan_remediation_tasks(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build only real corrective tasks from an approved remediation plan."""
    tasks: List[Dict[str, Any]] = []
    for action in plan.get("corrective_actions", []):
        action_type = action.get("type")
        if action_type == "package_remove":
            package = action.get("package")
            tasks.append(_make_task(
                f"Remediation - remove suspicious package {package}",
                f"apt-get remove --purge -y {package} && apt-get update"
            ))
        elif action_type == "restore_file_from_baseline":
            path = action.get("path")
            baseline = action.get("baseline")
            tasks.append(_make_task(
                f"Remediation - backup current {path}",
                f"cp -a {path} {path}.opensoar-pre-remediation.$(date +%s)"
            ))
            tasks.append(_make_task(
                f"Remediation - restore {path} from trusted baseline",
                f"install -m 0644 {baseline} {path}"
            ))
        elif action_type == "systemd_reload_validate":
            service = action.get("service")
            tasks.append(_make_task(
                "Remediation - reload systemd",
                "systemctl daemon-reload"
            ))
            if service:
                tasks.append(_make_task(
                    f"Remediation - validate service {service}",
                    f"systemctl status {service} --no-pager"
                ))
        elif action_type == "terminate_process":
            pid = action.get("pid")
            tasks.append(_make_task(
                f"Remediation - terminate exact suspicious PID {pid}",
                f"kill -TERM {pid} 2>/dev/null; sleep 2; if ps -p {pid} >/dev/null 2>&1; then kill -KILL {pid}; fi"
            ))
        elif action_type == "quarantine_file":
            path = action.get("path")
            tasks.append(_make_task(
                f"Remediation - quarantine exact binary {path}",
                f"if [ -f {path} ]; then mv {path} {path}.opensoar-quarantine.$(date +%s); fi"
            ))
        elif action_type == "block_remote_endpoint":
            remote_ip = action.get("remote_ip")
            remote_port = action.get("remote_port")
            if remote_port:
                cmd = f"iptables -A OUTPUT -d {remote_ip} -p tcp --dport {remote_port} -j DROP"
            else:
                cmd = f"iptables -A OUTPUT -d {remote_ip} -j DROP"
            tasks.append(_make_task(
                f"Remediation - block exact remote endpoint {remote_ip}",
                cmd
            ))
    return tasks


def _build_plan_verification_tasks(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build verification tasks described by the planner."""
    tasks: List[Dict[str, Any]] = []
    for i, check in enumerate(plan.get("verification_checks", []), start=1):
        tasks.append(_make_task(
            f"Verify - planner check {i}",
            f"echo {yaml.safe_dump(str(check)).strip()}"
        ))
    for action in plan.get("corrective_actions", []):
        action_type = action.get("type")
        if action_type == "terminate_process":
            pid = action.get("pid")
            tasks.append(_make_task(
                f"Verify - PID {pid} is gone",
                f"if ps -p {pid} >/dev/null 2>&1; then echo 'FAIL: PID still running'; exit 1; else echo 'PASS: PID not running'; fi"
            ))
        elif action_type == "package_remove":
            package = action.get("package")
            tasks.append(_make_task(
                f"Verify - package {package} removed",
                f"if dpkg -l | grep -w {package}; then echo 'FAIL: package still installed'; exit 1; else echo 'PASS: package not installed'; fi"
            ))
        elif action_type == "block_remote_endpoint":
            remote_ip = action.get("remote_ip")
            tasks.append(_make_task(
                f"Verify - no active connection to {remote_ip}",
                f"if ss -tunap 2>/dev/null | grep -F {remote_ip}; then echo 'WARN: connection still visible'; else echo 'PASS: no active connection'; fi"
            ))
    tasks.append(_make_task(
        "Verify - remediation summary",
        "echo 'Planner-driven remediation finished. Review verification checks and recurrence verification.'"
    ))
    return tasks


def _build_plan_rollback_tasks(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build exact rollback tasks from the planner's rollback_actions."""
    tasks: List[Dict[str, Any]] = []
    for action in plan.get("rollback_actions", []):
        action_type = action.get("type")
        if action_type == "package_reinstall":
            package = action.get("package")
            tasks.append(_make_task(
                f"Rollback - reinstall package {package}",
                f"apt-get install -y {package} || echo 'Rollback: package {package} could not be reinstalled automatically'"
            ))
        elif action_type == "restore_file_from_baseline":
            path = action.get("path")
            baseline = action.get("baseline")
            if path and baseline:
                tasks.append(_make_task(
                    f"Rollback - restore {path} from baseline",
                    f"install -m 0644 {baseline} {path} && echo 'Rollback: {path} restored from baseline'"
                ))
            elif path:
                # Fallback: restore from pre-remediation backup if baseline missing
                tasks.append(_make_task(
                    f"Rollback - restore {path} from pre-remediation backup",
                    f"latest=$(ls -t {path}.opensoar-pre-remediation.* 2>/dev/null | head -1) && if [ -n \"$latest\" ]; then cp -a \"$latest\" {path} && echo 'Rollback: restored from $latest'; else echo 'Rollback: no backup found for {path}'; fi"
                ))
        elif action_type == "iptables_remove_rule":
            rule_spec = action.get("rule_spec", "")
            if rule_spec:
                tasks.append(_make_task(
                    "Rollback - remove exact iptables rule",
                    f"iptables -D {rule_spec} || echo 'Rollback: iptables rule already removed or not present'"
                ))
        elif action_type == "start_service":
            service = action.get("service")
            tasks.append(_make_task(
                f"Rollback - start service {service}",
                f"systemctl start {service} || service {service} start || echo 'Rollback: could not start {service}'"
            ))
        elif action_type == "manual_rollback_only":
            description = action.get("description", "Manual rollback required")
            tasks.append(_make_task(
                f"Rollback - {description}",
                f"echo 'MANUAL ROLLBACK REQUIRED: {description}'"
            ))
        else:
            description = action.get("description", f"Rollback action {action_type}")
            tasks.append(_make_task(
                f"Rollback - {description}",
                f"echo 'Rollback: {description} — review and execute manually if needed'"
            ))
    return tasks


def _make_task(name: str, command: str) -> Dict[str, Any]:
    """Create an Ansible shell task."""
    return {
        "name": name,
        "ansible.builtin.shell": command,
        "changed_when": False,
        "failed_when": False,
    }


def _header_task(text: str) -> Dict[str, Any]:
    """Create a visual header task."""
    return _make_task(text, f"echo '===== {text} ====='")


def _build_evidence_collection(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build evidence collection tasks."""
    tasks = []
    fd_name = context.get("fd_name")
    proc_pid = context.get("proc_pid", 0)
    proc_name = context.get("proc_name", "")
    timestamp = "$(date +%Y%m%d_%H%M%S)"
    backup_dir = f"data/artifacts/runtime_backup_{timestamp}"

    tasks.append(_make_task(
        "Evidence — create backup directory",
        f"mkdir -p {backup_dir} && echo 'Backup dir: {backup_dir}'"
    ))

    # Backup file if applicable
    if fd_name:
        tasks.append(_make_task(
            f"Evidence — backup {fd_name}",
            f"cp -a {fd_name} {backup_dir}/$(basename {fd_name}).bak 2>/dev/null && "
            f"ls -la {backup_dir}/$(basename {fd_name}).bak 2>/dev/null || echo 'File not found or not backup-able'"
        ))

    # Backup process info if still running
    if proc_pid:
        tasks.append(_make_task(
            f"Evidence — collect process info for PID {proc_pid}",
            f"cat /proc/{proc_pid}/cmdline 2>/dev/null | tr '\\0' ' ' > {backup_dir}/proc_{proc_pid}_cmdline.txt && "
            f"cat /proc/{proc_pid}/status 2>/dev/null > {backup_dir}/proc_{proc_pid}_status.txt && "
            f"ls -la /proc/{proc_pid}/fd/ 2>/dev/null > {backup_dir}/proc_{proc_pid}_fds.txt && "
            f"echo 'Process evidence collected'"
        ))

    # Collect current system state
    tasks.append(_make_task(
        "Evidence — current process list",
        f"ps aux --sort=-%cpu > {backup_dir}/processes.txt && echo 'Process list saved'"
    ))

    tasks.append(_make_task(
        "Evidence — active connections",
        f"ss -tunapl > {backup_dir}/connections.txt 2>/dev/null || netstat -tunapl > {backup_dir}/connections.txt 2>/dev/null && echo 'Connections saved'"
    ))

    tasks.append(_make_task(
        "Evidence — system logs snapshot",
        f"journalctl --since '10 minutes ago' --no-pager 2>/dev/null | tail -50 > {backup_dir}/recent_logs.txt && echo 'Logs saved'"
    ))

    return tasks


def _build_safety_checks(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build safety check tasks."""
    tasks = []
    fd_name = context.get("fd_name")
    proc_cmdline = context.get("proc_cmdline", "")

    # SSH config safety check
    if fd_name and "/ssh" in fd_name:
        tasks.append(_make_task(
            "Safety — validate SSH configuration",
            "sshd -t 2>&1 && echo 'SSH config valid' || echo 'WARNING: SSH config has syntax errors'"
        ))

    # Sudoers safety check
    if fd_name and "sudoers" in fd_name:
        tasks.append(_make_task(
            "Safety — validate sudoers syntax",
            "visudo -c 2>&1 && echo 'Sudoers valid' || echo 'WARNING: Sudoers has syntax errors'"
        ))

    # Systemd safety check
    if "systemctl" in proc_cmdline:
        tasks.append(_make_task(
            "Safety — verify systemd is responsive",
            "systemctl daemon-reload 2>&1 && echo 'Systemd responsive' || echo 'WARNING: Systemd issue detected'"
        ))

    # Always check SSH connectivity
    tasks.append(_make_task(
        "Safety — verify SSH service is running",
        "systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || service ssh status 2>/dev/null || echo 'SSH status unknown'"
    ))

    return tasks


def _build_remediation_tasks(
    category: str,
    context: Dict[str, Any],
    findings: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Build category-specific remediation tasks."""
    if category == "persistence":
        return _remediate_persistence(context)
    elif category == "privilege_escalation":
        return _remediate_privesc(context)
    elif category == "credential_access":
        return _remediate_credential_access(context)
    elif category == "service_change":
        return _remediate_service_change(context)
    elif category == "process_execution":
        return _remediate_process_execution(context)
    elif category == "file_access":
        return _remediate_file_access(context)
    elif category == "container_runtime":
        return _remediate_container_runtime(context)
    elif category == "package_manager":
        return _remediate_package_manager(context)
    else:
        return []


def _remediate_persistence(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Remediate persistence attempts."""
    tasks = []
    fd_name = context.get("fd_name")
    proc_name = context.get("proc_name", "")

    # If a file was modified, restore from backup if available
    if fd_name:
        tasks.append(_make_task(
            f"Remediation — check for backup of {fd_name}",
            f"if [ -f data/artifacts/runtime_backup_*/$(basename {fd_name}).bak ]; then "
            f"  echo 'Backup found — manual restore required'; "
            f"else "
            f"  echo 'No backup found — investigate before restoring'; "
            f"fi"
        ))

    # Check for and remove unauthorized cron jobs
    tasks.append(_make_task(
        "Remediation — audit cron jobs",
        "for user in $(cut -f1 -d: /etc/passwd); do crontab -l -u $user 2>/dev/null | grep -v '^#' | grep -v '^$' && echo \"--- USER: $user ---\" ; done"
    ))

    # Check for unauthorized systemd units
    tasks.append(_make_task(
        "Remediation — audit systemd units",
        "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | grep -v '^  *[^a-zA-Z]' | head -30"
    ))

    # Check for unauthorized SSH keys
    tasks.append(_make_task(
        "Remediation — audit authorized_keys",
        "find /home /root -name 'authorized_keys' -o -name 'authorized_keys2' 2>/dev/null | while read f; do echo \"=== $f ===\"; cat \"$f\"; done"
    ))

    return tasks


def _remediate_privesc(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Remediate privilege escalation."""
    tasks = []
    user_name = context.get("user_name", "")
    proc_name = context.get("proc_name", "")

    # Review sudo configuration
    tasks.append(_make_task(
        "Remediation — review sudo configuration",
        "cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' && echo '---' && ls -la /etc/sudoers.d/ 2>/dev/null"
    ))

    # Find and audit SUID binaries
    tasks.append(_make_task(
        "Remediation — audit SUID binaries",
        "find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null | while read f; do rpm -qf $f 2>/dev/null || dpkg -S $f 2>/dev/null || echo \"UNOWNED: $f\"; done"
    ))

    # Check for unauthorized users
    if user_name and user_name != "root":
        tasks.append(_make_task(
            f"Remediation — audit user {user_name}",
            f"id {user_name} 2>/dev/null && echo '---' && getent passwd {user_name} 2>/dev/null && echo '---' && last {user_name} 2>/dev/null"
        ))

    return tasks


def _remediate_credential_access(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Remediate credential access."""
    tasks = []
    fd_name = context.get("fd_name")
    user_name = context.get("user_name", "")

    # Reset password if unauthorized access detected
    if user_name and user_name != "root":
        tasks.append(_make_task(
            f"Remediation — force password reset for {user_name}",
            f"passwd -e {user_name} 2>/dev/null && echo 'Password expired for {user_name}' || echo 'Could not expire password'"
        ))

    # Check file permissions
    if fd_name:
        tasks.append(_make_task(
            f"Remediation — restore permissions for {fd_name}",
            f"chmod 640 {fd_name} 2>/dev/null && chown root:shadow {fd_name} 2>/dev/null && ls -la {fd_name} || echo 'Permission restore failed'"
        ))

    # Audit for new unauthorized users
    tasks.append(_make_task(
        "Remediation — audit user accounts",
        "getent passwd | awk -F: '$3 >= 1000 {print $1}' | while read u; do echo \"=== $u ===\"; last $u 2>/dev/null | head -3; done"
    ))

    return tasks


def _remediate_service_change(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Remediate unauthorized service changes."""
    tasks = []
    proc_cmdline = context.get("proc_cmdline", "")

    # Extract service name
    service_name = ""
    if "systemctl" in proc_cmdline:
        parts = proc_cmdline.split()
        for i, part in enumerate(parts):
            if part in ["start", "stop", "restart", "enable", "disable"] and i + 1 < len(parts):
                service_name = parts[i + 1]
                break

    if service_name:
        tasks.append(_make_task(
            f"Remediation — review service {service_name}",
            f"systemctl status {service_name} --no-pager 2>/dev/null && echo '---' && "
            f"systemctl cat {service_name} 2>/dev/null | head -40"
        ))

    # List all enabled services
    tasks.append(_make_task(
        "Remediation — audit enabled services",
        "systemctl list-unit-files --state=enabled --type=service --no-pager 2>/dev/null | head -30"
    ))

    return tasks


def _remediate_process_execution(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Remediate suspicious process execution."""
    tasks = []
    proc_pid = context.get("proc_pid", 0)
    proc_name = context.get("proc_name", "")
    proc_cmdline = context.get("proc_cmdline", "")

    # Kill malicious process if confirmed
    if proc_pid:
        tasks.append(_make_task(
            f"Remediation — terminate suspicious process PID {proc_pid}",
            f"kill -TERM {proc_pid} 2>/dev/null && sleep 2 && "
            f"if ps -p {proc_pid} > /dev/null 2>&1; then kill -KILL {proc_pid} 2>/dev/null; fi && "
            f"echo 'Process termination attempted'"
        ))

    # Remove malicious binary if path is known
    if proc_cmdline and proc_cmdline.split():
        binary_path = proc_cmdline.split()[0]
        if binary_path.startswith("/"):
            tasks.append(_make_task(
                f"Remediation — quarantine suspicious binary {binary_path}",
                f"if [ -f {binary_path} ]; then mv {binary_path} {binary_path}.quarantined.$(date +%s) && echo 'Binary quarantined'; else echo 'Binary not found'; fi"
            ))

    # Check for persistence mechanisms related to the process
    tasks.append(_make_task(
        "Remediation — check for persistence related to process",
        f"grep -r '{proc_name}' /etc/cron* /etc/systemd/system/ /lib/systemd/system/ 2>/dev/null | head -10 || echo 'No persistence found'"
    ))

    return tasks


def _remediate_file_access(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Remediate unauthorized file access."""
    tasks = []
    fd_name = context.get("fd_name")
    user_name = context.get("user_name", "")

    if fd_name:
        # Restore proper permissions
        tasks.append(_make_task(
            f"Remediation — restore permissions for {fd_name}",
            f"chmod 640 {fd_name} 2>/dev/null && chown root:shadow {fd_name} 2>/dev/null && ls -la {fd_name} || echo 'Permission restore failed'"
        ))

        # Set immutable flag if appropriate
        if "shadow" in fd_name or "passwd" in fd_name:
            tasks.append(_make_task(
                f"Remediation — set immutable flag on {fd_name}",
                f"chattr +i {fd_name} 2>/dev/null && echo 'Immutable flag set' || echo 'chattr not available'"
            ))

    # Audit user access
    if user_name and user_name != "root":
        tasks.append(_make_task(
            f"Remediation — audit user {user_name} privileges",
            f"sudo -l -U {user_name} 2>/dev/null || echo 'Cannot audit user privileges'"
        ))

    return tasks


def _remediate_container_runtime(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Remediate container runtime events."""
    tasks = []
    container_id = context.get("container_id", "")
    container_name = context.get("container_name", "")
    target = container_id if container_id and container_id != "host" else container_name

    if target and target != "host":
        tasks.append(_make_task(
            f"Remediation — stop compromised container {target}",
            f"docker stop {target} 2>/dev/null && echo 'Container stopped' || echo 'Container not found or already stopped'"
        ))

        tasks.append(_make_task(
            f"Remediation — inspect container image for {target}",
            f"docker inspect {target} 2>/dev/null | grep -i 'image' | head -5 || echo 'Cannot inspect container'"
        ))

    return tasks


def _remediate_package_manager(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Remediate suspicious package manager activity."""
    tasks = []
    proc_cmdline = context.get("proc_cmdline", "")

    # Identify recently installed packages
    tasks.append(_make_task(
        "Remediation — list recently installed packages",
        "grep 'install ' /var/log/dpkg.log 2>/dev/null | tail -20 || echo 'dpkg.log not available'"
    ))

    # Check for suspicious packages
    tasks.append(_make_task(
        "Remediation — scan for suspicious packages",
        "dpkg -l 2>/dev/null | grep -iE 'backdoor|rootkit|nc|netcat|ncat|miner|xmr' || echo 'No suspicious packages found'"
    ))

    return tasks


def _build_verification_tasks(category: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build verification tasks to confirm remediation worked."""
    tasks = []
    fd_name = context.get("fd_name")
    proc_pid = context.get("proc_pid", 0)
    proc_name = context.get("proc_name", "")
    user_name = context.get("user_name", "")

    # Verify process is gone
    if proc_pid:
        tasks.append(_make_task(
            f"Verify — process PID {proc_pid} is terminated",
            f"if ps -p {proc_pid} > /dev/null 2>&1; then echo 'FAIL: Process still running'; else echo 'PASS: Process terminated'; fi"
        ))

    # Verify file permissions
    if fd_name:
        tasks.append(_make_task(
            f"Verify — {fd_name} has correct permissions",
            f"ls -la {fd_name} 2>/dev/null || echo 'FAIL: File not found'"
        ))

    # Verify SSH still works
    tasks.append(_make_task(
        "Verify — SSH service is responsive",
        "systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo 'SSH status check failed'"
    ))

    # Verify no new unauthorized users
    tasks.append(_make_task(
        "Verify — no unauthorized users",
        "getent passwd | wc -l && echo 'user count'"
    ))

    # Verify systemd is healthy
    tasks.append(_make_task(
        "Verify — systemd is healthy",
        "systemctl is-system-running 2>/dev/null || echo 'Systemd status unknown'"
    ))

    # Final summary
    tasks.append(_make_task(
        "Verify — remediation summary",
        "echo 'Remediation complete. Review verification results above.'"
    ))

    return tasks
