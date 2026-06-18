"""
Ansible Execution Engine.

Triggered after analyst approves a playbook.
Writes the playbook + inventory to /tmp/playbooks/, runs ansible-playbook,
captures output line by line, updates PlaybookRun in DB.
On success, triggers fix verifier.
"""
import asyncio
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

import structlog
import yaml
from sqlalchemy import select

from config import get_settings
from response.db import AsyncSessionLocal
from response.models import Investigation, PlaybookRun

logger = structlog.get_logger()
settings = get_settings()

def _ensure_secure_dir(path: Path) -> None:
    """Ensure directory exists with restrictive permissions (0700)."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _write_secure_file(path: Path, content: str) -> None:
    """Write file with 0600 permissions, creating if needed."""
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)


def _safe_extract_tar(tar_path: Path, dest_dir: Path) -> None:
    """Extract tar safely, rejecting path traversal and absolute paths."""
    import tarfile
    dest_dir = dest_dir.resolve()
    with tarfile.open(tar_path, "r:*") as tar:
        for member in tar.getmembers():
            member_path = (dest_dir / member.name).resolve()
            if not str(member_path).startswith(str(dest_dir)):
                raise ValueError(f"Tar member {member.name} attempts path traversal")
            if member.issym() or member.islnk():
                link_target = Path(member.linkname)
                if link_target.is_absolute():
                    raise ValueError(f"Tar member {member.name} has absolute symlink target")
                resolved_link = (dest_dir / link_target).resolve()
                if not str(resolved_link).startswith(str(dest_dir)):
                    raise ValueError(f"Tar member {member.name} has symlink escaping dest")
        tar.extractall(path=dest_dir)


PLAYBOOKS_DIR = Path(get_settings().playbook_dir)
_ensure_secure_dir(PLAYBOOKS_DIR)

# Guard against duplicate concurrent executions of the same investigation
_EXECUTING_IDS: set[str] = set()


def _is_local_connection(host_config: Optional[dict] = None) -> bool:
    """Check if Ansible is configured to run on localhost (no SSH needed).
    If host_config is provided (per-asset), check auth_type and ansible_host first.
    """
    if host_config:
        if host_config.get("auth_type") == "local":
            return True
        host = (host_config.get("ansible_host") or "").lower()
        if host in ("localhost", "127.0.0.1", "::1"):
            return True
    host = (getattr(settings, "ansible_remote_host", None) or "").lower()
    return host in ("localhost", "127.0.0.1", "::1")


def _redact_sensitive(output: str) -> str:
    """Redact passwords and sensitive values from Ansible output and errors."""
    if not output:
        return output
    import re
    # Redact ansible_become_pass values in inventory or output
    redacted = re.sub(r"ansible_become_pass='[^']*'", "ansible_become_pass='***REDACTED***'", output)
    redacted = re.sub(r"ansible_ssh_pass='[^']*'", "ansible_ssh_pass='***REDACTED***'", redacted)
    redacted = re.sub(r"ANSIBLE_SSH_PASS=[^\s]*", "ANSIBLE_SSH_PASS=***REDACTED***", redacted)
    # Redact common password prompt responses
    redacted = re.sub(r"(?i)(password\s*[:=]\s*)\S+", r"\1***REDACTED***", redacted)
    return redacted


async def _get_investigation(investigation_id: str) -> Investigation | None:
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .options(selectinload(Investigation.approval))
        )
        return result.scalar_one_or_none()


async def _update_run(run_id: str, **kwargs):
    from sqlalchemy import update
    async with AsyncSessionLocal() as session:
        await session.execute(
            update(PlaybookRun).where(PlaybookRun.id == run_id).values(**kwargs)
        )
        await session.commit()


async def _update_investigation(investigation_id: str, **kwargs):
    from sqlalchemy import update
    kwargs["updated_at"] = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        await session.execute(
            update(Investigation).where(Investigation.id == investigation_id).values(**kwargs)
        )
        await session.commit()


def _extract_verification_plan(playbook_yaml: str) -> dict | None:
    """Extract a normalized verification plan from a remediation playbook."""
    if not playbook_yaml:
        return None
    try:
        pb = yaml.safe_load(playbook_yaml)
    except Exception:
        return None
    if not isinstance(pb, list):
        return None

    for play in pb:
        if not isinstance(play, dict):
            continue
        for task in play.get("tasks", []):
            if not isinstance(task, dict):
                continue
            for key, val in task.items():
                if not isinstance(val, dict):
                    continue
                # iptables rule
                if "iptables" in key:
                    chain = val.get("chain", "INPUT")
                    source = val.get("source", val.get("src", ""))
                    jump = val.get("jump", "")
                    protocol = val.get("protocol", "")
                    destination_port = val.get("destination_port", "")
                    if source and jump:
                        return {
                            "type": "iptables_rule",
                            "chain": chain,
                            "source": source,
                            "jump": jump,
                            "protocol": protocol or None,
                            "port": destination_port or None,
                        }
                # file quarantine
                if key in ("ansible.builtin.copy", "ansible.builtin.command", "ansible.builtin.shell"):
                    task_str = str(val)
                    if "quarantine" in task_str:
                        src = val.get("src", "")
                        dest = val.get("dest", "")
                        if src and dest:
                            return {
                                "type": "file_quarantine",
                                "original_path": src,
                                "quarantine_path": dest,
                            }
                        # Try to parse mv command
                        if isinstance(val, str) and "mv " in val:
                            parts = val.split()
                            if len(parts) >= 3:
                                return {
                                    "type": "file_quarantine",
                                    "original_path": parts[1],
                                    "quarantine_path": parts[2],
                                }
    return None


def _write_playbook(investigation_id: str, playbook_yaml: str) -> Path:
    """Write playbook YAML to disk. Returns path."""
    path = PLAYBOOKS_DIR / f"{investigation_id}.yml"
    path.write_text(playbook_yaml, encoding="utf-8")
    return path


def _write_inventory(investigation_id: str, target_host: str, target_user: str, host_config: Optional[dict] = None) -> Path:
    """Write Ansible inventory file. Returns path.
    If host_config is provided (from MonitoredAsset.ansible_config_json), uses per-host settings.
    Otherwise falls back to global settings.
    """
    auth_type = "private_key"
    if host_config:
        auth_type = host_config.get("auth_type", "private_key")
        ssh_port = host_config.get("ansible_port", 22)
        become_method = host_config.get("become_method", "sudo")
        become_password = ""
        become_secret_ref = host_config.get("become_password_secret_ref", "")
        if become_secret_ref:
            import os
            become_password = os.environ.get(become_secret_ref, "")
        elif settings.ansible_become_password:
            become_password = settings.ansible_become_password
    else:
        ssh_port = settings.ansible_ssh_port or 22
        become_method = settings.ansible_become_method or "sudo"
        become_password = settings.ansible_become_password or ""

    # Resolve auth credentials based on auth_type
    ssh_key = ""
    ssh_password = ""
    if host_config:
        if auth_type == "private_key":
            ssh_key = host_config.get("ssh_key_ref", "")
            if not ssh_key and settings.ansible_ssh_key:
                ssh_key = settings.ansible_ssh_key
        elif auth_type == "password":
            direct_password = host_config.get("ansible_ssh_password")
            password_secret_ref = host_config.get("password_secret_ref", "")
            if direct_password:
                ssh_password = direct_password
            elif password_secret_ref:
                import os
                ssh_password = os.environ.get(password_secret_ref, "")
            elif settings.ansible_ssh_password:
                ssh_password = settings.ansible_ssh_password
    else:
        ssh_key = settings.ansible_ssh_key or ""
        ssh_password = settings.ansible_ssh_password or ""
        if not become_password:
            become_password = ssh_password  # Default to SSH password for global

    key_line = f" ansible_ssh_private_key_file={ssh_key}" if ssh_key else ""
    password_line = f" ansible_ssh_pass='{ssh_password}'" if ssh_password else ""
    become_pass_line = f" ansible_become_pass='{become_password}'" if become_password else ""

    if ssh_password:
        ssh_opts = (
            "-o StrictHostKeyChecking=no "
            "-o PreferredAuthentications=password,keyboard-interactive "
            "-o PasswordAuthentication=yes "
            "-o KbdInteractiveAuthentication=yes "
            "-o ConnectTimeout=15"
        )
    else:
        ssh_opts = (
            "-o StrictHostKeyChecking=no "
            "-o ConnectTimeout=15"
        )
    local_conn = " ansible_connection=local" if (target_host in ("localhost", "127.0.0.1") or auth_type == "local") else ""
    if become_method and become_method.lower() == "none":
        become_line = "ansible_become=no"
    else:
        become_line = f"ansible_become=yes ansible_become_method={become_method} {become_pass_line}"
    # Per-asset ansible_host override (fixes DNS resolution for assets without hostnames)
    ansible_host_line = ""
    if host_config and host_config.get("ansible_host"):
        ansible_host_line = f" ansible_host={host_config['ansible_host']}"
    content = (
        f"[target]\n"
        f"{target_host} ansible_user={target_user}{local_conn}{key_line}{password_line} "
        f"ansible_ssh_common_args='{ssh_opts}' "
        f"ansible_ssh_port={ssh_port} "
        f"{become_line}{ansible_host_line}\n"
    )
    path = PLAYBOOKS_DIR / f"{investigation_id}_inventory"
    _write_secure_file(path, content)
    logger.debug("inventory_written", path=str(path), host=target_host, user=target_user, has_become_password=bool(become_password), has_ssh_password=bool(ssh_password))
    return path


async def _validate_ansible_syntax(playbook_yaml: str, investigation_id: str) -> tuple[bool, str]:
    """
    Validate Ansible playbook syntax using ansible-playbook --syntax-check.
    Returns (is_valid, error_message).
    """
    import tempfile
    import subprocess
    
    # Write playbook to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(playbook_yaml)
        temp_path = f.name
    
    try:
        # Run ansible-playbook --syntax-check
        result = subprocess.run(
            ["ansible-playbook", "--syntax-check", temp_path],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            logger.info("ansible_syntax_valid", investigation_id=investigation_id)
            return True, ""
        else:
            error_msg = result.stderr.strip() or result.stdout.strip() or "Syntax check failed"
            logger.warning("ansible_syntax_invalid", investigation_id=investigation_id, error=error_msg)
            return False, error_msg
            
    except subprocess.TimeoutExpired:
        logger.warning("ansible_syntax_timeout", investigation_id=investigation_id)
        return False, "Syntax check timed out after 30 seconds"
    except FileNotFoundError:
        logger.warning("ansible_syntax_check_not_available", investigation_id=investigation_id)
        return True, "ansible-playbook not installed, skipping syntax check"
    except Exception as e:
        logger.warning("ansible_syntax_check_error", investigation_id=investigation_id, error=str(e))
        return True, f"Could not run syntax check: {e}"
    finally:
        # Clean up temp file
        try:
            import os
            os.unlink(temp_path)
        except:
            pass


async def _get_protected_ips(target_host: str) -> set[str]:
    """Return IPs that must NEVER be blocked by firewall rules."""
    protected = set()
    
    # Target host itself — never block the VM we're protecting
    protected.add(target_host)
    
    # OpenSOAR server IP
    import socket
    try:
        hostname = socket.gethostname()
        own_ip = socket.getaddrinfo(hostname, None, socket.AF_INET)[0][4][0]
        protected.add(own_ip)
    except Exception:
        pass
    
    # Whitelist entries from DB
    try:
        from core.whitelist import get_whitelist_entries
        entries = await get_whitelist_entries()
        for entry in entries:
            if entry.get("type") in ("ip", "subnet"):
                val = entry.get("value", "").strip()
                if "/" not in val:
                    protected.add(val)
    except Exception:
        pass
    
    return protected


def _sanitize_firewall_tasks(playbook_yaml: str, protected_ips: set[str]) -> tuple[bool, str, str]:
    """
    Detect and reject dangerous firewall/iptables tasks that could lock us out.
    Returns (is_safe, error_message, sanitized_yaml).
    """
    import ipaddress
    
    try:
        parsed = yaml.safe_load(playbook_yaml)
    except yaml.YAMLError as e:
        return False, f"Invalid YAML: {e}", playbook_yaml
    
    if not isinstance(parsed, list) or not parsed:
        return True, "", playbook_yaml
    
    errors = []
    
    for play_idx, play in enumerate(parsed):
        if not isinstance(play, dict):
            continue
        tasks = play.get("tasks", [])
        if not isinstance(tasks, list):
            continue
            
        for task_idx, task in enumerate(tasks):
            if not isinstance(task, dict):
                continue
                
            # Get module name (first key that isn't common metadata)
            module = None
            task_args = {}
            module_raw_value = None
            for key, val in task.items():
                if key not in ("name", "ignore_errors", "failed_when", "changed_when", "become", "tags", "vars", "when", "register", "notify", "loop", "with_items"):
                    module = key
                    module_raw_value = val
                    task_args = val if isinstance(val, dict) else {}
                    break
            
            if not module:
                continue
            
            task_name = task.get("name", f"task {task_idx}")
            
            # === ansible.builtin.iptables module checks ===
            if module == "ansible.builtin.iptables":
                chain = task_args.get("chain", "INPUT")
                jump = task_args.get("jump", "")
                source = task_args.get("source") or task_args.get("source_ip") or task_args.get("src")
                destination = task_args.get("destination") or task_args.get("dest")
                destination_port = task_args.get("destination_port") or task_args.get("dport")
                protocol = task_args.get("protocol", "")
                
                # Rule 1: DROP without source is DANGEROUS
                if jump in ("DROP", "REJECT") and not source:
                    errors.append(
                        f"[{task_name}] iptables DROP/REJECT without 'source' — this blocks ALL traffic. "
                        f"Use shell: iptables -A INPUT -s <attacker_ip> -j DROP"
                    )
                    continue
                
                # Rule 2: destination on INPUT chain is DANGEROUS (blocks self)
                if chain == "INPUT" and destination:
                    errors.append(
                        f"[{task_name}] iptables with 'destination' on INPUT chain blocks the VM itself. "
                        f"Use 'source' to block attacker IPs, not 'destination'."
                    )
                    continue
                
                # Rule 3: destination_port 22 without source is DANGEROUS
                if jump in ("DROP", "REJECT") and destination_port == 22 and not source:
                    errors.append(
                        f"[{task_name}] iptables blocks port 22 without source IP — this locks out SSH. "
                        f"Use shell: iptables -A INPUT -s <attacker_ip> -p tcp --dport 22 -j DROP"
                    )
                    continue
                
                # Rule 4: Check protected IPs aren't being blocked
                if jump in ("DROP", "REJECT") and source:
                    src_str = str(source).strip()
                    if src_str in protected_ips:
                        errors.append(
                            f"[{task_name}] iptables blocks protected IP {src_str} — this is a management/whitelist IP."
                        )
                        continue
            
            # === ansible.builtin.service module checks ===
            if module == "ansible.builtin.service":
                svc_name = str(task_args.get("name", "")).lower()
                svc_state = str(task_args.get("state", "")).lower()
                if svc_state in ("stopped", "reloaded", "restarted") and svc_name in ("ssh", "sshd", "ssh.service", "sshd.service", "network", "networking", "network.service", "NetworkManager"):
                    errors.append(
                        f"[{task_name}] stopping/restarting {svc_name} service cuts off management access. "
                        f"Use firewall rules to block attacker IPs instead."
                    )
                    continue
            
            # === ufw / firewalld / nftables module checks ===
            if module in ("ansible.builtin.ufw", "community.general.ufw"):
                errors.append(
                    f"[{task_name}] ufw module is blocked — use shell: iptables -A INPUT -s <attacker_ip> -j DROP instead."
                )
                continue
            if module in ("ansible.builtin.firewalld", "ansible.posix.firewalld"):
                errors.append(
                    f"[{task_name}] firewalld module is blocked — use shell: iptables -A INPUT -s <attacker_ip> -j DROP instead."
                )
                continue
            
            # === shell/command module checks ===
            if module in ("ansible.builtin.shell", "ansible.builtin.command"):
                if isinstance(module_raw_value, str):
                    cmd_text = module_raw_value
                elif isinstance(task_args, dict):
                    cmd_text = str(task_args.get("cmd", ""))
                else:
                    cmd_text = str(module_raw_value)
                cmd_lower = cmd_text.lower()
                
                # Block service stop commands
                if any(x in cmd_lower for x in ("systemctl stop ssh", "systemctl stop sshd", "service ssh stop", "service sshd stop", 
                                                   "systemctl restart ssh", "systemctl restart sshd", "systemctl disable ssh", "systemctl disable sshd",
                                                   "ip link set", "ifconfig .* down", "ip link del", "nmcli conn down")):
                    errors.append(
                        f"[{task_name}] shell command stops/restarts network or SSH service — this cuts off management access."
                    )
                    continue
                
                # Block ufw default-deny or enable
                if any(x in cmd_lower for x in ("ufw enable", "ufw default deny", "ufw reset", "ufw --force enable")):
                    errors.append(
                        f"[{task_name}] ufw command risks locking out management access. Use iptables with explicit source IP instead."
                    )
                    continue
                
                # Block nftables default-deny
                if "nft" in cmd_lower and any(x in cmd_lower for x in ("drop", "reject")) and "-s " not in cmd_lower:
                    errors.append(
                        f"[{task_name}] nftables DROP/REJECT without explicit source IP risks locking out management access."
                    )
                    continue
                
                if "iptables" in cmd_lower:
                    # Check for policy change (-P) to DROP — locks out ALL traffic
                    if "-p " in cmd_lower and ("drop" in cmd_lower or "reject" in cmd_lower):
                        errors.append(
                            f"[{task_name}] shell iptables changes default policy to DROP/REJECT — this blocks ALL incoming traffic and locks out SSH. "
                            f"CRITICAL: This would make the VM unreachable. Use '-A INPUT -s <source_ip> -j DROP' instead."
                        )
                        continue

                    # Check for DROP without -s
                    if ("-j drop" in cmd_lower or "-j reject" in cmd_lower) and "-s " not in cmd_lower:
                        errors.append(
                            f"[{task_name}] shell iptables DROP/REJECT without '-s <source_ip>' — this blocks ALL traffic."
                        )
                        continue

                    # Check for 0.0.0.0/0 as source (blocks everything)
                    if ("-j drop" in cmd_lower or "-j reject" in cmd_lower) and "0.0.0.0/0" in cmd_text:
                        errors.append(
                            f"[{task_name}] shell iptables uses 0.0.0.0/0 as source — this blocks ALL traffic."
                        )
                        continue

                    # Check for empty Jinja2 source variable that may render to nothing
                    if ("-j drop" in cmd_lower or "-j reject" in cmd_lower) and "-s {{" in cmd_lower:
                        errors.append(
                            f"[{task_name}] shell iptables uses Jinja2 template as source IP — this may render to empty and block ALL traffic."
                        )
                        continue

                    # Check for -d on INPUT chain
                    if "-d " in cmd_lower and "input" in cmd_lower:
                        errors.append(
                            f"[{task_name}] shell iptables uses '-d' on INPUT chain — this blocks the VM itself."
                        )
                        continue

                    # Check for port 22 without -s
                    if ("--dport 22" in cmd_lower or "-p tcp" in cmd_lower) and ("-j drop" in cmd_lower or "-j reject" in cmd_lower) and "-s " not in cmd_lower:
                        errors.append(
                            f"[{task_name}] shell iptables blocks port 22 without source IP — this locks out SSH."
                        )
                        continue

                    # Check protected IPs
                    for protected in protected_ips:
                        if protected and protected in cmd_text and ("-j drop" in cmd_lower or "-j reject" in cmd_lower):
                            errors.append(
                                f"[{task_name}] shell iptables blocks protected IP {protected} — this is a management/whitelist IP."
                            )
                            continue
    
    if errors:
        return False, "FIREWALL SAFETY BLOCKED:\n" + "\n".join(f"  - {e}" for e in errors), playbook_yaml
    
    return True, "", playbook_yaml


def _is_noop_playbook(playbook_yaml: str) -> bool:
    """Check if a playbook is just a no-op placeholder."""
    if not playbook_yaml:
        return True
    try:
        parsed = yaml.safe_load(playbook_yaml)
        if not isinstance(parsed, list) or not parsed:
            return True
        for play in parsed:
            if not isinstance(play, dict):
                continue
            for task in play.get("tasks", []):
                if isinstance(task, dict):
                    mod = [k for k in task if k not in ("name", "vars", "when", "ignore_errors", "tags")]
                    if mod and mod[0] != "ansible.builtin.debug":
                        return False
        return True
    except Exception:
        return False


def _generate_hardening_playbook(attack_type: str, target_host: str, investigation_id: str) -> str:
    """Generate sensible hardening tasks based on attack type when none exist in the playbook."""
    tasks = []

    if attack_type == "brute_force":
        tasks = [
            {
                "name": "Harden SSH - set MaxAuthTries to 3",
                "ansible.builtin.lineinfile": {
                    "path": "/etc/ssh/sshd_config",
                    "regexp": "^#?MaxAuthTries",
                    "line": "MaxAuthTries 3",
                    "backup": True,
                },
            },
            {
                "name": "Harden SSH - set ClientAliveInterval",
                "ansible.builtin.lineinfile": {
                    "path": "/etc/ssh/sshd_config",
                    "regexp": "^#?ClientAliveInterval",
                    "line": "ClientAliveInterval 300",
                    "backup": True,
                },
            },
            {
                "name": "Restart SSH service to apply hardening",
                "ansible.builtin.service": {"name": "sshd", "state": "reloaded"},
                "ignore_errors": True,
            },
            {
                "name": "Enable and configure fail2ban",
                "ansible.builtin.shell": (
                    "command -v fail2ban-server >/dev/null 2>&1 && "
                    "(systemctl enable fail2ban 2>/dev/null; systemctl start fail2ban 2>/dev/null; "
                    "fail2ban-client set sshd maxretry 3 2>/dev/null; echo 'fail2ban configured') || "
                    "echo 'fail2ban not installed'"
                ),
                "changed_when": False,
                "ignore_errors": True,
            },
        ]
    elif attack_type == "web_attack":
        tasks = [
            {
                "name": "Harden web server - disable server tokens",
                "ansible.builtin.shell": (
                    "if [ -f /etc/nginx/nginx.conf ]; then "
                    "sed -i 's/server_tokens on/server_tokens off/g' /etc/nginx/nginx.conf 2>/dev/null; "
                    "echo 'nginx tokens disabled'; "
                    "elif [ -f /etc/apache2/conf-available/security.conf ]; then "
                    "sed -i 's/ServerTokens OS/ServerTokens Prod/g' /etc/apache2/conf-available/security.conf 2>/dev/null; "
                    "echo 'apache tokens disabled'; "
                    "else echo 'web server config not found'; fi"
                ),
                "changed_when": False,
                "ignore_errors": True,
            },
            {
                "name": "Check and set restrictive umask",
                "ansible.builtin.shell": "umask 027 || umask 022",
                "changed_when": False,
            },
        ]
    elif attack_type in ("malware", "privilege_escalation", "execution"):
        tasks = [
            {
                "name": "Harden - ensure no SUID binaries in /tmp",
                "ansible.builtin.shell": "find /tmp -perm -4000 -type f -exec chmod u-s {} + 2>/dev/null || true",
                "changed_when": False,
            },
            {
                "name": "Harden - restrict cron to root only",
                "ansible.builtin.file": {
                    "path": "/etc/cron.allow",
                    "state": "touch",
                    "mode": "0640",
                },
            },
            {
                "name": "Harden - set secure sysctl parameters",
                "ansible.builtin.shell": (
                    "sysctl -w kernel.randomize_va_space=2 2>/dev/null || true; "
                    "sysctl -w fs.suid_dumpable=0 2>/dev/null || true; "
                    "echo 'sysctl hardening applied'"
                ),
                "changed_when": False,
            },
        ]
    else:
        tasks = [
            {
                "name": "Harden - ensure iptables persistence",
                "ansible.builtin.shell": (
                    "iptables-save > /etc/iptables/rules.v4 2>/dev/null || "
                    "iptables-save > /etc/iptables.rules 2>/dev/null || "
                    "echo 'iptables persistence not configured'"
                ),
                "changed_when": False,
                "ignore_errors": True,
            },
            {
                "name": "Harden - audit world-writable files",
                "ansible.builtin.shell": "find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20 || true",
                "changed_when": False,
            },
        ]

    playbook = [{
        "name": f"Hardening - {attack_type} ({investigation_id})",
        "hosts": "target",
        "gather_facts": False,
        "tasks": tasks,
    }]
    return yaml.safe_dump(playbook, sort_keys=False, default_flow_style=False)


def _generate_forensics_playbook(attack_type: str, target_host: str, investigation_id: str) -> str:
    """Generate forensics tasks when none exist in the playbook."""
    evidence_path = f"data/evidence/{investigation_id}"
    tasks = [
        {
            "name": "Forensics - capture current iptables state",
            "ansible.builtin.shell": f"iptables -L -n -v > {evidence_path}/iptables_post.txt 2>/dev/null || echo 'no iptables' > {evidence_path}/iptables_post.txt",
            "changed_when": False,
            "ignore_errors": True,
        },
        {
            "name": "Forensics - capture active connections",
            "ansible.builtin.shell": f"ss -tunapl > {evidence_path}/connections_post.txt 2>/dev/null || netstat -tunapl > {evidence_path}/connections_post.txt 2>/dev/null || echo 'no data' > {evidence_path}/connections_post.txt",
            "changed_when": False,
            "ignore_errors": True,
        },
        {
            "name": "Forensics - capture running processes",
            "ansible.builtin.shell": f"ps aux > {evidence_path}/processes_post.txt 2>/dev/null || echo 'no ps' > {evidence_path}/processes_post.txt",
            "changed_when": False,
            "ignore_errors": True,
        },
        {
            "name": "Forensics - capture auth log tail",
            "ansible.builtin.shell": f"tail -n 100 /var/log/auth.log > {evidence_path}/auth_post.txt 2>/dev/null || tail -n 100 /var/log/secure > {evidence_path}/auth_post.txt 2>/dev/null || echo 'no auth log' > {evidence_path}/auth_post.txt",
            "changed_when": False,
            "ignore_errors": True,
        },
    ]

    if attack_type == "brute_force":
        tasks.append({
            "name": "Forensics - list failed SSH attempts",
            "ansible.builtin.shell": f"grep 'Failed password' /var/log/auth.log | tail -n 50 > {evidence_path}/ssh_failed_post.txt 2>/dev/null || grep 'authentication failure' /var/log/secure | tail -n 50 > {evidence_path}/ssh_failed_post.txt 2>/dev/null || echo 'no data' > {evidence_path}/ssh_failed_post.txt",
            "changed_when": False,
            "ignore_errors": True,
        })
    elif attack_type == "web_attack":
        tasks.append({
            "name": "Forensics - capture web error log tail",
            "ansible.builtin.shell": f"tail -n 100 /var/log/nginx/error.log > {evidence_path}/web_errors_post.txt 2>/dev/null || tail -n 100 /var/log/apache2/error.log > {evidence_path}/web_errors_post.txt 2>/dev/null || echo 'no web logs' > {evidence_path}/web_errors_post.txt",
            "changed_when": False,
            "ignore_errors": True,
        })
    elif attack_type == "malware":
        tasks.append({
            "name": "Forensics - list unusual cron entries",
            "ansible.builtin.shell": f"crontab -l > {evidence_path}/crontab_post.txt 2>/dev/null; ls -la /etc/cron.d/ >> {evidence_path}/crontab_post.txt 2>/dev/null || true",
            "changed_when": False,
            "ignore_errors": True,
        })

    tasks.append({
        "name": "Forensics - create post-remediation tarball",
        "ansible.builtin.shell": f"tar czf {evidence_path}_post.tar.gz -C {evidence_path} . 2>/dev/null || echo 'tar failed'",
        "changed_when": False,
        "ignore_errors": True,
    })

    playbook = [{
        "name": f"Forensics - {attack_type} ({investigation_id})",
        "hosts": "target",
        "gather_facts": False,
        "tasks": tasks,
    }]
    return yaml.safe_dump(playbook, sort_keys=False, default_flow_style=False)


def _generate_verification_playbook(verification_plan: dict | None, attack_type: str, target_host: str, investigation_id: str) -> str:
    """Generate verification tasks from the verification plan."""
    tasks = []

    if verification_plan and verification_plan.get("type") == "iptables_rule":
        source = verification_plan.get("source", "")
        chain = verification_plan.get("chain", "INPUT")
        jump = verification_plan.get("jump", "DROP")
        protocol = verification_plan.get("protocol", "")
        port = verification_plan.get("port", "")

        proto_flag = f"-p {protocol} " if protocol else ""
        port_flag = f"--dport {port} " if port else ""

        tasks.append({
            "name": f"Verify iptables rule exists for {source}",
            "ansible.builtin.shell": (
                f"iptables -C {chain} -s {source} {proto_flag}{port_flag}-j {jump} 2>/dev/null && "
                f"echo 'VERIFIED: iptables rule for {source} exists' || "
                f"(echo 'FAILED: iptables rule for {source} NOT FOUND'; exit 1)"
            ),
            "changed_when": False,
        })
        tasks.append({
            "name": "Verify iptables rule is persisted",
            "ansible.builtin.shell": (
                "(iptables-save | grep -qF \"$(iptables -S INPUT | grep DROP | head -1)\" 2>/dev/null && "
                "echo 'VERIFIED: rules are in iptables-save output') || "
                "echo 'WARNING: rules may not persist after reboot'"
            ),
            "changed_when": False,
            "ignore_errors": True,
        })
    elif verification_plan and verification_plan.get("type") == "file_quarantine":
        dest = verification_plan.get("quarantine_path", "")
        tasks.append({
            "name": f"Verify quarantined file exists at {dest}",
            "ansible.builtin.stat": {"path": dest},
            "register": "quarantine_stat",
        })
        tasks.append({
            "name": "Fail if quarantined file is missing",
            "ansible.builtin.fail": {"msg": f"Quarantined file {dest} not found"},
            "when": "not quarantine_stat.stat.exists",
        })
    else:
        # Generic verification based on attack type
        if attack_type == "brute_force":
            tasks.append({
                "name": "Verify SSH is still accessible",
                "ansible.builtin.wait_for": {
                    "host": target_host,
                    "port": 22,
                    "timeout": 10,
                },
                "ignore_errors": True,
            })
            tasks.append({
                "name": "Verify fail2ban is active",
                "ansible.builtin.shell": (
                    "(systemctl is-active fail2ban 2>/dev/null && echo 'VERIFIED: fail2ban active') || "
                    "echo 'WARNING: fail2ban not active'"
                ),
                "changed_when": False,
                "ignore_errors": True,
            })
        elif attack_type == "web_attack":
            tasks.append({
                "name": "Verify web server is responding",
                "ansible.builtin.uri": {
                    "url": f"http://{target_host}:80/",
                    "status_code": [200, 403, 401],
                    "timeout": 10,
                },
                "ignore_errors": True,
            })
        else:
            tasks.append({
                "name": "Verify target host connectivity",
                "ansible.builtin.ping": {},
            })
            tasks.append({
                "name": "Verify no abnormal CPU load",
                "ansible.builtin.shell": (
                    "LOAD=$(cat /proc/loadavg | awk '{print $1}'); "
                    "CPUS=$(nproc 2>/dev/null || echo 1); "
                    "if (( $(echo \"$LOAD < $CPUS * 2\" | bc -l 2>/dev/null || echo 1) )); then "
                    "echo 'VERIFIED: CPU load normal'; else echo 'WARNING: high CPU load'; fi"
                ),
                "changed_when": False,
                "ignore_errors": True,
            })

    tasks.append({
        "name": "Verification complete",
        "ansible.builtin.debug": {
            "msg": "All verification checks completed for investigation {{ investigation_id }}"
        },
    })

    playbook = [{
        "name": f"Verification - {attack_type} ({investigation_id})",
        "hosts": "target",
        "gather_facts": False,
        "vars": {"investigation_id": investigation_id},
        "tasks": tasks,
    }]
    return yaml.safe_dump(playbook, sort_keys=False, default_flow_style=False)


async def _run_diagnostic_ansible_safe(
    playbook_path: Path, inventory_path: Path, timeout: Optional[int] = None,
    host_config: Optional[dict] = None,
) -> tuple[int, str]:
    """
    Run ansible-playbook for diagnostic playbooks using a thread-based
    synchronous subprocess to avoid non-blocking file-descriptor issues
    that can cause:
      "Ansible requires blocking IO on stdin/stdout/stderr"

    Returns (exit_code, combined_output).
    """
    import subprocess
    import concurrent.futures

    if not shutil.which("ansible-playbook"):
        return -1, "ansible-playbook not found in PATH. Install Ansible first."

    playbook_dir = playbook_path.parent
    # Derive password from per-asset config, then global fallback
    ssh_password = ""
    if host_config and host_config.get("auth_type") == "password":
        direct_password = host_config.get("ansible_ssh_password")
        secret_ref = host_config.get("password_secret_ref")
        if direct_password:
            ssh_password = direct_password
        elif secret_ref:
            ssh_password = os.environ.get(secret_ref, "")
    if not ssh_password:
        ssh_password = settings.ansible_ssh_password or ""
    ssh_port = settings.ansible_ssh_port or 22
    effective_timeout = timeout or settings.ansible_timeout

    # Create ansible.cfg
    ansible_cfg = playbook_dir / "ansible.cfg"
    cfg_content = f"""[defaults]
inventory = {inventory_path.name}
host_key_checking = False
retry_files_enabled = False
timeout = 30

[ssh_connection]
ssh_args = -o StrictHostKeyChecking=no -o PreferredAuthentications=password,keyboard-interactive -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes -p {ssh_port}
pipelining = True
"""
    ansible_cfg.write_text(cfg_content)

    cmd = [
        "ansible-playbook",
        "-i", inventory_path.name,
        playbook_path.name,
        "-v",
    ]

    env = os.environ.copy()
    env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    if ssh_password:
        env["ANSIBLE_SSH_PASS"] = ssh_password

    def _run() -> tuple[int, str]:
        try:
            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                cwd=str(playbook_dir),
                timeout=effective_timeout,
            )
            return result.returncode, result.stdout or ""
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + (exc.stderr or "")
            return -1, (
                f"Ansible diagnostic execution timed out after {effective_timeout}s. "
                f"The target host may be unreachable or SSH authentication is hanging.\n{output}"
            )
        except Exception as exc:
            return -1, f"Diagnostic execution error: {str(exc)}"

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        exit_code, output = await loop.run_in_executor(pool, _run)

    return exit_code, output


async def _run_ansible(
    playbook_path: Path, inventory_path: Path, timeout: Optional[int] = None,
    host_config: Optional[dict] = None,
) -> tuple[int, str]:
    """
    Run ansible-playbook and capture output.
    Returns (exit_code, combined_output).
    """
    if not shutil.which("ansible-playbook"):
        return -1, "ansible-playbook not found in PATH. Install Ansible first."

    playbook_dir = playbook_path.parent
    # Derive password from per-asset config, then global fallback
    ssh_password = ""
    if host_config and host_config.get("auth_type") == "password":
        secret_ref = host_config.get("password_secret_ref")
        if secret_ref:
            ssh_password = os.environ.get(secret_ref, "")
    if not ssh_password:
        ssh_password = settings.ansible_ssh_password or ""
    ssh_port = settings.ansible_ssh_port or 22
    effective_timeout = timeout or settings.ansible_timeout

    # Create a temp directory per execution to avoid ansible.cfg race conditions
    import tempfile
    exec_dir = tempfile.mkdtemp(prefix="ansible_exec_")
    # Symlink/copy playbook and inventory into temp dir
    temp_playbook = Path(exec_dir) / playbook_path.name
    temp_inventory = Path(exec_dir) / inventory_path.name
    temp_playbook.write_text(playbook_path.read_text(), encoding="utf-8")
    temp_inventory.write_text(inventory_path.read_text(), encoding="utf-8")

    if ssh_password:
        ssh_args_line = f"-o StrictHostKeyChecking=no -o PreferredAuthentications=password,keyboard-interactive -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes -p {ssh_port}"
    else:
        ssh_args_line = f"-o StrictHostKeyChecking=no -p {ssh_port}"

    cfg_content = f"""[defaults]
inventory = {temp_inventory.name}
host_key_checking = False
retry_files_enabled = False
timeout = 30

[ssh_connection]
ssh_args = {ssh_args_line}
pipelining = True
"""
    ansible_cfg = Path(exec_dir) / "ansible.cfg"
    ansible_cfg.write_text(cfg_content, encoding="utf-8")

    cmd = [
        "ansible-playbook",
        "-i", temp_inventory.name,
        temp_playbook.name,
        "-v",
    ]

    env = os.environ.copy()
    env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    if ssh_password:
        env["ANSIBLE_SSH_PASS"] = ssh_password

    proc: Optional[asyncio.subprocess.Process] = None
    try:
        # Increase pipe buffer limit to 1MB to handle very long output lines
        # (e.g., grep on large log files, top with many processes)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            cwd=exec_dir,
            limit=1024 * 1024,
        )

        output_chunks = []
        assert proc.stdout is not None

        async def _read_and_wait() -> tuple[int, str]:
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                output_chunks.append(chunk.decode("utf-8", errors="replace"))
            await proc.wait()
            return proc.returncode or 0, "".join(output_chunks)

        return_code, output = await asyncio.wait_for(
            _read_and_wait(), timeout=effective_timeout
        )
        # Cleanup temp execution directory
        shutil.rmtree(exec_dir, ignore_errors=True)
        return return_code, _redact_sensitive(output)

    except asyncio.TimeoutError:
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                pass
            if proc.returncode is None:
                proc.kill()
        shutil.rmtree(exec_dir, ignore_errors=True)
        return -1, f"Ansible execution timed out after {effective_timeout}s. The target host may be unreachable or SSH authentication is hanging.", ""
    except Exception as e:
        if proc and proc.returncode is None:
            try:
                proc.kill()
            except Exception:
                pass
        shutil.rmtree(exec_dir, ignore_errors=True)
        return -1, _redact_sensitive(f"Execution error: {str(e)}"), ""


async def _run_ansible_json(
    playbook_path: Path, inventory_path: Path, timeout: Optional[int] = None,
    host_config: Optional[dict] = None,
) -> tuple[int, str, str]:
    """
    Run ansible-playbook with JSON callback for reliable machine-readable output.
    Returns (exit_code, json_output_string, stderr_string).
    """
    if not shutil.which("ansible-playbook"):
        return -1, "ansible-playbook not found in PATH. Install Ansible first."

    # Derive password from per-asset config, then global fallback
    ssh_password = ""
    if host_config and host_config.get("auth_type") == "password":
        secret_ref = host_config.get("password_secret_ref")
        if secret_ref:
            ssh_password = os.environ.get(secret_ref, "")
    if not ssh_password:
        ssh_password = settings.ansible_ssh_password or ""
    ssh_port = settings.ansible_ssh_port or 22
    effective_timeout = timeout or settings.ansible_timeout

    import tempfile
    exec_dir = tempfile.mkdtemp(prefix="ansible_exec_json_")
    temp_playbook = Path(exec_dir) / playbook_path.name
    temp_inventory = Path(exec_dir) / inventory_path.name
    temp_playbook.write_text(playbook_path.read_text(), encoding="utf-8")
    temp_inventory.write_text(inventory_path.read_text(), encoding="utf-8")

    if ssh_password:
        ssh_args_line = f"-o StrictHostKeyChecking=no -o PreferredAuthentications=password,keyboard-interactive -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes -p {ssh_port}"
    else:
        ssh_args_line = f"-o StrictHostKeyChecking=no -p {ssh_port}"

    cfg_content = f"""[defaults]
inventory = {temp_inventory.name}
host_key_checking = False
retry_files_enabled = False
timeout = 30

[ssh_connection]
ssh_args = {ssh_args_line}
pipelining = True
"""
    ansible_cfg = Path(exec_dir) / "ansible.cfg"
    ansible_cfg.write_text(cfg_content, encoding="utf-8")

    cmd = [
        "ansible-playbook",
        "-i", temp_inventory.name,
        temp_playbook.name,
    ]

    env = os.environ.copy()
    env["ANSIBLE_STDOUT_CALLBACK"] = "json"
    if ssh_password:
        env["ANSIBLE_SSH_PASS"] = ssh_password

    proc: Optional[asyncio.subprocess.Process] = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=exec_dir,
            limit=1024 * 1024,
        )

        stdout_chunks = []
        stderr_chunks = []
        assert proc.stdout is not None
        assert proc.stderr is not None
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                break
            stdout_chunks.append(chunk.decode("utf-8", errors="replace"))

        while True:
            chunk = await proc.stderr.read(65536)
            if not chunk:
                break
            stderr_chunks.append(chunk.decode("utf-8", errors="replace"))

        await asyncio.wait_for(proc.wait(), timeout=effective_timeout)
        # Ansible JSON callback writes to stdout; stderr may contain warnings/errors
        output = "".join(stdout_chunks)
        stderr_output = "".join(stderr_chunks)
        shutil.rmtree(exec_dir, ignore_errors=True)
        return proc.returncode or 0, _redact_sensitive(output), _redact_sensitive(stderr_output)

    except asyncio.TimeoutError:
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                pass
            if proc.returncode is None:
                proc.kill()
        shutil.rmtree(exec_dir, ignore_errors=True)
        return -1, f"Ansible execution timed out after {effective_timeout}s. The target host may be unreachable or SSH authentication is hanging."
    except Exception as e:
        if proc and proc.returncode is None:
            try:
                proc.kill()
            except Exception:
                pass
        shutil.rmtree(exec_dir, ignore_errors=True)
        return -1, _redact_sensitive(f"Execution error: {str(e)}")


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3: Safe Staged Remediation Utilities
# ═══════════════════════════════════════════════════════════════════════════

EVIDENCE_DIR = Path("data/evidence")
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def _generate_evidence_playbook(
    target_host: str, investigation_id: str, attack_type: str
) -> str:
    """Generate an evidence-collection playbook to run before remediation."""
    evidence_path = f"data/evidence/{investigation_id}"

    # Base evidence tasks for all incidents
    base_tasks = f"""
    - name: "Create evidence directory"
      ansible.builtin.file:
        path: "{evidence_path}"
        state: directory
        mode: '0750'

    - name: "Collect network connections"
      ansible.builtin.shell: "ss -tunapl > {evidence_path}/network_connections.txt 2>/dev/null || netstat -tunapl > {evidence_path}/network_connections.txt 2>/dev/null || echo 'No network tools available' > {evidence_path}/network_connections.txt"
      ignore_errors: yes
      changed_when: false

    - name: "Collect firewall rules"
      ansible.builtin.shell: "iptables -L -n -v > {evidence_path}/iptables_rules.txt 2>/dev/null || nft list ruleset > {evidence_path}/nftables_rules.txt 2>/dev/null || echo 'No firewall data' > {evidence_path}/firewall.txt"
      ignore_errors: yes
      changed_when: false

    - name: "Collect running processes"
      ansible.builtin.shell: "ps aux --sort=-%cpu > {evidence_path}/processes.txt 2>/dev/null || ps -ef > {evidence_path}/processes.txt 2>/dev/null"
      ignore_errors: yes
      changed_when: false

    - name: "Collect open files"
      ansible.builtin.shell: "lsof > {evidence_path}/open_files.txt 2>/dev/null || echo 'lsof not available' > {evidence_path}/open_files.txt"
      ignore_errors: yes
      changed_when: false

    - name: "Collect recent auth logs"
      ansible.builtin.shell: "tail -n 200 /var/log/auth.log > {evidence_path}/auth_log.txt 2>/dev/null || tail -n 200 /var/log/secure > {evidence_path}/auth_log.txt 2>/dev/null || echo 'No auth log found' > {evidence_path}/auth_log.txt"
      ignore_errors: yes
      changed_when: false

    - name: "Collect system info"
      ansible.builtin.shell: "uname -a > {evidence_path}/system_info.txt 2>/dev/null; df -h >> {evidence_path}/system_info.txt 2>/dev/null; free -h >> {evidence_path}/system_info.txt 2>/dev/null"
      ignore_errors: yes
      changed_when: false

    - name: "Collect cron jobs"
      ansible.builtin.shell: "crontab -l > {evidence_path}/crontab.txt 2>/dev/null || echo 'No crontab'; ls -la /etc/cron.d/ > {evidence_path}/cron_d.txt 2>/dev/null || true"
      ignore_errors: yes
      changed_when: false

    - name: "Collect recent file changes"
      ansible.builtin.shell: "find /tmp /var/tmp -type f -mmin -60 > {evidence_path}/recent_files.txt 2>/dev/null || true"
      ignore_errors: yes
      changed_when: false

    - name: "Collect listening services"
      ansible.builtin.shell: "ss -tulpn > {evidence_path}/listening_services.txt 2>/dev/null || netstat -tulpn > {evidence_path}/listening_services.txt 2>/dev/null || echo 'No service data' > {evidence_path}/listening_services.txt"
      ignore_errors: yes
      changed_when: false
"""

    # Attack-specific evidence tasks
    attack_specific = ""
    if attack_type == "brute_force":
        attack_specific = f"""
    - name: "Collect SSH auth failures"
      ansible.builtin.shell: "grep 'Failed password' /var/log/auth.log | tail -n 100 > {evidence_path}/ssh_failures.txt 2>/dev/null || grep 'authentication failure' /var/log/secure | tail -n 100 > {evidence_path}/ssh_failures.txt 2>/dev/null || echo 'No SSH failure logs' > {evidence_path}/ssh_failures.txt"
      ignore_errors: yes
      changed_when: false

    - name: "Collect successful logins"
      ansible.builtin.shell: "grep 'Accepted password' /var/log/auth.log | tail -n 50 > {evidence_path}/ssh_success.txt 2>/dev/null || grep 'session opened' /var/log/secure | tail -n 50 > {evidence_path}/ssh_success.txt 2>/dev/null || echo 'No success logs' > {evidence_path}/ssh_success.txt"
      ignore_errors: yes
      changed_when: false

    - name: "Collect last logins"
      ansible.builtin.shell: "last -50 > {evidence_path}/last_logins.txt 2>/dev/null || echo 'last command not available' > {evidence_path}/last_logins.txt"
      ignore_errors: yes
      changed_when: false
"""
    elif attack_type == "web_attack":
        attack_specific = f"""
    - name: "Collect web server error logs"
      ansible.builtin.shell: "tail -n 500 /var/log/apache2/error.log > {evidence_path}/web_errors.txt 2>/dev/null || tail -n 500 /var/log/nginx/error.log > {evidence_path}/web_errors.txt 2>/dev/null || tail -n 500 /var/log/httpd/error_log > {evidence_path}/web_errors.txt 2>/dev/null || echo 'No web error logs' > {evidence_path}/web_errors.txt"
      ignore_errors: yes
      changed_when: false

    - name: "Collect web access logs"
      ansible.builtin.shell: "tail -n 500 /var/log/apache2/access.log > {evidence_path}/web_access.txt 2>/dev/null || tail -n 500 /var/log/nginx/access.log > {evidence_path}/web_access.txt 2>/dev/null || tail -n 500 /var/log/httpd/access_log > {evidence_path}/web_access.txt 2>/dev/null || echo 'No web access logs' > {evidence_path}/web_access.txt"
      ignore_errors: yes
      changed_when: false
"""
    elif attack_type == "malware":
        attack_specific = f"""
    - name: "Collect suspicious processes"
      ansible.builtin.shell: "ps aux | grep -E 'nc|netcat|python|perl|ruby|bash.*-i' > {evidence_path}/suspicious_procs.txt 2>/dev/null || true"
      ignore_errors: yes
      changed_when: false

    - name: "Collect /proc info for suspicious PIDs"
      ansible.builtin.shell: "for pid in $(ps aux | grep -v grep | awk '{{print $2}}' | head -50); do cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' ' > {evidence_path}/proc_$pid.txt; done || true"
      ignore_errors: yes
      changed_when: false

    - name: "Collect recently modified binaries"
      ansible.builtin.shell: "find /usr/bin /usr/sbin /bin /sbin -type f -mmin -120 > {evidence_path}/recent_binaries.txt 2>/dev/null || true"
      ignore_errors: yes
      changed_when: false
"""
    elif attack_type in ("privilege_escalation", "execution"):
        attack_specific = f"""
    - name: "Collect sudoers configuration"
      ansible.builtin.shell: "cat /etc/sudoers > {evidence_path}/sudoers.txt 2>/dev/null || echo 'Cannot read sudoers'; ls -la /etc/sudoers.d/ > {evidence_path}/sudoers_d.txt 2>/dev/null || true"
      ignore_errors: yes
      changed_when: false

    - name: "Collect SUID binaries"
      ansible.builtin.shell: "find / -perm -4000 -type f 2>/dev/null | head -100 > {evidence_path}/suid_binaries.txt || true"
      ignore_errors: yes
      changed_when: false
"""

    # Archive + fetch tasks to pull evidence OFF the target
    pull_tasks = f"""
    - name: "Archive evidence directory"
      ansible.builtin.archive:
        path: "{evidence_path}"
        dest: "{evidence_path}.tar.gz"
        format: gz
      ignore_errors: yes

    - name: "Fetch evidence archive to controller"
      ansible.builtin.fetch:
        src: "{evidence_path}.tar.gz"
        dest: "{PLAYBOOKS_DIR}/evidence/{investigation_id}.tar.gz"
        flat: yes
      ignore_errors: yes

    - name: "Evidence collection complete"
      ansible.builtin.debug:
        msg: "Evidence collected in {evidence_path} and pulled to controller"
"""

    playbook = f"""---
- name: "Evidence Collection - {investigation_id}"
  hosts: target
  gather_facts: no
  tasks:
{base_tasks}
{attack_specific}
{pull_tasks}
"""
    return playbook


async def _detect_os(target_host: str, target_user: str, host_config: Optional[dict] = None) -> str:
    """Detect target OS via SSH. Returns 'linux' | 'windows' | 'unknown'.
    
    Uses per-asset credentials from host_config when available, falling back
    to global settings.
    """
    auth_type = "private_key"
    ssh_key = settings.ansible_ssh_key or ""
    ssh_password = settings.ansible_ssh_password or ""
    ssh_port = settings.ansible_ssh_port or 22

    if host_config:
        auth_type = host_config.get("auth_type", "private_key")
        if host_config.get("ansible_port"):
            ssh_port = int(host_config["ansible_port"])
        if auth_type == "password":
            direct_password = host_config.get("ansible_ssh_password")
            secret_ref = host_config.get("password_secret_ref")
            if direct_password:
                ssh_password = direct_password
            elif secret_ref:
                ssh_password = os.environ.get(secret_ref, "")
            elif not ssh_password:
                ssh_password = settings.ansible_ssh_password or ""
            ssh_key = ""
        elif auth_type == "private_key":
            key_ref = host_config.get("ssh_key_ref")
            if key_ref and os.path.exists(key_ref):
                ssh_key = key_ref
            elif not ssh_key:
                ssh_key = settings.ansible_ssh_key or ""
            ssh_password = ""

    # Resolve effective host for SSH connection
    effective_host = target_host
    if host_config and host_config.get("ansible_host"):
        effective_host = host_config["ansible_host"]

    async def _try_cmd(cmd: list, desc: str) -> tuple[bool, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=15)
            except asyncio.TimeoutError:
                proc.kill()
                return False, "timeout"

            if proc.returncode == 0:
                stdout, _ = await proc.communicate()
                return True, stdout.decode().strip()
            return False, ""
        except Exception:
            return False, ""

    # Build base SSH command based on auth type
    if auth_type == "password" and ssh_password and shutil.which("sshpass"):
        base_cmd = ["sshpass", "-p", ssh_password, "ssh", "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=10", "-p", str(ssh_port)]
    else:
        base_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
                    "-o", "BatchMode=yes", "-p", str(ssh_port)]
        if ssh_key and auth_type == "private_key":
            base_cmd.extend(["-i", ssh_key])

    # Try Linux first (most common target)
    linux_cmd = base_cmd.copy()
    linux_cmd.append(f"{target_user}@{effective_host}")
    linux_cmd.append("uname -s")

    ok, output = await _try_cmd(linux_cmd, "linux")
    if ok:
        output_lower = output.lower()
        if "linux" in output_lower or "darwin" in output_lower:
            return "linux"

    # Try Windows
    win_cmd = base_cmd.copy()
    win_cmd.append(f"{target_user}@{effective_host}")
    win_cmd.append("cmd /c ver")

    ok, _ = await _try_cmd(win_cmd, "windows")
    if ok:
        return "windows"

    return "unknown"


async def _run_phase(
    investigation_id: str,
    phase: str,
    playbook_yaml: str,
    target_host: str,
    target_user: str,
    run_id: str,
    host_config: Optional[dict] = None,
) -> tuple[int, str]:
    """
    Run a single phase playbook.
    Updates PlaybookRun.current_phase and phases_json.
    Returns (exit_code, output).
    """
    logger.info("staged_phase_started",
                investigation_id=investigation_id,
                phase=phase,
                run_id=run_id)

    # Update current phase
    await _update_run(run_id, current_phase=phase)

    # Broadcast phase start
    try:
        from api.websocket import broadcast_investigation_change
        asyncio.create_task(broadcast_investigation_change(
            investigation_id, "running", "running",
            f"Phase {phase} started"
        ))
    except Exception:
        pass

    # Firewall safety check — prevent self-lockout
    protected_ips = await _get_protected_ips(target_host)
    is_safe, safety_error, sanitized_yaml = _sanitize_firewall_tasks(playbook_yaml, protected_ips)
    if not is_safe:
        logger.error("staged_phase_firewall_safety_blocked",
                     investigation_id=investigation_id,
                     phase=phase,
                     error=safety_error)
        output = f"FIREWALL SAFETY BLOCKED:\n{safety_error}\n\nThe playbook was NOT executed to prevent locking you out of the target VM."
        phase_record = {
            "status": "failed",
            "exit_code": -1,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "output_preview": output[:4000],
        }
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PlaybookRun).where(PlaybookRun.id == run_id)
            )
            run = result.scalar_one_or_none()
            if run:
                phases = dict(run.phases_json or {})
                phases[phase] = phase_record
                run.phases_json = phases
                await session.commit()
        return -1, output

    # Comprehensive safety validation for each phase
    from response.playbook_safety import validate_playbook_safety
    investigation_context = {
        "investigation_type": "security",
        "target_host": target_host,
        "alert_sources": [],
    }
    safety = validate_playbook_safety(sanitized_yaml, investigation_context)
    if not safety["executable"]:
        logger.error("staged_phase_comprehensive_safety_blocked",
                     investigation_id=investigation_id,
                     phase=phase,
                     reasons=safety["reasons"])
        output = "SAFETY VALIDATION BLOCKED:\n" + "\n".join(f"- {r}" for r in safety["reasons"])
        phase_record = {
            "status": "failed",
            "exit_code": -1,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "output_preview": output[:4000],
        }
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PlaybookRun).where(PlaybookRun.id == run_id)
            )
            run = result.scalar_one_or_none()
            if run:
                phases = dict(run.phases_json or {})
                phases[phase] = phase_record
                run.phases_json = phases
                await session.commit()
        return -1, output

    # Write phase playbook to disk
    phase_path = PLAYBOOKS_DIR / f"{investigation_id}_{phase}.yml"
    phase_path.write_text(sanitized_yaml, encoding="utf-8")

    # Write inventory
    inventory_path = _write_inventory(investigation_id, target_host, target_user, host_config)

    # Run ansible
    exit_code, output = await _run_ansible(phase_path, inventory_path, host_config=host_config)

    # Record phase result
    phase_record = {
        "status": "completed" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "output_preview": output[:4000] if output else "",
    }

    # Append to phases_json
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PlaybookRun).where(PlaybookRun.id == run_id)
        )
        run = result.scalar_one_or_none()
        if run:
            phases = dict(run.phases_json or {})
            phases[phase] = phase_record
            run.phases_json = phases
            await session.commit()

    # Broadcast phase completion
    try:
        from api.websocket import broadcast_investigation_change
        status_str = "completed" if exit_code == 0 else "failed"
        asyncio.create_task(broadcast_investigation_change(
            investigation_id, "running", "running",
            f"Phase {phase} {status_str}"
        ))
    except Exception:
        pass

    logger.info("staged_phase_finished",
                investigation_id=investigation_id,
                phase=phase,
                exit_code=exit_code,
                run_id=run_id)

    return exit_code, output


async def _execute_staged_remediation(
    investigation_id: str,
    inv: Investigation,
    playbook_yaml: str,
    target_host: str,
    run_id: str,
    host_config: Optional[dict] = None,
):
    """
    Execute remediation in staged phases.
    """
    from response.ai_engine.playbook_splitter import (
        split_playbook_into_phases,
        generate_rollback_playbook,
    )

    # Determine effective SSH user from asset config or investigation
    effective_user = inv.target_user
    if host_config and host_config.get("ansible_user"):
        effective_user = host_config["ansible_user"]
    elif effective_user == "root" and settings.ansible_remote_user:
        effective_user = settings.ansible_remote_user

    attack_type = "unknown"
    # Try to extract attack type from playbook vars or context
    try:
        parsed = yaml.safe_load(playbook_yaml)
        if isinstance(parsed, list) and parsed:
            vars_dict = parsed[0].get("vars", {})
            attack_type = vars_dict.get("attack_type", "unknown")
    except Exception:
        pass

    # Extract and store verification plan for robust fix verification
    verification_plan = _extract_verification_plan(playbook_yaml)
    if verification_plan:
        await _update_investigation(
            investigation_id,
            verification_plan_json=verification_plan,
        )
        await _update_run(
            run_id,
            verification_plan_json=verification_plan,
        )
        logger.info("verification_plan_extracted",
                    investigation_id=investigation_id,
                    plan_type=verification_plan.get("type"))

    # Phase 0: Evidence Collection
    if settings.staged_remediation_evidence_first:
        # Ensure local evidence directory exists for fetched files
        local_evidence_dir = PLAYBOOKS_DIR / "evidence" / investigation_id
        local_evidence_dir.mkdir(parents=True, exist_ok=True)
        (PLAYBOOKS_DIR / "evidence").mkdir(parents=True, exist_ok=True)

        evidence_playbook = _generate_evidence_playbook(
            target_host, investigation_id, attack_type
        )
        exit_code, output = await _run_phase(
            investigation_id, "evidence",
            evidence_playbook, target_host, effective_user, run_id, host_config,
        )

        # Extract fetched evidence archive locally
        local_tarball = PLAYBOOKS_DIR / "evidence" / f"{investigation_id}.tar.gz"
        extracted = False
        if local_tarball.exists():
            try:
                _safe_extract_tar(local_tarball, local_evidence_dir)
                extracted = True
                logger.info("evidence_extracted_locally",
                            investigation_id=investigation_id,
                            local_path=str(local_evidence_dir))
            except Exception as e:
                logger.warning("evidence_extract_failed",
                               investigation_id=investigation_id,
                               error=str(e))

        # Store evidence paths and output
        evidence_json = {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "path": f"data/evidence/{investigation_id}",
            "local_path": str(local_evidence_dir) if extracted else None,
            "archive_path": str(local_tarball) if local_tarball.exists() else None,
            "exit_code": exit_code,
            "output_preview": output[:3000] if output else "",
        }
        await _update_investigation(
            investigation_id,
            evidence_json=evidence_json,
        )
        # Evidence collection failure is MANDATORY — block completion
        if exit_code != 0:
            logger.error("staged_evidence_failed",
                         investigation_id=investigation_id,
                         exit_code=exit_code)
            await _update_run(
                run_id,
                status="failed",
                exit_code=exit_code,
                completion_quality="failed",
                failed_phase="evidence",
                finished_at=datetime.now(timezone.utc),
            )
            await _update_investigation(
                investigation_id,
                status="failed",
                completion_quality="failed",
                failed_phase="evidence",
                ai_error=f"Evidence collection failed (exit {exit_code}). Remediation cannot proceed without evidence.",
            )
            return

    # Phase 1: Dry-Run Preview
    if settings.staged_remediation_dry_run_first:
        # Firewall safety check before dry-run
        protected_ips = await _get_protected_ips(target_host)
        is_safe, safety_error, sanitized_yaml = _sanitize_firewall_tasks(playbook_yaml, protected_ips)
        if not is_safe:
            logger.error("staged_dry_run_firewall_safety_blocked",
                         investigation_id=investigation_id,
                         error=safety_error)
            dry_output = f"FIREWALL SAFETY BLOCKED:\n{safety_error}\n\nThe playbook was NOT executed to prevent locking you out of the target VM."
            phase_record = {
                "status": "failed",
                "exit_code": -1,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "output_preview": dry_output[:4000],
            }
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(PlaybookRun).where(PlaybookRun.id == run_id)
                )
                run = result.scalar_one_or_none()
                if run:
                    phases = dict(run.phases_json or {})
                    phases["dry_run"] = phase_record
                    run.phases_json = phases
                    await session.commit()
            await _update_run(
                run_id,
                status="failed",
                output=dry_output,
                exit_code=-1,
                finished_at=datetime.now(timezone.utc),
            )
            await _update_investigation(
                investigation_id,
                status="failed",
                ai_error=f"Dry-run blocked by firewall safety: {safety_error[:500]}",
            )
            return

        # Comprehensive safety validation before dry-run
        from response.playbook_safety import validate_playbook_safety
        investigation_context = {
            "investigation_type": inv.investigation_type or "security",
            "target_host": target_host,
            "alert_sources": [],
        }
        safety = validate_playbook_safety(sanitized_yaml, investigation_context)
        if not safety["executable"]:
            logger.error("staged_dry_run_comprehensive_safety_blocked",
                         investigation_id=investigation_id,
                         reasons=safety["reasons"])
            dry_output = "SAFETY VALIDATION BLOCKED:\n" + "\n".join(f"- {r}" for r in safety["reasons"])
            phase_record = {
                "status": "failed",
                "exit_code": -1,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "output_preview": dry_output[:4000],
            }
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(PlaybookRun).where(PlaybookRun.id == run_id)
                )
                run = result.scalar_one_or_none()
                if run:
                    phases = dict(run.phases_json or {})
                    phases["dry_run"] = phase_record
                    run.phases_json = phases
                    await session.commit()
            await _update_run(
                run_id,
                status="failed",
                output=dry_output,
                exit_code=-1,
                finished_at=datetime.now(timezone.utc),
            )
            await _update_investigation(
                investigation_id,
                status="failed",
                ai_error=f"Dry-run blocked by safety validation: {'; '.join(safety['reasons'])[:500]}",
            )
            return

        dry_run_path = PLAYBOOKS_DIR / f"{investigation_id}_dry_run.yml"
        dry_run_path.write_text(sanitized_yaml, encoding="utf-8")
        inventory_path = _write_inventory(investigation_id, target_host, effective_user, host_config)

        # Remove stale ansible.cfg in PLAYBOOKS_DIR to prevent it from
        # overriding cwd settings or default inventory
        stale_cfg = PLAYBOOKS_DIR / "ansible.cfg"
        if stale_cfg.exists():
            stale_cfg.unlink()

        # Run with --check
        dry_cmd = [
            "ansible-playbook",
            "-i", inventory_path.name,
            dry_run_path.name,
            "--check",
            "-v",
        ]
        dry_env = os.environ.copy()
        dry_env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
        # Use per-asset password if available
        dry_password = ""
        if host_config and host_config.get("auth_type") == "password":
            secret_ref = host_config.get("password_secret_ref")
            if secret_ref:
                dry_password = os.environ.get(secret_ref, "")
        if not dry_password and settings.ansible_ssh_password:
            dry_password = settings.ansible_ssh_password
        if dry_password:
            dry_env["ANSIBLE_SSH_PASS"] = dry_password

        dry_proc = None
        dry_output = ""
        try:
            dry_proc = await asyncio.create_subprocess_exec(
                *dry_cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=dry_env,
                cwd=str(PLAYBOOKS_DIR),
                limit=1024 * 1024,
            )
            chunks = []
            assert dry_proc.stdout is not None
            while True:
                chunk = await dry_proc.stdout.read(65536)
                if not chunk:
                    break
                chunks.append(chunk.decode("utf-8", errors="replace"))
            await asyncio.wait_for(dry_proc.wait(), timeout=settings.ansible_timeout)
            dry_exit = dry_proc.returncode or 0
            dry_output = "".join(chunks)
        except asyncio.TimeoutError:
            if dry_proc and dry_proc.returncode is None:
                try:
                    dry_proc.terminate()
                    await asyncio.wait_for(dry_proc.wait(), timeout=5)
                except Exception:
                    pass
                if dry_proc.returncode is None:
                    dry_proc.kill()
            dry_exit = -1
            dry_output = f"Dry-run timed out after {settings.ansible_timeout}s"

        # Record dry-run result
        phase_record = {
            "status": "completed" if dry_exit == 0 else "failed",
            "exit_code": dry_exit,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "output_preview": dry_output[:4000] if dry_output else "",
        }
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PlaybookRun).where(PlaybookRun.id == run_id)
            )
            run = result.scalar_one_or_none()
            if run:
                phases = dict(run.phases_json or {})
                phases["dry_run"] = phase_record
                run.phases_json = phases
                await session.commit()

        if dry_exit != 0:
            logger.error("staged_dry_run_failed",
                         investigation_id=investigation_id,
                         exit_code=dry_exit)
            await _update_run(
                run_id,
                status="failed",
                output=dry_output,
                exit_code=dry_exit,
                finished_at=datetime.now(timezone.utc),
            )
            await _update_investigation(
                investigation_id,
                status="failed",
                ai_error=f"Dry-run failed (exit {dry_exit}): {dry_output[:500]}",
            )
            return

    # Split playbook into phases
    phase_playbooks = split_playbook_into_phases(playbook_yaml)

    # If phases are empty/no-op, generate sensible default tasks
    if _is_noop_playbook(phase_playbooks.get("hardening", "")):
        phase_playbooks["hardening"] = _generate_hardening_playbook(
            attack_type, target_host, investigation_id
        )
        logger.info("staged_generated_default_hardening",
                    investigation_id=investigation_id,
                    attack_type=attack_type)

    if _is_noop_playbook(phase_playbooks.get("forensics", "")):
        phase_playbooks["forensics"] = _generate_forensics_playbook(
            attack_type, target_host, investigation_id
        )
        logger.info("staged_generated_default_forensics",
                    investigation_id=investigation_id,
                    attack_type=attack_type)

    if _is_noop_playbook(phase_playbooks.get("verification", "")):
        phase_playbooks["verification"] = _generate_verification_playbook(
            verification_plan, attack_type, target_host, investigation_id
        )
        logger.info("staged_generated_default_verification",
                    investigation_id=investigation_id,
                    attack_type=attack_type)

    # Baseline capture before any mutating phase
    await _capture_remote_baseline(
        investigation_id, inv, target_host, effective_user, run_id, host_config
    )

    # Phase 2: Containment
    containment_yaml = phase_playbooks.get("containment", "")
    if containment_yaml and containment_yaml.strip():
        exit_code, output = await _run_phase(
            investigation_id, "containment",
            containment_yaml, target_host, effective_user, run_id, host_config,
        )

        # Generate and store rollback playbook
        rollback = generate_rollback_playbook(containment_yaml)
        if rollback:
            await _update_investigation(
                investigation_id,
                rollback_playbook=rollback,
            )

        if exit_code != 0:
            logger.error("staged_containment_failed",
                         investigation_id=investigation_id,
                         exit_code=exit_code)
            # Auto-rollback if configured
            if settings.staged_remediation_auto_rollback_on_failure and rollback:
                logger.info("staged_auto_rollback_triggered",
                            investigation_id=investigation_id)
                rb_exit, rb_output = await _run_phase(
                    investigation_id, "rollback",
                    rollback, target_host, effective_user, run_id, host_config,
                )
                logger.info("staged_auto_rollback_complete",
                            investigation_id=investigation_id,
                            exit_code=rb_exit)

            await _update_run(
                run_id,
                status="failed",
                output=output,
                exit_code=exit_code,
                finished_at=datetime.now(timezone.utc),
            )
            await _update_investigation(investigation_id, status="failed")
            return

        # Post-containment SSH safety check — ensure we didn't lock ourselves out
        is_local = _is_local_connection(host_config)
        if not is_local:
            ssh_ok, ssh_err = await _test_ssh_connection(target_host, effective_user, host_config)
        else:
            ssh_ok = True
            ssh_err = ""
        if not ssh_ok:
            logger.error("staged_containment_ssh_lost",
                         investigation_id=investigation_id,
                         error=ssh_err)
            # Auto-rollback IMMEDIATELY if SSH is lost
            if rollback:
                logger.info("staged_ssh_rollback_triggered",
                            investigation_id=investigation_id)
                rb_exit, rb_output = await _run_phase(
                    investigation_id, "rollback",
                    rollback, target_host, effective_user, run_id, host_config,
                )
                logger.info("staged_ssh_rollback_complete",
                            investigation_id=investigation_id,
                            exit_code=rb_exit)
                await _append_to_phase_output(
                    run_id, "containment",
                    f"\n\n--- SSH LOCKOUT DETECTED ---\nContainment locked us out of the VM. Auto-rollback executed.\nSSH error: {ssh_err}"
                )
            await _update_run(
                run_id,
                status="failed",
                output=output + f"\n\nSSH LOCKOUT: {ssh_err}. Auto-rollback executed." if output else f"SSH LOCKOUT: {ssh_err}. Auto-rollback executed.",
                exit_code=-1,
                finished_at=datetime.now(timezone.utc),
            )
            await _update_investigation(
                investigation_id,
                status="failed",
                ai_error=f"Containment locked us out of the VM ({ssh_err}). Auto-rollback executed. Reboot may be required if rollback failed.",
            )
            return

        # Delay between phases
        if settings.staged_remediation_phase_delay_seconds > 0:
            await asyncio.sleep(settings.staged_remediation_phase_delay_seconds)

    # Track optional phase warnings
    warning_phases: list[str] = []

    # Phase 3: Hardening (optional)
    hardening_yaml = phase_playbooks.get("hardening", "")
    if hardening_yaml and hardening_yaml.strip():
        exit_code, output = await _run_phase(
            investigation_id, "hardening",
            hardening_yaml, target_host, effective_user, run_id, host_config,
        )
        if exit_code != 0:
            logger.warning("staged_hardening_failed",
                           investigation_id=investigation_id,
                           exit_code=exit_code)
            warning_phases.append("hardening")

        if settings.staged_remediation_phase_delay_seconds > 0:
            await asyncio.sleep(settings.staged_remediation_phase_delay_seconds)

    # Phase 4: Forensics (optional)
    forensics_yaml = phase_playbooks.get("forensics", "")
    if forensics_yaml and forensics_yaml.strip():
        exit_code, output = await _run_phase(
            investigation_id, "forensics",
            forensics_yaml, target_host, effective_user, run_id, host_config,
        )
        if exit_code != 0:
            logger.warning("staged_forensics_failed",
                           investigation_id=investigation_id,
                           exit_code=exit_code)
            warning_phases.append("forensics")

        if settings.staged_remediation_phase_delay_seconds > 0:
            await asyncio.sleep(settings.staged_remediation_phase_delay_seconds)

    # Phase 5: Verification (mandatory)
    verification_yaml = phase_playbooks.get("verification", "")
    verification_failed = False
    if verification_yaml and verification_yaml.strip():
        exit_code, output = await _run_phase(
            investigation_id, "verification",
            verification_yaml, target_host, effective_user, run_id, host_config,
        )
        if exit_code != 0:
            logger.error("staged_verification_failed",
                         investigation_id=investigation_id,
                         exit_code=exit_code)
            verification_failed = True
    else:
        # If no verification playbook was generated, check if we have ES verification at least
        pass

    # Phase 5b: Elasticsearch verification — confirm threat is actually gone
    es_verification_result = await _verify_fix_via_elasticsearch(investigation_id, inv)
    if es_verification_result:
        # Append ES verification result to the verification phase record
        await _append_to_phase_output(
            run_id, "verification",
            f"\n\n--- Elasticsearch Fix Verification ---\n{es_verification_result}"
        )

    # If verification playbook failed, mark as failed
    if verification_failed:
        await _update_run(
            run_id,
            status="failed",
            exit_code=exit_code,
            completion_quality="failed",
            failed_phase="verification",
            warning_phases=warning_phases or None,
            finished_at=datetime.now(timezone.utc),
        )
        await _update_investigation(
            investigation_id,
            status="failed",
            completion_quality="failed",
            failed_phase="verification",
            warning_phases=warning_phases or None,
            verification_status="failed",
            ai_error=f"Verification phase failed (exit {exit_code}). The remediation may not have fully resolved the issue.",
        )
        return

    # Build summary output from all phases so the frontend can display it
    summary_lines = ["=== Staged Remediation Complete ===\n"]
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PlaybookRun).where(PlaybookRun.id == run_id)
        )
        run = result.scalar_one_or_none()
        if run and run.phases_json:
            for phase_name in ["evidence", "containment", "hardening", "forensics", "verification"]:
                phase = run.phases_json.get(phase_name)
                if phase:
                    summary_lines.append(f"\n--- {phase_name.upper()} ---")
                    summary_lines.append(f"Status: {phase.get('status', 'unknown')}")
                    summary_lines.append(f"Exit code: {phase.get('exit_code', 'N/A')}")
                    out = phase.get('output', '') or phase.get('output_preview', '')
                    if out:
                        summary_lines.append(out[:2000])  # cap per phase
        await session.commit()
    summary_output = "\n".join(summary_lines)

    # Determine final status based on optional phase warnings
    if warning_phases:
        final_status = "completed_with_warnings"
        completion_quality = "warning"
    else:
        final_status = "completed"
        completion_quality = "success"

    await _update_run(
        run_id,
        status=final_status,
        exit_code=0,
        output=summary_output,
        completion_quality=completion_quality,
        warning_phases=warning_phases or None,
        finished_at=datetime.now(timezone.utc),
    )
    await _update_investigation(
        investigation_id,
        status=final_status,
        completion_quality=completion_quality,
        warning_phases=warning_phases or None,
        verification_status="passed",
    )

    # Trigger fix verifier (background delayed re-check)
    asyncio.create_task(_trigger_fix_verifier(investigation_id))

    logger.info("staged_remediation_complete",
                investigation_id=investigation_id,
                run_id=run_id,
                final_status=final_status,
                warning_phases=warning_phases)


async def execute_diagnostic_playbook(investigation_id: str) -> dict[str, Any]:
    """
    Run a pure diagnostic playbook on the target host and collect evidence.

    This is the diagnostic-first flow: no remediation, no changes.
    The playbook collects system evidence which is then interpreted by AI.

    Returns a dict with:
        - exit_code: Ansible exit code
        - output: Full raw stdout+stderr
        - run_id: PlaybookRun ID
    """
    logger.info("diagnostic_playbook_started", investigation_id=investigation_id)
    started_at = datetime.now(timezone.utc)

    inv = await _get_investigation(investigation_id)
    if not inv:
        logger.error("diagnostic_investigation_not_found", investigation_id=investigation_id)
        finished_at = datetime.now(timezone.utc)
        return {
            "status": "failed",
            "exit_code": -1,
            "output": "Investigation not found",
            "stderr": "",
            "run_id": None,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
        }

    target_host = inv.target_host
    if not target_host:
        logger.error("diagnostic_no_target_host", investigation_id=investigation_id)
        await _update_investigation(
            investigation_id,
            status="findings_ready",
            ai_error="No target host specified for diagnostic",
        )
        finished_at = datetime.now(timezone.utc)
        return {
            "status": "failed",
            "exit_code": -1,
            "output": "No target host",
            "stderr": "",
            "run_id": None,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
        }

    # Update investigation status
    await _update_investigation(
        investigation_id,
        status="diagnosing",
    )

    # Create or reuse PlaybookRun
    from response.models import PlaybookRun
    from sqlalchemy import select
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PlaybookRun).where(PlaybookRun.investigation_id == investigation_id)
        )
        existing_run = result.scalar_one_or_none()
        if existing_run:
            run_id = existing_run.id
            existing_run.status = "running"
            existing_run.output = None
            existing_run.exit_code = None
            existing_run.current_phase = "diagnostic"
            existing_run.phases_json = {}
            existing_run.started_at = datetime.now(timezone.utc)
            existing_run.finished_at = None
            await session.commit()
        else:
            run = PlaybookRun(
                investigation_id=investigation_id,
                status="running",
                current_phase="diagnostic",
                started_at=datetime.now(timezone.utc),
            )
            session.add(run)
            await session.flush()
            run_id = run.id

    # Resolve per-asset config for credential-aware SSH check
    host_config = None
    if inv.asset_id:
        try:
            async with AsyncSessionLocal() as session:
                from response.models import MonitoredAsset
                result = await session.execute(select(MonitoredAsset).where(MonitoredAsset.asset_id == inv.asset_id))
                asset = result.scalar_one_or_none()
                if asset:
                    host_config = asset.ansible_config_json or {}
        except Exception as e:
            logger.warning("diagnostic_asset_resolution_failed", investigation_id=investigation_id, asset_id=inv.asset_id, error=str(e))

    is_local = _is_local_connection(host_config)
    if not is_local:
        ssh_ok, ssh_err = await _test_ssh_connection(target_host, inv.target_user, host_config)
    else:
        ssh_ok = True
        ssh_err = ""
    if not ssh_ok:
        error_msg = f"SSH pre-flight failed: {ssh_err}"
        logger.error("diagnostic_ssh_failed", investigation_id=investigation_id, error=ssh_err)
        await _update_run(
            run_id,
            status="failed",
            output=error_msg,
            exit_code=-1,
            finished_at=datetime.now(timezone.utc),
        )
        await _update_investigation(
            investigation_id,
            status="findings_ready",
            ai_error=error_msg,
        )
        finished_at = datetime.now(timezone.utc)
        return {
            "status": "failed",
            "exit_code": -1,
            "output": error_msg,
            "stderr": error_msg,
            "run_id": run_id,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
        }

    # Determine effective user from host_config
    effective_user = inv.target_user
    if host_config and host_config.get("ansible_user"):
        effective_user = host_config["ansible_user"]
    elif effective_user == "root" and settings.ansible_remote_user:
        effective_user = settings.ansible_remote_user

    # Normalize playbook hosts to "target" to match the [target] inventory group
    playbook_yaml = inv.playbook_yaml or ""
    if playbook_yaml:
        hosts_match = re.search(r'^  hosts:\s*(\S+)', playbook_yaml, re.MULTILINE)
        playbook_hosts = hosts_match.group(1) if hosts_match else None
        if playbook_hosts and playbook_hosts != "target":
            new_playbook = playbook_yaml.replace(f"hosts: {playbook_hosts}", "hosts: target")
            if new_playbook != playbook_yaml:
                logger.info("diagnostic_playbook_hosts_replaced", old=playbook_hosts, new="target", investigation_id=investigation_id)
                playbook_yaml = new_playbook

    # Write playbook and inventory
    playbook_path = _write_playbook(investigation_id, playbook_yaml)
    inventory_path = _write_inventory(investigation_id, target_host, effective_user, host_config)

    # Validate syntax
    syntax_ok, syntax_error = await _validate_ansible_syntax(inv.playbook_yaml or "", investigation_id)
    if not syntax_ok:
        error_msg = f"Playbook syntax error: {syntax_error}"
        logger.error("diagnostic_syntax_error", investigation_id=investigation_id, error=syntax_error)
        await _update_run(
            run_id,
            status="failed",
            output=error_msg,
            exit_code=-1,
            finished_at=datetime.now(timezone.utc),
        )
        await _update_investigation(
            investigation_id,
            status="findings_ready",
            ai_error=error_msg,
        )
        finished_at = datetime.now(timezone.utc)
        return {
            "status": "failed",
            "exit_code": -1,
            "output": error_msg,
            "stderr": error_msg,
            "run_id": run_id,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
        }

    # Run the diagnostic playbook using the safe thread-based runner
    exit_code, output = await _run_diagnostic_ansible_safe(playbook_path, inventory_path, host_config=host_config)

    # Record phase result
    phase_record = {
        "status": "completed" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "output_preview": output[:4000] if output else "",
    }

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PlaybookRun).where(PlaybookRun.id == run_id)
        )
        run = result.scalar_one_or_none()
        if run:
            run.phases_json = {"diagnostic": phase_record}
            await session.commit()

    # Update run and investigation
    status = "completed" if exit_code == 0 else "failed"
    await _update_run(
        run_id,
        status=status,
        output=output,
        exit_code=exit_code,
        finished_at=datetime.now(timezone.utc),
    )

    logger.info(
        "diagnostic_playbook_complete",
        investigation_id=investigation_id,
        run_id=run_id,
        exit_code=exit_code,
        output_length=len(output) if output else 0,
    )

    finished_at = datetime.now(timezone.utc)
    return {
        "status": status,
        "exit_code": exit_code,
        "output": output or "",
        "stderr": "",
        "run_id": run_id,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
    }


async def execute_playbook(investigation_id: str):
    """
    Main entry point. Called after analyst approves.
    Runs the playbook on the target host and records results.
    """
    if investigation_id in _EXECUTING_IDS:
        logger.warning("ansible_duplicate_execution_prevented", investigation_id=investigation_id)
        return
    _EXECUTING_IDS.add(investigation_id)

    try:
            """
            Main entry point. Called after analyst approves.
            Runs the playbook on the target host and records results.
            """
            logger.info("ansible_execution_started", investigation_id=investigation_id)

            inv = await _get_investigation(investigation_id)
            if not inv:
                logger.error("ansible_exec_investigation_not_found", investigation_id=investigation_id)
                return

            if inv.investigation_type == "runtime":
                from response.runtime_ai_engine.remediation_planner import has_corrective_actions

                evidence = inv.evidence_json or {}
                plan = evidence.get("remediation_plan") if isinstance(evidence, dict) else None
                if not has_corrective_actions(plan):
                    logger.error(
                        "runtime_remediation_blocked_no_corrective_plan",
                        investigation_id=investigation_id,
                        status=inv.status,
                    )
                    await _update_investigation(
                        investigation_id,
                        status="manual_review_required",
                        ai_error="Runtime remediation blocked: no evidence-driven corrective action is available.",
                    )
                    return

            # Infrastructure investigations: 100% manual approval enforcement
            if inv.investigation_type == "infrastructure":
                if not inv.approval or inv.approval.decision != "approved":
                    logger.error(
                        "infrastructure_remediation_blocked_no_approval",
                        investigation_id=investigation_id,
                        status=inv.status,
                    )
                    await _update_investigation(
                        investigation_id,
                        status="failed",
                        ai_error="Infrastructure remediation blocked: explicit manual approval is required before execution.",
                    )
                    return
                logger.info(
                    "infrastructure_remediation_approved",
                    investigation_id=investigation_id,
                    approved_by=inv.approval.decided_by,
                )

            # Determine which playbook to use (edited or original)
            playbook_yaml = inv.playbook_yaml or ""
            
            logger.info("PLAYBOOK_RAW_CHECK",
                        has_playbook=bool(playbook_yaml),
                        first_200_chars=playbook_yaml[:200] if playbook_yaml else "",
                        investigation_id=investigation_id)
            
            if inv.approval and inv.approval.edited_playbook:
                playbook_yaml = inv.approval.edited_playbook
                logger.info("ansible_using_edited_playbook", investigation_id=investigation_id)

            if not playbook_yaml.strip():
                logger.error("ansible_exec_no_playbook", investigation_id=investigation_id)
                await _update_investigation(investigation_id, status="failed")
                return

            # Resolve per-asset config if asset_id is present
            host_config = None
            if inv.asset_id:
                from sqlalchemy import select
                from response.db import AsyncSessionLocal
                from response.models import MonitoredAsset
                try:
                    async with AsyncSessionLocal() as session:
                        result = await session.execute(select(MonitoredAsset).where(MonitoredAsset.asset_id == inv.asset_id))
                        asset = result.scalar_one_or_none()
                        if asset:
                            host_config = asset.ansible_config_json or {}
                            if not asset.enabled:
                                logger.error("remediation_blocked_disabled_asset", investigation_id=investigation_id, asset_id=inv.asset_id)
                                await _update_investigation(investigation_id, status="failed", ai_error="Remediation blocked: target asset is disabled.")
                                return
                            if not asset.remediation_enabled:
                                logger.error("remediation_blocked_not_enabled", investigation_id=investigation_id, asset_id=inv.asset_id)
                                await _update_investigation(investigation_id, status="failed", ai_error="Remediation blocked: remediation is not enabled for this asset.")
                                return
                except Exception as e:
                    logger.warning("asset_config_resolution_failed", investigation_id=investigation_id, asset_id=inv.asset_id, error=str(e))

            # Replace placeholder host with real target
            # If target_host is a hostname that can't be resolved, use ansible_remote_host (IP)
            # When configured for local connection, always use localhost and skip SSH checks
            is_local = _is_local_connection(host_config)
            if is_local:
                target_host = settings.ansible_remote_host or "localhost"
                logger.info("ansible_local_mode", investigation_id=investigation_id, target=target_host)
            else:
                if host_config and host_config.get("ansible_host"):
                    target_host = host_config["ansible_host"]
                else:
                    target_host = inv.target_host
                if target_host:
                    # Verify target_host is resolvable - if not, fall back to remote_host
                    import socket
                    try:
                        socket.gethostbyname(target_host)
                    except socket.gaierror:
                        if not host_config:
                            logger.warning("target_host_not_resolvable", host=target_host, falling_back=settings.ansible_remote_host)
                            target_host = settings.ansible_remote_host or "localhost"
                        else:
                            logger.error("target_host_not_resolvable", host=target_host)
                            await _update_investigation(investigation_id, status="failed", ai_error=f"Target host {target_host} is not resolvable.")
                            return
                else:
                    if not host_config:
                        target_host = settings.ansible_remote_host or "localhost"
                    else:
                        logger.error("target_host_missing", investigation_id=investigation_id)
                        await _update_investigation(investigation_id, status="failed", ai_error="Target host is missing from asset configuration.")
                        return
            
            # Replace the hostname in the playbook with "target" to match inventory group
            # This ensures the playbook runs against the [target] group defined in inventory
            # The playbook contains the original hostname from AI generation (e.g., "ghazi")
            # We need to replace that with "target" to match our inventory group
            
            # Try to find what hostname is in the playbook and replace it
            # Common patterns: hosts: ghazi, hosts: target, etc.
            import re
            hosts_match = re.search(r'^  hosts:\s*(\S+)', playbook_yaml, re.MULTILINE)
            playbook_hosts = hosts_match.group(1) if hosts_match else None
            
            logger.warning("DEBUG_REPLACE", 
                           inv_target_host=inv.target_host, 
                           target_host=target_host, 
                           playbook_hosts=playbook_hosts,
                           investigation_id=investigation_id)
            
            if playbook_hosts and playbook_hosts != "target":
                new_playbook = playbook_yaml.replace(f"hosts: {playbook_hosts}", "hosts: target")
                if new_playbook != playbook_yaml:
                    logger.info("playbook_hosts_replaced", old=playbook_hosts, new="target", investigation_id=investigation_id)
                    playbook_yaml = new_playbook
                else:
                    logger.warning("playbook_hosts_replace_failed", playbook_hosts=playbook_hosts, investigation_id=investigation_id)
            
            # Fix common Jinja2 template issues in AI-generated playbooks
            # Fix: loop: "{ var }" -> loop: "{{ var }}"
            playbook_yaml = re.sub(r'loop:\s*"\{\s*(\w+)\s*\}"', r'loop: "{{ \1 }}"', playbook_yaml)
            # Fix: loop: '{ var }' -> loop: '{{ var }}'
            playbook_yaml = re.sub(r"loop:\s*'\{\s*(\w+)\s*\}'", r"loop: '{{ \1 }}'", playbook_yaml)
            
            # ULTRA AGGRESSIVE FIX for iptables source/destination with {item}
            # Match ANY occurrence of "{ item }" or "{item}" or " { item }" in YAML values
            # This catches all variations of broken Jinja2 in iptables tasks
            
            logger.info("BEFORE_JINJA_FIX", 
                        sample_lines=[l for l in playbook_yaml.split('\n') if 'source:' in l or 'destination:' in l][:4],
                        investigation_id=investigation_id)
            
            # Fix patterns like: source: "{ item }" or destination: "{ item }"
            playbook_yaml = re.sub(r'(source|destination):\s*"\{\s*item\s*\}"', r'\1: "{{ item }}"', playbook_yaml)
            # Pattern 2: source: '{ item }' or destination: '{ item }'
            playbook_yaml = re.sub(r"(source|destination):\s*'\{\s*item\s*\}'", r"\1: '{{ item }}'", playbook_yaml)
            # Pattern 3: source: "{item}" (no spaces)
            playbook_yaml = re.sub(r'(source|destination):\s*"\{item\}"', r'\1: "{{ item }}"', playbook_yaml)
            # Pattern 4: source: '{item}'
            playbook_yaml = re.sub(r"(source|destination):\s*'\{item\}'", r"\1: '{{ item }}'", playbook_yaml)
            # Pattern 5: source: { item } (no quotes)
            playbook_yaml = re.sub(r'(source|destination):\s*\{\s*item\s*\}', r'\1: "{{ item }}"', playbook_yaml)
            # Pattern 6: source: "text { item }" or 'text { item }'
            playbook_yaml = re.sub(r'(source|destination):\s*"[^"]*\{\s*item\s*\}[^"]*"', r'\1: "{{ item }}"', playbook_yaml)
            playbook_yaml = re.sub(r"(source|destination):\s*'[^']*\{\s*item\s*\}[^']*'", r"\1: '{{ item }}'", playbook_yaml)
            
            logger.info("AFTER_JINJA_FIX",
                        sample_lines=[l for l in playbook_yaml.split('\n') if 'source:' in l or 'destination:' in l][:4],
                        investigation_id=investigation_id)
            
            # Validate YAML syntax first
            try:
                parsed = yaml.safe_load(playbook_yaml)
                if not isinstance(parsed, list):
                    raise ValueError("Playbook must be a YAML list")
                # Block hosts: all / hosts: '*' to prevent accidental multi-host execution
                for play in parsed:
                    if isinstance(play, dict):
                        hosts_value = play.get("hosts", "")
                        if isinstance(hosts_value, str) and hosts_value.lower() in ("all", "*"):
                            logger.error("ansible_exec_hosts_all_blocked", investigation_id=investigation_id, hosts=hosts_value)
                            await _update_investigation(investigation_id, status="failed", ai_error=f"Remediation blocked: playbook contains 'hosts: {hosts_value}' which is not allowed for security reasons.")
                            return
            except Exception as e:
                logger.error("ansible_exec_invalid_yaml", investigation_id=investigation_id, error=str(e))
                await _update_investigation(investigation_id, status="failed", ai_error=f"YAML syntax error: {e}")
                # Create ARIA alert for execution failure
                try:
                    async with AsyncSessionLocal() as alert_session:
                        from response.aria_alerts import alert_on_execution_failed
                        from response.models import Investigation
                        result = await alert_session.execute(select(Investigation).where(Investigation.id == investigation_id))
                        inv_alert = result.scalar_one_or_none()
                        if inv_alert:
                            await alert_on_execution_failed(alert_session, inv_alert, None)
                except Exception:
                    pass
                return
            
            # Validate Ansible syntax before running
            is_valid_ansible, ansible_error = await _validate_ansible_syntax(playbook_yaml, investigation_id)
            if not is_valid_ansible:
                logger.error("ansible_exec_invalid_syntax", investigation_id=investigation_id, error=ansible_error)
                await _update_investigation(investigation_id, status="failed", ai_error=f"Ansible syntax error: {ansible_error}")
                return

            # SSH pre-flight check: verify connectivity before executing
            # Skip entirely when running in local mode (ansible_connection=local)
            # Uses per-asset credentials from host_config when available
            ssh_user = settings.ansible_remote_user or inv.target_user or "root"
            ssh_port = settings.ansible_ssh_port or 22
            auth_type = "private_key"
            ssh_key = settings.ansible_ssh_key or ""
            ssh_password = settings.ansible_ssh_password or ""

            if host_config:
                if host_config.get("ansible_user"):
                    ssh_user = host_config["ansible_user"]
                if host_config.get("ansible_port"):
                    ssh_port = int(host_config["ansible_port"])
                auth_type = host_config.get("auth_type", "private_key")
                if auth_type == "password":
                    secret_ref = host_config.get("password_secret_ref")
                    if secret_ref:
                        ssh_password = os.environ.get(secret_ref, "")
                    elif not ssh_password:
                        ssh_password = settings.ansible_ssh_password or ""
                    ssh_key = ""
                elif auth_type == "private_key":
                    key_ref = host_config.get("ssh_key_ref")
                    if key_ref and os.path.exists(key_ref):
                        ssh_key = key_ref
                    elif not ssh_key:
                        ssh_key = settings.ansible_ssh_key or ""
                    ssh_password = ""

            if not is_local:
                async def _try_ssh(cmd: list, desc: str) -> bool:
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdin=asyncio.subprocess.DEVNULL,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
                        if proc.returncode == 0 and b"opensoar_ssh_ok" in stdout:
                            logger.info("ansible_ssh_preflight_ok", investigation_id=investigation_id, target=target_host, method=desc)
                            return True
                        err = stderr.decode().strip()[:200] if stderr else "unknown error"
                        logger.debug("ansible_ssh_preflight_attempt_failed", investigation_id=investigation_id, target=target_host, method=desc, error=err)
                        return False
                    except Exception as e:
                        logger.debug("ansible_ssh_preflight_attempt_error", investigation_id=investigation_id, target=target_host, method=desc, error=str(e))
                        return False

                ssh_ok = False
                base_ssh = [
                    "-o", "ConnectTimeout=10",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-p", str(ssh_port),
                ]

                if auth_type == "private_key":
                    # Attempt 1: key-based auth
                    key_cmd = ["ssh", "-o", "BatchMode=yes"] + base_ssh
                    if ssh_key:
                        key_cmd.extend(["-i", ssh_key])
                    key_cmd.extend([f"{ssh_user}@{target_host}", "echo", "opensoar_ssh_ok"])
                    ssh_ok = await _try_ssh(key_cmd, "key")
                elif auth_type == "password" and ssh_password:
                    # Attempt: password-based auth
                    pass_cmd = ["sshpass", "-p", ssh_password, "ssh"] + base_ssh
                    pass_cmd.extend([f"{ssh_user}@{target_host}", "echo", "opensoar_ssh_ok"])
                    ssh_ok = await _try_ssh(pass_cmd, "password")

                if not ssh_ok:
                    logger.error("ansible_ssh_preflight_failed", investigation_id=investigation_id, target=target_host)
                    await _update_investigation(
                        investigation_id,
                        status="failed",
                        ai_error=f"SSH pre-flight check failed for {target_host}. "
                                 f"Ensure password or SSH key authentication is configured correctly.",
                    )
                    # Create ARIA alert for execution failure
                    try:
                        async with AsyncSessionLocal() as alert_session:
                            from response.aria_alerts import alert_on_execution_failed
                            from response.models import Investigation
                            result = await alert_session.execute(select(Investigation).where(Investigation.id == investigation_id))
                            inv_alert = result.scalar_one_or_none()
                            if inv_alert:
                                await alert_on_execution_failed(alert_session, inv_alert, None)
                    except Exception:
                        pass
                    return

            # Whitelist check: do not execute against whitelisted targets
            from core.whitelist import is_whitelisted
            target_host_for_check = target_host
            if target_host_for_check and await is_whitelisted(target_host_for_check):
                logger.warning(
                    "ansible_target_whitelisted",
                    investigation_id=investigation_id,
                    target=target_host_for_check,
                )
                await _update_investigation(
                    investigation_id,
                    status="failed",
                    ai_error=f"Target {target_host_for_check} is whitelisted. Execution blocked.",
                )
                return

            # The inventory defines [target] group pointing to the real host

            # Validate YAML before running
            try:
                parsed = yaml.safe_load(playbook_yaml)
                if not isinstance(parsed, list):
                    raise ValueError("Playbook must be a YAML list")
            except Exception as e:
                logger.error("ansible_exec_invalid_yaml", investigation_id=investigation_id, error=str(e))
                await _update_investigation(investigation_id, status="failed")
                return

            # Create or reuse run record (idempotent — handles duplicate calls)
            from sqlalchemy import select as sa_select
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    sa_select(PlaybookRun).where(PlaybookRun.investigation_id == investigation_id)
                )
                existing_run = result.scalar_one_or_none()
                if existing_run:
                    run_id = existing_run.id
                    existing_run.status = "running"
                    existing_run.started_at = datetime.now(timezone.utc)
                    existing_run.finished_at = None
                    existing_run.exit_code = None
                    existing_run.output = None
                    await session.commit()
                else:
                    run = PlaybookRun(
                        investigation_id=investigation_id,
                        status="running",
                        started_at=datetime.now(timezone.utc),
                        verification_plan_json=inv.verification_plan_json,
                    )
                    session.add(run)
                    await session.commit()
                    run_id = run.id

            await _update_investigation(investigation_id, status="running")
            
            # Broadcast execution started
            try:
                from api.websocket import broadcast_investigation_change
                asyncio.create_task(broadcast_investigation_change(investigation_id, "approved", "running", "Playbook execution started"))
            except Exception:
                pass

            if not settings.ansible_enabled:
                # Dry-run mode — log what would happen, don't actually run
                dry_output = (
                    f"[DRY RUN] ANSIBLE_ENABLED=false — playbook was NOT executed.\n"
                    f"Would run against: {target_host}\n"
                    f"Playbook preview:\n{playbook_yaml[:500]}\n"
                    f"Set ANSIBLE_ENABLED=true in .env to enable real execution."
                )
                logger.info(
                    "ansible_dry_run",
                    investigation_id=investigation_id,
                    target=target_host,
                )
                await _update_run(
                    run_id,
                    status="skipped",
                    output=dry_output,
                    exit_code=0,
                    finished_at=datetime.now(timezone.utc),
                )
                await _update_investigation(investigation_id, status="completed")
                # Trigger fix verifier even in dry-run so the flow completes
                asyncio.create_task(_trigger_fix_verifier(investigation_id))
                return

            # Determine effective SSH user (fall back to settings if investigation has default)
            effective_user = inv.target_user
            if host_config and host_config.get("ansible_user"):
                effective_user = host_config["ansible_user"]
            elif effective_user == "root" and settings.ansible_remote_user:
                effective_user = settings.ansible_remote_user

            # Ensure playbook directory exists
            PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
            
            # Write playbook and inventory to disk
            playbook_path = _write_playbook(investigation_id, playbook_yaml)
            inventory_path = _write_inventory(investigation_id, target_host, effective_user, host_config)

            # Detect target OS (cache in investigation)
            if not inv.target_os:
                if is_local:
                    detected_os = "linux"
                else:
                    detected_os = await _detect_os(target_host, effective_user, host_config)
                await _update_investigation(investigation_id, target_os=detected_os)
                logger.info("ansible_target_os_detected",
                            investigation_id=investigation_id,
                            os=detected_os)

            # Test SSH connection before running playbook
            if settings.ansible_enabled and not is_local:
                logger.info("ansible_testing_connection", investigation_id=investigation_id, target=target_host)
                conn_ok, conn_error = await _test_ssh_connection(target_host, effective_user, host_config)
                if not conn_ok:
                    logger.error("ansible_connection_failed", investigation_id=investigation_id, target=target_host, error=conn_error)
                    await _update_run(
                        run_id,
                        status="failed",
                        output=f"SSH connection failed: {conn_error}",
                        exit_code=-1,
                        finished_at=datetime.now(timezone.utc),
                    )
                    
                    # If SSH fails, set to pending instead of failed - allows retry with corrected credentials
                    if "auth_failed" in conn_error:
                        await _update_investigation(
                            investigation_id, 
                            status="pending",
                            ai_error=f"SSH auth failed: {conn_error}. Check ANSIBLE_REMOTE_USER and ANSIBLE_SSH_PASSWORD in .env"
                        )
                        logger.warning("ansible_ssh_auth_failed_retrying", 
                                     investigation_id=investigation_id, 
                                     error=conn_error)
                    else:
                        await _update_investigation(investigation_id, status="failed")
                    return

            # Firewall safety check for immediate execution too
            protected_ips = await _get_protected_ips(target_host)
            is_safe, safety_error, sanitized_yaml = _sanitize_firewall_tasks(playbook_yaml, protected_ips)
            if not is_safe:
                logger.error("ansible_firewall_safety_blocked",
                             investigation_id=investigation_id,
                             error=safety_error)
                await _update_run(
                    run_id,
                    status="failed",
                    output=f"FIREWALL SAFETY BLOCKED:\n{safety_error}",
                    exit_code=-1,
                    finished_at=datetime.now(timezone.utc),
                )
                await _update_investigation(
                    investigation_id,
                    status="failed",
                    ai_error=f"Firewall safety blocked execution: {safety_error[:500]}",
                )
                # Create ARIA alert for execution failure
                try:
                    async with AsyncSessionLocal() as alert_session:
                        from response.aria_alerts import alert_on_execution_failed
                        from response.models import Investigation
                        result = await alert_session.execute(select(Investigation).where(Investigation.id == investigation_id))
                        inv_alert = result.scalar_one_or_none()
                        if inv_alert:
                            await alert_on_execution_failed(alert_session, inv_alert, None)
                except Exception:
                    pass
                return

            # Comprehensive playbook safety validation
            from response.playbook_safety import validate_playbook_safety
            investigation_context = {
                "investigation_type": inv.investigation_type or "security",
                "target_host": target_host,
                "alert_sources": [],
            }
            safety = validate_playbook_safety(sanitized_yaml, investigation_context)
            if not safety["executable"]:
                logger.error("ansible_comprehensive_safety_blocked",
                             investigation_id=investigation_id,
                             reasons=safety["reasons"])
                await _update_run(
                    run_id,
                    status="failed",
                    output="SAFETY VALIDATION BLOCKED:\n" + "\n".join(f"- {r}" for r in safety["reasons"]),
                    exit_code=-1,
                    finished_at=datetime.now(timezone.utc),
                )
                await _update_investigation(
                    investigation_id,
                    status="failed",
                    ai_error="SAFETY VALIDATION BLOCKED:\n" + "\n".join(f"- {r}" for r in safety["reasons"]),
                )
                # Create ARIA alert for execution failure
                try:
                    async with AsyncSessionLocal() as alert_session:
                        from response.aria_alerts import alert_on_execution_failed
                        from response.models import Investigation
                        result = await alert_session.execute(select(Investigation).where(Investigation.id == investigation_id))
                        inv_alert = result.scalar_one_or_none()
                        if inv_alert:
                            await alert_on_execution_failed(alert_session, inv_alert, None)
                except Exception:
                    pass
                return

            # Rewrite sanitized playbook
            playbook_path.write_text(sanitized_yaml, encoding="utf-8")

            # Branch: Staged vs Immediate execution
            if settings.staged_remediation_enabled:
                logger.info("ansible_staged_execution_enabled",
                            investigation_id=investigation_id,
                            evidence_first=settings.staged_remediation_evidence_first,
                            dry_run_first=settings.staged_remediation_dry_run_first)
                await _execute_staged_remediation(
                    investigation_id, inv, sanitized_yaml, target_host, run_id, host_config
                )
                return

            # ─── Immediate (monolithic) execution path ───
            logger.info(
                "ansible_running",
                investigation_id=investigation_id,
                target=target_host,
                playbook=str(playbook_path),
            )

            exit_code, output = await _run_ansible(playbook_path, inventory_path, host_config=host_config)

            # Better status determination based on exit code
            if exit_code == 0:
                status = "completed"
                failure_reason = None
            elif exit_code == -15:
                # SIGTERM - likely timeout or killed
                status = "failed"
                failure_reason = "timeout"
                logger.warning("ansible_execution_timeout", investigation_id=investigation_id)
            elif exit_code == -9:
                # SIGKILL - killed forcefully
                status = "failed"
                failure_reason = "killed"
                logger.warning("ansible_execution_killed", investigation_id=investigation_id)
            elif exit_code > 0:
                # Analyze output for specific errors
                status = "failed"
                if "Permission denied" in output:
                    failure_reason = "permission_denied"
                    logger.warning("ansible_permission_denied", investigation_id=investigation_id)
                elif "Connection refused" in output:
                    failure_reason = "connection_refused"
                    logger.warning("ansible_connection_refused", investigation_id=investigation_id)
                elif "UNREACHABLE" in output:
                    failure_reason = "unreachable"
                    logger.warning("ansible_host_unreachable", investigation_id=investigation_id)
                elif "FAILED" in output:
                    failure_reason = "task_failed"
                    # Count failed tasks
                    import re
                    failed_matches = re.findall(r'failed=(\d+)', output)
                    if failed_matches:
                        failure_reason = f"task_failed_{failed_matches[0]}_tasks"
                else:
                    failure_reason = "unknown_error"
            
            await _update_run(
                run_id,
                status=status,
                output=output,
                exit_code=exit_code,
                finished_at=datetime.now(timezone.utc),
            )
            await _update_investigation(investigation_id, status=status)
            
            # Broadcast execution completed
            try:
                from api.websocket import broadcast_investigation_change
                old_status = "running"
                details = f"Playbook execution {status}" + (f": {failure_reason}" if failure_reason else "")
                await broadcast_investigation_change(investigation_id, old_status, status, details)
            except Exception:
                pass

            logger.info(
                "ansible_execution_finished",
                investigation_id=investigation_id,
                exit_code=exit_code,
                status=status,
                failure_reason=failure_reason,
                output_lines=output.count("\n"),
            )

            # Trigger verification based on exit code
            if exit_code == 0:
                asyncio.create_task(_trigger_fix_verifier(investigation_id))
            else:
                logger.warning(
                    "ansible_execution_failed",
                    investigation_id=investigation_id,
                    exit_code=exit_code,
                    failure_reason=failure_reason,
                )
                # Create ARIA alert for execution failure
                try:
                    async with AsyncSessionLocal() as alert_session:
                        from response.aria_alerts import alert_on_execution_failed
                        inv_result = await alert_session.execute(select(Investigation).where(Investigation.id == investigation_id))
                        inv_alert = inv_result.scalar_one_or_none()
                        run_result = await alert_session.execute(select(PlaybookRun).where(PlaybookRun.investigation_id == investigation_id))
                        run_alert = run_result.scalar_one_or_none()
                        if inv_alert:
                            await alert_on_execution_failed(alert_session, inv_alert, run_alert)
                except Exception:
                    pass
                # Always verify - even if playbook failed, we need to know if problem got worse
                asyncio.create_task(_trigger_fix_verifier(investigation_id))


    finally:
        _EXECUTING_IDS.discard(investigation_id)

async def _verify_fix_via_elasticsearch(investigation_id: str, inv) -> str:
    """Query Elasticsearch to confirm the threat is gone after remediation.
    
    Returns a human-readable result string.
    """
    try:
        from core.elasticsearch import get_es_client
        es = await get_es_client()
        
        # Get source IPs from the investigation
        source_ips = []
        if inv.source_ips:
            source_ips = [ip.strip() for ip in inv.source_ips.split(",") if ip.strip()]
        
        if not source_ips:
            return "No source IPs available for ES verification."
        
        # Query window: last 5 minutes since remediation started
        window_start = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        window_end = datetime.now(timezone.utc).isoformat()
        
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": window_start, "lte": window_end}}},
                    {"terms": {"source_ip.keyword": source_ips}},
                ]
            }
        }
        
        response = await es.search(
            index="*",
            query=query,
            size=0,
            track_total_hits=True,
        )
        
        total_hits = response.get("hits", {}).get("total", {})
        if isinstance(total_hits, dict):
            total_hits = total_hits.get("value", 0)
        
        if total_hits == 0:
            return (
                f"✅ VERIFICATION PASSED: No new alerts from {', '.join(source_ips)} "
                f"in the last 5 minutes. Threat appears contained."
            )
        else:
            return (
                f"⚠️ VERIFICATION WARNING: {total_hits} new alert(s) detected from "
                f"{', '.join(source_ips)} in the last 5 minutes. "
                f"Containment may be incomplete."
            )
    except Exception as e:
        logger.warning("es_verification_failed", investigation_id=investigation_id, error=str(e))
        return f"ES verification error: {str(e)}"


async def _append_to_phase_output(run_id: str, phase: str, text: str):
    """Append text to a phase's output_preview in phases_json."""
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PlaybookRun).where(PlaybookRun.id == run_id)
            )
            run = result.scalar_one_or_none()
            if run and run.phases_json:
                phases = dict(run.phases_json)
                if phase in phases:
                    current = phases[phase].get("output_preview", "")
                    phases[phase]["output_preview"] = current + text
                    run.phases_json = phases
                    await session.commit()
    except Exception as e:
        logger.debug("append_phase_output_failed", error=str(e))


async def _trigger_fix_verifier(investigation_id: str):
    """Schedule a persistent fix verification job instead of an ephemeral sleep."""
    from response.fix_verifier import schedule_verification_job
    await schedule_verification_job(investigation_id)


async def _test_ssh_connection(target_host: str, target_user: str, host_config: Optional[dict] = None) -> tuple[bool, str]:
    """
    Test SSH connection to target host before running playbook.
    Uses per-asset credentials from host_config when available, falling back
    to global settings.
    Returns (success, error_message).
    """
    # Resolve effective host: ansible_host override takes precedence
    effective_host = target_host
    if host_config and host_config.get("ansible_host"):
        effective_host = host_config["ansible_host"]

    # Resolve effective user: ansible_user override takes precedence
    effective_user = target_user
    if host_config and host_config.get("ansible_user"):
        effective_user = host_config["ansible_user"]

    auth_type = "private_key"
    ssh_key = settings.ansible_ssh_key or ""
    ssh_password = settings.ansible_ssh_password or ""
    ssh_port = settings.ansible_ssh_port or 22

    if host_config:
        auth_type = host_config.get("auth_type", "private_key")
        if host_config.get("ansible_port"):
            ssh_port = int(host_config["ansible_port"])
        if auth_type == "password":
            secret_ref = host_config.get("password_secret_ref")
            if secret_ref:
                ssh_password = os.environ.get(secret_ref, "")
            elif not ssh_password:
                ssh_password = settings.ansible_ssh_password or ""
            ssh_key = ""
        elif auth_type == "private_key":
            key_ref = host_config.get("ssh_key_ref")
            if key_ref and os.path.exists(key_ref):
                ssh_key = key_ref
            elif not ssh_key:
                ssh_key = settings.ansible_ssh_key or ""
            ssh_password = ""
    
    logger.info("ssh_connection_test", 
                host=target_host, 
                user=target_user, 
                port=ssh_port,
                auth_type=auth_type,
                has_key=bool(ssh_key),
                has_password=bool(ssh_password),
                has_host_config=bool(host_config))
    
    # Use shell=True with sshpass for reliable password auth
    if ssh_password and shutil.which("sshpass"):
        env = os.environ.copy()
        env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
        env["SSHPASS"] = ssh_password
        cmd = f"sshpass -e ssh -o BatchMode=no -o NumberOfPasswordPrompts=1 -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p {ssh_port} {effective_user}@{effective_host} echo 'SSH_OK'"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=15)
        except asyncio.TimeoutError:
            proc.kill()
            logger.error("ssh_timeout", host=target_host, user=target_user, timeout=15)
            return False, "timeout"
        
        if proc.returncode == 0:
            logger.info("ssh_connection_success", host=target_host, user=target_user)
            return True, ""
        else:
            stdout, stderr = await proc.communicate()
            error_msg = stderr.decode().strip() if stderr else "Unknown error"
            
            # Categorize the error for better debugging
            if "permission denied" in error_msg.lower() or "authentication failed" in error_msg.lower():
                error_type = "auth_failed"
                logger.error("ssh_auth_failed", 
                           host=target_host, 
                           user=target_user, 
                           password_set=bool(ssh_password),
                           key_set=bool(ssh_key),
                           error=error_msg)
                return False, f"auth_failed: {error_msg}"
            elif "connection refused" in error_msg.lower():
                error_type = "connection_refused"
                logger.error("ssh_connection_refused", host=target_host, port=ssh_port)
                return False, f"connection_refused: Check if SSH port {ssh_port} is open"
            elif "no route to host" in error_msg.lower() or "unreachable" in error_msg.lower():
                error_type = "host_unreachable"
                logger.error("ssh_host_unreachable", host=target_host)
                return False, f"host_unreachable: Cannot reach {target_host}"
            elif "name or service not known" in error_msg.lower():
                error_type = "dns_failed"
                logger.error("ssh_dns_failed", host=target_host)
                return False, f"dns_failed: Cannot resolve {target_host}"
            else:
                logger.error("ssh_connection_error", host=target_host, user=target_user, error=error_msg)
                return False, f"connection_error: {error_msg}"
    
    # Fall back to key-based auth
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", "-p", str(ssh_port)]
    if ssh_key and auth_type == "private_key":
        cmd.extend(["-i", ssh_key])
    cmd.append(f"{effective_user}@{effective_host}")
    cmd.append("echo 'connection_test'")
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=15)
        except asyncio.TimeoutError:
            proc.kill()
            logger.error("ssh_key_timeout", host=target_host, user=target_user)
            return False, "timeout"
        
        if proc.returncode == 0:
            logger.info("ssh_key_connection_success", host=target_host, user=target_user)
            return True, ""
        else:
            stdout, stderr = await proc.communicate()
            error_msg = stderr.decode().strip() if stderr else "Unknown error"
            logger.error("ssh_key_connection_failed", host=target_host, user=target_user, error=error_msg)
            return False, f"key_auth_failed: {error_msg}"
    except Exception as e:
        logger.error("ssh_key_exception", host=target_host, user=target_user, error=str(e))
        return False, f"connection_error: {str(e)}"


# =============================================================================
# Remote Baseline Capture
# =============================================================================

async def _capture_remote_baseline(
    investigation_id: str,
    inv: Investigation,
    target_host: str,
    target_user: str,
    run_id: str,
    host_config: Optional[dict] = None,
) -> None:
    """
    Capture remote state baseline before any mutating remediation.
    Stores result in PlaybookRun.baseline_json.
    """
    verification_plan = inv.verification_plan_json or {}
    plan_type = verification_plan.get("type")

    if plan_type == "iptables_rule":
        chain = verification_plan.get("chain", "INPUT")
        source = verification_plan.get("source", "")
        jump = verification_plan.get("jump", "")
        command = f"iptables -S {chain} | grep '{source}' | grep '{jump}' && echo 'RULE_EXISTS' || echo 'RULE_ABSENT'"
    elif plan_type == "file_quarantine":
        original_path = verification_plan.get("original_path", "")
        quarantine_path = verification_plan.get("quarantine_path", "")
        command = f"test -f '{original_path}' && echo 'original_exists' || echo 'original_missing'; test -f '{quarantine_path}' && echo 'quarantine_exists' || echo 'quarantine_missing'"
    else:
        logger.info("baseline_capture_skipped",
                    investigation_id=investigation_id,
                    reason="no_verification_plan")
        return

    baseline_playbook = f"""---
- name: Baseline capture for {investigation_id}
  hosts: target
  become: true
  gather_facts: false
  tasks:
    - name: Capture baseline state
      ansible.builtin.shell: "{command}"
      register: baseline_result
      changed_when: false

    - name: Output baseline result
      ansible.builtin.debug:
        var: baseline_result.stdout
"""

    inventory_path = _write_inventory(investigation_id, target_host, target_user, host_config)
    baseline_path = PLAYBOOKS_DIR / f"{investigation_id}_baseline.yml"
    baseline_path.write_text(baseline_playbook, encoding="utf-8")

    try:
        exit_code, output = await _run_ansible(baseline_path, inventory_path, host_config=host_config)
    except Exception as e:
        logger.error("baseline_capture_failed",
                     investigation_id=investigation_id,
                     error=str(e))
        return

    if plan_type == "iptables_rule":
        chain = verification_plan.get("chain", "INPUT")
        source = verification_plan.get("source", "")
        jump = verification_plan.get("jump", "")
        rule_exists = f"-A {chain} -s {source}/32 -j {jump}" in output or f"-A {chain} -s {source} -j {jump}" in output
    elif plan_type == "file_quarantine":
        rule_exists = "original_exists" in output

    baseline_json = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "host": target_host,
        "command": command,
        "exit_code": exit_code,
        "stdout": output[:4000] if output else "",
        "stderr": "",
        "rule_exists": rule_exists,
        "plan_type": plan_type,
    }

    await _update_run(run_id, baseline_json=baseline_json)
    logger.info("baseline_captured",
                investigation_id=investigation_id,
                host=target_host,
                rule_exists=rule_exists,
                plan_type=plan_type)

    try:
        from response.audit_events import record_audit_event
        async with AsyncSessionLocal() as session:
            await record_audit_event(
                session, investigation_id, "baseline_captured",
                actor="system",
                details=f"Baseline captured on {target_host}. rule_exists={rule_exists}. plan_type={plan_type}.",
            )
            await session.commit()
    except Exception:
        pass


# =============================================================================
# Rollback Execution
# =============================================================================

async def execute_rollback(
    investigation_id: str,
    decided_by: str,
    reason: str,
) -> dict:
    """
    Execute rollback playbook for a completed investigation.
    Requires admin authorization (checked by caller).
    Returns result dict with status and verification.
    """
    inv = await _get_investigation(investigation_id)
    if not inv:
        return {"status": "failed", "error": "Investigation not found"}

    if not inv.rollback_playbook:
        return {"status": "failed", "error": "No rollback playbook exists for this investigation"}

    target_host = inv.target_host or settings.ansible_remote_host
    if not target_host:
        return {"status": "failed", "error": "No target host configured"}

    # Resolve per-asset config
    host_config = None
    effective_user = inv.target_user
    if inv.asset_id:
        try:
            async with AsyncSessionLocal() as session:
                from response.models import MonitoredAsset
                result = await session.execute(select(MonitoredAsset).where(MonitoredAsset.asset_id == inv.asset_id))
                asset = result.scalar_one_or_none()
                if asset:
                    host_config = asset.ansible_config_json or {}
                    if host_config.get("ansible_user"):
                        effective_user = host_config["ansible_user"]
                    elif effective_user == "root" and settings.ansible_remote_user:
                        effective_user = settings.ansible_remote_user
                    if host_config.get("ansible_host"):
                        target_host = host_config["ansible_host"]
        except Exception:
            pass

    # Safety validation on rollback playbook
    from response.playbook_safety import validate_playbook_safety
    safety = validate_playbook_safety(
        inv.rollback_playbook,
        {"investigation_type": inv.investigation_type, "target_host": target_host, "alert_sources": []},
    )
    if not safety["executable"]:
        logger.error("rollback_safety_blocked",
                     investigation_id=investigation_id,
                     reasons=safety["reasons"])
        try:
            from response.audit_events import record_audit_event
            async with AsyncSessionLocal() as session:
                await record_audit_event(
                    session, investigation_id, "rollback_safety_blocked",
                    actor=decided_by,
                    details=f"Rollback safety blocked: {'; '.join(safety['reasons'])}",
                )
                await session.commit()
        except Exception:
            pass
        return {"status": "failed", "error": "Rollback safety blocked", "reasons": safety["reasons"]}

    # Record rollback requested / started audit events
    try:
        from response.audit_events import record_audit_event
        async with AsyncSessionLocal() as session:
            await record_audit_event(
                session, investigation_id, "rollback_requested",
                actor=decided_by,
                details=f"Rollback requested. Reason: {reason}",
            )
            await record_audit_event(
                session, investigation_id, "rollback_started",
                actor=decided_by,
                details=f"Rollback execution started on {target_host}",
            )
            await session.commit()
    except Exception:
        pass

    # Write rollback playbook and inventory
    rollback_path = PLAYBOOKS_DIR / f"{investigation_id}_rollback.yml"
    rollback_path.write_text(inv.rollback_playbook, encoding="utf-8")
    inventory_path = _write_inventory(investigation_id, target_host, effective_user, host_config)

    logger.info("rollback_execution_started",
                investigation_id=investigation_id,
                host=target_host,
                actor=decided_by)

    try:
        exit_code, output = await _run_ansible(rollback_path, inventory_path, host_config=host_config)
    except Exception as e:
        logger.error("rollback_execution_failed",
                     investigation_id=investigation_id,
                     error=str(e))
        try:
            from response.audit_events import record_audit_event
            from response.models import AriaAlert
            async with AsyncSessionLocal() as session:
                await record_audit_event(
                    session, investigation_id, "rollback_failed",
                    actor="system",
                    details=f"Rollback execution failed: {str(e)}",
                )
                alert = AriaAlert(
                    alert_type="rollback_failed",
                    severity="high",
                    investigation_id=investigation_id,
                    title=f"Rollback failed for {investigation_id}",
                    description=f"Rollback execution raised exception: {str(e)}",
                )
                session.add(alert)
                await session.commit()
        except Exception:
            pass
        return {"status": "failed", "error": f"Rollback execution failed: {str(e)}"}

    success = exit_code == 0
    status_str = "completed" if success else "failed"

    # Update investigation status
    await _update_investigation(
        investigation_id,
        status=status_str,
    )

    # Record completion audit event
    try:
        from response.audit_events import record_audit_event
        async with AsyncSessionLocal() as session:
            await record_audit_event(
                session, investigation_id,
                "rollback_completed" if success else "rollback_failed",
                actor="system",
                details=f"Rollback finished with exit_code={exit_code}. Output preview: {output[:500] if output else ''}",
            )
            await session.commit()
    except Exception:
        pass

    if not success:
        try:
            from response.models import AriaAlert
            async with AsyncSessionLocal() as session:
                alert = AriaAlert(
                    alert_type="rollback_failed",
                    severity="high",
                    investigation_id=investigation_id,
                    title=f"Rollback failed for {investigation_id}",
                    description=f"Rollback exit_code={exit_code}. Output: {output[:1000] if output else ''}",
                )
                session.add(alert)
                await session.commit()
        except Exception:
            pass
        return {"status": "failed", "error": f"Rollback playbook failed (exit {exit_code})", "output": output}

    # Post-rollback verification
    verification = await _verify_post_rollback(inv)

    return {
        "status": "completed",
        "exit_code": exit_code,
        "output": output,
        "verification": verification,
    }


async def _verify_post_rollback(inv: Investigation) -> dict:
    """
    Verify that the remote state has been restored after rollback.
    For iptables_rule: the rule must be ABSENT.
    Returns structured result dict.
    """
    verification_plan = inv.verification_plan_json or {}
    plan_type = verification_plan.get("type")
    target_host = inv.target_host or settings.ansible_remote_host
    target_user = inv.target_user

    # Resolve per-asset config
    host_config = None
    if inv.asset_id:
        try:
            async with AsyncSessionLocal() as session:
                from response.models import MonitoredAsset
                result = await session.execute(select(MonitoredAsset).where(MonitoredAsset.asset_id == inv.asset_id))
                asset = result.scalar_one_or_none()
                if asset:
                    host_config = asset.ansible_config_json or {}
                    if host_config.get("ansible_user"):
                        target_user = host_config["ansible_user"]
                    if host_config.get("ansible_host"):
                        target_host = host_config["ansible_host"]
        except Exception:
            pass

    if not plan_type or not target_host:
        return {"status": "skipped", "reason": "no verification plan or target host"}

    if plan_type == "iptables_rule":
        chain = verification_plan.get("chain", "INPUT")
        source = verification_plan.get("source", "")
        command = f"iptables -S {chain} | grep '{source}' || true"
    elif plan_type == "file_quarantine":
        original_path = verification_plan.get("original_path", "")
        command = f"test -f '{original_path}' && echo 'exists' || echo 'missing'"
    else:
        return {"status": "skipped", "reason": f"unsupported plan type: {plan_type}"}

    verify_playbook = f"""---
- name: Post-rollback verification for {inv.id}
  hosts: target
  become: true
  gather_facts: false
  tasks:
    - name: Verify rollback state
      ansible.builtin.shell: "{command}"
      register: verify_result
      changed_when: false

    - name: Output verification result
      ansible.builtin.debug:
        var: verify_result.stdout
"""

    inventory_path = _write_inventory(inv.id, target_host, target_user, host_config)
    verify_path = PLAYBOOKS_DIR / f"{inv.id}_post_rollback_verify.yml"
    verify_path.write_text(verify_playbook, encoding="utf-8")

    try:
        exit_code, output = await _run_ansible(verify_path, inventory_path, host_config=host_config)
    except Exception as e:
        result = {
            "status": "failed",
            "reason": f"Exception during post-rollback verification: {str(e)}",
            "command": command,
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
        }
        await _update_investigation(inv.id, post_rollback_verification_json=result)
        return result

    if plan_type == "iptables_rule":
        passed = exit_code == 0 and f"-A {chain} -s {source}" not in output
    elif plan_type == "file_quarantine":
        passed = exit_code == 0 and "exists" in output
    else:
        passed = exit_code == 0

    result = {
        "status": "passed" if passed else "failed",
        "command": command,
        "exit_code": exit_code,
        "stdout": output[:4000] if output else "",
        "stderr": "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    await _update_investigation(inv.id, post_rollback_verification_json=result)

    try:
        from response.audit_events import record_audit_event
        async with AsyncSessionLocal() as session:
            await record_audit_event(
                session, inv.id,
                "post_rollback_verification_passed" if passed else "post_rollback_verification_failed",
                actor="system",
                details=f"Post-rollback verification {result['status']} on {target_host}. Command: {command}. Exit: {exit_code}.",
            )
            await session.commit()
    except Exception:
        pass

    return result
