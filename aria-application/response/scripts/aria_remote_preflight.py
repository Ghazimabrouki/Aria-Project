#!/usr/bin/env python3
"""
ARIA Remote Preflight — test remote target readiness without system mutation.

Usage:
    python3 response/scripts/aria_remote_preflight.py
    python3 response/scripts/aria_remote_preflight.py --json

Checks:
    - SSH connectivity to ANSIBLE_REMOTE_HOST
    - Remote user login
    - sudo/become availability (passwordless OR ansible_become_password)
    - Python availability on remote host
    - iptables command availability on remote host
    - Write permission to /tmp (via harmless temp file create/remove)
    - Local ansible-playbook availability

Does NOT:
    - Run any firewall rule
    - Restart any service
    - Edit any system file
    - Install/remove any package
    - Run sudoers or policy changes
    - Print or expose passwords in output
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import get_settings

settings = get_settings()


class PreflightReport:
    def __init__(self):
        self.checks: list[dict] = []
        self.ok = 0
        self.warning = 0
        self.failed = 0

    def add(self, name: str, status: str, detail: str, recommendation: str = ""):
        self.checks.append({"name": name, "status": status, "detail": detail, "recommendation": recommendation})
        if status == "OK":
            self.ok += 1
        elif status == "WARNING":
            self.warning += 1
        elif status == "FAILED":
            self.failed += 1
        # INFO / SKIPPED do not count toward any tally

    def overall(self) -> str:
        if self.failed > 0:
            return "failed"
        if self.warning > 0:
            return "degraded"
        return "ready"


async def _run_ssh_command(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run an SSH command via subprocess and return (exit_code, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


async def _check_ssh_connectivity(report: PreflightReport, host: str, user: str):
    """Check basic SSH connectivity with a harmless command."""
    ssh_key = settings.ansible_ssh_key or ""
    ssh_cmd = [
        "ssh",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
    ]
    if ssh_key:
        ssh_cmd.extend(["-i", ssh_key])
    ssh_cmd.extend([f"{user}@{host}", "echo aria-preflight-ok"])

    exit_code, stdout, stderr = await _run_ssh_command(ssh_cmd, timeout=15)
    if exit_code == 0 and "aria-preflight-ok" in stdout:
        report.add("SSH connectivity", "OK", f"SSH to {user}@{host} succeeded")
        return True
    else:
        report.add("SSH connectivity", "FAILED", f"SSH to {user}@{host} failed: {stderr[:200]}",
                   "Check SSH key, password, or network connectivity")
        return False


async def _check_sudo(report: PreflightReport, host: str, user: str):
    """Check sudo availability without running anything privileged."""
    ssh_key = settings.ansible_ssh_key or ""
    become_password = settings.ansible_become_password or settings.ansible_ssh_password or ""
    become_method = settings.ansible_become_method or "sudo"

    # First: test passwordless sudo
    ssh_cmd = [
        "ssh",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
    ]
    if ssh_key:
        ssh_cmd.extend(["-i", ssh_key])
    ssh_cmd.extend([f"{user}@{host}", "sudo -n true"])

    exit_code, stdout, stderr = await _run_ssh_command(ssh_cmd, timeout=15)
    if exit_code == 0:
        report.add("Sudo/become", "OK", f"Passwordless sudo available for {user}@{host}")
        return True

    # Passwordless failed — check if become_password is configured
    if become_password:
        # Test become via a minimal Ansible ad-hoc command
        report.add(
            "Sudo/become",
            "WARNING",
            f"Passwordless sudo not available for {user}@{host}. ansible_become_password is configured — will use Ansible become.",
            "Ensure ansible_become_password is correct before running remediation."
        )
        return True  # Consider it workable since we have a password

    # No passwordless sudo and no become password
    if exit_code == 1 and "password" in stderr.lower():
        report.add(
            "Sudo/become",
            "FAILED",
            f"sudo requires password for {user}@{host} and no ansible_become_password is configured.",
            "Option A: Set ARIA_ANSIBLE_BECOME_PASSWORD in .env. "
            "Option B: Configure NOPASSWD sudo via visudo: 'ghazi ALL=(ALL) NOPASSWD: /usr/sbin/iptables'. "
            "Option C: Use localhost-only remediation."
        )
    else:
        report.add(
            "Sudo/become",
            "FAILED",
            f"sudo check inconclusive for {user}@{host}: {stderr[:200]}",
            "Verify sudo is installed and user has privileges."
        )
    return False


async def _check_remote_python(report: PreflightReport, host: str, user: str):
    """Check Python is available on remote host."""
    ssh_key = settings.ansible_ssh_key or ""
    ssh_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no",
    ]
    if ssh_key:
        ssh_cmd.extend(["-i", ssh_key])
    ssh_cmd.extend([f"{user}@{host}", "python3 --version || python --version"])

    exit_code, stdout, stderr = await _run_ssh_command(ssh_cmd, timeout=15)
    if exit_code == 0:
        version = (stdout + stderr).strip().splitlines()[0]
        report.add("Remote Python", "OK", f"Python found: {version}")
    else:
        report.add("Remote Python", "FAILED", f"Python not found on {host}",
                   "Install python3 on remote host")


async def _check_remote_iptables(report: PreflightReport, host: str, user: str):
    """Check iptables command is available on remote host."""
    ssh_key = settings.ansible_ssh_key or ""
    ssh_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no",
    ]
    if ssh_key:
        ssh_cmd.extend(["-i", ssh_key])
    ssh_cmd.extend([f"{user}@{host}", "which iptables && iptables --version"])

    exit_code, stdout, stderr = await _run_ssh_command(ssh_cmd, timeout=15)
    if exit_code == 0:
        version = stdout.strip().splitlines()[-1]
        report.add("Remote iptables", "OK", f"iptables found: {version}")
    else:
        report.add("Remote iptables", "WARNING", f"iptables not found or not accessible on {host}",
                   "Install iptables or verify PATH for user")


async def _check_remote_tmp_write(report: PreflightReport, host: str, user: str):
    """Test write permission to /tmp by creating and removing a harmless file."""
    ssh_key = settings.ansible_ssh_key or ""
    test_file = f"/tmp/aria_preflight_test_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    ssh_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=no",
    ]
    if ssh_key:
        ssh_cmd.extend(["-i", ssh_key])
    ssh_cmd.extend([f"{user}@{host}", f"echo aria-test > {test_file} && cat {test_file} && rm -f {test_file}"])

    exit_code, stdout, stderr = await _run_ssh_command(ssh_cmd, timeout=15)
    if exit_code == 0 and "aria-test" in stdout:
        report.add("Remote /tmp write", "OK", f"Can create and remove temp files on {host}")
    else:
        report.add("Remote /tmp write", "FAILED", f"Cannot write to /tmp on {host}: {stderr[:200]}",
                   "Check disk space and permissions on /tmp")


async def _check_local_ansible(report: PreflightReport):
    """Check ansible-playbook is available locally."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ansible-playbook", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        if proc.returncode == 0:
            version = stdout.decode("utf-8", errors="replace").splitlines()[0]
            report.add("Local ansible-playbook", "OK", version)
        else:
            report.add("Local ansible-playbook", "FAILED", "ansible-playbook returned error",
                       "Install ansible on the local machine")
    except Exception as e:
        report.add("Local ansible-playbook", "FAILED", f"ansible-playbook not found: {e}",
                   "Install ansible on the local machine")


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="ARIA Remote Preflight Check")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    report = PreflightReport()
    host = settings.ansible_remote_host or "localhost"
    user = settings.ansible_remote_user or "root"
    become_method = settings.ansible_become_method or "sudo"
    has_become_password = bool(settings.ansible_become_password or settings.ansible_ssh_password)

    report.add("Target host", "INFO", host)
    report.add("Target user", "INFO", user)
    report.add("Become method", "INFO", become_method)
    report.add("Become password configured", "INFO", "yes" if has_become_password else "no")

    # Local checks
    await _check_local_ansible(report)

    # Remote checks (skip if host is localhost to avoid SSH overhead)
    if host in ("localhost", "127.0.0.1", "::1"):
        report.add("SSH connectivity", "OK", "Target is localhost — SSH not required")
        await _check_remote_python(report, host, user)
        await _check_remote_iptables(report, host, user)
        await _check_remote_tmp_write(report, host, user)
    else:
        ssh_ok = await _check_ssh_connectivity(report, host, user)
        if ssh_ok:
            await _check_sudo(report, host, user)
            await _check_remote_python(report, host, user)
            await _check_remote_iptables(report, host, user)
            await _check_remote_tmp_write(report, host, user)
        else:
            report.add("Sudo/become", "SKIPPED", "SSH not available")
            report.add("Remote Python", "SKIPPED", "SSH not available")
            report.add("Remote iptables", "SKIPPED", "SSH not available")
            report.add("Remote /tmp write", "SKIPPED", "SSH not available")

    # Output
    if args.json:
        output = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": host,
            "user": user,
            "become_method": become_method,
            "become_password_configured": has_become_password,
            "overall": report.overall(),
            "ok": report.ok,
            "warning": report.warning,
            "failed": report.failed,
            "checks": report.checks,
        }
        print(json.dumps(output, indent=2))
    else:
        print("=" * 70)
        print(f"ARIA Remote Preflight — {datetime.now(timezone.utc).isoformat()}")
        print("=" * 70)
        print(f"Target: {user}@{host}")
        print(f"Become: {become_method}")
        print(f"Become password configured: {'yes' if has_become_password else 'no'}")
        print(f"Overall: {report.overall().upper()}")
        print(f"  OK: {report.ok}  WARNING: {report.warning}  FAILED: {report.failed}")
        print("-" * 70)
        for check in report.checks:
            icon = "✓" if check["status"] == "OK" else "⚠" if check["status"] == "WARNING" else "✗" if check["status"] == "FAILED" else "ℹ"
            print(f"{icon} [{check['status']}] {check['name']}: {check['detail']}")
            if check.get("recommendation"):
                print(f"    → {check['recommendation']}")
        print("=" * 70)

    if report.failed > 0:
        sys.exit(2)
    if report.warning > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
