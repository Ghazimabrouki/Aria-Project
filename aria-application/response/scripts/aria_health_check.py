#!/usr/bin/env python3
"""
ARIA Health Check — comprehensive SOC workflow monitoring.

Usage:
    cd /path/to/project
    python3 response/scripts/aria_health_check.py

Returns:
    0 = healthy
    1 = degraded (warnings present)
    2 = critical (critical issues present)

Cron example (run every 5 minutes):
    */5 * * * * cd /home/dash/Desktop/opensoar\x20backend\x206\x20mai/opensoar\x20backend && python3 response/scripts/aria_health_check.py >> /var/log/aria-health.log 2>&1

Systemd timer example:
    # /etc/systemd/system/aria-health-check.service
    [Unit]
    Description=ARIA Health Check

    [Service]
    Type=oneshot
    WorkingDirectory=/home/dash/Desktop/opensoar backend 6 mai/opensoar backend
    ExecStart=/usr/bin/python3 response/scripts/aria_health_check.py

    # /etc/systemd/system/aria-health-check.timer
    [Unit]
    Description=Run ARIA Health Check every 5 minutes

    [Timer]
    OnBootSec=1min
    OnUnitActiveSec=5min

    [Install]
    WantedBy=timers.target
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Ensure project root is on PYTHONPATH regardless of where script is run from
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import select, func, text
from response.db import AsyncSessionLocal
from response.models import Investigation, FixVerificationJob, PlaybookRun
from response.playbook_safety import validate_playbook_safety, compute_investigation_safety

API_BASE = "http://localhost:8001"
HEALTH_TIMEOUT = 10


class HealthReport:
    def __init__(self):
        self.checks: list[dict] = []
        self.critical = 0
        self.warning = 0
        self.ok = 0

    def add(self, name: str, status: str, detail: str, recommendation: str = ""):
        self.checks.append({"name": name, "status": status, "detail": detail, "recommendation": recommendation})
        if status == "CRITICAL":
            self.critical += 1
        elif status == "WARNING":
            self.warning += 1
        else:
            self.ok += 1

    def overall(self) -> str:
        if self.critical > 0:
            return "critical"
        if self.warning > 0:
            return "degraded"
        return "healthy"


def _http_get(path: str) -> dict | None:
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", str(HEALTH_TIMEOUT), f"{API_BASE}{path}"],
            capture_output=True, text=True, timeout=HEALTH_TIMEOUT + 2
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


async def _check_api(report: HealthReport):
    data = _http_get("/health")
    if data and data.get("status") == "ok":
        report.add("API /health", "OK", "Backend API is responding")
    else:
        report.add("API /health", "CRITICAL", "Backend API is not responding", "Start uvicorn: python3 -m uvicorn api.app:app --host 0.0.0.0 --port 8001")

    data = _http_get("/api/v1/investigations/stats")
    if data and "total" in data:
        report.add("API /investigations/stats", "OK", f"Investigations: {data['total']}")
    else:
        report.add("API /investigations/stats", "CRITICAL", "Investigations stats endpoint failed")

    data = _http_get("/api/v1/alerts?limit=1")
    if data and "alerts" in data:
        report.add("API /alerts", "OK", "Alerts endpoint responding")
    else:
        report.add("API /alerts", "WARNING", "Alerts endpoint not responding correctly")

    data = _http_get("/monitor/health")
    if data and "status" in data:
        report.add("API /monitor/health", "OK", f"Monitor health: {data.get('status')}")
    else:
        report.add("API /monitor/health", "WARNING", "Monitoring endpoint not responding")


async def _check_database(report: HealthReport):
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(func.count(Investigation.id)))
            count = result.scalar_one()
            report.add("Database", "OK", f"SQLite reachable, {count} investigations")
    except Exception as e:
        report.add("Database", "CRITICAL", f"Database unreachable: {e}", "Check DB file permissions and path in config/settings.py")


async def _check_investigations(report: HealthReport):
    async with AsyncSessionLocal() as session:
        # Stuck investigations
        stuck_threshold = datetime.now(timezone.utc) - timedelta(hours=24)
        result = await session.execute(
            select(func.count(Investigation.id))
            .where(Investigation.status.in_(["pending", "running", "diagnosing"]))
            .where(Investigation.updated_at < stuck_threshold)
        )
        stuck = result.scalar_one()
        if stuck > 0:
            report.add("Stuck investigations", "WARNING", f"{stuck} investigations stuck >24h", "Check worker/main.py is running")
        else:
            report.add("Stuck investigations", "OK", "No investigations stuck >24h")

        # Old awaiting approval
        result = await session.execute(
            select(func.count(Investigation.id))
            .where(Investigation.status == "awaiting_approval")
            .where(Investigation.updated_at < stuck_threshold)
        )
        old_approval = result.scalar_one()
        if old_approval > 10:
            report.add("Old awaiting approval", "WARNING", f"{old_approval} investigations awaiting approval >24h", "Analysts should review backlog")
        else:
            report.add("Old awaiting approval", "OK", f"{old_approval} old awaiting approval")

        # Manual review required
        result = await session.execute(
            select(func.count(Investigation.id))
            .where(Investigation.status == "manual_review_required")
        )
        manual_review = result.scalar_one()
        report.add("Manual review required", "OK" if manual_review < 20 else "WARNING",
                   f"{manual_review} investigations require manual review")

        # Failed investigations
        result = await session.execute(
            select(func.count(Investigation.id))
            .where(Investigation.status == "failed")
        )
        failed = result.scalar_one()
        if failed > 50:
            report.add("Failed investigations", "WARNING", f"{failed} failed investigations", "Review failed cases for AI/pipeline issues")
        else:
            report.add("Failed investigations", "OK", f"{failed} failed investigations")

        # Empty AI summary
        result = await session.execute(
            select(func.count(Investigation.id))
            .where(Investigation.ai_summary.is_(None))
            .where(Investigation.status.in_(["awaiting_approval", "approved", "running"]))
        )
        empty_ai = result.scalar_one()
        if empty_ai > 20:
            report.add("Empty AI summaries", "WARNING", f"{empty_ai} investigations have no AI summary", "AI engine may be failing or disabled")
        else:
            report.add("Empty AI summaries", "OK", f"{empty_ai} without AI summary")

        # AI quality failed
        result = await session.execute(
            select(func.count(Investigation.id))
            .where(Investigation.ai_quality_status == "failed")
        )
        ai_failed = result.scalar_one()
        if ai_failed > 10:
            report.add("AI quality failed", "WARNING", f"{ai_failed} investigations with failed AI quality", "Review AI engine and prompt")
        else:
            report.add("AI quality failed", "OK", f"{ai_failed} investigations with failed AI quality")


async def _check_verifier_queue(report: HealthReport):
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(func.count(FixVerificationJob.id))
            .where(FixVerificationJob.status == "pending")
        )
        pending = result.scalar_one()
        if pending > 10:
            report.add("Verifier queue", "WARNING", f"{pending} pending verification jobs", "Check fix verifier scheduler")
        else:
            report.add("Verifier queue", "OK", f"{pending} pending verification jobs")

        result = await session.execute(
            select(func.count(FixVerificationJob.id))
            .where(FixVerificationJob.status == "failed")
        )
        failed_jobs = result.scalar_one()
        if failed_jobs > 5:
            report.add("Failed verifications", "WARNING", f"{failed_jobs} failed verification jobs")
        else:
            report.add("Failed verifications", "OK", f"{failed_jobs} failed verification jobs")


async def _check_playbook_safety(report: HealthReport):
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation)
            .where(Investigation.status.in_(["awaiting_approval", "approved", "running", "failed", "completed", "completed_with_warnings"]))
            .where(Investigation.playbook_yaml.is_not(None))
            .limit(50)
        )
        investigations = result.scalars().all()

        unsafe_count = 0
        for inv in investigations:
            safety = compute_investigation_safety(inv)
            if not safety["is_safe_to_display"]:
                unsafe_count += 1

        if unsafe_count > 30:
            report.add("Unsafe playbooks", "WARNING", f"{unsafe_count}/{len(investigations)} checked investigations have unsafe playbooks",
                       "Run audit script: python3 response/scripts/audit_legacy_investigations.py --fix")
        else:
            report.add("Unsafe playbooks", "OK", f"{unsafe_count}/{len(investigations)} checked investigations unsafe")


async def _check_execution_history(report: HealthReport):
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(func.count(PlaybookRun.id))
            .where(PlaybookRun.status == "failed")
        )
        failed_runs = result.scalar_one()
        if failed_runs > 10:
            report.add("Failed playbook runs", "WARNING", f"{failed_runs} failed playbook runs", "Check ansible_exec logs and SSH connectivity")
        else:
            report.add("Failed playbook runs", "OK", f"{failed_runs} failed playbook runs")

        result = await session.execute(
            select(func.count(PlaybookRun.id))
            .where(PlaybookRun.status == "completed_with_warnings")
        )
        warning_runs = result.scalar_one()
        if warning_runs > 0:
            report.add("Completed with warnings", "WARNING", f"{warning_runs} playbook runs completed with warnings", "Review optional phase failures")
        else:
            report.add("Completed with warnings", "OK", "No playbook runs with warnings")


async def _check_frontend(report: HealthReport):
    frontend_dir = PROJECT_ROOT / "frontend"
    if not frontend_dir.exists():
        report.add("Frontend directory", "CRITICAL", f"frontend/ directory not found at {frontend_dir}")
        return

    # Check build exists
    next_dir = frontend_dir / ".next"
    if next_dir.exists():
        report.add("Frontend build", "OK", ".next/ directory exists")
    else:
        report.add("Frontend build", "WARNING", ".next/ directory missing", "Run: cd frontend && pnpm build")

    # Check package.json
    pkg = frontend_dir / "package.json"
    if pkg.exists():
        report.add("Frontend package.json", "OK", "package.json exists")
    else:
        report.add("Frontend package.json", "CRITICAL", "package.json missing")


async def _check_smoke_tests(report: HealthReport):
    """Run lightweight safety validator smoke tests without live execution."""
    # Smoke test 1: dangerous playbook must be blocked
    dangerous_yaml = """---
- name: Dangerous
  hosts: all
  tasks:
    - name: Stop SSH
      ansible.builtin.service:
        name: sshd
        state: stopped
"""
    safety = validate_playbook_safety(dangerous_yaml, {"investigation_type": "security", "target_host": "localhost", "alert_sources": []})
    if safety["safe"]:
        report.add("Smoke: dangerous playbook", "CRITICAL", "Dangerous playbook was NOT blocked by safety validator")
    else:
        report.add("Smoke: dangerous playbook", "OK", "Dangerous playbook correctly blocked")

    # Smoke test 2: diagnostic-only playbook must not be executable
    diagnostic_yaml = """---
- name: Diagnostic
  hosts: all
  tasks:
    - name: List processes
      ansible.builtin.shell: ps aux
      changed_when: false
"""
    inv_mock = type("Inv", (), {"playbook_yaml": diagnostic_yaml, "rollback_playbook": "", "investigation_type": "security", "target_host": "localhost", "alerts": []})()
    safety = compute_investigation_safety(inv_mock)
    if safety["execution_mode"] != "diagnostic_only":
        report.add("Smoke: diagnostic-only", "WARNING", f"Diagnostic playbook misclassified as {safety['execution_mode']}")
    else:
        report.add("Smoke: diagnostic-only", "OK", "Diagnostic playbook correctly classified as diagnostic_only")

    # Smoke test 3: safe remediation must be executable
    safe_yaml = """---
- name: Safe block
  hosts: all
  tasks:
    - name: Block IP
      ansible.builtin.iptables:
        chain: INPUT
        source: 192.0.2.1
        jump: DROP
"""
    inv_mock = type("Inv", (), {"playbook_yaml": safe_yaml, "rollback_playbook": "---\n- name: Rollback\n  hosts: all\n  tasks:\n    - name: Remove rule\n      ansible.builtin.iptables:\n        chain: INPUT\n        source: 192.0.2.1\n        jump: DROP\n        state: absent", "investigation_type": "security", "target_host": "localhost", "status": "awaiting_approval", "alerts": []})()
    safety = compute_investigation_safety(inv_mock)
    if not safety["is_executable"]:
        report.add("Smoke: safe remediation", "WARNING", f"Safe remediation blocked: {safety['blocked_reasons']}")
    else:
        report.add("Smoke: safe remediation", "OK", "Safe remediation correctly allowed")


async def _check_worker_heartbeat(report: HealthReport):
    from response.worker_heartbeat import get_all_worker_heartbeats
    try:
        heartbeats = await get_all_worker_heartbeats()
        if not heartbeats:
            report.add("Worker heartbeat", "WARNING", "No worker heartbeat records found", "Start main.py to register worker heartbeats")
            return

        now = datetime.now(timezone.utc)
        for hb in heartbeats:
            # Skip test artifacts from pytest
            if hb.worker_name.startswith("test_"):
                continue
            last_success = hb.last_success_at
            if last_success and last_success.tzinfo is None:
                last_success = last_success.replace(tzinfo=timezone.utc)
            age_seconds = (now - last_success).total_seconds() if last_success else float("inf")
            # Thresholds vary by worker type
            thresholds = {
                "forwarder": 300,
                "incident_watcher": 300,
                "fix_verification_jobs": 300,
                "runtime_diagnostic_recovery": 300,
                "watchdog": 180,
                "auto_transitions": 7200,
                "incident_correlation": 3600,
                "retry_queue": 7200,
                "backup": 172800,
                "performance_monitoring": 600,
                "performance_watcher": 600,
            }
            threshold = thresholds.get(hb.worker_name, 600)
            if age_seconds == float("inf"):
                report.add(
                    f"Worker: {hb.worker_name}",
                    "WARNING",
                    f"No successful heartbeat recorded (threshold {threshold}s)",
                    "Check if main.py is running and worker is not stuck"
                )
            elif age_seconds > threshold:
                status = "WARNING" if age_seconds < threshold * 3 else "CRITICAL"
                report.add(
                    f"Worker: {hb.worker_name}",
                    status,
                    f"Last success {int(age_seconds)}s ago (threshold {threshold}s)",
                    "Check if main.py is running and worker is not stuck"
                )
            elif hb.status == "failed" and hb.last_error:
                report.add(
                    f"Worker: {hb.worker_name}",
                    "WARNING",
                    f"Last error: {hb.last_error[:80]}",
                    "Review logs for this worker"
                )
            else:
                detail = f"Last success {int(age_seconds)}s ago"
                if hb.last_duration_ms:
                    detail += f", duration {hb.last_duration_ms}ms"
                report.add(f"Worker: {hb.worker_name}", "OK", detail)
    except Exception as e:
        report.add("Worker heartbeat", "WARNING", f"Could not read heartbeats: {e}")


def _print_report(report: HealthReport, json_output: bool = False):
    if json_output:
        output = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall": report.overall(),
            "ok": report.ok,
            "warning": report.warning,
            "critical": report.critical,
            "checks": report.checks,
        }
        print(json.dumps(output, indent=2))
        return

    print("=" * 70)
    print(f"ARIA Health Report — {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)
    print(f"Overall status: {report.overall().upper()}")
    print(f"  OK:       {report.ok}")
    print(f"  WARNING:  {report.warning}")
    print(f"  CRITICAL: {report.critical}")
    print("-" * 70)

    for check in report.checks:
        icon = "✓" if check["status"] == "OK" else "⚠" if check["status"] == "WARNING" else "✗"
        print(f"{icon} [{check['status']}] {check['name']}: {check['detail']}")
        if check.get("recommendation"):
            print(f"    → {check['recommendation']}")

    print("=" * 70)


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="ARIA Health Check")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of human-readable text")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as critical (exit 2)")
    args = parser.parse_args()

    report = HealthReport()
    await _check_api(report)
    await _check_database(report)
    await _check_investigations(report)
    await _check_verifier_queue(report)
    await _check_playbook_safety(report)
    await _check_execution_history(report)
    await _check_frontend(report)
    await _check_smoke_tests(report)
    await _check_worker_heartbeat(report)

    _print_report(report, json_output=args.json)

    if report.critical > 0:
        sys.exit(2)
    if report.warning > 0:
        sys.exit(2 if args.strict else 1)
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
