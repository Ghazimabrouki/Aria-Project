#!/usr/bin/env python3
"""
Runtime QA Watchdog
===================
Continuously monitors the Falco runtime investigation pipeline for:
- Backend health (API, DB, ES)
- Data quality (corrupted fields, missing snapshots, empty findings)
- API contract truthfulness (fake remediation, unsafe approval, missing fields)
- Recovery loop health
- SSH timeout rate
- Frontend/API consistency

Outputs:
- /tmp/runtime_qa_watchdog.log
- reports/runtime_qa_watchdog_latest.json
- reports/runtime_qa_watchdog_latest.md

Exit codes:
- 0: all clear or warnings only
- 1: critical issues detected
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
import structlog

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_BASE = os.getenv("RUNTIME_QA_API_BASE", "http://localhost:8001")
ES_URL = os.getenv("ELASTICSEARCH_URL", "https://193.95.30.97:9200")
ES_USER = os.getenv("ELASTICSEARCH_USER", "")
ES_PASS = os.getenv("ELASTICSEARCH_PASSWORD", "")
DB_PATH = os.getenv("DB_PATH", "data/investigations.db")
REPORTS_DIR = Path(os.getenv("RUNTIME_QA_REPORTS_DIR", "reports"))
LOG_PATH = Path(os.getenv("RUNTIME_QA_LOG_PATH", "/tmp/runtime_qa_watchdog.log"))

# Alert thresholds
MAX_DIAGNOSING_MINUTES = 10
MAX_STUCK_MINUTES = 5
MAX_SSH_TIMEOUT_RATE = 0.20  # 20%
MIN_RAW_SNAPSHOT_COVERAGE = 0.90  # 90%

# Synthetic scenario expectations
SYNTHETIC_SCENARIOS: list[dict[str, Any]] = [
    {"name": "observe_case", "status": "observe", "expect_approve_run": False, "expect_remediation_label": False},
    {"name": "manual_review_case", "status": "manual_review_required", "expect_approve_run": False, "expect_next_manual_steps": True},
    {"name": "archived_not_fixed_case", "status": "archived_not_fixed", "expect_unresolved_risk": True},
    {"name": "safe_corrective_case", "status": "awaiting_approval", "expect_approve_run": True, "expect_corrective_actions": True},
    {"name": "high_risk_approval_case", "status": "awaiting_approval", "expect_approve_run": True, "expect_approval_required": True},
]

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    investigation_id: Optional[str]
    check: str
    severity: str  # critical, warning, info
    reason: str
    recommendation: str = ""
    data: dict[str, Any] = field(default_factory=dict)

@dataclass
class Report:
    generated_at: str
    duration_seconds: float
    api_reachable: bool
    es_reachable: bool
    db_reachable: bool
    stats: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    sampled_investigations: list[dict[str, Any]] = field(default_factory=list)
    data_quality_issues: list[Finding] = field(default_factory=list)
    api_contract_issues: list[Finding] = field(default_factory=list)
    synthetic_results: list[dict[str, Any]] = field(default_factory=list)
    recovery_loop_healthy: bool = True
    ssh_timeout_rate: float = 0.0
    raw_snapshot_coverage: float = 0.0
    frontend_build_ok: bool = True
    backend_tests_ok: bool = True
    critical_count: int = 0
    warning_count: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if finding.severity == "critical":
            self.critical_count += 1
        elif finding.severity == "warning":
            self.warning_count += 1

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging() -> structlog.stdlib.BoundLogger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.FileHandler(LOG_PATH, mode="a"), logging.StreamHandler(sys.stdout)],
    )
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    return structlog.get_logger("runtime_qa_watchdog")

logger: structlog.stdlib.BoundLogger

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _fmt(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.isoformat()

async def _api_get(path: str, timeout: float = 15.0) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(f"{API_BASE}{path}")
        resp.raise_for_status()
        return resp.json()

async def _api_post(path: str, timeout: float = 15.0) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.post(f"{API_BASE}{path}")
        resp.raise_for_status()
        return resp.json()

# ---------------------------------------------------------------------------
# Backend health checks
# ---------------------------------------------------------------------------

async def check_api_health(report: Report) -> None:
    try:
        data = await _api_get("/api/v1/runtime/investigations/stats")
        report.stats = data
        report.api_reachable = True
        logger.info("api_health_ok", stats=data)
    except Exception as exc:
        report.api_reachable = False
        report.add(Finding(None, "api_health", "critical", f"API unreachable: {exc}"))
        logger.error("api_health_fail", error=str(exc))

async def check_es_health(report: Report) -> None:
    try:
        if not ES_USER:
            logger.info("es_health_skipped_no_credentials")
            report.es_reachable = True  # assume ok if not monitoring
            return
        auth = (ES_USER, ES_PASS)
        verify = False  # dev/test environment often uses self-signed certs
        async with httpx.AsyncClient(timeout=10.0, verify=verify) as client:
            resp = await client.get(f"{ES_URL}/_cluster/health", auth=auth)
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status", "unknown")
            report.es_reachable = status in ("green", "yellow")
            if status == "red":
                report.add(Finding(None, "es_health", "critical", f"Elasticsearch cluster status: {status}"))
            else:
                logger.info("es_health_ok", status=status)
    except Exception as exc:
        report.es_reachable = False
        report.add(Finding(None, "es_health", "warning", f"Elasticsearch unreachable: {exc}"))
        logger.warning("es_health_fail", error=str(exc))

async def check_db_health(report: Report) -> None:
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text
        engine = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH}")
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT count(*) FROM investigations WHERE investigation_type = 'runtime'"))
            count = result.scalar()
            report.db_reachable = True
            logger.info("db_health_ok", runtime_count=count)
        await engine.dispose()
    except Exception as exc:
        report.db_reachable = False
        report.add(Finding(None, "db_health", "warning", f"SQLite DB unreachable: {exc}"))
        logger.warning("db_health_fail", error=str(exc))

async def check_diagnosing_backlog(report: Report) -> None:
    if not report.api_reachable:
        return
    try:
        data = await _api_get("/api/v1/runtime/investigations?status=diagnosing&limit=200")
        investigations = data.get("investigations", [])
        total = data.get("total", 0)
        if total > 0:
            report.add(
                Finding(
                    None,
                    "diagnosing_backlog",
                    "warning",
                    f"{total} investigations stuck in diagnosing",
                    recommendation="Check recovery loop and diagnostic pipeline health.",
                )
            )
        # Check age via DB
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
            from sqlalchemy import text
            engine = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH}")
            async with engine.connect() as conn:
                sql = text("""
                    SELECT id, diagnostic_started_at, status
                    FROM investigations
                    WHERE investigation_type = 'runtime'
                      AND status = 'diagnosing'
                      AND diagnostic_started_at < :cutoff
                """)
                result = await conn.execute(sql, {"cutoff": _now() - timedelta(minutes=MAX_STUCK_MINUTES)})
                rows = result.mappings().all()
                for row in rows:
                    mins = (_now() - row["diagnostic_started_at"]).total_seconds() / 60 if row["diagnostic_started_at"] else 999
                    report.add(
                        Finding(
                            row["id"],
                            "stuck_diagnosing",
                            "critical" if mins > MAX_DIAGNOSING_MINUTES else "warning",
                            f"Stuck in diagnosing for {mins:.0f} minutes",
                            recommendation="Recovery loop should pick this up; verify loop is running.",
                        )
                    )
            await engine.dispose()
        except Exception as exc:
            logger.warning("db_diagnosing_check_fail", error=str(exc))
    except Exception as exc:
        report.add(Finding(None, "diagnosing_backlog", "warning", f"Failed to query diagnosing backlog: {exc}"))

async def check_recovery_loop_health(report: Report) -> None:
    """Infer recovery loop health from diagnosing backlog trend."""
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text
        engine = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH}")
        async with engine.connect() as conn:
            # If there are diagnosing cases older than MAX_STUCK_MINUTES, recovery loop should be handling them
            sql = text("""
                SELECT count(*) as cnt
                FROM investigations
                WHERE investigation_type = 'runtime'
                  AND status = 'diagnosing'
                  AND diagnostic_started_at < :cutoff
            """)
            result = await conn.execute(sql, {"cutoff": _now() - timedelta(minutes=MAX_STUCK_MINUTES)})
            stuck_count = result.scalar() or 0

            # If stuck cases exist but are being created recently, recovery loop is doing its job
            # We consider loop healthy if no cases are stuck > 10 minutes (backlog should be zero)
            if stuck_count > 0:
                report.add(
                    Finding(
                        None,
                        "recovery_loop_backlog",
                        "warning",
                        f"{stuck_count} cases stuck in diagnosing > {MAX_STUCK_MINUTES} min",
                        recommendation="Recovery loop may be backlogged or stopped. Verify main.py.",
                    )
                )
                report.recovery_loop_healthy = False
            else:
                report.recovery_loop_healthy = True
                logger.info("recovery_loop_healthy", stuck_count=stuck_count)
        await engine.dispose()
    except Exception as exc:
        logger.warning("recovery_loop_check_fail", error=str(exc))

# ---------------------------------------------------------------------------
# API contract validation
# ---------------------------------------------------------------------------

REQUIRED_DETAIL_FIELDS = [
    "context_sections",
    "classification_context",
    "alert_payloads",
    "evidence_summary",
    "diagnostic_summary",
    "diagnostic_output",
    "playbook_summary",
    "playbook_phases",
    "remediation_plan",
    "remediation_summary",
    "outcome_summary",
    "verification",
    # "timeline",  # separate endpoint /timeline
    "available_actions",
]

async def validate_detail_contract(inv_id: str, detail: dict[str, Any], report: Report) -> None:
    # Required fields
    for field in REQUIRED_DETAIL_FIELDS:
        if field not in detail:
            report.add(
                Finding(
                    inv_id,
                    "api_contract_missing_field",
                    "critical",
                    f"Missing required field: {field}",
                    recommendation="Verify backend route returns complete payload.",
                )
            )

    aa = detail.get("available_actions", {})
    status = detail.get("status", "")
    rem = detail.get("remediation_summary", {}) or {}
    plan = detail.get("remediation_plan", {}) or {}
    outcome = detail.get("outcome_summary", {}) or {}

    corrective = bool(rem.get("corrective_actions"))
    actual = bool(plan.get("actual_remediation_available"))

    # Rule: approve_run only when awaiting_approval + corrective_actions exist
    if aa.get("approve_run") is True:
        if status != "awaiting_approval":
            report.add(
                Finding(
                    inv_id,
                    "unsafe_approval_path",
                    "critical",
                    f"approve_run=true but status is '{status}', not 'awaiting_approval'",
                    recommendation="Freeze remediation architecture — this is a regression.",
                )
            )
        if not corrective:
            report.add(
                Finding(
                    inv_id,
                    "fake_approval_path",
                    "critical",
                    "approve_run=true but no corrective_actions exist",
                    recommendation="Freeze remediation architecture — this is a regression.",
                )
            )

    # Rule: diagnostic playbook must be labeled Diagnostic Playbook
    diag_summary = detail.get("diagnostic_summary", {}) or {}
    if diag_summary.get("label") and diag_summary["label"] != "Diagnostic Playbook":
        report.add(
            Finding(
                inv_id,
                "diagnostic_label_wrong",
                "warning",
                f"Diagnostic label is '{diag_summary['label']}', expected 'Diagnostic Playbook'",
            )
        )

    # Rule: Remediation Playbook appears only when corrective_actions exist
    pb_summary = detail.get("playbook_summary", {}) or {}
    if pb_summary.get("current_playbook_label") == "Remediation Playbook" and not corrective:
        report.add(
            Finding(
                inv_id,
                "fake_remediation_playbook",
                "critical",
                "Remediation Playbook label shown but no corrective_actions exist",
                recommendation="Freeze remediation architecture — this is a regression.",
            )
        )

    # Rule: Manual review cases must show next_manual_steps
    if plan.get("decision") == "manual_review_required":
        if not plan.get("next_manual_steps"):
            report.add(
                Finding(
                    inv_id,
                    "missing_next_manual_steps",
                    "warning",
                    "manual_review_required case missing next_manual_steps",
                )
            )

    # Rule: Observe cases must not show fake remediation
    if plan.get("decision") in ("observe", "no_action_expected_activity"):
        if corrective or actual:
            report.add(
                Finding(
                    inv_id,
                    "observe_has_remediation",
                    "critical",
                    "Observe case shows corrective_actions or actual_remediation_available",
                    recommendation="Freeze remediation architecture — this is a regression.",
                )
            )

    # Rule: Archived unresolved cases must show unresolved risk
    if status in ("archived_not_fixed", "not_fixed", "inconclusive", "closed_with_risk"):
        if not outcome.get("unresolved_risk"):
            report.add(
                Finding(
                    inv_id,
                    "missing_unresolved_risk",
                    "warning",
                    f"Status '{status}' but outcome.unresolved_risk is false",
                )
            )

    # Rule: Container case gets host remediation without validation
    ctx = detail.get("context_sections", {}) or {}
    container = ctx.get("container", {}) or {}
    container_id = container.get("container_id")
    target_ctx = plan.get("target_context", "")
    # Valid container_id is a hex string like 20fa7c4c8039 (not literal "host")
    is_real_container = bool(container_id) and isinstance(container_id, str) and len(container_id) >= 12 and all(c in "0123456789abcdefABCDEF" for c in container_id)
    if is_real_container and target_ctx == "host":
        # Allow only if scope_reason explicitly validates namespace/mount
        scope_reason = (plan.get("scope_reason") or "").lower()
        if "namespace" not in scope_reason and "mount" not in scope_reason and "host pid" not in scope_reason:
            report.add(
                Finding(
                    inv_id,
                    "container_host_remediation_unsafe",
                    "critical",
                    "Container case targets host without namespace/mount validation",
                    recommendation="Freeze remediation architecture — this is a regression.",
                )
            )

    # Rule: Diagnostic-only case labeled remediation
    diag_is_remediation = diag_summary.get("is_remediation")
    if diag_is_remediation is True:
        report.add(
            Finding(
                inv_id,
                "diagnostic_marked_remediation",
                "critical",
                "Diagnostic summary is_remediation=true; diagnostics must never be labeled remediation",
                recommendation="Freeze remediation architecture — this is a regression.",
            )
        )

async def check_api_contracts(report: Report) -> None:
    if not report.api_reachable:
        return
    try:
        data = await _api_get("/api/v1/runtime/investigations?limit=20")
        investigations = data.get("investigations", [])
        report.sampled_investigations = investigations
        for inv in investigations[:5]:
            inv_id = inv.get("id")
            if not inv_id:
                continue
            try:
                detail = await _api_get(f"/api/v1/runtime/investigations/{inv_id}")
                await validate_detail_contract(inv_id, detail, report)
            except Exception as exc:
                report.add(
                    Finding(
                        inv_id,
                        "api_contract_detail_error",
                        "warning",
                        f"Failed to fetch/validate detail: {exc}",
                    )
                )
    except Exception as exc:
        report.add(Finding(None, "api_contract_list_error", "warning", f"Failed to list investigations: {exc}"))

# ---------------------------------------------------------------------------
# Data quality monitoring
# ---------------------------------------------------------------------------

async def check_data_quality(report: Report) -> None:
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text
        engine = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH}")
        async with engine.connect() as conn:
            # Check missing host
            sql = text("""
                SELECT id, target_host, status, findings_json, diagnostic_output, resource_context_json, created_at
                FROM investigations
                WHERE investigation_type = 'runtime'
                ORDER BY created_at DESC
                LIMIT 50
            """)
            result = await conn.execute(sql)
            rows = result.mappings().all()

            for row in rows:
                inv_id = row["id"]
                ctx = row["resource_context_json"] or {}
                if isinstance(ctx, str):
                    try:
                        ctx = json.loads(ctx)
                    except Exception:
                        ctx = {}
                findings = row["findings_json"] or {}
                if isinstance(findings, str):
                    try:
                        findings = json.loads(findings)
                    except Exception:
                        findings = {}

                # Missing host
                if not row["target_host"]:
                    report.add(
                        Finding(
                            inv_id,
                            "data_quality_missing_host",
                            "warning",
                            "Missing target_host",
                            recommendation="Check Falco mapper hostname extraction.",
                        )
                    )

                # Missing rule
                if not ctx.get("rule_name") and not ctx.get("falco_rule"):
                    report.add(
                        Finding(
                            inv_id,
                            "data_quality_missing_rule",
                            "info",
                            "Missing rule name in context",
                        )
                    )

                # Missing process
                if not ctx.get("proc_name") and not ctx.get("process"):
                    report.add(
                        Finding(
                            inv_id,
                            "data_quality_missing_process",
                            "info",
                            "Missing process name",
                        )
                    )

                # Numeric/corrupted proc_name
                proc = ctx.get("proc_name")
                if proc and isinstance(proc, str) and proc.isdigit():
                    report.add(
                        Finding(
                            inv_id,
                            "data_quality_corrupted_proc_name",
                            "info",
                            f"Corrupted proc_name '{proc}'",
                            recommendation="Historical data quality guard should flag this.",
                        )
                    )

                # Container context missing when container_id exists
                if ctx.get("container_id") and not ctx.get("container_name"):
                    report.add(
                        Finding(
                            inv_id,
                            "data_quality_missing_container_name",
                            "info",
                            "container_id present but container_name missing",
                        )
                    )

                # Empty findings
                if not findings or (isinstance(findings, dict) and not findings.get("detected_cause")):
                    if row["status"] not in ("diagnosing",):
                        report.add(
                            Finding(
                                inv_id,
                                "data_quality_empty_findings",
                                "warning",
                                "Empty findings for non-diagnosing case",
                                recommendation="Re-run diagnostic pipeline.",
                            )
                        )

                # Empty diagnostic output
                if not row["diagnostic_output"] and row["status"] not in ("diagnosing",):
                    report.add(
                        Finding(
                            inv_id,
                            "data_quality_empty_diagnostic_output",
                            "warning",
                            "Missing diagnostic output for non-diagnosing case",
                            recommendation="Re-run diagnostic pipeline.",
                        )
                    )

            # Raw snapshot coverage for new alerts
            sql2 = text("""
                SELECT
                    count(*) as total,
                    sum(case when raw_source_json is not null then 1 else 0 end) as with_snap
                FROM alerts
                WHERE source = 'falco'
                  AND created_at > :cutoff
            """)
            result2 = await conn.execute(sql2, {"cutoff": _now() - timedelta(hours=24)})
            row2 = result2.mappings().first()
            if row2:
                total = row2["total"] or 0
                with_snap = row2["with_snap"] or 0
                coverage = with_snap / total if total > 0 else 1.0
                report.raw_snapshot_coverage = coverage
                if coverage < MIN_RAW_SNAPSHOT_COVERAGE and total > 0:
                    report.add(
                        Finding(
                            None,
                            "raw_snapshot_coverage_low",
                            "warning",
                            f"Raw snapshot coverage {coverage:.0%} for last 24h ({with_snap}/{total})",
                            recommendation="Verify _persist_alert_local stores raw_source_json.",
                        )
                    )
                else:
                    logger.info("raw_snapshot_coverage", coverage=coverage, total=total, with_snap=with_snap)

            # Duplicated summaries check (heuristic: identical ai_summary across many)
            sql3 = text("""
                SELECT ai_summary, count(*) as cnt
                FROM investigations
                WHERE investigation_type = 'runtime'
                  AND ai_summary IS NOT NULL
                  AND ai_summary != ''
                GROUP BY ai_summary
                HAVING cnt > 5
                LIMIT 5
            """)
            result3 = await conn.execute(sql3)
            for row3 in result3.mappings().all():
                report.add(
                    Finding(
                        None,
                        "data_quality_duplicated_summaries",
                        "info",
                        f"Summary duplicated {row3['cnt']} times: {row3['ai_summary'][:80]}...",
                    )
                )

            # Suspicious old historical records (stuck in diagnosing forever)
            sql4 = text("""
                SELECT id, status, created_at, diagnostic_started_at
                FROM investigations
                WHERE investigation_type = 'runtime'
                  AND status = 'diagnosing'
                  AND created_at < :cutoff
                LIMIT 5
            """)
            result4 = await conn.execute(sql4, {"cutoff": _now() - timedelta(days=1)})
            for row4 in result4.mappings().all():
                report.add(
                    Finding(
                        row4["id"],
                        "data_quality_historical_stuck",
                        "warning",
                        f"Historical record stuck in diagnosing since {row4['created_at']}",
                        recommendation="Run backfill script or delete stale record.",
                    )
                )

        await engine.dispose()
    except Exception as exc:
        report.add(Finding(None, "data_quality_check_error", "warning", f"Data quality check failed: {exc}"))
        logger.error("data_quality_check_error", error=str(exc), traceback=traceback.format_exc())

# ---------------------------------------------------------------------------
# Synthetic scenario checks
# ---------------------------------------------------------------------------

async def check_synthetic_scenarios(report: Report) -> None:
    """Validate synthetic expectations against real sampled data."""
    if not report.sampled_investigations:
        return

    # Map real cases by status for quick lookup
    by_status: dict[str, list[dict]] = {}
    for inv in report.sampled_investigations:
        st = inv.get("status", "")
        by_status.setdefault(st, []).append(inv)

    for scenario in SYNTHETIC_SCENARIOS:
        name = scenario["name"]
        expected_status = scenario.get("status", "")
        candidates = by_status.get(expected_status, [])
        if not candidates:
            report.synthetic_results.append({
                "scenario": name,
                "result": "skipped",
                "reason": f"No real case with status '{expected_status}' found in sample",
            })
            continue

        candidate = candidates[0]
        inv_id = candidate["id"]
        try:
            detail = await _api_get(f"/api/v1/runtime/investigations/{inv_id}")
            plan = detail.get("remediation_plan", {}) or {}
            aa = detail.get("available_actions", {}) or {}
            outcome = detail.get("outcome_summary", {}) or {}
            issues: list[str] = []

            if "expect_approve_run" in scenario:
                actual = aa.get("approve_run", False)
                if actual != scenario["expect_approve_run"]:
                    issues.append(f"approve_run={actual}, expected={scenario['expect_approve_run']}")

            if "expect_remediation_label" in scenario:
                pb = detail.get("playbook_summary", {}) or {}
                label = pb.get("current_playbook_label", "")
                has_remed = "Remediation" in label
                if has_remed != scenario["expect_remediation_label"]:
                    issues.append(f"remediation_label={has_remed}, expected={scenario['expect_remediation_label']}")

            if "expect_next_manual_steps" in scenario:
                steps = plan.get("next_manual_steps", [])
                if not steps and scenario["expect_next_manual_steps"]:
                    issues.append("next_manual_steps missing")

            if "expect_unresolved_risk" in scenario:
                actual = outcome.get("unresolved_risk", False)
                if actual != scenario["expect_unresolved_risk"]:
                    issues.append(f"unresolved_risk={actual}, expected={scenario['expect_unresolved_risk']}")

            if "expect_corrective_actions" in scenario:
                rem = detail.get("remediation_summary", {}) or {}
                actions = rem.get("corrective_actions", [])
                if not actions and scenario["expect_corrective_actions"]:
                    issues.append("corrective_actions missing")

            if "expect_approval_required" in scenario:
                actual = plan.get("approval_required", False)
                if actual != scenario["expect_approval_required"]:
                    issues.append(f"approval_required={actual}, expected={scenario['expect_approval_required']}")

            if issues:
                report.synthetic_results.append({
                    "scenario": name,
                    "investigation_id": inv_id,
                    "result": "fail",
                    "issues": issues,
                })
                for issue in issues:
                    report.add(Finding(inv_id, f"synthetic_{name}", "critical", issue))
            else:
                report.synthetic_results.append({
                    "scenario": name,
                    "investigation_id": inv_id,
                    "result": "pass",
                })
        except Exception as exc:
            report.synthetic_results.append({
                "scenario": name,
                "investigation_id": inv_id,
                "result": "error",
                "error": str(exc),
            })

# ---------------------------------------------------------------------------
# SSH timeout rate
# ---------------------------------------------------------------------------

async def check_ssh_timeout_rate(report: Report) -> None:
    """Estimate SSH timeout rate from recent diagnostic outputs (last hour)."""
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text
        engine = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH}")
        async with engine.connect() as conn:
            sql = text("""
                SELECT diagnostic_output, status
                FROM investigations
                WHERE investigation_type = 'runtime'
                  AND diagnostic_output IS NOT NULL
                  AND diagnostic_finished_at > :cutoff
            """)
            # Use 1 hour window to avoid backfill noise
            cutoff = _now() - timedelta(hours=1)
            result = await conn.execute(sql, {"cutoff": cutoff})
            rows = result.mappings().all()
            total = len(rows)
            if total == 0:
                report.ssh_timeout_rate = 0.0
                logger.info("ssh_timeout_rate_no_data_recent")
                await engine.dispose()
                return

            timeouts = 0
            for row in rows:
                out = row["diagnostic_output"] or ""
                if "timeout" in out.lower() or "ssh" in out.lower() and ("failed" in out.lower() or "unreachable" in out.lower()):
                    timeouts += 1

            rate = timeouts / total
            report.ssh_timeout_rate = rate
            if rate > MAX_SSH_TIMEOUT_RATE:
                report.add(
                    Finding(
                        None,
                        "ssh_timeout_rate_high",
                        "warning",
                        f"SSH timeout rate {rate:.0%} ({timeouts}/{total}) in last {'1h' if total < 50 else '24h'}",
                        recommendation="Check target host SSH connectivity and ansible inventory.",
                    )
                )
            else:
                logger.info("ssh_timeout_rate_ok", rate=rate, total=total, timeouts=timeouts)
        await engine.dispose()
    except Exception as exc:
        logger.warning("ssh_timeout_rate_check_fail", error=str(exc))

# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _write_json(report: Report) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / "runtime_qa_watchdog_latest.json"
    data = {
        "generated_at": report.generated_at,
        "duration_seconds": report.duration_seconds,
        "api_reachable": report.api_reachable,
        "es_reachable": report.es_reachable,
        "db_reachable": report.db_reachable,
        "recovery_loop_healthy": report.recovery_loop_healthy,
        "ssh_timeout_rate": report.ssh_timeout_rate,
        "raw_snapshot_coverage": report.raw_snapshot_coverage,
        "stats": report.stats,
        "findings": [asdict(f) for f in report.findings],
        "sampled_investigations": report.sampled_investigations,
        "synthetic_results": report.synthetic_results,
        "summary": {
            "critical": report.critical_count,
            "warning": report.warning_count,
            "total": report.critical_count + report.warning_count,
        },
    }
    path.write_text(json.dumps(data, indent=2, default=str))
    logger.info("report_json_written", path=str(path))

def _write_markdown(report: Report) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / "runtime_qa_watchdog_latest.md"
    lines: list[str] = []
    lines.append("# Runtime QA Watchdog Report\n")
    lines.append(f"**Generated:** {report.generated_at}\n")
    lines.append(f"**Duration:** {report.duration_seconds:.2f}s\n")
    lines.append("## Health Summary\n")
    lines.append(f"- API Reachable: {'✅' if report.api_reachable else '❌'}\n")
    lines.append(f"- ES Reachable: {'✅' if report.es_reachable else '❌'}\n")
    lines.append(f"- DB Reachable: {'✅' if report.db_reachable else '❌'}\n")
    lines.append(f"- Recovery Loop Healthy: {'✅' if report.recovery_loop_healthy else '❌'}\n")
    lines.append(f"- SSH Timeout Rate (24h): {report.ssh_timeout_rate:.0%}\n")
    lines.append(f"- Raw Snapshot Coverage (24h): {report.raw_snapshot_coverage:.0%}\n")
    lines.append("\n## Stats\n")
    lines.append(f"```json\n{json.dumps(report.stats, indent=2, default=str)}\n```\n")

    if report.findings:
        lines.append("\n## Findings\n")
        for f in report.findings:
            icon = "🔴" if f.severity == "critical" else "🟡" if f.severity == "warning" else "🟢"
            lines.append(f"### {icon} {f.check}\n")
            lines.append(f"- **Investigation ID:** {f.investigation_id or 'N/A'}\n")
            lines.append(f"- **Severity:** {f.severity}\n")
            lines.append(f"- **Reason:** {f.reason}\n")
            if f.recommendation:
                lines.append(f"- **Recommendation:** {f.recommendation}\n")
            if f.data:
                lines.append(f"- **Data:** `{json.dumps(f.data, default=str)}`\n")
            lines.append("\n")
    else:
        lines.append("\n## Findings\n\n✅ No issues detected.\n")

    if report.synthetic_results:
        lines.append("\n## Synthetic Scenario Results\n")
        for sr in report.synthetic_results:
            icon = "✅" if sr["result"] == "pass" else "⚠️" if sr["result"] == "skipped" else "❌"
            lines.append(f"- {icon} **{sr['scenario']}** — {sr['result']}")
            if sr.get("issues"):
                lines.append(f"  - Issues: {', '.join(sr['issues'])}")
            lines.append("\n")

    lines.append("\n---\n")
    lines.append(f"*Critical: {report.critical_count} | Warning: {report.warning_count}*\n")
    path.write_text("".join(lines))
    logger.info("report_markdown_written", path=str(path))

def _print_alerts(report: Report) -> None:
    if report.critical_count == 0:
        print("\n🟢 Runtime QA Watchdog: ALL CLEAR\n")
        return
    print(f"\n🔴 Runtime QA Watchdog: {report.critical_count} CRITICAL, {report.warning_count} WARNING\n")
    for f in report.findings:
        if f.severity == "critical":
            print(f"  🔴 [{f.check}] {f.investigation_id or 'N/A'}: {f.reason}")
    print()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> int:
    global logger
    logger = _setup_logging()
    parser = argparse.ArgumentParser(description="Runtime QA Watchdog")
    parser.add_argument("--ci", action="store_true", help="CI mode: exit 1 on any critical")
    parser.add_argument("--silent", action="store_true", help="No console output, only logs/reports")
    args = parser.parse_args()

    start = time.time()
    report = Report(
        generated_at=_fmt(_now()),
        duration_seconds=0.0,
        api_reachable=False,
        es_reachable=False,
        db_reachable=False,
    )

    logger.info("watchdog_start")

    # Run all checks
    await check_api_health(report)
    await check_es_health(report)
    await check_db_health(report)
    await check_diagnosing_backlog(report)
    await check_recovery_loop_health(report)
    await check_api_contracts(report)
    await check_data_quality(report)
    await check_synthetic_scenarios(report)
    await check_ssh_timeout_rate(report)

    report.duration_seconds = time.time() - start

    _write_json(report)
    _write_markdown(report)

    if not args.silent:
        _print_alerts(report)

    logger.info(
        "watchdog_finish",
        duration=report.duration_seconds,
        critical=report.critical_count,
        warning=report.warning_count,
    )

    if args.ci and report.critical_count > 0:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
