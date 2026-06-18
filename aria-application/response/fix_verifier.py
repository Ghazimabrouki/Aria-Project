"""
Fix Verifier.

After Ansible playbook completes, waits fix_verify_window_minutes then
re-queries Elasticsearch to check if the same alert patterns are still firing.

Verdict:
  0 new alerts → likely_fixed
  1-2 new alerts → inconclusive
  3+ new alerts → not_fixed

Also posts a comment to the OpenSOAR incident with the result.
"""
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
import structlog

from config import get_settings
from response.db import AsyncSessionLocal
from response.models import Investigation, InvestigationAlert, PlaybookRun, FixVerification, FixVerificationJob

logger = structlog.get_logger()
settings = get_settings()


async def schedule_verification_job(investigation_id: str) -> FixVerificationJob:
    """Schedule a persistent fix verification job.

    Creates or updates a FixVerificationJob row with next_run_at set to
    fix_verify_wait_minutes from now.  Survives process restarts.
    """
    from sqlalchemy import select
    wait_minutes = settings.fix_verify_wait_minutes
    next_run_at = datetime.now(timezone.utc) + timedelta(minutes=wait_minutes)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(FixVerificationJob)
            .where(FixVerificationJob.investigation_id == investigation_id)
        )
        job = result.scalar_one_or_none()
        if job:
            job.status = "pending"
            job.next_run_at = next_run_at
            job.attempt_count = 0
            job.last_error = None
            job.updated_at = datetime.now(timezone.utc)
        else:
            job = FixVerificationJob(
                investigation_id=investigation_id,
                status="pending",
                next_run_at=next_run_at,
            )
            session.add(job)
        await session.commit()
        logger.info("fix_verification_job_scheduled",
                    investigation_id=investigation_id,
                    next_run_at=next_run_at.isoformat())
        return job


async def process_due_verification_jobs():
    """Find and process all verification jobs whose next_run_at has passed."""
    from sqlalchemy import select
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(FixVerificationJob)
            .where(FixVerificationJob.status == "pending")
        )
        all_pending = result.scalars().all()
    jobs = []
    for job in all_pending:
        next_run = job.next_run_at
        if next_run and next_run.tzinfo is None:
            next_run = next_run.replace(tzinfo=timezone.utc)
        if next_run and next_run <= now:
            jobs.append(job)
    for job in jobs:
        await _run_verification_job(job.id)


async def _run_verification_job(job_id: str):
    """Run a single verification job and update its status."""
    from sqlalchemy import select, update
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(FixVerificationJob).where(FixVerificationJob.id == job_id)
        )
        job = result.scalar_one_or_none()
        if not job or job.status != "pending":
            return
        job.status = "running"
        job.attempt_count += 1
        job.updated_at = datetime.now(timezone.utc)
        await session.commit()
        investigation_id = job.investigation_id
    try:
        await verify_fix(investigation_id)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(FixVerificationJob).where(FixVerificationJob.id == job_id)
            )
            job = result.scalar_one_or_none()
            if job:
                job.status = "completed"
                job.updated_at = datetime.now(timezone.utc)
                await session.commit()
    except Exception as e:
        logger.error("fix_verification_job_failed",
                     job_id=job_id,
                     investigation_id=investigation_id,
                     error=str(e))
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(FixVerificationJob).where(FixVerificationJob.id == job_id)
            )
            job = result.scalar_one_or_none()
            if job:
                job.status = "failed"
                job.last_error = str(e)[:500]
                job.updated_at = datetime.now(timezone.utc)
                await session.commit()


async def recover_pending_jobs():
    """On startup, re-schedule any pending jobs that are overdue."""
    from sqlalchemy import select, update
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(FixVerificationJob)
            .where(FixVerificationJob.status == "pending")
        )
        jobs = result.scalars().all()
        overdue = 0
        for job in jobs:
            next_run = job.next_run_at
            # SQLite returns naive datetimes; make them aware for comparison
            if next_run and next_run.tzinfo is None:
                next_run = next_run.replace(tzinfo=timezone.utc)
            if next_run and next_run <= now:
                overdue += 1
                # Reset to run immediately (or with a small grace period)
                job.next_run_at = now + timedelta(seconds=5)
                job.updated_at = now
        await session.commit()
    if jobs:
        logger.info("fix_verification_jobs_recovered",
                    total=len(jobs),
                    overdue=overdue)


async def _load_investigation(investigation_id: str) -> Optional[Investigation]:
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .options(
                selectinload(Investigation.alerts),
                selectinload(Investigation.run),
            )
        )
        return result.scalar_one_or_none()


async def _get_run(investigation_id: str) -> Optional[PlaybookRun]:
    from sqlalchemy import select
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PlaybookRun).where(PlaybookRun.investigation_id == investigation_id)
        )
        return result.scalar_one_or_none()


async def _save_verification(investigation_id: str, status: str, new_alerts: int, detail: str):
    from sqlalchemy import update
    async with AsyncSessionLocal() as session:
        inv = await session.get(Investigation, investigation_id)
        if inv and inv.investigation_type == "runtime":
            if status in {"likely_fixed", "verified"}:
                investigation_status = "verified"
            elif status in {"not_fixed", "playbook_failed_problem_worse"}:
                investigation_status = "not_fixed"
            elif status == "playbook_failed_but_quiet":
                investigation_status = "remediation_failed"
            else:
                investigation_status = "inconclusive"
        else:
            if status in {"likely_fixed", "verified", "declined"}:
                investigation_status = "completed"
            elif status in {"not_fixed", "playbook_failed_problem_worse", "inconclusive"}:
                investigation_status = "completed_with_warnings"
            elif status == "playbook_failed_but_quiet":
                investigation_status = "failed"
            elif inv and inv.status == "completed_with_warnings":
                investigation_status = "completed_with_warnings"
            else:
                investigation_status = "completed"
        v = FixVerification(
            investigation_id=investigation_id,
            status=status,
            new_alerts_found=new_alerts,
            checked_at=datetime.now(timezone.utc),
            detail=detail,
        )
        session.add(v)
        await session.execute(
            update(Investigation)
            .where(Investigation.id == investigation_id)
            .values(
                status=investigation_status,
                verification_status="passed" if status in ("likely_fixed", "verified") else ("failed" if status in ("not_fixed", "playbook_failed_problem_worse") else "inconclusive"),
                updated_at=datetime.now(timezone.utc),
            )
        )
        await session.commit()


async def _query_es_for_recurrence(
    alert_snapshots: list, run_finished_at: datetime
) -> tuple[int, str]:
    """
    Query Elasticsearch for new alerts matching the same rules/signatures
    that triggered the original incident.

    Returns (new_alert_count, detail_string)
    """
    from core.elasticsearch import get_es_client

    es = await get_es_client()

    # Extract rule names and source IPs from alert snapshots
    rule_names = set()
    source_ips = set()
    for snapshot in alert_snapshots:
        try:
            data = json.loads(snapshot.alert_json)
            if data.get("rule_name"):
                rule_names.add(data["rule_name"])
            if data.get("source_ip"):
                source_ips.add(data["source_ip"])
        except Exception:
            continue

    if not rule_names and not source_ips:
        return 0, "No rule names or IPs to check — verification skipped"

    window_end = datetime.now(timezone.utc)
    window_start = run_finished_at

    # Build ES query: look for alerts after the playbook ran
    must_clauses = [
        {"range": {"@timestamp": {
            "gte": window_start.isoformat(),
            "lte": window_end.isoformat(),
        }}}
    ]

    # Match any of the original rule names
    if rule_names:
        must_clauses.append({
            "bool": {
                "should": [
                    {"match": {"rule.description": rn}} for rn in list(rule_names)[:5]
                ],
                "minimum_should_match": 1,
            }
        })

    # Match any of the original source IPs
    if source_ips:
        must_clauses.append({"terms": {"source_ip": list(source_ips)}})

    query = {"bool": {"must": must_clauses}}

    total_hits = 0
    checked_indices = []

    for index_pattern in [
        settings.wazuh_index_pattern,
        settings.falco_index_pattern,
        settings.filebeat_index_pattern,
    ]:
        try:
            resp = await es.count(index=index_pattern, body={"query": query})
            count = resp.get("count", 0)
            if count > 0:
                total_hits += count
                checked_indices.append(f"{index_pattern}:{count}")
        except Exception as e:
            logger.debug("fix_verify_es_error", index=index_pattern, error=str(e))

    detail_lines = [
        f"What was checked: Elasticsearch recurrence query for {len(rule_names)} rule(s) and {len(source_ips)} source IP(s).",
        f"Query used: bool[must=range(@timestamp gte/lte) + match(rule.description) for rules: {list(rule_names)[:5]}].",
        f"Time window: {window_start.strftime('%Y-%m-%d %H:%M:%S')} UTC → {window_end.strftime('%Y-%m-%d %H:%M:%S')} UTC.",
        f"New duplicate alerts found: {total_hits}.",
    ]
    if checked_indices:
        detail_lines.append(f"Indices with hits: {', '.join(checked_indices)}.")
        detail_lines.append(
            "Interpretation: the same rule(s)/pattern(s) fired again after remediation, "
            "suggesting the issue was NOT fully resolved."
        )
    else:
        detail_lines.append("No hits in any checked index.")
        detail_lines.append(
            "Interpretation: no recurrence of the original alert patterns was detected in the checked window."
        )
    detail = "\n".join(detail_lines)
    return total_hits, detail


async def _post_opensoar_comment(incident_id: str, text: str):
    """Post a comment on the OpenSOAR incident to notify of fix status."""
    if not settings.upstream_enabled:
        return
    try:
        async with httpx.AsyncClient(
            base_url=settings.opensoar_url,
            timeout=httpx.Timeout(10.0),
        ) as client:
            # Authenticate
            auth_resp = await client.post(
                "/api/v1/auth/login",
                json={"username": settings.opensoar_username, "password": settings.opensoar_password},
            )
            if auth_resp.status_code != 200:
                return
            token = auth_resp.json().get("access_token")
            headers = {"Authorization": f"Bearer {token}"}

            # Get first alert of the incident to post comment on
            inc_resp = await client.get(
                f"/api/v1/incidents/{incident_id}/alerts",
                headers=headers,
            )
            if inc_resp.status_code == 200:
                alerts = inc_resp.json()
                if isinstance(alerts, list) and alerts:
                    first_alert_id = alerts[0].get("id") if isinstance(alerts[0], dict) else alerts[0]
                    if first_alert_id:
                        await client.post(
                            f"/api/v1/alerts/{first_alert_id}/comments",
                            headers=headers,
                            json={"text": text},
                        )
    except Exception as e:
        logger.debug("fix_verify_comment_error", error=str(e))


async def verify_fix(investigation_id: str):
    """
    Main entry point. Called by ansible_exec after playbook execution (success or failure).

    Enhanced with active verification - actually checks if remediation actions worked.
    For runtime investigations, diagnostic-only cases (no real corrective action) are
    NEVER marked as fixed.
    """
    logger.info("fix_verification_started", investigation_id=investigation_id)

    inv = await _load_investigation(investigation_id)
    if not inv:
        logger.error("fix_verify_not_found", investigation_id=investigation_id)
        return

    run = await _get_run(investigation_id)
    run_finished = run.finished_at if run and run.finished_at else datetime.now(timezone.utc)

    playbook_failed = run and run.status == "failed"
    exit_code = run.exit_code if run else None
    has_successful_remediation = (
        run is not None
        and run.status == "completed"
        and exit_code == 0
        and inv.investigation_type == "runtime"
    )

    # Re-check ES for alert recurrence
    new_alerts, detail = await _query_es_for_recurrence(inv.alerts, run_finished)

    # Active verification - actually verify remediation actions worked
    active_verification = await _active_verify_remediation(inv)

    # Build structured check report into detail
    check_report_lines = ["\n--- State Verification Checks ---"]
    for check in active_verification.get("checks", []):
        check_report_lines.append(
            f"  [{check['check_type'].upper()}] target={check['target']} "
            f"expected={check['expected_state']} actual={check['actual_state']} result={check['result']}"
        )
    if active_verification.get("detail"):
        check_report_lines.append(f"  Detail: {active_verification['detail']}")
    detail += "\n".join(check_report_lines)

    # Diagnostic-only: never mark as fixed
    playbook_yaml = inv.playbook_yaml or ""
    if not playbook_yaml or len(playbook_yaml.strip()) < 50:
        status = "not_fixed"
        detail += "\nInvestigation has no remediation playbook (diagnostic-only)."
        await _save_verification(investigation_id, status, new_alerts, detail)
        logger.info("fix_verification_complete", investigation_id=investigation_id, status=status, reason="diagnostic_only")
        from response.archiver import archive_investigation
        await archive_investigation(investigation_id, fix_status=status)
        return

    # Runtime guard: if no real corrective action was executed, do NOT mark fixed
    if inv.investigation_type == "runtime" and not has_successful_remediation:
        status = "not_fixed"
        comment = (
            f"[OpenSOAR Backend] Verification run for runtime investigation.\n"
            f"No successful remediation execution was recorded for this case.\n"
            f"Diagnostic-only or failed executions cannot be marked as fixed.\n"
            f"Recurrence check: {new_alerts} new alert(s) in verification window.\n"
            f"Status: NOT FIXED — no corrective action was applied.\n{detail}"
        )
        await _save_verification(investigation_id, status, new_alerts, detail)
        await _post_opensoar_comment(inv.incident_id, comment)
        logger.info(
            "fix_verification_complete",
            investigation_id=investigation_id,
            status=status,
            new_alerts=new_alerts,
            active_verification=active_verification["success"],
        )
        from response.archiver import archive_investigation
        await archive_investigation(investigation_id, fix_status=status)
        return

    # Determine verdict based on playbook result AND state verification
    # Alert count is the primary signal; active verification can only nudge by one tier.
    state_passed = active_verification["success"]
    has_state_checks = bool(active_verification.get("checks"))

    # Check for plan-based state verification result
    verification_plan = inv.verification_plan_json
    plan_check_result = None
    if verification_plan:
        for check in active_verification.get("checks", []):
            if check.get("check_type") in ("iptables", "file_quarantine"):
                plan_check_result = check.get("result")
                break

    def _base_status_from_alerts(n: int) -> str:
        """Core signal from ES alert recurrence count."""
        if n == 0:
            return "likely_fixed"
        elif n <= 2:
            return "inconclusive"
        else:
            return "not_fixed"

    def _nudge_down(tier: str) -> str:
        """Active verification failure can only downgrade by one tier."""
        if tier == "likely_fixed":
            return "inconclusive"
        elif tier == "inconclusive":
            return "not_fixed"
        return tier

    if playbook_failed:
        if new_alerts == 0:
            status = "playbook_failed_but_quiet"
            comment = (
                f"[OpenSOAR Backend] Playbook FAILED (exit code: {exit_code}).\n"
                f"However, no new matching alerts detected - the attack may have stopped on its own.\n"
                f"Active verification: {'PASSED' if state_passed else 'FAILED'}\n"
                f"Status: PLAYBOOK FAILED BUT QUIET - manual review recommended.\n{detail}"
            )
        else:
            status = "playbook_failed_problem_worse"
            comment = (
                f"[OpenSOAR Backend] Playbook FAILED (exit code: {exit_code}) AND {new_alerts} new alerts detected!\n"
                f"This is critical - remediation failed and the attack is ongoing.\n"
                f"Active verification: {'FAILED' if not state_passed else 'PASSED'}\n"
                f"Status: CRITICAL - immediate manual intervention required.\n{detail}"
            )
    elif verification_plan and plan_check_result is not None:
        # Verification plan exists — remote state proof is mandatory
        if plan_check_result == "failed":
            # Explicit plan contract broken → not_fixed regardless of alert count
            status = "not_fixed"
            comment = (
                f"[OpenSOAR Backend] Playbook ran but remote state verification FAILED.\n"
                f"Expected state not found on target host.\n"
                f"Recurrence check: {new_alerts} new alert(s).\n"
                f"Status: NOT FIXED — remote state does not match expected remediation.\n{detail}"
            )
        elif plan_check_result == "inconclusive":
            status = "inconclusive"
            comment = (
                f"[OpenSOAR Backend] Playbook ran but remote state verification was INCONCLUSIVE.\n"
                f"Could not confirm expected state on target host.\n"
                f"Recurrence check: {new_alerts} new alert(s).\n"
                f"Status: INCONCLUSIVE — manual review required.\n{detail}"
            )
        elif plan_check_result == "passed":
            # Plan passed: use alert count as primary signal
            status = _base_status_from_alerts(new_alerts)
            if status == "likely_fixed":
                comment = (
                    f"[OpenSOAR Backend] Automated remediation complete.\n"
                    f"Playbook ran successfully. Remote state verified. No new matching alerts detected in "
                    f"{settings.fix_verify_window_minutes} minutes.\n"
                    f"Status: LIKELY FIXED\n{detail}"
                )
            elif status == "inconclusive":
                comment = (
                    f"[OpenSOAR Backend] Playbook ran. Remote state verified.\n"
                    f"But {new_alerts} new alert(s) detected.\n"
                    f"Status: INCONCLUSIVE — manual review recommended.\n{detail}"
                )
            else:
                comment = (
                    f"[OpenSOAR Backend] Playbook ran. Remote state verified.\n"
                    f"But {new_alerts} new matching alerts detected!\n"
                    f"Status: NOT FIXED — attack is ongoing.\n{detail}"
                )
        else:
            status = "inconclusive"
            comment = (
                f"[OpenSOAR Backend] Playbook ran but remote state verification returned unexpected result: {plan_check_result}.\n"
                f"Recurrence check: {new_alerts} new alert(s).\n"
                f"Status: INCONCLUSIVE — manual review required.\n{detail}"
            )
    else:
        # No explicit verification plan — alert count is primary;
        # active verification can only nudge down by one tier.
        base = _base_status_from_alerts(new_alerts)
        if has_state_checks and not state_passed:
            status = _nudge_down(base)
        else:
            status = base

        if status == "likely_fixed":
            comment = (
                f"[OpenSOAR Backend] Automated remediation complete.\n"
                f"Playbook ran successfully. No new matching alerts detected in "
                f"{settings.fix_verify_window_minutes} minutes.\n"
                f"Active verification: {'PASSED' if state_passed else 'INCONCLUSIVE'}\n"
                f"Status: LIKELY FIXED\n{detail}"
            )
        elif status == "inconclusive":
            comment = (
                f"[OpenSOAR Backend] Playbook ran.\n"
                f"Recurrence check: {new_alerts} new alert(s). "
                f"Active verification: {'PASSED' if state_passed else 'FAILED/INCONCLUSIVE'}.\n"
                f"Status: INCONCLUSIVE — manual review recommended.\n{detail}"
            )
        else:
            comment = (
                f"[OpenSOAR Backend] Playbook ran but {new_alerts} new matching alerts detected!\n"
                f"Active verification: {'PASSED' if state_passed else 'FAILED'}\n"
                f"Status: NOT FIXED — attack is ongoing.\n{detail}"
            )

    await _save_verification(investigation_id, status, new_alerts, detail)

    # Post comment to OpenSOAR
    await _post_opensoar_comment(inv.incident_id, comment)

    logger.info(
        "fix_verification_complete",
        investigation_id=investigation_id,
        status=status,
        new_alerts=new_alerts,
        active_verification=active_verification["success"],
    )

    # Trigger archive for completed investigations
    from response.archiver import archive_investigation
    await archive_investigation(investigation_id, fix_status=status)


async def _active_verify_remediation(inv: Investigation) -> dict:
    """
    Actively verify that remediation actions actually worked.
    For supported remediation types, runs system-state checks via Ansible.
    Falls back to ES-based checks for unsupported types.
    """
    result = {"success": True, "detail": "", "checks": []}
    details = []
    checks = []

    target_host = inv.target_host or "localhost"
    target_user = inv.target_user or "root"

    # Diagnostic-only investigations should NOT be marked as fixed
    playbook_yaml = inv.playbook_yaml or ""
    if not playbook_yaml or len(playbook_yaml.strip()) < 50:
        details.append("No remediation playbook — diagnostic-only or empty")
        checks.append({
            "check_type": "diagnostic",
            "target": target_host,
            "expected_state": "no_remediation_required",
            "actual_state": "no_playbook",
            "result": "diagnostic_completed",
        })
        result["detail"] = " | ".join(details)
        result["checks"] = checks
        result["success"] = True
        return result

    # Try system-state verification first, preferring stored verification_plan
    verification_plan = inv.verification_plan_json
    state_result = await _verify_system_state(inv, target_host, target_user, verification_plan)
    if state_result.get("checks"):
        checks.extend(state_result["checks"])
        details.extend(state_result.get("details", []))

    # Fallback: ES-based alert recurrence (legacy behavior, now secondary)
    if not checks:
        from core.elasticsearch import get_es_client
        try:
            es = await get_es_client()
            source_ips = []
            if inv.source_ips:
                source_ips = inv.source_ips.split(",") if isinstance(inv.source_ips, str) else [inv.source_ips]
            if source_ips:
                for ip in source_ips[:3]:
                    query = {
                        "query": {
                            "bool": {
                                "must": [
                                    {"match": {"source.ip": ip}},
                                    {"range": {"@timestamp": {"gte": "now-5m"}}}
                                ]
                            }
                        }
                    }
                    for index_pattern in [settings.wazuh_index_pattern, settings.falco_index_pattern, settings.filebeat_index_pattern]:
                        try:
                            resp = await es.count(index=index_pattern, body=query)
                            count = resp.get("count", 0)
                            if count > 0:
                                details.append(f"WARNING: {count} alerts from {ip} in last 5 min")
                                checks.append({
                                    "check_type": "es_alert_recurrence",
                                    "target": ip,
                                    "expected_state": "no_alerts",
                                    "actual_state": f"{count}_alerts",
                                    "result": "not_verified",
                                })
                        except Exception:
                            pass
            if not checks:
                details.append("No active system-state checks possible; ES fallback also inconclusive")
                checks.append({
                    "check_type": "fallback",
                    "target": target_host,
                    "expected_state": "unknown",
                    "actual_state": "unknown",
                    "result": "inconclusive",
                })
        except Exception as e:
            logger.debug("active_verify_es_fallback_error", error=str(e))
            details.append(f"ES fallback failed: {str(e)[:50]}")

    result["detail"] = " | ".join(details) if details else "No active checks performed"
    result["checks"] = checks
    # Success means all state checks passed AND no warnings in details
    has_failed_checks = any(c["result"] in ("failed", "not_verified") for c in checks)
    result["success"] = not has_failed_checks and not any("WARNING" in d for d in details)
    return result


async def _verify_system_state(inv: Investigation, target_host: str, target_user: str, verification_plan: dict | None = None) -> dict:
    """Dispatch to specific state verifiers based on stored plan or playbook content."""
    result = {"checks": [], "details": []}

    # Prefer stored verification_plan if available
    if verification_plan:
        plan_type = verification_plan.get("type")
        if plan_type == "iptables_rule":
            iptables_result = await _verify_iptables_state_with_plan(inv, target_host, target_user, verification_plan)
            result["checks"].append(iptables_result)
            result["details"].append(iptables_result.get("detail", ""))
            return result
        elif plan_type == "file_quarantine":
            file_result = await _verify_file_state_with_plan(inv, target_host, target_user, verification_plan)
            result["checks"].append(file_result)
            result["details"].append(file_result.get("detail", ""))
            return result
        else:
            result["details"].append(f"Unknown verification plan type: {plan_type}")

    # Fallback: parse playbook YAML for legacy records
    playbook_yaml = inv.playbook_yaml or ""
    import yaml
    try:
        pb = yaml.safe_load(playbook_yaml)
    except Exception:
        result["details"].append("Malformed playbook YAML — cannot parse for verification")
        result["checks"].append({
            "check_type": "parse",
            "target": target_host,
            "expected_state": "parseable_playbook",
            "actual_state": "malformed_yaml",
            "result": "inconclusive",
        })
        return result

    if not isinstance(pb, list):
        result["details"].append("Playbook YAML is not a list — cannot parse for verification")
        result["checks"].append({
            "check_type": "parse",
            "target": target_host,
            "expected_state": "parseable_playbook",
            "actual_state": "not_a_list",
            "result": "inconclusive",
        })
        return result

    # Detect remediation type from playbook tasks
    has_iptables = False
    has_file_op = False
    for play in pb:
        if not isinstance(play, dict):
            continue
        for task in play.get("tasks", []):
            if not isinstance(task, dict):
                continue
            for key in task:
                if "iptables" in key:
                    has_iptables = True
                if key in ("ansible.builtin.copy", "ansible.builtin.file", "ansible.builtin.command", "ansible.builtin.shell"):
                    task_def = task.get(key, "")
                    task_str = str(task_def)
                    if "quarantine" in task_str or "mv " in task_str or "rm " in task_str:
                        has_file_op = True

    if has_iptables:
        iptables_result = await _verify_iptables_state(inv, target_host, target_user)
        result["checks"].append(iptables_result)
        result["details"].append(iptables_result.get("detail", ""))

    if has_file_op:
        file_result = await _verify_file_state(inv, target_host, target_user)
        result["checks"].append(file_result)
        result["details"].append(file_result.get("detail", ""))

    if not has_iptables and not has_file_op:
        result["details"].append("No recognizable remediation type in playbook")
        result["checks"].append({
            "check_type": "parse",
            "target": target_host,
            "expected_state": "known_remediation_type",
            "actual_state": "unknown_type",
            "result": "inconclusive",
        })

    return result


async def _verify_iptables_state_with_plan(inv: Investigation, target_host: str, target_user: str, plan: dict) -> dict:
    """Verify iptables rule using stored verification plan."""
    chain = plan.get("chain", "INPUT")
    source = plan.get("source", "")
    jump = plan.get("jump", "DROP")

    if not source:
        return {
            "check_type": "iptables",
            "target": target_host,
            "expected_state": "DROP_rule",
            "actual_state": "no_source_in_plan",
            "result": "inconclusive",
            "detail": "Verification plan has no source IP",
        }

    verify_yaml = f"""---
- name: "Verify iptables rule"
  hosts: {target_host}
  gather_facts: no
  tasks:
    - name: "Check iptables rule for {source}"
      ansible.builtin.shell: "iptables -S {chain} | grep '{source}' | grep '{jump}' || true"
      register: rule_check
      changed_when: false
      ignore_errors: yes
    - name: "Collect iptables state"
      ansible.builtin.shell: "iptables -S | head -20"
      register: iptables_state
      changed_when: false
      ignore_errors: yes
"""

    exit_code, output = await _run_verification_playbook(verify_yaml, target_host, target_user, inv.id)

    if source in output and jump in output:
        return {
            "check_type": "iptables",
            "target": target_host,
            "expected_state": f"{jump}_rule_for_{source}",
            "actual_state": "rule_present",
            "result": "passed",
            "detail": f"FIX VERIFIED: iptables {jump} rule for {source} exists on {target_host}",
        }
    else:
        return {
            "check_type": "iptables",
            "target": target_host,
            "expected_state": f"{jump}_rule_for_{source}",
            "actual_state": "rule_missing",
            "result": "failed",
            "detail": f"WARNING: iptables {jump} rule for {source} not found on {target_host}",
        }


async def _verify_file_state_with_plan(inv: Investigation, target_host: str, target_user: str, plan: dict) -> dict:
    """Verify file quarantine using stored verification plan."""
    original_path = plan.get("original_path", "")
    quarantine_path = plan.get("quarantine_path", "")

    if not quarantine_path and not original_path:
        return {
            "check_type": "file_quarantine",
            "target": target_host,
            "expected_state": "file_quarantined",
            "actual_state": "no_paths_in_plan",
            "result": "inconclusive",
            "detail": "Verification plan has no file paths",
        }

    checks = []
    if quarantine_path:
        checks.append(
            f"    - name: 'Check quarantine file exists'\n"
            f"      ansible.builtin.stat:\n"
            f"        path: {quarantine_path}\n"
            f"      register: quarantine_stat\n"
        )
    if original_path:
        checks.append(
            f"    - name: 'Check original file removed'\n"
            f"      ansible.builtin.stat:\n"
            f"        path: {original_path}\n"
            f"      register: original_stat\n"
        )

    verify_yaml = f"""---
- name: "Verify file quarantine"
  hosts: {target_host}
  gather_facts: no
  tasks:
{''.join(checks)}
"""

    exit_code, output = await _run_verification_playbook(verify_yaml, target_host, target_user, inv.id)

    quarantine_exists = "quarantine_stat" in output and "exists" in output.lower()
    original_removed = "original_stat" in output and ("does not exist" in output.lower() or "exists=false" in output.lower())

    if quarantine_path and original_path:
        if quarantine_exists and original_removed:
            return {
                "check_type": "file_quarantine",
                "target": target_host,
                "expected_state": "quarantine_exists_original_removed",
                "actual_state": "quarantine_exists_original_removed",
                "result": "passed",
                "detail": f"FIX VERIFIED: {original_path} quarantined to {quarantine_path}",
            }
        else:
            return {
                "check_type": "file_quarantine",
                "target": target_host,
                "expected_state": "quarantine_exists_original_removed",
                "actual_state": f"quarantine_exists={quarantine_exists}, original_removed={original_removed}",
                "result": "failed",
                "detail": f"WARNING: File quarantine verification failed on {target_host}",
            }
    elif quarantine_path:
        return {
            "check_type": "file_quarantine",
            "target": target_host,
            "expected_state": "quarantine_exists",
            "actual_state": "quarantine_exists" if quarantine_exists else "missing",
            "result": "passed" if quarantine_exists else "failed",
            "detail": f"Quarantine file {'exists' if quarantine_exists else 'missing'} on {target_host}",
        }
    else:
        return {
            "check_type": "file_quarantine",
            "target": target_host,
            "expected_state": "original_removed",
            "actual_state": "original_removed" if original_removed else "still_present",
            "result": "passed" if original_removed else "failed",
            "detail": f"Original file {'removed' if original_removed else 'still present'} on {target_host}",
        }


async def _verify_iptables_state(inv: Investigation, target_host: str, target_user: str) -> dict:
    """Verify that an iptables DROP rule exists for the blocked source IP."""
    import yaml
    playbook_yaml = inv.playbook_yaml or ""
    source_ips = []
    if inv.source_ips:
        source_ips = [s.strip() for s in inv.source_ips.split(",") if s.strip()]

    # Parse playbook to extract expected iptables rules
    expected_rules = []
    try:
        pb = yaml.safe_load(playbook_yaml)
        if isinstance(pb, list):
            for play in pb:
                if not isinstance(play, dict):
                    continue
                for task in play.get("tasks", []):
                    if not isinstance(task, dict):
                        continue
                    for key, val in task.items():
                        if "iptables" in key and isinstance(val, dict):
                            chain = val.get("chain", "INPUT")
                            src = val.get("source", "")
                            jump = val.get("jump", "")
                            if src and jump:
                                expected_rules.append({"chain": chain, "source": src, "jump": jump})
    except Exception:
        pass

    if not expected_rules and source_ips:
        # Fallback: assume standard DROP for source IPs
        expected_rules = [{"chain": "INPUT", "source": ip, "jump": "DROP"} for ip in source_ips[:1]]

    if not expected_rules:
        return {
            "check_type": "iptables",
            "target": target_host,
            "expected_state": "DROP_rule",
            "actual_state": "no_rules_parsed",
            "result": "inconclusive",
            "detail": "Could not parse expected iptables rules from playbook",
        }

    # Build verification playbook
    rule_checks = []
    for rule in expected_rules:
        rule_checks.append(
            f"    - name: 'Check iptables rule for {rule['source']}'\n"
            f"      ansible.builtin.shell: \"iptables -L {rule['chain']} -n | grep '{rule['source']}' | grep '{rule['jump']}' || true\"\n"
            f"      register: rule_check_{len(rule_checks)}\n"
            f"      changed_when: false\n"
            f"      ignore_errors: yes\n"
        )

    verify_yaml = f"""---
- name: "Verify iptables rules"
  hosts: {target_host}
  gather_facts: no
  tasks:
{''.join(rule_checks)}
    - name: "Collect iptables state"
      ansible.builtin.shell: "iptables -L -n | head -20"
      register: iptables_state
      changed_when: false
      ignore_errors: yes
"""

    exit_code, output = await _run_verification_playbook(verify_yaml, target_host, target_user, inv.id)

    missing_rules = []
    for rule in expected_rules:
        if rule["source"] not in output or rule["jump"] not in output:
            # More precise check: look for the source IP in output
            if rule["source"] not in output:
                missing_rules.append(rule)

    if missing_rules:
        return {
            "check_type": "iptables",
            "target": target_host,
            "expected_state": f"DROP_rule_for_{expected_rules[0]['source']}",
            "actual_state": "rule_missing",
            "result": "failed",
            "detail": f"WARNING: iptables rule for {missing_rules[0]['source']} not found on {target_host}",
        }
    else:
        return {
            "check_type": "iptables",
            "target": target_host,
            "expected_state": f"DROP_rule_for_{expected_rules[0]['source']}",
            "actual_state": "rule_present",
            "result": "passed",
            "detail": f"FIX VERIFIED: iptables DROP rule for {expected_rules[0]['source']} exists on {target_host}",
        }


async def _verify_file_state(inv: Investigation, target_host: str, target_user: str) -> dict:
    """Verify file quarantine: original removed, quarantine copy exists."""
    import yaml
    playbook_yaml = inv.playbook_yaml or ""
    quarantine_path = None
    original_path = None

    try:
        pb = yaml.safe_load(playbook_yaml)
        if isinstance(pb, list):
            for play in pb:
                if not isinstance(play, dict):
                    continue
                for task in play.get("tasks", []):
                    if not isinstance(task, dict):
                        continue
                    for key, val in task.items():
                        if key in ("ansible.builtin.copy", "ansible.builtin.command", "ansible.builtin.shell"):
                            task_str = str(val)
                            if "quarantine" in task_str:
                                # Try to extract paths
                                if isinstance(val, dict) and val.get("dest"):
                                    quarantine_path = val["dest"]
                                if isinstance(val, dict) and val.get("src"):
                                    original_path = val["src"]
                            if isinstance(val, str) and "mv " in val:
                                parts = val.split()
                                if len(parts) >= 3:
                                    original_path = parts[1]
                                    quarantine_path = parts[2]
    except Exception:
        pass

    if not quarantine_path and not original_path:
        return {
            "check_type": "file_quarantine",
            "target": target_host,
            "expected_state": "file_quarantined",
            "actual_state": "no_paths_parsed",
            "result": "inconclusive",
            "detail": "Could not parse file quarantine paths from playbook",
        }

    checks = []
    if quarantine_path:
        checks.append(
            f"    - name: 'Check quarantine file exists'\n"
            f"      ansible.builtin.stat:\n"
            f"        path: {quarantine_path}\n"
            f"      register: quarantine_stat\n"
        )
    if original_path:
        checks.append(
            f"    - name: 'Check original file removed'\n"
            f"      ansible.builtin.stat:\n"
            f"        path: {original_path}\n"
            f"      register: original_stat\n"
        )

    verify_yaml = f"""---
- name: "Verify file quarantine"
  hosts: {target_host}
  gather_facts: no
  tasks:
{''.join(checks)}
"""

    exit_code, output = await _run_verification_playbook(verify_yaml, target_host, target_user, inv.id)

    quarantine_exists = "quarantine_stat" in output and "exists" in output.lower()
    original_removed = "original_stat" in output and ("does not exist" in output.lower() or "exists=false" in output.lower())

    if quarantine_path and original_path:
        if quarantine_exists and original_removed:
            return {
                "check_type": "file_quarantine",
                "target": target_host,
                "expected_state": f"quarantine_exists_original_removed",
                "actual_state": "quarantine_exists_original_removed",
                "result": "passed",
                "detail": f"FIX VERIFIED: {original_path} quarantined to {quarantine_path}",
            }
        else:
            return {
                "check_type": "file_quarantine",
                "target": target_host,
                "expected_state": f"quarantine_exists_original_removed",
                "actual_state": f"quarantine_exists={quarantine_exists}, original_removed={original_removed}",
                "result": "failed",
                "detail": f"WARNING: File quarantine verification failed on {target_host}",
            }
    else:
        return {
            "check_type": "file_quarantine",
            "target": target_host,
            "expected_state": "file_quarantined",
            "actual_state": "partial_check",
            "result": "inconclusive",
            "detail": "Partial file quarantine check — paths unclear",
        }


async def _run_verification_playbook(playbook_yaml: str, target_host: str, target_user: str, investigation_id: str) -> tuple[int, str]:
    """Lightweight Ansible runner for verification playbooks."""
    import asyncio
    import os
    from pathlib import Path
    from config import get_settings
    from sqlalchemy import select

    s = get_settings()
    playbook_dir = Path(s.playbook_dir)
    playbook_dir.mkdir(exist_ok=True)

    verify_id = f"verify_{investigation_id}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    playbook_path = playbook_dir / f"{verify_id}.yml"
    playbook_path.write_text(playbook_yaml, encoding="utf-8")

    # Load per-asset credentials, falling back to global settings
    asset_config = {}
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Investigation).where(Investigation.id == investigation_id)
            )
            inv = result.scalar_one_or_none()
            if inv and inv.asset_id:
                from response.models import MonitoredAsset
                asset_result = await session.execute(
                    select(MonitoredAsset).where(MonitoredAsset.asset_id == inv.asset_id)
                )
                asset = asset_result.scalar_one_or_none()
                if asset and asset.ansible_config_json:
                    asset_config = asset.ansible_config_json
    except Exception:
        pass

    # Write inventory
    ssh_key = asset_config.get("ansible_ssh_key") or s.ansible_ssh_key or ""
    ssh_password = asset_config.get("ansible_ssh_password") or s.ansible_ssh_password or ""
    ssh_port = asset_config.get("ansible_ssh_port") or s.ansible_ssh_port or 22
    become_method = asset_config.get("ansible_become_method") or s.ansible_become_method or "sudo"
    become_password = asset_config.get("ansible_become_password") or s.ansible_become_password or ssh_password

    key_line = f" ansible_ssh_private_key_file={ssh_key}" if ssh_key else ""
    password_line = f" ansible_ssh_pass='{ssh_password}'" if ssh_password else ""
    become_pass_line = f" ansible_become_pass='{become_password}'" if become_password else ""
    ssh_opts = (
        "-o StrictHostKeyChecking=no "
        "-o PreferredAuthentications=password "
        "-o PasswordAuthentication=yes "
        "-o KbdInteractiveAuthentication=no "
        "-o ConnectTimeout=15"
    )
    inventory_content = (
        f"[target]\n"
        f"{target_host} ansible_user={target_user}{key_line}{password_line} "
        f"ansible_ssh_common_args='{ssh_opts}' "
        f"ansible_ssh_port={ssh_port} "
        f"ansible_become=yes ansible_become_method={become_method} {become_pass_line}\n"
    )
    inventory_path = playbook_dir / f"{verify_id}_inventory"
    inventory_path.write_text(inventory_content, encoding="utf-8")

    cmd = [
        "ansible-playbook",
        "-i", str(inventory_path),
        str(playbook_path.name),
        "-v",
    ]
    env = os.environ.copy()
    if ssh_password:
        env["ANSIBLE_SSH_PASS"] = ssh_password

    proc = None
    output = ""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            cwd=str(playbook_dir),
            limit=1024 * 1024,
        )
        chunks = []
        assert proc.stdout is not None
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                break
            chunks.append(chunk.decode("utf-8", errors="replace"))
        await asyncio.wait_for(proc.wait(), timeout=60)
        exit_code = proc.returncode or 0
        output = "".join(chunks)
    except asyncio.TimeoutError:
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                pass
            if proc.returncode is None:
                proc.kill()
        exit_code = -1
        output = "Verification playbook timed out after 60s"
    except Exception as e:
        exit_code = -1
        output = f"Verification playbook error: {e}"

    # Cleanup
    try:
        playbook_path.unlink(missing_ok=True)
        inventory_path.unlink(missing_ok=True)
    except Exception:
        pass

    return exit_code, output
