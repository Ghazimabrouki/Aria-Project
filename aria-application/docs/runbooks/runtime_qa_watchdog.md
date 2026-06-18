# Runtime QA Watchdog Runbook

## What it checks

The watchdog continuously verifies that `/runtime/investigations/` stays reliable, truthful, and SOC-ready.

| Check | Method | Alert if |
|-------|--------|----------|
| API health | `GET /api/v1/runtime/investigations/stats` | API unreachable |
| DB health | SQLite query for runtime count | DB unreachable |
| ES health | Cluster health (optional) | ES red or unreachable |
| Diagnosing backlog | API + DB query for `status=diagnosing` | > 0 stuck > 10 min |
| Recovery loop health | DB scan for stuck cases > 5 min | Cases not recovering |
| API contract | Detail payload field validation | Missing required fields |
| Fake remediation | `approve_run` / `corrective_actions` / playbook label mismatch | Fake approval or remediation shown |
| Container safety | Container ID + `target_context=host` without validation | Unsafe host remediation |
| Data quality | Missing host/rule/process, corrupted `proc_name`, empty findings | Data gaps or corruption |
| Raw snapshots | `raw_source_json` coverage (24h) | Coverage < 90% |
| SSH timeout rate | Diagnostic output scan (1h window) | Rate > 20% |
| Synthetic scenarios | Real cases sampled by status | Decision/actions mismatch |

## How to run manually

```bash
# Run once, print alerts to console
python3 scripts/validation/runtime_qa_watchdog.py

# CI mode: exit 1 if any critical issue found
python3 scripts/validation/runtime_qa_watchdog.py --ci

# Silent mode: logs and reports only, no console output
python3 scripts/validation/runtime_qa_watchdog.py --silent
```

## How it is scheduled

**Systemd timer** (active on this host):

```bash
# Check status
systemctl list-timers runtime-qa-watchdog.timer

# View recent runs
journalctl -u runtime-qa-watchdog.service --no-pager

# Disable
sudo systemctl disable --now runtime-qa-watchdog.timer
```

Runs every 5 minutes via:
- `/etc/systemd/system/runtime-qa-watchdog.service`
- `/etc/systemd/system/runtime-qa-watchdog.timer`

**Cron alternative** (if systemd is unavailable):

```cron
*/5 * * * * cd /path/to/project && /usr/bin/python3 scripts/validation/runtime_qa_watchdog.py --silent >> /tmp/runtime_qa_watchdog.log 2>&1
```

## How to read the report

**Markdown** (human-readable):
```bash
cat reports/runtime_qa_watchdog_latest.md
```

**JSON** (machine-readable):
```bash
cat reports/runtime_qa_watchdog_latest.json | jq '.summary'
```

**Log** (structured):
```bash
cat /tmp/runtime_qa_watchdog.log | jq 'select(.level=="warning" or .level=="error")'
```

Report top-level fields:
- `api_reachable`, `db_reachable`, `es_reachable`
- `recovery_loop_healthy`
- `stats` — current runtime investigation counts
- `findings[]` — every anomaly found
- `synthetic_results[]` — scenario validation outcomes
- `summary.critical` / `summary.warning`

## What critical alerts mean

A **critical** finding means the runtime investigation pipeline may have a regression or is unsafe to operate without review.

Common critical findings:

| Finding | Meaning |
|---------|---------|
| `fake_remediation_playbook` | A case shows "Remediation Playbook" but has no corrective actions |
| `observe_has_remediation` | An observe case incorrectly offers remediation |
| `unsafe_approval_path` | `approve_run=true` when status is not `awaiting_approval` |
| `fake_approval_path` | `approve_run=true` but no corrective actions exist |
| `container_host_remediation_unsafe` | Container case targets host without namespace/mount validation |
| `diagnostic_marked_remediation` | Diagnostic summary has `is_remediation=true` |
| `api_contract_missing_field` | Detail endpoint is missing required fields |
| `stuck_diagnosing` | Case stuck in diagnosing > 10 minutes |

## What to do if diagnosing backlog grows

1. Check if `main.py` is running (recovery loop is inside it)
2. Run the backfill script if needed:
   ```bash
   python3 scripts/backfill/backfill_runtime_diagnostics.py --age-minutes 10 --batch-size 20
   ```
3. Check SSH connectivity to the target host (Ansible inventory)
4. Check `pipeline/datausage/runtime_orchestrator.py` `_DIAGNOSTIC_SEMAPHORE` is not exhausted
5. If backlog persists, escalate — do not let diagnosing accumulate

## What to do if fake remediation is detected

1. **Freeze the remediation architecture immediately** — do not deploy any planner/approval changes
2. Identify the affected investigation IDs from the report
3. Verify the backend has not executed any unwanted Ansible playbooks
4. Check `response/runtime_ai_engine/remediation_planner.py` for regressions
5. File a bug and treat as a SOC incident — fake remediation is a safety violation

## What to do if unsafe approval path is detected

1. **Block all approvals** until the root cause is found
2. Check `api/routes/runtime.py` `_available_actions()` logic
3. Verify `has_corrective_actions()` and status gating have not been bypassed
4. Do not allow any `approve_run=true` unless `status==awaiting_approval` **and** corrective actions exist
5. Treat as a security regression

## What to do if frontend/API contract breaks

1. Check the exact missing fields in `reports/runtime_qa_watchdog_latest.json`
2. Verify the backend API is running on port 8001
3. Run the CI validation script to isolate the failure:
   ```bash
   ./scripts/validation/validate_runtime_feature.sh
   ```
4. If backend tests pass but API contract fails, the route payload has drifted
5. If Playwright fails but API is healthy, check frontend page selectors

## CI validation command

Run the full suite before any deployment:

```bash
./scripts/validation/validate_runtime_feature.sh
```

It validates:
- Python compilation of key backend files
- `tests/test_manual_workflow.py` (27 tests)
- `tests/test_forwarder.py` (12 tests)
- Runtime QA watchdog (no critical issues)
- Frontend lint (0 errors)
- Frontend build (Next.js production)
- Playwright E2E (`e2e/runtime-investigations.spec.ts`)

## Contact / Escalation

- Backend/API issues: check `main.py`, `api/routes/runtime.py`, `response/runtime_ai_engine/`
- Frontend issues: check `frontend/app/(dashboard)/runtime/`, `frontend/e2e/`
- Infrastructure issues: check systemd timer, backend port 8001, frontend port 3000
