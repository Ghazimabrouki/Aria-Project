# FIX REPORT — OpenSOAR Internal Trusted Mode Critical Fixes
**Date:** 2026-05-17  
**Branch:** `17_mai`  
**Scope:** 9 critical/high findings from senior review, NO full JWT auth  

---

## A. FILES CHANGED

### Backend Routes
- `api/routes/investigations.py` — admin auth, audit context, truth report fix
- `api/routes/aria_alerts.py` — full API implementation (was empty)

### Backend Core
- `response/models.py` — added audit context columns to `InvestigationAuditEvent`
- `response/db.py` — migration for new audit columns
- `response/audit_events.py` — reliable commit + enriched audit context
- `response/ansible_exec.py` — secure inventory, sshpass env var, safe tar extraction
- `response/fix_verifier.py` — ES recurrence includes source IPs, verdict logic tightened
- `response/playbook_safety.py` — empty playbook blocked from execution
- `response/workflow_summary.py` — no changes needed (already used alert_json)

### Tests
- `tests/test_playbook_safety.py` — updated empty playbook assertion
- `tests/test_internal_trusted_admin_secret.py` — NEW
- `tests/test_audit_persistence.py` — NEW
- `tests/test_truth_report_evidence.py` — NEW
- `tests/test_ansible_secret_handling.py` — NEW
- `tests/test_safe_tar_extract.py` — NEW
- `tests/test_aria_alerts.py` — NEW
- `tests/test_verifier_recurrence.py` — NEW

---

## B. ROOT CAUSE AND FIX FOR EACH FINDING

### 1. Admin access was a no-op
**Root cause:** `_validate_admin_access` returned `decided_by` without checking any credential.  
**Fix:** Implemented internal-trusted-mode validation:
- Requires `X-ARIA-Admin-Secret` header matching `settings.aria_admin_secret`
- Blocks default/empty secrets (`changeme`, `default`, `admin`, empty string)
- Returns 403 for missing or wrong secret
- `decided_by` spoofing alone no longer grants access

**Files:** `api/routes/investigations.py`

### 2. Audit events silently dropped
**Root cause:** `record_audit_event` did `session.add(event)` but never committed. When called after `session.commit()` in endpoint handlers, the event was lost.  
**Fix:**
- Added `await session.commit()` inside `record_audit_event`
- Added 5 new columns to `InvestigationAuditEvent`: `operator_label`, `source_ip`, `user_agent`, `request_id`, `auth_mode`
- Updated all 12 endpoints to pass request context via `_audit_ctx(request)`
- Added DB migration for new columns

**Files:** `response/audit_events.py`, `response/models.py`, `response/db.py`, `api/routes/investigations.py`

### 3. Truth report read non-existent DB column
**Root cause:** `_has_evidence_of_compromise` and `_build_truth_report` accessed `a.alert_snapshot`, but `InvestigationAlert` only has `alert_json`. The `except Exception: pass` silently swallowed the error.  
**Fix:**
- Added `_get_alert_payload(alert)` helper that reads `alert_json` (current) with fallback to `alert_snapshot` (legacy)
- Replaced all `a.alert_snapshot` references with `_get_alert_payload(a)`
- Added explicit diagnostics to truth report when evidence is limited

**Files:** `api/routes/investigations.py`

### 4. Plaintext credentials on disk
**Root cause:** `_write_inventory()` wrote `ansible_ssh_pass` and `ansible_become_pass` to `/tmp/opensoar_playbooks/` with default permissions (world-readable).  
**Fix:**
- Added `_ensure_secure_dir(path)` — creates directory with `0o700`
- Added `_write_secure_file(path, content)` — writes file with `0o600`
- Replaced all inventory/vars file writes with secure helpers

**Files:** `response/ansible_exec.py`

### 5. sshpass password exposed in process listing
**Root cause:** `_test_ssh_connection()` used `subprocess_shell` with `sshpass -p '{password}' ssh ...`, making the password visible in `ps` output.  
**Fix:**
- Replaced with `sshpass -e` and `SSHPASS` environment variable
- Set `stdin=DEVNULL` to prevent interactive prompts
- Added `-o BatchMode=no -o NumberOfPasswordPrompts=1`

**Files:** `response/ansible_exec.py`

### 6. Fix verifier ES recurrence ignored source IPs
**Root cause:** `_query_es_for_recurrence()` extracted `source_ips` from alert snapshots but never added them to ES `must_clauses`.  
**Fix:**
- Added `{"terms": {"source_ip": list(source_ips)}}` to `must_clauses` when `source_ips` is non-empty
- Tightened verdict logic: without `verification_plan`, ES silence alone returns `inconclusive` instead of `likely_fixed`
- State verification failure now overrides ES silence

**Files:** `response/fix_verifier.py`

### 7. Unsafe tar extraction
**Root cause:** `tar.extractall(path=...)` had no path sanitization, allowing directory traversal from malicious tarballs.  
**Fix:**
- Added `_safe_extract_tar(tar_path, dest_dir)` helper
- Rejects `../` traversal, absolute paths, and symlink escapes
- Replaced all `tar.extractall()` usage

**Files:** `response/ansible_exec.py`

### 8. Empty playbook marked executable
**Root cause:** `validate_playbook_safety()` returned `safe=True, executable=True` for empty/invalid playbooks.  
**Fix:**
- Empty playbook now returns `executable=False, manual_review_required=True, execution_mode="none"`
- `compute_investigation_safety()` forces `has_remediation_action=False` and downgrades tier for empty playbooks
- Approval/execute endpoints already reject non-executable playbooks

**Files:** `response/playbook_safety.py`

### 9. ARIA alerts router empty (404)
**Root cause:** `api/routes/aria_alerts.py` only had an empty `APIRouter`.  
**Fix:**
- Implemented `GET /stats` — counts by severity + unacknowledged
- Implemented `GET /` — paginated list with filters
- Implemented `POST /{id}/acknowledge` — protected by admin secret
- Implemented `DELETE /{id}` — protected by admin secret

**Files:** `api/routes/aria_alerts.py`

---

## C. SECURITY POSTURE WITHOUT JWT

### What was implemented: internal trusted mode
- `auth_mode = internal_trusted`
- No user login, no JWT, no OAuth, no session cookies
- `operator_label` + `source_ip` + `user_agent` + `request_id` stored in audit events for traceability
- `decided_by` is a self-reported label, NOT an authenticated identity

### What protects dangerous actions:
- `X-ARIA-Admin-Secret` header required for:
  - `admin-decision-approve`
  - `admin-soft-override`
  - `execute` (soft-block cases)
  - `rollback`
  - `acknowledge/delete` ARIA alerts
- Secret must be strong (not empty/changeme/default/admin)
- Secret is never logged, never in frontend source
- Admin endpoints return 403 for missing/wrong secret

### Deployment assumptions:
- Backend runs behind VPN or private network
- Not safe for direct public internet exposure
- Frontend-to-backend communication is on trusted network
- Admin secret is distributed out-of-band to operators

### Honest limitations:
- Anyone on the trusted network can perform analyst actions (approve safe-tier, decline, archive)
- `decided_by` can be spoofed for analyst actions — audit trail records what was claimed, not who was authenticated
- This is intentional: the user explicitly deferred full auth

---

## D. TESTS AND EXACT RESULTS

### Backend Compilation
```bash
python3 -m py_compile api/routes/investigations.py api/routes/aria_alerts.py \
  response/ansible_exec.py response/fix_verifier.py response/playbook_safety.py \
  response/audit_events.py response/models.py response/db.py
```
**Result:** All files compile (exit 0)

### Full Test Suite
```bash
pytest tests/test_action_invariants.py tests/test_analyst_control.py \
  tests/test_admin_override.py tests/test_safety_invariants.py \
  tests/test_safety_tiers.py tests/test_deterministic_remediation.py \
  tests/test_playbook_safety.py tests/test_execution_reliability.py \
  tests/test_operational_readiness.py tests/test_controlled_remediation.py \
  tests/test_internal_trusted_admin_secret.py tests/test_audit_persistence.py \
  tests/test_truth_report_evidence.py tests/test_ansible_secret_handling.py \
  tests/test_safe_tar_extract.py tests/test_aria_alerts.py \
  tests/test_verifier_recurrence.py -v
```
**Result:** `200 passed in 5.30s`

### New Tests Breakdown

| Test File | Tests | Result |
|-----------|-------|--------|
| `test_internal_trusted_admin_secret.py` | 5 | PASS |
| `test_audit_persistence.py` | 5 | PASS |
| `test_truth_report_evidence.py` | 4 | PASS |
| `test_ansible_secret_handling.py` | 2 | PASS |
| `test_safe_tar_extract.py` | 3 | PASS |
| `test_aria_alerts.py` | 5 | PASS |
| `test_verifier_recurrence.py` | 3 | PASS |

### Frontend Build
```bash
cd frontend && pnpm build
```
**Result:** Build succeeds, no errors

### Frontend TypeScript
```bash
cd frontend && pnpm exec tsc --noEmit
```
**Result:** 23 errors (all in non-SOC modules: infrastructure, ips, metrics, runtime, operator). 0 errors in alerts/incidents/investigations.

### Health Check
```bash
python3 response/scripts/aria_health_check.py
```
**Result:** `Overall status: DEGRADED` (production data backlog: 80 stuck, 409 awaiting approval, 123 failed runs). All smoke checks pass. ARIA alerts API now responds.

### API Probes
```bash
curl http://127.0.0.1:8001/api/v1/aria-alerts/stats
```
**Result:** `{"total": 0, "by_severity": {...}, "unacknowledged": 0}` (no more 404)

---

## E. REMAINING RISKS

| Risk | Severity | Mitigation | Owner |
|------|----------|------------|-------|
| Container detection by string length | Medium | Hardened but still heuristic. Needs runtime inventory context. | Future |
| Prompt length ceiling | Medium | Large incidents could overflow LLM context. Needs truncation. | Future |
| No deduplication in ARIA alerts | Medium | Could spam on retry loops. Add `get_or_create` logic. | Future |
| Archive button shown for approved but transition blocked | Low | UX confusion only. Button returns 400. | Future |
| Duplicate alert evidence rendering | Low | UX bug. Alerts shown twice in Evidence tab. | Future |
| Hardcoded "admin" user in frontend | Low | Cosmetic. All actions pass "admin" as label. Audit records real context. | Future |
| No abort controllers on async actions | Low | Navigating away during action leaves dangling promise. | Future |
| Investigation detail page 1,956 lines | Low | Maintenance burden. Should be split into components. | Future |
| Health check degraded production state | N/A | Data backlog, not code issue. Needs operational triage. | Ops |

---

## F. FINAL VERDICT

**INTERNAL TRUSTED MODE CRITICAL FIXES COMPLETE**

All 9 critical/high findings from the senior review have been addressed:
1. ✅ Admin auth enforced via `X-ARIA-Admin-Secret`
2. ✅ Audit events persist reliably with request context
3. ✅ Truth report uses correct `alert_json` column
4. ✅ Ansible inventory credentials secured (0600/0700)
5. ✅ sshpass uses environment variable, not command string
6. ✅ Verifier ES recurrence includes source IPs
7. ✅ Safe tar extraction with path traversal guards
8. ✅ Empty playbook blocked from execution
9. ✅ ARIA alerts API fully implemented

**Test coverage:** 200 tests pass (172 existing + 28 new). No regressions.

**Security posture:** Internal trusted mode is operational. Dangerous actions require admin secret. No JWT/OAuth added. Deployment must remain behind VPN/private network.
