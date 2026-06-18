# STRICT SENIOR-LEVEL REVIEW REPORT — OpenSOAR SOC Workflow
**Date:** 2026-05-17  
**Branch:** `17_mai`  
**Scope:** `/alerts` → `/incidents` → `/investigations` end-to-end  
**Reviewer:** Kimi Code CLI (read-only, no mutations)  

---

## A. EXECUTIVE VERDICT

**LOGIC MOSTLY CONSISTENT WITH WARNINGS**

The core state machine, action contract, safety tier system, and deterministic remediation planner are coherent and well-tested (172/172 tests pass). The controlled remediation end-to-end (baseline → execution → verification → rollback → post-rollback verification) has been proven on TEST-NET IPs.

However, **three critical bugs** break forensic reliability and data integrity:
1. Admin authentication is completely disabled (anyone can override, rollback, execute).
2. Audit events are silently dropped in most admin/action endpoints.
3. Truth reports read a non-existent DB column (`alert_snapshot`), making evidence-of-compromise checks silently fail.

Additionally, **plaintext credential exposure** on disk and **fragile verification string-matching** create operational security risks. The ARIA alerts router is empty (404), and the health check shows a degraded production state (80 stuck investigations, 123 failed playbook runs, 409 awaiting approval backlog).

**What is safe to demo:** `/alerts` list/detail, `/incidents` list/detail, `/investigations` list/detail, safety badge rendering, workflow stage display, deterministic playbook generation, action button visibility (safe-tier cases).

**What is risky:** Any admin action (soft override, rollback), execution on soft-block with override, truth report accuracy, fix verification precision, ES recurrence detection.

**What must be fixed next:** Admin auth, audit event persistence, truth report column fix, credential-at-rest sanitization, ARIA alerts router implementation.

---

## B. FILES REVIEWED

### Backend Routes
- `api/routes/alerts.py`
- `api/routes/incidents.py`
- `api/routes/investigations.py`
- `api/routes/aria_alerts.py`

### Backend Core
- `response/models.py`
- `response/workflow_summary.py`
- `response/playbook_safety.py`
- `response/remediation_planner.py`
- `response/ai_engine/main.py`
- `response/ai_engine/prompt_builder.py`
- `response/ai_engine/response_parser.py`
- `response/ansible_exec.py`
- `response/fix_verifier.py`
- `response/audit_events.py`
- `response/aria_alerts.py`

### Frontend
- `frontend/lib/api.ts`
- `frontend/components/status-badge.tsx`
- `frontend/app/(dashboard)/alerts/page.tsx`
- `frontend/app/(dashboard)/incidents/page.tsx`
- `frontend/app/(dashboard)/incidents/[id]/page.tsx`
- `frontend/app/(dashboard)/investigations/page.tsx`
- `frontend/app/(dashboard)/investigations/[id]/page.tsx`

### Tests & Health
- `tests/test_action_invariants.py`
- `tests/test_analyst_control.py`
- `tests/test_admin_override.py`
- `tests/test_safety_invariants.py`
- `tests/test_safety_tiers.py`
- `tests/test_deterministic_remediation.py`
- `tests/test_playbook_safety.py`
- `tests/test_execution_reliability.py`
- `tests/test_operational_readiness.py`
- `tests/test_controlled_remediation.py`
- `response/scripts/aria_health_check.py`

---

## C. FLOW MATRIX

| Step | Frontend File | Backend Endpoint/Service | Expected Behavior | Actual Behavior | Status | Evidence |
|------|---------------|--------------------------|-------------------|-----------------|--------|----------|
| 1. Real alert ingestion | N/A (pipeline) | `pipeline/poller/`, `pipeline/mappers/` | Alerts from Wazuh/Suricata/Falco/Filebeat normalized and stored | Wazuh alerts present; API probe shows only Wazuh in sample (`sources: ['wazuh']`) | **PARTIAL** | API probe: `total: 602, sources: ['wazuh']` — Falco/Suricata/Filebeat may be filtered or not ingested |
| 2. Alert list/detail | `alerts/page.tsx` | `GET /api/v1/alerts`, `GET /api/v1/alerts/{id}` | Real alert data with filters, IOCs, related incidents | Works. Falco excluded from list. Detail Sheet renders IOCs, related incidents, whitelist button | **PASS** | Frontend code: filters synced to URL, bulk select, create incident dialog |
| 3. Create/open incident | `alerts/page.tsx` | `POST /api/v1/incidents/manual` | Create incident from 1–100 alerts, link alerts, broadcast WS | Works. Falco alerts rejected. Upstream incident shell created without alert links | **PASS** | `incidents.py:180-317` |
| 4. Incident detail | `incidents/[id]/page.tsx` | `GET /api/v1/incidents/{id}` | Incident + linked alerts + investigations + timeline | Works. Four parallel SWR hooks. Launch button hidden if investigation exists | **PASS** | Frontend: `investigations.length === 0` gate |
| 5. Launch investigation | `incidents/page.tsx`, `incidents/[id]/page.tsx` | `POST /api/v1/investigations/manual` | Create investigation from incident, spawn AI engine | Works. Status becomes `pending`, AI engine runs background | **PASS** | `investigations.py:manual` endpoint |
| 6. Investigation detail | `investigations/[id]/page.tsx` | `GET /api/v1/investigations/{id}` | Full detail with safety, actions, workflow, truth report, evidence | Renders. **Truth report silently broken** due to `alert_snapshot` bug | **PARTIAL** | `_build_truth_report` accesses `a.alert_snapshot` (lines 348, 414) which does NOT exist on `InvestigationAlert` model |
| 7. Evidence display | `investigations/[id]/page.tsx` | `GET /api/v1/investigations/{id}/evidence-files` | Evidence cards, alert snapshots, file metadata | **Duplicate rendering bug**: alerts rendered twice unconditionally (lines ~1203 and ~1275) | **PARTIAL** | Code review: two unconditional `data.alerts && data.alerts.length > 0` blocks |
| 8. AI/truth report | `investigations/[id]/page.tsx` | `response/ai_engine/main.py` | LLM or deterministic plan with quality gates, grounding check | Deterministic planner works. Quality gates exist. Truth report broken (see step 6) | **PARTIAL** | `main.py:598` fires `alert_on_unsafe_playbook`; `_quality_gate_check` and `_ai_grounding_quality_check` present |
| 9. Remediation plan | `investigations/[id]/page.tsx` | `response/remediation_planner.py` | Deterministic playbooks for known scenarios, LLM fallback | Works. SSH brute-force, Suricata reputation, file quarantine builders tested | **PASS** | `tests/test_deterministic_remediation.py` all pass |
| 10. Safety tier | `investigations/[id]/page.tsx` | `response/playbook_safety.py` | `safe` / `soft_block` / `hard_block` with reasons | Works. All safety tests pass. Hard/soft block reasons accurate | **PASS** | `tests/test_safety_tiers.py`, `test_playbook_safety.py` pass |
| 11. Approval | `investigations/[id]/page.tsx` | `POST /api/v1/investigations/{id}/approve` | Analyst approves → creates approval record → **immediately executes** | By design: approve triggers execution via background task | **PASS** | `investigations.py:approve` spawns `execute_playbook` |
| 12. Admin decision approval | `investigations/[id]/page.tsx` | `POST /{id}/admin-decision-approve` | Decision-only approval, NO execution, status → `decision_approved` | Works correctly. No execution triggered. Requires reason ≥10 chars | **PASS** | Code review + previous fix verification |
| 13. Admin soft override | `investigations/[id]/page.tsx` | `POST /{id}/admin-soft-override` | Override soft block → `approved`, NO execution, requires confirm | Works correctly. No execution triggered. Requires `confirm_danger=True` | **PASS** | Code review |
| 14. Execution | `investigations/[id]/page.tsx` | `POST /{id}/execute`, `response/ansible_exec.py` | Re-checks safety, baseline capture, staged phases, WS broadcasts | Works. Baseline captured. Staged remediation proven. Safety re-checked at runtime | **PASS** | `tests/test_controlled_remediation.py` pass |
| 15. Verification | `investigations/[id]/page.tsx` | `response/fix_verifier.py` | ES recurrence + active state verification | **ES query ignores source IPs**. **String matching on Ansible output** instead of structured parsing | **PARTIAL** | `fix_verifier.py:234` extracts `source_ips` but never includes in `must_clauses`. `_verify_iptables_state` uses `source in output` |
| 16. Rollback | `investigations/[id]/page.tsx` | `POST /{id}/rollback`, `response/ansible_exec.py` | Validate rollback safety, execute, post-rollback verification | Works. Post-rollback verification checks iptables rule absence. End-to-end proven | **PASS** | `tests/test_action_invariants.py` prove rollback button contract |
| 17. Archive | `investigations/[id]/page.tsx` | `POST /{id}/archive`, `response/archiver.py` | Derive fix_status, create Archive row, update status | Works. Idempotent. Skips if already archived | **PASS** | Code review |

---

## D. PAGE REVIEW MATRIX

| Page | API Calls | Buttons/Actions | Loading/Error/Empty States | Navigation | UX Clarity | Status |
|------|-----------|-----------------|----------------------------|------------|------------|--------|
| `/alerts` | `alertsAPI.list`, `alertsAPI.get`, `incidentsAPI.createManual`, `whitelistAPI.create` | Filters, bulk select, Create Incident, Whitelist IP | Skeleton table, error card with retry, empty message | → `/incidents` (after creation), → `/search`, → `/incidents/{id}` | Good. Bulk select is page-only. Detail Sheet is clean. | **PASS** |
| `/incidents` | `incidentsAPI.list`, `investigationsAPI.createManual` | Filters, Launch, View | Skeleton, error card, empty message | → `/incidents/{id}`, → `/investigations/{id}` (after launch) | Good. Launch button hidden if investigation exists. | **PASS** |
| `/incidents/[id]` | `incidentsAPI.get`, `getAlerts`, `getTimeline`, `getInvestigations`, `update`, `whitelistAPI.create`, `investigationsAPI.createManual` | Launch Investigation, Assign, Whitelist IPs | Full-page spinner, per-tab spinners, error cards | → `/alerts`, → `/investigations/{id}` | Good. Four independent SWR hooks may drift. | **PASS** |
| `/investigations` | `investigationsAPI.list`, `getStats` | Filters, status overview cards, Review/View buttons | Skeleton, error card, pending approvals banner, empty message | → `/investigations/{id}`, → `/incidents/{id}` | Good. Status cards are clickable filters. 9 cards in `grid-cols-8` causes wrap. | **PASS** |
| `/investigations/[id]` | `investigationsAPI.get`, `getTimeline`, `getEvidenceFiles`, `getRunStatus`, `approve`, `decline`, `requestRegeneration`, `markReviewed`, `execute`, `adminDecisionApprove`, `adminSoftOverride`, `rollback`, `archive` | Conditional action bar driven by `analyst_actions`/`admin_actions` + 7 dialogs | Full-page spinner, action error banner, per-tab loading, playbook generation spinner | → `/incidents/{id}`, → `/alerts`, → `/search` | **PARTIAL** | Good safety banners and phase progress. **Duplicate alert evidence rendering**. **Hardcoded "admin" user**. **No abort controllers**. File is 1,956 lines (violates 500-line project guideline). |

---

## E. BACKEND CONTRACT MATRIX

| Endpoint | Method | Purpose | Response Fields | Frontend Match | Status |
|----------|--------|---------|-----------------|----------------|--------|
| `/api/v1/alerts` | GET | List alerts | `alerts[], total, limit, offset, source` | `alertsAPI.list` → `AlertListResponse` | **PASS** |
| `/api/v1/alerts/{id}` | GET | Alert detail | `data, relationships, actions` | `alertsAPI.get` → `AlertDetailResponse` | **PASS** |
| `/api/v1/incidents` | GET | List incidents | `incidents[], total, limit, offset, source` | `incidentsAPI.list` → `IncidentListResponse` | **PASS** |
| `/api/v1/incidents/{id}` | GET | Incident detail | `incident, alerts, investigations, timeline` | `incidentsAPI.get` → `IncidentDetailResponse` | **PASS** |
| `/api/v1/incidents/manual` | POST | Create incident | `incident, alerts` | `incidentsAPI.createManual` | **PASS** |
| `/api/v1/investigations` | GET | List investigations | `investigations[], total, offset, limit` | `investigationsAPI.list` → `InvestigationListResponse` | **PASS** |
| `/api/v1/investigations/stats` | GET | Status counts | `pending, awaiting_approval, approved, ...` | `investigationsAPI.getStats` → `InvestigationStats` | **PASS** |
| `/api/v1/investigations/{id}` | GET | Investigation detail | ~50 fields including `analyst_actions`, `admin_actions`, `workflow`, `truth_report`, `safety_tier` | `investigationsAPI.get` → `Investigation` (280-line type) | **PASS** |
| `/api/v1/investigations/{id}/approve` | POST | Approve + execute | `message, investigation_id, status` | `investigationsAPI.approve` | **PASS** |
| `/api/v1/investigations/{id}/admin-decision-approve` | POST | Decision-only approval | `message, investigation_id, status, safety_tier, executed` | `investigationsAPI.adminDecisionApprove` | **PASS** |
| `/api/v1/investigations/{id}/admin-soft-override` | POST | Override soft block | `message, investigation_id, status, safety_tier, override_reason, executed` | `investigationsAPI.adminSoftOverride` | **PASS** |
| `/api/v1/investigations/{id}/execute` | POST | Execute approved playbook | `message, investigation_id, status, run_id` | `investigationsAPI.execute` | **PASS** |
| `/api/v1/investigations/{id}/rollback` | POST | Rollback remediation | `message, investigation_id, status, rollback_result, post_rollback_verification` | `investigationsAPI.rollback` | **PASS** |
| `/api/v1/investigations/{id}/timeline` | GET | Timeline events | `events[], total` | `investigationsAPI.getTimeline` → `InvestigationTimeline` | **PASS** |
| `/api/v1/aria-alerts/stats` | GET | ARIA alert stats | **404 Not Found** | `ariaAlertsAPI.getStats` | **FAIL** |

---

## F. STATE/ACTION MATRIX

| Status | analyst_actions | admin_actions | Frontend Buttons | Expected Allowed Transitions | Issues Found |
|--------|-----------------|---------------|------------------|------------------------------|--------------|
| `pending` | `["decline"]` | `["decline", "admin_decision_approve"]` | Decline, Admin Approve | → `running`, `declined` | None |
| `awaiting_approval` | `["approve"]` (safe only), `["decline", "request_regeneration", "mark_reviewed", "edit_playbook"]` | +`["admin_decision_approve", "admin_soft_override"]` (if soft_block) | Approve, Decline, Regenerate, Mark Reviewed, Edit, Admin Approve, Admin Override | → `approved`, `declined`, `regeneration_requested`, `reviewed_no_action`, `decision_approved` | None |
| `approved` | `["execute"]` (safe only) | +`["archive"]` | Execute, Archive | → `running` | `archive` action shown but transition `approved → archived` is **BLOCKED** by state machine |
| `decision_approved` | `["archive", "request_regeneration", "mark_reviewed"]` | Same | Archive, Regenerate, Mark Reviewed | → `archived`, `regeneration_requested`, `reviewed_no_action`, `declined` | **Correct: NO execute button** |
| `running` | `[]` | `[]` | None | → `awaiting_approval`, `completed`, `completed_with_warnings`, `failed` | None |
| `completed` | `["archive"]` | +`["rollback"]` (if rollback_playbook) | Archive, Rollback | → `archived` | None |
| `completed_with_warnings` | `["archive"]` | +`["rollback"]` (if rollback_playbook) | Archive, Rollback | → `archived` | None |
| `failed` | `["archive", "request_regeneration"]` | +`["rollback"]` (if rollback_playbook) | Archive, Regenerate, Rollback | → `archived`, `approved`, `regeneration_requested`, `decision_approved` | None |
| `declined` | `["archive", "request_regeneration"]` | Same | Archive, Regenerate | → `archived`, `regeneration_requested` | None |
| `manual_review_required` | `["archive", "request_regeneration", "mark_reviewed"]` | +`["admin_decision_approve", "admin_soft_override"]` | Archive, Regenerate, Mark Reviewed, Admin Approve, Admin Override | → `declined`, `archived`, `regeneration_requested`, `reviewed_no_action`, `decision_approved`, `approved` | None |
| `regeneration_requested` | `["archive"]` | Same | Archive | → `pending`, `archived` | None |
| `reviewed_no_action` | `["archive"]` | Same | Archive | → `archived` | None |
| `archived` | `[]` | `[]` | None | (final) | None |

**Key Finding:** The action contract is consistent. `decision_approved` correctly has NO `execute`. `admin_decision_approve` correctly does NOT trigger execution. `soft_override` correctly does NOT trigger execution. All 14 action-invariant tests pass.

---

## G. BUGS / RISKS FOUND

### Critical

| # | Bug/Risk | Location | Why It Matters |
|---|----------|----------|----------------|
| G1 | **Admin auth completely disabled** | `api/routes/investigations.py:44-47` | `_validate_admin_access` returns `decided_by` without checking `X-ARIA-Admin-Secret` or any credential. Anyone can soft-override, rollback, or execute soft-block playbooks by passing `decided_by="admin"`. |
| G2 | **Audit events silently dropped** | `investigations.py` multiple endpoints | `record_audit_event` is called **after** `session.commit()` in `execute_playbook_direct`, `admin_decision_approve`, `admin_soft_override`, `mark_reviewed`, `request_regeneration`, `edit_playbook`. The event is added to an already-committed session and never flushed. Compliance trail is broken. |
| G3 | **Truth report reads non-existent DB column** | `investigations.py:348, 414` | `_has_evidence_of_compromise` and `_build_truth_report` access `a.alert_snapshot`, but `InvestigationAlert` model only has `alert_json`. These functions silently catch `AttributeError` and return empty/limited data. Evidence-of-compromise checks are non-functional. |
| G4 | **Plaintext credentials on disk** | `response/ansible_exec.py` | `_write_inventory()` writes `ansible_ssh_pass` and `ansible_become_pass` into inventory files under `/tmp/opensoar_playbooks/`. Readable by any process with `/tmp` access. No `chmod` or secure deletion. |
| G5 | **sshpass password exposed in shell command** | `response/ansible_exec.py` | `_test_ssh_connection()` uses `subprocess_shell` with `sshpass -p '{ssh_password}' ssh ...`. Password visible in `ps` and shell history. |

### High

| # | Bug/Risk | Location | Why It Matters |
|---|----------|----------|----------------|
| G6 | **ES recurrence query ignores source IPs** | `response/fix_verifier.py:234` | `_query_es_for_recurrence()` extracts `source_ips` from alert snapshots but never includes them in the ES `must_clauses`. An attacker changing IPs would evade detection while the verifier reports `likely_fixed`. |
| G7 | **Fragile string matching in verification** | `response/fix_verifier.py` | `_verify_iptables_state()` checks `source in output` — if the output contains the IP anywhere (error message, different rule), it passes. No structured JSON parsing of `ansible-playbook` results. |
| G8 | **Unsafe tar extraction** | `response/ansible_exec.py` | Evidence tarball extracted with `tar.extractall(path=local_evidence_dir)` without path sanitization. A malicious tarball with `../../../etc/cron.d/backdoor` could overwrite controller files. |
| G9 | **Container detection by string length** | `response/playbook_safety.py` | `is_container_target = len(target_host) == 12 and target_host.isalnum()`. Easily bypassed. A 13-char hostname is treated as VM; a Docker container with 64-char hex ID is ignored. |
| G10 | **Empty playbook = safe/executable** | `response/playbook_safety.py` | `validate_playbook_safety` returns `safe=True, executable=True` for empty/invalid playbooks. Empty playbooks bypass all safety gates. |
| G11 | **ARIA alerts router empty** | `api/routes/aria_alerts.py` | Router has zero endpoints. `GET /api/v1/aria-alerts/stats` returns 404. ARIA alerts exist in DB but are not queryable via API. |

### Medium

| # | Bug/Risk | Location | Why It Matters |
|---|----------|----------|----------------|
| G12 | **Stale PlaybookApproval reused** | `investigations.py:approve, decline, request-regeneration` | Old approval records are reused without clearing decision/override metadata. A previously declined investigation moved back to `awaiting_approval` (via `failed → approved`) would retain the old decline record until overwritten. |
| G13 | **Double-JSON encoding in soft override** | `investigations.py:admin_soft_override` | `original_blocked_reasons = _json.dumps(safety["blocked_reasons"])`. If the DB column is JSON type, this stores a JSON string instead of a native list. |
| G14 | **Archive action shown for `approved` but transition blocked** | `_compute_admin_actions` + `_ALLOWED_TRANSITIONS` | `approved` status shows `archive` button, but `_ALLOWED_TRANSITIONS["approved"]` only allows `running`. Clicking archive returns 400. |
| G15 | **Path validation performed locally, not remotely** | `response/remediation_planner.py` | `_validate_quarantine_path()` uses `Path.resolve()` on the local controller filesystem. A target-only symlink (`/app/config → /etc/passwd`) would pass because `/app/config` doesn't exist locally. |
| G16 | **No deduplication in ARIA alerts** | `response/aria_alerts.py` | Every call creates a new row. Retry loops could spam critical alerts. |
| G17 | **Health check degraded** | `aria_health_check.py` | 80 stuck investigations, 409 old awaiting approval, 123 failed playbook runs, 116 manual review required, 201 empty AI summaries. Production state is unhealthy. |
| G18 | **Frontend direct object mutation** | `frontend/alerts/page.tsx:691` | `alertDetail.data.whitelisted = true` mutates SWR cache directly instead of using `mutate()`. May not trigger React re-renders reliably. |
| G19 | **Duplicate alert evidence rendering** | `frontend/investigations/[id]/page.tsx` | Alert evidence rendered twice unconditionally in the Evidence tab. |
| G20 | **Playbook edit passes empty `alert_sources`** | `investigations.py:edit_playbook` | `investigation_context = { "alert_sources": [] }`. Source-aware safety rules cannot trigger during edit validation. |

### Low

| # | Bug/Risk | Location | Why It Matters |
|---|----------|----------|----------------|
| G21 | **WebSocket broadcasts use hardcoded old status** | `investigations.py:approve, decline` | `broadcast_investigation_change` is called with hardcoded `"awaiting_approval"` as old_status even if transition came from `failed`. |
| G22 | **Investigation detail page 1,956 lines** | `frontend/investigations/[id]/page.tsx` | Violates project's own 500-line guideline. Maintenance burden is extreme. |
| G23 | **No abort controllers on async actions** | `frontend/investigations/[id]/page.tsx` | Navigating away during an action leaves the async call dangling. No cleanup. |
| G24 | **Hardcoded "admin" user** | `frontend/investigations/[id]/page.tsx` | All actions pass `"admin"` as `decidedBy`. No session context. |
| G25 | **Memory leak in manual investigation locks** | `investigations.py:create_manual_investigation` | `_investigation_locks` dict stored on function object, never evicted. |
| G26 | **Prompt has no length ceiling** | `response/ai_engine/prompt_builder.py` | Large incidents with thousands of alerts could exceed LLM context limits. |

---

## H. NO-CODE-CHANGE RECOMMENDATIONS

### H1. Fix admin authentication (Critical)
- **File:** `api/routes/investigations.py`
- **Problem:** `_validate_admin_access` is a no-op pass-through.
- **Why it matters:** Anyone with network access can execute soft-block overrides and rollbacks.
- **Suggested fix:** Implement actual secret validation against `settings.admin_secret` or integrate with the deferred auth system. Return 403 on mismatch.
- **Test:** `tests/test_admin_override.py` should include a test that passes wrong secret and expects 403.

### H2. Fix audit event persistence (Critical)
- **File:** `api/routes/investigations.py`
- **Problem:** `record_audit_event` is called after `session.commit()` in multiple endpoints.
- **Why it matters:** Compliance/forensic trail is silently lost for admin actions.
- **Suggested fix:** Either (a) move `record_audit_event` before `session.commit()`, or (b) add `await session.commit()` inside `record_audit_event`, or (c) use a separate session for audit events.
- **Test:** Add a test that calls `admin_decision_approve`, then queries `audit_events` table and asserts count increased.

### H3. Fix truth report column reference (Critical)
- **File:** `api/routes/investigations.py`
- **Problem:** `_has_evidence_of_compromise` and `_build_truth_report` access `a.alert_snapshot` which does not exist.
- **Why it matters:** Evidence-of-compromise checks are silently non-functional. SSH brute-force vs compromise classification is broken.
- **Suggested fix:** Replace `a.alert_snapshot` with `a.alert_json` everywhere in these two functions.
- **Test:** Create a test investigation with an alert containing `"successful_login": true` in `alert_json`, assert `_has_evidence_of_compromise` returns `True`.

### H4. Sanitize credentials at rest (Critical)
- **File:** `response/ansible_exec.py`
- **Problem:** Inventory files contain plaintext passwords in `/tmp/`.
- **Why it matters:** Any process on the host can read SSH/become passwords.
- **Suggested fix:** Write inventory with `mode=0o600`, use `ansible-vault encrypt_string` for passwords, or pass credentials via environment variables instead of inventory files.
- **Test:** Inspect generated inventory file permissions; assert `stat.S_IMODE(mode) == 0o600`.

### H5. Remove sshpass from shell command string (Critical)
- **File:** `response/ansible_exec.py`
- **Problem:** `sshpass -p '{password}' ssh ...` exposes password in process listings.
- **Why it matters:** Password visible to any user running `ps`.
- **Suggested fix:** Use `sshpass` with `SSHPASS` environment variable: `env={'SSHPASS': password}`.
- **Test:** Mock `create_subprocess_shell`, capture command string, assert password not in command.

### H6. Fix ES recurrence query to include source IPs (High)
- **File:** `response/fix_verifier.py`
- **Problem:** `_query_es_for_recurrence` extracts `source_ips` but never adds them to `must_clauses`.
- **Why it matters:** Verification can falsely report `likely_fixed` when the attacker simply changed source IP.
- **Suggested fix:** Add `"terms": {"source_ip": source_ips}` to `must_clauses` when `source_ips` is non-empty.
- **Test:** Mock ES client, call `verify_fix` with `source_ips=["1.2.3.4"]`, assert ES query contains `source_ip` filter.

### H7. Use structured Ansible output for verification (High)
- **File:** `response/fix_verifier.py`
- **Problem:** String matching on `ansible-playbook` stdout is brittle.
- **Why it matters:** False positives/negatives in fix verification.
- **Suggested fix:** Run verification with `ansible-playbook --json` or parse registered variables from JSON output.
- **Test:** Provide stdout that contains the IP in an error message; assert verification returns `not_fixed` or `inconclusive`.

### H8. Implement ARIA alerts API router (High)
- **File:** `api/routes/aria_alerts.py`
- **Problem:** Router is completely empty.
- **Why it matters:** ARIA alerts are written to DB but cannot be queried by frontend or operators.
- **Suggested fix:** Add `GET /stats`, `GET /`, `PATCH /{id}/acknowledge` endpoints.
- **Test:** Create an ARIA alert, query `/api/v1/aria-alerts/stats`, assert count > 0.

### H9. Fix archive action for approved status (Medium)
- **File:** `api/routes/investigations.py`
- **Problem:** `_compute_admin_actions` returns `archive` for `approved`, but state machine blocks `approved → archived`.
- **Why it matters:** Confusing UX — button exists but always fails.
- **Suggested fix:** Either remove `archive` from `approved` actions, or add `archived` to `_ALLOWED_TRANSITIONS["approved"]`.
- **Test:** `test_action_invariants.py` should assert that every action in `admin_actions` corresponds to an allowed transition.

### H10. Fix duplicate alert evidence rendering (Medium)
- **File:** `frontend/app/(dashboard)/investigations/[id]/page.tsx`
- **Problem:** Alert evidence rendered twice in Evidence tab.
- **Why it matters:** Wasted screen space, confusing UX.
- **Suggested fix:** Remove the second unconditional `data.alerts` block.
- **Test:** Visual regression or DOM assertion that alerts appear exactly once.

### H11. Harden tar extraction (Medium)
- **File:** `response/ansible_exec.py`
- **Problem:** `tar.extractall()` without path sanitization.
- **Why it matters:** Path traversal from malicious remote tarball.
- **Suggested fix:** Use `tarfile` with member validation: reject members with `..` or absolute paths.
- **Test:** Create a tarball with `../../../tmp/pwned`, assert extraction raises `ValueError`.

### H12. Improve container detection (Medium)
- **File:** `response/playbook_safety.py`
- **Problem:** `len(target_host) == 12 and target_host.isalnum()` is trivially bypassed.
- **Why it matters:** False negatives for container safety blocks.
- **Suggested fix:** Use a container hint list (e.g., `target_host` in known container inventory, or check `container.runtime` context field).
- **Test:** Pass a 64-char hex container ID; assert safety rules still apply.

---

## I. COMMANDS RUN AND EXACT RESULTS

### Backend Compilation
```bash
python3 -m py_compile api/routes/alerts.py api/routes/incidents.py \
  api/routes/investigations.py response/workflow_summary.py \
  response/playbook_safety.py response/remediation_planner.py \
  response/ansible_exec.py response/fix_verifier.py \
  response/aria_alerts.py response/audit_events.py response/models.py
```
**Result:** All files compile successfully (exit 0).

### Pytest SOC Core Suite
```bash
pytest tests/test_action_invariants.py tests/test_analyst_control.py \
  tests/test_admin_override.py tests/test_safety_invariants.py \
  tests/test_safety_tiers.py tests/test_deterministic_remediation.py \
  tests/test_playbook_safety.py tests/test_execution_reliability.py \
  tests/test_operational_readiness.py tests/test_controlled_remediation.py -v
```
**Result:** `172 passed in 5.30s`

### Frontend Build
```bash
cd frontend && pnpm build
```
**Result:** Build succeeds, no errors.

### Frontend TypeScript
```bash
cd frontend && pnpm exec tsc --noEmit
```
**Result:** 23 errors total, **0 errors in SOC pages** (`alerts`, `incidents`, `investigations`). All 23 errors are in non-SOC modules (`infrastructure`, `ips`, `metrics`, `runtime`, `operator`).

### API Read-Only Probes
```bash
curl http://127.0.0.1:8001/api/v1/alerts?limit=2
# → total: 602, sources: ['wazuh']

curl http://127.0.0.1:8001/api/v1/incidents?limit=2
# → total: 323, statuses: ['open']

curl http://127.0.0.1:8001/api/v1/investigations?limit=2
# → total: 486, statuses: ['awaiting_approval', 'decision_approved']

curl http://127.0.0.1:8001/api/v1/investigations/stats
# → pending:1, awaiting_approval:259, approved:0, decision_approved:10,
#   declined:0, running:0, completed:2, completed_with_warnings:0,
#   failed:138, archived:11, manual_review_required:64,
#   regeneration_requested:0, reviewed_no_action:1, total:486

curl http://127.0.0.1:8001/api/v1/aria-alerts/stats
# → {"detail":"Not Found"}
```

### Health Check
```bash
python3 response/scripts/aria_health_check.py
```
**Result:** `Overall status: DEGRADED`
- OK: 23, WARNING: 7, CRITICAL: 0
- Stuck investigations: 80
- Old awaiting approval: 409
- Manual review required: 116
- Failed investigations: 172
- Empty AI summaries: 201
- Failed playbook runs: 123
- Smoke: safe remediation blocked (AI summary empty)

---

## J. FINAL RECOMMENDATION

### What is safe to demo
- **Alert list/detail (`/alerts`)**: Real Wazuh data, filters work, incident creation flows correctly.
- **Incident list/detail (`/incidents`)**: Real incidents, launch investigation works, timeline renders.
- **Investigation list (`/investigations`)**: Status cards, filters, safety badges render correctly.
- **Investigation detail (`/investigations/[id]`) for SAFE tier**: Workflow stages, playbook review, approval → execution → completion flow is coherent.
- **Safety system**: Hard/soft block detection is accurate and well-tested. Deterministic remediation planner works for SSH brute-force and Suricata reputation cases.
- **Rollback workflow**: End-to-end proven on TEST-NET IPs. Action contract tests (14/14) pass.

### What is risky
- **Admin actions**: Authentication is disabled. Do not demo soft override or rollback in front of stakeholders without explaining this is a known temporary measure.
- **Truth report**: Evidence-of-compromise classification is silently broken. The report may misclassify SSH brute-force as compromise or vice versa.
- **Fix verification**: ES recurrence query ignores source IPs. Active verification uses string matching on stdout. A false `likely_fixed` is possible.
- **Credential exposure**: Inventory files with plaintext passwords exist on disk. Do not expose `/tmp/opensoar_playbooks/` to untrusted users.
- **ARIA alerts**: Written to DB but not queryable. Operators cannot see critical workflow anomalies via API.

### What must be fixed next (priority order)
1. **Admin authentication** (`_validate_admin_access`) — security regression
2. **Audit event persistence** — compliance/forensic requirement
3. **Truth report `alert_snapshot` → `alert_json` fix** — data integrity
4. **Credential sanitization** (`ansible_exec.py` inventory + sshpass) — operational security
5. **ES recurrence query source IP inclusion** — verification accuracy
6. **ARIA alerts API endpoints** — operator visibility
7. **Duplicate alert evidence rendering** — UX polish
8. **Archive button for approved status** — remove or allow transition

### End-to-end coherence verdict
`/alerts`, `/incidents`, and `/investigations` are **coherent end-to-end** for the happy path (safe tier → approve → execute → complete → archive). The state machine is sound, the action contract is proven by tests, and the frontend correctly reflects backend capabilities.

The workflow breaks down in three areas:
1. **Security boundaries** (auth disabled, credentials exposed)
2. **Data integrity** (audit events lost, truth reports broken)
3. **Verification accuracy** (ES query incomplete, string matching fragile)

These are fixable without architectural changes. The foundation is solid.
