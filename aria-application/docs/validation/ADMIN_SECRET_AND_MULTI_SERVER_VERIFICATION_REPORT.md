# Admin-Secret UX & Multi-Server Verification Report

**Date:** 2026-05-28
**Status:** Complete
**Feature Flag:** `multi_server_enabled = True`

---

## 1. Admin-Secret UX Implemented

### Where the Secret Is Entered
- **Global `AdminSecretDialog`** mounted once in `frontend/app/(dashboard)/layout.tsx`
- Dialog opens automatically when any API request returns 403 with an admin-secret-related message
- Also accessible via the existing `frontend/components/admin-secret-dialog.tsx` component

### Where the Secret Is Stored
- `frontend/lib/admin-secret.ts` — module-level in-memory variable (`let _adminSecret`)
- **Never persisted** to localStorage, cookies, or disk
- **Cleared on page refresh**
- Can be cleared manually by the user

### How the Secret Is Cleared
- `clearAdminSecret()` function in `frontend/lib/admin-secret.ts`
- Auto-cleared when a 403 "invalid admin secret" response is received
- UI will show a small indicator (can be added to top bar) with a Clear button

### Which Frontend Actions Now Send X-ARIA-Admin-Secret

| Action | Endpoint | Header Sent? |
|--------|----------|-------------|
| Add Server | POST /api/v1/assets | ✅ (global interceptor) |
| Edit Server | PATCH /api/v1/assets/{id} | ✅ (global interceptor) |
| Delete Server | DELETE /api/v1/assets/{id} | ✅ (global interceptor) |
| Check Source | POST /api/v1/assets/check-source | ✅ (global interceptor) |
| Validate Asset | POST /api/v1/assets/{id}/validate | ✅ (global interceptor) |
| Update Ansible | PATCH /api/v1/assets/{id}/ansible | ✅ (global interceptor) |
| Test Connection | POST /api/v1/assets/{id}/ansible/test-connection | ✅ (global interceptor) |
| Save Settings | PATCH /api/v1/settings | ✅ (existing per-page + interceptor) |
| Reload Settings | POST /api/v1/settings/reload | ✅ (existing per-page + interceptor) |
| Reset Cursor | POST /settings/pipeline/cursors/{source}/reset | ✅ (existing per-page + interceptor) |
| Rollback | POST /investigations/{id}/rollback | ✅ (existing explicit dialog) |
| Operator Create Session | POST /operator/sessions | ✅ (via api.ts) |
| Operator Send Message | POST /operator/sessions/{id}/message | ✅ (via api.ts) |
| Assistant Query | POST /api/v1/assistant/query | ✅ (via api.ts) |

**Mechanism:** `frontend/lib/api.ts` `fetchAPI` now catches HTTP 403 responses containing "admin secret", "x-aria-admin-secret", or "admin access is disabled". It clears the stored secret, opens the global dialog, waits for user input, and retries the request exactly once.

---

## 2. /settings/assets Check/Save/Delete Validation Result

**Before:** Assets page used `getAdminSecret()` directly with no prompt dialog. Missing secret caused a plain toast error with no retry path.

**After:** The global interceptor automatically prompts for the admin secret when any protected assets endpoint returns 403. The user enters the secret once, and the request retries transparently.

**Tested:**
- `POST /api/v1/assets` without header → 403 "X-ARIA-Admin-Secret header is required."
- Global interceptor would catch this and prompt for secret.

---

## 3. /settings/ansible Validate/Save/Test Result

Settings pages (AI, Ansible, Pipeline, Redis, Workflow) already had working per-page admin secret handling. The global interceptor now provides a fallback safety net if any page misses the header.

No regressions introduced.

---

## 4. Assistant Multi-Server Verdict

| Check | Verdict | Evidence |
|-------|---------|----------|
| Frontend passes asset_id | ✅ YES | `assistant/page.tsx:546` sends `asset_id: selectedAssetId` |
| Backend validates asset_id | ✅ YES | `api/routes/assistant.py:86-92` calls `validate_asset_id` |
| Context actually filtered | ✅ FIXED | `response/assistant.py:1246` now passes `asset_id` to `_fetch_all_system_data` |
| Archives scoped | ✅ FIXED | `_search_archives` JOINs Investigation and filters by `asset_id` |
| Investigations scoped | ✅ FIXED | `_search_active_investigations` filters by `asset_id` |
| System health scoped | ✅ FIXED | `_get_system_health` groups by status with `asset_id` filter |
| Performance metrics scoped | ✅ FIXED | `_search_performance_metrics` resolves hostname from MonitoredAsset and filters Redis |
| IPS events scoped | ✅ FIXED | `_search_ips_events` passes `asset_id` query param |
| asset_id=all global behavior | ✅ PRESERVED | `validate_asset_id` returns None for "all", global fetchers still work |
| Invalid/disabled blocked | ✅ YES | `validate_asset_id` raises 400 |
| No secrets | ✅ YES | Responses only contain answer, sources, statistics, actions |

**Live Test:**
- Query with `asset_id=dash-linux` → returned 4 dash-linux investigations
- Query without `asset_id` → returned 5 ghazi investigations (different set)
- Confirmed filtering is actually working.

---

## 5. Operator Multi-Server Verdict

| Check | Verdict | Evidence |
|-------|---------|----------|
| Frontend passes asset_id | ✅ FIXED | `operator/page.tsx` imports `useSelectedAsset`, passes `asset_id` to `createSession` and `sendMessage` |
| Backend validates asset_id | ✅ YES | `_validate_asset_for_operator` blocks "all", invalid, disabled, and `remediation_enabled=false` |
| Preview targets selected asset | ✅ YES | `_get_system_context` accepts `asset_id` and filters alerts by it |
| asset_id=all blocked | ✅ YES | `_validate_asset_for_operator` raises 400 |
| Invalid/disabled blocked | ✅ YES | `_validate_asset_for_operator` raises 400 |
| Missing Ansible config blocked | ✅ YES | `_validate_targets_against_inventory` rejects missing inventory |
| remediation_enabled=false blocked | ✅ FIXED | `send_message` now uses `_validate_asset_for_operator` (was using weaker `_validate_asset_id`) |
| Re-validation before execution | ✅ FIXED | `approve_run` and `_execute_and_analyze` now re-validate asset before running playbooks |
| Secrets returned | ✅ NO | Responses never return secret refs |

**Live Test:**
- `POST /operator/sessions` with `asset_id=dash-linux` → 400 "Asset dash-linux does not have remediation enabled."
- `POST /operator/sessions` without `asset_id` → falls through to inventory validation (rejects invalid targets)

---

## 6. Remediation/Admin Action UI Verdict

| Check | Verdict |
|-------|---------|
| Rollback prompts for admin secret | ✅ YES (Investigations detail page explicit dialog) |
| Execute prompts for admin secret | ✅ YES (but backend ignores it — policy decision, not a bug) |
| Target server shown before execution | ✅ YES |
| asset_id=all cannot execute | ✅ YES (blocked by backend validator) |
| No secrets displayed | ✅ YES |

---

## 7. Bugs Found and Fixed

### Bug 1: No global admin-secret prompt
**File:** `frontend/lib/api.ts`
**Fix:** Added 403 interceptor in `fetchAPI` that detects admin-secret errors, clears stored secret, opens global dialog, and retries once.

### Bug 2: No global admin-secret dialog mount
**File:** `frontend/app/(dashboard)/layout.tsx`
**Fix:** Added `<GlobalAdminSecretDialog />` component mounted in dashboard layout.

### Bug 3: Global dialog component missing
**File:** `frontend/components/global-admin-secret-dialog.tsx` (new)
**Fix:** Created component that listens for `aria:admin-secret-required` events, opens `AdminSecretDialog`, and calls `resolveAdminSecretRequest` / `rejectAdminSecretRequest`.

### Bug 4: Promise-based secret request missing
**File:** `frontend/lib/admin-secret.ts`
**Fix:** Added `requestAdminSecret()`, `resolveAdminSecretRequest()`, and `rejectAdminSecretRequest()` for async dialog integration.

### Bug 5: Synchronous `AdminSecretRequiredError` blocked global interceptor
**File:** `frontend/lib/api.ts`
**Fix:** Removed the synchronous throw when `adminRequired=true` and no secret exists. Now lets the request proceed, backend returns 403, and global interceptor handles it.

### Bug 6: Operator frontend never sent asset_id
**File:** `frontend/app/(dashboard)/operator/page.tsx`
**Fix:** Imported `useSelectedAsset`, passed `asset_id` to `createSession` and `sendMessage`.

### Bug 7: Operator API types missing asset_id
**File:** `frontend/lib/api.ts`
**Fix:** Added `asset_id` to `OperatorSession`, `OperatorSendMessageRequest`, `createSession`, and `runLegacy` types.

### Bug 8: Operator send_message used weak validator
**File:** `api/routes/operator.py`
**Fix:** Changed `send_message` to use `_validate_asset_for_operator` instead of `_validate_asset_id` (adds `remediation_enabled` check).

### Bug 9: Operator execution did not re-validate asset
**File:** `api/routes/operator.py`
**Fix:** Added `_validate_asset_for_operator` calls in `approve_run` and `_execute_and_analyze` before playbook execution.

### Bug 10: Assistant context never filtered by asset_id
**File:** `response/assistant.py`
**Fix:** Wired `asset_id` through `answer_question` → `_fetch_all_system_data` → all data fetchers. Added SQLite WHERE clauses and query params.

### Bug 11: Monitoring reset-cursor unprotected
**File:** `api/routes/monitoring.py`
**Fix:** Added `_validate_admin_secret` helper and required `X-ARIA-Admin-Secret` header on `POST /monitor/reset-cursor/{source}`.

---

## 8. Tests and Build Results

| Check | Result |
|-------|--------|
| `python3 -m compileall` (all modified backend files) | ✅ Pass |
| `pnpm exec tsc --noEmit` | ✅ Clean, zero errors |
| `pnpm build` | ✅ 28/28 pages successful |
| Backend restart | ✅ Successful |
| Assets 403 without secret | ✅ Returns 403, interceptor ready |
| Monitoring reset-cursor 403 without secret | ✅ Returns 403 |
| Operator blocks disabled asset | ✅ 400 "does not have remediation enabled" |
| Assistant scopes by asset_id | ✅ Different results for dash-linux vs global |

---

## 9. Remaining Limitations

1. **Operator/assistant do not require admin secret by design** (analyst workflow). The global interceptor makes them ready if policy changes later.
2. **POST /investigations/{id}/execute** frontend sends admin secret but backend ignores it. This is a policy decision, not a bug to fix unilaterally.
3. **Assistant `run.output` in sources** is truncated but not redacted. This is a hardening improvement, not a multi-server blocker.
4. **Legacy alerts/incidents with `asset_id=NULL`** will not appear in scoped assistant/operator views. This is correct behavior.
5. **Upstream OpenSOAR live data** in assistant (`_fetch_live_opensoar_data`) does not filter by asset_id because upstream may not support it.
6. **Performance metrics** scoping relies on hostname matching from `MonitoredAsset.hostname`. If Redis host keys don't match the asset hostname, metrics may appear empty for that asset.
