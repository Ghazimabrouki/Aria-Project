# ARIA Frontend & Backend Improvement Plan

## Phase 1: Critical Backend Bugs (Must Fix First)

### 1.1 Archive Statistics Fix
**File:** `api/routes/archives.py:234`
**Bug:** Success rate only counts `likely_fixed`, ignoring `verified` and `archived_fixed`.
**Fix:** Update `archive_stats()` to count all successful statuses:
```python
successful_statuses = {"likely_fixed", "verified", "archived_fixed"}
fixed = sum(fix_counts.get(s, 0) for s in successful_statuses)
```

### 1.2 Runtime Archives Missing from Table
**File:** `api/routes/runtime.py:1155-1185`
**Bug:** Runtime archive endpoint updates investigation status but never calls `archive_investigation()`.
**Fix:** Call `archive_investigation()` at the end of the runtime archive endpoint.

### 1.3 Non-Runtime Investigation Status Bug
**File:** `response/fix_verifier.py:193-198`
**Bug:** Non-runtime investigations always marked `completed` regardless of fix outcome.
**Fix:** Map verification status to investigation status properly:
- `likely_fixed` / `verified` → `completed`
- `not_fixed` / `playbook_failed_problem_worse` → `completed_with_warnings`
- `inconclusive` → `completed_with_warnings`
- `playbook_failed_but_quiet` → `failed`

### 1.4 Operator Session Asset Bug
**File:** `api/routes/operator.py`
**Bug:** `create_session()` calls `.ansible_config_json` on a string returned by `_validate_asset_id()`.
**Fix:** Query the actual `MonitoredAsset` object or fix the return type.

### 1.5 IPS Filters NameError
**File:** `api/routes/ips.py`
**Bug:** `get_available_filters()` references undefined `asset_id` variable.
**Fix:** Remove or properly pass the asset_id parameter.

### 1.6 Verification Per-Asset Credentials
**File:** `response/fix_verifier.py:1100-1125`
**Bug:** Verification ignores per-asset credentials.
**Fix:** Load asset-specific Ansible config before running verification playbook.

## Phase 2: Frontend Quick Fixes (Independent)

### 2.1 IPS Page
- Remove read-only banner (lines ~1269-1283)
- Fix dynamic Tailwind classes in `StatSummaryCard`
- Add proper empty state for map
- Use `ErrorState` component for errors
- Improve loading state

### 2.2 Alerts Page
- Remove description text from PageHeader
- Fix SWR direct mutation bug
- Extract IOCs panel to component
- Use `ErrorState` in detail sheet

### 2.3 Incidents Page
- Remove Assignee column
- Clean table layout
- Rename "Launch" to "Investigate"

## Phase 3: Major Frontend Redesigns

### 3.1 Operator Page
- Replace manual fetch with API client
- Add rollback display in ResultCard
- Add session delete confirmation
- Show message timestamps
- Extract AssetReadinessBanner
- Improve layout and spacing

### 3.2 Assistant Page
- Add real markdown rendering (react-markdown)
- Remove dead code
- Add input limit warning
- Fix sidebar toggle positioning
- Add source card click navigation
- Fix confirmation dialog styling

### 3.3 Archives Page
- Extract shared `FixStatusBadge` component
- Add time filter and search
- Use `ErrorState` component
- Add severity distribution stat
- Show avg resolution time

### 3.4 Archive Detail Page
- Full redesign with clear sections:
  - Header (title, severity, status, date, counts, IPs, host, country)
  - Executive Summary
  - Timeline
  - Evidence
  - AI Analysis
  - Remediation
  - Verification (structured, not raw text)
  - Linked Objects
- Add syntax highlighting to playbook
- Replace alerts cards with DataTable or add pagination
- Extract shared `FixStatusBadge`

## Phase 4: PDF Report Generation

### 4.1 Backend PDF Endpoint
**New file:** `api/routes/reports.py`
- Use `reportlab` or `weasyprint` to generate PDFs
- Accept `archive_id` parameter
- Include all archive detail sections

### 4.2 Frontend Integration
- Add "Download PDF Report" button to archive detail
- Show loading state during generation

## Phase 5: Verification Result Formatting

### 5.1 Backend Structured Verification
**File:** `response/fix_verifier.py`
- Return structured verification object instead of raw text
- Fields: check_type, what_was_checked, time_window, query_summary, new_duplicates_found, state_verification_result, firewall_rule_result, final_interpretation

### 5.2 Frontend Display
- Display structured fields in cards/tables
- Put raw details in expandable "Raw details" section

## Phase 6: QA Testing

### 6.1 Test Each Page
- Verify no console errors
- Verify responsive behavior
- Verify data correctness
- Verify navigation

### 6.2 Test Backend Fixes
- Verify archive stats are correct
- Verify runtime archives appear in table
- Verify verification statuses are accurate
- Verify operator session creation works

### 6.3 Test PDF Generation
- Verify PDF downloads correctly
- Verify PDF content is complete
