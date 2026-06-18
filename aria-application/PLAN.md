# IPS Overhaul — Remaining Work Plan

## Context
First batch of parallel subagents completed 5 out of 7 change sets. Two critical files still need work:
1. `api/routes/ips.py` (backend IPS API)
2. `frontend/app/(dashboard)/ips/page.tsx` (frontend attack map)

## Goal
Finish the overhaul without breaking the attack map. The previous attempt failed because filtering out paths with missing destination coordinates on the backend eliminated most events. The fix is: backend includes all paths with valid source coordinates; frontend conditionally renders arcs/destinations only when destination coordinates exist, but always renders source markers.

---

## Phase A: Backend IPS API (`api/routes/ips.py`)

### A1. Attack Categories
**Current:** `category = alert.get("source", "Unknown")` — shows "wazuh", "suricata", "falco"
**Fix:** Derive category with priority:
1. `alert.get("metadata", {}).get("category")` (Suricata ET category)
2. `alert.get("category")` (mapped operational category)
3. Pattern-match on `alert.get("title")` or `alert.get("rule_name")`
4. Fallback to `alert.get("source")` only as last resort

### A2. Local Events Missing Metadata
**Current:** `_get_local_events()` reads Alert table but doesn't extract `protocol`, `source_port`, `dest_port`, `signature_id` from `alert_metadata` JSON blob.
**Fix:** Extract these fields from `metadata` dict when building `alert_dict`.

### A3. Remove Fake Destination Defaults
**Current:**
- `dest_ip = alert.get("dest_ip") or "10.175.1.137"` (hardcoded private IP)
- Destination coordinates fall back to Tunis, Tunisia (36.8065, 10.1815)
- `city` falls back to "Tunis", `country_name` to "Tunisia"

**Fix:**
- `dest_ip = alert.get("dest_ip")` — no fallback
- When `target_geo` is None: `lat: None, lon: None, country: "XX", country_name: "Unknown", city: ""`
- Same fixes for `receive_attack_event()` (manual event endpoint)

### A4. Remove Event Caps
**Current:** Live events endpoint defaults to `limit=50` (max 100)
**Fix:** Change to `limit=100` (max 200). Add `total_before_limit` count to response.

### A5. Map Data MUST Include Missing Destinations
**Current:** Already only checks source coordinates. **Do NOT add destination coordinate check.** Events with valid source coords but `null` destination coords must stay in `paths`.

---

## Phase B: Frontend Attack Map (`frontend/app/(dashboard)/ips/page.tsx`)

### B1. Remove Hardcoded Tunis Marker
**Current:** `<AnimatedMarker coordinates={[TUNIS_LON, TUNIS_LAT]} ... />` renders regardless of data.
**Fix:** Remove the static Tunis marker. Destination markers must come from actual `path.to` coordinates per event.

### B2. Separate Lifecycle Rendering
**Current:** All `active` and `investigating` paths spawn the same looping `AnimatedAttackPath`. `mitigated`/`blocked` show dashed lines.
**Fix:**
- `active` → `AnimatedAttackPath` with `loop={true}` (continuous looping arc), red
- `investigating` → static SOLID orange line (new `InvestigatingPath` component)
- `mitigated` → static DASHED green line
- `blocked` → static DASHED purple line

### B3. Handle Null Destination Coordinates Safely
**Current:** No null checks before passing to `<Line>` or destination `<Marker>`. Previous failure was caused by backend filtering out null-dest events.
**Fix:**
- Create helper: `hasDest(p) = p.to.lat != null && p.to.lon != null && !isNaN(...)`
- Filter paths by `hasDest` BEFORE passing to `<Line>` or destination `<Marker>`
- Source markers use the ORIGINAL unfiltered arrays (all paths with valid source coords get a source marker)
- Sporadic attack animation (`activeAttacks`) must only spawn from `activePaths.filter(hasDest)`

### B4. Remove 15-Path Cap
**Current:** `filteredPaths.slice(0, 15)`
**Fix:** Remove `.slice(0, 15)` entirely.

### B5. Wire Up `newEventIds` Highlighting
**Current:** `newEventIds` state is initialized as `Set<string>` but never populated.
**Fix:**
- Use `useRef` to track previous live event IDs
- On `liveEvents` update, detect new IDs and add to `newEventIds`
- `setTimeout(5000)` to remove them
- Table already has CSS animation class conditional on `newEventIds.has(event.event_id)`

### B6. Map Data Request Limit
**Current:** `ipsAPI.getMapData({ limit: 50, ... })`
**Fix:** Change to `limit: 100`

---

## Phase C: Verification

1. `python3 -m py_compile api/routes/ips.py` — syntax check
2. `cd frontend && npx tsc --noEmit` — TypeScript check
3. Refresh `http://localhost:3000/ips` — confirm map renders with source markers
4. Check arcs/lines render correctly for paths with valid destinations
5. Verify source-only events show markers without crashing

---

## Execution Strategy
- Launch **2 parallel subagents**: one for Phase A (backend), one for Phase B (frontend)
- Both receive the Phase C verification checklist as a post-change requirement
- After both complete, run verification manually
