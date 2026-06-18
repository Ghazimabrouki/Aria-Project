# Runtime Remediation Safe Demo Runbook

## What This Is

A **safe, local-only demonstration** of the `/runtime/investigations/` remediation flow. It creates a controlled demo investigation with real corrective actions that only touch temporary files under `/tmp/opensoar_runtime_demo/`.

**No system files are modified.** No services, packages, iptables rules, `/etc` files, or credentials are touched.

---

## What Remediation Means

In OpenSOAR, **remediation** means executing an Ansible playbook to fix a confirmed security issue:

1. **Diagnostic phase** — collect evidence about what happened
2. **Planner phase** — decide if a safe, evidence-backed corrective action exists
3. **Approval gate** — human analyst must approve before execution
4. **Execution phase** — Ansible playbook runs on the target host
5. **Verification phase** — re-query Elasticsearch to confirm the fix worked
6. **Rollback phase** — exact undo steps are included in the playbook for safety

Remediation is **only generated when**:
- The planner finds a concrete, safe corrective action
- A trusted baseline exists (for restores)
- The target context is validated (host vs container vs Kubernetes)
- Evidence gaps are minimal

---

## Why Most Real Cases Are Observe / Manual Review

The current production dataset (447 runtime investigations) contains **zero** cases with `corrective_actions > 0`. This is expected because:

1. **Falco detects many administrative activities** as "suspicious" that are actually expected (package installs, service restarts, file edits by admins).
2. **Container safety rules** block host-scoped remediation for container events until namespace validation is done.
3. **Missing baselines** prevent automatic file restores when no known-good reference exists.
4. **Conservative planner** — the system prioritizes evidence and safety over action. "Do no harm" is the default.

The demo exists so operators can **see and understand** the full remediation flow without waiting for a rare real-world case.

---

## How to Run the Safe Demo

### 1. Seed the demo

```bash
cd /home/dash/Desktop/opensoar\ backend\ 6\ mai/opensoar\ backend
python3 scripts/demo/seed_runtime_remediation_demo.py
```

Output:
```
[DEMO] Created marker file: /tmp/opensoar_runtime_demo/suspicious_marker.txt
[DEMO] Created runtime investigation: <UUID>
[DEMO] Status: awaiting_approval
[DEMO] Corrective actions: 1
[DEMO] Rollback actions: 1
```

### 2. Open the frontend

Navigate to:
```
http://localhost:3000/runtime/investigations
```

Look for the card titled:
> **DEMO: Safe Runtime Remediation Test**

Click it to open the detail page.

### 3. What you should see

#### Overview tab
- Status badge: **Awaiting Approval**
- Threat assessment: **suspicious**
- Target context: **host**
- Available actions: **Approve & Run** button visible

#### Remediation tab
- Playbook YAML displayed
- Phase 0: Evidence Collection (lists demo directory)
- Phase 1: Safety Check (confirms marker exists)
- Phase 2: Remediation (backs up and removes marker)
- Phase 3: Verification (confirms marker is gone)
- Phase 4: Rollback (restores marker from backup)

#### Actions
- Click **Approve & Run**
- The playbook executes on `localhost`
- After execution, the status changes to **verified** or **completed**

#### Verification tab
- Shows whether the fix was confirmed
- For the demo: "Verification PASSED: demo marker removed."

---

## Playbook Safety Details

The demo playbook only touches:
- `/tmp/opensoar_runtime_demo/suspicious_marker.txt`
- `/tmp/opensoar_runtime_demo/suspicious_marker.txt.bak`

It **does NOT** touch:
- `/etc/*` or any system configuration
- systemd services or units
- iptables rules
- Installed packages
- Running processes (except via `ls` for evidence)
- Container runtimes or Kubernetes resources
- User credentials or `/etc/shadow`

---

## How to Clean Up the Demo

```bash
python3 scripts/demo/seed_runtime_remediation_demo.py --cleanup
```

This removes:
- The demo investigation from the SQLite database
- All related records (approvals, runs, verifications)
- The entire `/tmp/opensoar_runtime_demo/` directory

---

## Files Involved

| File | Purpose |
|------|---------|
| `scripts/demo/seed_runtime_remediation_demo.py` | Creates or cleans up the demo |
| `/tmp/opensoar_runtime_demo/` | Demo filesystem sandbox |
| `docs/runbooks/runtime_remediation_demo.md` | This runbook |

---

## Troubleshooting

**Q: The "Approve & Run" button is not visible.**
A: Ensure the investigation status is `awaiting_approval` and the remediation plan has `actual_remediation_available: true`. Run the seeder script again if needed.

**Q: The playbook execution fails.**
A: Check that Ansible is installed and `localhost` is reachable. The demo playbook uses `ansible.builtin.command` and `ansible.builtin.file` which require no special modules.

**Q: Can I run the demo multiple times?**
A: Yes. Each run creates a new investigation with a new UUID. Run `--cleanup` to remove all demo instances.

**Q: Will the demo affect the Runtime QA Watchdog?**
A: No. The watchdog only checks real Falco investigations. Demo cases are excluded because they have a distinctive title (`DEMO: ...`).
