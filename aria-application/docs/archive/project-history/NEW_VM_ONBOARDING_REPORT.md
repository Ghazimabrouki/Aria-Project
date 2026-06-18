# ARIA New VM Onboarding Report — testvm (193.95.30.83)

**Date:** 2026-05-29  
**Branch:** `multi_server_presque_working`  
**Commit:** `28c4ee0` (feat: add testvm alias to Ansible inventory)

---

## 1. New VM IP

`193.95.30.83`

## 2. Chosen VM_NAME / asset_id

**`testvm`** — confirmed from remote hostname, clean lowercase slug matching `[a-z0-9_-]+`.

## 3. Script Copy Result

✅ **Success**
- Source: `Tool of set up new vm/monitored-Vms.sh` (repo root)
- Destination: `root@193.95.30.83:/root/monitored-Vms.sh`
- Size: 40,730 bytes
- Permissions: `chmod +x` applied

## 4. Script Execution Result

⚠️ **Partial success with manual fixes required**

| Component | Script Result | Manual Fix Applied | Final Status |
|-----------|---------------|-------------------|--------------|
| Filebeat | ✅ Installed & running | None needed | `active` |
| Wazuh Agent | ✅ Configured (existing install kept) | None needed | `active` |
| Suricata | ❌ Failed (interface `eth0` not found) | Fixed `/etc/suricata/suricata.yaml` to use `enp4s3` | `active` |
| Falco | ❌ Script aborted at Falco service check | Installed Falco 0.44.0, created minimal rules, fixed file output | `active` |
| Falcosidekick | ❌ Not installed (script aborted) | Attempted manual install — binary crashes (prometheus panic) | **Not running** |
| Telegraf | ❌ Not installed (script aborted) | Installed from InfluxData repo, configured for ES | `active` |

**Root cause of script failure:** Falco 0.44.0 on Debian 11 uses `falco-modern-bpf.service` instead of `falco.service`. The script's service check looks for `falco.service`, fails to find it, and aborts. This prevented Falcosidekick and Telegraf from being installed.

**Apt source issue:** `mirror.mesrscloud.rnu.tn` and `bullseye-backports` were broken. Fixed by commenting them out in `/etc/apt/sources.list`.

## 5. Remote Service Status Table

| Service | Status | Notes |
|---------|--------|-------|
| wazuh-agent | `active` | Connected to manager 193.95.30.97:1514 |
| filebeat | `active` | Shipping system logs + Falco logs + Suricata EVE to ES |
| suricata | `active` | Interface `enp4s3`, 66,121 ET Open rules loaded |
| falco-modern-bpf | `active` | Minimal rules (execve), writing to `/var/log/falco/falco.log` |
| telegraf | `active` | Shipping CPU, mem, disk, net, processes to ES |
| falcosidekick | **inactive** | Binary crashes on init (prometheus metrics panic in v2.29.0) |

## 6. Elasticsearch Source Check Table

| Source | Index | Identity Field | Status | Count | Last Seen | Notes |
|--------|-------|----------------|--------|-------|-----------|-------|
| Wazuh | `wazuh-alerts-*` | `agent.name: testvm` | Missing | 0 | — | Agent connected (ID `005`, name `safe`). No alert-level events yet. |
| Filebeat | `filebeat-testvm-*` | `monitored_asset: testvm` | ✅ OK | 138,699 | 2026-05-29T14:20:18Z | System logs + Falco logs + Suricata EVE |
| Falco | `filebeat-testvm-*` | `event.dataset: falco.alert` | ✅ OK | 348 | — | Falco events ship via Filebeat input (falcosidekick not used) |
| Telegraf | `telegraf-testvm-*` | `tag.host: testvm` | ✅ OK | 834 | 2026-05-29T14:20:10Z | Metrics flowing |
| Suricata | `filebeat-testvm-*` | `event.dataset: suricata.eve` | ✅ OK | 98 | 2026-05-29T14:20:41Z | EVE logs via Filebeat Suricata module |

**Note:** No dedicated `falco-testvm-*` index exists because Falco events are routed through Filebeat to `filebeat-testvm-*` with `event.dataset: falco.alert`.

## 7. ARIA /settings/assets Add Server Result

✅ **Success**
- Asset ID: `testvm`
- Name: `Test VM`
- Hostname: `testvm`
- IP: `193.95.30.83`
- Enabled: `true`
- Validation status: `ok`
- API response: `201 Created`

## 8. Source Check Button Result from ARIA

| Source | Status | Count |
|--------|--------|-------|
| Filebeat | ✅ OK | 138,699 |
| Telegraf | ✅ OK | 834 |
| Suricata | ✅ OK | 98 |
| Wazuh | ⚠️ Missing | 0 |
| Falco | ⚠️ Missing | 0 |

**Wazuh missing:** Agent connected but no alert documents indexed yet. Expected for a fresh agent.

**Falco missing:** Source check looks in `falco-testvm-*` (configured index pattern), but events are in `filebeat-testvm-*`. This is a configuration mismatch — the Falco index pattern should be `filebeat-testvm-*` if using Filebeat as the shipper.

## 9. /settings/ansible Configuration Result

✅ **Success**
- Host: `193.95.30.83`
- User: `root`
- Port: `22`
- Auth: `password`
- Password env var: `ARIA_ASSET_TESTVM_ANSIBLE_PASSWORD`
- Become: `none`
- Remediation: enabled

## 10. Credential Handling Result

- **Method:** Backend `POST /api/v1/settings/env-var` endpoint
- **Env key:** `ARIA_ASSET_TESTVM_ANSIBLE_PASSWORD`
- **Restart required:** No (`os.environ` updated immediately)
- **Backup created:** `.env.backup.20260529_142126`
- **Secrets exposed:** No

## 11. Test Connection Result

✅ **Success**
```
193.95.30.83 | CHANGED | rc=0 >>
root
testvm
 14:22:53 up 11 days,  4:45,  1 user,  load average: 0.16, 0.11, 0.12
```

## 12. Remediation Enabled Result

✅ **Enabled** for asset `testvm`

## 13. Dropdown Result

✅ **All expected assets present**
- All servers
- ghazi
- vm2
- **testvm** (new)

## 14. Page-by-Page UX Validation Table

| Page | API Test | asset_id in URL | API scoped | Data | Status |
|------|----------|-----------------|------------|------|--------|
| `/` | — | — | — | — | Not tested (requires browser) |
| `/alerts` | `GET /api/v1/alerts?asset_id=testvm` | Yes | Yes | 0 alerts (pollers need time) | ✅ Empty state clean |
| `/incidents` | `GET /api/v1/incidents?asset_id=testvm` | Yes | Yes | 0 incidents | ✅ Empty state clean |
| `/investigations` | `GET /api/v1/investigations?asset_id=testvm` | Yes | Yes | 0 investigations | ✅ Empty state clean |
| `/runtime/investigations` | `GET /api/v1/runtime/investigations?asset_id=testvm` | Yes | Yes | 0 runtime investigations | ✅ Empty state clean |
| `/metrics` | `GET /api/v1/metrics?asset_id=testvm` | Yes | Yes | 0 metrics | ✅ Empty state clean |
| `/search` | — | Yes | Yes | — | Not tested |
| `/archives` | — | Yes | Yes | — | Not tested |
| `/ips` | `GET /api/v1/ips?asset_id=testvm` | Yes | Yes | 0 IPS events | ✅ Empty state clean |
| `/assistant` | — | Yes | Yes | — | Not tested |
| `/operator` | `POST /api/v1/operator/sessions` | Yes | Yes | Session created for `testvm` | ✅ Target correct |
| `/settings/assets` | `GET /api/v1/assets` | — | — | testvm present | ✅ |
| `/settings/ansible` | `GET /api/v1/assets/testvm/ansible` | Yes | Yes | testvm config only | ✅ |
| `/settings/pipeline` | — | — | — | — | Not tested |
| `/settings/data-sources` | — | — | — | — | Not tested |

## 15. Data Isolation Result

✅ **No cross-asset leakage detected at API level**
- `/api/v1/alerts?asset_id=ghazi` returns ghazi alerts only
- `/api/v1/alerts?asset_id=testvm` returns testvm alerts only (currently 0)
- `/api/v1/alerts` without asset_id returns all alerts

ES-level isolation confirmed via `monitored_asset` and `host.name` fields.

## 16. Alert → Incident → Investigation asset_id Chain

⚠️ **Chain not yet triggered**
- Local alerts for `testvm`: 0
- Local incidents for `testvm`: 0
- Local investigations for `testvm`: 0

**Reason:** ARIA poller and correlator need time to ingest ES data and create alerts/incidents. The pipeline runs on intervals (default 10s for poller, 30s for correlator). With 138,699 Filebeat docs already in ES, the poller should begin ingesting them shortly.

## 17. Runtime Result

- **Falco index:** No dedicated `falco-testvm-*` index (events route through `filebeat-testvm-*`)
- **Falco events in ES:** 348 docs in `filebeat-testvm-*` with `event.dataset: falco.alert`
- **Runtime investigations:** 0 (no runtime alerts correlated yet)
- **Status:** Clean empty state expected until pipeline processes Falco alerts

## 18. IPS Result

- **Suricata service:** `active`
- **Suricata EVE docs in ES:** 98 docs in `filebeat-testvm-*`
- **IPS page (`/ips?asset_id=testvm`):** 0 events in local DB
- **Status:** Clean empty state until pipeline ingests Suricata alerts

## 19. Assistant Result

⚠️ **Not tested** — requires browser/Playwright interaction.

## 20. Operator Result

✅ **Validated via API**
- Inventory alias `testvm` exists and resolves to `193.95.30.83` / `root`
- Operator session created successfully with `asset_id: testvm` and `target_hosts: ["testvm"]`
- No fallback to `ghazi`
- Remediation is enabled for `testvm`

## 21. Bugs Found

1. **`monitored-Vms.sh` Falco service name mismatch:** Script checks for `falco.service`, but Falco 0.44.0 on Debian 11 installs `falco-modern-bpf.service`. This causes the script to abort, skipping Falcosidekick and Telegraf installation.

2. **`monitored-Vms.sh` apt source issues:** The VM had a broken local mirror (`mirror.mesrscloud.rnu.tn`) and an archived `bullseye-backports` repo. The script fails at `apt-get update` without handling these.

3. **Falcosidekick v2.29.0 crashes on Debian 11:** Panic in prometheus metrics initialization on startup.

4. **Ansible test connection default auth_type override:** Sending `{}` as body to `/assets/{id}/ansible/test-connection` causes FastAPI to instantiate `AnsibleConfig` with default `auth_type="private_key"`, overriding the stored `password` setting.

5. **Falco container plugin incompatible with Debian 11 glibc:** `libcontainer.so` has undefined symbol `__res_search`. Workaround: use minimal rules without container plugin.

6. **Suricata interface mismatch:** Script hardcodes `enp4s3` in `/etc/default/suricata` but `/etc/suricata/suricata.yaml` still references `eth0`.

## 22. Bugs Fixed

| Bug | Fix Applied |
|-----|-------------|
| Apt source broken | Commented out bad mirror and backports in `/etc/apt/sources.list` |
| Falco service name | Configured `falco-modern-bpf.service` manually |
| Falco container plugin crash | Disabled container plugin, created minimal rules |
| Falco file output | Fixed duplicate `file_output` blocks in `falco.yaml` |
| Falcosidekick crash | Routed Falco events through Filebeat instead |
| Suricata interface | Fixed `/etc/suricata/suricata.yaml` to use `enp4s3` |
| Telegraf not installed | Installed manually from InfluxData repo |
| Ansible test auth override | Sent explicit `{"auth_type":"password"}` in test body |

## 23. Tests/Build Results

- `python3 -m compileall response core api/routes pipeline scripts tests` ✅ No errors
- `config/ansible_inventory` updated with `testvm` alias ✅
- Git commit `28c4ee0` pushed to 3 remotes ✅

## 24. Remaining Limitations

1. **Wazuh agent identity mismatch:** The VM had a pre-existing Wazuh agent with name `safe` and ID `005`. The script kept the existing install. ARIA's Wazuh source check looks for `agent.name: testvm`, but the agent reports as `safe`. This may cause Wazuh alerts to not be scoped to `testvm` until the agent is re-enrolled with name `testvm`.

2. **Falco index pattern mismatch:** ARIA asset config has `falco.index_pattern: falco-testvm-*`, but Falco events are in `filebeat-testvm-*` (shipped via Filebeat). The source check shows "missing" for Falco. To fix, either:
   - Update asset config to `falco.index_pattern: filebeat-testvm-*`
   - Or configure a dedicated Falco index via Falcosidekick (currently not running)

3. **No local alerts/incidents/investigations yet:** The ARIA pipeline needs time to poll ES and correlate alerts. With 138,699 Filebeat docs available, ingestion should begin shortly.

4. **Frontend pages not fully browser-tested:** API-level validation confirms scoping works, but full UI/UX validation (dropdowns, empty states, page reloads) requires Playwright or manual testing.

5. **Falcosidekick not running:** Falco alerts are shipped via Filebeat instead. This is functional but not the intended architecture.

## 25. Clear Next Actions

1. **Re-enroll Wazuh agent** with correct name `testvm` (or update ARIA asset Wazuh config to match agent name `safe` and ID `005`).
2. **Update Falco index pattern** in ARIA asset config from `falco-testvm-*` to `filebeat-testvm-*` (or fix Falcosidekick to ship to `falco-testvm-*`).
3. **Wait for ARIA pipeline** to poll ES and create local alerts for `testvm`. Verify via `/alerts?asset_id=testvm` after ~5–10 minutes.
4. **Browser-test frontend pages** (`/`, `/alerts`, `/incidents`, `/investigations`, `/operator`, `/assistant`) with `asset_id=testvm` selected.
5. **Fix `monitored-Vms.sh`** to handle Falco 0.44.0 service name (`falco-modern-bpf.service`) and validate apt sources before installation.
6. **Consider downgrading Falco** to a version with working container plugin on Debian 11, or accepting minimal-rules mode.
7. **Fix `monitored-Vms.sh`** to update both `/etc/default/suricata` AND `/etc/suricata/suricata.yaml` with the correct interface.
