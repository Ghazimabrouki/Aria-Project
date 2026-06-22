# Core SOC Workflow — Alert Pipeline

## 1. Feature name
Alert Ingestion & Enrichment Pipeline

## 2. Purpose
Poll Elasticsearch indices for Wazuh, Suricata, Falco, Filebeat, and generic alerts; normalize, deduplicate, filter noise, enrich with GeoIP/MITRE, track campaigns, check whitelist, and persist locally or forward upstream.

## 3. Input
- ES indices: `wazuh-*`, `suricata-*`, `falco-*`, `filebeat-*`, and custom patterns.
- Raw JSON documents from each source.

## 4. Processing steps
1. **Poll** (`pipeline/poller/main.py`) — Parallel per-source polling with adaptive sleep.
2. **Map** (`pipeline/mappers/`) — Source-specific normalization to OpenSOAR format.
3. **Dedup** (`pipeline/poller/alert_processor.py`) — Redis + memory + DB check with source-specific keys.
4. **Noise filter** — Sigma noise rules + auto-learned noise skip.
5. **Severity filter** — Skip below `ALERT_MIN_SEVERITY`.
6. **Enrich** — GeoIP (`enrich_alert`), MITRE ATT&CK tag extraction, dynamic cloud-provider detection.
7. **Campaign track** — `track_alert()` groups related alerts into campaigns.
8. **Whitelist** — Skip if IP/hash/domain in whitelist.
9. **Persist** — `_persist_alert_local()` writes to SQLite `Alert` with pre-computed `_geo` for IPS performance.
10. **Forward** — `OpenSOARClient` sends to upstream with retry queue.

## 5. Output
- SQLite `Alert` rows (local mode).
- Upstream OpenSOAR alerts (upstream mode).
- Redis dedup keys + campaign state.

## 6. Main files
| File | Role |
|------|------|
| `pipeline/poller/main.py` | Forwarder loop, cursor management |
| `pipeline/poller/alert_processor.py` | `process_single_alert()` pipeline |
| `pipeline/mappers/wazuh.py` | Wazuh normalization |
| `pipeline/mappers/suricata.py` | Suricata normalization |
| `pipeline/mappers/falco.py` | Falco normalization |
| `pipeline/mappers/filebeat.py` | Filebeat normalization |
| `pipeline/mappers/generic.py` | Universal/CrowdStrike/AWS/GuardDuty/Azure |
| `pipeline/enrichment/geoip.py` | GeoIP enrichment |
| `pipeline/enrichment/mitrecraft.py` | MITRE mapping |
| `pipeline/dedup.py` | Deduplication engine |
| `pipeline/noise_learner.py` | Auto-learned noise rules |

## 7. API endpoints
None dedicated; data consumed by `/alerts`, `/incidents`, `/ips`, `/search`.

## 8. Database tables
- `Alert` (with `_geo` JSON column)
- `WhitelistEntry`

## 9. Background jobs
- **Alert Forwarder / Local Poller** (every `ALERT_POLL_INTERVAL`, default 10s)

## 10. Frontend page
- **Route**: `/alerts`
- **Features**: Alert list with filters, severity badges, source icons.

## 11. Example
Wazuh alert `rule.id=5710` (SSH brute-force) → mapped to severity `high`, MITRE `T1110` → GeoIP resolves attacker IP to Romania → not duplicate → not noise → campaign `ssh_brute_force_2024_04_28` → persisted locally → visible in `/alerts` and `/ips`.

## 12. Known limitations
- Mapper-level Sigma filtering may drop valid alerts if Sigma rules are overly broad.
- Upstream mode requires external OpenSOAR instance; local mode does not forward.
- No migration framework; schema changes rely on `init_db()` table creation.
