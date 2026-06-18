# Suricata Alert Lifecycle — Complete Pipeline Trace

> **Document**: End-to-end trace of every Suricata alert from Elasticsearch ingestion to IPS map display  
> **Source**: `pipeline/poller/main.py` → `api/routes/ips.py`  
> **Last Updated**: April 20, 2026

---

## High-Level Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 0: ELASTICSEARCH SOURCE                               │
│  Index: filebeat-*  │  Query: fileset.name=eve AND suricata.eve.event_type=alert       │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 1: POLLER (every 10s)                                 │
│  File: pipeline/poller/main.py :: poll_source("filebeat", "filebeat-*")                │
│  ├─ _get_cursor("filebeat") → Redis → disk file → fallback: now-24h                   │
│  ├─ ES search: @timestamp > cursor, sort asc, batch 50                                 │
│  ├─ Per hit: _is_ever_seen(es_id)? → skip                                              │
│  └─ process_single_alert(es_id, source_doc, "filebeat", mapper, ts)                    │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 2: MAPPING & FILTERING                                │
│  File: pipeline/mappers/filebeat.py → map_filebeat_alert()                              │
│  └─ Validate: fileset.name=="eve" && event_type=="alert" → else ValueError(skip)       │
│                                                                                          │
│  File: pipeline/mappers/suricata.py :: map_suricata_alert()                             │
│  ├─ Extract: signature → title/rule_name                                                │
│  ├─ _map_category_to_severity(category, signature) → 1-4 (low→critical)                │
│  ├─ extract_ips(doc, "suricata") → source_ip, dest_ip                                   │
│  ├─ _build_iocs() → {ip, port, domain, url, hash, filepath}                             │
│  ├─ _build_observables() → [{type, value, direction}, ...]                              │
│  ├─ _build_metadata() → signature_id, protocol, flow_id, payload, HTTP, TLS, DNS        │
│  ├─ enrich_with_mitre() → tags: mitre-T1190, mitre-tactic-Initial Access               │
│  └─ sigma_is_noise()? → ValueError(skip) — noisy patterns filtered                     │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 3: ALERT PROCESSOR                                    │
│  File: pipeline/poller/alert_processor.py :: process_single_alert()                     │
│                                                                                          │
│  GATE 1: is_duplicate(source, payload)?                                                 │
│    └─ Redis (TTL 300s) → memory → DB check → skip if duplicate                         │
│                                                                                          │
│  GATE 2: is_auto_noise(payload)?                                                        │
│    └─ Learned patterns → skip if auto-noise                                              │
│                                                                                          │
│  GATE 3: severity >= min_severity?                                                      │
│    └─ Compare against settings.opensoar_min_severity → skip if below                    │
│                                                                                          │
│  ENRICHMENT (in order):                                                                 │
│    ├─ _is_threat_intel() → appends "| N unique IPs" to description                     │
│    ├─ enrich_alert() → GeoIP: src-country-US, src-AS123, src-provider-AWS              │
│    └─ track_alert() → campaign detection: "Campaign: X from N IPs"                     │
│                                                                                          │
│  PERSIST: _persist_alert_local("filebeat", es_id, clean_payload)                        │
│    ├─ Check: SELECT id FROM alerts WHERE source="filebeat" AND source_id=es_id          │
│    ├─ Insert: Alert(external_id, source, source_id, title, description,                │
│    │            severity, status="active", category, source_ip, dest_ip,                │
│    │            hostname, rule_name, tags, iocs, observables, metadata,                 │
│    │            event_time, dedup_key, whitelisted)                                      │
│    └─ Returns: local_alert_id (UUID)                                                    │
│                                                                                          │
│  LINK: _link_suricata_to_wazuh(local_id, source, payload) — NO-OP for filebeat source   │
│                                                                                          │
│  FORWARD DECISION:                                                                      │
│    ├─ Pattern exists? → _handle_repeated_alert() → PATCH occurrences-N tag             │
│    └─ New alert → client.send_alert(clean_payload) → POST /webhooks/alerts             │
│         ├─ 422 → duplicate, update local external_id                                    │
│         ├─ Success → extract upstream_alert_id                                          │
│         └─ Background task: _process_alert_data_usage(local_id, upstream_id, payload)   │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 4: DATA USAGE ORCHESTRATOR                            │
│  File: pipeline/datausage/orchestrator.py :: process_alert() (async background task)     │
│                                                                                          │
│  STAGE 1: Observables                                                                   │
│    └─ observable_manager.auto_create_from_alert(upstream_id, alert_data)                │
│       → Extract IOCs via regex → POST /api/v1/observables → skip 422 dupes             │
│                                                                                          │
│  STAGE 2: AI Triage                                                                     │
│    └─ ai_pipeline.smart_triage_and_apply(upstream_id, alert_data)                       │
│       → LLM prompt → triage + summarize (if critical/high)                              │
│                                                                                          │
│  STAGE 3: Incident Management                                                           │
│    └─ incident_manager.process_incident(upstream_id, alert_payload, local_id)           │
│       → Extract signals: MITRE tactics, attack patterns, kill-chain, cloud, country     │
│       → DECISION TREE:                                                                  │
│          ├─ Noise (ICMP/ping) → NEVER create                                            │
│          ├─ Critical severity → ALWAYS create                                           │
│          ├─ Attack pattern (ssh_brute, port_scan, malware, c2, web, ddos) → CREATE     │
│          ├─ Kill chain (2+ MITRE phases) → CREATE                                       │
│          ├─ Spamhaus DROP → CREATE                                                      │
│          ├─ High + MITRE → CREATE                                                       │
│          ├─ Medium + high-risk tactic → CREATE                                          │
│          ├─ Medium without context → needs 2+ alerts same key within 15 min            │
│          └─ Low/CINS-only → NEVER create                                                │
│       → If CREATE: generate title, escalate severity (multi-source/kill-chain), tags   │
│       → Link alert to incident upstream                                                 │
│       → Upsert local Incident shadow record                                             │
│                                                                                          │
│  STAGE 4: Alert Enrichment                                                              │
│    └─ alert_manager.auto_enrich_alert(upstream_id, alert_data, incident_id)             │
│       → Status: new → investigating (if linked to incident)                             │
│       → Determination: malicious/benign/unknown                                         │
│       → Comment: GeoIP + MITRE + campaign context                                       │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 5: INCIDENT WATCHER                                   │
│  File: response/watcher/main.py :: watch_incidents() (background task, every 15s)       │
│                                                                                          │
│  ├─ Fast scan: fetch 50 most recent open incidents                                     │
│  ├─ Full scan: paginate ALL open incidents (every 60 cycles ≈ 15 min)                  │
│  ├─ Skip known: check Investigation.incident_id + Incident.external_id                 │
│  ├─ Fetch linked alerts: reader.get_incident_alerts(id) → get_alert(id) for each       │
│  ├─ Gate: skip if alert_count < incident_min_alerts (default 1)                         │
│  ├─ Build context: _build_investigation_context(incident, full_alerts)                 │
│  │   → Timeline, IPs, hostnames, users, processes, files, domains, hashes, ports       │
│  │   → Behavioral analysis: auth, recon, execution, exfil, malware, web, DoS           │
│  │   → Attack type determination with confidence scoring                                │
│  │   → Risk score calculation (0-100)                                                   │
│  ├─ Upsert local Incident shadow + link to local Alerts via AlertIncidentLink           │
│  ├─ Create Investigation: status="pending", target_host, target_user                  │
│  ├─ Store alert snapshots: InvestigationAlert table (JSON blob per alert)               │
│  └─ Spawn AI engine: _run_ai_engine(inv_id, context) — semaphore-limited (max 4)        │
│       → LLM generates Ansible playbook                                                  │
│       → Create PlaybookApproval record                                                  │
│       → On success: send notification (Slack/email)                                     │
│       → On failure: store ai_error, status stays pending                                │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 6: INVESTIGATION LIFECYCLE                            │
│  File: api/routes/investigations.py                                                      │
│                                                                                          │
│  States: pending → awaiting_approval → approved → running → completed/failed             │
│                    ↓ declined                                                             │
│                    ↓ archived (from completed/failed/declined)                           │
│                                                                                          │
│  Analyst actions:                                                                        │
│    ├─ View AI analysis + generated playbook                                             │
│    ├─ Approve → triggers Ansible execution (response/ansible_exec.py)                   │
│    ├─ Decline → status="declined"                                                       │
│    ├─ Edit playbook → YAML editor with validation                                       │
│    └─ Execute → subprocess ansible-playbook -i inventory playbook.yml                   │
│                                                                                          │
│  Fix verification:                                                                       │
│    └─ response/fix_verifier.py → re-query ES to verify remediation success              │
│       → FixVerification record: is_fixed, confidence, method, details                   │
│                                                                                          │
│  Archival:                                                                               │
│    └─ response/archiver.py → create Archive record with full context JSON               │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 7: IPS ATTACK MAP                                     │
│  File: api/routes/ips.py                                                                 │
│                                                                                          │
│  DATA SOURCES (priority order):                                                          │
│    1. Upstream OpenSOAR: client.list_alerts(limit=200)                                  │
│    2. Local fallback: SELECT * FROM alerts WHERE source_ip IS NOT NULL                  │
│       ORDER BY created_at DESC LIMIT 200                                                │
│                                                                                          │
│  EVENT CONVERSION: _alert_to_event(alert_dict)                                          │
│    ├─ Filter: is_private_ip(source_ip)? → skip                                          │
│    ├─ GeoIP: resolve_ip(source_ip) → country, city, lat, lon, ISP, ASN                 │
│    ├─ Target default: dest_ip missing → 10.175.1.137 (Tunisia fallback)                 │
│    └─ Lifecycle: _get_lifecycle_for_alert(alert_id) → active/investigating/mitigated/   │
│       └─ Queries Investigation + InvestigationAlert (15s cache)                         │
│                                                                                          │
│  CACHING:                                                                               │
│    ├─ _alert_cache: 10s TTL for upstream/local fetch                                    │
│    ├─ _recent_events: manual POST events (240 min retention)                            │
│    └─ _lifecycle_cache: 15s TTL per alert ID                                            │
│                                                                                          │
│  ENDPOINTS:                                                                             │
│    ├─ GET /map-data → attacks[] + paths[] (source→destination lat/lon)                  │
│    ├─ GET /statistics → by_severity, by_category, by_protocol, by_lifecycle, top_countries│
│    ├─ GET /summary → total, active, unique_sources, critical/high/medium/low            │
│    └─ GET /events → paginated event list with filters                                   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Decision Gate Detail — What Gets Filtered Where

```
ES Query (filebeat-*)
    │
    ▼
┌─────────────────────────────┐
│ fileset.name == "eve"       │ ← ES filter (only Suricata eve docs)
│ event_type == "alert"       │ ← ES filter (only alerts, not flows)
│ @timestamp > cursor         │ ← ES filter (only new docs)
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│ es_id in seen_ids?          │ ← Memory/disk dedup (50k IDs)
│ es_id in batch_processed?   │ ← Intra-batch dedup
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│ map_filebeat_alert()        │
│   └─ is_suricata_alert?     │ ← Validates fileset + event_type
│   └─ map_suricata_alert()   │
│        └─ sigma_is_noise()? │ ← Noisy signatures filtered
│        └─ Missing signature?│ ← ValueError(skip)
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│ is_duplicate()?             │ ← Redis (300s TTL) + memory + DB
│ is_auto_noise()?            │ ← Learned patterns
│ severity >= min_severity?   │ ← Config threshold (default: low)
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│ _persist_alert_local()      │
│   └─ DB duplicate check     │ ← SELECT WHERE source=source_id
│   └─ INSERT Alert           │ ← SQLite
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│ client.send_alert()         │ ← POST upstream /webhooks/alerts
│   ├─ 422 → duplicate        │ ← Update local external_id
│   ├─ Success → alert_id     │ ← Update pattern tracking
│   └─ Failure → retry_queue  │ ← 3 retries + exponential backoff
└─────────────────────────────┘
```

---

## Field Transformation: Raw ES → Local SQLite

| Raw Elasticsearch Field | Mapper Output | Local SQLite (`alerts` table) | Notes |
|------------------------|---------------|------------------------------|-------|
| `@timestamp` | `event_time` | `event_time` (DateTime) | ISO-8601 normalized |
| `suricata.eve.alert.signature` | `title`, `rule_name` | `title`, `rule_name` | Truncated to 100 chars for rule_name |
| `suricata.eve.alert.signature_id` | `metadata.signature_id` | `alert_metadata` (JSON) | Stored in metadata blob |
| `suricata.eve.alert.category` | `metadata.category` | `alert_metadata` (JSON) | Used for severity mapping |
| `suricata.eve.proto` | `metadata.protocol` | `alert_metadata` (JSON) | TCP/UDP/ICMP/etc |
| `suricata.eve.src_ip` | `source_ip` | `source_ip` | Extracted via ip_extractor |
| `suricata.eve.dest_ip` | `dest_ip` | `dest_ip` | Extracted via ip_extractor |
| `suricata.eve.src_port` | `metadata.src_port` | `alert_metadata` (JSON) | |
| `suricata.eve.dest_port` | `metadata.dst_port` | `alert_metadata` (JSON) | |
| `suricata.eve.flow_id` | `metadata.flow_id` | `alert_metadata` (JSON) | |
| `suricata.eve.payload_printable` | `metadata.payload_printable` | `alert_metadata` (JSON) | Truncated to 200 chars |
| `host.name` | `hostname` | `hostname` | |
| `_id` (ES doc ID) | `source_id` | `source_id` | Primary dedup key |
| — | `severity` | `severity` | 1-4 mapped to low/medium/high/critical |
| — | `category` | `category` | Hardcoded "network" for Suricata |
| — | `tags` | `tags` (JSON) | Includes MITRE, GeoIP, provider |
| — | `iocs` | `iocs` (JSON) | Structured IOC dict |
| — | `observables` | `observables` (JSON) | Observable array |
| — | `dedup_key` | `dedup_key` | Hash(source + signature_id + src_ip + dst_ip + dst_port) |
| upstream response `alert_id` | `id` | `external_id` | Set after successful forward |

---

## Incident Creation Decision Tree

```
Suricata alert arrives at incident_manager
    │
    ▼
┌────────────────────────────────────┐
│ Noise? (ICMP ping, recon scans)   │──YES──▶ NEVER create incident
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Critical severity?                 │──YES──▶ CREATE incident
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Attack pattern detected?           │──YES──▶ CREATE incident
│ (ssh_brute, port_scan, malware,  │
│  c2, web_attack, ddos)            │
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Kill chain (2+ MITRE phases)?      │──YES──▶ CREATE incident
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Spamhaus DROP?                     │──YES──▶ CREATE incident
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ High + MITRE tactics?              │──YES──▶ CREATE incident
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Medium + high-risk tactic?         │──YES──▶ CREATE incident
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Medium without context?            │──▶ Need 2+ alerts same key │
│                                    │    within 15 min ──YES──▶ CREATE
└────────────────────────────────────┘
    │ NO / insufficient
    ▼
┌────────────────────────────────────┐
│ Low / CINS-only                    │──▶ NEVER create incident
└────────────────────────────────────┘
```

---

## Lifecycle Mapping: Investigation → IPS Event State

```
Investigation Status          │ IPS Lifecycle
──────────────────────────────┼─────────────────
approved + run.completed      │ → blocked
approved + approval.decision  │ → blocked
fix_verification.likely_fixed │ → mitigated
archived/completed + run.done │ → mitigated
archived (any)                │ → mitigated
failed                        │ → active
fix.not_fixed                 │ → active
fix.playbook_failed_but_quiet │ → active
pending                       │ → investigating
approved (pre-execution)      │ → investigating
awaiting_approval             │ → investigating
completed (no verification)   │ → investigating
run.running                   │ → investigating
approval.declined             │ → investigating
(default)                     │ → active
```

---

## Code Reference Index

| Phase | File | Key Function | Line ~ |
|-------|------|--------------|--------|
| Poll | `pipeline/poller/main.py` | `poll_source()` | 40 |
| Poll | `pipeline/poller/main.py` | `run_forwarder()` | 20 |
| Cursor | `pipeline/poller/cursor_manager.py` | `_get_cursor()` | 15 |
| Cursor | `pipeline/poller/cursor_manager.py` | `_set_cursor()` | 35 |
| Seen IDs | `pipeline/poller/seen_ids.py` | `_is_ever_seen()` | 20 |
| Seen IDs | `pipeline/poller/seen_ids.py` | `_save_seen_ids()` | 45 |
| Map | `pipeline/mappers/filebeat.py` | `map_filebeat_alert()` | 10 |
| Map | `pipeline/mappers/suricata.py` | `map_suricata_alert()` | 25 |
| Severity | `pipeline/mappers/suricata.py` | `_map_category_to_severity()` | 120 |
| MITRE | `pipeline/enrichment/mitre.py` | `enrich_with_mitre()` | 30 |
| Sigma | `pipeline/enrichment/sigma.py` | `is_noise_alert()` | 40 |
| Process | `pipeline/poller/alert_processor.py` | `process_single_alert()` | 198 |
| Dedup | `pipeline/services/dedup.py` | `is_duplicate()` | 25 |
| Noise | `pipeline/services/noise_learner.py` | `is_auto_noise()` | 50 |
| GeoIP | `pipeline/enrichment/geoip.py` | `enrich_alert()` | 60 |
| Campaign | `pipeline/services/correlator.py` | `track_alert()` | 40 |
| Persist | `pipeline/poller/alert_processor.py` | `_persist_alert_local()` | 89 |
| Link | `pipeline/poller/alert_processor.py` | `_link_suricata_to_wazuh()` | 148 |
| Forward | `pipeline/sender.py` | `send_alert()` | 153 |
| Retry | `pipeline/sender.py` | `_post_with_retry()` | 80 |
| Retry Queue | `pipeline/retry_queue.py` | `add()` | 30 |
| Data Usage | `pipeline/datausage/orchestrator.py` | `process_alert()` | 35 |
| Observables | `pipeline/datausage/observable_manager.py` | `auto_create_from_alert()` | 250 |
| AI | `pipeline/datausage/ai_pipeline.py` | `smart_triage_and_apply()` | 40 |
| Incident | `pipeline/datausage/incident_manager.py` | `process_alert()` | 60 |
| Alert Mgr | `pipeline/datausage/alert_manager.py` | `auto_enrich_alert()` | 80 |
| Watcher | `response/watcher/main.py` | `watch_incidents()` | 50 |
| Context | `response/watcher/context_builder.py` | `_build_investigation_context()` | 100 |
| Invest DB | `response/watcher/investigation_db.py` | `_create_investigation()` | 40 |
| AI Engine | `response/ai_engine/` | `run_investigation()` | varies |
| Approval | `api/routes/investigations.py` | `approve_investigation()` | 350 |
| Execute | `response/ansible_exec.py` | `execute_playbook()` | 80 |
| Verify | `response/fix_verifier.py` | `verify_fix()` | 60 |
| Archive | `response/archiver.py` | `archive_investigation()` | 100 |
| IPS | `api/routes/ips.py` | `_get_alerts_as_events()` | 280 |
| IPS | `api/routes/ips.py` | `_alert_to_event()` | 140 |
| IPS | `api/routes/ips.py` | `_get_lifecycle_for_alert()` | 100 |
| IPS | `api/routes/ips.py` | `get_map_data()` | 432 |
