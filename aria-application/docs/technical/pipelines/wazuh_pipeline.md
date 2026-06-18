# Wazuh Alert Lifecycle — Complete Pipeline Trace

> **Document**: End-to-end trace of every Wazuh alert from Elasticsearch ingestion to IPS map display  
> **Source**: `pipeline/poller/main.py` → `api/routes/ips.py`  
> **Last Updated**: April 20, 2026

---

## Important: Wazuh Indexing Stopped

**Status**: `wazuh-alerts-4.x-*` indices stopped receiving new documents on **April 16, 2026 at 08:49 UTC**.

**Evidence** (from `backend.log`):
```
cursor=2026-04-16T08:49:32.632000Z
hits_available=0
hits_returned=0
index=wazuh-alerts-4.x-*
source=wazuh
```

**Root cause**: The Wazuh manager on `193.95.30.97` needs `systemctl restart wazuh-manager`. This is an upstream data-source outage, not a pipeline bug. The forwarder is healthy — it successfully queries Elasticsearch and receives valid empty responses.

**Local DB state**: 130 Wazuh alerts persisted from before the outage.

---

## High-Level Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 0: ELASTICSEARCH SOURCE                               │
│  Index: wazuh-alerts-4.x-*  │  Query: @timestamp > cursor ONLY                         │
│  ⚠️ LAST INDEXED: 2026-04-16 08:49 UTC                                                  │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 1: POLLER (every 10s)                                 │
│  File: pipeline/poller/main.py :: poll_source("wazuh", "wazuh-alerts-4.x-*")           │
│  ├─ _get_cursor("wazuh") → Redis → disk file → fallback: now-24h                      │
│  ├─ ES search: @timestamp > cursor, sort asc, batch 50                                  │
│  ├─ Per hit: _is_ever_seen(es_id)? → skip                                               │
│  └─ process_single_alert(es_id, source_doc, "wazuh", mapper, ts)                        │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 2: MAPPING & FILTERING                                │
│  File: pipeline/mappers/wazuh.py :: map_wazuh_alert()                                   │
│                                                                                          │
│  VALIDATION: _validate_wazuh_doc()                                                      │
│    ├─ Requires: rule (dict) with rule.id present                                        │
│    ├─ Requires: agent (dict)                                                            │
│    └─ Rejects Falco cross-contamination (priority + output_fields)                      │
│                                                                                          │
│  LOW-VALUE FILTER:                                                                      │
│    └─ If rule.level < 3 → ValueError("Low-value alert filtered")                       │
│       (Levels 1-2 are filtered at mapper level)                                         │
│                                                                                          │
│  FIELD EXTRACTION:                                                                      │
│    ├─ rule.name → title (fallback: rule.description, full_log[:100])                    │
│    ├─ full_log / rule.description → description (truncated 2000)                        │
│    ├─ rule.level → severity via _map_wazuh_severity()                                   │
│    ├─ agent.name → hostname                                                             │
│    ├─ rule.groups → category via _categorize_wazuh_alert()                              │
│    ├─ extract_ips(doc, "wazuh") → source_ip, dest_ip                                    │
│    ├─ @timestamp / timestamp / time → event_time                                        │
│    ├─ rule.id → tags                                                                    │
│    ├─ mitre.* → tags (mitre technique IDs)                                              │
│    └─ _build_metadata() → agent, rule, mitre, decoder, manager, data                    │
│                                                                                          │
│  IP EXTRACTION HIERARCHY: _extract_wazuh_ips()                                          │
│    1. doc["src_ip"] / doc["source_ip"]                                                  │
│    2. doc["dst_ip"] / doc["dest_ip"]                                                    │
│    3. doc["data"]["srcip"] / doc["data"]["src_ip"]                                      │
│    4. doc["data"]["dstip"] / doc["data"]["dst_ip"]                                      │
│    5. Regex scan of full_log for first IPv4 address → src_ip                            │
│                                                                                          │
│  SEVERITY MAPPING: _map_wazuh_severity(level)                                           │
│    Level 10-15 → critical                                                               │
│    Level 7-9   → high                                                                   │
│    Level 4-6   → medium                                                                 │
│    Level 1-3   → low (also filtered if < 3)                                             │
│                                                                                          │
│  CATEGORY MAPPING: _categorize_wazuh_alert()                                            │
│    ├─ auth / authentication → "authentication"                                          │
│    ├─ web / apache / nginx → "network"                                                  │
│    ├─ malware / trojan / virus → "malware"                                              │
│    ├─ syscheck / fim → "system"                                                         │
│    └─ default → "other"                                                                 │
│                                                                                          │
│  SIGMA NOISE FILTER: is_noise_alert("wazuh", doc)                                       │
│    └─ Smart exceptions for critical/high + attack patterns + threat intel               │
│                                                                                          │
│  IOCS: _build_iocs()                                                                    │
│    ├─ syscheck hashes → hash IOCs                                                       │
│    ├─ data.win.eventdata.hashes → hash IOCs                                             │
│    ├─ data.url → url IOCs                                                               │
│    └─ data.srcuser → user IOCs                                                          │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 3: ALERT PROCESSOR                                    │
│  File: pipeline/poller/alert_processor.py :: process_single_alert()                     │
│                                                                                          │
│  GATE 1-3: Same as all sources (dedup, auto_noise, min_severity)                        │
│                                                                                          │
│  ENRICHMENT:                                                                            │
│    ├─ _is_threat_intel() → "| N unique IPs" in description                              │
│    ├─ enrich_alert() → GeoIP enrichment                                                 │
│    └─ track_alert() → campaign detection                                                │
│                                                                                          │
│  PERSIST: _persist_alert_local("wazuh", es_id, clean_payload)                           │
│    ├─ Check DB duplicate by source + source_id                                          │
│    └─ Insert Alert(...) → returns local_alert_id                                         │
│                                                                                          │
│  CROSS-SOURCE LINKING: _link_suricata_to_wazuh()                                        │
│    ├─ ONLY runs when source == "suricata" (NOT when source == "wazuh")                  │
│    ├─ Takes Suricata alert's source_ip                                                  │
│    ├─ Queries: SELECT id, title FROM alerts                                             │
│    │   WHERE source = 'wazuh' AND source_ip = :src_ip                                   │
│    │   AND created_at >= now - 5 minutes                                                │
│    │   ORDER BY created_at DESC LIMIT 1                                                 │
│    └─ If match: injects correlated_wazuh_alert_id + title into Suricata metadata        │
│       → Also persists to Suricata Alert.alert_metadata                                  │
│                                                                                          │
│  FORWARD: client.send_alert() → POST /webhooks/alerts                                   │
│    ├─ 422 → duplicate                                                                   │
│    ├─ Success → upstream_alert_id + background task                                     │
│    └─ Failure → retry_queue                                                             │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 4: DATA USAGE ORCHESTRATOR                            │
│  File: pipeline/datausage/orchestrator.py :: process_alert()                            │
│                                                                                          │
│  STAGE 1: Observables                                                                   │
│    └─ auto_create_from_alert() → IPs, hashes, URLs, users from Wazuh data               │
│                                                                                          │
│  STAGE 2: AI Triage                                                                     │
│    └─ smart_triage_and_apply() → LLM analysis                                           │
│                                                                                          │
│  STAGE 3: Incident Management                                                           │
│    └─ process_incident() → DECISION TREE:                                               │
│         Wazuh-specific attack patterns:                                                 │
│           ├─ ssh_brute_force: "authentication failed", "failed password",              │
│           │   "invalid user", "max authentication attempts"                             │
│           ├─ malware: "malware detected", "trojan detected", "virus detected"          │
│           └─ privilege_escalation: sudo, root access patterns                           │
│                                                                                          │
│         CORRELATION KEY:                                                                │
│           1. source_ip → 2. hostname (agent.name) → 3. container_id → 4. agent_name    │
│                                                                                          │
│  STAGE 4: Alert Enrichment                                                              │
│    └─ auto_enrich_alert() → status, determination, comment                              │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 5: INCIDENT WATCHER                                   │
│  File: response/watcher/main.py :: watch_incidents()                                    │
│                                                                                          │
│  ├─ Fast scan / Full scan                                                               │
│  ├─ Fetch linked alerts → full alert objects                                            │
│  ├─ _build_investigation_context()                                                      │
│  │   → Behavioral analysis for auth failures, file integrity, malware                   │
│  ├─ Create Investigation: status="pending"                                              │
│  └─ _run_ai_engine() → LLM playbook generation                                          │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 6: IPS ATTACK MAP                                     │
│  File: api/routes/ips.py                                                                 │
│                                                                                          │
│  _alert_to_event():                                                                     │
│    ├─ source_ip present? → yes for most Wazuh alerts (extracted from data.srcip)       │
│    ├─ is_private_ip(source_ip)? → skip if RFC1918                                       │
│    ├─ GeoIP resolve → country, city, lat, lon                                           │
│    └─ Category on map: "wazuh" (from alert.source)                                      │
│                                                                                          │
│  Wazuh alerts are well-represented on IPS map because:                                  │
│    ├─ Most have source_ip (from data.srcip or full_log regex)                          │
│    ├─ Network events (firewall, IDS) have public IPs                                    │
│    └─ Brute force attacks come from external IPs                                        │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Wazuh-Suricata Correlation Mechanism

```
Suricata alert arrives (source == "suricata")
    │
    ▼
┌─────────────────────────────┐
│ _link_suricata_to_wazuh()   │
│   ├─ source == "suricata"?  │──NO──▶ return immediately
│   ├─ local_alert_id valid?  │──NO──▶ return
│   └─ Extract src_ip from    │
│      clean_payload            │
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│ Query local SQLite:         │
│   SELECT id, title          │
│   FROM alerts               │
│   WHERE source = 'wazuh'    │
│     AND source_ip = :src_ip │
│     AND created_at >=       │
│       now() - 5 minutes     │
│   ORDER BY created_at DESC  │
│   LIMIT 1                   │
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│ Match found?                │
│   ├─ YES → Update Suricata  │
│   │   alert_metadata with:  │
│   │   - correlated_wazuh_alert_id
│   │   - correlated_wazuh_alert_title
│   │   → Also update DB      │
│   └─ NO → silently skip     │
└─────────────────────────────┘
```

**Purpose**: Links network-level Suricata detections ("SSH Brute Force Attack from IP X") with host-level Wazuh detections ("Multiple authentication failures from IP X") to provide correlated context.

---

## Field Transformation: Raw ES → SQLite

| Raw ES Field | SQLite Column | Notes |
|-------------|---------------|-------|
| `rule.name` | `title` | Fallback: rule.description, full_log[:100] |
| `full_log` / `rule.description` | `description` | Truncated 2000 chars |
| `rule.level` | `severity` | 1-3→low, 4-6→medium, 7-9→high, 10-15→critical |
| `agent.name` | `hostname` | Wazuh agent name |
| `rule.groups` | `category` | auth→authentication, malware→malware, syscheck→system |
| `data.srcip` / `src_ip` / regex from `full_log` | `source_ip` | Extracted via ip_extractor |
| `data.dstip` / `dst_ip` | `dest_ip` | Extracted via ip_extractor |
| `@timestamp` | `event_time` | ISO normalized |
| `_id` | `source_id` | ES doc ID |
| `rule.id` | `tags` | Included in tags list |
| `mitre.id` / `mitre.tactic` | `tags` | mitre technique/tactic tags |
| `syscheck` / `data.win.eventdata.hashes` | `iocs` (JSON) | Hash IOCs for file integrity |
| upstream `alert_id` | `external_id` | Set after forward |

---

## Wazuh Incident Creation Decision Tree

```
Wazuh alert arrives at incident_manager
    │
    ▼
┌────────────────────────────────────┐
│ Noise? (ICMP/ping/NTP)            │──YES──▶ NEVER create
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Critical severity (level 10-15)?   │──YES──▶ CREATE
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ ssh_brute_force keywords?          │──YES──▶ CREATE
│ (authentication failed, failed    │
│  password, invalid user, max      │
│  authentication attempts)         │
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ malware keywords?                  │──YES──▶ CREATE
│ (malware detected, trojan, virus) │
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Kill chain (2+ MITRE phases)?      │──YES──▶ CREATE
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ High + MITRE?                      │──YES──▶ CREATE
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ syscheck file integrity + high?    │──YES──▶ CREATE
│ (critical file changed)           │
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Medium no context?                 │──▶ Need 2+ same key in 15min
└────────────────────────────────────┘
    │ NO / insufficient
    ▼
┌────────────────────────────────────┐
│ Low / routine system events        │──▶ NEVER create
└────────────────────────────────────┘
```

---

## Code Reference Index

| Phase | File | Key Function | Line ~ |
|-------|------|--------------|--------|
| Poll | `pipeline/poller/main.py` | `poll_source()` | 40 |
| Cursor | `pipeline/poller/cursor_manager.py` | `_get_cursor()` | 15 |
| Seen IDs | `pipeline/poller/seen_ids.py` | `_is_ever_seen()` | 20 |
| Map | `pipeline/mappers/wazuh.py` | `map_wazuh_alert()` | 15 |
| Validate | `pipeline/mappers/wazuh.py` | `_validate_wazuh_doc()` | 80 |
| Severity | `pipeline/mappers/severity.py` | `_map_wazuh_severity()` | 30 |
| IP Extract | `pipeline/mappers/ip_extractor.py` | `_extract_wazuh_ips()` | 20 |
| Category | `pipeline/mappers/wazuh.py` | `_categorize_wazuh_alert()` | 200 |
| Sigma | `pipeline/enrichment/sigma.py` | `is_noise_alert()` | 186 |
| Process | `pipeline/poller/alert_processor.py` | `process_single_alert()` | 198 |
| Link | `pipeline/poller/alert_processor.py` | `_link_suricata_to_wazuh()` | 148 |
| Persist | `pipeline/poller/alert_processor.py` | `_persist_alert_local()` | 89 |
| Incident | `pipeline/datausage/incident_manager.py` | `process_alert()` | 1259 |
| IPS | `api/routes/ips.py` | `_alert_to_event()` | 140 |
| Watcher | `response/watcher/main.py` | `watch_incidents()` | 50 |
| Context | `response/watcher/context_builder.py` | `_build_investigation_context()` | 100 |
