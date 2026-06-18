# Falco Alert Lifecycle — Complete Pipeline Trace

> **Document**: End-to-end trace of every Falco alert from Elasticsearch ingestion to IPS map display  
> **Source**: `pipeline/poller/main.py` → `api/routes/ips.py`  
> **Last Updated**: April 20, 2026

---

## High-Level Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 0: ELASTICSEARCH SOURCE                               │
│  Index: falco-events-*  │  Query: @timestamp > cursor ONLY (no source-specific filters) │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 1: POLLER (every 10s)                                 │
│  File: pipeline/poller/main.py :: poll_source("falco", "falco-events-*")               │
│  ├─ _get_cursor("falco") → Redis → disk file → fallback: now-24h                      │
│  ├─ ES search: @timestamp > cursor, sort asc, batch 50                                  │
│  ├─ Per hit: _is_ever_seen(es_id)? → skip                                               │
│  └─ process_single_alert(es_id, source_doc, "falco", mapper, ts)                        │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 2: MAPPING & FILTERING                                │
│  File: pipeline/mappers/falco.py :: map_falco_alert()                                   │
│                                                                                          │
│  VALIDATION: _validate_falco_doc()                                                      │
│    ├─ Requires: priority, rule, output                                                  │
│    ├─ Rejects Wazuh cross-contamination (manager/agent + full_log)                      │
│    └─ Validates priority against: emergency, alert, critical, error, warning,           │
│        notice, info, informational, debug                                               │
│                                                                                          │
│  FIELD EXTRACTION:                                                                      │
│    ├─ rule → title (truncated 200), rule_name (truncated 100)                           │
│    ├─ output → description (truncated 2000)                                             │
│    ├─ priority → severity via _map_falco_severity()                                     │
│    ├─ hostname → hostname (default "unknown")                                           │
│    ├─ output_fields → iocs, observables, metadata (deep extraction)                     │
│    ├─ tags → tags + falco-priority-{priority}                                           │
│    └─ @timestamp/time/timestamp → event_time                                            │
│                                                                                          │
│  IP EXTRACTION: _extract_falco_ips()                                                    │
│    1. doc["source_ip"] / doc["dest_ip"]                                                 │
│    2. Regex from output field                                                           │
│    3. Scan output_fields values for IP strings                                          │
│    → Often returns (None, None) for pure container events                               │
│                                                                                          │
│  CONTAINER/K8S METADATA: _build_metadata()                                              │
│    ├─ container_id, container_name, container_image, container_image_tag                │
│    ├─ pod_name, namespace, k8s_cluster                                                  │
│    ├─ process_name, process_cmdline, process_exepath, process_parent                    │
│    ├─ user_name, user_uid                                                               │
│    ├─ fd_type, fd_lport, fd_rport                                                       │
│    ├─ event_type (evt.type)                                                             │
│    └─ falco_source, falco_uuid                                                          │
│                                                                                          │
│  IOCS: _build_iocs()                                                                    │
│    ├─ ip: [src_ip, dst_ip]                                                              │
│    ├─ container_id: from output_fields["container.id"]                                  │
│    ├─ process: from proc.name / proc.cmdline                                            │
│    └─ filepath: from fd.name                                                            │
│                                                                                          │
│  OBSERVABLES: _build_observables()                                                      │
│    ├─ type: ip, container_id, process, user, filepath, container_image                  │
│                                                                                          │
│  SEVERITY MAPPING: _map_falco_severity()                                                │
│    emergency/alert/critical → critical                                                  │
│    error → high                                                                           │
│    warning/notice → medium                                                               │
│    info/informational/debug → low                                                        │
│                                                                                          │
│  SIGMA NOISE FILTER: is_noise_alert("falco", doc)                                       │
│    ├─ NEVER filter: critical/high severity, attack patterns, threat intel               │
│    ├─ noise_falco.yml: Unexpected UDP Traffic                                           │
│    ├─ noise_falco_low_severity.yml: Delete shell history, Cron jobs,                    │
│    │   User mgmt binaries, Package repo updates, Read ssh info,                         │
│    │   Change thread namespace, Read sensitive file, Modify binary dirs                  │
│    └─ noise_falco_container.yml: Launch Sensitive Mount, Launch Capable Container       │
│                                                                                          │
│  MITRE ENRICHMENT: enrich_with_mitre()                                                  │
│    └─ container escape → T1611 Privilege Escalation                                     │
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
│    ├─ enrich_alert() → GeoIP (if IP present)                                            │
│    └─ track_alert() → campaign detection                                                │
│                                                                                          │
│  PERSIST: _persist_alert_local("falco", es_id, clean_payload)                           │
│    ├─ Check: SELECT id FROM alerts WHERE source="falco" AND source_id=es_id             │
│    ├─ Insert: Alert(...) → source_ip may be NULL                                        │
│    └─ Returns: local_alert_id (UUID)                                                    │
│                                                                                          │
│  FORWARD DECISION:                                                                      │
│    ├─ Pattern exists? → _handle_repeated_alert() → PATCH occurrences-N tag             │
│    └─ New alert → client.send_alert(clean_payload) → POST /webhooks/alerts             │
│         ├─ 422 → duplicate, update local external_id                                    │
│         ├─ Success → extract upstream_alert_id                                          │
│         └─ Background task: _process_alert_data_usage()                                  │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 4: DATA USAGE ORCHESTRATOR                            │
│  File: pipeline/datausage/orchestrator.py :: process_alert()                            │
│                                                                                          │
│  STAGE 1: Observables                                                                   │
│    └─ auto_create_from_alert() → container_id, process, user, filepath observables      │
│                                                                                          │
│  STAGE 2: AI Triage                                                                     │
│    └─ smart_triage_and_apply() → LLM triage for medium/high severity                    │
│                                                                                          │
│  STAGE 3: Incident Management                                                           │
│    └─ process_incident() → DECISION TREE:                                               │
│         CORRELATION KEY (Falco-aware hierarchy):                                        │
│           1. source_ip → 2. hostname → 3. container_id → 4. container_name              │
│           5. agent_name → 6. alert_id → 7. unknown                                     │
│         → Falco alerts WITHOUT IPs can still create incidents via hostname/container    │
│                                                                                          │
│         DECISION:                                                                       │
│           ├─ Noise (ICMP/ping) → NEVER                                                  │
│           ├─ Critical severity → ALWAYS                                                 │
│           ├─ Attack pattern → ALWAYS (container_escape triggers via keywords)           │
│           ├─ Kill chain (2+ MITRE) → ALWAYS                                             │
│           ├─ High + MITRE → ALWAYS                                                      │
│           ├─ Medium + high-risk → ALWAYS                                                │
│           ├─ Medium no context → needs 2+ alerts same key within 15 min                │
│           └─ Low → NEVER                                                                │
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
│  ├─ _build_investigation_context(incident, full_alerts)                                 │
│  │   → Falco-specific: detects "container_escape" behavioral indicator                  │
│  │   → If Falco ratio ≥ 30% and container_escape > 0 → boosted score                    │
│  │   → Extracts container_id, container_image into IOCs                                 │
│  ├─ Create Investigation: status="pending"                                              │
│  │   → target_host: hostname → dest_ip → source_ip → settings → localhost              │
│  └─ _run_ai_engine() → LLM playbook with container context                              │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 6: IPS ATTACK MAP                                     │
│  File: api/routes/ips.py                                                                 │
│                                                                                          │
│  CRITICAL GATE: _alert_to_event()                                                       │
│    ├─ source_ip must be present → MANY Falco alerts are NULL here                       │
│    ├─ is_private_ip(source_ip)? → skip                                                  │
│    └─ → Falco alerts with NO external IP are INVISIBLE on the map                       │
│                                                                                          │
│  Falco alerts that DO appear:                                                           │
│    ├─ "Unexpected UDP Traffic" (if IP extracted from output)                            │
│    ├─ "Contact EC2 Metadata" (if network fields present)                                │
│    └─ Any rule with src_ip/dst_ip in output_fields                                      │
│                                                                                          │
│  Category on map: "falco" (from alert.source)                                           │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Falco-Specific Behaviors

### 1. No Source IP = No IPS Map

```
Falco container event (no network context)
    │
    ▼
┌─────────────────────────────┐
│ map_falco_alert()           │
│   └─ _extract_falco_ips()   │
│       ├─ source_ip = None   │
│       └─ dest_ip = None     │
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│ _persist_alert_local()      │
│   └─ source_ip = NULL       │
└─────────────────────────────┘
    │
    ▼
┌─────────────────────────────┐
│ _alert_to_event()           │
│   └─ source_ip is None?     │──YES──▶ return None (invisible)
└─────────────────────────────┘
```

**Result**: 648 Falco alerts in DB, but only a fraction appear on IPS map.

### 2. Container-Aware Correlation

```
Falco alert (no IP)
    │
    ▼
┌─────────────────────────────┐
│ _get_correlation_key()      │
│   1. source_ip → missing    │
│   2. hostname → "ghazi"     │──▶ USE THIS
│   3. container_id → "abc.." │
│   4. container_name → "app" │
└─────────────────────────────┘
    │
    ▼
Incident correlated by hostname/container
```

### 3. Noise Filtering Specific to Falco

```
Falco alert arrives
    │
    ▼
┌─────────────────────────────┐
│ sigma_is_noise("falco", doc)│
│                             │
│ Smart guardrails:           │
│   ├─ critical/high? → PASS  │
│   ├─ attack pattern? → PASS │
│   └─ threat intel? → PASS   │
│                             │
│ noise_falco.yml:            │
│   └─ "Unexpected UDP Traffic" → FILTER if low severity
│                             │
│ noise_falco_low_severity.yml│
│   ├─ "Delete shell history" → FILTER
│   ├─ "Schedule Cron Jobs"   → FILTER
│   ├─ "User mgmt binaries"   → FILTER
│   └─ "Read sensitive file"  → FILTER
│                             │
│ noise_falco_container.yml:  │
│   ├─ "Launch Sensitive Mount Container" → FILTER
│   └─ "Launch Excessively Capable Container" → FILTER
└─────────────────────────────┘
```

---

## Field Transformation: Raw ES → SQLite

| Raw ES Field | SQLite Column | Notes |
|-------------|---------------|-------|
| `rule` | `title`, `rule_name` | Truncated 200/100 chars |
| `output` | `description` | Truncated 2000 chars |
| `priority` | `severity` | emergency→critical, error→high, warning→medium, info→low |
| `hostname` | `hostname` | Defaults to "unknown" |
| `output_fields` | `alert_metadata` (JSON) | Container, process, user, fd metadata |
| `output_fields` | `iocs` (JSON) | container_id, process, filepath |
| `output_fields` | `observables` (JSON) | ip, container_id, process, user, filepath, container_image |
| `@timestamp` | `event_time` | ISO normalized |
| `_id` | `source_id` | ES doc ID |
| `tags` | `tags` (JSON) | Appended with `falco-priority-{priority}` |
| upstream `alert_id` | `external_id` | Set after forward |
| — | `source_ip` | Often NULL (container events) |
| — | `category` | Usually "other" (mapper sets from metadata or "other") |

---

## Falco Incident Creation Decision Tree

```
Falco alert arrives at incident_manager
    │
    ▼
┌────────────────────────────────────┐
│ Noise? (ICMP/ping)                │──YES──▶ NEVER create
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Critical severity?                 │──YES──▶ CREATE
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ container_escape keywords?         │──YES──▶ CREATE
│ (write below, read sensitive,    │
│  bpf program, unexpected conn,   │
│  contact ec2, contact metadata,  │
│  terminal shell, modify binary,  │
│  exec binary)                    │
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Attack pattern? (malware, c2,    │──YES──▶ CREATE
│  web_attack, ddos, etc.)         │
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Kill chain (2+ MITRE)?            │──YES──▶ CREATE
│ T1611 Privilege Escalation        │
│ (Escape to Host)                  │
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ High + MITRE?                      │──YES──▶ CREATE
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Medium + high-risk?                │──YES──▶ CREATE
└────────────────────────────────────┘
    │ NO
    ▼
┌────────────────────────────────────┐
│ Medium no context?                 │──▶ Need 2+ same key in 15min
└────────────────────────────────────┘
    │ NO / insufficient
    ▼
┌────────────────────────────────────┐
│ Low / container noise              │──▶ NEVER create
└────────────────────────────────────┘
```

---

## Code Reference Index

| Phase | File | Key Function | Line ~ |
|-------|------|--------------|--------|
| Poll | `pipeline/poller/main.py` | `poll_source()` | 40 |
| Map | `pipeline/mappers/falco.py` | `map_falco_alert()` | 13 |
| Validate | `pipeline/mappers/falco.py` | `_validate_falco_doc()` | 72 |
| Severity | `pipeline/mappers/severity.py` | `_map_falco_severity()` | 50 |
| IP Extract | `pipeline/mappers/ip_extractor.py` | `_extract_falco_ips()` | 52 |
| MITRE | `pipeline/enrichment/mitre.py` | `enrich_with_mitre()` | 30 |
| Sigma | `pipeline/enrichment/sigma.py` | `is_noise_alert()` | 186 |
| Process | `pipeline/poller/alert_processor.py` | `process_single_alert()` | 198 |
| Persist | `pipeline/poller/alert_processor.py` | `_persist_alert_local()` | 89 |
| Incident | `pipeline/datausage/incident_manager.py` | `process_alert()` | 1259 |
| Correlation | `pipeline/datausage/incident_manager.py` | `_get_correlation_key()` | 375 |
| IPS | `api/routes/ips.py` | `_alert_to_event()` | 140 |
| Watcher | `response/watcher/main.py` | `watch_incidents()` | 50 |
| Context | `response/watcher/context_builder.py` | `_build_investigation_context()` | 100 |
