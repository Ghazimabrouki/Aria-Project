# OpenSOAR / ARIA Backend — Complete Architectural Reference

> **Document Type:** Senior Architecture Review  
> **Scope:** Every feature, logic block, technique, and operational step from Elasticsearch ingestion to frontend display  
> **Version:** 2026-04-27  
> **Author:** AI Senior Architect  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture Overview](#2-system-architecture-overview)
3. [Data Sources — Elasticsearch](#3-data-sources--elasticsearch)
4. [Pipeline Layer — Ingestion & Forwarding](#4-pipeline-layer--ingestion--forwarding)
5. [Enrichment & Correlation](#5-enrichment--correlation)
6. [Local Storage — SQLite ORM](#6-local-storage--sqlite-orm)
7. [Incident Correlation Engine](#7-incident-correlation-engine)
8. [Response Intelligence Layer](#8-response-intelligence-layer)
9. [Approval Workflow](#9-approval-workflow)
10. [Ansible Execution Engine](#10-ansible-execution-engine)
11. [Fix Verification](#11-fix-verification)
12. [Archiving](#12-archiving)
13. [Performance Monitoring System](#13-performance-monitoring-system)
14. [API Layer — FastAPI](#14-api-layer--fastapi)
15. [WebSocket Real-Time Layer](#15-websocket-real-time-layer)
16. [Frontend Integration](#16-frontend-integration)
17. [Background Tasks & Scheduling](#17-background-tasks--scheduling)
18. [Operational Features](#18-operational-features)
19. [Complete Data Flow Diagrams](#19-complete-data-flow-diagrams)
20. [Configuration Reference](#20-configuration-reference)

---

## 1. Executive Summary

OpenSOAR (also known as ARIA — Adaptive Response Intelligence Automation) is a **security operations platform** that ingests security alerts from multiple sources hosted in Elasticsearch, applies AI-powered investigation, generates Ansible remediation playbooks, manages human or auto-approval workflows, executes fixes on target infrastructure, verifies remediation success, and archives resolved cases.

### Key Capabilities

| Capability | Description |
|-----------|-------------|
| **Multi-Source Ingestion** | Polls Wazuh, Suricata (via Filebeat), Falco, and Telegraf indices from Elasticsearch |
| **Alert Enrichment** | GeoIP resolution, MITRE ATT&CK mapping, Sigma noise filtering, campaign detection, whitelist checking |
| **Local-First Storage** | SQLite with SQLAlchemy 2.0 async ORM for alerts, incidents, investigations, and archives |
| **AI Investigation** | Multi-provider LLM support (NVIDIA NIM, Ollama, OpenAI, Anthropic, Google, OpenRouter) with rule-based fallback |
| **Incident Correlation** | Time-windowed correlation by source IP, hostname, container, attack pattern, and kill-chain progression |
| **Auto-Approval** | Four-tier decision system: static guardrails → static pass → dynamic learning → AI confidence scoring |
| **Ansible Remediation** | Dynamic playbook generation, SSH pre-check, syntax validation, ad-hoc execution |
| **Fix Verification** | Post-remediation Elasticsearch re-query to confirm alert recurrence stopped |
| **Performance Monitoring** | Telegraf metrics polling, anomaly detection (statistical + AI), auto-remediation for performance issues |
| **IPS Visualization** | Real-time geospatial attack map with animated paths, GeoIP enrichment, lifecycle tracking |
| **AI Assistant & Operator** | Natural-language querying across all data sources with action execution capability |

### Technology Stack

**Backend:**
- Python 3.12+, FastAPI (async), Uvicorn on port `8001`
- SQLite + `aiosqlite` + SQLAlchemy 2.0 async ORM
- Redis (`redis.asyncio`) for caching, deduplication, cursors, performance metrics
- Elasticsearch async client for alert source and verification queries
- Ansible subprocess execution for remediation
- `structlog` for structured logging
- `pydantic-settings` for configuration

**Frontend:**
- Next.js 16.2.0 with App Router
- React 19, TypeScript 5.7.3, Tailwind CSS v4.2.0
- shadcn/ui component system
- `swr` for data fetching, `recharts` for charts, `react-simple-maps` for IPS map
- Custom WebSocket provider for real-time updates

---

## 2. System Architecture Overview

### Deployment Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND (Port 3000)                           │
│  Next.js 16 Dashboard ──► lib/api.ts ──► HTTP/REST to localhost:8001       │
│                              │                                              │
│                              ▼                                              │
│                    WebSocket ws://localhost:8001/ws                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BACKEND API (Port 8001)                           │
│  FastAPI + 16 routers + WebSocketManager (investigations/performance/system)│
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    ▼                  ▼                  ▼
         ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
         │  Background  │   │   SQLite     │   │   Redis      │
         │   Tasks      │   │ investigations.db │   │  localhost:6379│
         │  (main.py)   │   │   (aiosqlite)│   │              │
         └──────────────┘   └──────────────┘   └──────────────┘
                    │
        ┌───────────┼───────────┬───────────────┐
        ▼           ▼           ▼               ▼
┌─────────────┐ ┌─────────┐ ┌──────────┐ ┌─────────────┐
│  Forwarder  │ │ Watcher │ │ Performance│ │   Retry     │
│  (ES poll)  │ │ (incident│ │  Poller   │ │   Queue     │
│             │ │  poll)   │ │           │ │             │
└──────┬──────┘ └────┬────┘ └─────┬─────┘ └─────────────┘
       │             │            │
       ▼             ▼            ▼
┌─────────────────────────────────────────────────────┐
│              ELASTICSEARCH (Port 9200)               │
│  wazuh-alerts-*  falco-*  filebeat-*  telegraf-*    │
└─────────────────────────────────────────────────────┘
```

### Process Isolation

The production deployment (`run_backend.sh`) runs the **API server** and **`main.py` (background tasks)** as **separate OS processes**. This ensures a crash in background tasks does not take down the HTTP API. Each background coroutine in `main.py` is wrapped in `_run_safe_task()`, which catches exceptions and restarts the individual task after a 5-second delay.

---

## 3. Data Sources — Elasticsearch

The system polls four categories of data from Elasticsearch:

### 3.1 Security Alert Indices

| Source | Index Pattern | Content | Mapper File |
|--------|--------------|---------|-------------|
| **Wazuh** | `wazuh-alerts-*` or `wazuh-*` | Host-based IDS alerts from Wazuh agents | `pipeline/mappers/wazuh.py` |
| **Falco** | `falco-*` or `falco-events-*` | Container runtime security alerts | `pipeline/mappers/falco.py` |
| **Suricata** | `suricata-*` or `filebeat-*` | Network IDS/IPS alerts (often embedded in Filebeat) | `pipeline/mappers/suricata.py` |
| **Filebeat** | `filebeat-*` | Generic beats data; specifically filters for Suricata `eve` alerts | `pipeline/mappers/filebeat.py` |

**Filebeat-Suricata Bridge:** The Filebeat mapper checks `fileset.name == "eve"` and `suricata.eve.event_type == "alert"`. If matched, it delegates to the Suricata mapper. This handles environments where Suricata logs ship through Filebeat rather than a dedicated `suricata-*` index.

### 3.2 Performance Metrics Index

| Source | Index Pattern | Content | Poller File |
|--------|--------------|---------|-------------|
| **Telegraf** | `telegraf-*` | System metrics: CPU, memory, disk, network, processes, load, netstat | `pipeline/performance_poller.py` |

**Telegraf Document Structure:**
```json
{
  "@timestamp": "2026-04-27T04:00:20+01:00",
  "measurement_name": "cpu",
  "tag": {
    "host": "ghazi",
    "deployment": "soc",
    "input": "cpu",
    "role": "control-plane"
  },
  "cpu": {
    "usage_idle": 85.5,
    "usage_user": 10.2,
    "usage_system": 3.1
  }
}
```

The hostname is stored in `tag.host` (keyword field). The poller queries this field to discover hosts and filter per-host metrics.

### 3.3 Elasticsearch Connection

**File:** `core/elasticsearch.py`

- **Loop-aware singleton:** `_client` is cached per asyncio event loop to prevent cross-loop errors.
- **SSL handling:** When `elasticsearch_use_ssl=false`, creates an `ssl.SSLContext` with `verify_mode=CERT_NONE` for self-signed certificates.
- **Retry:** `retry_with_backoff()` provides exponential backoff (base 1s, max 3 retries).
- **Circuit breaker:** `elasticsearch_circuit` (threshold=5, timeout=60s) in `core/circuit_breaker.py` protects against cascading ES failures.

---

## 4. Pipeline Layer — Ingestion & Forwarding

### 4.1 Main Forwarder Loop

**File:** `pipeline/poller/main.py`

**Entry point:** `run_forwarder(shutdown_event)` — called by `main.py` as a background task.

**Polling Strategy:**
1. **Source discovery:** Builds `index_patterns` dict from settings. Suricata is only added if `suricata_index_pattern != filebeat_index_pattern`.
2. **Parallel polling:** `asyncio.gather(*[poll_source(source, pattern) for ...])` polls all sources concurrently.
3. **Adaptive pacing:**
   - High volume (>20 alerts): sleep 1s
   - Normal volume (>0): sleep 3s
   - Idle: sleep `alert_poll_interval` (default 10s)

**Per-Source Polling (`poll_source`):**
1. Read cursor from Redis (`opensoar:cursor:{source}`) or file fallback (`{cursor_dir}/{source}.cursor`)
2. First-run: cursor = `now - first_run_lookback_hours` (default 24h)
3. Build ES query: `@timestamp > cursor` (+ Filebeat-specific filters for Suricata)
4. Sort by `@timestamp asc`, batch size = `es_batch_size` (default 50)
5. For each hit:
   - Skip if `_id` in seen-ids cache (`pipeline/poller/seen_ids.py`)
   - Call `process_single_alert()`
   - Update cursor to latest `@timestamp`
6. Persist cursor and seen-ids to disk

### 4.2 Alert Processing Pipeline

**File:** `pipeline/poller/alert_processor.py`

**Function:** `process_single_alert(es_id, source_doc, source, mapper, latest_ts) -> ProcessResult`

**Step-by-step logic:**

| Step | Logic | Files Involved |
|------|-------|----------------|
| 1. **Map** | Calls source-specific mapper or raw-doc fallback | `pipeline/mappers/*.py` |
| 2. **Set source_id** | `source_id = ES _id` | — |
| 3. **Deduplicate** | Checks Redis (`opensoar:dedup:{hash}`), memory cache, then local DB `Alert.dedup_key` within TTL | `pipeline/services/dedup.py` |
| 4. **Noise filter** | Sigma noise rules + auto-learned noise patterns | `pipeline/enrichment/sigma.py`, `pipeline/services/noise_learner.py` |
| 5. **Severity filter** | Skip if below `alert_min_severity` | `pipeline/mappers/severity.py` |
| 6. **GeoIP enrichment** | Resolves source/dest IPs to country, city, ASN, provider | `pipeline/enrichment/geoip.py`, `core/geoip.py` |
| 7. **MITRE mapping** | Adds `mitre-TXXXX` tags and `mitre_techniques` array | `pipeline/enrichment/mitre.py` |
| 8. **Campaign detection** | Tracks by dimensions (src IP, dst IP, username, hostname) to detect SSH brute-force, port scans, threat intel campaigns | `pipeline/services/correlator.py` |
| 9. **Whitelist check** | Skips if source/dest IP or hostname is whitelisted | `core/whitelist.py` |
| 10. **Persist local** | Inserts into SQLite `Alert` table | `response/models.py` |
| 11. **Link Suricata→Wazuh** | If Suricata alert, finds matching Wazuh alert by `source_ip` within 5 minutes | `_link_suricata_to_wazuh()` |
| 12. **Pattern tracking** | Groups repeated alerts by `(source, source_ip, rule_name)`, updates occurrence count instead of creating duplicates | `pipeline/poller/pattern_tracker.py` |
| 13. **Forward upstream** (optional) | If `upstream_enabled=True`, sends to OpenSOAR via `client.send_alert()` with 3 retries | `pipeline/sender.py` |
| 14. **Retry queue** | On upstream failure, adds to Redis-backed retry queue | `pipeline/retry_queue.py` |
| 15. **Data-usage pipeline** | Extracts observables, runs AI triage, correlates incidents | `pipeline/datausage/orchestrator.py` |
| 16. **WebSocket broadcast** | Broadcasts `alert_created` on `performance` channel | `api/websocket.py` |

### 4.3 Alert Mappers — Detailed Logic

#### Wazuh Mapper (`pipeline/mappers/wazuh.py`)

**Validation:** Requires `rule` and `agent` structures. Skips if `rule.level < 3`.

**Extraction:**
- `timestamp`: `timestamp` or `@timestamp`
- `title`: `rule.description`
- `hostname`: `agent.name`
- `IPs`: `data.srcip`, `data.dstip`, `full_log` regex extraction
- `category`: Derived from `rule.groups` and `rule.mitre` (brute-force, privilege-escalation, web-attack, reconnaissance, malware, dos, c2, exfiltration, threat-intel, authentication, network, system, other)
- `tags`: MITRE tactics from `rule.mitre.tactic`, techniques from `rule.mitre.technique/id`
- `IOCs`: Extracted from `data` fields
- `observables`: IP, hash, URL, domain scanning

**Sigma noise filter:** Applied before mapping completes. If filtered, returns `None`.

#### Falco Mapper (`pipeline/mappers/falco.py`)

**Validation:** Requires `priority`, `rule`, `output`.

**Extraction:**
- `hostname`: `hostname` or `output_fields.hostname`
- `container info`: `container.id`, `container.name`, `k8s.pod.name`, `k8s.ns.name`
- `process info`: `proc.name`, `proc.cmdline`, `proc.pid`, `proc.ppid`
- `user info`: `user.name`, `user.uid`
- `fd info`: `fd.name`, `fd.type`
- `IOCs`: container_id, process, filepath

**MITRE enrichment:** `enrich_with_mitre()` adds tactics based on rule name and output content.

#### Suricata Mapper (`pipeline/mappers/suricata.py`)

**Validation:** Extracts from `doc.suricata.eve.alert`.

**Noise filtering:**
- Skips signatures containing: `byte_jump`, `connection established`, `stream`, `window update`, `retransmission`, `duplicate ack`, `out of order`
- These are network noise, not security events.

**Severity mapping:**
- Category 1 → low
- Category 2 → medium
- Category 3 → high
- Category 4 → critical

**IPS-specific fields:**
- `ips_action`: `blocked` or `allowed` (from `alert.action` or `drop` event type)
- `attack_status`: `active` or `stopped`

**Metadata enrichment:**
- `signature_id`, `gid`, `rev`
- `flow`: src_ip, dest_ip, src_port, dest_port, protocol
- `http`: hostname, url, http_method, status, user_agent
- `dns`: query, rrtype, rcode
- `tls`: subject, issuer, fingerprint
- `fileinfo`: filename, magic, gaps

#### Generic Mapper (`pipeline/mappers/generic.py`)

**Purpose:** Fallback for unknown document formats.

**Technique:**
1. Scans document using `FIELD_MAPPINGS` for common field names (`source_ip`, `dest_ip`, `hostname`, `severity`, `title`, etc.)
2. Supports nested dot-notation field access
3. Detects source type from document content strings (`wazuh`, `falco`, `suricata`, `crowdstrike`, `aws_guardduty`)
4. Normalizes CrowdStrike severity (1-100) and AWS GuardDuty (0-10) to 0-10 scale

### 4.4 Deduplication Service

**File:** `pipeline/services/dedup.py`

**Logic:** `is_duplicate(source, payload) -> bool`

Generates source-specific dedup keys:

| Source | Dedup Key Formula |
|--------|-------------------|
| Wazuh | `source:agent_id:rule_id:src_ip` |
| Falco | `source:hostname:container_id:rule_name` |
| Suricata | `source:sig_id:src_ip:dst_ip:dst_port` |
| Filebeat | `source:threat_intel:rule_name` (groups threat intel by rule only) |

**Check order:**
1. Redis: `opensoar:dedup:{hash}` (TTL 5 minutes)
2. Memory cache: in-process dict (same TTL)
3. Local DB: `Alert.dedup_key` column, checked within TTL window

**Threat intel extended TTL:** For threat intel patterns, the dedup TTL is extended to prevent spam from the same indicator.

### 4.5 Sigma Noise Filter

**File:** `pipeline/enrichment/sigma.py`

**Logic:** `is_noise_alert(source, doc) -> bool`

1. Loads YAML Sigma rules from `config/sigma_rules/`
2. Supports operators: `contains`, `startswith`, `endswith`, `equals`, `regex`
3. **Smart exceptions (NEVER filter):**
   - Attack patterns: malware, brute force, exploit, SQLi, XSS, port scan, webshell
   - Critical/high severity
   - Threat intel indicators
4. Only filters true noise: low severity + repeated + no attack pattern

### 4.6 Noise Learner

**File:** `pipeline/services/noise_learner.py`

**Auto-learning logic:**
1. Tracks alert frequency by `source|title` in memory
2. When `count >= 10` within 1 hour AND `< 20%` are high/critical severity:
   - Auto-generates a noise rule
   - Stores in `data/artifacts/auto_noise_rules.json`
3. `is_auto_noise(payload)` checks generated rules before processing

### 4.7 Campaign Correlator

**File:** `pipeline/services/correlator.py`

**Logic:** `track_alert(alert) -> Optional[str]`

1. Tracks alerts by dimensions: `source_ip`, `dest_ip`, `username`, `hostname`
2. Campaign TTL: 24 hours
3. Minimum alerts for campaign: 3 (or 2+ sources)
4. Detected patterns:
   - `ssh_brute_force`: ≥5 auth failures from same source IP
   - `port_scan`: multiple destination ports from same source
   - `threat_intel_hit`: repeated threat intel indicators
   - `web_attack`: repeated web attack signatures
5. Returns campaign context string appended to alert description

### 4.8 Sender / OpenSOAR Client

**File:** `pipeline/sender.py`

**Class:** `OpenSOARClient` (singleton `client`)

**Authentication:**
- `authenticate()` → POST `/api/v1/auth/login`
- Stores Bearer token in memory
- `_auth_headers()` adds `x-webhook-signature` if `opensoar_webhook_secret` is configured

**Retry Logic (`_post_with_retry`):**
- `401 Unauthorized` → re-authenticate once, then retry
- `429 Too Many Requests` → exponential backoff with `Retry-After` header support (max 4 retries, base 2s)
- Timeout → retry up to `MAX_429_RETRIES`

**Key Methods:**
| Method | Endpoint | Purpose |
|--------|----------|---------|
| `send_alert(alert_data)` | `POST /api/v1/webhooks/alerts` | Primary alert submission |
| `forward_elastic_alert(payload)` | `POST /api/v1/webhooks/alerts/elastic` | Raw ES doc fallback |
| `create_alert(source, doc)` | — | Maps then sends |
| `list_alerts()` | `GET /api/v1/alerts` | Query upstream alerts |
| `list_incidents()` | `GET /api/v1/incidents` | Query upstream incidents |
| `create_incident(data)` | `POST /api/v1/incidents` | Create upstream incident |
| `link_alert_to_incident(...)` | `POST /api/v1/incidents/{id}/alerts` | Link alert to incident |

**Upstream Guard:** All upstream calls are guarded by `if not get_settings().upstream_enabled: return False/None`.

### 4.9 Retry Queue

**File:** `pipeline/retry_queue.py`

**Class:** `RetryQueue`

- Redis list key: `opensoar:alert_retry_queue`
- Max retries: 5
- Exponential backoff: `BASE_DELAY * (2 ** retry_count)` where base = 60s
- `add(alert, error, retry_count)` — LPUSH to Redis with serialized JSON
- `process_queue(process_func)` — iterates pending, checks `next_retry_at`, calls `process_func(alert)`, re-queues or drops on max retries
- `get_stats()` — pending count grouped by retry count

**Disabled in local mode:** When `upstream_enabled=False`, the retry queue loop sleeps forever instead of processing.

---

## 5. Enrichment & Correlation

### 5.1 GeoIP Enrichment

**File:** `pipeline/enrichment/geoip.py`  
**Core resolver:** `core/geoip.py`

**Primary source:** MaxMind GeoLite2-City.mmdb + GeoLite2-ASN.mmdb (`/opt/geoip/`)

**Fallback sources:**
- `ip-api.com` free API (async via `aiohttp`)
- `ipapi.co` API

**Enrichment fields added to alert:**
- `src-country-{XX}`, `dst-country-{XX}`
- `src-AS{number}`, `dst-AS{number}`
- `src-provider-{AWS/Azure/GCP/etc.}`, `dst-provider-{...}`
- `internal-source`, `internal-dest`

**Provider detection:**
1. Dynamic ASN keyword matching from GeoLite2-ASN
2. Hardcoded IP range fallbacks for AWS, Azure, DigitalOcean, Google Cloud, OVH, Hetzner
3. Cloud provider tags enable cloud-specific playbook tasks

**Cache:**
- In-memory `OrderedDict` (max 5000 entries)
- Disk-persisted to `data/artifacts/geoip_cache.json` with 7-day TTL
- Batch resolution: `async_resolve_ips(ips)` with semaphore (max 20 concurrent)

### 5.2 MITRE ATT&CK Mapping

**File:** `pipeline/enrichment/mitre.py`

**Dynamic mapping:** `dynamic_mitre_mapping(title, category, signature, description, rule_name, severity)`

1. Scores techniques by keyword overlap with alert text
2. Returns top 3 matching techniques with confidence scores (0.0–1.0)
3. `enrich_with_mitre(alert)` adds:
   - Tags: `mitre-TXXXX`
   - Field: `mitre_techniques` array with `{id, name, confidence}`

### 5.3 Threat Intel Tracking

During alert processing (`alert_processor.py`):
- `_is_threat_intel()` detects threat intel indicators in alert title/tags
- Adds unique IP counts to alert description for context
- `_THREAT_INTEL_IPS` tracks unique IPs per threat intel rule

---

## 6. Local Storage — SQLite ORM

### 6.1 Database Engine

**File:** `response/db.py`

- Engine: `sqlite+aiosqlite:///{DB_PATH}` (default `data/investigations.db`)
- `check_same_thread=False` for async compatibility
- `init_db()` creates all tables on startup
- `_migrate_db()` performs lightweight migrations (no Alembic)

### 6.2 ORM Models

**File:** `response/models.py` — 14 tables

| Model | Table | Key Fields | Relationships |
|-------|-------|------------|---------------|
| `Investigation` | `investigations` | `id` (UUID), `incident_id`, `local_incident_id`, `upstream_incident_id`, `status`, `ai_summary`, `ai_narrative`, `ai_risk`, `playbook_yaml`, `playbook_valid`, `target_host`, `target_user`, `source_ips`, `hostnames`, `mitre_tactics` | → `alerts` (InvestigationAlert), → `approval` (PlaybookApproval), → `run` (PlaybookRun), → `verification` (FixVerification) |
| `InvestigationAlert` | `investigation_alerts` | `investigation_id`, `alert_id`, `alert_json`, `severity`, `source`, `title` | → `investigation` |
| `PlaybookApproval` | `playbook_approvals` | `investigation_id` (unique), `decision`, `decided_by`, `decided_at`, `reason`, `edited_playbook` | → `investigation` |
| `PlaybookRun` | `playbook_runs` | `investigation_id` (unique), `status`, `output`, `exit_code`, `started_at`, `finished_at` | → `investigation` |
| `FixVerification` | `fix_verifications` | `investigation_id` (unique), `status`, `new_alerts_found`, `detail` | → `investigation` |
| `Archive` | `archives` | `investigation_id` (unique), `incident_id`, `full_context_json`, `source_ips`, `hostnames`, `mitre_tactics`, `severity`, `fix_status`, `archived_at` | — |
| `AssistantConversation` | `assistant_conversations` | `id`, `title`, `focus_entity_type`, `focus_entity_id` | → `messages` (AssistantMessage) |
| `AssistantMessage` | `assistant_messages` | `conversation_id`, `role`, `content`, `actions_json`, `sources_json` | → `conversation` |
| `Alert` | `alerts` | `external_id`, `source`, `source_id`, `title`, `description`, `severity`, `status`, `category`, `source_ip`, `dest_ip`, `hostname`, `rule_name`, `tags`, `iocs`, `observables`, `alert_metadata`, `event_time`, `dedup_key`, `whitelisted`, `occurrence_count` | → `incidents` (via AlertIncidentLink) |
| `Incident` | `incidents` | `external_id`, `correlation_key`, `severity`, `status`, `source_ips`, `hostnames`, `rule_ids`, `alert_ids`, `assigned_to`, `whitelisted`, `soar_actions` | → `alerts` (via AlertIncidentLink), → `investigations` |
| `AlertIncidentLink` | `alert_incident_links` | `alert_id`, `incident_id`, `correlation_confidence`, `correlation_reason` | → `alert`, → `incident` |
| `WhitelistEntry` | `whitelist_entries` | `type` (ip/subnet/domain), `value`, `label` | — |
| `OperatorRun` | `operator_runs` | `prompt`, `intent`, `playbook_yaml`, `risk_level`, `target_hosts`, `status`, `result_json`, `approval_id` | — |
| `OperatorSession` | `operator_sessions` | `id`, `title`, `created_at` | → `messages` (OperatorMessage) |
| `OperatorMessage` | `operator_messages` | `session_id`, `role`, `content`, `metadata_json` | → `session` |

### 6.3 Lightweight Migrations

**Function:** `response/db.py::_migrate_db()`

Idempotent schema changes by inspecting `PRAGMA table_info()`:

| Migration | Action |
|-----------|--------|
| `incidents.whitelisted` | `ADD COLUMN BOOLEAN DEFAULT 0` + index |
| `incidents.created_by` / `updated_by` | `ADD COLUMN VARCHAR(100)` |
| `investigations.remediation_mode` | `DROP COLUMN` (orphaned) |
| `investigations.created_by` / `updated_by` | `ADD COLUMN VARCHAR(100)` |
| `ix_investigations_incident_id` | Remove `UNIQUE` constraint (allows reinvestigation) |
| `investigations.local_incident_id` / `upstream_incident_id` | `ADD COLUMN VARCHAR(36)` + index |
| `incidents.correlation_key` | `ADD COLUMN VARCHAR(255)` + index |
| `alerts.occurrence_count` | `ADD COLUMN INTEGER DEFAULT 1` |

### 6.4 Full-Text Search (FTS5)

**File:** `response/search_fts.py`

- **Virtual tables:** `alerts_fts`, `incidents_fts`, `investigations_fts`, `archives_fts`
- **Tokenizer:** `porter unicode61` with `contentless_delete=1`
- **Triggers:** Auto-generated INSERT/UPDATE/DELETE triggers keep FTS5 synced with base tables
- **Query parser:** Supports quoted phrases, prefix `*`, NOT `-word`, `OR`/`AND`
- **Ranking:** BM25 with normalized relevance scores (0.0–1.0)
- **Fallback:** ILIKE queries when FTS5 is unavailable or corrupted

---

## 7. Incident Correlation Engine

### 7.1 Data-Usage Orchestrator

**File:** `pipeline/datausage/orchestrator.py`

**Function:** `process_alert(local_alert_id, alert_data, upstream_alert_id=None)`

Stages (all run for every alert after ingestion):

| Stage | File | Purpose |
|-------|------|---------|
| 1. Observables | `observable_manager.py` | Extract IOCs (IPs, domains, hashes, URLs, emails, hostnames, usernames, ports) from alert text and raw payload. Create upstream observables with caching. Auto-enrich with GeoIP, cloud provider, threat intel, MITRE. |
| 2. AI Triage | `ai_pipeline.py` | Local LLM summarize/triage/auto-resolve. `smart_triage_and_apply()` conditionally triages based on severity + MITRE tactics + campaign context. |
| 3. Incidents | `incident_manager.py` or `local_incident_manager.py` | Correlates alert into existing incident or creates new one. |
| 4. Alert Enrichment | `alert_manager.py` | Auto-updates status, determination, comments on upstream alert. |

### 7.2 Incident Manager (Upstream Mode)

**File:** `pipeline/datausage/incident_manager.py`

**Correlation key hierarchy (most specific to least):**
1. `source_ip + attack_pattern`
2. `source_ip`
3. `hostname`
4. `container_id`
5. `container_name`
6. `agent_name`
7. `alert_id` (fallback)

**Signals extracted:**
- MITRE tactics and techniques
- Cloud provider
- Campaign type (from campaign correlator)
- Country
- Attack pattern
- Kill chain progression
- High-risk tactics (lateral_movement, exfiltration, c2, impact)
- Spamhaus/CINS indicators

**Incident creation rules:**

| Condition | Action |
|-----------|--------|
| Noise alert | Never create |
| Critical severity | Always create |
| Attack pattern (ssh_brute_force, port_scan, malware, c2, web_attack, ddos) | Always create |
| Kill chain (2+ phases detected) | Always create |
| Spamhaus DROP list | Always create |
| High + MITRE technique | Always create |
| Medium + high-risk tactic | Always create |
| Medium without context | Requires 2+ recent alerts within 15 min |

**Severity escalation:** `calculate_incident_severity()` escalates based on kill chain completeness and multi-source detection.

**Incident deduplication:** `_find_or_update_existing_incident()` checks:
1. Local cache (30-minute window)
2. Upstream open incidents (same correlation key)
3. If found with lower severity, escalates upstream incident severity

### 7.3 Local Incident Manager (Local-Only Mode)

**File:** `pipeline/datausage/local_incident_manager.py`

- Pure SQLite incident correlation (no upstream API calls)
- Reuses all logic from `incident_manager.py`
- `_find_local_incident_by_correlation()` — matches by `source_ips` overlap or `hostnames` within correlation window
- `_escalate_local_incident()` — severity escalation in SQLite
- `_link_alert_to_local_incident_db()` — creates `AlertIncidentLink` M2M record
- `create_local_incident()` — inserts `Incident` model directly
- `run_local_correlation_cycle()` — background cycle promotes tracked correlation keys to incidents when thresholds met

### 7.4 Alert Manager

**File:** `pipeline/datausage/alert_manager.py`

- CRUD on upstream alerts: list, get, update, delete, bulk_update, claim
- Comments: add, edit
- `auto_enrich_comment()` — adds GeoIP, cloud provider, MITRE tactics/techniques, campaign context
- `auto_update_on_incident_link()` — changes status from `new` → `investigating`
- `_calculate_determination()`:
  - Noise → `benign`
  - High-risk MITRE → `malicious`
  - Spamhaus → `malicious`
  - Critical → `malicious`
  - Default → `unknown`
- `auto_set_determination()` — patches upstream alert if currently `unknown`
- `auto_resolve_on_incident_close()` — bulk resolves linked alerts

### 7.5 Action Executor

**File:** `pipeline/datausage/action_executor.py`

Auto-execution rules based on IOC type + severity + MITRE tactics:

| IOC Type | Conditions | Auto-Action |
|----------|-----------|-------------|
| IP | threat_intel or malicious_score≥70 | block / ban |
| Hostname | execution + persistence MITRE tactics | isolate / quarantine |
| File hash | malware indicator | quarantine / delete |
| Domain | malware / c2 / phishing | block / sinkhole |

### 7.6 Ticketing System

**Files:** `pipeline/datausage/ticketing/*.py`

**Models (`models.py`):**
- `Ticket`, `TicketHistory`, `TicketCreate`, `TicketUpdate`
- Statuses: `open` → `investigating` → `contained` → `resolved` → `closed`
- Priorities: `P1` (critical) to `P4` (low)

**Store (`store.py`):**
- SQLite at `data/artifacts/tickets.db` with WAL mode
- CRUD, history tracking, stats (avg resolution time, by-status/priority counts)

**Routing Rules (`routing_rules.py`):**
- **Auto-create:** critical/high severity, MITRE kill chain, cloud provider, campaign, multi-source
- **Skip:** AI benign determination, low severity without context
- **Assignment:**
  - initial-access → network-team
  - exfiltration → incident-response
  - privilege-escalation → endpoint-team
  - falco → container-team
  - cloud → cloud-team

**Lifecycle (`lifecycle.py`):**
- Valid state machine transitions
- Auto-escalate stale open tickets (>24h)
- Auto-resolve contained (>48h)
- Auto-close resolved (>7d)

---

## 8. Response Intelligence Layer

### 8.1 The Watcher — Incident Polling & Investigation Spawning

**File:** `response/watcher/main.py`

**Entry point:** `watch_incidents(shutdown_event)`

**Mode dispatch:**
- If `upstream_enabled=False` → `watch_local_incidents()`
- If `upstream_enabled=True` → polls upstream OpenSOAR for open incidents

**Upstream polling strategy:**
- **Fast scan every cycle:** fetches most recent 50 open incidents
- **Full scan every `FULL_SCAN_INTERVAL` (60 cycles ≈ 15 min):** paginates through ALL open incidents up to 1,000 offset

**Per-cycle maintenance (every cycle):**
1. `_retry_pending_investigations()` — retry stuck pending
2. `_execute_approved_investigations()` — execute approved ones missing a `PlaybookRun`
3. `_check_stuck_investigations()` — alert on stuck cases
4. `_recover_stuck_running_investigations()` — auto-recover hung Ansible

**Every 5 cycles:** `_refresh_existing_investigations(reader)` fetches new alerts for active investigations and re-runs AI if still `pending`.

**Local watcher (`watch_local_incidents`):**
1. Queries `Incident` table for `status="open"` where no `Investigation` exists
2. Fetches linked alerts via `AlertIncidentLink` or `incident.alert_ids`
3. Applies whitelist filtering and `incident_min_alerts` threshold
4. Calls `_build_investigation_context()` → `_create_investigation()` → `_store_alerts()` → `_run_ai_engine()`

### 8.2 Context Builder

**File:** `response/watcher/context_builder.py`

**Function:** `_build_investigation_context(incident, alerts)`

**Extraction:**
1. **IOCs:** `source_ips`, `dest_ips`, `hostnames`, `usernames`, `processes`, `file_paths`, `domains`, `hashes`, `ports`, `protocols`, `services`
2. **Timeline:** Sorted chronological list of all alerts
3. **Behavioral pattern detection** (keyword-based):
   - `auth_failure`, `auth_success`, `reconnaissance`, `execution`, `exfiltration`, `malware`, `web_attack`, `dos`, `privilege_escalation`, `container_escape`, `file_integrity`, `system_modification`, `lateral_movement`, `network_anomaly`
4. **Smart authentication analysis** (`_analyze_authentication_patterns()`):
   - Detects brute-force + success = compromised account
   - Flags ≥5 failures from same IP
   - Flags root access after failures
5. **Attack type determination** (`_determine_attack_type()`):
   - Multi-factor scoring using rule names, behavioral ratios, MITRE tactics, alert sources
   - Confidence thresholds: minimum score 3, must beat second place by 1.5× ratio
   - Fallback: `mixed` or `unknown`
6. **Risk score** (`_calculate_risk_score()`): 0–100 based on:
   - Severity weight
   - Attacker count (unique source IPs)
   - Target count (unique hostnames/dest IPs)
   - Alert volume
   - Duration of incident
   - Critical behaviors (privilege escalation, lateral movement, exfiltration)

### 8.3 AI Engine — Orchestrator

**File:** `response/ai_engine/main.py`

**Function:** `run_investigation(investigation_id, context)`

**Step-by-step:**

| Step | Action | Outcome on Failure |
|------|--------|-------------------|
| 1 | Set `status="pending"`, broadcast `ai_started` | — |
| 2 | Build prompt via `_build_prompt(context)` | — |
| 3 | Check circuit breaker (`can_proceed()`) | Wait and retry |
| 4 | Call `_call_llm(prompt)` with adaptive timeout | Fallback to rule-based |
| 5 | Parse response via `_parse_ai_response()` | Fallback |
| 6 | Validate YAML via `_validate_playbook()` | Fallback |
| 7 | Update DB: `ai_summary`, `ai_narrative`, `ai_risk`, `playbook_yaml`, `playbook_valid`, `status="awaiting_approval"` | — |
| 8 | Broadcast `ai_completed` | — |
| 9 | Attempt auto-approve: `apply_auto_approve(investigation_id)` | Human review |
| 10 | If not auto-approved, send approval notification | — |

**Fallback generation (`_generate_fallback_ai_result(context)`):**
- Rule-based summary from alert names/hosts/IPs
- Basic Ansible playbook: collect connections, auth failures, running processes, `iptables` DROP loop for source IPs
- Updates DB to `awaiting_approval` with fallback output

### 8.4 Prompt Builder

**File:** `response/ai_engine/prompt_builder.py`

**Function:** `_build_prompt(context)`

**Prompt structure:**
1. **Incident overview:** severity, risk score, attack type, MITRE tactics/techniques
2. **Complete timeline:** ALL events with timestamps
3. **All extracted IOCs:** IPs, hosts, usernames, ports, services, domains, file paths, hashes
4. **Behavioral analysis:** Per-behavior severity (CRITICAL/HIGH/MODERATE)
5. **Attack-type specific guidance:** 16 types with tailored remediation advice:
   - `brute_force`, `port_scan`, `web_attack`, `malware`, `exfiltration`, `dos`, `privilege_escalation`, `execution`, `container_escape`, `file_integrity`, `system_modification`, `lateral_movement`, `network_anomaly`, `mixed`, `unknown`
6. **Summary statistics:** unique attackers, targets, duration, primary method

**Required output format (exact headers):**
```
## INCIDENT SUMMARY
## ATTACK CHAIN ANALYSIS
## THREAT INTELLIGENCE
## RISK ASSESSMENT
## REMEDIATION PLAYBOOK
## VERIFICATION PROCEDURE
```

**Playbook constraints specified in prompt:**
- Valid Ansible YAML
- `become: yes`
- Use Jinja2 `{{ item }}`
- `ignore_errors: yes` where appropriate
- 4 phases: contain, harden, forensics, verify

### 8.5 LLM Client Routing

**File:** `response/ai_engine/llm_clients.py`

**Function:** `_call_llm(prompt)` routes by `settings.llm_provider`:

| Provider | Function | Endpoint | Notes |
|----------|----------|----------|-------|
| `google` | `_call_google(prompt)` | `generativelanguage.googleapis.com` | Gemini models, 3 retries, 429 handling |
| `openrouter` | `_call_openrouter(prompt)` | `openrouter.ai/api/v1` | DeepSeek, etc., 3 retries |
| `nvidia` | `_call_nvidia(prompt)` | `integrate.api.nvidia.com` | NIM models, 3 retries |
| `ollama` (default) | `_call_ollama(prompt)` | `{ollama_host}/api/generate` | Local models, adaptive timeout, 2 retries |

**Adaptive timeout:**
- Model-specific baselines: `qwen3:8b`=90s, `gemini-2.0-flash`=15s
- Prompt-length scaling: `10 * (1 + log10(1 + prompt_length/500))`
- Adjusts upward if average response exceeds baseline

### 8.6 Response Parser

**File:** `response/ai_engine/response_parser.py`

**Function:** `_parse_ai_response(text)`

1. Strips `<think>...</think>` blocks (DeepSeek-R1 chain-of-thought)
2. Extracts sections by regex using `_SECTION_HEADERS` (accepts primary + variant headers)
3. Extracts YAML playbook from ` ```yaml ... ``` ` fenced block; falls back to raw `---\n` match
4. Returns dict: `summary`, `narrative`, `threat_intel`, `risk`, `playbook_yaml`, `verification`

**Validation (`_validate_playbook(playbook_yaml)`):**
- Requires length ≥ 20
- Parses with `yaml.safe_load()`
- Accepts list of plays (each dict) or single dict

### 8.7 Adaptive System

**File:** `response/adaptive.py`

**Components:**

| Component | Purpose |
|-----------|---------|
| `AdaptiveConfig` | Bounds: timeout 30–120s, retry intervals 1–60s, concurrency 1–4 |
| `ErrorClassifier` | Categorizes: timeout, parse_error, network_error, validation_error, auth_error, not_found_error, rate_limit, unknown |
| `MetricsCollector` | Thread-safe async collection: response times (max 100), completed/failed counts, error counts by type, concurrent tracking, queue depth |
| `AdaptiveTimeout` | Model-specific baselines + prompt-length scaling + upward adjustment |
| `AdaptiveRetryRate` | Per-investigation retry tracking with error-specific backoff: timeout (exponential, max 6), network (linear, max 30s), parse (max 3), rate_limit (aggressive: 120×2^retry, max 50min), auth (never retry) |
| `CircuitBreaker` | States: closed → open (after 3 failures) → half-open (after 300s) → closed |
| `AdaptiveConcurrency` | Self-tuning semaphore: increases if avg <60s and success >0.7; decreases if avg >180s or success <0.5; requires 2 stabilization cycles |

**Safe fallback functions:** `get_timeout_safe()`, `get_retry_decision_safe()`, `record_response_safe()`, `record_error_safe()`

---

## 9. Approval Workflow

### 9.1 States & Transitions

**Investigation status lifecycle:**

```
                    ┌─────────────┐
                    │   pending   │◄────── AI engine running
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌─────────┐  ┌─────────┐  ┌─────────┐
        │approved │  │declined │  │awaiting_│
        │ (auto)  │  │         │  │approval │
        └────┬────┘  └────┬────┘  └────┬────┘
             │            │            │
             ▼            ▼            ▼
        ┌─────────┐  ┌─────────┐  ┌─────────┐
        │ running │  │archived │  │approved │
        │         │  │         │  │(human)  │
        └────┬────┘  └─────────┘  └────┬────┘
             │                         │
        ┌────┴────┐                    ▼
        ▼         ▼               ┌─────────┐
   ┌─────────┐ ┌─────────┐       │ running │
   │completed│ │ failed  │       └────┬────┘
   └────┬────┘ └────┬────┘            │
        │           │            ┌────┴────┐
        ▼           ▼            ▼         ▼
   ┌─────────┐ ┌─────────┐  ┌─────────┐ ┌─────────┐
   │archived │ │archived │  │completed│ │ failed  │
   │(fixed)  │ │(failed) │  └────┬────┘ └────┬────┘
   └─────────┘ └─────────┘       │           │
                                 ▼           ▼
                            ┌─────────┐ ┌─────────┐
                            │archived │ │archived │
                            │(fixed)  │ │(failed) │
                            └─────────┘ └─────────┘
```

**Allowed transitions (`_ALLOWED_TRANSITIONS`):**
```python
{
    "pending": ["awaiting_approval", "approved", "declined", "running", "failed"],
    "awaiting_approval": ["approved", "declined", "running"],
    "approved": ["running", "failed"],
    "running": ["completed", "failed"],
    "completed": ["archived"],
    "failed": ["archived", "pending"],
    "declined": ["archived"],
}
```

### 9.2 Auto-Approve Logic

**File:** `response/auto_approve.py`

**Function:** `should_auto_approve(investigation_id) -> AutoApproveResult`

**Decision cascade:**

1. **Static Guardrails** (`_check_guardrails()`):
   - Blocks if severity in `auto_approve_block_severities` (default: `["critical"]`)
   - Blocks if risk score > `auto_approve_block_risk_score` (default: 75)
   - Blocks if attack type in `auto_approve_block_attack_types` (ransomware, c2, data_exfiltration, privilege_escalation, lateral_movement)
   - `_check_suspicious_auth_patterns()`: blocks if brute force + successful login detected (compromised account)

2. **Static Pass** (`_check_static_pass()`):
   - Auto-approves if severity in `auto_approve_severities` (default: `["low"]`)
   - AND risk ≤ `auto_approve_max_risk_score` (default: 25)
   - AND alert count ≤ `auto_approve_max_alerts` (default: 10)

3. **Dynamic Learning** (`_check_dynamic()`):
   - Delegates to `confidence_tracker.get_approval_recommendation()`
   - Uses historical success rates by severity and risk score thresholds
   - Requires ≥10 approvals before adapting

4. **AI Confidence** (`_check_ai_confidence()`):
   - Scores 0.0–1.0:
     - Playbook validity: +0.25
     - Playbook completeness (4 phases): +0.25
     - Risk level (lower = better): +0.30
     - Summary quality (non-fallback): +0.20
   - Auto-approve threshold: ≥`auto_approve_ai_threshold` (default 0.85)
   - High-priority queue threshold: ≥`auto_approve_ai_high_priority_threshold` (default 0.50)
   - Critical severity always blocked

5. **Default:** Requires human review.

**Application (`apply_auto_approve(investigation_id)`):**
- If approved: updates `status="approved"`, spawns `execute_playbook(investigation_id)` as background task, sends auto-approve notification
- If not approved: returns without action

### 9.3 Confidence Tracker

**File:** `response/confidence_tracker.py`

- `record_approval_decision(...)`: Stores decisions to `data/artifacts/approval_history.json` (max 1,000)
- `_recalculate_adaptive_thresholds()`:
  - >90% approval rate → threshold +10
  - >70% → threshold +5
  - <50% → threshold –5
- `get_approval_recommendation(severity, risk_score, attack_type, alert_count)`:
  - Looks at similar historical investigations (same severity, risk within ±20)
  - If risk < adaptive threshold and success rate > 0.7 → recommend approve
  - If risk > threshold or success rate < 0.5 → recommend block

### 9.4 Decision Logger

**File:** `response/decision_logger.py`

- `log_approval_decision(...)`: Appends to `data/artifacts/decision_log.json` (max 5,000) with timestamp, decision, reason, source, confidence, metadata
- `log_execution_result(...)`: Finds prior decision entry and adds `execution_result`, `exit_code`, error
- `get_decision_history()` / `get_decision_stats()`: Query and aggregate

---

## 10. Ansible Execution Engine

### 10.1 Execution Flow

**File:** `response/ansible_exec.py`

**Function:** `execute_playbook(investigation_id)`

**Step-by-step:**

| Step | Action | Details |
|------|--------|---------|
| 1 | Load investigation + approval | Edited playbook takes precedence over original |
| 2 | Host replacement | Extracts `hosts:` value from AI playbook, replaces with `target` to match inventory group `[target]` |
| 3 | Jinja2 fixes | Aggressive regex fixes for broken `loop:` values (`{ item }` → `{{ item }}`), especially `iptables` `source:`/`destination:` |
| 4 | Validation | `yaml.safe_load()` + `_validate_ansible_syntax()` runs `ansible-playbook --syntax-check` in temp file |
| 5 | Whitelist check | Blocks execution if `target_host` is whitelisted |
| 6 | Dry-run mode | If `ANSIBLE_ENABLED=false`, writes `PlaybookRun(status="skipped")` and triggers fix verifier |
| 7 | SSH pre-check | `_test_ssh_connection()` tests connectivity: password auth via `sshpass` if available, falls back to key-based. Categorizes errors: auth_failed, connection_refused, host_unreachable, dns_failed. On auth failure, sets investigation back to `pending` with credential error |
| 8 | Write files | Playbook to `PLAYBOOKS_DIR/{id}.yml`, inventory to `{id}_inventory` with `[target]` group, SSH opts, become method/pass. Writes `ansible.cfg` with `host_key_checking=False`, pipelining |
| 9 | Run Ansible | `ansible-playbook -i inventory playbook -v` via `asyncio.create_subprocess_exec`. Pipe limit 1MB, reads stdout in 64KB chunks. Timeout = `settings.ansible_timeout` |
| 10 | Exit code analysis | `0`→completed, `-15`→failed (timeout), `-9`→failed (killed), `>0`→analyzes output for Permission denied, Connection refused, UNREACHABLE, FAILED |
| 11 | Update DB | `PlaybookRun` and `Investigation.status` |
| 12 | Broadcast | WebSocket broadcast of execution completion |
| 13 | Trigger fix verifier | Calls `verify_fix()` regardless of success or failure |

### 10.2 Inventory Resolution

**File:** `api/routes/operator.py` (shared helper)

- `_resolve_target_from_inventory(alias)` — reads `config/ansible_inventory` to resolve host alias
- `_get_first_target_from_inventory()` — returns first host from inventory

**Inventory format written per-investigation:**
```ini
[target]
193.95.30.97 ansible_user=ghazi ansible_port=22

[target:vars]
ansible_become_method=sudo
ansible_ssh_private_key_file=/path/to/key
```

---

## 11. Fix Verification

### 11.1 Verification Flow

**File:** `response/fix_verifier.py`

**Function:** `verify_fix(investigation_id)`

**Step-by-step:**

| Step | Action |
|------|--------|
| 1 | Load investigation + alerts + playbook run |
| 2 | `_query_es_for_recurrence(alert_snapshots, run_finished_at)` |
| 3 | Extract rule names and source IPs from stored `InvestigationAlert.alert_json` |
| 4 | Query Elasticsearch `count` on `wazuh-*`, `falco-*`, `filebeat-*` for alerts in time window after playbook finished |
| 5 | Return `(new_alert_count, detail_string)` |
| 6 | `_active_verify_remediation(inv)` |
| 7 | Check if same source IPs still generating alerts in last 5 minutes |
| 8 | Check if target host still has recent alerts |
| 9 | Return `{"success": bool, "detail": str}` |
| 10 | **Verdict logic:** |

**Verdict matrix:**

| Playbook Result | New Alerts | Active Verification | Verdict |
|----------------|------------|---------------------|---------|
| Failed | 0 | — | `playbook_failed_but_quiet` |
| Failed | >0 | — | `playbook_failed_problem_worse` |
| Success | 0 | Passed | `likely_fixed` |
| Success | 1–2 | Passed | `inconclusive` |
| Any | >2 or failed | — | `not_fixed` |

| 11 | Save `FixVerification` record |
| 12 | Post comment to upstream incident (if enabled) |
| 13 | Call `archive_investigation(investigation_id, fix_status)` |

---

## 12. Archiving

### 12.1 Archive Flow

**File:** `response/archiver.py`

**Function:** `archive_investigation(investigation_id, fix_status="unknown")`

**Step-by-step:**

| Step | Action |
|------|--------|
| 1 | Skip if `Archive` already exists for this investigation |
| 2 | Load full investigation with `alerts`, `approval`, `run`, `verification` via `selectinload` |
| 3 | Load linked local `Incident` |
| 4 | `_build_full_context(inv, incident)` |
| 5 | Parse all `InvestigationAlert.alert_json` strings back to objects |
| 6 | Assemble giant dict: `investigation`, `alerts`, `approval`, `playbook_run`, `fix_verification`, `incident`, `archived_at` |
| 7 | Serialize to JSON string |
| 8 | Create `Archive` row with denormalized index fields (`source_ips`, `hostnames`, `mitre_tactics`, `severity`, `fix_status`) |
| 9 | Update `Investigation.status="archived"` |
| 10 | Update local `Incident`:
|    | - `status="archived"` (or `"resolved"` if fix was `likely_fixed`/`verified`) |
|    | - `resolved_at`, `resolved_by="auto"` |
|    | - Append `soar_actions["archive_summary"]` with investigation ID, fix status, playbook run summary |

---

## 13. Performance Monitoring System

### 13.1 Performance Poller

**File:** `pipeline/performance_poller.py`

**Class:** `PerformancePoller`

**Polling cycle (`poll_once()`):**
1. Get cursor (looks back 5 minutes on first run)
2. `_get_hosts_from_telegraf()` — aggregation on `tag.host` in `telegraf-*` index, `now-1h`
3. For each host, query in parallel:
   - **CPU:** `measurement_name=cpu`, calculates `100 - usage_idle`
   - **Memory:** `measurement_name=mem`, extracts `used_percent`, `used`, `available`
   - **Disk:** `measurement_name=disk`, per-device `used_percent`, `used`, `free`, `inodes_used_percent`
   - **Network:** `measurement_name=net`, `bytes_recv`, `bytes_sent`
   - **Processes:** `measurement_name=processes`, running/sleeping/total/total_threads
   - **System:** `measurement_name=system`, load1/load5/load15, n_cpus
   - **Netstat:** `measurement_name=netstat`, tcp_established/tcp_listen/udp_socket
   - **Procstat:** `measurement_name=procstat`, top 15 processes by CPU (skips kernel threads by checking `cmdline`)
   - **Disk directories:** `measurement_name=disk_dir`, directory sizes from `du -sh`
4. Data freshness thresholds:
   - Fresh: ≤5 minutes old
   - Stale: >10 minutes old → skipped
5. Store in `_host_metrics_cache`

### 13.2 Performance Orchestrator

**File:** `pipeline/datausage/performance_orchestrator.py`

**Function:** `run_performance_monitoring_cycle()`

1. Poll metrics → `PerformancePoller.poll_once()`
2. Store metrics in Redis → `performance_redis.store_current_metrics()`
3. Append scalar history (CPU, memory, disk, network, load) → `performance_redis.append_to_history()`
4. Detect anomalies → `AnomalyDetector.detect_all()`:
   - CPU threshold + statistical (stddev from Redis baseline)
   - Memory threshold + statistical
   - Disk threshold (usage % and inodes %)
   - Load normalized >2.5 (warning) / >4.0 (critical)
   - Network rate computed from Redis history
5. Check cooldown → `detector.should_create_alert()`
6. Root cause analysis → `analyze_performance_root_cause()` (calls local LLM)
7. Generate alert → `performance_alert_generator.generate_alert()`
8. Broadcast via WebSocket
9. Send to upstream → `_send_alert_to_opensoar()` (best effort, guarded by `upstream_enabled`)
10. Create local investigation → `_create_performance_investigation()` (if `auto_remediable`)
11. Set cooldown

### 13.3 Dynamic Playbook Generator

**File:** `pipeline/response/dynamic_playbook.py`

**Function:** `generate_dynamic_playbook(context, root_cause_result)`

**Context:** host, anomaly_type, current_value, threshold, remediation_type, affected_process, evidence, top_processes, disk_device/path

**Remediation type mappings:**

| Remediation Type | Task Generator |
|-----------------|----------------|
| `restart_service` | Process-specific: nginx, apache, redis, java, mysql, postgres, generic |
| `clear_memory` | Page cache clear, slab clear, Redis flush |
| `clean_logs` / `temp` / `resize_disk` | Disk cleanup: logs, temp, docker, apt |
| `scale` | CPU tasks + scaling checks |
| `investigate` | System info gathering |

**Output:** Valid Ansible YAML with `hosts: target`, `become: yes`

### 13.4 Performance Redis Storage

**File:** `core/redis_performance.py`

**Class:** `PerformanceRedis`

| Method | Purpose |
|--------|---------|
| `store_current_metrics(host, metrics)` | Hash storage, 5-min TTL |
| `get_current_metrics(host)` | Retrieve current metrics |
| `get_all_current_metrics()` | Scan all hosts |
| `append_to_history(host, metric_name, value)` | LPUSH with LTRIM (max 1000), 2-day TTL |
| `get_history(host, metric_name, limit)` | Retrieve historical values |
| `update_baseline(host, metric_name)` | Calculate mean, std, p95, p99 from 24h history |
| `get_baseline(host, metric_name)` | Retrieve baseline |
| `set_alert_cooldown(host, alert_type)` / `is_in_cooldown(host, alert_type)` | Prevent alert spam |
| `store_alert(alert)` / `get_alert_history(host, severity, limit)` | Sorted set by timestamp |

### 13.5 Performance Watcher

**File:** `pipeline/datausage/performance_watcher.py`

- Tracks performance incidents in Redis (`performance_incidents`)
- `check_incident_resolution(incident_id)` — re-polls metrics, checks if CPU/memory/disk back below critical thresholds
- `cleanup_resolved_incidents(max_age_hours=24)`
- Runs every 60 seconds

---

## 14. API Layer — FastAPI

### 14.1 Application Factory

**File:** `api/app.py`

- **Lifespan:** `init_db()` on startup
- **CORS:** `allow_origins=["*"]` (all origins), credentials allowed
- **14 routers registered:** investigations, archives, assistant, adaptive, alerts, incidents, monitoring, pipeline, search, dashboard, ips, performance, whitelist, operator, approval_ui, websocket

### 14.2 Route Modules Summary

| Router | Prefix | Key Endpoints |
|--------|--------|---------------|
| `alerts.py` | `/api/v1/alerts` | `GET /`, `GET /{id}`, `PATCH /{id}/archive` |
| `incidents.py` | `/api/v1/incidents` | `GET /`, `POST /manual`, `GET /{id}`, `GET /{id}/alerts`, `GET /{id}/timeline`, `PATCH /{id}` |
| `investigations.py` | `/api/v1/investigations` | `GET /`, `POST /manual`, `GET /stats`, `GET /{id}`, `PATCH /{id}/playbook`, `POST /{id}/execute`, `POST /{id}/approve`, `POST /{id}/decline`, `POST /{id}/archive`, `GET /{id}/run-status`, `GET /{id}/timeline` |
| `archives.py` | `/api/v1/archives` | `GET /`, `GET /stats`, `GET /{id}`, `GET /{id}/original-incident`, `GET /by-investigation/{id}` |
| `assistant.py` | `/api/v1/assistant` | `POST /query`, `POST /actions`, `GET /conversations`, `GET /context`, `GET /sources` |
| `approval_ui.py` | `/` | `GET /approve/{id}` — HTML approval page |
| `dashboard.py` | `/api/v1/dashboard` | `GET /summary`, `GET /quick-stats`, `GET /trends` |
| `monitoring.py` | `/monitor` | `GET /stats`, `GET /health`, `GET /pipeline-health`, `GET /services-status`, `GET /stuck-investigations`, `GET /execution-stats`, `POST /reset-cursor/{source}` |
| `pipeline.py` | `/api/v1/pipeline` | `GET /status`, `GET /sources`, `GET /cursors`, `GET /trace/alert/{id}`, `GET /stats` |
| `search.py` | `/api/v1/search` | `GET /`, `GET /ips/{ip}`, `GET /domains/{domain}` |
| `ips.py` | `/api/v1/ips` | `GET /map-data`, `GET /events`, `GET /statistics`, `POST /event`, `POST /events/bulk` |
| `performance.py` | `/api/v1/metrics` | `GET /dashboard`, `GET /hosts`, `GET /{host}`, `GET /{host}/history`, `GET /{host}/root-cause`, `GET /{host}/disk-analysis` |
| `adaptive.py` | `/adaptive` | `GET /status`, `GET /metrics`, `POST /reset-metrics` |
| `whitelist.py` | `/api/v1/whitelist` | `GET /`, `POST /`, `DELETE /{id}`, `GET /check`, `POST /check-batch` |
| `operator.py` | `/api/v1/operator` | `POST /sessions`, `GET /sessions`, `POST /sessions/{id}/message`, `POST /runs/{id}/approve`, `GET /runs/{id}/status` |

### 14.3 IPS Visualization API

**File:** `api/routes/ips.py`

**Global state:** `_recent_events` (max 2500), `_event_stats`, `_alert_cache`, `_lifecycle_cache`

**Data sources:**
- Upstream alerts (if `upstream_enabled=True`)
- Local SQLite alerts (always)
- Manually submitted events via `POST /event` and `POST /events/bulk`

**Enrichment pipeline:**
1. Convert alert to event → `_alert_to_event()`
2. Category derivation from title patterns (brute-force, web-attack, reconnaissance, malware, DoS, C2, etc.)
3. GeoIP resolution (batch parallel)
4. Lifecycle derivation from investigation status (`blocked`, `mitigated`, `active`, `investigating`)

**Endpoints:**
- `GET /map-data` — Attack data for world map with animated paths
- `GET /events` — Paginated attack events table
- `GET /events/live` — Live events for real-time table
- `GET /statistics` — Comprehensive stats: total attacks, unique sources/targets, top countries/ISPs/sources, by severity/category/protocol/lifecycle
- `GET /countries` — Attack count by country
- `GET /filters` — Available filter options

### 14.4 AI Operator API

**File:** `api/routes/operator.py`

**Execution pipeline:**
1. `_reason_about_request()` — Intent analysis with JSON schema output; classifies mode (`local`, `remote`, `hybrid`)
2. `_generate_playbook()` — Playbook generation with pre-built template matching for common tasks
3. `_generate_execution_summary()` — Human-readable summary
4. `_execute_and_analyze()` — SSH pre-check, playbook write + inventory write, Ansible run with 60s timeout, structured output parsing, LLM analysis
5. `_analyze_execution_result()` — Natural language analysis; fast path for common commands (df, free, ps, systemctl, iptables, ss)

**Pre-built templates:** `ram_processes`, `ram_usage`, `disk_usage`, `cpu_processes`, `open_ports`, `ssh_failures`, `service_status`, `firewall_rules`, `cron_jobs`, `docker_containers`, `docker_images`, `file_read`, `package_check`

**Playbook hardening:**
- `_normalize_playbook_hosts()` — replaces `hosts:` with `target`, adds `failed_when: false` and `changed_when: false` to diagnostic tasks, strips `ignore_errors` from state-changing tasks
- `_sanitize_shell_commands()` — fixes unquoted grep patterns

---

## 15. WebSocket Real-Time Layer

**File:** `api/websocket.py`

**Class:** `WebSocketManager`

- **Channels:** `investigations`, `performance`, `system`
- **Connections:** `Dict[str, List[WebSocket]]`
- **Broadcast:** Sends JSON to all clients in a channel, cleans up dead connections

**Endpoints:**
- `GET /ws/investigations` — Investigation lifecycle events
- `GET /ws/performance` — Performance monitoring alerts
- `GET /ws/system` — System health updates
- `GET /ws` — "All" channel — receives all three channels
- `GET /ws/health` — Connection counts per channel

**Typed broadcast helpers:**
- `broadcast_investigation_update(...)` — Status transitions, AI completion, approval
- `broadcast_performance_alert(...)` — Performance anomalies
- `broadcast_system_health(...)` — Service health changes

**Frontend integration:** `frontend/lib/websocket.tsx`
- Auto-reconnect with exponential backoff (max 30s)
- Typed subscription API: `subscribe(eventType, callback)`
- Hook: `useWSSubscription(eventType, callback)` triggers SWR `mutate()` for live updates

---

## 16. Frontend Integration

### 16.1 API Client

**File:** `frontend/lib/api.ts` (~1,744 lines)

- **Base URL:** `process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001"`
- **Generic fetcher:** `fetchAPI<T>(endpoint, options?)` handles JSON, error extraction (`error.detail`), response parsing
- **SWR integration:** Every page uses `swr` with refresh intervals

### 16.2 Dashboard Pages

| Page | Route | SWR Interval | Key Features |
|------|-------|--------------|--------------|
| Dashboard Home | `/` | 30s | Quick stats, 24h alert trend (AreaChart), severity pie chart, activity feed |
| Alerts | `/alerts` | — (WS) | Paginated table, multi-select, bulk create incident, detail sheet with Tabs |
| Incidents | `/incidents` | 30s | Table, filters, "Launch Investigation" dialog |
| Investigations | `/investigations` | 15s | Status cards, paginated table, review CTA |
| Investigation Detail | `/investigations/[id]` | — | AI summary, playbook YAML editor, approve/decline/execute buttons, timeline, run output |
| Archives | `/archives` | — | Archived list, fix status badges |
| Metrics | `/metrics` | 5s (live) / 30s | Host selector, CPU/Memory/Disk/Load cards, historical charts, process lists, root cause |
| Monitoring | `/monitoring` | 30s | Service status grid, pipeline health, stuck investigations, logs viewer |
| IPS Map | `/ips` | 10s | Interactive world map (`react-simple-maps`), animated attack paths, live events, statistics |
| Search | `/search` | — | Global search across all entities |
| AI Assistant | `/assistant` | — | Chat interface, persistent conversations, action buttons |
| AI Operator | `/operator` | 3s (run poll) | Session-based NL operations, execution plan, approval, result display |
| Pipeline | `/pipeline` | — | Status, cursors, alert trace |
| Whitelist | `/whitelist` | — | Entry management |

### 16.3 Key Components

**Dashboard components (`frontend/components/dashboard/`):**
- `stat-card.tsx` — Animated counters with variants (critical/warning/success), trend indicators
- `alerts-chart.tsx` — Recharts AreaChart for 24h trends
- `severity-chart.tsx` — Pie/donut chart for severity breakdown
- `activity-feed.tsx` — Recent investigations activity
- `quick-actions.tsx` — Pending approvals CTA + shortcuts

**Shared UI:**
- `PageHeader` — Title, refresh button, live indicator
- `DataTable` — Sortable/paginated with skeleton states
- `SeverityBadge`, `StatusBadge`, `WhitelistBadge` — Consistent styling

---

## 17. Background Tasks & Scheduling

**File:** `main.py`

All tasks run concurrently, each wrapped in `_run_safe_task()` which catches exceptions and restarts after 5 seconds.

| Task | Coroutine | Interval | Description |
|------|-----------|----------|-------------|
| **Alert Forwarder** | `run_forwarder` | 10s (`alert_poll_interval`) | Polls ES for new alerts, enriches, deduplicates, stores locally or forwards upstream |
| **Incident Watcher** | `watch_incidents` | 15s (internal) | Polls for open incidents, spawns AI investigations |
| **Incident Correlation** | `run_correlation_cycle` | 30s (`incident_correlation_interval`) | Correlates alerts into incidents locally |
| **Retry Queue** | `_run_retry_queue_loop` | 300s (5 min) | Re-sends failed alerts to upstream (sleeps forever if upstream disabled) |
| **Auto-Transitions** | `_run_auto_transitions_loop` | 3600s (1 hour) | Processes ticketing lifecycle state transitions |
| **Daily Backup** | `_run_backup_loop` | Daily at 03:00 AM | Copies DB, cursors, tickets to `data/backups/` |
| **Performance Poller** | `run_performance_poller` | 30s (`performance_poll_interval`) | Polls Telegraf metrics from ES |
| **Performance Monitoring** | `start_performance_monitoring` | Internal | Anomaly detection + auto-remediation |
| **Performance Watcher** | `start_performance_watcher` | Internal | Watches performance incidents |
| **Watchdog** | `_run_watchdog` | 60s | Logs memory usage (MB) and child process count |
| **API Server** | `_run_response_api` | Blocking | FastAPI on port 8001 in daemon thread; sleeps if port in use |
| **Health Monitor** | `health_monitor.start_background_check` | Once at startup | Upstream health checks (skipped if upstream disabled) |

**Shutdown sequence (SIGINT/SIGTERM):**
1. Set `_shutdown_event`
2. Persist seen IDs to disk
3. Close OpenSOAR sender client
4. Cancel all running tasks
5. Stop dashboard/health monitors
6. Close ticket store
7. Close ES and Redis clients

---

## 18. Operational Features

### 18.1 Backup & Restore

**Scripts:** `scripts/backup_db.sh`, `scripts/restore_db.sh`

**Backup (`backup_db.sh`):**
- Copies `data/investigations.db`
- Copies cursor state (`data/cursors`)
- Copies ticket store (`data/artifacts`)
- Copies main log
- Destination: `data/backups/{timestamp}/`
- Retention: `BACKUP_RETENTION_DAYS` (default 30)

**Restore (`restore_db.sh <timestamp>`):**
- Stops `main.py`
- Restores DB + cursors + tickets from backup
- Restarts backend via `nohup`

### 18.2 Notifications

**File:** `response/notification.py`

| Function | Trigger | Channels |
|----------|---------|----------|
| `send_approval_notification()` | AI finishes, `awaiting_approval` | Slack (rich blocks with button), Email (SMTP) |
| `send_remediation_complete_notification()` | Fix verification done | Slack |
| `send_pipeline_failure_notification()` | Pipeline stage fails | Slack + Email |
| `send_stuck_investigation_alert()` | Investigation stuck > threshold | Slack (rich blocks with Approve button link) + Email |
| `send_auto_approve_notification()` | Auto-approval executes | Slack (if enabled) |

### 18.3 AI Assistant

**File:** `response/assistant.py`

**Features:**
- Persistent conversations (`AssistantConversation`, `AssistantMessage`)
- Deep entity fetching: investigations, incidents, alerts, archives, performance metrics, IPS events, pipeline cursors, system health
- Keyword extraction: IPs, hostnames, UUIDs, severity, MITRE tactics
- LLM prompt assembly with relevance-prioritized records
- Fallback renderer: structured markdown from fetched data
- **Allowed actions:** `approve_investigation`, `decline_investigation`, `execute_investigation`, `archive_investigation`, `trigger_watcher`

### 18.4 Whitelist System

**File:** `core/whitelist.py`

- **Cache:** In-memory dict with 60-second TTL
- **Types:** `ip`, `subnet`, `domain`
- **`is_whitelisted(value, check_type)`:** Exact match + subnet containment for IPs
- **`check_alert_whitelist(alert)`:** Checks `source_ip`, `dest_ip`, `hostname`
- **`add_whitelist_entry(...)`:** Adds entry, retroactively marks matching alerts in background

### 18.5 Stuck Investigation Recovery

**File:** `response/watcher/stuck_recovery.py`

| Function | What It Does |
|----------|--------------|
| `_retry_pending_investigations()` | Finds `pending` investigations with errors (>5 min) or never-processed (>30s). Re-fetches incident + alerts, rebuilds context, re-runs AI engine with adaptive concurrency |
| `_execute_approved_investigations()` | Finds `approved` investigations with no `PlaybookRun`, spawns `execute_playbook()` |
| `_check_stuck_investigations()` | Alerts on: `awaiting_approval` >2h, `running` >30m, `pending` >1h |
| `_recover_stuck_running_investigations()` | Uses `psutil` to scan for `ansible-playbook` processes. If process not found, marks `failed` and triggers fix verifier |

---

## 19. Complete Data Flow Diagrams

### 19.1 Security Alert Flow (End-to-End)

```
Elasticsearch
├─ wazuh-alerts-*
├─ falco-*
├─ filebeat-* (with suricata.eve.alert)
└─ telegraf-*
     │
     ▼
pipeline/poller/main.py:poll_source()
     │
     ▼
pipeline/mappers/*.py
(Wazuh/Falco/Suricata/Filebeat/Generic)
     │
     ▼
pipeline/poller/alert_processor.py:process_single_alert()
├─ dedup (Redis → memory → SQLite)
├─ noise filter (Sigma + learned)
├─ severity filter
├─ GeoIP enrichment
├─ MITRE mapping
├─ campaign detection
├─ whitelist check
├─ persist to SQLite (Alert)
├─ pattern tracking (group repeats)
├─ [upstream_enabled] ──► sender.py ──► Upstream OpenSOAR
└─ datausage/orchestrator.py:process_alert()
     ├─ observable_manager (IOC extraction)
     ├─ ai_pipeline (LLM triage)
     ├─ incident_manager / local_incident_manager
     │      └─ AlertIncidentLink ──► Incident (SQLite)
     └─ alert_manager (status/determination)
     │
     ▼
response/watcher/main.py:watch_incidents()
├─ [local] Queries Incident WHERE status="open" AND no Investigation
└─ [upstream] Polls upstream for open incidents
     │
     ▼
response/watcher/context_builder.py
├─ Extract IOCs
├─ Behavioral patterns
├─ Authentication analysis
├─ Attack type determination
└─ Risk score calculation
     │
     ▼
response/ai_engine/main.py:run_investigation()
├─ Build prompt (prompt_builder.py)
├─ Call LLM (llm_clients.py)
│   ├─ Ollama (default)
│   ├─ NVIDIA NIM
│   ├─ Google Gemini
│   ├─ OpenRouter
│   └─ Fallback: rule-based playbook
├─ Parse response (response_parser.py)
├─ Validate YAML
├─ Update DB: awaiting_approval
├─ Broadcast WebSocket
└─ Auto-approve attempt (auto_approve.py)
     │
     ├──► Approved ──► response/ansible_exec.py:execute_playbook()
     │                    ├─ Host replacement
     │                    ├─ Jinja2 fixes
     │                    ├─ Syntax validation
     │                    ├─ SSH pre-check
     │                    ├─ Write playbook + inventory
     │                    ├─ Run ansible-playbook
     │                    ├─ Update PlaybookRun
     │                    ├─ Broadcast WebSocket
     │                    └─ Trigger fix verifier
     │                         │
     │                         ▼
     │                    response/fix_verifier.py:verify_fix()
     │                    ├─ Query ES for recurrence
     │                    ├─ Active verification
     │                    ├─ Verdict (likely_fixed / not_fixed / inconclusive)
     │                    ├─ Save FixVerification
     │                    └─ Call archiver
     │                         │
     │                         ▼
     │                    response/archiver.py:archive_investigation()
     │                    ├─ Build full context JSON
     │                    ├─ Create Archive row
     │                    ├─ Update Investigation.status="archived"
     │                    └─ Update Incident.status="resolved"/"archived"
     │
     ├──► Declined ──► Archive (background)
     │
     └──► Human Review ──► api/routes/approval_ui.py
                              └─ HTML page with Approve/Decline buttons
                                   │
                                   ▼
                              api/routes/investigations.py
                              ├─ POST /{id}/approve
                              └─ POST /{id}/decline
```

### 19.2 Performance Monitoring Flow

```
Elasticsearch telegraf-*
     │
     ▼
pipeline/performance_poller.py:poll_once()
├─ Discover hosts (tag.host aggregation)
├─ Per-host parallel queries:
│   ├─ CPU, Memory, Disk, Network
│   ├─ Processes, System load, Netstat
│   ├─ Procstat (top 15 by CPU)
│   └─ Disk directories (du -sh)
└─ Filter stale data (>10 min)
     │
     ▼
pipeline/datausage/performance_orchestrator.py
├─ Store in Redis (performance_redis)
├─ Append scalar history
├─ Detect anomalies (AnomalyDetector)
│   ├─ CPU: threshold + statistical stddev
│   ├─ Memory: threshold + statistical
│   ├─ Disk: usage % + inodes %
│   ├─ Load: normalized >2.5 / >4.0
│   └─ Network: rate from history
├─ Check cooldown
├─ Root cause analysis (AI LLM)
├─ Generate performance alert
├─ Broadcast WebSocket
├─ Send upstream (best effort)
└─ Create local investigation + dynamic playbook
     │
     ▼
pipeline/datausage/performance_watcher.py
├─ Track incidents in Redis
├─ Check resolution (metrics back to normal)
└─ Cleanup resolved (>24h)
```

### 19.3 Frontend Data Flow

```
User Browser (Next.js on :3000)
     │
     ├──► HTTP/REST ──► frontend/lib/api.ts ──► FastAPI (:8001)
     │                    ├─ SWR caching with intervals
     │                    └─ Typed API namespaces
     │
     └──► WebSocket ──► frontend/lib/websocket.tsx ──► ws://localhost:8001/ws
                          ├─ Auto-reconnect (exponential backoff, max 30s)
                          ├─ subscribe(eventType, callback)
                          └─ useWSSubscription() → triggers SWR mutate()

Channels:
  /ws/investigations  ──► investigation_updated  ──► Refresh investigations/incidents
  /ws/performance     ──► performance_alert      ──► Refresh metrics dashboard
  /ws/system          ──► system_health          ──► Refresh monitoring page
```

---

## 20. Configuration Reference

**File:** `config/settings.py` — Pydantic `BaseSettings`

### Key Configuration Categories

| Category | Variables |
|----------|-----------|
| **Elasticsearch** | `elasticsearch_url`, `elasticsearch_user`, `elasticsearch_password`, `elasticsearch_use_ssl` |
| **Redis** | `redis_host`, `redis_port` |
| **Index Patterns** | `wazuh_index_pattern`, `falco_index_pattern`, `filebeat_index_pattern`, `suricata_index_pattern`, `telegraf_index_pattern` |
| **LLM / AI** | `llm_provider`, `llm_model`, `ollama_host`, `ollama_timeout`, `llm_enabled`, `nvidia_api_key`, `google_api_key`, `openrouter_api_key` |
| **Upstream** (deprecated) | `opensoar_enabled` (alias: `upstream_enabled`), `opensoar_url`, `opensoar_username`, `opensoar_password`, `opensoar_poll_interval`, `opensoar_batch_size` |
| **Local Mode** | `local_ingestion_enabled`, `incident_auto_create_enabled`, `incident_correlation_window_minutes`, `max_concurrent_investigations` |
| **Ansible / SSH** | `ansible_enabled`, `ansible_remote_host`, `ansible_remote_user`, `ansible_ssh_key`, `ansible_ssh_password`, `ansible_become_method`, `ansible_become_password`, `ansible_timeout` |
| **Auto-Approve** | `auto_approve_enabled`, `auto_approve_method` (`static`/`dynamic`/`ai`/`hybrid`), `auto_approve_severities`, `auto_approve_block_severities`, `auto_approve_max_risk_score`, `auto_approve_block_risk_score`, `auto_approve_ai_threshold` |
| **Performance** | `performance_enabled`, `performance_poll_interval`, `performance_cpu_warning/critical`, `performance_memory_warning/critical`, `performance_disk_warning/critical`, `performance_anomaly_detection`, `performance_auto_remediate_enabled` |
| **Notifications** | `slack_webhook_url`, `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password` |
| **Paths** | `db_path`, `playbook_dir`, `cursor_dir`, `seen_ids_dir`, `backup_dir`, `pattern_tracking_file` |
| **Intervals** | `incident_watcher_interval` (15s), `incident_correlation_interval` (30s), `alert_poll_interval` (10s) |

### Backward-Compatible Aliases

```python
upstream_enabled = property(lambda self: self.opensoar_enabled)
alert_poll_interval = property(lambda self: self.opensoar_poll_interval)
es_batch_size = property(lambda self: self.opensoar_batch_size)
alert_first_run_lookback_hours = property(lambda self: self.opensoar_first_run_lookback_hours)
alert_min_severity = property(lambda self: self.opensoar_min_severity)
```

---

## Appendix: File Reference

### Pipeline Layer

| File | Lines | Purpose |
|------|-------|---------|
| `pipeline/poller/main.py` | ~200 | Main forwarder loop, adaptive pacing |
| `pipeline/poller/alert_processor.py` | ~400 | Single alert processing pipeline |
| `pipeline/poller/seen_ids.py` | ~80 | ES _id deduplication (JSON files) |
| `pipeline/poller/pattern_tracker.py` | ~120 | Repeated alert grouping |
| `pipeline/mappers/wazuh.py` | ~200 | Wazuh alert mapping |
| `pipeline/mappers/falco.py` | ~180 | Falco alert mapping |
| `pipeline/mappers/suricata.py` | ~220 | Suricata alert mapping |
| `pipeline/mappers/filebeat.py` | ~60 | Filebeat→Suricata bridge |
| `pipeline/mappers/generic.py` | ~150 | Generic/unknown source mapping |
| `pipeline/mappers/severity.py` | ~80 | Severity normalization |
| `pipeline/mappers/ip_extractor.py` | ~100 | IP extraction per source |
| `pipeline/enrichment/geoip.py` | ~150 | GeoIP enrichment wrapper |
| `pipeline/enrichment/mitre.py` | ~120 | MITRE ATT&CK mapping |
| `pipeline/enrichment/sigma.py` | ~180 | Sigma noise filter |
| `pipeline/enrichment/anomaly_detector.py` | ~250 | Performance anomaly detection |
| `pipeline/enrichment/root_cause.py` | ~150 | AI root cause analysis |
| `pipeline/services/dedup.py` | ~120 | Deduplication service |
| `pipeline/services/noise_learner.py` | ~100 | Auto noise learning |
| `pipeline/services/correlator.py` | ~150 | Campaign detection |
| `pipeline/sender.py` | ~300 | OpenSOAR HTTP client |
| `pipeline/retry_queue.py` | ~150 | Redis retry queue |
| `pipeline/performance_poller.py` | ~637 | Telegraf metrics polling |
| `pipeline/datausage/orchestrator.py` | ~200 | Data-usage pipeline orchestrator |
| `pipeline/datausage/observable_manager.py` | ~250 | IOC extraction & creation |
| `pipeline/datausage/ai_pipeline.py` | ~200 | Local LLM triage |
| `pipeline/datausage/incident_manager.py` | ~350 | Upstream incident correlation |
| `pipeline/datausage/local_incident_manager.py` | ~300 | Local SQLite incident correlation |
| `pipeline/datausage/alert_manager.py` | ~250 | Alert CRUD & enrichment |
| `pipeline/datausage/performance_orchestrator.py` | ~300 | Performance anomaly pipeline |
| `pipeline/datausage/performance_watcher.py` | ~150 | Performance incident watcher |
| `pipeline/response/dynamic_playbook.py` | ~200 | Dynamic Ansible playbook generation |
| `pipeline/response/performance_playbook.py` | ~150 | Pre-defined performance playbook templates |
| `pipeline/response/performance_auto_approve.py` | ~120 | Performance auto-approve logic |

### Response Layer

| File | Lines | Purpose |
|------|-------|---------|
| `response/db.py` | ~150 | Async SQLite engine, migrations |
| `response/models.py` | ~400 | SQLAlchemy ORM models (14 tables) |
| `response/search_fts.py` | ~200 | FTS5 full-text search |
| `response/watcher/main.py` | ~300 | Incident watcher loop |
| `response/watcher/context_builder.py` | ~400 | Investigation context assembly |
| `response/watcher/investigation_db.py` | ~250 | Investigation DB operations |
| `response/watcher/ai_runner.py` | ~150 | AI engine trigger with semaphore |
| `response/watcher/stuck_recovery.py` | ~250 | Stuck investigation recovery |
| `response/ai_engine/main.py` | ~300 | AI investigation orchestrator |
| `response/ai_engine/prompt_builder.py` | ~350 | LLM prompt construction |
| `response/ai_engine/llm_clients.py` | ~300 | Multi-provider LLM routing |
| `response/ai_engine/response_parser.py` | ~200 | AI response parsing & validation |
| `response/auto_approve.py` | ~250 | Auto-approve decision cascade |
| `response/confidence_tracker.py` | ~150 | Dynamic learning for approvals |
| `response/decision_logger.py` | ~100 | Approval audit logging |
| `response/ansible_exec.py` | ~400 | Ansible execution engine |
| `response/fix_verifier.py` | ~200 | Fix verification logic |
| `response/archiver.py` | ~150 | Case archival |
| `response/adaptive.py` | ~400 | Self-tuning adaptive system |
| `response/assistant.py` | ~1143 | Contextual AI assistant |
| `response/notification.py` | ~415 | Multi-channel notifications |

### API Layer

| File | Lines | Purpose |
|------|-------|---------|
| `api/app.py` | ~153 | FastAPI factory, router registration |
| `api/websocket.py` | ~223 | WebSocket manager & endpoints |
| `api/routes/investigations.py` | ~400 | Investigation CRUD + lifecycle |
| `api/routes/incidents.py` | ~300 | Incident CRUD + manual creation |
| `api/routes/alerts.py` | ~200 | Alert listing & detail |
| `api/routes/archives.py` | ~200 | Archive access |
| `api/routes/assistant.py` | ~200 | AI assistant endpoints |
| `api/routes/operator.py` | ~500 | AI operator endpoints |
| `api/routes/ips.py` | ~400 | IPS visualization API |
| `api/routes/performance.py` | ~350 | Performance metrics API |
| `api/routes/monitoring.py` | ~300 | System health & monitoring |
| `api/routes/dashboard.py` | ~150 | Dashboard summary stats |
| `api/routes/search.py` | ~200 | Unified search |
| `api/routes/pipeline.py` | ~150 | Pipeline telemetry |
| `api/routes/whitelist.py` | ~150 | Whitelist management |
| `api/routes/adaptive.py` | ~80 | Adaptive system status |
| `api/routes/approval_ui.py` | ~150 | HTML approval pages |

### Core Layer

| File | Lines | Purpose |
|------|-------|---------|
| `core/elasticsearch.py` | ~133 | Async ES client with retry |
| `core/redis.py` | ~80 | Async Redis client |
| `core/redis_performance.py` | ~250 | Performance metrics Redis storage |
| `core/geoip.py` | ~150 | GeoIP resolution with cache |
| `core/whitelist.py` | ~150 | Whitelist system |
| `core/circuit_breaker.py` | ~100 | Circuit breaker pattern |

---

*End of Architectural Reference*
