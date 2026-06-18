# OpenSOAR ARIA — System Architecture Document

> **Project**: Adaptive Response Intelligence Automation (ARIA)  
> **Author**: Ghazi Mabrouki  
> **Institution**: Huawei PFE — ISI Kef  
> **Date**: April 2026  
> **Version**: 2.0 (Verified against Current Codebase)

---

## 1. Executive Summary

ARIA is a **hybrid Security Orchestration, Automation and Response (SOAR)** platform that ingests security alerts from Elasticsearch, correlates them into incidents, generates AI-driven remediation playbooks, and executes them via Ansible — all while maintaining a local shadow database for resilience when upstream services are unreachable.

**Core Principle**: The system operates **independently** of the upstream OpenSOAR instance. All alerts, incidents, investigations, and archives are stored locally in SQLite. Upstream forwarding is best-effort.

**Current Operational Scale**:
- 2,577 alerts ingested across 3 sources (Wazuh 130, Falco 648, Suricata 1,799)
- 202 incidents correlated
- 424 investigations generated
- 104 archived cases

---

## 2. High-Level Architecture

### 2.1 System Context Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               EXTERNAL DATA SOURCES                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────────┐  ┌─────────────────────────────────┐ │
│  │  Wazuh  │  │  Falco  │  │  Suricata   │  │      Telegraf (metrics)         │ │
│  │ (130)   │  │ (648)   │  │  (1,799)    │  │  Host: ghazi                    │ │
│  └────┬────┘  └────┬────┘  └──────┬──────┘  │  CPU/Mem/Disk/Network/Load      │ │
│       │            │               │         └─────────────────────────────────┘ │
│       └────────────┴───────┬───────┘                                            │
│                            ▼                                                    │
│                   ┌─────────────────┐                                           │
│                   │  Elasticsearch  │  https://193.95.30.97:9200                │
│                   │   (Data Lake)   │                                           │
│                   └────────┬────────┘                                           │
└────────────────────────────┼────────────────────────────────────────────────────┘
                             │ POLL (every 10s for alerts, 30s for metrics)
                             ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         BACKEND — FastAPI (port 8001)                            │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  LAYER 1: PIPELINE & INGESTION                                          │    │
│  │  ┌──────────────┐  ┌─────────────┐  ┌──────────────────────────────┐   │    │
│  │  │   Poller     │→ │   Mappers   │→ │   Alert Processor             │   │    │
│  │  │  (4 sources) │  │(Wazuh/Falco │  │  - 3-layer dedup              │   │    │
│  │  │  parallel)   │  │ /Suricata/  │  │  - GeoIP enrichment           │   │    │
│  │  │  cursor-based│  │  Filebeat)  │  │  - Sigma noise filtering      │   │    │
│  │  │  seen-ids    │  │             │  │  - Campaign detection         │   │    │
│  │  └──────────────┘  └─────────────┘  │  - Pattern tracking           │   │    │
│  │                                      │  - Local persistence (SQLite) │   │    │
│  │                                      │  - Upstream forward (best-eff)│   │    │
│  │                                      └──────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  LAYER 2: DATA USAGE & INTELLIGENCE                                     │    │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  │    │
│  │  │ Observable  │  │   AI Triage  │  │   Incident  │  │    Ticket    │  │    │
│  │  │  Manager    │  │   Pipeline   │  │   Manager   │  │   System     │  │    │
│  │  │             │  │              │  │             │  │              │  │    │
│  │  │ - IOC auto- │  │ - Smart      │  │ - Correlat. │  │ - Open→Inv.  │  │    │
│  │  │   extract   │  │   analysis   │  │ - 13 attack │  │ - Contained  │  │    │
│  │  │ - Threat    │  │ - Summarize  │  │   types     │  │ - Resolved   │  │    │
│  │  │   intel     │  │ - Auto-resol.│  │ - Time win. │  │ - Closed     │  │    │
│  │  └─────────────┘  └──────────────┘  └─────────────┘  └──────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  LAYER 3: RESPONSE INTELLIGENCE                                         │    │
│  │  ┌────────────┐  ┌─────────────┐  ┌──────────────────────────────────┐  │    │
│  │  │  Watcher   │  │  AI Engine   │  │   Ansible Execution Engine       │  │    │
│  │  │            │  │              │  │                                  │  │    │
│  │  │- 15s cycle │  │- LLM prompt │  │- Syntax validation (--syntax-chk)│  │    │
│  │  │- Fast scan │  │- 5 sections │  │- SSH pre-flight test             │  │    │
│  │  │  (50 recs) │  │- Fallback   │  │- Host replacement (→ "target")   │  │    │
│  │  │- Full scan │  │  on timeout │  │- Jinja2 fixup                    │  │    │
│  │  │  (all open)│  │- Auto-appro.│  │- Whitelist check                 │  │    │
│  │  │- Stuck rec.│  │  hybrid sys.│  │- Dry-run mode                    │  │    │
│  │  │- Auto-exec.│  │              │  │- Line-by-line output capture     │  │    │
│  │  └────────────┘  └─────────────┘  └──────────────────────────────────┘  │    │
│  │                                                                           │    │
│  │  ┌─────────────────┐  ┌────────────────────────────────────────────────┐  │    │
│  │  │  Auto-Approve   │  │  Performance Monitor                           │  │    │
│  │  │                 │  │  - Poll Telegraf→ES every 30s                  │  │    │
│  │  │- Guardrails:    │  │  - Threshold + statistical + AI anomaly detect │  │    │
│  │  │  never critical │  │  - Root cause analysis                         │  │    │
│  │  │- Static pass:   │  │  - Dynamic playbook generation                 │  │    │
│  │  │  always low     │  │  - Cooldown: 30 min per anomaly type           │  │    │
│  │  │- Dynamic learn. │  │  - Redis metrics storage for API               │  │    │
│  │  │- AI confidence  │  │  - Creates investigations awaiting approval    │  │    │
│  │  └─────────────────┘  └────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  LAYER 4: API & REAL-TIME                                               │    │
│  │  FastAPI (port 8001) with 16 route modules + WebSocket channels         │    │
│  │  /api/v1/alerts     /api/v1/incidents     /api/v1/investigations        │    │
│  │  /api/v1/ips        /api/v1/metrics       /api/v1/archives              │    │
│  │  /api/v1/pipeline   /api/v1/dashboard     /api/v1/search                │    │
│  │  /api/v1/assistant  /api/v1/whitelist     /api/v1/operator              │    │
│  │  /ws/investigations /ws/performance       /ws/system                    │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  DATA LAYER                                                             │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────────┐   │    │
│  │  │   SQLite     │  │    Redis     │  │   Elasticsearch (remote)     │   │    │
│  │  │ investigations│  │ - Dedup      │  │   - Alert source             │   │    │
│  │  │      .db      │  │ - Cursors    │  │   - Telegraf metrics         │   │    │
│  │  │  (local)      │  │ - Cooldowns  │  │   - Fix verification queries │   │    │
│  │  │  13 models    │  │ - Pattern    │  │                              │   │    │
│  │  │  2,577 alerts │  │   tracking   │  └──────────────────────────────┘   │    │
│  │  │  423 invs     │  │ - Metrics    │                                     │    │
│  │  │  202 incidents│  │   history    │                                     │    │
│  │  └──────────────┘  └──────────────┘                                     │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      FRONTEND — Next.js 16 (port 3000)                           │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────────────────┐   │
│  │  Dashboard │  │   Alerts   │  │  Incidents │  │  Investigations          │   │
│  │  (SWR)     │  │  (Table)   │  │  (Detail)  │  │  (Approve/Decline/Edit)  │   │
│  └────────────┘  └────────────┘  └────────────┘  └──────────────────────────┘   │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────────────────┐   │
│  │  IPS Map   │  │  Metrics   │  │  Archives  │  │  Assistant (Chat)        │   │
│  │  (Leaflet) │  │  (Charts)  │  │  (History) │  │  (LLM-powered)           │   │
│  └────────────┘  └────────────┘  └────────────┘  └──────────────────────────┘   │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────────────────┐   │
│  │  Pipeline  │  │  Operator  │  │  Search    │  │  Monitoring              │   │
│  │  Status    │  │  (AI exec) │  │  (Global)  │  │  (Live indicators)       │   │
│  └────────────┘  └────────────┘  └────────────┘  └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Technology Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| **Backend Runtime** | Python | 3.12 | Core runtime |
| **Web Framework** | FastAPI | latest | REST API + WebSocket |
| **ORM** | SQLAlchemy | 2.0 async | SQLite async operations |
| **Database** | SQLite + aiosqlite | 3.x | Local shadow storage |
| **Cache / State** | Redis | 7.x | Dedup, cursors, cooldowns, metrics history |
| **Search / Metrics Source** | Elasticsearch | 8.x | Alert and metric source |
| **LLM Inference** | Ollama | latest | Local AI (qwen3:8b default) |
| **Playbook Execution** | Ansible | core 2.x | Remediation execution |
| **GeoIP** | MaxMind GeoLite2 | — | IP geolocation |
| **Frontend Framework** | Next.js | 16.2.0 | React App Router |
| **Frontend UI** | React | 19 | UI framework |
| **Styling** | Tailwind CSS | 3.x | Utility-first CSS |
| **Components** | shadcn/ui | — | Headless UI primitives |
| **State / Fetching** | SWR | latest | Data fetching + caching |
| **Charts** | Recharts | — | Metrics visualization |
| **Maps** | Leaflet | — | IPS attack map |
| **Logging** | structlog | — | Structured JSON logging |
| **Process Manager** | nohup + bash | — | Production deployment |

---

## 4. Backend Module Breakdown

### 4.1 Pipeline Layer (`pipeline/`)

| Module | Files | Responsibility |
|--------|-------|----------------|
| `poller/` | `main.py`, `alert_processor.py`, `cursor_manager.py`, `seen_ids.py`, `pattern_tracker.py` | Polls ES every 10s, maps raw docs → structured alerts, persists locally, forwards upstream. Pattern tracking groups repeated alerts by source_ip + rule_name |
| `mappers/` | `wazuh.py`, `falco.py`, `suricata.py`, `filebeat.py`, `generic.py`, `ip_extractor.py`, `severity.py` | Source-specific field normalization. Extracts title, severity, IPs, MITRE tactics, IOCs, container metadata |
| `enrichment/` | `geoip.py`, `mitre.py`, `sigma.py`, `anomaly_detector.py`, `root_cause.py` | GeoIP lookup, MITRE ATT&CK tagging, Sigma noise filtering, performance anomaly detection (threshold + statistical + AI), root cause analysis |
| `datausage/` | `orchestrator.py`, `incident_manager.py`, `observable_manager.py`, `alert_manager.py`, `ai_pipeline.py`, `performance_orchestrator.py`, `performance_watcher.py`, `health_monitor.py`, `dashboard_monitor.py` | Central data processing pipeline: observables → AI triage → incidents → alerts. Performance monitoring lifecycle |
| `datausage/ticketing/` | `lifecycle.py`, `models.py`, `store.py`, `routing_rules.py` | Ticket state machine (Open→Investigating→Contained→Resolved→Closed), auto-transitions, escalation |
| `services/` | `correlator.py`, `dedup.py`, `noise_learner.py` | Campaign detection, 3-layer dedup, auto-learned noise filtering |
| `response/` | `dynamic_playbook.py`, `performance_playbook.py`, `performance_auto_approve.py` | Dynamic Ansible playbook generation for performance remediation |

### 4.2 Response Intelligence Layer (`response/`)

| Module | Responsibility |
|--------|----------------|
| `ai_engine/main.py` | Main AI investigation runner. Calls LLM, parses response, stores results. Falls back to rule-based analysis on timeout/error |
| `ai_engine/llm_clients.py` | LLM client abstraction (Ollama primary, Google Gemini alternative). Adaptive timeout based on history |
| `ai_engine/prompt_builder.py` | Structured 5-section prompt construction |
| `ai_engine/response_parser.py` | Extracts summary, narrative, threat intel, risk, playbook YAML from raw LLM output. Validates playbook structure |
| `watcher/main.py` | Incident watcher loop (15s). Fast scan (50 recent) vs full scan (all open, every 15min). Discovers new incidents, triggers AI engine |
| `watcher/ai_runner.py` | Runs AI engine with semaphore-controlled concurrency. Broadcasts completion via WebSocket |
| `watcher/context_builder.py` | Builds investigation context from incident + linked alerts |
| `watcher/investigation_db.py` | Creates/updates investigation records, stores alert snapshots, refreshes existing investigations |
| `watcher/stuck_recovery.py` | Retries pending investigations, executes approved ones, checks stuck status, auto-recovers running investigations |
| `ansible_exec.py` | Full Ansible execution engine: syntax validation, SSH pre-flight, host replacement, Jinja2 fixup, whitelist check, dry-run mode, line-by-line output capture |
| `auto_approve.py` | Hybrid auto-approval: static guardrails → static pass → dynamic learning → AI confidence scoring. Threshold ≥0.85 |
| `archiver.py` | Assembles full context snapshot (incident + alerts + AI + run + verification) into Archive record |
| `fix_verifier.py` | Re-checks Elasticsearch after playbook execution to verify fix effectiveness |
| `adaptive.py` | Circuit breaker, response time tracking, error classification |
| `confidence_tracker.py` | Dynamic learning from approval patterns |
| `notification.py` | Slack/email notifications for approvals, failures, auto-approvals |
| `models.py` | 13 SQLAlchemy models (Investigation, Alert, Incident, Archive, PlaybookApproval, PlaybookRun, FixVerification, etc.) |
| `db.py` | Async SQLite engine + session factory |

### 4.3 API Layer (`api/routes/`)

16 route modules:

| Route | Endpoints | Responsibility |
|-------|-----------|----------------|
| `alerts.py` | GET /api/v1/alerts, GET /api/v1/alerts/{id}, PATCH archive | Hybrid local/upstream alert listing with relationship resolution |
| `incidents.py` | GET /api/v1/incidents, GET /api/v1/incidents/{id} | Incident CRUD with upstream fallback |
| `investigations.py` | Full approval workflow, playbook edit, execute, decline, timeline | Investigation lifecycle management with state machine validation |
| `archives.py` | GET /api/v1/archives, search | Searchable archived investigation history |
| `ips.py` | GET /api/v1/ips/map, stats, filters | Attack map with GeoIP, local fallback when upstream down |
| `performance.py` | GET /api/v1/metrics/dashboard, /history, /alerts | Hardware resource monitoring dashboard data |
| `pipeline.py` | GET /api/v1/pipeline/status, cursors, trace | Pipeline health, cursor positions, processing stats |
| `dashboard.py` | GET /api/v1/dashboard/summary, /quick-stats, /trends | Summary stats, trend data from local shadow store |
| `search.py` | GET /api/v1/search | Global search across alerts, incidents, investigations |
| `assistant.py` | POST /api/v1/assistant/query, /conversations | LLM chat with investigation context awareness |
| `adaptive.py` | GET/POST adaptive settings | Auto-approve configuration |
| `monitoring.py` | Health checks, live indicators | System health endpoints |
| `whitelist.py` | GET/POST whitelist entries | IP/domain whitelist management |
| `operator.py` | POST /api/v1/operator/execute | AI operator for custom playbook generation |
| `approval_ui.py` | HTML dashboard page | Standalone approval dashboard |
| `websocket.py` | /ws/investigations, /ws/performance, /ws/system | Real-time event broadcast |

---

## 5. Data Flows

### 5.1 Security Alert Flow (End-to-End)

```
Elasticsearch (Wazuh/Falco/Suricata/Filebeat)
    ↓
pipeline/poller/main.py — poll_source() every 10s (parallel)
    ↓
CursorManager — gets last cursor, queries ES for docs > cursor
    ↓
SeenIds — skips already-processed ES doc IDs (disk-persisted JSON)
    ↓
Mapper — raw ES doc → normalized OpenSOAR alert format
    ↓
Dedup — 3-layer check (in-memory → Redis 5min TTL → DB SELECT)
    ↓
NoiseLearner — skips auto-learned noise patterns
    ↓
Severity filter — skips below configured minimum
    ↓
GeoIP enrichment — adds country, city, ASN, coordinates
    ↓
Campaign detection (correlator) — groups repeated alerts
    ↓
Persist to local SQLite (Alert table)
    ↓
Forward to upstream OpenSOAR (best-effort, 3 retries)
    ↓
If forward succeeds:
    └── DataUsage Orchestrator:
        ├── Observable Manager — auto-extract IOCs
        ├── AI Pipeline — smart triage, summarize
        ├── Incident Manager — correlate alerts, create incidents
        └── Alert Manager — auto-enrich, update status
    ↓
Watcher discovers incident → triggers AI Engine
    ↓
AI Engine (Ollama qwen3:8b):
    ├── Build structured 5-section prompt
    ├── Call LLM with circuit breaker + adaptive timeout
    ├── Parse response (summary, narrative, threat intel, risk, playbook)
    ├── Validate playbook YAML
    └── Fallback to rule-based on timeout/error
    ↓
Investigation created with status="awaiting_approval"
    ↓
Auto-Approve System evaluates:
    ├── Guardrails (never: critical, high risk, blocked attack types)
    ├── Static pass (always: low severity, low risk, few alerts)
    ├── Dynamic learning (confidence tracker)
    └── AI confidence (validity + completeness + risk + summary)
    ↓
Analyst reviews via frontend → Approve / Decline / Edit playbook
    ↓
Approve → Ansible Execution Engine:
    ├── Validate YAML syntax
    ├── Validate Ansible syntax (--syntax-check)
    ├── Test SSH connection (sshpass or key-based)
    ├── Replace playbook host with "target" group
    ├── Fix Jinja2 templates (loop variables)
    ├── Whitelist check
    └── Execute ansible-playbook, capture output line-by-line
    ↓
Fix Verifier — re-checks ES after configured delay
    ↓
Archive investigation (fix_status: verified / likely_fixed / not_fixed / declined)
```

### 5.2 Performance Alert Flow

```
Telegraf agents → Elasticsearch (telegraf-* indices)
    ↓
PerformancePoller every 30s
    ↓
ES terms aggregation on tag.host — discovers all hosts
    ↓
Per-host metric queries (cpu, mem, disk, net, load, processes)
    ↓
AnomalyDetector — hybrid detection:
    ├── Threshold-based (configurable warning/critical)
    ├── Statistical (stddev from 24h baseline)
    └── AI-assisted (if enabled)
    ↓
Root Cause Analysis — affected process, evidence, explanation
    ↓
PerformanceAlertGenerator — structured alert with severity
    ↓
Cooldown check — 30 minutes per anomaly type per host (Redis)
    ↓
Broadcast via WebSocket (/ws/performance)
    ↓
Best-effort forward to upstream OpenSOAR
    ↓
Dynamic Playbook Generation (AI-driven task selection):
    ├── Context: host, anomaly_type, current_value, threshold, metrics
    ├── Tasks selected from matrix (cpu→restart top proc, disk→cleanup, etc.)
    └── YAML serialization with safe quoting for special chars
    ↓
Local Investigation created with status="awaiting_approval"
    ↓
Analyst approves → Ansible execution (disk cleanup, service restart, etc.)
    ↓
Metrics stored in Redis for API dashboard access
```

---

## 6. Database Schema

### 6.1 Core Models (13 tables)

| Model | Key Fields | Relationships |
|-------|-----------|---------------|
| **Alert** | `id`, `source`, `source_id`, `external_id`, `severity`, `status`, `source_ip`, `dest_ip`, `hostname`, `rule_name`, `iocs`, `tags`, `dedup_key`, `whitelisted` | → Incidents (many-to-many via AlertIncidentLink) |
| **Incident** | `id`, `external_id`, `title`, `description`, `severity`, `status`, `source_ips`, `hostnames`, `alert_ids`, `tags`, `assigned_to`, `assigned_username` | → Alerts, → Investigations |
| **AlertIncidentLink** | `alert_id`, `incident_id`, `correlation_confidence`, `correlation_reason` | Junction table with confidence scoring |
| **Investigation** | `id`, `incident_id`, `incident_title`, `incident_severity`, `status`, `ai_summary`, `ai_narrative`, `ai_risk`, `playbook_yaml`, `playbook_valid`, `target_host`, `target_user`, `source` | → PlaybookApproval, → PlaybookRun, → FixVerification, → Archive, → InvestigationAlerts |
| **InvestigationAlert** | `id`, `investigation_id`, `alert_id`, `alert_json`, `severity`, `source`, `title` | Snapshot of linked alerts |
| **PlaybookApproval** | `id`, `investigation_id`, `decision`, `decided_by`, `decided_at`, `reason`, `edited_playbook` | One-to-one with Investigation |
| **PlaybookRun** | `id`, `investigation_id`, `status`, `output`, `exit_code`, `started_at`, `finished_at` | One-to-one with Investigation |
| **FixVerification** | `id`, `investigation_id`, `status`, `new_alerts_found`, `checked_at`, `detail` | One-to-one with Investigation |
| **Archive** | `id`, `investigation_id`, `incident_id`, `full_context_json`, `fix_status`, `source_ips`, `hostnames`, `mitre_tactics` | Standalone denormalized record |
| **AssistantConversation** | `id`, `title`, `focus_entity_type`, `focus_entity_id` | → AssistantMessages |
| **AssistantMessage** | `id`, `conversation_id`, `role`, `content`, `actions_json`, `sources_json` | Part of conversation thread |
| **WhitelistEntry** | `id`, `type`, `value`, `label`, `description` | IPs/subnets/domains to never block |
| **OperatorRun** | `id`, `prompt`, `intent`, `playbook_yaml`, `risk_level`, `target_hosts`, `status` | Log of AI Operator executions |

### 6.2 Investigation Status Lifecycle

```
┌─────────┐    run     ┌─────────┐   AI done    ┌─────────────────┐
│ pending │ ─────────→ │ running │ ───────────→ │awaiting_approval│
└─────────┘            └────┬────┘              └────────┬────────┘
    │                       │   fail                    │
    │                       ▼                           ▼
    │                   ┌─────────┐              ┌─────────┐
    │                   │ failed  │ ←────────────┤approved │
    │                   └────┬────┘   retry      └────┬────┘
    │                      │                          │
    │                      ▼                          ▼
    │                   ┌─────────┐              ┌─────────┐
    │                   │archived │              │ running │
    │                   └─────────┘              └────┬────┘
    │                                                 │
    ▼                                                 ▼
┌─────────┐                                     ┌─────────┐
│declined │                                     │completed│
└────┬────┘                                     └────┬────┘
     │                                               │
     └───────────────────┬───────────────────────────┘
                         ▼
                    ┌─────────┐
                    │archived │
                    └─────────┘
```

**State Transitions (validated in API):**
```python
_ALLOWED_TRANSITIONS = {
    "pending": {"running", "declined"},
    "running": {"awaiting_approval", "completed", "failed"},
    "awaiting_approval": {"approved", "declined"},
    "approved": {"running"},
    "completed": {"archived"},
    "failed": {"archived", "approved"},   # retry path
    "declined": {"archived"},
}
```

---

## 7. Deployment & Process Model

### 7.1 Single-Process Architecture

The entire backend runs as a **single Python process** (`main.py`) with an asyncio event loop:

```
main.py
├── Uvicorn API server (thread, port 8001)
│   └── FastAPI app with 16 route modules + WebSocket
│
└── Asyncio Event Loop Tasks
    ├── Forwarder — polls ES every 10s (4 sources in parallel)
    │   └── Adaptive sleep: 1s (high volume) / 3s (normal) / 10s (idle)
    │
    ├── Incident Watcher — polls upstream every 15s
    │   ├── Fast scan: 50 most recent open incidents
    │   └── Full scan: ALL open incidents (every 60 cycles = 15 min)
    │
    ├── Incident Correlation — runs every 30s
    │
    ├── Auto-Transitions — runs every 1 hour
    │   └── Escalates stale tickets, auto-resolves contained, auto-closes resolved
    │
    ├── Retry Queue — processes failed forwards every 5 minutes
    │
    ├── Performance Monitoring — polls metrics every 30s (if enabled)
    ├── Performance Watcher — fix verification for performance (if enabled)
    ├── Performance Poller — metric collection (if enabled)
    │
    ├── Daily Backup — at 3 AM, keeps last 7 backups
    │
    └── Watchdog — health heartbeat every 60s (memory, child processes)
```

**Crash Resilience**: Every background task is wrapped in `_run_safe_task()` which catches exceptions, logs them, and restarts the task after a 5-second delay. The API server runs in a separate thread and is protected by port-in-use detection.

### 7.2 Configuration Hierarchy

| File | Purpose |
|------|---------|
| `.env` | All runtime configuration: API keys, DB paths, ES/Redis URLs, credentials, thresholds |
| `config/settings.py` | Pydantic Settings with validation, defaults, and property helpers |
| `config/sigma_rules/` | YAML noise-filtering rules |
| `config/ansible_inventory` | Target host definitions for Ansible |

Key configurable aspects:
- **LLM**: Provider (ollama/google), model, timeout, fallback settings
- **OpenSOAR**: URL, credentials, poll interval, batch size, min severity
- **Ansible**: Inventory path, SSH key/password, become method, timeout, enable/disable
- **Auto-approve**: Method (static/dynamic/ai/hybrid), thresholds, blocked attack types
- **Performance**: Poll interval, thresholds per metric, cooldown, auto-remediate types
- **Stuck detection**: Hours for pending, minutes for running

---

## 8. Resilience Design

### 8.1 Upstream Unreachability Handling

When `193.95.30.97:8000` (upstream OpenSOAR) is down:

| Feature | Behavior |
|---------|----------|
| Alert ingestion | ✅ Continues normally — all alerts stored in SQLite |
| Incident creation | ✅ Local incident correlation continues |
| AI investigations | ✅ Generated locally via Ollama |
| Playbook approval | ✅ Full workflow works |
| Ansible execution | ✅ Executes against local inventory |
| IPS Attack Map | ✅ Falls back to local SQLite alerts with GeoIP |
| Dashboard stats | ✅ Reads from local shadow store |
| Upstream forwarding | ❌ Fails gracefully — queued in retry loop |
| Upstream enrichment | ❌ Skipped — local data used instead |

### 8.2 Key Resilience Patterns

| Pattern | Implementation |
|---------|----------------|
| **Cursor-based polling** | Redis cursors with file-based fallback per source |
| **Seen ID persistence** | Per-source JSON files (`data/seen_ids/{source}.json`) |
| **Triple dedup** | In-memory (per-cycle) → Redis (5-min TTL) → DB `source + source_id` check |
| **Retry queue** | Failed upstream forwards stored and retried every 5 min |
| **Circuit breaker** | LLM client has circuit breaker (5 failures → 120s cooldown) |
| **Adaptive timeout** | LLM timeout adjusts based on historical response times |
| **Fallback analysis** | Rule-based playbook generation when LLM unavailable |
| **Safe task wrapper** | All background tasks auto-restart on crash |
| **SSH pre-flight** | Connection tested before playbook execution; auth failures set status to pending (retryable) |
| **Dry-run mode** | Ansible can run in simulation mode when disabled |
| **Daily backups** | SQLite DB copied daily at 3 AM, 7-day retention |
| **Graceful shutdown** | SIGINT/SIGTERM handlers persist cursors and seen IDs |

---

## 9. Codebase Metrics (Verified)

| Metric | Value |
|--------|-------|
| Python backend LOC | ~38,889 |
| TypeScript/TSX frontend LOC | ~56,948 |
| Backend test files | 16 |
| API route modules | 16 |
| Database models | 13 |
| Background tasks | 10+ concurrent |
| Sigma noise rules | 12+ |
| Supported alert sources | 4 (Wazuh, Falco, Suricata, Filebeat) |
| Performance metrics tracked | 20+ per host |
| WebSocket channels | 3 (+ aggregate) |
| Tests passing | 188 / 188 |

---

*End of Architecture Document*
