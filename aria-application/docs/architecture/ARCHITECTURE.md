# OpenSOAR Backend — System Architecture

## 1. Overall System Architecture

```mermaid
flowchart TB
    subgraph Sources["Alert Sources (Elasticsearch)"]
        W["wazuh-alerts-*"]
        S["suricata-*"]
        F["falco-events-*"]
        FB["filebeat-*"]
    end

    subgraph Pipeline["Pipeline / Forwarder (main.py)"]
        P1["Poller<br/>poll_source()"]
        P2["Mappers<br/>wazuh.py / suricata.py<br/>falco.py / filebeat.py"]
        P3["Deduplication<br/>Redis + Local DB"]
        P4["Enrichment<br/>GeoIP / MITRE / Sigma"]
        P5["Shadow Writer<br/>_persist_alert_local()"]
        P6["OpenSOAR Sender<br/>client.send_alert()"]
        RQ["Retry Queue"]
    end

    subgraph LocalStore["Local Shadow Store (SQLite)"]
        A["Alert Table"]
        I["Incident Table"]
        AI["AlertIncidentLink"]
        WL["WhitelistEntry"]
        OR["OperatorRun"]
        INV["Investigation"]
        ARC["Archive"]
    end

    subgraph Upstream["Upstream OpenSOAR"]
        OS["OpenSOAR API<br/>193.95.30.97:8000"]
        OS_DB["OpenSOAR DB"]
    end

    subgraph API["FastAPI Backend (api.app)"]
        R1["/api/v1/alerts<br/>(hybrid: local + upstream)"]
        R2["/api/v1/incidents<br/>(hybrid: local + upstream)"]
        R3["/api/v1/investigations"]
        R4["/api/v1/dashboard<br/>(local aggregates + upstream fallback)"]
        R5["/api/v1/whitelist"]
        R6["/api/v1/operator"]
        R7["/api/v1/metrics<br/>(performance monitoring)"]
        WS["/ws<br/>(WebSocket)"]
    end

    subgraph Frontend["Next.js Frontend (port 3000)"]
        DASH["Dashboard"]
        ALP["Alerts Page"]
        INCP["Incidents Page"]
        INVP["Investigations Page"]
        METP["Metrics Page"]
        OPP["AI Operator Page"]
    end

    subgraph Actions["Response Actions"]
        ANS["Ansible Executor"]
        WLF["Whitelist Check"]
        VER["Fix Verifier"]
        ARCH["Archiver"]
    end

    W --> P1
    S --> P1
    F --> P1
    FB --> P1

    P1 --> P2
    P2 --> P3
    P3 --> P4
    P4 --> P5
    P4 --> P6
    P6 -->|fire-and-forget| OS
    P6 -.->|on failure| RQ
    RQ -.->|retry| P6

    P5 --> A
    A --> AI
    AI --> I
    WL -.->|check before block| ANS
    OR --> ANS
    INV --> ANS
    ANS --> VER
    VER --> ARCH
    ARCH --> ARC

    A --> R1
    I --> R2
    INV --> R3
    ARC --> R4
    WL --> R5
    OR --> R6

    R1 --> DASH
    R1 --> ALP
    R2 --> INCP
    R3 --> INVP
    R4 --> DASH
    R6 --> OPP
    R7 --> METP
    WS --> DASH

    OS -->|fallback| R1
    OS -->|fallback| R2
    OS -->|fallback| R4
```

---

## 2. Alert Ingestion Pipeline

```mermaid
flowchart LR
    subgraph ES["Elasticsearch Indices"]
        E1["wazuh-alerts-*"]
        E2["suricata-*"]
        E3["falco-events-*"]
        E4["filebeat-*"]
    end

    subgraph Poller["Poller (per source, every 30s)"]
        C1["Cursor Manager<br/>_get_cursor() / _set_cursor()"]
        Q["ES Query<br/>@timestamp > cursor"]
        D1["Batch Deduplicate<br/>processed_ids set"]
        D2["Ever-Seen Check<br/>seen_ids/{source}.json"]
    end

    subgraph Mapper["Source Mappers"]
        M1["Wazuh Mapper<br/>• rule.id / rule.level<br/>• agent.name → hostname<br/>• srcip → source_ip<br/>• MITRE tactics<br/>• category detection<br/>• skip level < 3"]
        M2["Suricata Mapper<br/>• signature_id<br/>• flow_id / proto<br/>• ips_action: blocked/allowed<br/>• attack_status: active/stopped<br/>• payload_printable"]
        M3["Falco Mapper"]
        M4["Filebeat Mapper"]
    end

    subgraph Dedup["Deduplication Layers"]
        RD["Redis dedup<br/>5-min TTL per source"]
        MD["Memory dedup<br/>fallback cache"]
        LD["Local DB dedup<br/>_db_has_dedup_key()"]
    end

    subgraph Shadow["Shadow Write"]
        SW["_persist_alert_local()<br/>→ SQLite alerts table"]
    end

    subgraph Forward["Forward"]
        PT["Pattern Tracker<br/>occurrence_count++"]
        OS["OpenSOAR POST<br/>client.send_alert()"]
    end

    E1 --> Q
    E2 --> Q
    E3 --> Q
    E4 --> Q
    C1 --> Q
    Q --> D1
    D1 --> D2
    D2 --> Mapper
    M1 --> Dedup
    M2 --> Dedup
    M3 --> Dedup
    M4 --> Dedup
    Dedup --> SW
    Dedup --> PT
    PT --> OS
```

### Key Design Decisions

| Layer | Purpose | TTL/Storage |
|-------|---------|-------------|
| Batch dedup | Same poll cycle duplicates | In-memory set |
| Ever-seen | Never resend same ES doc | `data/seen_ids/{source}.json` (50K max) |
| Redis dedup | Content-based dedup | 5 minutes |
| Local DB dedup | Cross-restart dedup | SQLite, same TTL as Redis |

---

## 3. Hybrid API Strategy

```mermaid
flowchart TD
    subgraph Client["Frontend / API Consumer"]
        REQ["GET /api/v1/alerts?limit=50"]
    end

    subgraph Backend["FastAPI Route"]
        QL["Query Local SQLite"]
        QU["Query Upstream OpenSOAR"]
        MERGE["Merge Results<br/>• local IDs override upstream<br/>• upstream fills gaps<br/>• sort by created_at desc"]
        PAG["Apply Pagination<br/>offset + limit"]
    end

    subgraph Stores["Data Stores"]
        LDB["SQLite<br/>alerts table<br/>(shadow store)"]
        UOS["OpenSOAR API<br/>/api/v1/alerts"]
    end

    REQ --> QL
    REQ --> QU
    QL --> LDB
    QU --> UOS
    LDB --> MERGE
    UOS --> MERGE
    MERGE --> PAG
    PAG --> RES["{ alerts: [...], total: N, source: 'merged' }"]

    style LDB fill:#90EE90
    style UOS fill:#FFB6C1
    style MERGE fill:#87CEEB
```

### Why Hybrid?

| Scenario | Behavior |
|----------|----------|
| Local DB empty (cold start) | Returns upstream data immediately |
| Local DB has some data | Merges local + upstream; local takes precedence |
| Local DB fully populated | Still queries upstream to fill gaps (e.g., old data not yet shadowed) |
| Network partition | Local DB serves stale but available data |

---

## 4. Investigation Lifecycle & State Machine

```mermaid
stateDiagram-v2
    [*] --> pending: New incident discovered
    pending --> running: AI engine starts
    pending --> declined: Analyst declines

    running --> awaiting_approval: AI completes, playbook ready
    running --> completed: Auto-remediation succeeds
    running --> failed: AI error / timeout

    awaiting_approval --> approved: Analyst approves
    awaiting_approval --> declined: Analyst declines

    approved --> running: Ansible execution starts

    completed --> archived: Fix verified
    failed --> archived: Manual review complete
    declined --> archived: Analyst declines

    archived --> [*]
```

### State Transition Guards

```python
_ALLOWED_TRANSITIONS = {
    "pending": {"running", "declined"},
    "running": {"awaiting_approval", "completed", "failed"},
    "awaiting_approval": {"approved", "declined"},
    "approved": {"running"},
    "completed": {"archived"},
    "failed": {"archived"},
    "declined": {"archived"},
}
```

Invalid transitions return **HTTP 400** with allowed transitions list.

---

## 5. Dashboard Data Flow

```mermaid
flowchart LR
    subgraph FE["Frontend (page.tsx)"]
        SWR["SWR Polling<br/>refreshInterval: 30s"]
        WS["WebSocket<br/>investigation_updated"]
        CHART["Recharts<br/>trend + severity charts"]
    end

    subgraph BE["Dashboard API"]
        DS["/dashboard/summary"]
        DQ["/dashboard/quick-stats"]
        DT["/dashboard/trends"]
    end

    subgraph Local["Local SQLite"]
        A_COUNT["SELECT COUNT(*) FROM alerts"]
        I_COUNT["SELECT COUNT(*) FROM incidents"]
        INV_GB["SELECT status, COUNT(*) FROM investigations GROUP BY status"]
        ARC_COUNT["SELECT COUNT(*) FROM archives"]
        TREND["SELECT strftime('%Y-%m-%d %H:00', created_at), COUNT(*) FROM alerts GROUP BY hour"]
    end

    subgraph Upstream2["Upstream Fallback"]
        UOS2["OpenSOAR /api/v1/alerts<br/>(only if local=0)"]
    end

    SWR --> DS
    SWR --> DQ
    SWR --> DT
    WS --> SWR

    DS --> A_COUNT
    DS --> I_COUNT
    DS --> INV_GB
    DS --> ARC_COUNT
    DQ --> A_COUNT
    DQ --> I_COUNT
    DQ --> INV_GB
    DT --> TREND

    I_COUNT -.->|if empty| UOS2
    A_COUNT -.->|if empty| UOS2

    DS --> FE
    DQ --> FE
    DT --> CHART
```

### Dashboard Improvements vs Before

| Metric | Before | After |
|--------|--------|-------|
| Alerts total | `limit=200` upstream cap | Local `COUNT(*)` — no cap |
| Incidents total | `limit=200` upstream cap | Local `COUNT(*)` — no cap |
| Trend data | Client-side bucketing of 100 alerts | Server-side SQL `GROUP BY hour` |
| Time filters | None | `?range=15m\|1h\|24h\|7d` |
| Refresh | SWR 30s only | SWR 30s + WebSocket events |

---

## 6. AI Operator Flow

```mermaid
sequenceDiagram
    actor User
    participant FE as Frontend /operator
    participant API as /api/v1/operator/run
    participant LLM as Ollama / Google
    participant DB as SQLite OperatorRun
    participant APP as PlaybookApproval
    participant ANS as Ansible Executor

    User->>FE: "Check disk usage on ghazi"
    FE->>API: POST /operator/run<br/>{prompt, target_hosts, require_approval}
    API->>LLM: System prompt + user request
    LLM-->>API: JSON: {intent, playbook_yaml, risk_level, explanation}
    API->>API: Parse JSON response

    alt risk_level == "high" OR require_approval
        API->>DB: Create OperatorRun(status="pending")
        API->>APP: Create PlaybookApproval(decision="pending")
        API-->>FE: {run_id, status: "pending_approval", explanation}
        FE-->>User: Show plan + "Execute" button

        User->>FE: Click Execute
        FE->>API: POST /operator/runs/{run_id}/approve
        API->>DB: Update status="running"
        API->>ANS: _execute_operator_playbook()
        ANS-->>API: {exit_code, output}
        API->>DB: Update status="completed/failed", result_json
    else risk_level == "low/medium" AND auto-execute
        API->>DB: Create OperatorRun(status="running")
        API->>ANS: _execute_operator_playbook()
        ANS-->>API: {exit_code, output}
        API->>DB: Update status="completed/failed", result_json
    end
```

---

## 7. Whitelist System

```mermaid
flowchart TD
    subgraph Input["Input"]
        IP["IP: 192.168.1.1"]
        SUBNET["Subnet: 10.0.0.0/8"]
        DOMAIN["Domain: internal.corp"]
    end

    subgraph API_WL["Whitelist API"]
        ADD["POST /whitelist<br/>{type, value, label}"]
        LIST["GET /whitelist"]
        CHECK["GET /whitelist/check?value=..."]
        DEL["DELETE /whitelist/{id}"]
    end

    subgraph DB_WL["SQLite whitelist_entries"]
        T["type: ip|subnet|domain"]
        V["value"]
        L["label: internal|trusted|admin"]
    end

    subgraph Enforcement["Enforcement Points"]
        P1["Ansible Executor<br/>Before playbook run"]
        P2["Action Executor<br/>Before block/isolate"]
        P3["Poller<br/>Tag whitelisted alerts"]
    end

    IP --> ADD
    SUBNET --> ADD
    DOMAIN --> ADD
    ADD --> DB_WL
    LIST --> DB_WL
    CHECK --> DB_WL
    DEL --> DB_WL

    DB_WL --> P1
    DB_WL --> P2
    DB_WL --> P3
```

---

## 8. Suricata ↔ Wazuh Correlation

```mermaid
sequenceDiagram
    participant W as Wazuh Alert
    participant S as Suricata Alert
    participant C as Correlator
    participant DB as SQLite

    W->>DB: Persist alert<br/>{source: "wazuh", source_ip: "1.2.3.4", event_time: T}
    Note over W,DB: Within 5 minutes...
    S->>C: New Suricata alert<br/>{source: "suricata", source_ip: "1.2.3.4", event_time: T+2min}
    C->>DB: SELECT wazuh alert<br/>WHERE source_ip = "1.2.3.4"<br/>AND created_at >= now - 5min
    DB-->>C: Found matching Wazuh alert
    C->>DB: UPDATE suricata alert metadata<br/>SET correlated_wazuh_alert_id = ...<br/>SET correlated_wazuh_alert_title = ...
```

---

## 9. Data Consistency & Failure Modes

```mermaid
flowchart TD
    subgraph Normal["Normal Operation"]
        N1["Poller reads ES → maps → dedups → stores local → forwards upstream"]
        N2["API serves merged local + upstream"]
        N3["Dashboard shows accurate counts from local DB"]
    end

    subgraph Failure1["Local DB Empty (cold start / migration)"]
        F1a["API falls back to upstream OpenSOAR"]
        F1b["Dashboard shows upstream counts"]
        F1c["Frontend still works with full data"]
    end

    subgraph Failure2["Upstream OpenSOAR Down"]
        F2a["API serves only local data"]
        F2b["Poller stores alerts locally (retry queue for upstream)"]
        F2c["Dashboard shows local counts"]
    end

    subgraph Failure3["Redis Unavailable"]
        F3a["Deduplication falls back to memory cache"]
        F3b["Memory cache falls back to local DB check"]
        F3c["No duplicate alerts accepted"]
    end

    Normal --> Failure1
    Normal --> Failure2
    Normal --> Failure3
```

---

## 10. File Structure

```
opensoar backend/
├── api/
│   ├── app.py                          # FastAPI app with all routers
│   ├── routes/
│   │   ├── alerts.py                   # Hybrid local/upstream alerts API
│   │   ├── incidents.py                # Hybrid local/upstream incidents API
│   │   ├── investigations.py           # Lifecycle + state transitions
│   │   ├── dashboard.py                # Local aggregates + trends
│   │   ├── whitelist.py                # Whitelist CRUD
│   │   ├── operator.py                 # AI Operator endpoints
│   │   └── ...
│   └── websocket.py                    # Real-time broadcasts
├── pipeline/
│   ├── poller/
│   │   ├── main.py                     # Forwarder loop
│   │   └── alert_processor.py          # _persist_alert_local(), _link_suricata_to_wazuh()
│   ├── mappers/
│   │   ├── wazuh.py                    # Category detection, level filter
│   │   ├── suricata.py                 # IPS action, attack_status
│   │   └── ...
│   ├── services/
│   │   ├── dedup.py                    # Redis + memory + local DB
│   │   └── correlator.py               # Campaign detection
│   └── sender.py                       # OpenSOARClient
├── response/
│   ├── models.py                       # Alert, Incident, WhitelistEntry, OperatorRun
│   ├── archiver.py                     # Archive investigation + update incident
│   ├── ansible_exec.py                 # Whitelist check before execution
│   └── ai_engine/                      # LLM clients, prompt builder
├── core/
│   └── whitelist.py                    # is_whitelisted(), check_alert_whitelist()
└── frontend/
    └── app/(dashboard)/
        ├── operator/page.tsx             # AI Operator chat UI
        └── ...
```

---

## 11. Reliability Checklist

| Component | Failure Mode | Mitigation |
|-----------|-------------|------------|
| Local SQLite | DB locked / corrupt | `aiosqlite` async driver, auto-retry on commit |
| OpenSOAR upstream | Network down / 503 | API falls back to local; poller uses retry queue |
| Redis | Connection refused | Deduplication falls back to memory → local DB |
| LLM (Ollama/Google) | Timeout / 503 | AI Operator returns error; investigation gets `ai_error` |
| Ansible target | SSH auth fail / unreachable | Status set to `failed`; retry possible |
| Whitelist | Missing critical entry | Default-deny for blocks; all checks are logged |
| Poller | ES query timeout | Skip cycle; cursor not advanced; retry next cycle |
| Frontend | Stale bundle | Hard refresh (`Ctrl+F5`) after rebuild |
