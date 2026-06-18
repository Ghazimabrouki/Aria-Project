# ARIA - Backend Processes Documentation

**Service:** ARIA - Adaptive Response Intelligence Automation  
**Version:** 1.4.0  
**Base URL:** `http://localhost:8001`

---

## Table of Contents

1. [Watcher - Incident Polling](#1-watcher---incident-polling)
2. [AI Engine - Investigation Analysis](#2-ai-engine---investigation-analysis)
3. [Ansible - Remediation Execution](#3-ansible---remediation-execution)
4. [Auto-Approve System](#4-auto-approve-system)
5. [Pipeline - Alert Forwarding](#5-pipeline---alert-forwarding)
6. [Monitoring APIs](#6-monitoring-apis)
7. [Investigation Workflow APIs](#7-investigation-workflow-apis)
8. [Execution Tracking APIs](#8-execution-tracking-apis)

---

## 1. Watcher - Incident Polling

### What is Watcher?
The Watcher polls OpenSOAR for new "open" incidents every 15 seconds. When found, it creates an investigation and triggers AI analysis.

### How it Works

```
OpenSOAR (Port 8000) → Watcher (15s interval) → Investigation Created → AI Analysis
```

### Watcher Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/monitor/services-status` | GET | Check if Watcher is running |
| `/monitor/health` | GET | System health including Watcher |

### Watcher Status Response

```json
{
  "services": {
    "incident_watcher": {
      "name": "Incident Watcher",
      "status": "running",
      "poll_interval": 15,
      "description": "Polls OpenSOAR for new incidents"
    }
  },
  "total_running": 10
}
```

---

## 2. AI Engine - Investigation Analysis

### What is AI Engine?
The AI Engine uses NVIDIA NIM API (qwen/qwen2.5-coder-32b-instruct) to analyze incidents and generate:
- **AI Summary**: Brief summary of the threat
- **AI Narrative**: Detailed narrative of what happened
- **AI Risk**: Risk assessment
- **Playbook**: Ansible playbook for remediation

### How it Works

```
Investigation Created → AI Engine → NVIDIA NIM API → Playbook Generated → Awaiting Approval
```

### AI Response Fields (in Investigation)

```json
{
  "ai_summary": "SSH brute force attack detected from IP 1.2.3.4. Multiple failed authentication attempts were made to target host ghazi.",
  "ai_narrative": "At approximately 14:30 UTC, an external attacker initiated a brute force attack against the SSH service on target host ghazi (10.175.1.137). The attacker tried 150 different username/password combinations over a 5-minute window. All attempts were blocked by the SSH server's built-in protections, but the repeated attempts indicate an active reconnaissance effort.",
  "ai_risk": "MEDIUM - While no successful authentication occurred, the attacker demonstrates persistent interest in compromising this system. Recommend blocking source IP and reviewing authentication logs.",
  "playbook_yaml": "- name: Block SSH Brute Force Attacker\n  hosts: ghazi\n  become: yes\n  tasks:\n    - name: Block attacker IP in iptables\n      iptables:\n        chain: INPUT\n        source: 1.2.3.4\n        jump: DROP"
}
```

### AI Assistant Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/assistant/context` | GET | Available data sources |
| `/api/v1/assistant/sources` | GET | Source statistics |
| `/api/v1/assistant/health` | GET | AI health status |
| `/api/v1/assistant/query` | POST | Ask AI questions |

### AI Health Response

```json
{
  "status": "healthy",
  "llm_available": true,
  "model": "qwen/qwen2.5-coder-32b-instruct"
}
```

### Ask AI Question

**Endpoint:** `POST /api/v1/assistant/query`

**Input:**
```json
{
  "question": "How many critical alerts do we have?",
  "context": { "time_range": "1h" },
  "sources": ["all"]
}
```

**Output:**
```json
{
  "answer": "You have 5 critical alerts in the last hour. The main threats are: SSH brute force attacks, suspicious authentication patterns, and potential privilege escalation attempts.",
  "sources": [
    { "type": "incident", "id": "uuid", "title": "SSH Brute Force Attack" }
  ],
  "statistics": {
    "archives": 5,
    "active_investigations": 3,
    "live_alerts_incidents": 8
  },
  "record_count": 15,
  "recommendations": [
    { "action": "Approve playbook", "investigation_id": "uuid" }
  ]
}
```

---

## 3. Ansible - Remediation Execution

### What is Ansible?
Ansible executes the generated playbook on the target host to remediate the threat. It SSHs into the target and runs tasks defined in the playbook.

### How it Works

```
Playbook Approved → Ansible Exec → SSH to Target → Run Tasks → Capture Output → Verify Fix
```

### Playbook Execution Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/investigations/{id}/execute` | POST | Execute playbook directly |
| `/api/v1/investigations/{id}/approve` | POST | Approve + execute playbook |
| `/api/v1/investigations/{id}/run-status` | GET | Get execution status |

### Approve Investigation (Triggers Ansible)

**Endpoint:** `POST /api/v1/investigations/{investigation_id}/approve`

**Input:**
```json
{
  "decided_by": "admin"
}
```

**Output:**
```json
{
  "message": "Playbook approved. Execution started.",
  "investigation_id": "uuid"
}
```

### Execute Directly

**Endpoint:** `POST /api/v1/investigations/{investigation_id}/execute`

**Output:**
```json
{
  "message": "Playbook execution started",
  "investigation_id": "uuid",
  "run_id": "run-uuid"
}
```

### Run Status Response

**Endpoint:** `GET /api/v1/investigations/{investigation_id}/run-status`

**Output:**
```json
{
  "investigation_id": "uuid",
  "run_id": "run-uuid",
  "status": "completed",
  "started_at": "2026-04-13T18:00:00Z",
  "completed_at": "2026-04-13T18:00:40Z",
  "duration_seconds": 40,
  "exit_code": 0,
  "output": "PLAY RECAP\nghazi : ok=1 changed=0 unreachable=0 failed=0",
  "tasks": [
    { "name": "Gathering Facts", "status": "ok" },
    { "name": "Block attacker IP", "status": "ok" },
    { "name": "Restart service", "status": "ok" },
    { "name": "Verify fix", "status": "ok" }
  ]
}
```

### Playbook YAML

**Endpoint:** `GET /api/v1/investigations/{investigation_id}/playbook/yaml`

**Output:**
```yaml
---
# AUTO-GENERATED ANSIBLE PLAYBOOK
# Designed for: SSH Brute Force Attack remediation
# Target hosts: ghazi

- name: Remediation - SSH Brute Force Attack
  hosts: ghazi
  become: yes
  gather_facts: yes
  vars:
    attacker_ips: ["1.2.3.4", "2.3.4.5"]
    target_ips: []
    attacker_ports: []
  tasks:
    - name: Block attacker IPs in iptables
      iptables:
        chain: INPUT
        source: "{{ item }}"
        jump: DROP
      loop: "{{ attacker_ips }}"
      when: attacker_ips | length > 0

    - name: Block SSH for attackers
      lineinfile:
        path: /etc/ssh/sshd_config
        line: "DenyUsers attacker"
      when: false
```

---

## 4. Auto-Approve System

### What is Auto-Approve?
The Auto-Approve system automatically approves low and medium severity investigations without human intervention.

### How it Works

```
AI Analysis Complete → Check Severity → 
  If LOW/MEDIUM → Auto-Approve → Run Playbook
  If HIGH/CRITICAL → Human Review Required
```

### Auto-Approve Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/monitor/auto-approve-stats` | GET | Auto-approve statistics |
| `/monitor/auto-approve-config` | GET | Auto-approve configuration |

### Auto-Approve Stats Response

```json
{
  "total_investigations": 100,
  "auto_approved": 65,
  "human_approved": 35,
  "auto_approve_rate_pct": 65.0,
  "by_severity": {
    "critical": { "total": 10, "auto": 0, "human": 10 },
    "high": { "total": 20, "auto": 5, "human": 15 },
    "medium": { "total": 40, "auto": 35, "human": 5 },
    "low": { "total": 30, "auto": 30, "human": 0 }
  },
  "rejected_auto_approve": 5,
  "rejection_reasons": ["suspicious_auth", "brute_force", "privilege_escalation"]
}
```

### Auto-Approve Config Response

```json
{
  "enabled": true,
  "auto_approve_severities": ["low", "medium"],
  "block_severities": ["critical", "high"],
  "additional_checks": ["attack_pattern", "failed_threshold", "privilege_level"]
}
```

---

## 5. Pipeline - Alert Forwarding

### What is Pipeline?
The Pipeline forwards alerts from Elasticsearch to OpenSOAR. It polls every 10 seconds.

### How it Works

```
Elasticsearch → Poller (10s) → Normalize → Enrich → OpenSOAR → Advance Cursor
```

### Pipeline Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/pipeline/status` | GET | Pipeline status |
| `/api/v1/pipeline/sources` | GET | Tracked sources |
| `/api/v1/pipeline/cursors` | GET | Cursor positions |
| `/api/v1/pipeline/trace/alert/{id}` | GET | Alert lifecycle |

### Pipeline Status Response

```json
{
  "running": true,
  "poll_interval": 10,
  "batch_size": 50,
  "description": "Alert pipeline from Elasticsearch to OpenSOAR"
}
```

### Pipeline Sources Response

```json
{
  "sources": [
    {
      "source": "wazuh",
      "cursor": "2026-04-11T23:38:39.266000+00:00",
      "documents_tracked": 5060,
      "index_pattern": "wazuh-alerts-4.x-*"
    },
    {
      "source": "suricata",
      "cursor": "2026-04-12T23:32:59.074617+00:00",
      "documents_tracked": 5010,
      "index_pattern": "suricata-events-*"
    },
    {
      "source": "falco",
      "cursor": "2026-04-12T23:32:59.074617+00:00",
      "documents_tracked": 1500,
      "index_pattern": "falco-events-*"
    },
    {
      "source": "filebeat",
      "cursor": "2026-04-12T07:14:17.764000+00:00",
      "documents_tracked": 500,
      "index_pattern": "filebeat-*"
    }
  ]
}
```

### Alert Trace

**Endpoint:** `GET /api/v1/pipeline/trace/alert/{alert_id}`

**Output:**
```json
{
  "alert_id": "uuid",
  "steps": [
    { "step": "elasticsearch_indexed", "timestamp": "..." },
    { "step": "poller_picked_up", "timestamp": "..." },
    { "step": "normalized", "timestamp": "..." },
    { "step": "enriched", "timestamp": "..." },
    { "step": "forwarded_to_opensar", "timestamp": "..." },
    { "step": "incident_created", "timestamp": "..." }
  ]
}
```

---

## 6. Monitoring APIs

### System Status Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/monitor/stats` | GET | System statistics |
| `/monitor/health` | GET | System health |
| `/monitor/services-status` | GET | All services status |
| `/monitor/stuck-investigations` | GET | Stuck > 1 hour |

### Services Status Response

```json
{
  "services": {
    "api_server": {
      "name": "API Server",
      "status": "running",
      "port": 8001
    },
    "forwarder": {
      "name": "Alert Forwarder",
      "status": "running",
      "poll_interval": 10,
      "sources": ["wazuh", "suricata", "falco", "filebeat"]
    },
    "incident_watcher": {
      "name": "Incident Watcher",
      "status": "running",
      "poll_interval": 15
    },
    "auto_transitions": {
      "name": "Auto Transitions",
      "status": "running"
    },
    "retry_queue": {
      "name": "Retry Queue",
      "status": "running"
    },
    "backup": {
      "name": "Database Backup",
      "status": "running"
    },
    "health_monitor": {
      "name": "Health Monitor",
      "status": "running"
    },
    "performance_monitoring": {
      "name": "Performance Monitoring",
      "status": "running",
      "poll_interval": 30
    }
  },
  "total_running": 10,
  "total_disabled": 0
}
```

### Stuck Investigations

**Endpoint:** `GET /monitor/stuck-investigations`

**Output:**
```json
{
  "investigations": [
    {
      "id": "uuid",
      "status": "running",
      "duration_minutes": 65,
      "last_update": "2026-04-13T17:00:00Z"
    }
  ],
  "total": 1
}
```

### Logs Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/monitor/logs/recent` | GET | Recent logs |
| `/monitor/services/{service}/logs` | GET | Service logs |
| `/monitor/services/{service}/errors` | GET | Service errors |

---

## 7. Investigation Workflow APIs

### Investigation Lifecycle

```
pending → running → awaiting_approval → approved → running → completed → archived
                                        ↓
                                      declined → archived
```

### Investigation Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/investigations` | GET | List investigations |
| `/api/v1/investigations/{id}` | GET | Investigation detail |
| `/api/v1/investigations/stats` | GET | Stats by status |
| `/api/v1/investigations/{id}/approve` | POST | Approve + execute |
| `/api/v1/investigations/{id}/decline` | POST | Decline + archive |
| `/api/v1/investigations/{id}/execute` | POST | Execute directly |
| `/api/v1/investigations/{id}/archive` | POST | Archive |
| `/api/v1/investigations/{id}/timeline` | GET | Event timeline |
| `/api/v1/investigations/{id}/run-status` | GET | Execution status |

### Investigation Status Response

```json
{
  "id": "uuid",
  "incident_id": "inc-uuid",
  "incident_title": "SSH Brute Force Attack",
  "status": "awaiting_approval",
  "severity": "high",
  "ai_summary": "...",
  "ai_narrative": "...",
  "ai_risk": "...",
  "playbook_yaml": "...",
  "playbook_valid": true,
  "target_host": "ghazi",
  "created_at": "2026-04-13T17:00:00Z",
  "updated_at": "2026-04-13T17:05:00Z"
}
```

### Investigation Timeline

**Endpoint:** `GET /api/v1/investigations/{id}/timeline`

**Output:**
```json
{
  "investigation_id": "uuid",
  "events": [
    { "type": "created", "timestamp": "2026-04-13T17:00:00Z" },
    { "type": "ai_started", "timestamp": "2026-04-13T17:00:01Z" },
    { "type": "ai_completed", "timestamp": "2026-04-13T17:05:00Z", "playbook_generated": true },
    { "type": "approved", "timestamp": "2026-04-13T17:10:00Z", "decided_by": "admin" },
    { "type": "playbook_execution_completed", "timestamp": "2026-04-13T17:15:00Z", "exit_code": 0 },
    { "type": "fix_verified", "timestamp": "2026-04-13T17:16:00Z", "fix_status": "likely_fixed" },
    { "type": "archived", "timestamp": "2026-04-13T17:20:00Z" }
  ]
}
```

---

## 8. Execution Tracking APIs

### Playbook Runs

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/monitor/playbook-runs` | GET | All playbook executions |
| `/monitor/execution-stats` | GET | Execution statistics |
| `/monitor/forwarder-status` | GET | Forwarder status |

### Playbook Runs Response

```json
{
  "runs": [
    {
      "id": "uuid",
      "investigation_id": "inv-uuid",
      "status": "completed",
      "exit_code": 0,
      "started_at": "2026-04-13T17:00:00Z",
      "finished_at": "2026-04-13T17:00:40Z"
    }
  ],
  "total": 10
}
```

### Execution Stats Response

```json
{
  "total_runs": 64,
  "successful": 55,
  "failed": 9,
  "success_rate_pct": 85.9,
  "by_playbook_type": {
    "block_ip": { "total": 40, "success": 38 },
    "restart_service": { "total": 20, "success": 17 },
    "clean_disk": { "total": 4, "success": 0 }
  },
  "avg_duration_seconds": 45,
  "last_24h": { "runs": 25, "success": 22 }
}
```

### Forwarder Status Response

```json
{
  "running": true,
  "poll_interval_seconds": 10,
  "last_poll": "2026-04-13T18:05:35Z",
  "documents_processed_24h": 15000,
  "errors_24h": 0,
  "sources": {
    "wazuh": { "status": "ok", "documents": 5000 },
    "suricata": { "status": "ok", "documents": 8000 },
    "falco": { "status": "ok", "documents": 1500 },
    "filebeat": { "status": "ok", "documents": 500 }
  }
}
```

### Pipeline Health

**Endpoint:** `GET /monitor/pipeline-health`

**Output:**
```json
{
  "overall_status": "healthy",
  "elasticsearch": { "status": "ok", "latency_ms": 45 },
  "redis": { "status": "ok", "latency_ms": 2 },
  "opensora": { "status": "ok", "latency_ms": 120 },
  "forwarder": { "status": "ok", "last_poll": "5s ago" },
  "cursor_tracking": { "status": "ok" }
}
```

---

## Complete Process Flow

### Full Backend Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ARIA BACKEND PROCESSES                              │
└─────────────────────────────────────────────────────────────────────────────┘

1. ALERT SOURCES (Elasticsearch)
   ┌──────────┐  ┌───────────┐  ┌────────┐  ┌──────────┐
   │  Wazuh   │  │ Suricata  │  │ Falco  │  │Filebeat │
   └─────┬────┘  └──────┬────┘  └──┬────┘  └────┬─────┘
         │            │          │          │
         ▼            ▼          ▼          ▼
2. PIPELINE - ALERT FORWARDER (10s)
   ┌──────────────────────────────────────────────┐
   │  Query ES → Normalize → Enrich → OpenSOAR    │
   │  GeoIP, MITRE, Sigma, IOCs                   │
   └─────��──────────────┬───────────────────────────┘
                       │
                       ▼
3. OPENSOAR - INCIDENT MANAGEMENT
   ┌──────────────────────────────────────────────┐
   │  Create Alert → Create Incident              │
   └────────────────────┬───────────────────────────┘
                        │
                        ▼
4. WATCHER - INCIDENT POLLING (15s)
   ┌──────────────────────────────────────────────┐
   │  Poll OpenSOAR → Find "open" incidents        │
   │  → Create Investigation                   │
   └────────────────────┬───────────────────────────┘
                           │
                           ▼
5. AI ENGINE - INVESTIGATION (NVIDIA NIM)
   ┌──────────────────────────────────────────────┐
   │  Analyze → Summary → Narrative → Risk      │
   │  → Generate Playbook                   │
   └────────────────────┬───────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          ▼                             ▼
6. AUTO-APPROVE                 7. HUMAN APPROVAL
   (low/medium)                  (high/critical)
        │                             │
        ▼                             ▼
8. ANSIBLE - REMEDIATION
   ┌──────────────────────────────────────────────┐
   │  SSH → Execute Playbook → Get Exit Code    │
   └────────────────────┬───────────────────────────┘
                         │
                         ▼
9. FIX VERIFIER
   ┌──────────────────────────────────────────────┐
   │  Re-query ES → Check Recurrence            │
   │  → Mark: likely_fixed / not_fixed        │
   └────────────────────┬───────────────────────────┘
                        │
                        ▼
10. ARCHIVER
    ┌──────────────────────────────────────────────┐
    │  Store Full Context → Calculate Success Rate │
    │  → Ready for Reports                   │
    └─────────────────────────────────────────────┘
```

---

**Version:** 1.4.0  
**Last Updated:** April 13, 2026