# ARIA - Complete API Documentation for Frontend Developer

**Service:** ARIA - Adaptive Response Intelligence Automation  
**Version:** 1.5.1  
**Base URL:** `http://193.95.30.97:8001` (Production)
**Base URL:** `http://localhost:8001` (Development)

---

## Table of Contents

1. [Quick Start for Frontend](#1-quick-start-for-frontend)
2. [API Overview](#2-api-overview)
3. [Alert Entities](#3-alert-entities)
4. [Incident Entities](#4-incident-entities)
5. [Investigation Entities](#5-investigation-entities)
6. [Archive Entities](#6-archive-entities)
7. [Pipeline Entities](#7-pipeline-entities)
8. [Performance Entities](#8-performance-entities)
9. [Search Entities](#9-search-entities)
10. [Dashboard Entities](#10-dashboard-entities)
11. [IPS Map Entities](#11-ips-map-entities)
12. [AI Assistant Entities](#12-ai-assistant-entities)
13. [Monitoring Entities](#13-monitoring-entities)
14. [Frontend Workflows](#14-frontend-workflows)
15. [Entity Relationships](#15-entity-relationships)
16. [Complete Navigation Flow](#16-complete-navigation-flow)

---

## 1. Quick Start for Frontend

### Base Configuration

```javascript
// Frontend base configuration
const API_BASE = 'http://localhost:8001';
const API_VERSION = '/api/v1';

// All endpoints will use this base
const FULL_API_BASE = API_BASE + API_VERSION;
```

### Health Check (First Call)

```javascript
// Check if backend is running
const response = await fetch(`${API_BASE}/health`);
const data = await response.json();
// Expected: { "status": "ok" }
```

### Quick Stats (Dashboard Header)

**Endpoint:** `GET /api/v1/dashboard/quick-stats`

```javascript
// Get all counts in one call
const response = await fetch(`${FULL_API_BASE}/dashboard/quick-stats`);
const data = await response.json();
```

**Output:**
```javascript
{
  "alerts": 849,
  "incidents": 64,
  "investigations": 64,
  "archives": 20
}
```

---

## 2. API Overview

### All API Categories

| Category | Purpose | Path |
|----------|--------|------|
| Alerts | Security alerts from Wazuh, Suricata, Falco | `/alerts` |
| Incidents | Cases created from alerts | `/incidents` |
| Investigations | AI analysis + playbook | `/investigations` |
| Archives | Closed cases | `/archives` |
| Pipeline | Alert forwarding status | `/pipeline` |
| Performance | Server metrics | `/metrics` |
| Search | Global search | `/search` |
| Dashboard | Summary counts | `/dashboard` |
| IPS Map | Attack visualization | `/ips` |
| AI Assistant | Ask questions | `/assistant` |
| Monitoring | System health | `/monitor` |

---

## 3. Alert Entities

### What are Alerts?
Alerts are raw security events from:
- **Wazuh** - HIDS alerts
- **Suricata** - IDS/IPS alerts
- **Falco** - Kubernetes runtime security
- **Filebeat** - File integrity monitoring

### List Alerts

**Endpoint:** `GET /api/v1/alerts`

**Input:**
```javascript
{
  limit: 50,           // Number of results (1-200, default: 50)
  offset: 0,           // Skip first N results (default: 0)
  status: "new",       // Filter: new, open, investigating, closed
  severity: "high",    // Filter: critical, high, medium, low
  source: "suricata",  // Filter: wazuh, suricata, falco, filebeat
  hostname: "ghazi"    // Filter by target host
}
```

**Output:**
```javascript
{
  "alerts": [
    {
      "id": "30be7820-7282-40e6-b876-5f0cb3210925",
      "source": "generic",
      "source_id": "cd15e208-548e-4a2b-af0d-00df92dd110d",
      "title": "Performance Alert - Network incoming at 5056.1 MB/s (threshold: 476.8 MB/s)",
      "description": "Host: ghazi",
      "severity": "high",
      "status": "new",
      "source_ip": "",
      "dest_ip": "",
      "hostname": "ghazi",
      "rule_name": "Performance Alert",
      "iocs": { "ips": [], "hashes": [], "domains": [], "urls": [] },
      "tags": ["source-generic"],
      "created_at": "2026-04-15T11:36:29.447560Z",
      "updated_at": "2026-04-15T11:36:37.549173Z"
    },
    {
      "id": "291c2e8d-64cb-4dda-9394-7a4a2831fa6c",
      "source": "generic",
      "source_id": "...",
      "title": "Performance Alert - Network incoming at 5056.1 MB/s",
      "severity": "high",
      "status": "new",
      "hostname": "ghazi",
      "created_at": "2026-04-15T11:30:00Z"
    }
  ],
  "total": 435,
  "limit": 50,
  "offset": 0
}
```
```

### Get Single Alert

**Endpoint:** `GET /api/v1/alerts/{alert_id}`

**Input:** No parameters (alert_id in URL)

**Output:**
```javascript
{
  "data": {
    "id": "uuid-string",
    "source": "suricata",
    "title": "ET SCAN Potential SSH Scan",
    // ... all alert fields
  },
  "relationships": {
    "incidents": {
      "count": 3,
      "items": [
        { "id": "inc-uuid", "title": "..." }
      ],
      "view_all": "/api/v1/alerts/{alert_id}/incidents"
    },
    "similar": {
      "count": 10,
      "items": [
        { "id": "alert-uuid", "source_ip": "..." }
      ],
      "view_all": "/api/v1/alerts/{alert_id}/similar"
    }
  },
  "actions": {
    "view_timeline": "/api/v1/incidents/{incident_id}/timeline",
    "search_ip": "/api/v1/search/ips/{ip}"
  }
}
```

### Get Alert's Incidents

**Endpoint:** `GET /api/v1/alerts/{alert_id}/incidents`

**Input:** No parameters

**Output:**
```javascript
{
  "incidents": [
    {
      "id": "inc-uuid",
      "title": "Incident title",
      "severity": "high"
    }
  ],
  "total": 3
}
```

### Get Similar Alerts

**Endpoint:** `GET /api/v1/alerts/{alert_id}/similar`

**Input:** No parameters

**Purpose:** Find alerts with same source IP

**Output:**
```javascript
{
  "alerts": [
    {
      "id": "uuid",
      "title": "...",
      "source_ip": "same-ip",
      "created_at": "..."
    }
  ],
  "total": 10
}
```

### Frontend: Alert Page

```javascript
// Alert list page should show:
// - Table with columns: Time, Title, Source IP, Severity, Status
// - Click row → Go to Alert Detail
// - Click "Incidents" → Go to incidents page with this alert filtered
// - Click "Similar" → Go to alerts page with same IP filtered
```

---

## 4. Incident Entities

### What are Incidents?
Incidents are cases created in OpenSOAR from one or more alerts. They represent a security event that needs investigation.

### List Incidents

**Endpoint:** `GET /api/v1/incidents`

**Input:**
```javascript
{
  limit: 50,
  offset: 0,
  status: "open",     // Filter: open, closed
  severity: "high",   // Filter: critical, high, medium, low
  assignee: "admin"  // Filter by assigned user
}
```

**Output:**
```javascript
{
  "incidents": [
    {
      "id": "f375b756-8b55-4355-bb49-8067fb46763c",
      "title": "ET CINS Active Threat Intelligence Poor Reputation IP group — 141.98.83.48 on ghazi",
      "description": "Malicious IP activity detected",
      "severity": "medium",
      "status": "open",
      "assigned_to": null,
      "assigned_username": null,
      "tags": ["source-suricata", "cloud-Flyservers S.A."],
      "alert_count": 2,
      "closed_at": null,
      "created_at": "2026-04-15T10:00:00.000000Z",
      "updated_at": "2026-04-15T10:00:00.000000Z"
    },
    {
      "id": "9ab5b3ce-1c5f-4527-8b55-4355-bb49-8067fb46763c",
      "title": "SSH Brute Force Attack — 121.146.70.26 (KR) [8 alerts]",
      "description": "Critical SSH brute force attack from Korea",
      "severity": "critical",
      "status": "open",
      "tags": ["cloud-Korea Telecom", "high-risk", "mitre-tactic-Credential Access", "attack-ssh_brute_force"],
      "alert_count": 8,
      "created_at": "2026-04-15T09:49:20.132561Z"
    }
  ],
  "total": 30,
  "limit": 50,
  "offset": 0
}
}
```

### Get Single Incident

**Endpoint:** `GET /api/v1/incidents/{incident_id}`

**Output:**
```javascript
{
  "data": {
    "id": "uuid",
    "title": "Incident title",
    "description": "...",
    "severity": "high",
    "status": "open",
    "tags": [],
    "alert_count": 1,
    "created_at": "...",
    "updated_at": "..."
  },
  "relationships": {
    "alerts": {
      "count": 1,
      "items": [...],
      "view_all": "/api/v1/incidents/{id}/alerts"
    },
    "timeline": {
      "exists": true,
      "view": "/api/v1/incidents/{id}/timeline"
    },
    "investigations": {
      "exists": true,
      "view": "/api/v1/incidents/{id}/investigations"
    }
  }
}
```

### Get Incident Alerts

**Endpoint:** `GET /api/v1/incidents/{incident_id}/alerts`

**Output:**
```javascript
{
  "alerts": [...],
  "total": 1
}
```

### Get Incident Timeline

**Endpoint:** `GET /api/v1/incidents/{incident_id}/timeline`

**Purpose:** Full lifecycle of incident from creation to closure

**Output:**
```javascript
{
  "incident_id": "uuid",
  "total_events": 5,
  "events": [
    {
      "type": "created",
      "timestamp": "2026-04-13T18:08:27Z",
      "description": "Incident created from alert"
    },
    {
      "type": "investigation_started",
      "timestamp": "2026-04-13T18:08:30Z",
      "investigation_id": "inv-uuid"
    },
    {
      "type": "ai_completed",
      "timestamp": "2026-04-13T18:08:45Z",
      "playbook_generated": true
    },
    {
      "type": "approved",
      "timestamp": "2026-04-13T18:09:00Z",
      "decided_by": "admin"
    },
    {
      "type": "remediation_completed",
      "timestamp": "2026-04-13T18:09:30Z",
      "fix_verified": true
    }
  ]
}
```

### Get Incident Investigations

**Endpoint:** `GET /api/v1/incidents/{incident_id}/investigations`

**Output:**
```javascript
{
  "investigations": [...],
  "total": 1
}
```

### Get Incidents by Alert

**Endpoint:** `GET /api/v1/incidents/by-alert/{alert_id}`

**Output:**
```javascript
{
  "incidents": [...],
  "total": 1
}
```

### Create Incident

**Endpoint:** `POST /api/v1/incidents`

**Input:**
```javascript
{
  "title": "Test Incident - Live Test",
  "description": "Auto-created by live test script to verify incident creation and alert linking",
  "severity": "medium",
  "tags": ["live-test", "automated", "datausage-test"]
}
```

**Output:**
```javascript
{
  "id": "1c5f4527-8b55-4355-bb49-8067fb46763c",
  "title": "Test Incident - Live Test",
  "severity": "medium",
  "tags": ["live-test", "automated", "datausage-test"],
  "status": "open",
  "created_at": "2026-04-15T12:46:18.000000Z"
}
```

### Link Alert to Incident

**Endpoint:** `POST /api/v1/incidents/{incident_id}/alerts`

**Input:**
```javascript
{
  "alert_id": "30be7820-7282-40e6-b876-5f0cb3210925"
}
```

**Output:**
```javascript
{
  "id": "30be7820-7282-40e6-b876-5f0cb3210925",
  "source": "generic",
  "title": "Performance Alert - Network incoming at 5056.1 MB/s",
  "severity": "high",
  "status": "new"
}
```

### Get Incident Suggestions

**Endpoint:** `GET /api/v1/incidents/suggestions`

**Purpose:** Get suggested incident correlations - groups of unlinked alerts that could form new incidents.

**Output:**
```javascript
[
  {
    "source_ip": "",
    "alert_count": 2,
    "alerts": [
      {
        "id": "30be7820-7282-40e6-b876-5f0cb3210925",
        "source": "generic",
        "title": "Performance Alert - Network incoming at 5056.1 MB/s (threshold: 476.8 MB/s)",
        "description": "Host: ghazi",
        "severity": "high",
        "status": "new",
        "hostname": "ghazi"
      }
    ]
  },
  {
    "source_ip": "119.13.69.71",
    "alert_count": 7,
    "alerts": [...]
  }
]
```

**Note:** Returns groups of 2+ unlinked alerts from OpenSOAR. Used by ARIA correlation engine to automatically create incidents. Now includes hostname-based grouping when source_ip is empty.

### Frontend: Incident Page

```javascript
// Incident list should show:
// - Table: Time, Title, Severity, Status, Alert Count
// - Click row → Incident Detail

// Incident detail should show:
// - Header: Title, Severity badge, Status badge
// - Description section
// - Timeline tab (shows full lifecycle)
// - Alerts tab (linked alerts)
// - Related investigations
// - Navigation: Click alert → Alert detail
// - Navigation: Click investigation → Investigation detail
```

---

## 5. Investigation Entities

### What are Investigations?
Investigations are AI-generated analyses with playbook recommendations. They link to incidents and go through approval workflow.

### Investigation Statuses

| Status | Meaning | Can Approve? |
|--------|---------|---------------|
| `pending` | Just created, waiting for AI | No |
| `running` | AI is analyzing | No |
| `awaiting_approval` | Playbook ready | Yes |
| `approved` | Analyst approved | No |
| `declined` | Analyst declined | No |
| `running` | Ansible executing | No |
| `completed` | Remediation done + verified | No |
| `failed` | Error occurred | No |
| `archived` | Case closed | No |

### List Investigations

**Endpoint:** `GET /api/v1/investigations`

**Input:**
```javascript
{
  limit: 50,
  offset: 0,
  status: "awaiting_approval",  // Filter by status
  source: "security",           // Filter: security, performance
  severity: "high"              // Filter by severity
}
```

**Output:**
```javascript
{
  "investigations": [
    {
      "id": "uuid-string",
      "incident_id": "inc-uuid",
      "incident_title": "SSH Brute Force Attack — 117.50.130.90 (CN)",
      "status": "awaiting_approval",
      "severity": "high",
      "source_ips": ["117.50.130.90"],
      "created_at": "2026-04-13T17:00:00Z",
      "updated_at": "2026-04-13T17:05:00Z"
    }
  ],
  "total": 118
}
```

### Get Investigation Stats

**Endpoint:** `GET /api/v1/investigations/stats`

**Output:**
```javascript
{
  "pending": 5,
"awaiting_approval": 18,
  "approved": 0,
  "declined": 0,
  "running": 0,
  "completed": 4,
  "failed": 1,
  "archived": 5,
  "declined": 0,
  "total": 93
}
```

### Get Single Investigation

**Endpoint:** `GET /api/v1/investigations/{investigation_id}`

**Output:**
```javascript
{
  "id": "uuid",
  "incident_id": "inc-uuid",
  "incident_title": "SSH Brute Force Attack — 117.50.130.90 (CN)",
  "incident_severity": "high",
  "status": "awaiting_approval",
  
  "ai_summary": "AI generated summary of the threat...",
  "ai_narrative": "AI generated narrative of what happened...",
  "ai_risk": "AI generated risk assessment...",
  
  "playbook_yaml": "# Ansible playbook in YAML format...",
  "playbook_valid": true,
  "playbook_error": null,
  
  "target_host": "ghazi",
  
  "created_at": "...",
  "updated_at": "..."
}
```

### Get Playbook YAML

**Endpoint:** `GET /api/v1/investigations/{investigation_id}/playbook/yaml`

**Output:**
```javascript
{
  "yaml": "--- # Ansible playbook\n- name: Remediation...\n  hosts: ghazi\n  become: yes\n  tasks:\n    - name: Block attacker IP\n      iptables:\n        ...",
  "valid": true,
  "investigation_id": "uuid"
}
```

### Approve Investigation

**Endpoint:** `POST /api/v1/investigations/{investigation_id}/approve`

**Input:**
```javascript
{
  "decided_by": "admin"  // Username of person approving
}
```

**Output:**
```javascript
{
  "message": "Playbook approved. Execution started.",
  "investigation_id": "uuid"
}
```

### Decline Investigation

**Endpoint:** `POST /api/v1/investigations/{investigation_id}/decline`

**Input:**
```javascript
{
  "decided_by": "admin",
  "reason": "Not needed"  // Optional reason
}
```

**Output:**
```javascript
{
  "message": "Investigation declined and queued for archive",
  "investigation_id": "uuid"
}
```

### Get Investigation Timeline

**Endpoint:** `GET /api/v1/investigations/{investigation_id}/timeline`

**Output:**
```javascript
{
  "investigation_id": "uuid",
  "events": [
    {
      "type": "created",
      "timestamp": "2026-04-13T17:00:00Z"
    },
    {
      "type": "ai_started",
      "timestamp": "2026-04-13T17:00:01Z"
    },
    {
      "type": "ai_completed",
      "timestamp": "2026-04-13T17:05:00Z",
      "playbook_generated": true
    },
    {
      "type": "approved",
      "timestamp": "2026-04-13T17:10:00Z",
      "decided_by": "admin"
    },
    {
      "type": "remediation_completed",
      "timestamp": "2026-04-13T17:15:00Z",
      "fix_verified": true
    }
  ]
}
```

### Frontend: Investigation Page

```javascript
// Investigation dashboard should show:
// - Cards showing counts by status
// - "Awaiting Approval" should be prominent (needs action)

// Investigation detail should show:
// - Header: Title, Severity badge, Status badge
// - Tab: Overview - AI summary, narrative, risk
// - Tab: Playbook - YAML editor (read-only or editable)
// - Tab: Timeline - Event history
// - Button: Approve (if awaiting_approval)
// - Button: Decline (if awaiting_approval)
// - Button: Execute (if approved)

// Workflow:
// 1. New investigation created → Status: pending
// 2. AI analyzes → Status: running → awaiting_approval
// 3. Analyst reviews playbook → Approve or Decline
// 4. If approved → Ansible runs → remdiation
// 5. Fix verified → Status: completed
// 6. Archived → Status: archived
```

---

## 6. Archive Entities

### What are Archives?
Archives are closed investigations with full context stored for historical reference.

### List Archives

**Endpoint:** `GET /api/v1/archives`

**Input:**
```javascript
{
  limit: 50,
  offset: 0,
  fix_status: "likely_fixed"  // Filter: likely_fixed, not_fixed, unknown
}
```

**Output:**
```javascript
{
  "archives": [
    {
      "id": "uuid",
      "investigation_id": "inv-uuid",
      "incident_id": "inc-uuid",
      "incident_title": "Original incident title",
      "severity": "high",
      "fix_status": "likely_fixed",
      "fix_detail": "No new alerts after remediation",
      "archived_at": "2026-04-13T18:00:00Z"
    }
  ],
  "total": 34
}
```

### Get Archive Stats

**Endpoint:** `GET /api/v1/archives/stats`

**Output:**
```javascript
{
  "total_archived": 34,
  "fix_success_rate_pct": 80.0,
  "by_fix_status": {
    "likely_fixed": 20,
    "not_fixed": 4,
    "unknown": 1
  },
  "by_severity": {
    "high": 3,
    "medium": 19,
    "low": 3
  }
}
```

### Get Single Archive

**Endpoint:** `GET /api/v1/archives/{archive_id}`

**Output:**
```javascript
{
  "id": "uuid",
  "investigation_id": "inv-uuid",
  "incident_id": "inc-uuid",
  "incident_title": "...",
  "severity": "high",
  "fix_status": "likely_fixed",
  "fix_detail": "Verification details...",
  "full_context": {
    // Complete investigation + alert + incident data
  },
  "archived_at": "..."
}
```

### Get Archive Alerts

**Endpoint:** `GET /api/v1/archives/{archive_id}/alerts`

### Get Archive by Investigation

**Endpoint:** `GET /api/v1/archives/by-investigation/{investigation_id}`

### Frontend: Archive Page

```javascript
// Archive page should show:
// - Stats cards: Total, Fix Rate %, by Severity
// - Table: Archived Time, Title, Severity, Fix Status
// - Click row → Full archive detail with all context

// Archive detail should show:
// - Full timeline
// - All linked alerts
// - Fix verification result
// - Playbook used
```

---

## 7. Pipeline Entities

### What is the Pipeline?
The pipeline is the backend system that forwards alerts from Elasticsearch to OpenSOAR.

### Get Pipeline Status

**Endpoint:** `GET /api/v1/pipeline/status`

**Output:**
```javascript
{
  "running": true,
  "poll_interval": 10,
  "batch_size": 50,
  "description": "Alert pipeline from Elasticsearch to OpenSOAR"
}
```

### Get Pipeline Sources

**Endpoint:** `GET /api/v1/pipeline/sources`

**Output:**
```javascript
{
  "sources": [
    {
      "source": "wazuh",
      "cursor": "2026-04-11T23:38:39.266000+00:00",
      "documents_tracked": 5060,
      "index_pattern": "wazuh-alerts-4.x-*"
    },
    {
      "source": "falco",
      "cursor": "2026-04-12T23:32:59.074617+00:00",
      "documents_tracked": 5010,
      "index_pattern": "falco-events-*"
    },
    // ... more sources
  ]
}
```

### Get Pipeline Cursors

**Endpoint:** `GET /api/v1/pipeline/cursors`

### Trace Alert

**Endpoint:** `GET /api/v1/pipeline/trace/alert/{alert_id}`

**Output:**
```javascript
{
  "alert_id": "uuid",
  "steps": [
    { "step": "received", "timestamp": "..." },
    { "step": "enriched", "timestamp": "..." },
    { "step": "forwarded_to_opensar", "timestamp": "..." }
  ]
}
```

### Frontend: Pipeline Page (Optional)

```javascript
// Pipeline monitoring for admins:
// - Show if running
// - Show cursor position for each source
// - Show document count
// - Alert count over time
```

---

## 8. Hardware Resources (Performance) Entities

### What are Hardware Resources?
Server performance monitoring from Telegraf data in Elasticsearch. Monitors CPU, Memory, Disk, Network, Load, Connections, and Processes.

### Get All Hosts Dashboard

**Endpoint:** `GET /api/v1/metrics/dashboard`

**Purpose:** Get all monitored hosts with their latest metrics for dashboard display

**Output:**
```javascript
{
  "hosts": [
    {
      "hostname": "ghazi",
      "ip": "193.95.30.97",
      "status": "warning",  // normal, warning, critical
      "last_update": "2026-04-13T18:05:35Z",
      "metrics": {
        "cpu": { "current": 45.2, "user": 40.1, "system": 5.1, "iowait": 0.0 },
        "memory": { "current": 66.5, "used_mb": 8192.0, "available_mb": 4096.0 },
        "disk": [
          { "device": "/", "used_percent": 45.2, "used_gb": 45.2, "free_gb": 54.8 }
        ],
        "network": { "in_mb": 1.25, "out_mb": 0.85 },
        "load": { "1m": 2.5, "5m": 2.2, "15m": 1.8, "cpus": 4 },
        "connections": { "tcp_established": 145, "tcp_listen": 23, "udp": 5 }
      },
      "processes": {
        "top_cpu": [
          { "name": "nginx", "cpu": 45.2, "mem_mb": 230, "pid": 1234 }
        ],
        "top_memory": [
          { "name": "java", "cpu": 12.5, "mem_mb": 4100, "pid": 5678 }
        ]
      }
    }
  ],
  "timestamp": "2026-04-13T18:05:35.240453+00:00"
}
```

### List Monitored Hosts

**Endpoint:** `GET /api/v1/metrics/hosts`

**Purpose:** Get list of all hosts being monitored

**Output:**
```javascript
{
  "hosts": [
    { "hostname": "ghazi", "ip": "193.95.30.97", "status": "warning" }
  ],
  "total": 1
}
```

### Get Single Host Metrics

**Endpoint:** `GET /api/v1/metrics/{host}`

**Purpose:** Get current hardware metrics for a specific host

**Input:** `host` - hostname or IP in URL

**Output:**
```javascript
{
  "hostname": "ghazi",
  "ip": "193.95.30.97",
  "timestamp": "2026-04-13T18:05:35Z",
  "metrics": {
    "cpu": {
      "usage_percent": 45.2,
      "user_percent": 40.1,
      "system_percent": 5.1,
      "iowait_percent": 0.0
    },
    "memory": {
      "used_percent": 66.5,
      "used_bytes": 8589934592,
      "used_mb": 8192.0,
      "available_bytes": 4294967296,
      "available_mb": 4096.0
    },
    "disk": [
      {
        "device": "/",
        "used_percent": 45.2,
        "used_bytes": 48549068800,
        "used_gb": 45.2,
        "free_bytes": 58781071544,
        "free_gb": 54.8
      }
    ],
    "network": {
      "bytes_recv": 1310720,
      "bytes_sent": 891289,
      "in_mb": 1.25,
      "out_mb": 0.85
    },
    "load": {
      "load_1": 2.5,
      "load_5": 2.2,
      "load_15": 1.8,
      "n_cpus": 4
    },
    "connections": {
      "tcp_established": 145,
      "tcp_timewait": 12,
      "tcp_listen": 23,
      "udp_socket": 5
    }
  },
  "processes": {
    "total": 234,
    "running": 5,
    "sleeping": 229,
    "top_cpu": [
      { "pid": 1234, "name": "nginx", "user": "www-data", "cpu_percent": 45.2, "mem_percent": 2.3, "command": "nginx: worker" }
    ],
    "top_memory": [
      { "pid": 5678, "name": "java", "user": "root", "cpu_percent": 12.5, "mem_percent": 39.1, "command": "java -jar app.jar" }
    ]
  },
  "alert_status": "warning",
  "triggered_by": "cpu_usage"
}
```

### Get Host History

**Endpoint:** `GET /api/v1/metrics/{host}/history`

**Purpose:** Get historical metrics for a host (default: 24 hours)

**Input:**
```javascript
{
  hours: 24,    // Hours of history (default: 24)
  interval: 5   // Minutes between points (default: 5)
}
```

**Output:**
```javascript
{
  "hostname": "ghazi",
  "period": { "from": "2026-04-12T18:05:00Z", "to": "2026-04-13T18:05:00Z" },
  "data_points": [
    {
      "timestamp": "2026-04-13T18:05:00Z",
      "cpu": 45.2,
      "memory": 66.5,
      "disk": 45.2,
      "network_in": 1.25,
      "network_out": 0.85,
      "load_1": 2.5
    },
    // ... more data points
  ],
  "statistics": {
    "cpu": { "avg": 42.1, "min": 15.2, "max": 89.5 },
    "memory": { "avg": 65.2, "min": 45.1, "max": 85.2 },
    "disk": { "avg": 44.8, "min": 44.0, "max": 45.2 }
  }
}
```

### Get Root Cause Analysis

**Endpoint:** `GET /api/v1/metrics/{host}/root-cause`

**Purpose:** AI-generated root cause analysis when thresholds exceeded

**Output:**
```javascript
{
  "hostname": "ghazi",
  "timestamp": "2026-04-13T18:05:35Z",
  "anomalies": [
    {
      "type": "cpu_high",
      "value": 95.2,
      "threshold": 90.0,
      "severity": "critical"
    }
  ],
  "root_cause": {
    "explanation": "nginx worker process #1234 consuming 85% CPU due to slowloris attack",
    "affected_process": {
      "pid": 1234,
      "name": "nginx",
      "cpu_percent": 85.2,
      "mem_mb": 230
    },
    "evidence": [
      "8000 TIME_WAIT connections (normal: ~100)",
      "150 req/sec (normal: 50)"
    ],
    "confidence": 0.92,
    "recommended_action": "restart nginx, block IPs"
  }
}
```

### Get Alert Thresholds

**Endpoint:** `GET /api/v1/metrics/thresholds`

**Purpose:** Get configured warning/critical thresholds

**Output:**
```javascript
{
  "cpu": { "warning": 70, "critical": 90 },
  "memory": { "warning": 75, "critical": 85 },
  "disk": { "warning": 80, "critical": 90 },
  "disk_inodes": { "warning": 80, "critical": 90 },
  "network_in": { "warning": 104857600, "critical": 524288000 },
  "network_out": { "warning": 104857600, "critical": 524288000 }
}
```

### Get Metrics Status

**Endpoint:** `GET /api/v1/metrics/status`

**Purpose:** Get performance monitoring system status

**Output:**
```javascript
{
  "running": true,
  "poll_interval": 30,
  "last_poll": "2026-04-13T18:05:35Z",
  "hosts_tracked": 1,
  "errors": []
}
```

### Get Metrics Health

**Endpoint:** `GET /api/v1/metrics/health`

**Purpose:** Health check for metrics system

**Output:**
```javascript
{
  "status": "healthy",
  "elasticsearch": "ok",
  "redis": "ok",
  "timestamp": "2026-04-13T18:05:35Z"
}
```

### Get Detailed Metrics Health

**Endpoint:** `GET /api/v1/metrics/health/detailed`

**Purpose:** Detailed health check with all components

**Output:**
```javascript
{
  "status": "healthy",
  "components": {
    "elasticsearch": { "status": "ok", "latency_ms": 45 },
    "redis": { "status": "ok", "latency_ms": 2 },
    "cache": { "status": "ok", "entries": 1440 }
  },
  "metrics": {
    "hosts": 1,
    "last_update": "2026-04-13T18:05:35Z",
    "update_age_seconds": 5
  }
}
```

### Get Performance Alerts

**Endpoint:** `GET /api/v1/metrics/alerts`

**Purpose:** Get all performance-generated alerts

**Input:**
```javascript
{
  limit: 50,
  severity: "critical"  // optional filter
}
```

**Output:**
```javascript
{
  "alerts": [
    {
      "id": "uuid",
      "hostname": "ghazi",
      "type": "cpu_high",
      "severity": "critical",
      "value": 95.2,
      "threshold": 90.0,
      "created_at": "2026-04-13T18:05:35Z"
    }
  ],
  "total": 5
}
```

### Get Host Relationships

**Endpoint:** `GET /api/v1/metrics/{host}/relationships`

**Purpose:** Get host + metrics + related alerts + investigations

**Output:**
```javascript
{
  "host": {
    "hostname": "ghazi",
    "ip": "193.95.30.97",
    "status": "warning"
  },
  "metrics": { ... },
  "alerts": {
    "count": 3,
    "items": [
      { "id": "alert-uuid", "type": "cpu_high", "severity": "critical" }
    ]
  },
  "investigations": {
    "count": 1,
    "items": [
      { "id": "inv-uuid", "status": "pending" }
    ]
  }
}
```

### Get Host Alerts

**Endpoint:** `GET /api/v1/metrics/{host}/alerts`

**Purpose:** Get performance alerts for specific host

### Get Host Investigations

**Endpoint:** `GET /api/v1/metrics/{host}/investigations`

**Purpose:** Get investigations triggered by this host's metrics

### Frontend: Hardware Resources Page

```javascript
// Hardware Resources page should show:
// - Dashboard: All hosts with status cards (normal/warning/critical)
// - Click host → Host detail with all metrics
// - Tabs: Overview, CPU, Memory, Disk, Network, Processes
// - Chart: Historical graphs (24h)
// - Alerts: If thresholds exceeded
// - Root Cause: AI analysis when critical

// Metrics to display:
// 1. CPU: gauge + sparkline
// 2. Memory: gauge + used/available
// 3. Disk: per device bars
// 4. Network: in/out rates
// 5. Load: 1m/5m/15m
// 6. Processes: sortable table

// Alert colors:
// - Normal: Green (#10B981)
// - Warning: Yellow (#F59E0B)  
// - Critical: Red (#EF4444)
```

---

## 9. Search Entities

### What is Search?
Global search across all entities.

### Search by Query

**Endpoint:** `GET /api/v1/search`

**Input:**
```javascript
{
  q: "ssh",           // Search term
  limit: 50           // Max results
}
```

**Output:**
```javascript
{
  "query": "ssh",
  "results": {
    "alerts": [...],
    "incidents": [...],
    "investigations": [...]
  },
  "counts": {
    "alerts": 3,
    "incidents": 3,
    "investigations": 3
  }
}
```

### Search by IP

**Endpoint:** `GET /api/v1/search/ips/{ip}`

**Output:**
```javascript
{
  "ip": "1.2.3.4",
  "results": {
    "alerts": [...],
    "incidents": [...]
  },
  "counts": { ... }
}
```

### Search by Domain

**Endpoint:** `GET /api/v1/search/domains/{domain}`

### Frontend: Search

```javascript
// Global search in header:
// - Input box that searches all entities
// - Results grouped by type
// - Click result → Go to detail page
```

---

## 10. Dashboard Entities

### Get Dashboard Summary

**Endpoint:** `GET /api/v1/dashboard/summary`

**Output:**
```javascript
{
  "alerts": {
    "total": 849,
    "links": {
      "list": "/api/v1/alerts",
      "by_severity": "/api/v1/alerts?severity=critical"
    }
  },
  "incidents": {
    "total": 64,
    "open": 64,
    "links": {
      "list": "/api/v1/incidents",
      "by_status": "/api/v1/incidents?status=open"
    }
  },
  "investigations": {
    "total": 63,
    "by_status": {
      "approved": 2,
      "archived": 20,
      "awaiting_approval": 30,
      "completed": 11,
      "failed": 2
    },
    "links": {
      "list": "/api/v1/investigations",
      "stats": "/api/v1/investigations/stats",
      "awaiting_approval": "/api/v1/investigations?status=awaiting_approval",
      "running": "/api/v1/investigations?status=running"
    }
  },
  "archives": {
    "total": 20,
    "links": {
      "list": "/api/v1/archives",
      "stats": "/api/v1/archives/stats"
    }
  },
  "navigation": [
    { "label": "Alerts", "path": "/api/v1/alerts", "icon": "bell" },
    { "label": "Incidents", "path": "/api/v1/incidents", "icon": "alert-triangle" },
    { "label": "Investigations", "path": "/api/v1/investigations", "icon": "search" },
    { "label": "Archives", "path": "/api/v1/archives", "icon": "archive" },
    { "label": "Performance", "path": "/api/v1/metrics/dashboard", "icon": "activity" },
    { "label": "Search", "path": "/api/v1/search", "icon": "search" },
    { "label": "Pipeline", "path": "/api/v1/pipeline/status", "icon": "activity" }
  ]
}
```

### Frontend: Dashboard

```javascript
// Main dashboard should show:
// - 4 stat cards: Alerts, Incidents, Investigations, Archives
// - Click card → Go to list page
// - Recent activity section
// - "Needs Attention" section (awaiting approval investigations)
```

---

## 11. IPS Map & Attack Visualization

### What is IPS Attack Map?
Real-time world map visualization showing cyber attack traffic between source IPs (attackers) and destination IPs (our servers). Features animated arcs, live events table, statistics, and filtering.

> **Data source:** Events are automatically populated from real OpenSOAR alerts (30-second cache). Manual events via `POST /api/v1/ips/event` are merged in.  
> **GeoIP caveat:** The local GeoIP database is currently missing, so most source IPs resolve to `country: "XX"`, `country_name: "Unknown"`, `lat: 0`, `lon: 0` until the DB is present at `data/geoip/ip2location-db.csv`.

---

### Get Map Data with Animated Paths

**Endpoint:** `GET /api/v1/ips/map-data`

**Input (Query Parameters):**
```javascript
{
  limit: 50,              // Number of attacks (max 100, default 50)
  time_range: 60,         // Minutes of history (optional)
  severity: "high"        // Filter by severity (optional)
}
```

**Output:**
```javascript
{
  "attacks": [
    {
      "event_id": "02702308-2c0e-4873-b4a3-c6e9bda175c4",
      "timestamp": "2026-04-15T14:01:02.084824Z",
      "source": {
        "ip": "165.154.29.93",
        "port": 0,
        "country": "XX",
        "country_name": "Unknown",
        "city": "",
        "region": "",
        "isp": "",
        "asn": "",
        "lat": 0,
        "lon": 0,
        "org": ""
      },
      "destination": {
        "ip": "10.175.1.137",
        "port": 0,
        "country": "TN",
        "country_name": "Tunisia",
        "city": "Tunis",
        "region": "",
        "lat": 36.8065,
        "lon": 10.1815
      },
      "severity": "medium",
      "alert_name": "ET CINS Active Threat Intelligence Poor Reputation IP group 234",
      "category": "suricata",
      "protocol": "TCP",
      "signature_id": ""
    }
  ],
  "paths": [
    // Paths are only generated when lat/lon are non-zero.
    // Currently empty because GeoIP DB is missing.
  ],
  "count": 1,
  "timestamp": "2026-04-15T14:07:00Z"
}
```

---

### Get Live Events Table

**Endpoint:** `GET /api/v1/ips/events/live`

**Purpose:** Real-time table data for live-updating events display

**Input (Query Parameters):**
```javascript
{
  limit: 50,       // Max 100
  severity: "high" // Optional filter
}
```

**Output:**
```javascript
{
  "events": [
    {
      "event_id": "02702308-2c0e-4873-b4a3-c6e9bda175c4",
      "timestamp": "2026-04-15T14:01:02.084824Z",
      "source_ip": "165.154.29.93",
      "source_city": "",
      "source_country": "Unknown",
      "source_country_code": "XX",
      "dest_ip": "10.175.1.137",
      "dest_city": "Tunis",
      "dest_country": "Tunisia",
      "severity": "medium",
      "alert_name": "ET CINS Active Threat Intelligence Poor Reputation IP group 234",
      "category": "suricata",
      "protocol": "TCP"
    }
  ],
  "count": 44,
  "timestamp": "2026-04-15T14:07:00Z"
}
```

---

### Get Paginated Events

**Endpoint:** `GET /api/v1/ips/events`

**Input (Query Parameters):**
```javascript
{
  limit: 20,           // default 20, max 100
  offset: 0,           // default 0
  severity: "high",    // Optional filter
  country: "XX",       // Optional filter (source country code)
  protocol: "TCP",     // Optional filter
  category: "suricata" // Optional filter
}
```

**Output:**
```javascript
{
  "events": [
    {
      "event_id": "02702308-2c0e-4873-b4a3-c6e9bda175c4",
      "timestamp": "2026-04-15T14:01:02.084824Z",
      "source": {
        "ip": "165.154.29.93",
        "port": 0,
        "country": "XX",
        "country_name": "Unknown",
        "city": "",
        "region": "",
        "isp": "",
        "asn": "",
        "lat": 0,
        "lon": 0,
        "org": ""
      },
      "destination": {
        "ip": "10.175.1.137",
        "port": 0,
        "country": "TN",
        "country_name": "Tunisia",
        "city": "Tunis",
        "region": "",
        "lat": 36.8065,
        "lon": 10.1815
      },
      "severity": "medium",
      "alert_name": "ET CINS Active Threat Intelligence Poor Reputation IP group 234",
      "category": "suricata",
      "protocol": "TCP",
      "signature_id": ""
    }
  ],
  "total": 44,
  "limit": 20,
  "offset": 0
}
```

---

### Get Statistics

**Endpoint:** `GET /api/v1/ips/statistics`

**Output:**
```javascript
{
  "total_attacks": 44,
  "unique_sources": 36,
  "unique_targets": 1,
  "active_events": 44,
  "by_severity": { "critical": 0, "high": 9, "medium": 34, "low": 0 },
  "by_category": [
    { "category": "suricata", "count": 43 },
    { "category": "Unknown", "count": 1 }
  ],
  "by_protocol": [
    { "protocol": "TCP", "count": 43 },
    { "protocol": "UDP", "count": 1 }
  ],
  "top_countries": [
    { "code": "XX", "count": 44 }
  ],
  "top_isps": [
    { "isp": "", "count": 44 }
  ],
  "timestamp": "2026-04-15T14:07:00Z"
}
```

---

### Get Countries Breakdown

**Endpoint:** `GET /api/v1/ips/countries`

**Output:**
```javascript
{
  "countries": [
    { "code": "XX", "name": "Unknown", "count": 44, "percentage": 100.0 }
  ],
  "total": 44
}
```

---

### Get Industry Statistics

**Endpoint:** `GET /api/v1/ips/statistics/industries`

**Output:**
```javascript
{
  "industries": [
    { "industry": "suricata", "count": 44, "percentage": 100.0 }
  ],
  "total": 44
}
```

---

### Get Target Statistics

**Endpoint:** `GET /api/v1/ips/statistics/targets`

**Output:**
```javascript
{
  "targets": [
    { "ip": "10.175.1.137", "count": 44, "percentage": 100.0 }
  ],
  "total": 44
}
```

---

### Get Attack Type Statistics

**Endpoint:** `GET /api/v1/ips/statistics/attack-types`

**Output:**
```javascript
{
  "attack_types": [
    { "type": "ET CINS Active Threat Intelligence Poor Reputation IP group 234", "count": 2 },
    { "type": "ET SCAN Potential SSH Scan", "count": 1 }
    // ... 31 unique types total
  ],
  "total": 44
}
```

---

### Get Available Filters

**Endpoint:** `GET /api/v1/ips/filters`

**Output:**
```javascript
{
  "severities": ["high", "medium"],
  "categories": ["Unknown", "suricata"],
  "protocols": ["TCP", "UDP"],
  "countries": ["XX"]
}
```

---

### Get Quick Summary

**Endpoint:** `GET /api/v1/ips/summary`

**Output:**
```javascript
{
  "total": 44,
  "active": 44,
  "unique_sources": 36,
  "critical": 0,
  "high": 10,
  "medium": 34,
  "low": 0
}
```

---

### Get Health

**Endpoint:** `GET /api/v1/ips/status`

**Output:**
```javascript
{
  "status": "healthy",
  "events_stored": 44,
  "unique_sources": 36,
  "total_processed": 44
}
```

---

### Get Detailed Health

**Endpoint:** `GET /api/v1/ips/status/detailed`

**Output:**
```javascript
{
  "status": "healthy",
  "events": {
    "stored": 44,
    "max_events": 1000,
    "retention_minutes": 60
  },
  "statistics": {
    "total": 44,
    "unique_sources": 36,
    "unique_targets": 1,
    "by_severity": { "high": 10, "medium": 34 },
    "by_category": {
            "Unknown": 1,
            "suricata": 43
          }
  },
  "timestamp": "2026-04-15T14:07:00Z"
}
```

---

### Get Health (alias)

**Endpoint:** `GET /api/v1/ips/health`

**Output:**
```javascript
{
  "status": "healthy",
  "events_stored": 44,
  "unique_sources": 37
}
```

---

### Submit Attack Event

**Endpoint:** `POST /api/v1/ips/event`

**Input:**
```javascript
{
  "source_ip": "8.8.8.8",
  "dest_ip": "10.175.1.137",
  "src_port": 443,
  "dst_port": 443,
  "severity": "high",
  "alert_name": "ET SCAN Potential SSH Scan",
  "category": "Attempted Information Leak",
  "protocol": "TCP",
  "signature_id": "2001219"
}
```

**Output:**
```javascript
{
  "status": "stored",
  "event_id": "d6381d93-..."
}
```

---

### Submit Bulk Events

**Endpoint:** `POST /api/v1/ips/events/bulk`

**Input:**
```javascript
[
  {
    "source_ip": "1.1.1.1",
    "dest_ip": "10.175.1.137",
    "severity": "medium",
    "alert_name": "Bulk Event 1",
    "protocol": "UDP"
  }
]
```

**Output:**
```javascript
{
  "status": "stored",
  "events_count": 1
}
```

---

### Clear Events

**Endpoint:** `DELETE /api/v1/ips/events`

**Output:**
```javascript
{
  "status": "cleared"
}
```

---

### Get Single Event

**Endpoint:** `GET /api/v1/ips/{event_id}`

**Output:**
```javascript
{
  "event_id": "0caa8490-7e1d-4a95-8c70-3f86ff0d4410",
  "timestamp": "2026-04-15T14:01:02.084824Z",
  "source": {
    "ip": "193.124.20.253",
    "port": 0,
    "country": "XX",
    "country_name": "Unknown",
    "city": "",
    "region": "",
    "isp": "",
    "asn": "",
    "lat": 0,
    "lon": 0,
    "org": ""
  },
  "destination": {
    "ip": "10.175.1.137",
    "port": 0,
    "country": "TN",
    "country_name": "Tunisia",
    "city": "Tunis",
    "region": "",
    "lat": 36.8065,
    "lon": 10.1815
  },
  "severity": "medium",
  "alert_name": "ET CINS Active Threat Intelligence Poor Reputation IP group 43",
  "category": "suricata",
  "protocol": "TCP",
  "signature_id": ""
}
```

---

### Frontend: IPS Attack Map Implementation

```javascript
// IPS Map page should show:

// 1. WORLD MAP (2D/3D toggle)
//    - Use Leaflet or react-simple-maps
//    - Animated arcs from source to destination
//    - Color-coded by severity:
//      - critical: Red (#EF4444)
//      - high: Orange (#F97316)
//      - medium: Yellow (#EAB308)
//      - low: Blue (#3B82F6)
//    - Click marker for details

// 2. LIVE EVENTS TABLE
//    Columns: Time, Source IP, Source City, Dest IP, Severity, Alert, Category, Protocol
//    Auto-refresh: 5s, 10s, 30s (toggle)
//    Sort by timestamp (newest first)

// 3. STATISTICS PANEL
//    - Total attacks count
//    - Unique sources count
//    - By severity bars
//    - Top countries list
//    - Top ISPs list

// 4. FILTERS
//    - Severity (multi-select)
//    - Country (dropdown)
//    - Protocol (dropdown)
//    - Category (dropdown)
//    - Time range: 1h, 6h, 24h, 7d

// 5. REFRESH CONTROLS
//    - Auto-refresh toggle
//    - Interval: 5s/10s/30s
//    - Pause/Resume button

// 6. MAP CONTROLS
//    - 2D/3D toggle
//    - Zoom controls
//    - Fullscreen toggle
//    - Legend

// Color scheme:
// - Primary: #1E3A5F (Deep Navy)
// - Attack paths: Based on severity
// - Background: #0F172A (Dark)
```

### Frontend: IPS Map

```javascript
// IPS Map page should show:
// - World map with attack arcs
// - Color-coded by severity
// - Statistics panel
// - Countries breakdown
// - Auto-refresh (5s, 10s, 30s)
// - Filter by severity, country, time
```

---

## 12. AI Assistant Entities

### What is the AI Assistant?
A unified AI that can answer questions about your entire security system.

### Get Context

**Endpoint:** `GET /api/v1/assistant/context`

**Output:**
```javascript
{
  "available_sources": [
    {
      "name": "OpenSOAR Alerts",
      "description": "Live security alerts from Wazuh, Suricata, Falco",
      "endpoint": "/api/v1/alerts"
    },
    {
      "name": "OpenSOAR Incidents",
      "description": "Active incidents from OpenSOAR",
      "endpoint": "/api/v1/incidents"
    },
    {
      "name": "Local Investigations",
      "description": "AI investigations in progress",
      "endpoint": "/api/v1/investigations"
    },
    {
      "name": "Archives",
      "description": "Completed and archived investigations",
      "endpoint": "/api/v1/archives"
    },
    {
      "name": "Performance Metrics",
      "description": "CPU, memory, disk from monitored hosts",
      "endpoint": "/api/v1/metrics"
    },
    {
      "name": "Pipeline Status",
      "description": "Alert forwarding status",
      "endpoint": "/api/v1/pipeline/status"
    },
    {
      "name": "IPS Events",
      "description": "Network attack events",
      "endpoint": "/api/v1/ips"
    }
  ],
  "query_tips": [
    "Ask about specific hosts: 'How is ghazi performing?'",
    "Ask about IPs: 'What alerts from 1.2.3.4'",
    "Ask about severity: 'Show critical alerts'",
    "Ask about status: 'How many investigations pending?'"
  ]
}
```

### Get Sources Stats

**Endpoint:** `GET /api/v1/assistant/sources`

**Output:**
```javascript
{
  "sources": {
    "active_investigations": 47,
    "archives": 23,
    "opensoar": "connect to check",
    "performance": "connect to check"
  }
}
```

### Get Health

**Endpoint:** `GET /api/v1/assistant/health`

**Output:**
```javascript
{
  "status": "healthy",
  "llm_enabled": true,
  "model": "qwen/qwen2.5-coder-32b-instruct",
  "sources": "all_configured"
}
```

### Query

**Endpoint:** `POST /api/v1/assistant/query`

> **Provider:** Configured via `.env` (`LLM_PROVIDER=nvidia`, `LLM_MODEL=qwen/qwen2.5-coder-32b-instruct`). The assistant currently uses the **NVIDIA API** and returns synthesized answers. If the LLM becomes unreachable, it falls back to raw records.

**Input:**
```javascript
{
  "question": "How many alerts do we have?"
}
```

**Output:**
```javascript
{
  "answer": "Based on the provided data, here is the count of alerts:

- **LIVE ALERTS:**
  - 5 alerts in total
  - 3 with status "new"
  - 2 with status "in_progress"

- **LIVE INCIDENTS:**
  - 2 incidents in total
  - Both with status "open"
  - Total alerts in incidents: 4 (2 alerts per incident)

So, the total number of alerts is **9**.",
  "sources": [
    { "type": "archived_investigation", "incident_title": "ET CINS Active Threat Intelligence Poor Reputation IP group  — 104.243.35.94 on ghazi", "severity": "medium" },
    { "type": "active_investigation", "id": "4aea1d87-e5f0-42cf-a42a-fe6bc0a3411b", "status": "completed" },
    { "type": "live_alert", "title": "ET CINS Active Threat Intelligence Poor Reputation IP group 53", "severity": "medium" },
    { "type": "live_incident", "title": "ET CINS Active Threat Intelligence Poor Reputation IP group  — 194.88.98.83 on ghazi", "severity": "medium" }
  ],
  "statistics": {
    "archives": 5,
    "active_investigations": 3,
    "live_alerts_incidents": 8,
    "performance_metrics": 0,
    "pipeline_sources": 4,
    "system_health": 5
  },
  "record_count": 15
}


```javascript
// AI Assistant page should show:
// - Chat interface with message bubbles
// - Left sidebar: Available data sources + counts
// - Quick action buttons:
//   - "Show critical alerts"
//   - "Pending investigations"
//   - "Top attacking countries"
// - Ask any question in input
// - Show sources used in response (clickable)
```

---

## 13. Monitoring Entities

### What is Monitoring?
Backend system health and service status.

### Get Services Status

**Endpoint:** `GET /monitor/services-status`

**Output:**
```javascript
{
  "services": {
    "api_server": {
      "name": "API Server",
      "status": "running",
      "port": 8001,
      "description": "FastAPI HTTP server on port 8001"
    },
    "forwarder": {
      "name": "Alert Forwarder",
      "status": "running",
      "poll_interval": 10,
      "sources": ["wazuh", "falco", "filebeat", "suricata"],
      "description": "Polls Elasticsearch and forwards alerts to OpenSOAR"
    },
    "incident_watcher": {
      "name": "Incident Watcher",
      "status": "running",
      "poll_interval": 15,
      "description": "Polls OpenSOAR for new incidents"
    },
    "incident_correlation": {
      "name": "Incident Correlation",
      "status": "running",
      "interval": 30,
      "description": "Correlates related incidents"
    },
    "auto_transitions": {
      "name": "Auto Transitions",
      "status": "running",
      "description": "Automatic investigation state transitions"
    },
    "retry_queue": {
      "name": "Retry Queue",
      "status": "running",
      "description": "Retries failed operations"
    },
    "backup": {
      "name": "Database Backup",
      "status": "running",
      "description": "Periodic SQLite backups"
    },
    "health_monitor": {
      "name": "Health Monitor",
      "status": "running",
      "description": "Background health checks"
    },
    "performance_monitoring": {
      "name": "Performance Monitoring",
      "status": "running",
      "poll_interval": 30,
      "description": "Server metrics monitoring via Telegraf/ES"
    },
    "performance_watcher": {
      "name": "Performance Watcher",
      "status": "running",
      "description": "Performance alert cooldown management"
    }
  },
  "timestamp": "2026-04-15T14:37:58.886050+00:00",
  "total_running": 10,
  "total_disabled": 0
}
```

### Get Health

**Endpoint:** `GET /monitor/health`

**Output:**
```javascript
{
  "status": "healthy",
  "database": "ok",
  "timestamp": "2026-04-15T14:37:58.385534+00:00"
}
```

### Get Pipeline Health

**Endpoint:** `GET /monitor/pipeline-health`

**Output:**
```javascript
{
  "timestamp": "2026-04-15T15:16:27.240964+00:00",
  "stages": {
    "database": { "status": "healthy", "message": "connected" },
    "redis": { "status": "healthy", "message": "connected" },
    "elasticsearch": { "status": "healthy", "message": "connected" },
    "opensoar": { "status": "healthy", "message": "connected" },
    "forwarder": {
      "status": "running",
      "message": "Forwarder polls ES indices",
      "sources": ["wazuh", "falco", "filebeat", "suricata"]
    },
    "performance_monitoring": { "status": "running", "message": "Polls telegraf-* every 30s" },
    "incident_watcher": { "status": "running", "message": "Polls OpenSOAR every 15s" },
    "response_intelligence": { "status": "running", "message": "AI investigation + Ansible remediation" }
  },
  "overall_status": "healthy",
  "unhealthy_stages": []
}
```

### Get Monitor Stats

**Endpoint:** `GET /monitor/stats`

**Output:**
```javascript
{
  "total_investigations": 71,
  "status_breakdown": [
    { "status": "approved", "count": 2 },
    { "status": "archived", "count": 23 },
    { "status": "awaiting_approval", "count": 31 },
    { "status": "completed", "count": 12 },
    { "status": "failed", "count": 2 },
    { "status": "pending", "count": 1 }
  ],
  "completed_rate": 16.9,
  "failed_rate": 2.8,
  "avg_resolution_time_minutes": 4.8
}
```

### Get Investigations (Monitor View)

**Endpoint:** `GET /monitor/investigations`

**Output:** Array of investigation monitor records.
```javascript
[
  {
    "investigation_id": "6cc7cf48-13e7-4831-8e05-c88d8d673aa5",
    "status": "pending",
    "target_host": "ghazi",
    "target_user": "ghazi",
    "risk_score": null,
    "attack_type": null,
    "created_at": "2026-04-15T14:37:41.265488",
    "updated_at": "2026-04-15T14:37:57.137542",
    "playbook_status": null,
    "verification_status": null
  }
]
```

### Get Single Investigation (Monitor View)

**Endpoint:** `GET /monitor/investigations/{investigation_id}`

**Output:**
```javascript
{
  "id": "6cc7cf48-13e7-4831-8e05-c88d8d673aa5",
  "status": "pending",
  "incident_title": "ET CINS Active Threat Intelligence Poor Reputation IP group  — 193.176.31.152 on ghazi",
  "incident_id": "854f39bf-030c-4062-8e4a-4e1dc0f20e2f",
  "target_host": "ghazi",
  "target_user": "ghazi",
  "source_ips": "193.176.31.152",
  "risk_score": null,
  "ai_summary": null,
  "ai_error": null,
  "playbook_valid": false,
  "created_at": "2026-04-15T14:37:41.265488",
  "updated_at": "2026-04-15T14:37:57.137542",
  "playbook_run": null,
  "verification": null
}
```

### Get Investigation Dependencies

**Endpoint:** `GET /monitor/investigations/{investigation_id}/dependencies`

**Output:**
```javascript
{
  "investigation_id": "6cc7cf48-13e7-4831-8e05-c88d8d673aa5",
  "incident_id": "854f39bf-030c-4062-8e4a-4e1dc0f20e2f",
  "target_host": "ghazi",
  "status": "running",
  "created_at": "2026-04-15T14:37:41.265488",
  "dependencies": {
    "triggers": "/api/v1/incidents/854f39bf-030c-4062-8e4a-4e1dc0f20e2f",
    "host_metrics": "/api/v1/metrics/ghazi",
    "alerts": "/api/v1/incidents/854f39bf-030c-4062-8e4a-4e1dc0f20e2f/alerts"
  }
}
```

### Get Playbook Runs

**Endpoint:** `GET /monitor/playbook-runs`

**Output:**
```javascript
[
  {
    "id": "8bedcc61-fb3f-432a-ac15-f92988ceb4f9",
    "investigation_id": "6ecd3975-3eb6-4331-89d3-e8885a3b567d",
    "status": "completed",
    "exit_code": 0,
    "started_at": "2026-04-15T14:28:53.322199",
    "finished_at": "2026-04-15T14:29:55.360803"
  },
  {
    "id": "24973da4-be69-40bd-b31a-481a4a18b38a",
    "investigation_id": "31984b40-30f2-4bc1-a2e4-8bd4f071551d",
    "status": "failed",
    "exit_code": null,
    "started_at": "2026-04-15T13:40:33.626165",
    "finished_at": null
  },
  {
    "id": "8c903c47-f4f0-42f8-bb9f-97775ff11640",
    "investigation_id": "6dd5726a-577c-4ad0-84b9-1b8ab03561a9",
    "status": "running",
    "exit_code": null,
    "started_at": "2026-04-15T13:32:17.789250",
    "finished_at": null
  }
]
```

### Get Stuck Investigations

**Endpoint:** `GET /monitor/stuck-investigations`

**Output:**
```javascript
{
  "count": 31,
  "stuck_investigations": [
    {
      "id": "114eb173-8a48-4e79-81ed-8b0de237916b",
      "status": "awaiting_approval",
      "severity": "high",
      "hours_stuck": 5.64,
      "created_at": "2026-04-15T10:30:08.371211",
      "updated_at": "2026-04-15T10:30:31.590910"
    }
  ]
}
```

### Get Execution Stats

**Endpoint:** `GET /monitor/execution-stats`

**Output:**
```javascript
{
  "total_runs": 31,
  "successful": 31,
  "failed": 0,
  "success_rate": 100.0,
  "avg_duration_minutes": 1.18
}
```

### Reset Pipeline Cursor

**Endpoint:** `POST /monitor/reset-cursor/{source}`

**Output:**
```javascript
{
  "source": "wazuh",
  "new_cursor": "2026-04-14T15:08:17.447236+00:00",
  "message": "Cursor reset to 24 hours ago. Next poll will fetch alerts from that time."
}
```

### Get Auto-Approve Stats

**Endpoint:** `GET /monitor/auto-approve-stats`

**Output:**
```javascript
{
  "total_decisions": 517,
  "auto_approved": 180,
  "human_review_required": 337,
  "auto_approve_rate": "34.8%",
  "by_source": {
    "none": 336,
    "static": 170
  },
  "execution_success": 0,
  "execution_failed": 0,
  "execution_success_rate": "N/A"
}
```

### Get Auto-Approve Config

**Endpoint:** `GET /monitor/auto-approve-config`

**Output:**
```javascript
{
  "enabled": true,
  "method": "hybrid",
  "static": {
    "severities": ["low", "medium"],
    "max_risk_score": 45,
    "max_alerts": 10
  },
  "guardrails": {
    "block_severities": ["critical"],
    "block_risk_score": 75,
    "block_attack_types": [
      "ransomware",
      "c2",
      "data_exfiltration",
      "privilege_escalation",
      "lateral_movement"
    ]
  },
  "dynamic": {
    "enabled": true,
    "min_approvals": 10
  },
  "ai": {
    "enabled": false,
    "threshold": 0.85
  },
  "notifications": {
    "on_auto": true,
    "on_fallback": true
  }
}
```

### Get Retry Queue Stats

**Endpoint:** `GET /monitor/retry-queue-stats`

**Output:**
```javascript
{
  "status": "ok",
  "pending_count": 0,
  "by_retry_count": {}
}
```

### Get Forwarder Status

**Endpoint:** `GET /monitor/forwarder-status`

**Output:**
```javascript
{
  "sources": {
    "wazuh": {
      "enabled": true,
      "index_pattern": "wazuh-alerts-4.x-*",
      "last_cursor": "2026-04-14T14:37:58.937015+00:00",
      "alerts_forwarded": 0,
      "errors": 0,
      "status": "running"
    },
    "falco": {
      "enabled": true,
      "index_pattern": "falco-events-*",
      "last_cursor": "2026-04-15T14:37:11.774778+00:00",
      "alerts_forwarded": 0,
      "errors": 0,
      "status": "running"
    },
    "filebeat": {
      "enabled": true,
      "index_pattern": "filebeat-*",
      "last_cursor": "2026-04-15T14:37:25.321000+00:00",
      "alerts_forwarded": 0,
      "errors": 0,
      "status": "running"
    },
    "suricata": {
      "enabled": true,
      "index_pattern": "suricata-*",
      "last_cursor": null,
      "alerts_forwarded": 0,
      "errors": 0,
      "status": "unknown"
    },
    "performance": {
      "enabled": true,
      "index_pattern": "telegraf-*",
      "last_poll": null,
      "hosts": [],
      "alerts_generated": 100,
      "status": "running"
    }
  },
  "pipeline": {
    "redis": "healthy",
    "elasticsearch": "healthy",
    "forwarder": "running"
  },
  "timestamp": "2026-04-15T14:37:59.013268+00:00"
}
```

### Get Service Logs

**Endpoint:** `GET /monitor/services/{service}/logs`

**Output:**
```javascript
{
  "service": "backend",
  "logs": [
    "2026-04-15 16:03:29 [info     ] starting_opensoar_backend      api_port=8001",
    "2026-04-15 16:03:30 [info     ] geoip_db_not_found             path='/home/dash/opensoar backend/data/geoip/ip2location-db.csv'",
    "future: <Task finished name='Task-306' coro=<execute_playbook() done... exception=IntegrityError('(sqlite3.IntegrityError) UNIQUE constraint failed: playbook_runs.investigation_id')>",
    "File "/home/dash/opensoar backend/response/ansible_exec.py", line 339, in execute_playbook",
    "future: <Task finished name='Task-373' coro=<execute_playbook() done... exception=IntegrityError('(sqlite3.IntegrityError) UNIQUE constraint failed: playbook_runs.investigation_id')>",
    "File "/home/dash/opensoar backend/response/ansible_exec.py", line 339, in execute_playbook"
  ],
  "total": 6
}
```

### Get Service Errors

**Endpoint:** `GET /monitor/services/{service}/errors`

**Output:**
```javascript
{
  "service": "backend",
  "errors": [],
  "total": 0,
  "related_investigation_ids": []
}
```

### Get Recent Logs

**Endpoint:** `GET /monitor/logs/recent`

**Output:**
```javascript
{
  "logs": [
    "2026-04-15 15:37:41 [info     ] watcher_cycle_complete         new_investigations=1",
    "2026-04-15 15:37:41 [info     ] ai_engine_started              investigation_id=..."
  ],
  "total": 50,
  "filters": { "level": null }
}
```

### Frontend: Monitoring Page (Admin)

```javascript
// Admin/monitoring page should show:
// - Service status cards (all should be running)
// - Database health
// - Stuck investigations (if any)
// - Links to restart services if needed
```

---

## 14. Frontend Workflows

### Workflow 1: Alert Triage

```javascript
// 1. Go to Alerts page
//    GET /api/v1/alerts?limit=50&status=new

// 2. Click alert → Alert detail
//    GET /api/v1/alerts/{id}

// 3. View linked incidents
//    GET /api/v1/alerts/{id}/incidents

// 4. Click incident → Incident detail
//    GET /api/v1/incidents/{id}

// 5. View timeline
//    GET /api/v1/incidents/{id}/timeline

// 6. View investigations
//    GET /api/v1/incidents/{id}/investigations

// 7. Click investigation → Investigation detail
//    GET /api/v1/investigations/{id}
```

### Workflow 2: Investigation Approval

```javascript
// 1. Go to Investigations page
//    GET /api/v1/investigations?status=awaiting_approval

// 2. Click investigation
//    GET /api/v1/investigations/{id}

// 3. Review AI summary, narrative, risk

// 4. View playbook YAML
//    GET /api/v1/investigations/{id}/playbook/yaml

// 5. Click Approve
//    POST /api/v1/investigations/{id}/approve
//    Body: { "decided_by": "admin" }

// 6. View timeline
//    GET /api/v1/investigations/{id}/timeline
```

### Workflow 3: Incident Investigation

```javascript
// 1. Go to Incidents page
//    GET /api/v1/incidents?status=open

// 2. Click incident
//    GET /api/v1/incidents/{id}

// 3. View alerts
//    GET /api/v1/incidents/{id}/alerts

// 4. View timeline
//    GET /api/v1/incidents/{id}/timeline

// 5. View investigations
//    GET /api/v1/incidents/{id}/investigations
```

### Workflow 4: Search

```javascript
// 1. Enter search term in header
//    GET /api/v1/search?q=ssh

// 2. Click IP result
//    GET /api/v1/search/ips/1.2.3.4

// 3. Click alert → Alert detail
```

### Workflow 5: Ask AI

```javascript
// 1. Go to AI Assistant page

// 2. Click quick action "Show critical alerts"
//    POST /api/v1/assistant/query
//    Body: { "question": "Show critical alerts" }

// 3. View answer with sources

// 4. Click source → Go to detail
```

### Workflow 6: Archive Review

```javascript
// 1. Go to Archives page
//    GET /api/v1/archives

// 2. View stats
//    GET /api/v1/archives/stats

// 3. Click archive
//    GET /api/v1/archives/{id}

// 4. View full context, alerts, timeline
```

---

## 15. Entity Relationships

### Navigation Map

```
ALERTS                    INCIDENTS
    │                         │
    ├─→ incidents              ├─→ alerts
    ├─→ similar               ├─→ timeline
    │                         ├─→ investigations
    │                         │
    ▼                         ▼
INVESTIGATIONS           ARCHIVES
    │                         │
    ├─→ playbook/yaml        ├─→ alerts
    ├─→ timeline             ├─→ full_context
    ├─→ approve              └─────────────
    ├─→ decline
    │
    ▼
PLAYBOOK/RUN → VERIFICATION
```

### Click Relationships

| On Page | Clicking | Goes To |
|---------|---------|---------|
| Alert List | Row | Alert Detail |
| Alert Detail | Incidents link | Incidents with this alert |
| Alert Detail | Similar link | Alerts with same IP |
| Incident List | Row | Incident Detail |
| Incident Detail | Alert link | Alert Detail |
| Incident Detail | Timeline | Timeline page |
| Investigation List | Row | Investigation Detail |
| Investigation Detail | Approve | API call + refresh |
| Archive List | Row | Archive Detail |
| Search Results | Result | Respective detail |

---

## 16. Complete Navigation Flow

### Main Navigation (Sidebar)

```
┌─────────────────────────────────────────┐
│  ARIA                                   │
│  ───────────────────────────────────    │
│  📊 Dashboard                          │
│  🔔 Alerts                             │
│  📁 Incidents                          │
│  🔍 Investigations                   │
│  🤖 AI Assistant                       │
│  🗺 IPS Map                            │
│  📈 Performance                        │
│  📦 Archives                          │
│  ⚙️ Monitoring (admin)                │
└─────────────────────────────────────────┘
```

### Page Flows

```javascript
// DASHBOARD
Dashboard → quick stats + navigation cards
           → Click card → respective list page

// ALERTS
Alerts (list) → Alert Detail → Incidents → Incident Detail
            → Similar alerts → Alert list (filtered)
            
// INCIDENTS  
Incidents (list) → Incident Detail → Alerts → Alert Detail
               → Timeline (embedded)
               → Investigations → Investigation Detail

// INVESTIGATIONS
Investigations (list) → Investigation Detail → Playbook view
                     → Approve button (if awaiting_approval)
                     → Decline button (if awaiting_approval)
                     → Timeline (embedded)

// AI ASSISTANT
AI Assistant → Chat interface → Quick actions + Ask anything
           → Sources sidebar → Click → Go to respective page

// IPS MAP
IPS Map → World map with attacks → Click attack → Attack detail
        → Statistics panel → Countries list
        → Filters → Severity, country, time

// ARCHIVES
Archives (list) → Archive Detail → Full context + timeline

// MONITORING (admin)
Monitoring → Service status → Stuck investigations
            → System health
```

---

## Complete API Reference Summary

### Core APIs (2)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/` | GET | Service info |

### Alert APIs (4)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/alerts` | GET | List all alerts |
| `/api/v1/alerts/{id}` | GET | Alert detail + relationships |
| `/api/v1/alerts/{id}/incidents` | GET | Get incidents with this alert |
| `/api/v1/alerts/{id}/similar` | GET | Alerts with same source IP |

### Incident APIs (7)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/incidents` | GET | List all incidents |
| `/api/v1/incidents/{id}` | GET | Incident detail + relationships |
| `/api/v1/incidents/{id}/alerts` | GET | Get alerts for incident |
| `/api/v1/incidents/{id}/timeline` | GET | Full lifecycle timeline |
| `/api/v1/incidents/{id}/investigations` | GET | Investigations for incident |
| `/api/v1/incidents/by-alert/{alert_id}` | GET | Get incidents by alert |
| `/api/v1/incidents/suggestions` | GET | Get incident suggestions (unlinked alert groups) |

### Investigation APIs (12)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/investigations` | GET | List all investigations |
| `/api/v1/investigations/{id}` | GET | Investigation detail |
| `/api/v1/investigations/stats` | GET | Counts by status |
| `/api/v1/investigations/{id}/playbook/yaml` | GET | Get raw playbook YAML |
| `/api/v1/investigations/{id}/playbook` | PUT | Update playbook |
| `/api/v1/investigations/{id}/execute` | POST | Execute directly |
| `/api/v1/investigations/{id}/approve` | POST | Approve + run playbook |
| `/api/v1/investigations/{id}/decline` | POST | Decline + archive |
| `/api/v1/investigations/{id}/archive` | POST | Archive investigation |
| `/api/v1/investigations/{id}/run-status` | GET | Playbook execution status |
| `/api/v1/investigations/{id}/timeline` | GET | Investigation events |
| `/api/v1/investigations/{id}/alerts` | GET | Linked alerts |

### Archive APIs (5)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/archives` | GET | List closed cases |
| `/api/v1/archives/stats` | GET | Archive statistics |
| `/api/v1/archives/{id}` | GET | Full archived context |
| `/api/v1/archives/{id}/alerts` | GET | Archived alerts |
| `/api/v1/archives/by-investigation/{id}` | GET | Get archive by investigation |

### Pipeline APIs (4)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/pipeline/status` | GET | Pipeline running status |
| `/api/v1/pipeline/sources` | GET | Sources tracked |
| `/api/v1/pipeline/cursors` | GET | Cursor positions |
| `/api/v1/pipeline/trace/alert/{id}` | GET | Alert lifecycle trace |

### Hardware Resources APIs (13)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/metrics/dashboard` | GET | All hosts + metrics |
| `/api/v1/metrics/hosts` | GET | List monitored hosts |
| `/api/v1/metrics/{host}` | GET | Single host current metrics |
| `/api/v1/metrics/{host}/history` | GET | Historical metrics (24h) |
| `/api/v1/metrics/{host}/root-cause` | GET | AI root cause analysis |
| `/api/v1/metrics/thresholds` | GET | Alert threshold config |
| `/api/v1/metrics/status` | GET | Polling status |
| `/api/v1/metrics/health` | GET | Metrics system health |
| `/api/v1/metrics/health/detailed` | GET | Detailed health check |
| `/api/v1/metrics/alerts` | GET | Performance alerts |
| `/api/v1/metrics/{host}/relationships` | GET | Host + alerts + investigations |
| `/api/v1/metrics/{host}/alerts` | GET | Alerts for host |
| `/api/v1/metrics/{host}/investigations` | GET | Investigations for host |

### Search APIs (3)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/search` | GET | Global search |
| `/api/v1/search/ips/{ip}` | GET | Search by IP address |
| `/api/v1/search/domains/{domain}` | GET | Search by domain |

### Dashboard APIs (2)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/dashboard/summary` | GET | Full dashboard stats (alerts, incidents, investigations, archives) |
| `/api/v1/dashboard/quick-stats` | GET | Minimal counts |

### IPS Map & Attack Visualization APIs (16)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/ips/map-data` | GET | Map data with animated paths |
| `/api/v1/ips/events/live` | GET | Live events for table |
| `/api/v1/ips/events` | GET | Paginated events |
| `/api/v1/ips/statistics` | GET | Comprehensive statistics |
| `/api/v1/ips/statistics/industries` | GET | Industry breakdown |
| `/api/v1/ips/statistics/targets` | GET | Most targeted hosts |
| `/api/v1/ips/statistics/attack-types` | GET | Attack type breakdown |
| `/api/v1/ips/countries` | GET | Countries breakdown |
| `/api/v1/ips/filters` | GET | Available filters |
| `/api/v1/ips/summary` | GET | Quick summary |
| `/api/v1/ips/status` | GET | Health check |
| `/api/v1/ips/status/detailed` | GET | Detailed health |
| `/api/v1/ips/event` | POST | Submit single event |
| `/api/v1/ips/events/bulk` | POST | Submit bulk events |
| `/api/v1/ips/events` | DELETE | Clear all events |
| `/api/v1/ips/{event_id}` | GET | Get single event |

### AI Assistant APIs (4)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/assistant/context` | GET | Available data sources |
| `/api/v1/assistant/sources` | GET | Source statistics |
| `/api/v1/assistant/health` | GET | Assistant status |
| `/api/v1/assistant/query` | POST | Ask AI question |

### Monitoring & System Health APIs (18)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/monitor/stats` | GET | System statistics |
| `/monitor/investigations` | GET | All investigations with metrics |
| `/monitor/investigations/{id}` | GET | Single investigation metrics |
| `/monitor/playbook-runs` | GET | All playbook executions |
| `/monitor/health` | GET | System health |
| `/monitor/pipeline-health` | GET | Pipeline health |
| `/monitor/services-status` | GET | All services status |
| `/monitor/stuck-investigations` | GET | Stuck > 1 hour investigations |
| `/monitor/execution-stats` | GET | Execution statistics |
| `/monitor/reset-cursor/{source}` | POST | Reset cursor for source |
| `/monitor/auto-approve-stats` | GET | Auto-approve statistics |
| `/monitor/auto-approve-config` | GET | Auto-approve configuration |
| `/monitor/retry-queue-stats` | GET | Retry queue statistics |
| `/monitor/forwarder-status` | GET | Forwarder status |
| `/monitor/services/{service}/logs` | GET | Logs from service |
| `/monitor/services/{service}/errors` | GET | Errors from service |
| `/monitor/logs/recent` | GET | Recent logs |
| `/monitor/investigations/{id}/dependencies` | GET | Investigation dependencies |

### Data Flow & Lifecycle Tracking APIs (10)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/pipeline/trace/alert/{id}` | GET | Alert: ES → OpenSOAR → response |
| `/api/v1/pipeline/trace/source/{source_id}` | GET | Trace by source ID |
| `/api/v1/search/investigations/{id}/trace` | GET | Full investigation lifecycle |
| `/monitor/pipeline-health` | GET | Pipeline health |
| `/monitor/forwarder-status` | GET | Forwarder status |
| `/monitor/playbook-runs` | GET | All playbook executions |
| `/monitor/investigations/{id}` | GET | Investigation metrics |
| `/monitor/investigations/{id}/dependencies` | GET | Investigation dependencies |
| `/monitor/execution-stats` | GET | Execution statistics |
| `/monitor/auto-approve-stats` | GET | Auto-approve statistics |

---

## 17. Complete Data Flow Pipeline

### The Complete Data Lifecycle

This section shows how data flows through the entire ARIA system from source to remediation.

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                        ARIA COMPLETE DATA FLOW                                    │
└─────────────────────────────────────────────────────────────────────────────────┘

STEP 1: ALERT SOURCE (Elasticsearch)
═══════════════════════════════
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Wazuh    │     │  Suricata  │     │   Falco    │     │  Filebeat  │
│   (HIDS)   │     │   (IDS)    │     │ (K8s RT)   │     │   (FIM)   │
└─────┬──────┘     └─────┬──────┘     └─────┬──────┘     └─────┬──────┘
      │                  │                  │                  │
      ▼                  ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────────┐
│          Elasticsearch (Index: wazuh-*, falco-*, etc.)  │
│  - Raw security events stored                │
│  - Indexed by timestamp, source, host      │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
STEP 2: FORWARDER (Pipeline)
═══════════════════════
┌─────────────────────────────────────────────────────────────────┐
│              ALERT POLLER (10s interval)              │
│                                                 │
│  1. Query ES with cursor                         │
│  2. Normalize alert format (source mapper)        │
│  3. Enrich: GeoIP, MITRE, Sigma, IOCs         │
│  4. Deduplicate (Redis)                         │
│  5. Forward to OpenSOAR                      │
│  6. Store cursor (Redis + file)              │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
STEP 3: OPENSOAR (Incident Management)
════════════════════════════
┌─────────────────────────────────────────────────────────────────┐
│                   OpenSOAR                     │
│                                                 │
│  POST /api/v1/alerts          → Create alert   │
│  POST /api/v1/incidents     → Create case    │
│  POST /api/v1/observables    → Store IPs     │
│  GET /api/v1/incidents     → Poll for new │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
STEP 4: WATCHER (Response Intelligence)
════════════════════════════
┌─────────────────────────────────────────────────────────────────┐
│           INCIDENT WATCHER (15s interval)           │
│                                                 │
│  1. Poll OpenSOAR for "open" incidents        │
│  2. Fetch alerts, build context            │
│  3. Create investigation record            │
│  4. Trigger AI analysis                        │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
STEP 5: AI ENGINE (NVIDIA NIM)
═══════════════════════════
┌─────────────────────────────────────────────────────────────────┐
│                 AI INVESTIGATION                    │
│                                                 │
│  Using: qwen/qwen2.5-coder-32b-instruct          │
│                                                 │
│  Functions:                                   │
│  1. Triage - Categorize threat                 │
│  2. Summarize - Create summary               │
│  3. Investigate - Deep analysis           │
│  4. Root Cause - What's the cause?          │
│  5. Generate Playbook - Ansible YAML       │
└────────────────────┬────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
STEP 6a: AUTO-APPROVE      STEP 6b: HUMAN APPROVAL
═══════════════════    ═══════════════════
┌─────────────────┐   ┌─────────────────┐
│  Auto-Approve   │   │  Analyst       │
│  (low/medium)  │   │  Reviews       │
│                │   │  playbook      │
│  - Check rules │   │               │
│  - If safe    │   │  - Approve     │
│    → approve  │   │  - Decline    │
└───────┬───────┘   └───────┬───────┘
        │                 │
        ▼                 ▼
STEP 7: REMEDIATION (Ansible)
════════════════════════════
┌─────────────────────────────────────────────────────────────────┐
│              ANSIBLE EXECUTION                     │
│                                                 │
│  1. Generate playbook YAML                    │
│  2. SSH to target host                       │
│  3. Execute tasks                          │
│  4. Capture output                         │
│  5. Get exit code                          │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
STEP 8: FIX VERIFIER
═══════════════════
┌─────────────────────────────────────────────────────────────────┐
│               FIX VERIFICATION                   │
│                                                 │
│  1. Re-query Elasticsearch                   │
│  2. Check for recurrence                │
│  3. Verify metrics normalized           │
│  4. Mark: likely_fixed / not_fixed      │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
STEP 9: ARCHIVER
═════════════
┌─────────────────────────────────────────────────────────────────┐
│                 ARCHIVER                      │
│                                                 │
│  1. Store full context                   │
│  2. Mark investigation archived    │
│  3. Calculate fix success rate         │
│  4. Ready for historical reports     │
└─────────────────────────────────┘
```

### How to Trace Any Alert

Use these APIs to follow an alert through the entire system:

#### Example: Trace Alert from Elasticsearch to Archive

```javascript
// 1. Get alert from OpenSOAR
GET /api/v1/alerts/{alert_id}

// 2. Get incidents containing this alert
GET /api/v1/alerts/{alert_id}/incidents

// 3. Get timeline of incident
GET /api/v1/incidents/{incident_id}/timeline

// 4. Get investigations for incident
GET /api/v1/incidents/{incident_id}/investigations

// 5. Get full investigation trace
GET /api/v1/search/investigations/{investigation_id}/trace

// 6. Get playbook execution status
GET /api/v1/investigations/{investigation_id}/run-status

// 7. View playbook YAML
GET /api/v1/investigations/{investigation_id}/playbook/yaml

// 8. Get archived investigation
GET /api/v1/archives/by-investigation/{investigation_id}
```

### Pipeline Trace API

**Endpoint:** `GET /api/v1/pipeline/trace/alert/{alert_id}`

**Purpose:** Track alert from Elasticsearch through OpenSOAR to response system

**Output:**
```javascript
{
  "alert_id": "uuid",
  "source": "elasticsearch",
  "steps": [
    {
      "step": "elasticsearch_indexed",
      "timestamp": "2026-04-13T18:00:00Z",
      "details": "Indexed in wazuh-alerts-4.x-*"
    },
    {
      "step": "poller_picked_up",
      "timestamp": "2026-04-13T18:00:10Z",
      "details": "Poller found 1 new document"
    },
    {
      "step": "normalized",
      "timestamp": "2026-04-13T18:00:10Z",
      "details": "Converted to OpenSOAR format"
    },
    {
      "step": "enriched",
      "timestamp": "2026-04-13T18:00:11Z",
      "details": "Added GeoIP, MITRE, IOCs"
    },
    {
      "step": "forwarded_to_opensar",
      "timestamp": "2026-04-13T18:00:12Z",
      "details": "POST /api/v1/alerts - 201 Created"
    },
    {
      "step": "incident_created",
      "timestamp": "2026-04-13T18:00:30Z",
      "details": "Incident created in OpenSOAR"
    },
    {
      "step": "investigation_started",
      "timestamp": "2026-04-13T18:00:35Z",
      "investigation_id": "inv-uuid"
    },
    {
      "step": "ai_completed",
      "timestamp": "2026-04-13T18:01:00Z",
      "details": "Playbook generated"
    },
    {
      "step": "approved",
      "timestamp": "2026-04-13T18:01:30Z",
      "decided_by": "auto"
    },
    {
      "step": "playbook_executed",
      "timestamp": "2026-04-13T18:02:00Z",
      "details": "Ansible completed"
    },
    {
      "step": "fix_verified",
      "timestamp": "2026-04-13T18:02:30Z",
      "details": "No new alerts - likely_fixed"
    },
    {
      "step": "archived",
      "timestamp": "2026-04-13T18:03:00Z",
      "details": "Stored in archives"
    }
  ]
}
```

### Investigation Trace API

**Endpoint:** `GET /api/v1/search/investigations/{investigation_id}/trace`

**Output:**
```javascript
{
  "investigation_id": "4c0f62d6-1a74-4174-9889-bae2aa3924b9",
  "steps": [
    {
      "step": "investigation_created",
      "incident_id": "b04c2515-fdf1-407f-81ee-c65d95d5d350",
      "target_host": "ghazi",
      "status": "completed",
      "created_at": "2026-04-15T14:07:41.827875"
    },
    {
      "step": "incident_found",
      "title": "ET DROP Dshield Block Listed Source group 1 — 198.235.24.174 on ghazi",
      "severity": "medium"
    }
  ],
  "navigation": {
    "incident": "/api/v1/incidents/b04c2515-fdf1-407f-81ee-c65d95d5d350",
    "alerts": "/api/v1/incidents/b04c2515-fdf1-407f-81ee-c65d95d5d350/alerts",
    "timeline": "/api/v1/investigations/4c0f62d6-1a74-4174-9889-bae2aa3924b9/timeline"
  }
}
```

### Playbook Run Status API

**Endpoint:** `GET /api/v1/investigations/{investigation_id}/run-status`

**Output:**
```javascript
{
  "investigation_id": "uuid",
  "run_id": "run-uuid",
  "status": "completed",
  "started_at": "2026-04-13T18:00:50Z",
  "completed_at": "2026-04-13T18:01:30Z",
  "duration_seconds": 40,
  "exit_code": 0,
  "output": "PLAY RECAP ...\n\nghazi : ok=1 changed=0 unreachable=0 failed=0\n",
  "tasks": [
    { "name": "Gathering Facts", "status": "ok" },
    { "name": "Block attacker IP", "status": "ok" },
    { "name": "Restart service", "status": "ok" },
    { "name": "Verify fix", "status": "ok" }
  ]
}
```

### Execution Statistics API

**Endpoint:** `GET /monitor/execution-stats`

**Output:**
```javascript
{
  "total_runs": 100,
  "successful": 85,
  "failed": 15,
  "success_rate_pct": 85.0,
  "by_playbook_type": {
    "block_ip": { "total": 50, "success": 48 },
    "restart_service": { "total": 30, "success": 29 },
    "clean_disk": { "total": 20, "success": 18 }
  },
  "avg_duration_seconds": 45,
  "last_24h": { "runs": 25, "success": 22 }
}
```

### Auto-Approve Statistics API

**Endpoint:** `GET /monitor/auto-approve-stats`

**Output:**
```javascript
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

### Forwarder Status API

**Endpoint:** `GET /monitor/forwarder-status`

**Output:**
```javascript
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

### Pipeline Health API

**Endpoint:** `GET /monitor/pipeline-health`

**Output:**
```javascript
{
  "timestamp": "2026-04-15T15:16:27.240964+00:00",
  "stages": {
    "database": { "status": "healthy", "message": "connected" },
    "redis": { "status": "healthy", "message": "connected" },
    "elasticsearch": { "status": "healthy", "message": "connected" },
    "opensoar": { "status": "healthy", "message": "connected" },
    "forwarder": {
      "status": "running",
      "message": "Forwarder polls ES indices",
      "sources": ["wazuh", "falco", "filebeat", "suricata"]
    },
    "performance_monitoring": { "status": "running", "message": "Polls telegraf-* every 30s" },
    "incident_watcher": { "status": "running", "message": "Polls OpenSOAR every 15s" },
    "response_intelligence": { "status": "running", "message": "AI investigation + Ansible remediation" }
  },
  "overall_status": "healthy",
  "unhealthy_stages": []
}
```

### Frontend: Data Flow Visualization

```javascript
// For frontend, show complete data flow:

// 1. Alert List Page → Click alert
//    - Shows: ES → OpenSOAR flow

// 2. Incident Detail → Timeline tab
//    - Shows: Full lifecycle

// 3. Investigation Detail → Steps
//    - Shows: AI → Approval → Remediation → Verify → Archive

// 4. Monitoring Dashboard → Pipeline Health
//    - Shows: ES → Forwarder → OpenSOAR → Watcher → AI → Ansible

// Visual representation:
// ┌─────┐    ┌──────┐    ┌───────┐    ┌─────┐    ┌──────┐
// │ ES  │───▶│Pipe──│───▶│OpenSOAR│───▶│Watch │───▶│ AI  │
// └─────┘    └──────┘    └───────┘    └─────┘    └──────┘
//
//    ┌──────┐    ┌────────┐    ┌────────┐    ┌───────┐
//    │Ansible│───▶│Verify │───▶│Archive│───▶│Done  │
//    └──────┘    └────────┘    └────────┘    └───────┘

// Color coding for steps:
// - pending: Gray
// - running: Blue
// - completed: Green
// - failed: Red
```
| `/monitor/pipeline-health` | GET | Pipeline health |
| `/monitor/forwarder-status` | GET | Forwarder status |
| `/monitor/playbook-runs` | GET | All playbook executions |
| `/monitor/investigations/{id}` | GET | Investigation metrics |
| `/monitor/investigations/{id}/dependencies` | GET | Investigation dependencies |
| `/monitor/execution-stats` | GET | Execution statistics |
| `/monitor/auto-approve-stats` | GET | Auto-approve statistics |

---

## Frontend Implementation Notes

### 1. Always Handle Errors

```javascript
try {
  const response = await fetch(url);
  if (!response.ok) {
    const error = await response.json();
    // Show error message to user
    return;
  }
  const data = await response.json();
} catch (e) {
  // Network error - show retry option
}
```

### 2. Cache Strategy

```javascript
// - Quick stats: Cache 30s
// - Lists: Cache 1min
// - Detail pages: No cache (always fresh)
// - Pipeline status: Cache 10s
```

### 3. Real-time Updates

```javascript
// Use WebSocket for:
// - Investigation status changes
// - New alerts (optional)
// - Performance alerts (optional)

// Endpoint: ws://localhost:8001/ws/investigations
```

### 4. Polling Intervals

```javascript
// Dashboard: 30s
// Alert list: 30s
// Investigation: 15s
// Pipeline: 10s
// IPS Map: 10s
```

### 5. Security

```javascript
// If adding authentication:
// - Add token to headers
// - Handle 401 (redirect to login)
// - Handle 403 (show permission denied)
```

---

**Version:** 1.5.0  
**Last Updated:** April 15, 2026
**Tested With:** Real OpenSOAR instance at http://193.95.30.97:8000

### Verified Operations (Tested with Real Data)

The following operations were tested against the live OpenSOAR instance and verified to work correctly:

| Operation | Endpoint | Status | Verification |
|-----------|----------|--------|--------------|
| Create Incident | POST /api/v1/incidents | ✅ PASS | Created incident ID: 1c5f4527-8b55-4355-bb49-8067fb46763c |
| Link Alert to Incident | POST /api/v1/incidents/{id}/alerts | ✅ PASS | Alert successfully linked |
| Create Observable | POST /api/v1/observables | ✅ PASS | Created observable ID: 5d876af0-8584-4275-85ac-7a5d4ffbf979 |
| Add Enrichment | POST /api/v1/observables/{id}/enrichments | ✅ PASS | Enrichment added successfully |
| Add Comment | POST /api/v1/alerts/{id}/comments | ✅ PASS | Comment ID: 91ad1e07... |
| List Alerts | GET /api/v1/alerts | ✅ PASS | Returns 435 real alerts |
| List Incidents | GET /api/v1/incidents | ✅ PASS | Returns 30 real incidents |
| List Playbooks | GET /api/v1/playbooks | ✅ PASS | Returns 6 enabled playbooks |
| List Runs | GET /api/v1/runs | ✅ PASS | Returns 1206 runs |
| Suggestions | GET /api/v1/incidents/suggestions | ✅ PASS | Returns correlation groups |

### Current Live Data

```
OpenSOAR Dashboard: http://193.95.30.97:8000
ARIA Backend: http://193.95.30.97:8001

Total Alerts: 435 (critical: 12, high: 304, medium: 114, low: 5)
Total Incidents: 30
Total Playbooks: 6 (all enabled)
Total Runs: 1206
Total Observables: 106
```