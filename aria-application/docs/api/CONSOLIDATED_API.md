# ARIA - API Documentation

**Service:** ARIA - Adaptive Response Intelligence Automation  
**Version:** 1.4.0  
**Base URL:** `http://localhost:8001`

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Base Endpoints](#2-base-endpoints)
3. [Interconnected Data Model](#3-interconnected-data-model)
4. [Alert APIs](#4-alert-apis)
5. [Incident APIs](#5-incident-apis)
6. [Investigation APIs](#6-investigation-apis)
7. [Pipeline APIs](#7-pipeline-apis)
8. [Archive APIs](#8-archive-apis)
9. [Performance APIs](#9-performance-apis)
10. [System Monitoring APIs](#10-system-monitoring-apis)
11. [Search APIs](#11-search-apis)
12. [Dashboard APIs](#12-dashboard-apis)
13. [WebSocket APIs](#13-websocket-apis)
14. [AI Assistant APIs](#14-ai-assistant-apis)
15. [IPS Attack Visualization](#15-ips-attack-visualization)

---

## 1. Getting Started

### Starting the Backend

```bash
cd /home/dash/opensoar\ backend
source .venv/bin/activate
python3 main.py
```

### Health Check

```bash
curl http://localhost:8001/health
```

---

## 2. Base Endpoints

### GET /
Service information.

```bash
curl http://localhost:8001/
```

### GET /health
Health check.

```bash
curl http://localhost:8001/health
```

### GET /docs
Interactive API documentation (Swagger UI).

```bash
curl http://localhost:8001/docs
```

---

## 3. Interconnected Data Model

### Entity Relationships

```
ALERT → INCIDENT → INVESTIGATION → PLAYBOOK → VERIFICATION → ARCHIVE
        ↓              ↓
     SIMILAR        TIMELINE
      ALERTS
```

### Navigation Flow

| From Entity | View | Link To |
|------------|------|---------|
| Alert | incidents | `/api/v1/alerts/{id}/incidents` |
| Alert | similar | `/api/v1/alerts/{id}/similar` |
| Incident | alerts | `/api/v1/incidents/{id}/alerts` |
| Incident | timeline | `/api/v1/incidents/{id}/timeline` |
| Incident | investigation | `/api/v1/incidents/{id}/investigations` |
| Investigation | playbook | `/api/v1/investigations/{id}/playbook` |
| Host | metrics | `/api/v1/metrics/{host}` |

---

## 4. Alert APIs

### GET /api/v1/alerts
List all alerts from OpenSOAR.

```bash
curl "http://localhost:8001/api/v1/alerts?limit=5&severity=high"
```

### GET /api/v1/alerts/{alert_id}
Get single alert with relationships.

```bash
curl http://localhost:8001/api/v1/alerts/a8f21bfb-ef0a-489c-9c78-5c02fb164e3e
```

### GET /api/v1/alerts/{alert_id}/incidents
Get incidents containing this alert.

### GET /api/v1/alerts/{alert_id}/similar
Find similar alerts by source_ip.

---

## 5. Incident APIs

### GET /api/v1/incidents
List incidents from OpenSOAR.

```bash
curl "http://localhost:8001/api/v1/incidents?status=open&limit=5"
```

### GET /api/v1/incidents/{incident_id}
Get incident with relationships.

### GET /api/v1/incidents/{incident_id}/alerts
Get alerts linked to this incident.

### GET /api/v1/incidents/{incident_id}/timeline
Full lifecycle timeline.

### GET /api/v1/incidents/{incident_id}/investigations
Get local investigations for this incident.

---

## 6. Investigation APIs

### GET /api/v1/investigations
List all investigations.

### GET /api/v1/investigations/{investigation_id}
Full investigation with playbook.

### PUT /api/v1/investigations/{investigation_id}/playbook
Update playbook YAML.

### GET /api/v1/investigations/{investigation_id}/playbook/yaml
Get raw YAML for editor.

### POST /api/v1/investigations/{investigation_id}/execute
Execute playbook directly.

### POST /api/v1/investigations/{investigation_id}/approve
Approve playbook.

### POST /api/v1/investigations/{investigation_id}/decline
Decline playbook.

### GET /api/v1/investigations/{investigation_id}/timeline
Investigation timeline.

### GET /api/v1/investigations/stats
Investigation statistics.

---

## 7. Pipeline APIs

### GET /api/v1/pipeline/status
Pipeline status.

### GET /api/v1/pipeline/sources
Per-source statistics.

### GET /api/v1/pipeline/cursors
Current cursor positions.

### GET /api/v1/pipeline/trace/alert/{alert_id}
Trace alert lifecycle.

---

## 8. Archive APIs

### GET /api/v1/archives
List archives.

### GET /api/v1/archives/stats
Archive statistics.

### GET /api/v1/archives/{archive_id}
Full archived context.

---

## 9. Performance APIs

### GET /api/v1/metrics/dashboard
All hosts with metrics.

### GET /api/v1/metrics/{host}
Single host metrics.

### GET /api/v1/metrics/{host}/relationships
Host + metrics + alerts + investigations.

---

## 10. System Monitoring APIs

### GET /monitor/services-status
All services status.

### GET /monitor/health
Health check.

### GET /monitor/pipeline-health
Pipeline health.

### GET /monitor/stuck-investigations
Investigations stuck > 1 hour.

### GET /monitor/services/{service}/logs
Logs from specific service.

### GET /monitor/services/{service}/errors
Errors from service.

---

## 11. Search APIs

### GET /api/v1/search
Search by text query.

### GET /api/v1/search/ips/{ip}
Find entities by IP address.

### GET /api/v1/search/domains/{domain}
Find entities by domain.

---

## 12. Dashboard APIs

### GET /api/v1/dashboard/summary
All counts with navigation.

### GET /api/v1/dashboard/quick-stats
Minimal stats for headers.

---

## 13. WebSocket APIs

### WS /ws/investigations
Investigation updates.

### WS /ws/performance
Performance alerts.

### WS /ws/system
System events.

---

## 14. AI Assistant APIs

### POST /api/v1/assistant/query
Ask questions.

```bash
curl -X POST http://localhost:8001/api/v1/assistant/query \
  -H "Content-Type: application/json" \
  -d '{"question": "How is ghazi performing?"}'
```

### GET /api/v1/assistant/context
Data sources available.

### GET /api/v1/assistant/sources
Source statistics.

### GET /api/v1/assistant/health
Assistant health check.

---

## 15. IPS Attack Visualization

### GET /api/v1/ips/map-data
Attack data for map.

### GET /api/v1/ips/statistics
Attack statistics.

### POST /api/v1/ips/event
Submit attack event.

---

## Testing Commands

```bash
# Health
curl http://localhost:8001/health

# Dashboard
curl http://localhost:8001/api/v1/dashboard/summary

# Quick Stats
curl http://localhost:8001/api/v1/dashboard/quick-stats

# Alerts
curl http://localhost:8001/api/v1/alerts?limit=5

# Incidents
curl http://localhost:8001/api/v1/incidents?limit=5

# Timeline
curl "http://localhost:8001/api/v1/incidents/{id}/timeline"

# Investigations
curl http://localhost:8001/api/v1/investigations

# Pipeline
curl http://localhost:8001/api/v1/pipeline/status

# Archives
curl http://localhost:8001/api/v1/archives

# Performance
curl http://localhost:8001/api/v1/metrics/dashboard

# Monitoring
curl http://localhost:8001/monitor/services-status

# Search
curl "http://localhost:8001/api/v1/search?q=ssh"

# IPS Map
curl http://localhost:8001/api/v1/ips/map-data
curl http://localhost:8001/api/v1/ips/statistics

# AI Assistant
curl http://localhost:8001/api/v1/assistant/context
curl -X POST http://localhost:8001/api/v1/assistant/query \
  -H "Content-Type: application/json" \
  -d '{"question": "How is the system performing?"}'
```

---

**Version:** 1.4.0  
**Last Updated:** April 13, 2026