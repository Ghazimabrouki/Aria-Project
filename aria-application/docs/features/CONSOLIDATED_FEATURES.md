# ARIA - Features & Operations

**Service:** ARIA - Adaptive Response Intelligence Automation  
**Version:** 1.4.0

---

## Table of Contents

1. [Feature Overview](#1-feature-overview)
2. [Working Features](#2-working-features)
3. [What's New (v1.4.0)](#3-whats-new-v140)
4. [Progress Reports](#4-progress-reports)
5. [Troubleshooting](#5-troubleshooting)
6. [Quick Reference](#6-quick-reference)

---

## 1. Feature Overview

ARIA consists of two main layers:

1. **Alert Forwarder** - Polls Elasticsearch, enriches alerts, forwards to OpenSOAR
2. **Response Intelligence** - AI investigation, playbook execution, verification

---

## 2. Working Features

### Alert Forwarder

| Feature | Status | Description |
|---------|--------|-------------|
| Elasticsearch polling | ✅ | Polls Wazuh, Falco, Suricata, Filebeat |
| Alert normalization | ✅ | Source-specific mappers |
| Cursor tracking | ✅ | Redis + file |
| Severity mapping | ✅ | Source-specific |
| IOC extraction | ✅ | IPs, hashes, domains |
| GeoIP enrichment | ✅ | Geographic context |
| MITRE mapping | ✅ | ATT&CK tactics |
| OpenSOAR integration | ✅ | POST to /api/v1/alerts |
| Deduplication | ✅ | Redis-based |

### Response Intelligence

| Feature | Status | Description |
|---------|--------|-------------|
| Incident polling | ✅ | Polls OpenSOAR |
| AI investigation | ✅ | NVIDIA NIM |
| Playbook generation | ✅ | Ansible YAML |
| Investigation storage | ✅ | SQLite |
| Approval workflow | ✅ | Approve/decline |
| Auto-approve | ✅ | Hybrid static + dynamic |
| Ansible execution | ✅ | Runs playbooks |
| Fix verification | ✅ | Re-queries ES |
| Archival | ✅ | Completed cases |

### API Endpoints

| Feature | Status |
|---------|--------|
| GET /health | ✅ |
| GET /api/v1/investigations | ✅ |
| POST /api/v1/investigations/{id}/approve | ✅ |
| POST /api/v1/investigations/{id}/decline | ✅ |
| GET /monitor/stats | ✅ |
| GET /monitor/stuck-investigations | ✅ |
| GET /api/v1/archives | ✅ |
| GET /api/v1/metrics/dashboard | ✅ |
| GET /api/v1/dashboard/summary | ✅ |
| GET /api/v1/search | ✅ |
| GET /api/v1/ips/map-data | ✅ |
| POST /api/v1/assistant/query | ✅ |

### Monitoring

| Feature | Status |
|---------|--------|
| Stuck investigation alerts | ✅ |
| Auto-recovery | ✅ |
| Playbook validation | ✅ |
| Exit code analysis | ✅ |
| WebSocket real-time | ✅ |

---

## 3. What's New (v1.4.0)

### IPS Attack Visualization

Real-time attack map showing cyber attack traffic.

| Endpoint | Description |
|----------|-------------|
| GET /api/v1/ips/map-data | Attack data for visualization |
| GET /api/v1/ips/statistics | Attack statistics |
| POST /api/v1/ips/event | Submit attack event |

### Enhanced AI Assistant

Unified AI that knows everything about your system.

| Endpoint | Description |
|----------|-------------|
| POST /api/v1/assistant/query | Enhanced query |
| GET /api/v1/assistant/context | Available data sources |
| GET /api/v1/assistant/sources | Source statistics |
| GET /api/v1/assistant/health | Assistant health |

### Interconnected Data Model

- Alert → Incidents → Investigation → Timeline
- Alert → Similar Alerts (same IP)
- Incident → Alerts → Timeline
- Host → Metrics → Investigations

### New Investigation Features

| Endpoint | Description |
|----------|-------------|
| PUT /api/v1/investigations/{id}/playbook | Update playbook |
| GET /api/v1/investigations/{id}/playbook/yaml | Get raw YAML |
| POST /api/v1/investigations/{id}/execute | Execute directly |

---

## 4. Progress Reports

### v1.3.2 - Smart Wazuh Authentication Monitoring (April 12, 2026)

- Fixed noise filtering to keep useful auth events
- Added smart auth pattern analysis (brute force, compromised account)
- Enhanced auto-approve guardrails

### v1.3.1 - WebSocket Integration (April 11, 2026)

- WebSocket manager for real-time updates
- /ws/investigations, /ws/performance, /ws/system

### v1.3.0 - Performance Monitoring System (April 11, 2026)

- Real-time server metrics (CPU, RAM, Disk, Network)
- Hybrid anomaly detection (statistical + AI)
- Root cause analysis via NVIDIA AI
- Dynamic AI-generated playbooks

### v1.2.0 - Real-Time Processing (April 11, 2026)

| Metric | Before | After |
|--------|--------|-------|
| Poll interval | 30s | 10s |
| Watcher interval | 60s | 15s |
| Correlation interval | 300s | 60s |
| Batch size | 25 | 50 |

### v1.1.0 - Auto-Approve System (April 2026)

- Hybrid static + dynamic auto-approve
- Low/medium severity auto-approved
- Critical/high blocked for human review

---

## 5. Troubleshooting

### Common Errors

#### httpx.Timeout Error
```python
# Wrong
httpx.Timeout(180)

# Correct
httpx.Timeout(connect=10.0, read=180.0, write=10.0, pool=10.0)
```

#### Connection Refused
```bash
# Check Elasticsearch
curl -k https://193.95.30.97:9200

# Check OpenSOAR
curl http://193.95.30.97:8000/health
```

#### Database Lock Error
- Use async sessions properly
- Avoid blocking operations

#### Port Already in Use
```bash
lsof -i :8001
pkill -f "python3 main.py"
```

### Debug Commands

```bash
# Health check
curl http://localhost:8001/health

# System stats
curl http://localhost:8001/monitor/stats

# Stuck investigations
curl http://localhost:8001/monitor/stuck-investigations

# Execution stats
curl http://localhost:8001/monitor/execution-stats
```

### Database Queries

```bash
# SQLite CLI
sqlite3 data/investigations.db

# Status counts
SELECT status, COUNT(*) FROM investigations GROUP BY status;
```

### Recovery Procedures

```bash
# Restart backend
pkill -f "python3 main.py"
sleep 2
python3 main.py &

# Backup database
cp data/investigations.db data/backups/investigations_backup_$(date +%Y%m%d).db

# Clear cursor
redis-cli DEL "opensoar:cursor:wazuh"
rm data/cursors/wazuh.cursor
```

---

## 6. Quick Reference

### Quick Links

| Category | Endpoint |
|----------|----------|
| Health | `GET /health` |
| Dashboard | `GET /api/v1/dashboard/summary` |
| Quick Stats | `GET /api/v1/dashboard/quick-stats` |
| AI Context | `GET /api/v1/assistant/context` |

### Core Entities

| Entity | List | Detail |
|--------|------|--------|
| Alerts | /api/v1/alerts | /api/v1/alerts/{id} |
| Incidents | /api/v1/incidents | /api/v1/incidents/{id} |
| Investigations | /api/v1/investigations | /api/v1/investigations/{id} |
| Archives | /api/v1/archives | /api/v1/archives/{id} |

### Parameters

| Parameter | Values | Default |
|-----------|--------|---------|
| limit | 1-200 | 50 |
| status | open, closed, investigating | all |
| severity | critical, high, medium, low | all |

### Status Values

- `pending` - Just created
- `running` - AI analysis in progress
- `awaiting_approval` - Playbook generated
- `approved` - Playbook approved
- `completed` - Remediation done
- `failed` - Remediation failed
- `archived` - Case closed
- `declined` - Playbook declined

### WebSocket

```javascript
const ws = new WebSocket('ws://localhost:8001/ws/investigations');
```

### Testing Commands

```bash
curl http://localhost:8001/health
curl http://localhost:8001/api/v1/dashboard/summary
curl http://localhost:8001/api/v1/alerts?limit=5
curl http://localhost:8001/api/v1/incidents?limit=5
curl http://localhost:8001/api/v1/investigations
curl http://localhost:8001/monitor/services-status
curl http://localhost:8001/api/v1/ips/map-data
curl -X POST http://localhost:8001/api/v1/assistant/query \
  -H "Content-Type: application/json" \
  -d '{"question": "How is the system performing?"}'
```

---

**Version:** 1.4.0  
**Last Updated:** April 13, 2026