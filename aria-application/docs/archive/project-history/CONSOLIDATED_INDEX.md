# ARIA - Documentation Index

**Service:** ARIA - Adaptive Response Intelligence Automation  
**Version:** 1.4.0  
**Last Updated:** April 13, 2026

---

## Overview

ARIA (Adaptive Response Intelligence Automation) is a Security Operations Center (SOC) automation platform that:

- Pulls security alerts from Elasticsearch (Wazuh, Falco, Suricata, Filebeat)
- Forwards enriched alerts to OpenSOAR for incident management
- Uses **NVIDIA NIM API** (qwen/qwen2.5-coder-32b-instruct) for AI analysis
- Auto-approves low/medium severity incidents
- Executes automated remediation via Ansible
- Verifies fixes by re-querying Elasticsearch
- Provides real-time server performance monitoring
- Features an interactive IPS attack map visualization
- Includes an enhanced AI assistant that knows everything about your system

**Reliability Score: 10/10** - Production ready

---

## Consolidated Documentation

This documentation has been consolidated into 3 main files:

| File | Description |
|------|-------------|
| [CONSOLIDATED_API.md](./CONSOLIDATED_API.md) | Complete API reference with all endpoints |
| [CONSOLIDATED_ARCHITECTURE.md](./CONSOLIDATED_ARCHITECTURE.md) | System design, config, database, dev guide |
| [CONSOLIDATED_FEATURES.md](./CONSOLIDATED_FEATURES.md) | Features, operations, troubleshooting, quick reference |

### Quick Navigation

| Topic | File |
|-------|------|
| API Endpoints | CONSOLIDATED_API.md |
| Architecture | CONSOLIDATED_ARCHITECTURE.md |
| Configuration | CONSOLIDATED_ARCHITECTURE.md |
| Database Schema | CONSOLIDATED_ARCHITECTURE.md |
| Development Guide | CONSOLIDATED_ARCHITECTURE.md |
| Feature Status | CONSOLIDATED_FEATURES.md |
| What's New | CONSOLIDATED_FEATURES.md |
| Troubleshooting | CONSOLIDATED_FEATURES.md |
| Quick Reference | CONSOLIDATED_FEATURES.md |

---

## Quick Start

### Run the Backend

```bash
cd "/home/dash/opensoar backend"
python3 main.py
```

### Check Health

```bash
curl http://localhost:8001/health
```

### Check Dashboard

```bash
curl http://localhost:8001/api/v1/dashboard/summary
```

---

## Key Endpoints

| Endpoint | Description |
|----------|-------------|
| `/health` | Health check |
| `/api/v1/dashboard/summary` | Full dashboard with counts |
| `/api/v1/dashboard/quick-stats` | Quick stats for headers |
| `/api/v1/investigations` | List all investigations |
| `/api/v1/investigations/{id}` | Investigation details |
| `/api/v1/alerts` | List alerts |
| `/api/v1/incidents` | List incidents |
| `/api/v1/archives` | List archives |
| `/api/v1/metrics/dashboard` | Performance metrics |
| `/api/v1/ips/map-data` | IPS attack map data |
| `/api/v1/assistant/context` | AI assistant context |
| `/monitor/services-status` | System services status |

---

## What's New in v1.4.0

### 1. IPS Attack Visualization
Real-time world map showing cyber attack traffic.

```bash
curl http://localhost:8001/api/v1/ips/map-data
curl http://localhost:8001/api/v1/ips/statistics
```

### 2. Enhanced AI Assistant
Unified AI that queries all system data sources.

```bash
curl -X POST http://localhost:8001/api/v1/assistant/query \
  -H "Content-Type: application/json" \
  -d '{"question": "How is the system performing?"}'
```

### 3. Interconnected Data Model
Every entity links to related entities.

- Alert → Incidents, Similar Alerts
- Incident → Alerts, Timeline, Investigation
- Investigation → Playbook, Timeline

### 4. New Investigation Features

```bash
PUT /api/v1/investigations/{id}/playbook        # Update playbook
GET /api/v1/investigations/{id}/playbook/yaml  # Get raw YAML
POST /api/v1/investigations/{id}/execute     # Execute directly
```

---

## System Statistics

- **Total Investigations:** 150+
- **Status Breakdown:**
  - Pending: 130+
  - Completed: 20+
  - Failed: 5
- **Performance Investigations:** 25+ (source=performance)
- **Success Rate:** 80%+

**AI Pipeline:** Using NVIDIA NIM API (qwen/qwen2.5-coder-32b-instruct)
- Response time: ~1 second per call

---

## Directory Structure

```
/home/dash/opensoar backend/
├── main.py                    # Entry point
├── .env                     # Configuration
├── config/
│   └── settings.py          # Pydantic settings
├── core/
│   ├── elasticsearch.py      # ES client
│   ├── redis.py           # Redis client
│   └── geoip.py          # IP geolocation
├── pipeline/               # Alert Forwarder
│   ├── poller.py          # Main polling
│   ├── sender.py         # OpenSOAR client
│   └── mappers/         # Alert transformers
├── response/              # Response Intelligence
│   ├── watcher.py        # Incident watcher
│   ├── ai_engine.py     # AI integration
│   ├── ansible_exec.py # Playbook execution
│   └── models.py       # DB models
├── api/                   # FastAPI
│   ├── app.py           # App definition
│   └── routes/         # Endpoints
└── docs/                 # Documentation
```

---

## Support

For issues or questions:
1. Check [CONSOLIDATED_FEATURES.md](./CONSOLIDATED_FEATURES.md) - Troubleshooting section
2. Check backend console output
3. Check logs: `/tmp/opensoar.log`

---

**Version:** 1.4.0  
**Last Updated:** April 13, 2026