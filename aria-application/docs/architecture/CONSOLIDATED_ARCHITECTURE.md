# ARIA - Architecture & Configuration

**Service:** ARIA - Adaptive Response Intelligence Automation  
**Version:** 1.4.0

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Components](#2-components)
3. [Data Flow](#3-data-flow)
4. [Directory Structure](#4-directory-structure)
5. [Technology Stack](#5-technology-stack)
6. [Configuration](#6-configuration)
7. [Database Schema](#7-database-schema)
8. [Development Guide](#8-development-guide)

---

## 1. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ARIA Backend                                     │
│                                                                             │
│  ┌──────────────────────┐    ┌──────────────────────┐                 │
│  │   Alert Forwarder    │    │ Response Intelligence │                     │
│  │   (Pipeline)        │    │   (Response)          │                     │
│  └──────────┬───────────┘    └──────────┬───────────┘                 │
│             │                           │                                │
│             ▼                           ▼                                │
│  ┌──────────────────────┐    ┌──────────────────────┐                 │
│  │  Elasticsearch        │    │   OpenSOAR            │                 │
│  │  (Wazuh, Falco,      │───▶│   (Incident          │◀──┐              │
│  │   Suricata, Filebeat) │    │    Management)       │   │              │
│  └──────────────────────┘    └──────────────────────┘   │              │
│                                                          │              │
│                                                          ▼              │
│                                                 ┌──────────────────┐      │
│                                                 │   NVIDIA NIM      │      │
│                                                 │   qwen2.5-coder  │      │
│                                                 └──────────────────┘      │
│                                                          │              │
│                                                          ▼              │
│                                                 ┌──────────────────┐      │
│                                                 │   Ansible        │      │
│                                                 │   (Remediation)  │      │
│                                                 └──────────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Components

### Alert Forwarder (Pipeline)

| Component | File | Description |
|-----------|------|-------------|
| Poller | `pipeline/poller.py` | Main polling loop, cursor management |
| Sender | `pipeline/sender.py` | OpenSOAR API client |
| Mappers | `pipeline/mappers/` | Alert format transformers |
| Enrichment | `pipeline/enrichment/` | GeoIP, MITRE, Sigma |

### Response Intelligence Layer

| Component | File | Description |
|-----------|------|-------------|
| Watcher | `response/watcher.py` | Polls OpenSOAR for incidents |
| AI Engine | `response/ai_engine.py` | NVIDIA NIM integration |
| Auto-Approve | `response/auto_approve.py` | Hybrid auto-approve |
| Ansible Exec | `response/ansible_exec.py` | Playbook execution |
| Fix Verifier | `response/fix_verifier.py` | Post-remediation verification |
| Archiver | `response/archiver.py` | Archive completed |

### API Layer

| Component | File | Description |
|-----------|------|-------------|
| App | `api/app.py` | FastAPI application |
| Investigations | `api/routes/investigations.py` | CRUD operations |
| Monitoring | `api/routes/monitoring.py` | Stats and logs |
| Assistant | `api/routes/assistant.py` | AI assistant |
| IPS | `api/routes/ips.py` | Attack visualization |

---

## 3. Data Flow

### Flow 1: Alert Forwarding

```
Elasticsearch → Poller → Mappers → Enrich → OpenSOAR → Redis (cursor)
```

1. Poller queries Elasticsearch with cursor
2. Normalize with source-specific mapper
3. Enrich with GeoIP, MITRE, Sigma
4. POST to OpenSOAR `/api/v1/alerts`
5. Advance cursor and persist

### Flow 2: Incident Investigation

```
OpenSOAR → Watcher → AI Engine → Analyst → Ansible → Fix Verifier → Archiver
```

1. Watcher polls OpenSOAR for new "open" incidents
2. Fetch alerts, build context
3. AI Engine generates: summary, narrative, risk, playbook
4. Investigation moves to "awaiting_approval"
5. Analyst approves via API
6. Ansible Exec runs playbook
7. Fix Verifier confirms fix
8. Archiver moves to archive

---

## 4. Directory Structure

```
/home/dash/opensoar backend/
├── main.py                    # Entry point
├── .env                     # Configuration
├── config/
│   └── settings.py            # Pydantic settings
├── core/
│   ├── elasticsearch.py      # ES client
│   ├── redis.py             # Redis client
│   └── geoip.py            # IP geolocation
├── pipeline/                # Alert Forwarder
│   ├── poller.py            # Main polling
│   ├── sender.py            # OpenSOAR client
│   ├── mappers/            # Alert transformers
│   └── enrichment/         # Alert enrichment
├── response/                # Response Intelligence
│   ├── watcher.py          # Incident watcher
│   ├── ai_engine.py        # AI integration
│   ├── ansible_exec.py    # Playbook execution
│   ├── fix_verifier.py    # Fix verification
│   ├── models.py          # DB models
│   └── assistant.py       # AI assistant
├── api/                    # FastAPI
│   ├── app.py              # App definition
│   └── routes/            # Endpoints
├── docs/                    # Documentation
└── tests/                   # Test suite
```

---

## 5. Technology Stack

| Layer | Technology |
|-------|-------------|
| Language | Python 3.12+ |
| Web Framework | FastAPI + Uvicorn |
| Database | SQLite |
| ORM | SQLAlchemy 2.0 (async) |
| HTTP Client | httpx 0.28+ |
| Logging | structlog |
| AI | NVIDIA NIM (qwen/qwen2.5-coder-32b-instruct) |
| Automation | Ansible |
| Cache/Queue | Redis |
| Search | Elasticsearch |

---

## 6. Configuration

### Environment Variables (.env)

```bash
# Elasticsearch
ELASTICSEARCH_URL=https://193.95.30.97:9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=<ELASTICSEARCH_PASSWORD>

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# OpenSOAR
OPENSAR_ENABLED=true
OPENSAR_URL=http://193.95.30.97:8000
OPENSAR_USERNAME=admin
OPENSAR_PASSWORD=admin123

# AI / NVIDIA
LLM_MODEL=qwen/qwen2.5-coder-32b-instruct

# Ansible
ANSIBLE_ENABLED=true
ANSIBLE_REMOTE_USER=ghazi

# Backend
BACKEND_PORT=8001
```

### Key Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSAR_POLL_INTERVAL` | 10s | Alert polling interval |
| `OPENSAR_BATCH_SIZE` | 50 | Alerts per ES query |
| `INCIDENT_WATCHER_INTERVAL` | 15s | Incident polling interval |
| `AUTO_APPROVE_ENABLED` | true | Enable auto-approve |
| `AUTO_APPROVE_SEVERITIES` | low, medium | Auto-approve severities |

---

## 7. Database Schema

### SQLite Location
`data/investigations.db`

### Tables

#### investigations
| Column | Type | Description |
|--------|------|-------------|
| id | String(36) | UUID, primary key |
| incident_id | String(36) | OpenSOAR incident ID |
| incident_title | Text | Incident title |
| incident_severity | String(20) | low/medium/high/critical |
| status | String(30) | pending/awaiting_approval/approved/running/completed/failed/archived |
| ai_summary | Text | AI-generated summary |
| ai_narrative | Text | AI-generated narrative |
| ai_risk | Text | AI-generated risk |
| playbook_yaml | Text | Ansible playbook |
| playbook_valid | Boolean | YAML validation |
| target_host | String(255) | Target for Ansible |
| created_at | DateTime | Creation timestamp |
| updated_at | DateTime | Last update |

#### investigation_alerts
| Column | Type | Description |
|--------|------|-------------|
| id | String(36) | UUID |
| investigation_id | String(36) | FK to investigations |
| alert_id | String(36) | OpenSOAR alert ID |
| alert_json | Text | Full alert JSON |
| severity | String(20) | Alert severity |

#### playbook_approvals
| Column | Type | Description |
|--------|------|-------------|
| id | String(36) | UUID |
| investigation_id | String(36) | FK to investigations |
| decision | String(20) | approved/declined |
| decided_by | String(255) | Who decided |

#### playbook_runs
| Column | Type | Description |
|--------|------|-------------|
| id | String(36) | UUID |
| investigation_id | String(36) | FK to investigations |
| status | String(20) | running/completed/failed |
| output | Text | Ansible output |
| exit_code | Integer | Exit code |

#### fix_verifications
| Column | Type | Description |
|--------|------|-------------|
| id | String(36) | UUID |
| investigation_id | String(36) | FK to investigations |
| status | String(20) | checking/likely_fixed/not_fixed |
| new_alerts_found | Integer | Alert count after fix |

#### archives
| Column | Type | Description |
|--------|------|-------------|
| id | String(36) | UUID |
| investigation_id | String(36) | FK to investigations |
| incident_id | String(36) | OpenSOAR incident ID |
| full_context_json | Text | Complete context |
| severity | String(20) | Severity |
| fix_status | String(30) | likely_fixed/not_fixed/inconclusive |

### Investigation Lifecycle

```
pending → awaiting_approval → approved/declined → running → completed/failed → archived
```

| Status | Description |
|--------|-------------|
| pending | Investigation created |
| awaiting_approval | AI completed, waiting for analyst |
| approved | Playbook approved |
| declined | Playbook declined |
| running | Ansible executing |
| completed | Success + verification |
| failed | Error |
| archived | Case closed |

---

## 8. Development Guide

### Code Conventions

- **Files:** snake_case (`ai_engine.py`)
- **Classes:** PascalCase (`Investigation`)
- **Functions:** snake_case (`run_investigation`)
- **Constants:** UPPER_SNAKE_CASE (`AI_TIMEOUT`)

### Async Patterns

```python
# CORRECT - async context manager
async with AsyncSessionLocal() as session:
    result = await session.execute(select(Investigation))
    await session.commit()

# WRONG - blocks event loop
session = AsyncSessionLocal()
```

### Logging

```python
import structlog
logger = structlog.get_logger()

logger.info("action_name", key="value")
logger.error("action_failed", error=str(e))
```

### Adding New API

```python
# api/routes/new_feature.py
from fastapi import APIRouter

router = APIRouter()

@router.get("/new-feature")
async def get_new_feature():
    return {"data": "result"}
```

Register in `api/app.py`:
```python
from api.routes.new_feature import router as new_feature_router
app.include_router(new_feature_router, prefix="/api/v1")
```

### Testing

```bash
# Run tests
python3 -m pytest tests/ -v

# Run specific test
python3 -m pytest tests/test_ai_engine.py -v
```

---

**Version:** 1.4.0  
**Last Updated:** April 13, 2026