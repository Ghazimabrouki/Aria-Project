# OpenSOAR Backend — Agent Guide

This document summarizes the architecture, technology stack, build processes, and development conventions for the OpenSOAR project (also referred to as ARIA — Adaptive Response Intelligence Automation). It is intended for AI coding agents who need to navigate and modify the codebase.

---

## 1. Project Overview

OpenSOAR is a security operations platform that ingests alerts from multiple sources (Wazuh, Suricata, Falco, Filebeat via Elasticsearch), correlates them into incidents locally, and then applies an AI-powered "Response Intelligence Layer" to investigate incidents, generate Ansible remediation playbooks, manage human or auto-approval workflows, execute fixes, verify them, and archive cases.

The backend supports two modes:
- **Local-only mode** (default): All alerts, incidents, and investigations are stored in local SQLite. No upstream OpenSOAR instance is required.
- **Upstream mode** (legacy): Alerts can be forwarded to an upstream OpenSOAR instance for centralized storage, while the local backend continues to run AI investigations and remediation.

The repository contains:
- A **Python async backend** (FastAPI + background async tasks)
- A **Next.js 16 dashboard frontend** for operators
- A suite of **pytest-driven tests** (unit + end-to-end)
- Deployment shell scripts and a systemd service unit

---

## 2. Technology Stack

### Backend
- **Language**: Python 3.12+
- **Web Framework**: FastAPI (async), served by Uvicorn on port `8001` (configurable via `BACKEND_PORT`)
- **Database**: SQLite with `aiosqlite` and SQLAlchemy 2.0 async ORM
  - Default path: `data/investigations.db` (configured in `config/settings.py`)
- **Caching / Deduplication**: Redis (`redis.asyncio`)
- **Search / Alert Source**: Elasticsearch (`elasticsearch` async client)
- **HTTP Client**: `httpx`
- **Logging**: `structlog`
- **Configuration**: `pydantic-settings` reading from `.env`
- **Remediation**: Ansible (writes playbooks + inventory to disk and invokes `ansible-playbook`)
- **AI / LLM**: Multi-provider support (NVIDIA NIM, Ollama, OpenAI, Anthropic, Google, OpenRouter) with rule-based fallback

### Frontend
- **Framework**: Next.js 16.2.0 with App Router
- **UI Library**: React 19, TypeScript 5.7.3
- **Styling**: Tailwind CSS v4.2.0, `tw-animate-css`, custom OKLCH-based theming (light + dark)
- **Component System**: shadcn/ui ("new-york" style, ~40+ Radix UI primitives in `components/ui/`)
- **Data Fetching**: `swr`
- **Real-Time**: Custom WebSocket context/provider (`lib/websocket.tsx`)
- **Charts**: `recharts`
- **Maps**: `react-simple-maps`
- **Icons**: `lucide-react`
- **Package Manager**: pnpm (evidenced by `pnpm-lock.yaml`)

### Testing
- **Backend**: `pytest` with `asyncio_mode = auto`
- **Frontend**: Playwright `^1.59.1` is installed in `frontend/package.json` but **no Playwright tests or config exist** at this time

---

## 3. Code Organization

### Top-Level Directories

| Directory | Purpose |
|-----------|---------|
| `api/` | FastAPI app (`app.py`), WebSocket manager (`websocket.py`), route modules (`api/routes/`), and HTML templates (`api/templates/`) |
| `config/` | Pydantic settings (`settings.py`), Sigma rules (`config/sigma_rules/`), and misc config files |
| `core/` | Shared infrastructure clients: Elasticsearch, Redis, GeoIP |
| `data/` | Persistent runtime data: SQLite DB (`investigations.db`), playbooks, cursors, seen IDs, backups, artifacts, evidence, GeoIP |
| `docs/` | Markdown documentation (architecture, API specs, features, backend processes) |
| `frontend/` | Next.js application (pages, components, hooks, lib, styles, public) |
| `pipeline/` | Alert ingestion, mapping, enrichment, deduplication, forwarding, retry queue, and performance polling |
| `response/` | AI investigation engine, incident watcher, approval workflow, Ansible execution, fix verification, archiving |
| `scripts/` | Operational scripts (`backup_db.sh`, `restore_db.sh`) |
| `tests/` | Python unit tests and end-to-end tests under `tests/e2e/` |

### Key Backend Modules

- **`api/app.py`** — FastAPI factory, registers all routers, initializes the response DB on startup
- **`api/routes/`** — 13+ route modules (investigations, alerts, incidents, archives, assistant, adaptive, monitoring, pipeline, search, dashboard, ips, performance, approval_ui)
- **`pipeline/poller/`** — Main forwarder loop: polls Elasticsearch, processes alerts, manages cursors and seen-ID deduplication
- **`pipeline/sender.py`** — `OpenSOARClient` singleton for forwarding alerts to the upstream OpenSOAR instance
- **`pipeline/mappers/`** — Source-specific mappers: `wazuh`, `falco`, `suricata`, `filebeat`, `generic`
- **`pipeline/enrichment/`** — GeoIP enrichment, MITRE ATT&CK mapping, Sigma noise filtering
- **`response/watcher/`** — Polls OpenSOAR for open incidents and spawns AI investigations
- **`response/ai_engine/`** — LLM prompt building, multi-provider clients, response parsing, playbook validation
- **`response/db.py`** — Async SQLite engine and session factory
- **`response/models.py`** — SQLAlchemy models: `Investigation`, `InvestigationAlert`, `PlaybookApproval`, `PlaybookRun`, `FixVerification`, `Archive`
- **`response/ansible_exec.py`** — Executes Ansible playbooks via subprocess
- **`response/fix_verifier.py`** — Re-queries Elasticsearch to verify remediation success
- **`core/elasticsearch.py`** — Async Elasticsearch client with retry/backoff helpers
- **`core/redis.py`** — Async Redis client with loop-aware singleton caching

### Key Frontend Modules

- **`frontend/app/(dashboard)/`** — Route group containing all dashboard pages (alerts, incidents, investigations, archives, assistant, metrics, monitoring, pipeline, search, ips)
- **`frontend/app/layout.tsx`** — Root layout with fonts, metadata, and Vercel Analytics
- **`frontend/lib/api.ts`** — Large typed API client (~1,380 lines). Uses `NEXT_PUBLIC_API_URL` when set; in Docker it uses same-origin relative URLs that Next.js rewrites to the backend.
- **`frontend/lib/websocket.tsx`** — WebSocket provider subscribing to backend channels
- **`frontend/components/ui/`** — shadcn/ui component library

---

## 4. Build, Run & Test Commands

> **Note**: Python dependencies are listed in `requirements.txt` for containerized deployments. The legacy startup scripts may still reference either `.venv` or system `python3` depending on the script. The Docker frontend proxies HTTP API calls through the Next.js server to avoid CORS issues.

### Docker (Recommended for Local Development)

A complete `docker-compose` stack is available. It launches Redis, the backend API, background workers, and the Next.js frontend with a single command:

```bash
# Build images and start all services
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop everything
docker-compose down
```

**Services and ports**
| Service | Container | Host port | Notes |
|---------|-----------|-----------|-------|
| Redis | `aria-redis` | `6380` | Cache / dedup; internal container port is `6379` |
| Backend API | `aria-api` | `8001` | FastAPI / uvicorn |
| Background worker | `aria-worker` | none | Runs `main.py`; skips API because port 8001 is already in use |
| Frontend | `aria-frontend` | `3001` | Production Next.js build |

> Host ports `3001` and `6380` are used because `3000` and `6379` were already occupied on this machine. You can change them in `docker-compose.yml` if those ports become free.

**Important Docker notes**
- The host `.env` file is mounted read-write into the backend containers.
- Settings and per-asset credential changes made through the UI are published to Redis and reloaded by both the API and worker containers — no container restart is required.
- The host `./data` directory is mounted into the backend containers so SQLite, playbooks, cursors, seen IDs, artifacts, and backups persist across restarts.
- Elasticsearch and Ollama remain **external** services; ensure the containers can reach the URLs configured in `.env`.
- `docker-compose.yml` overrides `REDIS_HOST=redis`, so no `.env` change is required for Redis.
- The frontend is built with `NEXT_PUBLIC_API_URL=""` so API calls use same-origin relative URLs (`/api/v1/...`). Next.js rewrites those requests to the `api` container internally, so the browser never needs direct CORS access to port 8001.
- All frontend `fetch` calls use `cache: "no-store"` to prevent stale errors from browser cache.
- A script unregisters any previously-installed service workers on page load.
- WebSocket still connects directly to `ws://localhost:8001/ws`; access the frontend via `localhost:3001` (or set `NEXT_PUBLIC_WS_URL` to match your host).
- `RATE_LIMIT_ENABLED=false` and `SEARCH_RATE_LIMIT_ENABLED=false` are set in `docker-compose.yml` because all frontend requests share the same Docker gateway IP and would otherwise hit per-IP rate limits.

### Backend

Start the full backend (API + all background services):
```bash
# Recommended production-like launcher (uses system python3, auto-restarts crashed processes)
./run_backend.sh
```

Start only the API server:
```bash
./run_api.sh
# or directly
python3 -m uvicorn api.app:app --host 0.0.0.0 --port 8001
```

Start only background services (main.py will skip API if port 8001 is already in use):
```bash
python3 main.py
```

Other startup options:
```bash
./start.sh          # activates .venv, starts API + main.py in separate sessions
./supervisor.sh     # simple supervisor that restarts main.py if it dies
python3 run_daemon.py  # daemonizes uvicorn via the python-daemon library
```

Run backend unit tests:
```bash
pytest tests/ -v
```

Run E2E tests:
```bash
./run_e2e_tests.sh all
# or a subset:
./run_e2e_tests.sh fast   # connectivity + pipeline + response
```

### Frontend

```bash
cd frontend

# Development server
pnpm dev

# Production build
pnpm build

# Production start (used by the Docker image)
pnpm start

# Linting
pnpm lint
```

---

## 5. Configuration & Environment

All backend configuration is driven by `config/settings.py` (Pydantic `BaseSettings`) and loaded from a `.env` file at the project root. **Do not commit `.env` or any file containing secrets.**

Key configuration categories:

| Category | Notable Variables |
|----------|-------------------|
| Elasticsearch | `ELASTICSEARCH_URL`, `ELASTICSEARCH_USER`, `ELASTICSEARCH_PASSWORD`, `ELASTICSEARCH_USE_SSL` |
| Redis | `REDIS_HOST`, `REDIS_PORT` |
| Upstream OpenSOAR (legacy) | `OPENSOAR_ENABLED` / `UPSTREAM_ENABLED`, `OPENSOAR_URL`, `OPENSOAR_USERNAME`, `OPENSOAR_PASSWORD`, `ALERT_POLL_INTERVAL`, `ES_BATCH_SIZE`, `ALERT_MIN_SEVERITY` |
| LLM / AI | `LLM_PROVIDER`, `LLM_MODEL`, `NVIDIA_API_KEY`, `OLLAMA_HOST`, `OLLAMA_TIMEOUT`, `LLM_ENABLED`, `LLM_FALLBACK_TO_PYRCA` |
| Ansible / SSH | `ANSIBLE_ENABLED`, `ANSIBLE_REMOTE_HOST`, `ANSIBLE_REMOTE_USER`, `ANSIBLE_SSH_KEY`, `ANSIBLE_SSH_PASSWORD`, `ANSIBLE_BECOME_METHOD`, `ANSIBLE_BECOME_PASSWORD` |
| Auto-Approval | `AUTO_APPROVE_ENABLED`, `AUTO_APPROVE_METHOD` (`static` \| `dynamic` \| `ai` \| `hybrid`), `AUTO_APPROVE_SEVERITIES`, `AUTO_APPROVE_BLOCK_SEVERITIES` |
| Performance Monitoring | `PERFORMANCE_ENABLED`, `PERFORMANCE_POLL_INTERVAL`, `PERFORMANCE_CPU_WARNING`, `PERFORMANCE_CPU_CRITICAL`, `PERFORMANCE_MEMORY_WARNING`, `PERFORMANCE_MEMORY_CRITICAL`, `PERFORMANCE_ANOMALY_DETECTION` |
| Notifications | `SLACK_WEBHOOK_URL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` |
| API / Backend | `BACKEND_PORT` (default 8001), `BACKEND_URL`, `BACKEND_API_KEY` |
| Paths / State | `DB_PATH` (default `data/investigations.db`), `CURSOR_DIR` (`data/cursors`), `SEEN_IDS_DIR` (`data/seen_ids`), `PLAYBOOK_DIR` (`data/playbooks`), `BACKUP_DIR` (`data/backups`) |

---

## 6. Testing Strategy

- **Unit tests** live in `tests/` (e.g., `test_client.py`, `test_forwarder.py`, `test_mappers.py`, `test_severity.py`, `test_datausage.py`, `test_ip_extractor.py`).
- **E2E tests** live in `tests/e2e/` and require external services:
  - Elasticsearch at `https://193.95.30.97:9200`
  - OpenSOAR at `http://193.95.30.97:8000`
  - Ollama at `http://193.95.30.97:11434`
  - Local backend API at `http://localhost:8001`
- `pytest.ini` sets `asyncio_mode = auto`, `testpaths = tests/e2e`, and quiet formatting (`-v --tb=short --no-header -p no:warnings`).
- E2E `conftest.py` automatically starts the local backend via `uvicorn api.app:app --host 0.0.0.0 --port 8001` before the session and tears it down after.
- **Frontend**: there is no active frontend test suite despite Playwright being a devDependency. Build verification (`next build`) and linting (`eslint .`) are the current quality gates.

---

## 7. Deployment & Operations

### Systemd
`opensoar-backend.service` runs **only the API server** via Uvicorn:
```ini
ExecStart=/home/dash/opensoar backend/.venv/bin/python3 -m uvicorn api.app:app --host 0.0.0.0 --port 8001
Restart=always
```
For a complete deployment, `main.py` (background services) must also be running.

### Process Isolation
The production startup scripts (`run_backend.sh`, `start.sh`) intentionally run the API server and `main.py` as **separate OS processes** so a crash in background tasks does not take down the HTTP API. `main.py` itself wraps each background coroutine in `_run_safe_task`, which catches exceptions and restarts the individual task after a delay.

### Background Tasks (started by `main.py`)
| Task | Interval / Behavior |
|------|---------------------|
| Alert Forwarder / Local Poller | Polls ES every `ALERT_POLL_INTERVAL` seconds (default 10s) |
| Incident Watcher | Polls local SQLite for open incidents every `INCIDENT_WATCHER_INTERVAL` seconds (default 15s). In upstream mode, polls OpenSOAR instead. |
| Incident Correlation | Every `INCIDENT_CORRELATION_INTERVAL` seconds (default 30s). In local mode, runs purely on local SQLite data. |
| Retry Queue | Every 5 minutes |
| Auto-Transitions | Every 1 hour |
| Daily Backup | At 03:00 local time |
| Performance Monitoring | Optional (when `PERFORMANCE_ENABLED=true`) |
| Watchdog | Logs memory + child-process heartbeat every 60s |

### Logging

ARIA supports two production logging modes:

**Option A — systemd journald (recommended for production)**
- Use `opensoar-backend.service` with `StandardOutput`/`StandardError` commented out (default).
- Logs are captured by journald: `journalctl -u opensoar-backend -f`
- Survives reboots, rotated by systemd, no file permissions to manage.

**Option B — `/var/log/aria/` with logrotate**
- `run_backend.sh` and `start.sh` write API and background service logs to `/var/log/aria/`.
- The directory is created at runtime with a safe permission check.
- Deploy `deploy/logrotate/aria` to `/etc/logrotate.d/` for daily rotation (30 days, compressed).
- For systemd file logging, uncomment the `StandardOutput`/`StandardError` lines in `opensoar-backend.service`.

Operational logs:
| Log | Path | Produced by |
|-----|------|-------------|
| API server | `/var/log/aria/api.log` | `run_backend.sh`, `start.sh` |
| Background services | `/var/log/aria/main.log` | `run_backend.sh`, `start.sh` |
| Systemd service | journald or `/var/log/aria/backend.log` | `opensoar-backend.service` |

### Backup & Restore

**What is backed up:**
- `data/investigations.db` — SQLite database
- `data/playbooks/` — playbooks, inventories, extracted evidence
- `data/cursors/` — Elasticsearch poll cursors
- `data/seen_ids/` — deduplication IDs
- `data/artifacts/` — tickets DB, decision logs, pattern tracking, geoip cache, incident cache/links
- `data/evidence/` — remote evidence staging (if non-empty)

**What is NOT backed up:**
- Active operational logs (handled by journald/logrotate)
- Ephemeral `/tmp` files

**Commands:**
- **Backup**: `scripts/maintenance/backup_db.sh` copies persistent data to `data/backups/` with configurable retention (`BACKUP_RETENTION_DAYS`, default 30).
- **Restore**: `scripts/maintenance/restore_db.sh <timestamp>` restores from a backup. The operator must restart the backend afterward.

---

## 8. Code Style & Conventions

- **Language**: All source code comments and documentation are written in **English**.
- **Imports**: The project favors direct module imports over deep package re-exports. Only `pipeline/`, `core/`, and `pipeline/poller/` actively re-export public symbols in their `__init__.py` files.
- **Logging**: Use `structlog` with structured key-value logging (e.g., `logger.info("event_name", key=value)`).
- **Async**: The backend is fully async. Use `async`/`await` for I/O, database access, HTTP calls, and Elasticsearch queries.
- **Database**: Use the async SQLAlchemy session from `response.db` for all SQLite operations.
- **File size**: The existing `CLAUDE.md` (not this file) asks to keep files under 500 lines.
- **Secrets**: Never hardcode API keys, credentials, or connection strings in source files.

---

## 9. Security Considerations

- **Do not commit `.env`** or any file containing secrets.
- **CORS**: `api/app.py` currently allows all origins (`allow_origins=["*"]`). This is convenient for local development but should be tightened for production.
- **Path sanitization**: When accepting user-provided paths, validate them to prevent directory traversal (several endpoints accept file-like identifiers that are resolved under `/tmp`).
- **SSH / Ansible**: Playbooks and inventory are written to `data/playbooks/` and executed via `ansible-playbook`. Ensure the target host and SSH credentials are properly scoped.
- **Input validation**: FastAPI handles request validation via Pydantic models, but business-logic boundaries (e.g., playbook YAML content) should be validated before disk write or execution.

---

## 10. Important Notes for Agents

- **`requirements.txt` exists for containerized deployments**: Python dependencies are pinned in `requirements.txt` and installed in the Docker image. If you add a new third-party dependency, update `requirements.txt` and rebuild the backend image.
- **Docker Compose deployment**: `docker-compose.yml`, `Dockerfile.backend`, `frontend/Dockerfile`, and `.dockerignore` files are present. Run `docker-compose up --build -d` to start the stack.
- **Frontend ↔ Backend coupling**: In local development the frontend points to `localhost:8001` via `NEXT_PUBLIC_API_URL`. In Docker, `NEXT_PUBLIC_API_URL` is set to an empty string so the frontend uses same-origin relative URLs (`/api/v1/...`), which Next.js rewrites to the `api` container internally.
- **WebSocket channels**: The backend broadcasts on `investigations`, `performance`, `system`, and `all`. If you add new real-time events, reuse `api/websocket.py`.
- **Database migrations**: There is no migration framework (e.g., Alembic). Schema changes are handled by `response.db.init_db()`, which creates tables if they do not exist.
- **Test external dependencies**: E2E tests assume specific remote IPs (`193.95.30.97`). Do not run E2E tests blindly in a different environment without updating `tests/e2e/conftest.py` or the target URLs.
