# ARIA / OpenSOAR Project Structure

This document explains the organization of the ARIA backend and frontend codebase.

## Root Folders

| Folder | Purpose |
|--------|---------|
| `api/` | FastAPI application, routes, WebSocket manager |
| `core/` | Shared infrastructure: Elasticsearch, Redis, GeoIP, circuit breaker |
| `config/` | Pydantic settings, Sigma rules, Ansible inventory, SSH keys |
| `pipeline/` | Alert ingestion, mapping, enrichment, correlation, forwarding |
| `response/` | AI engine, investigation workflow, Ansible execution, archiving |
| `scripts/` | Operational and maintenance scripts (organized by purpose) |
| `tests/` | pytest unit and E2E tests |
| `frontend/` | Next.js 16 dashboard application |
| `docs/` | Architecture, API, feature, runbook, and technical documentation |
| `reports/` | Runtime QA and validation reports |
| `deploy/` | Deployment configs (systemd, logrotate) |
| `data/` | Runtime data: SQLite DB, playbooks, cursors, seen IDs, backups |
| `var/` | Runtime logs (created on demand) |
| `_archive/` | Archived logs and old files |

## Backend Package Roots

These directories are Python package roots and must not be moved:

- `api/`
- `core/`
- `config/`
- `pipeline/`
- `response/`

## API Routes

Routes are defined in `api/routes/*.py`. Private helpers live in `api/routes/_<domain>/` folders.

Key routes:
- `alerts.py`
- `incidents.py`
- `investigations.py`
- `runtime.py`
- `infrastructure.py`
- `assistant.py`
- `operator.py`
- `assets.py`
- `metrics.py` (performance)
- `aria_alerts.py`

## Response Workflow Modules

| Module | Purpose |
|--------|---------|
| `response/ai_engine/` | LLM clients, prompt building, response parsing |
| `response/runtime_ai_engine/` | Runtime-specific AI: diagnostics, remediation |
| `response/infrastructure_ai_engine/` | Infrastructure AI: resource analysis |
| `response/watcher/` | Incident watcher, AI runner, stuck recovery |
| `response/ansible_exec.py` | Ansible playbook execution |
| `response/fix_verifier.py` | Post-remediation verification |
| `response/db.py` | Async SQLite engine |
| `response/models.py` | SQLAlchemy ORM models |

## Frontend App Routes

Dashboard pages live in `frontend/app/(dashboard)/`.

Key pages:
- `/alerts`
- `/incidents`
- `/investigations`
- `/runtime/investigations`
- `/infrastructure/investigations`
- `/operator`
- `/assets`
- `/metrics`
- `/monitoring`
- `/search`
- `/ips`
- `/assistant`
- `/settings/*`

## Frontend Components

| Folder | Contents |
|--------|----------|
| `components/ui/` | shadcn/ui primitives |
| `components/layout/` | App sidebar, global command menu |
| `components/common/` | Shared: page header, badges, data table, skeletons |
| `components/common/badges/` | Severity, status, fix-status, whitelist badges |
| `components/alerts/` | Alert-specific panels |
| `components/investigations/` | Risk cards, attack narrative |
| `components/assets/` | Asset banners |
| `components/settings/` | Settings forms |
| `components/security/` | Admin secret dialogs |
| `components/dashboard/` | Dashboard-specific |
| `components/runtime/` | Runtime-specific |
| `components/infrastructure/` | Infrastructure-specific |
| `components/operator/` | Operator-specific |

## Scripts Organization

| Subfolder | Purpose |
|-----------|---------|
| `scripts/backfill/` | Historical data backfill scripts |
| `scripts/demo/` | Demo and seed scripts |
| `scripts/maintenance/` | Backup, restore, cleanup |
| `scripts/migration/` | Database migration scripts |
| `scripts/validation/` | API test scripts, QA watchdog |
| `scripts/vm-onboarding/` | VM bootstrap and monitoring setup |

## Runtime Data Policy

`data/` is listed in `.gitignore`. Do not commit:
- `data/investigations.db`
- `data/playbooks/`
- `data/cursors/`
- `data/seen_ids/`
- `data/backups/`
- `data/artifacts/`
- `data/evidence/`

## Logs Policy

- Production: use systemd journald (`journalctl -u opensoar-backend`)
- Development: `/var/log/aria/` or stdout
- Old logs: archive to `_archive/logs/YYYY-MM-DD/`

## What Not to Commit

- `.env` and any `.env.*` files
- `node_modules/`
- `.next/`
- `__pycache__/` and `*.pyc`
- `data/`
- `tree.txt` (generated)
- `config/keys/*` (SSH private keys)

## Validation Commands

```bash
# Backend compile check
PYTHONPYCACHEPREFIX=/tmp/opensoar-pycache python3 -m compileall api core response config pipeline scripts

# Backend import check
PYTHONPYCACHEPREFIX=/tmp/opensoar-pycache python3 -c "from api.app import app; print(len(app.routes))"

# Frontend build
cd frontend && pnpm build

# Shell script syntax check
find scripts -type f -name "*.sh" -exec bash -n {} \;

# Safe unit tests
PYTHONPYCACHEPREFIX=/tmp/opensoar-pycache pytest -q tests/test_severity.py tests/test_ip_extractor.py
```

## Clean Tree Generation

```bash
scripts/maintenance/generate_tree.sh
```

This generates `tree.txt` while excluding generated and runtime directories.
