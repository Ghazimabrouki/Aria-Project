# ARIA Deep Discovery Report

Audit date: 2026-06-22  
Mode: read-only discovery; no application, service, infrastructure, database, image, or Git state was changed.

## 1. Executive understanding

ARIA (Adaptive Response Intelligence Automation, historically called OpenSOAR in parts of the code and documentation) is a single-node, AI-assisted Security Orchestration, Automation and Response platform for a SOC. It collects already-indexed security and infrastructure telemetry from Elasticsearch, normalizes and enriches it, creates and correlates alerts/incidents, supports AI or rule-based investigation, proposes Ansible remediation, gates execution through approval and safety controls, verifies the result, and archives the case. Its intended users are SOC analysts, SOC administrators, and security operators. The business value is shorter detection-to-response time, a consistent audit trail, multi-server visibility, and controlled automation without requiring every response to be assembled manually.

Primary evidence: `Front_end + back_end/README.md`, `aria-report/chapters/03-aria-design.tex`, `aria-report/chapters/04-aria-realization.tex`, `Front_end + back_end/main.py`, and `Front_end + back_end/api/app.py`.

The current implementation is **local-first**. The old external OpenSOAR integration remains as disabled compatibility code (`OPENSOAR_ENABLED=false` by default), but the implemented normal path persists alerts and incidents directly in ARIA's SQLite database. Older diagrams that require an external OpenSOAR instance are historical and must not be treated as the current mandatory topology. Evidence: `Front_end + back_end/config/settings.py`, `Front_end + back_end/pipeline/sender.py`, `Front_end + back_end/pipeline/datausage/local_incident_manager.py`, and `Front_end + back_end/main.py`.

## 2. Confidence labels

- **Confirmed** means directly supported by current source or active configuration, with a path cited.
- **Probable** means supported by project reports or screenshots but not fully reproducible from current code/config alone.
- **Not found** means repository search found no implemented component, deployment definition, or runbook.

## 3. Repository map and audit coverage

### Top-level areas

| Area | Purpose and audit result |
|---|---|
| `Front_end + back_end/` | Current ARIA application: Python/FastAPI backend and workers, Next.js frontend, SQLite runtime data, configuration, tests, docs, operational scripts, and application Compose. This is the authoritative implementation. |
| `Aria_Tools_SetUp/` | Central monitoring-stack installers plus multiple monitored-VM bootstrap copies. Installs Elastic/Kibana/Filebeat, Wazuh Manager, Suricata, Falco/Falcosidekick, Telegraf, Kibana rules, UFW, Fail2Ban, and SSH hardening. |
| `Ansible+script--setup-the-VMS-via_Ansible/` | Ansible-driven monitored-VM bootstrap wrapper, inventory, and a newer bootstrap copy. Contains active-looking hard-coded infrastructure values and plaintext credentials. |
| `Docker-compose files/` | Duplicate of the application Compose definition. It does not deploy the monitoring/SIEM stack. |
| `aria-report/` | LaTeX PFE report, Mermaid sources, diagrams, screenshot inventory, and generated PDF/build artifacts. Chapters 2–5 are useful architectural evidence, but some prose lags current code. |
| `ARIA Screenshots/` | 112 timestamped UI screenshots (visual evidence). Binary pixels were not individually OCR-audited; filenames and report mappings were inspected. |
| `ghazi mabrouki ristutition/` | Historical presentations, diagrams, copies of earlier tool scripts, and ZIP/PPTX artifacts. Treated as historical corroboration, not authoritative deployment source. |

### Meaningful application packages

| Path | Responsibility |
|---|---|
| `Front_end + back_end/api/` | FastAPI application, 24 domain routers, CORS/rate limiting, WebSocket endpoints, and legacy approval HTML. |
| `Front_end + back_end/core/` | Elasticsearch and Redis clients, circuit breaker, GeoIP, whitelist, performance cache, and asset query scoping. |
| `Front_end + back_end/pipeline/` | Source polling, cursor/seen-ID state, mappers, enrichment, local alert/incident management, correlation, retry, performance monitoring, and optional upstream forwarding. |
| `Front_end + back_end/response/` | SQLAlchemy models, watcher, LLM clients, investigations, assistant/operator, Ansible execution, safety policy, staged remediation, verification, archive, search, audit, and heartbeats. |
| `Front_end + back_end/config/` | Pydantic settings, Sigma rules, Telegraf procstat config, Ansible inventory, and ignored SSH key material. |
| `Front_end + back_end/frontend/` | Next.js 16/React 19 dashboard, domain pages, UI components, API/auth clients, asset context, and WebSocket provider. |
| `Front_end + back_end/scripts/` | Backfill, demo, maintenance, migration, validation, and monitored-VM onboarding scripts. |
| `Front_end + back_end/deploy/`, `.systemd/` | Logrotate and runtime QA watchdog units. Main application service definition also exists as `opensoar-backend.service`. |
| `Front_end + back_end/tests/` | Unit, workflow, safety, API, and Playwright E2E coverage. Tests were read/inventoried but not executed, per read-only/no-runtime-change scope. |
| `Front_end + back_end/data/` | Live SQLite DB, generated playbooks/inventories, cursor/seen-ID state, artifacts, and backups. Structures and representative files were inspected; databases/backups were not mutated or exhaustively dumped. |

### Intentionally skipped or sampled

The following were identified first and then excluded from file-by-file content review because they are generated, dependency-heavy, binary, duplicated history, or runtime state:

- `Front_end + back_end/.venv/`, `frontend/node_modules/` if present: installed dependencies.
- `frontend/.next/` (large development build/cache), `frontend/test-results/` videos, `tsconfig.tsbuildinfo`: generated output.
- `.pytest_cache/`, `__pycache__/`, `*.pyc`: caches.
- `Front_end + back_end/.git/`: VCS objects; tracked-file status was queried read-only.
- `.agents/`, `.claude/`, `.claude-flow/`, `.swarm/`, `.codex/`: development-agent metadata unrelated to ARIA runtime.
- `_archive/`, `docs/archive/project-history/`: historical material was sampled where it explained onboarding or production gaps, but is not authoritative over current source.
- `data/backups/`, large SQLite copies, `data/seen_ids/*.json`, `var/`, logs, WAL/SHM files, generated playbooks: inventoried and sampled, not exhaustively read.
- PNG/JPG screenshots and diagram renders: filenames/mappings and selected metadata inspected; Mermaid sources and LaTeX descriptions were used for semantics.
- PDF/PPTX/XLSX/ZIP and LaTeX build products (`main.pdf`, `.aux`, `.log`, etc.): binary/generated; source `.tex`, `.mmd`, and Markdown were reviewed instead.

## 4. Users and major features

### Roles

- **super_admin**: global asset scope, account and asset administration, settings and protected actions (`response/auth.py`, `api/routes/accounts.py`).
- **server_user**: constrained to its assigned `asset_id` on routes that apply the scope dependency (`response/auth.py`, `api/routes/_shared.py`).
- **SOC analyst/operator**: workflow role described in UI/report; in code it maps to one of the two account roles rather than a separate RBAC role (`frontend/app/(dashboard)/`, `response/models.py`).

### Implemented functional areas

| Feature | Current implementation evidence |
|---|---|
| Dashboard and health | `api/routes/dashboard.py`, `api/routes/monitoring.py`, `frontend/app/(dashboard)/page.tsx` |
| Alerts and IOC evidence | `api/routes/alerts.py`, `pipeline/mappers/`, `pipeline/enrichment/`, `frontend/app/(dashboard)/alerts/page.tsx` |
| Incident correlation/lifecycle | `pipeline/services/correlator.py`, `pipeline/datausage/incident_manager.py`, `api/routes/incidents.py` |
| Security investigations | `response/watcher/`, `response/ai_engine/`, `api/routes/investigations.py` |
| Runtime/Falco investigations | `pipeline/mappers/falco_runtime.py`, `pipeline/datausage/runtime_orchestrator.py`, `response/runtime_ai_engine/`, `api/routes/runtime.py` |
| Infrastructure/performance | `pipeline/performance_poller.py`, `pipeline/datausage/performance_orchestrator.py`, `response/infrastructure_ai_engine/`, `api/routes/performance.py`, `api/routes/infrastructure.py` |
| AI assistant | `response/assistant.py`, `api/routes/assistant.py`, `frontend/app/(dashboard)/assistant/page.tsx` |
| AI operator | `api/routes/operator.py`, `response/ansible_exec.py`, `response/safety_policy.py`, `frontend/app/(dashboard)/operator/page.tsx` |
| Remediation/approval/rollback | `response/auto_approve.py`, `response/playbook_safety.py`, `response/remediation_planner.py`, `response/ansible_exec.py`, `api/routes/investigations.py` |
| Verification/archive/reporting | `response/fix_verifier.py`, `response/archiver.py`, `api/routes/archives.py`, `api/routes/reports.py` |
| Asset registry and multi-server scope | `response/models.py:MonitoredAsset`, `core/asset_scope.py`, `api/routes/assets.py`, `frontend/lib/asset-context.tsx` |
| Accounts/JWT | `response/auth.py`, `api/routes/auth.py`, `api/routes/accounts.py`, `frontend/lib/auth-context.tsx` |
| Search, IPS map, whitelist | `response/search_fts.py`, `api/routes/search.py`, `api/routes/ips.py`, `core/whitelist.py`, `api/routes/whitelist.py` |
| Runtime settings reload | `api/routes/settings.py`, Redis channel `aria:settings:reload` in `main.py` |

## 5. Backend and worker logic

`api/app.py` creates the FastAPI service, initializes SQLite on lifespan startup, installs configured CORS and an in-memory IP rate limiter, then mounts the domain routers and WebSockets. The API runs on container/internal port 8001.

The separate worker container runs `main.py` with `SKIP_RESPONSE_API=1`. It initializes the same database and starts independently supervised async loops:

1. Elasticsearch alert forwarder plus heartbeat.
2. Local incident correlation.
3. Incident watcher and AI investigation.
4. Ticket auto-transitions.
5. Retry queue when upstream forwarding is enabled.
6. Daily SQLite backup loop.
7. Persistent fix-verification jobs.
8. Recovery of stuck runtime diagnostics.
9. Redis settings-reload subscriber.
10. Optional performance monitoring and performance watcher.
11. Process watchdog/worker heartbeats.

Evidence: `Front_end + back_end/main.py`. Individual loops are wrapped in `_run_safe_task`, which catches crashes and restarts long-running tasks.

### Source ingestion and data flow

Confirmed implemented path:

```text
Monitored/central Linux host
  ├─ Wazuh Agent -> Wazuh Manager -> Filebeat -> wazuh-alerts-*
  ├─ system/auth logs + Suricata EVE -> Filebeat -> filebeat-<asset>-*
  ├─ Falco -> local Falcosidekick :2801 -> falco-<asset>-*
  └─ Telegraf ---------------------------------> telegraf-<asset>-*
                                      HTTPS :9200
                                             |
                                             v
                                    Elasticsearch 7.17.13
                                             |
                     cursor polling / per-source mapping
                                             v
       normalize -> whitelist/noise -> GeoIP/MITRE/Sigma -> deduplicate
                                             |
                                             v
                                SQLite Alert + correlation
                                             |
                                             v
                         Incident -> Investigation watcher
                                             |
                           LLM provider or rule fallback
                                             |
                         proposed staged Ansible playbook
                                             |
                safety policy -> human/auto approval -> SSH execution
                                             |
                         ES re-query verification -> archive
                                             |
                         FastAPI REST/WebSocket :8001
                                             |
                             Next.js dashboard :3000/:3001
```

Mappers are source-specific (`pipeline/mappers/wazuh.py`, `suricata.py`, `filebeat.py`, `falco.py`, `falco_runtime.py`, `generic.py`). Cursors and seen IDs have Redis plus file-backed state under `data/cursors/` and `data/seen_ids/` (`pipeline/poller/cursor_manager.py`, `pipeline/poller/seen_ids.py`). Alerts are persisted locally and correlated by time/entity dimensions (`pipeline/datausage/local_incident_manager.py`, `pipeline/services/correlator.py`).

Kafka is **not in this flow**. `response/assistant.py` explicitly tells users ARIA does not monitor Kafka, Fluent Bit, ETL, enricher, or separate correlation engines. Repository search found no Kafka broker, topic, producer, consumer, or Compose service. “ETL” in ARIA is the in-process poll/map/enrich/correlate Python pipeline.

Neo4j is **not implemented as an active dependency**. Only disabled settings (`neo4j_enabled=false`, URI/user/password) exist in `config/settings.py`; no driver or graph persistence path was found.

## 6. API and authentication overview

Routers include authentication/accounts, alerts, incidents, investigations, archives/reports, assets, assistant/operator, runtime/infrastructure/performance, dashboard/monitoring/pipeline, IPS/search/whitelist, settings, adaptive logic, internal ARIA alerts, approval UI, and WebSockets (`api/app.py`, `api/routes/*.py`). OpenAPI is available at `/docs`; health is `/health` and `/api/v1/health`.

Authentication uses bcrypt password hashes, 24-hour HS256 JWT bearer tokens, and database-backed account state (`response/auth.py`, `api/routes/auth.py`). The frontend stores the bearer token in browser `localStorage` and uses `/api/v1/auth/me` to restore the session (`frontend/lib/auth-context.tsx`). Roles are `super_admin` and `server_user`; the latter should be locked to its assigned asset.

Dangerous legacy/settings actions may accept either a super-admin JWT or `X-ARIA-Admin-Secret`; several asset routes still use their own admin-secret-only helper (`api/routes/_shared.py`, `api/routes/assets.py`). The API client can add the admin secret (`frontend/lib/admin-secret.ts`, `frontend/lib/api.ts`).

**Important confirmed weakness:** enforcement is inconsistent. Many list/summary routes require `require_auth` and call `enforce_asset_scope`, while a number of detail, action, WebSocket, approval UI, and monitoring routes lack an equivalent dependency. The JWT secret is a hard-coded string in `response/auth.py`, not an environment variable. Therefore the report's historical statement that there is “no full public authentication layer” remains directionally correct despite the newer JWT work. Public exposure is unsafe without a route-by-route authorization review.

## 7. Data model

The async SQLAlchemy/SQLite database defaults to `data/investigations.db` (`response/db.py`, `config/settings.py`). Current ORM tables in `response/models.py` are:

- `investigations`, `investigation_audit_events`, `investigation_alerts`
- `playbook_approvals`, `playbook_runs`, `fix_verifications`, `fix_verification_jobs`
- `archives`, `aria_alerts`
- `alerts`, `incidents`, `alert_incident_links`
- `assistant_conversations`, `assistant_messages`
- `operator_runs`, `operator_sessions`, `operator_messages`
- `whitelist_entries`, `worker_heartbeats`
- `aria_accounts`, `monitored_assets`

SQLite is ARIA's operational source of truth. Elasticsearch is the evidence/telemetry source. Redis is ephemeral/operational state. Generated playbooks and inventories are written under `data/playbooks/`; cursors, seen IDs, artifacts, evidence, and backups use adjacent `data/` paths (`config/settings.py`, `response/ansible_exec.py`). A separate ticket SQLite artifact exists at `data/artifacts/tickets.db` (`pipeline/datausage/ticketing/store.py`).

No Alembic directory or declarative migration chain was found. `response/db.py` initializes tables and contains compatibility schema handling; one-off scripts exist under `scripts/migration/` and `scripts/backfill/`. This makes schema evolution an operational risk.

## 8. Frontend

The dashboard is Next.js 16.2, React 19, TypeScript 5.7, Tailwind 4, shadcn/Radix UI, SWR, Recharts, MapLibre/react-simple-maps, and WebSockets (`frontend/package.json`). Major routes are dashboard, alerts, incidents, investigations, runtime investigations, infrastructure investigations, IPS, metrics, assistant, operator, search, whitelist, archives, and settings subpages (`frontend/app/`).

The frontend talks directly to `NEXT_PUBLIC_API_URL` (default `http://127.0.0.1:8001`) and `NEXT_PUBLIC_WS_URL` compiled at image build time (`frontend/Dockerfile`, `frontend/lib/api.ts`, `frontend/lib/websocket.tsx`). The application Compose does not pass these build args or runtime public URLs, so the published frontend image must have been built with the correct browser-reachable API address. This is a deployment coupling, especially for remote browsers where `localhost` means the analyst workstation.

## 9. Integrations and dependencies

| Dependency | Status | Role/evidence |
|---|---|---|
| Elasticsearch 7.17.13 | Required external/native central service | Alert/metric source and post-fix verification; `Aria_Tools_SetUp/tools/siem_setup.sh`, `core/elasticsearch.py`. |
| Kibana | Operational tool, not API dependency | Analyst raw search and detection/saved objects; `siem_setup.sh`, `detection_rules_setup.sh`. |
| Wazuh Manager/Agents 4.5.4-1 | Source | Host security, enrollment 1515, events 1514; `wazuh_setup.sh`, monitored bootstrap. |
| Filebeat | Source forwarder | Wazuh, system/auth, Suricata EVE forwarding; `siem_setup.sh`, bootstrap. |
| Suricata | Source | Network IDS; `suricata_setup.sh`, bootstrap. |
| Falco + Falcosidekick | Source | Runtime detection and ES forwarding; `setup-falco-server-elastic.sh`, bootstrap. |
| Telegraf | Source | Host/process/network metrics to ES; `telegraf_setup.sh`, bootstrap. |
| Redis 7 | Required application service | Cache, cursors, pub/sub, retry/baselines; application Compose and `core/redis.py`. |
| SQLite | Required embedded storage | ARIA workflow and tickets; `response/db.py`. |
| Ansible + SSH/sshpass | Optional action dependency | Approved remote diagnostics/remediation; `Dockerfile.backend`, `response/ansible_exec.py`. |
| LLM providers | Optional | NVIDIA, Ollama, OpenAI, Anthropic, Google, OpenRouter with fallback; `response/ai_engine/llm_clients.py`. |
| Slack/SMTP | Optional | Notifications; `response/notification.py`, settings. |
| Kafka | Not found/explicitly unsupported | No broker/topics/clients; `response/assistant.py`. |
| Neo4j | Placeholder only | Disabled config fields, no active driver/integration; `config/settings.py`. |
| Prometheus/OTel/Metricbeat | Removed legacy tooling | Compatibility setup explicitly removes/replaces these with Telegraf; `Aria_Tools_SetUp/tools/setup_script.sh`, `telegraf_setup.sh`. |

## 10. Confirmed facts, probable statements, and unknowns

### Confirmed

- Current application deployment is four Compose services: `redis`, `api`, `worker`, `frontend` (`Front_end + back_end/docker-compose.yml`).
- Central security tools are installed as native systemd services by destructive provisioning scripts, not by that Compose file (`Aria_Tools_SetUp/tools/*.sh`).
- The observed project central VM was Huawei ECS `ecs-ghazi`, Ubuntu 24, 64 vCPU/128 GB (`aria-report/chapters/02-cloud-and-monitoring.tex`). This is evidence of the tested host, not a minimum requirement.
- Multi-server identity is stored in `MonitoredAsset.source_config_json`; per-asset Ansible settings are stored in `ansible_config_json` with secret references (`response/models.py`, `api/routes/assets.py`).
- New assets default to `remediation_enabled=false` in the bootstrap payload.

### Probable but not fully verified

- “Brain VM” means the single central ECS that hosts Elasticsearch/Kibana/Wazuh Manager, central collectors, Redis, ARIA API/worker/frontend, SQLite, and Ansible controller. The repository does not use “Brain VM” as a formal config role; it uses “central host/server”.
- The current Docker Hub images contain code matching this checkout. Compose pins mutable `*-latest` tags and contains no digest, so parity cannot be proven offline.
- Screenshots and validation chapters show a working deployed environment, but this audit did not contact it or rerun tests.

### Not found / unverifiable

- Formal minimum/recommended VM sizing, disk IOPS/capacity, retention sizing, or tested scale limits.
- Infrastructure-as-code for VPC, subnet, EIP, security groups, DNS, ECS, or storage.
- A complete production reverse proxy/TLS/DNS configuration for ARIA itself.
- Automated central-stack uninstallation, disaster recovery, Elasticsearch snapshots, or full restore drill.
- `delete_set_up.sh`, although bootstrap failure messages reference it.
- Kafka or an active Neo4j deployment.

## Ready for Next Work

ARIA is understood as a single-central-node SOAR platform over an Elasticsearch-based monitoring foundation, with asset-specific telemetry, local workflow persistence, optional AI, and approval-gated Ansible response. The safest next work that does not change the finished application is: reconcile the canonical onboarding script, produce a secrets-rotation plan, build a route authorization matrix, create a cloud/firewall worksheet, document backup/restore and decommission procedures, and pin an immutable deployment bill of materials.
