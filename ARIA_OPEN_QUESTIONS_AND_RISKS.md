# ARIA Open Questions and Risks

Audit date: 2026-06-22. This register separates repository-confirmed facts, probable interpretations, and items not found.

## 1. Priority risk register

| Priority | Status | Risk/gap | Evidence and impact |
|---|---|---|---|
| P0 | Confirmed | Plaintext and historical secrets exist in repository material. | Root password and ES password in `Ansible+script--setup-the-VMS-via_Ansible/{inventory.ini,playbook.yml}`; tracked `.env.backup.*`; live ignored `.env`; private-key-looking files in `config/keys/`. Assume compromise until rotated. |
| P0 | Confirmed | JWT signing secret is hard-coded and globally predictable. | `Front_end + back_end/response/auth.py`. Anyone with source can forge super-admin tokens if the deployment uses it unchanged. |
| P0 | Confirmed | Authentication/authorization is not consistently applied route-by-route. | Several list routes use `require_auth`/asset scope, while detail/action/WebSocket/approval routes do not consistently do so across `api/routes/*.py` and `api/websocket.py`. Risk: unauthenticated reads/actions and cross-asset access. |
| P0 | Confirmed | Central/monitored setup scripts are destructive and not idempotently safe for an existing production host. | `siem_setup.sh` can purge Elastic/Kibana/Filebeat; `telegraf_setup.sh` removes old stacks; Ansible wrapper kills apt/dpkg and removes locks; hardening can change SSH/UFW. Never run as a routine update. |
| P1 | Confirmed | Multiple onboarding scripts have diverged; no canonical source is declared. | Primary app/Aria_Tools copies hash alike; Ansible copy differs and is newer; V1/V2/test copies also exist. Results can differ by entry point. |
| P1 | Confirmed | Generated Wazuh asset attribution appears wrong in a primary bootstrap copy. | `scripts/vm-onboarding/bootstrap_monitored_vm.sh` constructs Wazuh `host_name`/`agent_name` from `VM_ENVIRONMENT`, not `VM_NAME`. This can mix assets or make validation misleading. |
| P1 | Confirmed | No complete decommission automation/runbook; referenced cleanup file is missing. | Bootstrap references `delete_set_up.sh`; repository search found none. Asset DELETE only removes SQLite registry state (`api/routes/assets.py`). Agents, enrollment, indices, credentials, and SSH remain. |
| P1 | Confirmed | Brain VM is a broad single point of failure. | Single-node Elasticsearch, SQLite, local Redis volume, local backups, application containers, Wazuh Manager and all central tools share one ECS (`aria-report/chapters/02-cloud-and-monitoring.tex`). |
| P1 | Confirmed | TLS verification is frequently disabled or defaults to insecure. | `siem_setup.sh`, Falcosidekick configs, bootstrap `TLS_MODE=insecure`, Curl `-k`, `elasticsearch.ssl.verificationMode: none`. Enables MITM/endpoint spoofing. |
| P1 | Confirmed | Compose exposes sensitive services and uses weak deployment coupling. | Redis maps host 6380; API 8001 is plain HTTP; mutable `latest` tags; `.env` bind-mounted; frontend public URLs are build-time (`docker-compose.yml`, Dockerfiles). |
| P1 | Confirmed | SSH host-key verification is disabled. | `config/ansible_inventory`, `Ansible.../ansible.cfg`; risk of SSH MITM. |
| P1 | Confirmed | Schema management lacks a formal migration chain. | No Alembic; `response/db.py` startup compatibility logic and one-off scripts. Recovery/upgrade behavior is hard to predict. |
| P1 | Confirmed | Backup coverage is incomplete and local-only. | SQLite worker copies and scripts exist; no ES snapshots/off-host restore/RPO/RTO. A host/disk failure can lose telemetry and operational history. |
| P2 | Confirmed | Documentation conflicts with current code. | Older docs show external OpenSOAR as mandatory and no auth; current code is local-first and has partial JWT. README/report port 3000 differs from Compose host 3001. |
| P2 | Confirmed | `.env.example` does not represent current settings. | Current settings/live variable-name inventory includes multi-server, safety, performance, backup, per-asset secrets, etc. absent from example. Deployment can silently take unsafe defaults. |
| P2 | Confirmed | No immutable bill of materials. | Elastic/Wazuh versions are pinned in scripts, but Falcosidekick queries latest GitHub release, pnpm prepares latest, and application images use `latest`. Reproducibility and rollback are weak. |
| P2 | Confirmed | Rate limiting is process-local and disabled in Compose. | In-memory middleware in `api/app.py`; Compose sets `RATE_LIMIT_ENABLED=false`. It does not protect multi-worker/restart scenarios. |
| P2 | Confirmed | Frontend stores bearer JWT in localStorage. | `frontend/lib/auth-context.tsx`; an XSS vulnerability can steal it. No HttpOnly cookie/CSRF design. |
| P2 | Confirmed | Worker/API readiness and observability are incomplete. | Worker `depends_on` lacks health condition; only Redis health is defined; no API/frontend/worker Compose healthchecks; no Prometheus/central alert manager. |
| P2 | Confirmed | High-privilege/shared credentials are used for telemetry forwarding. | Bootstrap and setup commonly use the `elastic` superuser. Per-agent least-privilege ingest roles/API keys are not implemented. |

## 2. Important unanswered questions

### Ownership and production truth

1. Which bootstrap script is canonical: application, Aria_Tools, or Ansible copy?
2. Are Docker Hub `ghaziiii/aria_project:*latest` images built from this exact embedded Git commit? Where is the build pipeline?
3. Is the active production topology still the single ECS/public IP shown in report/inventories, or have addresses changed?
4. Which documents are normative: current code, README, PFE report, or operational scripts?
5. Who owns Elastic/Wazuh, ARIA application, cloud networking, and incident-response approvals?

### Security

6. Have every credential found in inventory, playbook, `.env` backups, keys, and scripts been rotated?
7. What is the intended public/authentication boundary: VPN only, reverse proxy, SSO, or direct ports?
8. Which API endpoints must be analyst, server-user, super-admin, or internal-worker only?
9. Should admin-secret compatibility remain, or should JWT/role authorization replace it?
10. What secret manager should hold per-asset SSH/become credentials and LLM/ES keys?
11. Is `elastic` deliberately used for all shippers, or can scoped ingest/API credentials be issued?
12. What certificate lifecycle, CA distribution, renewal, and revocation process is intended?

### Capacity and resilience

13. What event rate, asset count, retention, and concurrent analyst/remediation load must be supported?
14. What are minimum/recommended CPU, RAM, disk capacity/IOPS, and network requirements? The 64-vCPU/128-GB host is only observed evidence.
15. What RPO/RTO applies to Elasticsearch, SQLite, Redis, Wazuh config, Kibana objects, and generated evidence?
16. Is single-node availability acceptable? If not, what target HA topology is required?
17. What ES index lifecycle/retention policy prevents disk exhaustion?

### Onboarding and lifecycle

18. Is direct monitored-host write access to Elasticsearch acceptable, or should an ingest gateway/API be used?
19. How should Wazuh agent names/IDs map to ARIA assets, especially given the bootstrap payload defect?
20. What is the supported OS/version matrix beyond tested Ubuntu/Debian assumptions?
21. What is the approved decommission sequence and evidence-retention policy?
22. Should host tools be completely removed on decommission or only disabled/revoked?

### Application operations

23. How is the first production super-admin created and recovered if credentials are lost?
24. What is the intended database migration/release procedure?
25. Which settings are safe to reload at runtime and which require API/worker restart?
26. Are AI-generated playbooks allowed in production, and for which asset/risk classes?
27. Which current tests/validation reports correspond to the exact deployed build?

## 3. Missing or broken resources

### Confirmed absent

- `delete_set_up.sh` referenced by the monitored bootstrap.
- Cloud IaC (Terraform/OpenTofu/CloudFormation/Huawei templates) for VPC/ECS/EIP/security groups.
- Production reverse-proxy, DNS, TLS termination, SSO, or WAF configuration for ARIA.
- Kafka broker/topics/clients; ARIA explicitly says it does not monitor Kafka (`response/assistant.py`).
- Active Neo4j implementation; only disabled settings exist (`config/settings.py`).
- Formal ES ILM/snapshot/restore definitions.
- Formal schema migration tool/history.
- Full-stack disaster recovery and decommission runbooks.
- Application CI/CD or image provenance definitions in the audited current tree.
- Compose health checks for API, worker, and frontend.
- Minimum hardware/capacity specification.

### Broken/conflicting references

- `docs/architecture/CONSOLIDATED_ARCHITECTURE.md` references old paths such as monolithic `pipeline/poller.py`/`response/watcher.py` and mandatory external OpenSOAR.
- `docs/PROJECT_STRUCTURE.md` mentions `api/routes/metrics.py`; current performance API is `api/routes/performance.py` with `/api/v1/metrics` behavior.
- README and report often describe frontend port 3000; application Compose publishes host 3001.
- Report prose says Falco/Falcosidekick are partly Docker-based in one section, while current central installer uses native packages/systemd (`setup-falco-server-elastic.sh`).
- Production rollout prose mentions migrations/systemd for application deployment, while current Compose initializes tables at app startup and no migration chain exists.

## 4. Confirmed architecture facts

- ARIA's current direct data path is Elasticsearch -> in-process Python poll/map/enrich/dedup -> SQLite alert/incident -> watcher/AI -> approval -> Ansible -> ES verification -> archive -> FastAPI/Next.js.
- Redis holds operational state, not the primary case record.
- Kafka is not used. “ETL/enrichment/correlation” are Python modules inside the worker.
- Neo4j is disabled/unimplemented.
- The Brain VM is a central single-node platform plus monitoring foundation; monitored VMs are producers and optional Ansible targets.
- Application Compose does not deploy Elasticsearch/Kibana/Wazuh/Falco/Suricata/Filebeat/Telegraf.
- New monitored assets are registered in SQLite and default to remediation off.
- Tool and application deployment are separate procedures with no single end-to-end declarative orchestrator.

## 5. Probable but unconfirmed

- “Brain VM” and “central ECS” are the same role.
- The central tools and ARIA containers coexist on the same VM in the active environment.
- The screenshots/validation report reflect a functioning deployment close to this source revision.
- The large ECS was chosen for co-location convenience rather than measured minimum capacity.
- External OpenSOAR can be completely retired, but compatibility code and docs remain.

## 6. Not found in repository

- Evidence that current production secrets were rotated after being committed/copied.
- Evidence of tested off-host restore or whole-VM recovery.
- Formal threat model, data classification, compliance, retention, or audit-log immutability policy.
- Load/performance test results defining supported scale.
- Separate tool VM design.
- Kubernetes deployment.
- Message broker architecture.

## 7. Recommended next work, ordered by priority

These are recommendations only; none were implemented during this audit.

1. **Emergency credential inventory and rotation plan:** treat repository-exposed ES/root/admin/SSH/JWT material as compromised; preserve evidence, rotate, then remove from history under an approved security change.
2. **Route authorization matrix and threat model:** enumerate every REST/WS route, required role, asset-scope behavior, and admin-secret compatibility; test unauthenticated/cross-asset access.
3. **Canonical onboarding decision:** select one script, diff variants, correct identity payload, version it, and archive/label historical copies.
4. **Production boundary design:** VPN/reverse proxy/TLS/SSO, no public ES/Redis/API, least-privilege security groups and shipper credentials.
5. **Immutable release manifest:** pin image digests, Falcosidekick/pnpm/dependency versions, source commit, database schema version, and rollback artifact.
6. **Backup/restore design and drill:** ES snapshots, SQLite consistent backup, Redis/config/Kibana/Wazuh state, off-host encryption, RPO/RTO, documented restore test.
7. **Safe onboarding/decommission runbooks:** preflight, approval, validation, rollback, agent enrollment removal, index retention, credential revocation, and asset deletion.
8. **Cloud deployment worksheet/IaC plan:** VM roles, sizing based on load, subnet/routing/DNS/NTP, disks, security groups, repositories, and monitoring.
9. **Formal schema migration strategy:** versioned migrations, backup gate, forward/backward compatibility, and release ordering.
10. **Operational observability:** healthchecks for every container/service, centralized structured logs, alerting on worker heartbeat/ES disk/index lag/backup failure/cert expiry.
11. **Documentation reconciliation:** mark historical OpenSOAR diagrams, correct ports/native-vs-Docker Falco, generate settings/API references from current source.
12. **Capacity and failure testing:** ingestion backlog, ES outage, Redis loss, worker restart, SQLite lock/corruption, LLM timeout, Ansible partial failure, and multi-asset isolation.

## 8. Areas future work must avoid breaking

- Asset scoping across SQLite and Elasticsearch (`core/asset_scope.py`, route dependencies).
- Cursor and dedup persistence (`pipeline/poller/`, Redis/file fallbacks).
- Investigation state machine, audit events, staged remediation, and rollback (`response/models.py`, `response/ansible_exec.py`, `response/safety_policy.py`).
- API/worker process separation and settings reload channel (`main.py`, Compose).
- Per-asset secret references and the safe default `remediation_enabled=false`.
- Existing runtime/infrastructure distinction and backend-provided available actions.
- Evidence/archive integrity and post-fix verification.

## Ready for Next Work

The application logic and deployment boundary are sufficiently mapped for non-invasive follow-up. The safest immediate activities are documentation/security design work: secret-rotation planning, route authorization review, canonical onboarding reconciliation, cloud/firewall design, immutable release inventory, and recovery/decommission runbooks. Any execution of setup scripts, migrations, Compose, or remediation must wait for an explicit change request and reviewed rollback plan.
