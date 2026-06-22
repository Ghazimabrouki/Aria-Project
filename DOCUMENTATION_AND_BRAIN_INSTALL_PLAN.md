# ARIA Documentation and Brain VM Installation Plan

Status: proposal only; no installer or documentation implementation is authorized by this file.  
Prepared: 2026-06-22  
Scope: GitHub documentation and one Brain VM orchestration wrapper only.

## Evidence and scope

This plan reconciles the following repository evidence:

- `ARIA_DISCOVERY_REPORT.md`
- `ARIA_ARCHITECTURE_AND_OPERATIONS_MAP.md`
- `ARIA_OPEN_QUESTIONS_AND_RISKS.md`
- `Front_end + back_end/README.md`
- `Front_end + back_end/docker-compose.yml`
- `Docker-compose files/docker-compose.yml`
- `Aria_Tools_SetUp/tools/`
- `Ansible+script--setup-the-VMS-via_Ansible/`
- `Front_end + back_end/scripts/vm-onboarding/`
- `aria-report/`
- Public GitHub snapshot `Ghazimabrouki/Aria-Project`, branch `main`, commit `305e41e370fbe30764ec824d0ec92a2a318b3b58`, inspected read-only.

The public GitHub snapshot maps the local folders as follows:

| Local evidence path | GitHub path |
|---|---|
| `Front_end + back_end/` | `aria-application/` |
| `Aria_Tools_SetUp/` | `aria-tools-setup/` |
| `Ansible+script--setup-the-VMS-via_Ansible/` | `ansible-vm-setup/` |
| `Docker-compose files/` | `docker-compose/` |
| `aria-report/` | `aria-report/` |

The application files shared by the local application and GitHub `aria-application/` have matching Git blob hashes. The plan therefore treats the audited local application source as representative of the GitHub snapshot. No statement below authorizes changing that source.

## 1. Current documentation assessment

### What is explained well

- `Front_end + back_end/README.md` explains ARIA's SOC/SOAR purpose, intended workflow, technology stack, major features, application packages, Compose services, ports, and application access URLs.
- The GitHub root `README.md` gives a useful consolidated repository map and distinguishes the application, Brain VM tools, Ansible onboarding, Compose deployment, and final report.
- `aria-report/chapters/02-cloud-and-monitoring.tex` documents the demonstrated central monitoring foundation, service order, ports, system services, and Huawei Cloud evidence.
- `aria-report/chapters/03-aria-design.tex` and `04-aria-realization.tex` describe application modules and workflows in substantial detail.
- `aria-report/chapters/05-onboarding-and-production.tex`, the monitored-VM bootstrap scripts, and the asset API collectively explain the intended monitored-server flow.
- `Front_end + back_end/docs/` contains useful feature, API, validation, and troubleshooting detail for maintainers.

### Problems requiring documentation reconciliation

- Current and historical material are mixed. Older documents still present external OpenSOAR as mandatory or reference old monolithic paths; current source is local-first with the upstream integration disabled by default.
- `Front_end + back_end/README.md` includes environment-specific IP examples and exposes more configuration detail than a root overview should.
- The GitHub root README says no Python requirements file exists even though `aria-application/requirements.txt` is present.
- The GitHub high-level diagram routes Elasticsearch polling through the API; `main.py` confirms that the worker performs polling.
- Port descriptions alternate between frontend container port `3000` and Compose host port `3001` without always identifying the boundary.
- Some report prose describes Falco/Falcosidekick as Docker-based; the maintained central setup uses native packages and systemd.
- The report is final-year evidence and contains valuable diagrams, but it is not a versioned production operations contract.
- The two Compose files are byte-identical today, but having two copies creates an avoidable future source-of-truth conflict.
- Monitored-VM bootstrap copies differ, and no repository declaration identifies one canonical onboarding version.
- The existing documentation does not provide one safe, exact empty-Brain-to-running-ARIA sequence.
- Backup, recovery, decommission, certificate lifecycle, capacity minimums, and production authentication boundaries are incomplete. Unknown details must be written as `Not confirmed from repository`.
- Current public GitHub Ansible examples contain sensitive values. Documentation must discuss only secret categories and references, never reproduce values.

### Authority matrix

Only the required assessment labels are used in this table.

| Area | Status | Source and interpretation |
|---|---|---|
| ARIA application behavior | Current authoritative source | `Front_end + back_end/api/`, `core/`, `pipeline/`, `response/`, `config/settings.py`, `main.py`, and `frontend/`. Source code overrides historical prose where they conflict. |
| Application feature overview | Useful but incomplete | `Front_end + back_end/README.md` and `docs/features/`; useful orientation, but not authoritative for every current path, default, security boundary, or deployment condition. |
| Docker Compose deployment | Current authoritative source | `Front_end + back_end/docker-compose.yml` locally and `aria-application/docker-compose.yml` on GitHub. The separate `Docker-compose files/docker-compose.yml`/`docker-compose/docker-compose.yml` is identical but should not become a second authority. |
| Central Brain VM orchestration | Current authoritative source | `Aria_Tools_SetUp/tools/setup_script_telegraf.sh`; it is the maintained all-components runner. |
| Central Brain VM compatibility entry point | Useful but incomplete | `Aria_Tools_SetUp/tools/setup_script.sh`; it contains no installation logic and only `exec`s the maintained runner. |
| Individual central tool behavior | Current authoritative source | `siem_setup.sh`, `suricata_setup.sh`, `wazuh_setup.sh`, `setup-falco-server-elastic.sh`, `telegraf_setup.sh`, `detection_rules_setup.sh`, and `hardening_setup.sh`. These define actual package, config, service, and destructive behavior. |
| Monitored VM standalone onboarding | Not confirmed | The application/tools primary copies are identical, but the Ansible copy differs and is newer. No canonical designation exists. Documentation must expose this ambiguity until separately resolved; the Brain installer must not call any monitored-VM bootstrap. |
| Ansible onboarding automation | Current authoritative source | `Ansible+script--setup-the-VMS-via_Ansible/playbook.yml` plus its colocated bootstrap define current Ansible behavior. Inventory and credential values are not safe documentation examples. |
| Older onboarding variants (`V 1`, `V 2`, test VM, `monitored-Vms.sh`) | Historical/reference only | These show project evolution and must not be presented as current installation entry points. |
| Current application architecture diagrams | Useful but incomplete | `aria-report/diagrams/mermaid/` diagrams that agree with current source can be reused after source cross-checking. They do not override code. |
| Restitution diagrams, rendered legacy diagrams, screenshots | Historical/reference only | Useful evidence and presentation material; dates and environment-specific topology prevent them from being a live operations contract. |
| Consolidated/older architecture documents requiring external OpenSOAR or old paths | Conflicting or outdated | Examples include `docs/architecture/CONSOLIDATED_ARCHITECTURE.md` and historical technical reports. |
| Final-year report | Historical/reference only | `aria-report/main.tex`, chapters, appendices, diagrams, and `main.pdf` are academic evidence of the demonstrated system. |
| Minimum production sizing, HA, complete backup/restore, SSO, certificate renewal, and disaster recovery | Not confirmed | The repository documents a demonstrated single ECS and partial backup behavior, not complete production requirements or procedures. |

## 2. Exact GitHub documentation changes proposed

The following seven documentation files are justified. They separate overview, architecture, installation, onboarding, validation, security, and known operational limitations without changing application behavior. The three discovery reports remain evidence inputs; they should not be copied verbatim into user-facing documentation because they include audit detail and local workspace paths.

| Proposed file | Purpose | Evidence source | What it must contain | What it must NOT claim |
|---|---|---|---|---|
| `README.md` (update GitHub root; create corresponding root source in this workspace only after approval) | Concise repository entry point. | Current source, Compose, maintained central runner, discovery reports, verified report diagrams. | ARIA purpose/users, real worker-driven flow, role boundaries, repository map, deployment order, links, destructive-script warning, confirmed limitations. | No live secrets/IPs; no Kafka, active Neo4j, Kubernetes, IaC, HA, complete TLS/SSO/backup, or unsupported feature claims. |
| `docs/architecture/ARIA_ARCHITECTURE.md` | One current architecture contract for component placement and data flow. | `main.py`, `api/app.py`, `config/settings.py`, `response/models.py`, `core/asset_scope.py`, Compose, central scripts, current Mermaid sources. | Brain VM, monitored VM, native tools, containers, external LLM option, Elasticsearch/Redis/SQLite responsibilities, ports and flow, current single-node boundary. | Must not treat the report or old OpenSOAR diagrams as authority; must not add tool VMs, brokers, HA, or active Neo4j. |
| `docs/deployment/BRAIN_VM_SETUP.md` | Exact preconditions and approved central installation order, including the proposed wrapper. | `setup_script_telegraf.sh`, all invoked component scripts, Compose, `.env.example`, discovery operations map. | Root/systemd/apt assumptions, destructive warning, explicit confirmation, maintained runner path, expected services, Compose location, `.env` prerequisite, wrapper sequence, safe checks, known omissions. | Must not promise idempotence, cloud provisioning, secret generation, automated recovery, or safe reuse on an existing production host. |
| `docs/deployment/MONITORED_VM_ONBOARDING.md` | Keep monitored-server work separate from Brain installation. | All bootstrap variants, Ansible playbook, `api/routes/assets.py`, report chapter 5. | Roles, required connectivity, standalone versus Ansible paths, current canonical ambiguity, generated asset payload, validation, remediation-off default, decommission limitation. | Must not choose or modify a canonical bootstrap in this scope; must not imply the Brain installer onboards assets, runs Ansible, or enables remediation. |
| `docs/operations/VALIDATION_AND_TROUBLESHOOTING.md` | Safe post-install checks and failure entry points. | systemd calls/log paths in component scripts, Compose, `/health`, worker/container definitions, report validation chapter. | Mandatory service/container checks, Falco service-name variants, API/Redis/frontend checks, credential-required ES/Kibana checks, journald/log paths, failure interpretation. | Must not embed credentials, run remediation, mutate indices, restart services automatically, or claim tests were run when they were not. |
| `docs/operations/SECURITY_AND_SECRETS.md` | Define safe handling boundary for existing configuration. | `.env.example`, `config/settings.py`, Compose mounts, Ansible files, setup scripts, discovery risk report. | Secret categories, never-commit rules, `.env` prerequisite, secure prompting, Ansible inventory sanitization warning, TLS/SSH limitations, public exposure warning. | Must not reproduce values, recommend committing `.env`, claim a secret manager exists, or claim TLS/SSO/RBAC is production-complete. |
| `docs/operations/BACKUP_AND_DECOMMISSION_LIMITATIONS.md` | State exactly what exists and what does not, without inventing a runbook. | `main.py` backup loop, `scripts/maintenance/backup_db.sh`, `restore_db.sh`, Redis volume, asset DELETE route, missing `delete_set_up.sh`, discovery reports. | Confirmed SQLite/Redis behavior, absence of full ES/off-host recovery, asset-delete limitation, manual decisions required, `Not confirmed from repository` items. | Must not present a complete disaster-recovery or monitored-agent removal workflow; must not instruct destructive deletion without a separately approved runbook. |

No separate API reference, feature catalogue, CI/CD document, cloud IaC guide, or new platform design is proposed. Existing application docs already cover features/APIs, and CI/CD/IaC/new services are outside the approved scope.

## 3. Root README design

The root README should be concise enough to orient a new engineer and point to detailed documents. Proposed structure:

1. **Title and one-paragraph purpose**
   - ARIA is an AI-assisted SOC/SOAR platform over existing Elasticsearch telemetry.
   - It normalizes/enriches signals, correlates incidents, supports controlled investigation and approved Ansible response.
2. **Who uses ARIA**
   - SOC analysts, administrators, and security operators.
3. **Confirmed architecture at a glance**
   - A small source-backed diagram:

     ```text
     monitored/central agents
       -> Elasticsearch
       -> ARIA worker: poll/map/enrich/deduplicate/correlate
       -> SQLite investigations and workflow state
       -> optional LLM analysis
       -> approval-gated Ansible
       -> verification/archive
       -> FastAPI and Next.js dashboard
     ```

4. **Deployment roles**
   - Brain/central VM: native monitoring tools plus ARIA Compose stack.
   - Monitored VM/server: selected agents/collectors and optional later Ansible target.
   - ARIA containers: Redis, API, worker, frontend.
   - Monitoring/security tools: Elasticsearch, Kibana, Filebeat, Wazuh Manager, Suricata, Falco/Falcosidekick, Telegraf, detection rules, hardening.
   - Separate tool VM: `Not confirmed from repository`.
5. **Repository structure**
   - Use GitHub names: `aria-application/`, `aria-tools-setup/`, `ansible-vm-setup/`, `docker-compose/`, `aria-report/`, and the new `docs/`/`scripts/` paths.
6. **Deployment order**
   - Prepare intended Brain host and secrets.
   - Run the explicit-confirmation Brain wrapper.
   - Validate native services and containers.
   - Onboard monitored servers separately.
   - Register/validate assets; remediation remains a separate deliberate action.
7. **Quick links**
   - Architecture, Brain setup, monitored onboarding, validation/troubleshooting, security/secrets, backup/decommission limitations.
8. **Safety warning**
   - Existing tool scripts install, purge, reconfigure, start/stop services, change firewall/SSH settings, remove older stacks, and write credentials into service configs. Review before execution; use only on the intended Brain host.
9. **Confirmed limitations**
   - Demonstrated single Brain VM/single-node Elasticsearch.
   - Local SQLite operational state.
   - Local Redis volume.
   - Incomplete full-stack/off-host backup and restore.
   - Production TLS, exposure, authentication/authorization, and secret controls require review.
   - Image tags remain those in current Compose.
10. **Historical evidence**
    - Link the final-year report and mark it historical/reference only.

The README must not claim Kafka, active Neo4j, Kubernetes, infrastructure-as-code, HA, production-complete TLS/SSO/backup, a separate tool VM, or any behavior not confirmed by source.

## 4. Brain VM installer design — exact scope

### Canonical new file

Create exactly one script after approval:

```text
scripts/install_brain_vm.sh
```

The root location is justified because this wrapper spans two existing top-level concerns: central native-tool setup and application Compose deployment. It must not live inside the application package or a component-tool directory, because it owns neither implementation.

### Repository-layout resolution

The working evidence tree and GitHub snapshot use different top-level names. The script should determine its repository root from its own path and resolve only these confirmed candidates, in priority order:

| Purpose | GitHub-ready primary path | Local evidence fallback |
|---|---|---|
| Maintained tools runner | `aria-tools-setup/tools/setup_script_telegraf.sh` | `Aria_Tools_SetUp/tools/setup_script_telegraf.sh` |
| Canonical application Compose | `aria-application/docker-compose.yml` | `Front_end + back_end/docker-compose.yml` |

It must not select the separate duplicate `docker-compose/docker-compose.yml`/`Docker-compose files/docker-compose.yml`. If neither primary nor fallback exists, it must stop. If future layouts contain both and their content differs, it must stop and report ambiguity rather than guessing.

### Script behavior and failure policy

The future implementation should use strict shell behavior (`set -Eeuo pipefail`) and an error trap that names the failed stage without printing commands containing secrets.

Exact sequence:

1. **Resolve repository root and candidate files.**
   - Confirm the maintained runner and canonical application Compose are regular readable files.
2. **Validate the intended execution environment.**
   - Require root, Linux, systemd, and the apt-based Debian/Ubuntu assumptions used by the existing scripts.
   - Display hostname and detected primary address for operator verification, but do not persist them.
   - Repository-defined automatic Brain identity is `Not confirmed from repository`; therefore no hostname/IP allowlist may be invented.
3. **Validate mandatory commands before mutation.**
   - `bash`, `id`, `hostname`, `systemctl`, `curl`, `docker`.
   - Require `docker compose version` to succeed. The maintained runner defines a Docker installer function but does not call it from `main`; the wrapper must fail early rather than silently install or substitute a new Docker method.
4. **Reject partial central installation flags.**
   - If any existing `INSTALL_SIEM`, `INSTALL_SURICATA`, `INSTALL_WAZUH`, `INSTALL_FALCO`, `INSTALL_TELEGRAF`, `INSTALL_DETECTION_RULES`, or `INSTALL_HARDENING` variable is set to a value other than `1`, stop. The requested wrapper is for the complete existing Brain stack, not a partial profile.
5. **Require explicit destructive confirmation.**
   - Print the exact maintained runner path, hostname, components, and destructive categories.
   - Require a typed phrase such as `I_UNDERSTAND_THIS_CONFIGURES_THE_BRAIN_VM`.
   - EOF/non-interactive input or any mismatch aborts. No `--yes` bypass is proposed.
6. **Run the maintained central runner exactly as-is.**
   - Invoke `bash "$TOOLS_RUNNER"` directly.
   - Do not copy, source, wrap individual component scripts, override versions/ports, pass secrets on a command line, capture password prompts, or continue on non-zero exit.
   - The runner retains its own secure Elastic-password prompt and component ordering.
7. **Validate expected native services.**
   - Mandatory active services: `elasticsearch`, `kibana`, `filebeat`, `suricata`, `wazuh-manager`, `falcosidekick`, `telegraf`, `fail2ban`.
   - Falco uses one of `falco-modern-bpf`, `falco-bpf`, or `falco-kmod`; accept the installed variant only if exactly one supported unit is active. The component script currently does not define plain `falco.service` as a selected central variant.
   - Detection rules have no systemd service; their runner exit status is the available mandatory result.
   - Any missing mandatory service stops before Compose deployment.
8. **Locate and validate the canonical application Compose.**
   - Use the resolved application-local Compose file.
   - Set the Compose working directory to the Compose file's directory so `./data` and `./.env` mounts retain current semantics.
9. **Validate `.env` without reading or printing it.**
   - Require a regular readable `.env` beside the canonical Compose file.
   - Do not create, source, parse, copy, chmod, log, or validate secret values.
   - If missing, stop and point to `.env.example`/security documentation.
10. **Deploy the unchanged Compose stack.**
    - In the Compose directory, run exactly:

      ```text
      docker compose pull
      docker compose up -d
      ```

    - Do not build images, alter tags, add profiles, edit Compose, remove volumes, or run `down`.
11. **Validate existing Compose services.**
    - Confirm `redis`, `api`, `worker`, and `frontend` exist and are running via `docker compose ps`/`docker compose ps --services --status running`.
    - Retry the confirmed API health endpoint `http://127.0.0.1:8001/health` for a bounded period.
    - Confirm Redis through the existing service with `docker compose exec -T redis redis-cli ping`.
    - Confirm the frontend HTTP endpoint on host port `3001` responds; do not require a specific rendered page body.
    - Worker validation is container-running status because no dedicated worker health endpoint is defined in Compose.
    - Any mandatory validation failure exits non-zero and prints safe diagnostic commands only.
12. **Print safe completion information.**
    - Local dashboard: `http://127.0.0.1:3001`
    - Local API health/docs: `http://127.0.0.1:8001/health`, `http://127.0.0.1:8001/docs`
    - Kibana: HTTPS port `5601`; access depends on host/network/TLS configuration.
    - Reference the validation and security documents.
    - Never print `.env`, credentials, generated Telegraf bootstrap content, private addresses beyond what the operator already confirmed, or Ansible inventory values.

### Explicit non-goals

The wrapper must not:

- rewrite/copy existing tool scripts;
- invoke individual component scripts directly;
- change tool versions, ports, credentials, TLS choices, or service configs;
- generate secrets or `.env`;
- create cloud resources, DNS, VMs, monitored hosts, or firewall rules beyond the existing hardening runner;
- run monitored-VM bootstrap or Ansible;
- register assets or enable remediation;
- modify Compose or build images;
- change current `latest` tags;
- run migrations, seed data, tests, or application maintenance scripts;
- automatically restart/repair a failed mandatory service;
- silently continue after a failure.

## 5. Existing tools script selection

### Recommended canonical entry point

GitHub-ready path:

```text
aria-tools-setup/tools/setup_script_telegraf.sh
```

Local evidence path:

```text
Aria_Tools_SetUp/tools/setup_script_telegraf.sh
```

### Candidate comparison

| Candidate | Role | Selection result |
|---|---|---|
| `setup_script_telegraf.sh` | Maintained all-components runner with defaults enabling SIEM, Suricata, Wazuh, Falco, Telegraf, detection rules, and hardening. | Select as the direct canonical runner. |
| `setup_script.sh` | Compatibility entry point; explicitly states that older OTel/Metricbeat/Prometheus references were removed and `exec`s `setup_script_telegraf.sh`. | Do not call from the new wrapper; one indirection adds no behavior and hides the maintained filename. |
| `siem_setup.sh` | Installs/configures Elasticsearch 7.17.13, Kibana, Filebeat, TLS material, built-in credentials, and system log modules. | Sub-script only; invoked by the runner. |
| `suricata_setup.sh` | Installs/configures Suricata, interface, EVE output, rules, and Filebeat module integration. | Sub-script only; invoked by the runner. |
| `wazuh_setup.sh` | Installs Wazuh Manager 4.5.4-1 and integrates Wazuh alerts through Filebeat/Kibana. | Sub-script only; invoked by the runner. |
| `setup-falco-server-elastic.sh` | Installs native Falco service and Falcosidekick, configures Elasticsearch forwarding, and verifies both services/ingestion. | Sub-script only; invoked by the runner. |
| `telegraf_setup.sh` | Installs Telegraf, configures Elasticsearch metric output, verifies data, and may generate a credential-bearing target bootstrap under `/root`. | Sub-script only; invoked by the runner. The wrapper must never print generated bootstrap contents. |
| `detection_rules_setup.sh` | Creates Kibana index patterns/detection rules after SIEM availability. | Sub-script only; invoked by the runner. |
| `hardening_setup.sh` | Installs/enables Fail2Ban, changes UFW policy/rules, and hardens/restarts SSH. | Sub-script only; invoked by the runner; primary lockout/destructive warning. |

### Actual runner behavior

With default `INSTALL_*` values, the maintained runner performs this source-confirmed order:

```text
prerequisite checks/installation
-> shared Elastic password prompt
-> SIEM (Elasticsearch, Kibana, Filebeat)
-> Suricata
-> Wazuh Manager
-> Falco/Falcosidekick
-> Telegraf
-> Kibana detection rules
-> Fail2Ban/UFW/SSH hardening
```

It calls each sub-script by path and exits when a called mandatory script returns non-zero. Telegraf and detection rules can return a successful skip if `/etc/filebeat/filebeat.yml` is absent, although a successful default SIEM stage should create that file.

Known destructive/state-changing behavior includes package installation/purge options, certificate/config replacement, service enable/start/restart, old metrics/Falco stack removal, firewall changes, SSH hardening, and credential-bearing config/bootstrap generation. These behaviors belong to existing scripts and must be documented, not rewritten in this scope.

### What remains unautomated after the central runner

- Cloud/VPC/VM/security-group creation.
- A repository-defined machine-readable Brain identity.
- Application `.env` preparation and secret lifecycle.
- ARIA Compose pull/up; this is the sole additional deployment job of the proposed wrapper.
- External DNS/reverse proxy/production TLS/SSO.
- Elasticsearch snapshot/retention and complete disaster recovery.
- Monitored-VM onboarding, asset registration, source validation, and remediation enablement.
- Capacity sizing beyond the runner's 4 GB warning/8 GB recommendation and the report's demonstrated large ECS. Production minimum is `Not confirmed from repository`.

## 6. Validation checklist

All commands below are read-only health/status checks supported by current scripts/configuration. The future wrapper runs only the mandatory subset described in Section 4; the rest belong in the validation document.

### Native Brain services

| Check | Expected result | Credential note |
|---|---|---|
| `systemctl is-active --quiet elasticsearch` | Active | None. |
| `systemctl is-active --quiet kibana` | Active | None. |
| `systemctl is-active --quiet filebeat` | Active | None. |
| `systemctl is-active --quiet wazuh-manager` | Active | None. |
| `systemctl is-active --quiet suricata` | Active; the existing script also accepts its engine-started log marker during installation | None. Wrapper should require active after completion. |
| `systemctl is-active --quiet falcosidekick` | Active | None. |
| `systemctl is-active --quiet falco-modern-bpf` or `falco-bpf` or `falco-kmod` | One installed supported Falco variant active | None. |
| `systemctl is-active --quiet telegraf` | Active | None. |
| `systemctl is-active --quiet fail2ban` | Active | None. |
| `systemctl status elasticsearch kibana filebeat wazuh-manager suricata falcosidekick telegraf fail2ban --no-pager -l` | Diagnostic detail | None; may expose hostnames/paths in operator terminal. |
| `journalctl -u <service> -n 120 --no-pager` | Diagnostic logs | None; logs may contain infrastructure metadata and must not be pasted publicly without review. |

### Elasticsearch and Kibana

| Check | Expected result | Credential note |
|---|---|---|
| HTTPS Elasticsearch root/cluster health on port `9200` | Reachable, authenticated, non-red when queried | Requires credentials and CA/insecure choice. Do not embed credentials or place passwords in shell history. Not a mandatory automated wrapper check. |
| Kibana `/api/status` on HTTPS port `5601` | Reachable/status payload | May require credentials/TLS handling. Not a mandatory automated wrapper check. |
| `_cat/indices` for `wazuh-alerts-*`, `filebeat-*`, `falco-*`, `telegraf-*` | Expected index families after data is generated | Requires Elasticsearch credentials. Absence immediately after installation is not proof of service failure; telemetry may not yet exist. |

### ARIA Compose stack

Run from the canonical Compose directory or supply `-f` while preserving its working directory:

| Check | Expected result | Credential note |
|---|---|---|
| `docker compose ps` | `redis`, `api`, `worker`, `frontend` present and running | None. |
| `docker compose ps --services --status running` | All four service names | None. |
| `docker compose exec -T redis redis-cli ping` | `PONG` under current Compose configuration | None under current Redis command; if Redis auth is later introduced, handling is `Not confirmed from repository`. |
| `curl --fail --silent --show-error http://127.0.0.1:8001/health` | JSON status OK | None. |
| `curl --fail --silent --show-error http://127.0.0.1:8001/api/v1/health` | JSON status OK | None. Optional duplicate API check. |
| `curl --fail --silent --show-error --output /dev/null http://127.0.0.1:3001` | Successful HTTP response | None. |
| `docker compose logs --tail=200 api worker redis frontend` | Diagnostic output only when validation fails | Logs may contain metadata; do not publish without review. |

### Not valid as automatic success claims

- A running container does not prove source telemetry is arriving.
- An existing index does not prove current data freshness.
- API `/health` does not prove worker loops, LLM, Elasticsearch, or Ansible are healthy.
- The repository has no worker health endpoint in Compose.
- Complete backup/restore and public-production readiness are `Not confirmed from repository`.

## 7. Approved implementation boundary

This section defines the exact Phase 2 boundary that may be approved later. Nothing in it is implemented by this planning phase.

### Documentation files allowed for Phase 2

Create/update exactly:

```text
README.md
docs/architecture/ARIA_ARCHITECTURE.md
docs/deployment/BRAIN_VM_SETUP.md
docs/deployment/MONITORED_VM_ONBOARDING.md
docs/operations/VALIDATION_AND_TROUBLESHOOTING.md
docs/operations/SECURITY_AND_SECRETS.md
docs/operations/BACKUP_AND_DECOMMISSION_LIMITATIONS.md
```

### Script file allowed for Phase 2

Create exactly:

```text
scripts/install_brain_vm.sh
```

No additional helper, configuration, service unit, Dockerfile, Compose override, environment file, generated secret, or migration file is approved.

### Existing files and trees that must remain untouched

```text
Front_end + back_end/api/
Front_end + back_end/core/
Front_end + back_end/pipeline/
Front_end + back_end/response/
Front_end + back_end/config/
Front_end + back_end/frontend/
Front_end + back_end/data/
Front_end + back_end/tests/
Front_end + back_end/main.py
Front_end + back_end/docker-compose.yml
Front_end + back_end/Dockerfile.backend
Front_end + back_end/frontend/Dockerfile
Docker-compose files/docker-compose.yml
Aria_Tools_SetUp/tools/
Aria_Tools_SetUp/Script that i should inject in VMs to monitor them/
Ansible+script--setup-the-VMS-via_Ansible/
Front_end + back_end/scripts/vm-onboarding/
aria-report/
ARIA_DISCOVERY_REPORT.md
ARIA_ARCHITECTURE_AND_OPERATIONS_MAP.md
ARIA_OPEN_QUESTIONS_AND_RISKS.md
```

The future root documentation may link these sources but must not edit them under this boundary.

### Phase 2 static validations

Without executing installers or services:

- `bash -n scripts/install_brain_vm.sh`
- Verify only the eight approved files changed/appeared.
- Verify the wrapper references only the maintained tools runner and canonical application Compose candidates.
- Verify it contains no credential/IP/token/private-key value and never prints `.env`.
- Verify it does not invoke Ansible, monitored bootstrap, migrations, builds, `docker compose down`, volume removal, or component sub-scripts.
- Verify every documentation claim has a cited repository path or is marked `Not confirmed from repository`.
- Verify all seven documentation files consistently identify worker-driven polling, host/container ports, native central tools, and current limitations.

Runtime validation commands in Section 6 are documented for an authorized installation window only. They will not be executed while implementing documentation or the wrapper.

### Final boundary statement

Frontend, backend, API routes, database models, worker logic, AI logic, alert/correlation logic, Ansible remediation logic, Docker images, Compose definitions, existing central setup scripts, monitored-VM scripts, and infrastructure state will not be changed. Phase 2, if approved, is limited to seven documentation files and one orchestration wrapper that sequentially invokes the existing maintained central runner and the unchanged existing ARIA Compose deployment.
