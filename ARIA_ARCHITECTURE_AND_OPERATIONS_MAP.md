# ARIA Architecture and Operations Map

Audit date: 2026-06-22. Commands below are validation/troubleshooting commands inferred from repository files; they were not executed against live services during this read-only audit.

## 1. Deployment roles

### Brain / central platform VM

“Brain VM” is interpreted as the repository's **central host/server**. In the demonstrated Huawei Cloud environment it is ECS `ecs-ghazi`, Ubuntu 24, 64 vCPU and 128 GB RAM (`aria-report/chapters/02-cloud-and-monitoring.tex`). That size is observed, not a documented minimum.

Responsibilities:

- Elastic 7.17.13 single-node Elasticsearch and Kibana.
- Wazuh Manager and central Filebeat.
- Optional local Suricata, Falco/Falcosidekick, and Telegraf for self-monitoring.
- Redis, ARIA FastAPI, background worker, Next.js dashboard, SQLite data, playbooks/evidence/backups.
- Ansible control node for approved SSH-based response.
- Certificates/credentials and all analytics/correlation/AI workflow state.

Evidence: `Aria_Tools_SetUp/tools/*.sh`, `Front_end + back_end/docker-compose.yml`, `Front_end + back_end/main.py`.

### Monitored VM/server

Runs only selected producers/agents: Wazuh Agent, Filebeat, Suricata, Falco/Falcosidekick, and Telegraf. It does not run ARIA analytics, SQLite, Redis, Kibana, Elasticsearch, or Wazuh Manager. It sends telemetry to the central host and can optionally be reached from the Brain VM over SSH for Ansible after explicit remediation enablement (`scripts/vm-onboarding/bootstrap_monitored_vm.sh`).

### Tool VM

No separate tool-VM topology is implemented. The report and scripts place the monitoring tools on the central VM. A split deployment might be desirable for scale, but no Compose, inventory, certificates, or runbook defines it.

### Application containers

`aria-redis`, `aria-api`, `aria-worker`, and `aria-frontend` are the only Compose services. Elasticsearch/Kibana/Wazuh/Falco/etc. are external native services from the application's point of view (`Front_end + back_end/docker-compose.yml`).

## 2. Architecture diagram

```text
                       Huawei Cloud VPC / trusted network

  +-------------------- Monitored VM <asset> -----------------------+
  | Wazuh Agent --1514/1515--> central Wazuh Manager                |
  | system/auth logs ----+                                          |
  | Suricata EVE --------+--> Filebeat --HTTPS 9200----------------+ |
  | Falco --> Falcosidekick localhost:2801 --HTTPS 9200-----------+| |
  | Telegraf ------------------------------HTTPS 9200-------------+| |
  | optional SSH target <----------------------- Brain VM :22      || |
  +---------------------------------------------------------------||-+
                                                                  ||
  +---------------------- Brain / central VM ---------------------||-+
  | Native monitoring foundation                                 vv |
  | Wazuh Manager -> Filebeat ----+       +-------------------------+|
  | Suricata -> Filebeat ---------+------>| Elasticsearch 7.17 :9200||
  | Falco -> Falcosidekick -------+       | indices:                 ||
  | Telegraf ---------------------+       | wazuh-alerts-*           ||
  |                                       | filebeat-<asset>-*       ||
  | Kibana :5601 <------------------------| falco-<asset>-*          ||
  |                                       | telegraf-<asset>-*       ||
  |                                       +------------+------------+|
  |                                                    | poll/query  |
  | Docker Compose network (default project bridge)    v             |
  | +-------------+   +-------------+   +------------------------+  |
  | | Redis :6379 |<->| ARIA API    |<->| SQLite /app/data       |  |
  | | host :6380  |   | :8001       |   | investigations.db      |  |
  | +------+------+   +------+------+   +------------------------+  |
  |        ^                 ^                 ^                      |
  |        |                 | REST/WebSocket  |                      |
  | +------+-------+         |            +----+------------------+  |
  | | ARIA worker  |---------+------------| Ansible -> SSH :22    |  |
  | | poll/enrich/ |                      | LLM provider optional |  |
  | | correlate/AI |                      +-----------------------+  |
  | +--------------+                                                |
  |                         +---------------------------+            |
  | analyst browser ------->| Next.js host :3001/:3000 |            |
  |                         +---------------------------+            |
  +-----------------------------------------------------------------+
```

## 3. Component operations table

| Component | Location/technology | Input -> output | Config/startup | Failure impact |
|---|---|---|---|---|
| Elasticsearch | Brain, native systemd, 7.17.13 | HTTPS telemetry/query -> indices | `/etc/elasticsearch/elasticsearch.yml`; `siem_setup.sh`; 9200 | All ingestion, dashboards, verification, and new alert processing degrade/stop. |
| Kibana | Brain, native systemd | ES -> analyst raw search/rules | `/etc/kibana/kibana.yml`; 5601 | ARIA can operate, but raw SIEM exploration/rule UI is unavailable. |
| Wazuh Manager | Brain, native 4.5.4-1 | agents 1514/1515 -> alerts/Filebeat | `/var/ossec/`; `wazuh_setup.sh`; API 55000 | Wazuh host alerts/enrollment stop. |
| Wazuh Agent | Monitored VM | host events -> manager | `/var/ossec/etc/ossec.conf`; bootstrap | Only that host's Wazuh visibility fails. |
| Filebeat | Brain and monitored VMs | logs/Wazuh/Suricata -> ES | `/etc/filebeat/filebeat.yml`, modules; bootstrap/SIEM scripts | Affected log/network/Wazuh pipelines stop. |
| Suricata | Brain/monitored VM | packets -> `/var/log/suricata/eve.json` -> Filebeat | `/etc/suricata/suricata.yaml`, `/etc/default/suricata` | Network IDS visibility lost for host/interface. |
| Falco | Brain/monitored VM | syscalls/eBPF -> local sidekick HTTP 2801 | `/etc/falco/config.d/10-aria-output.yaml` | Runtime detections stop. |
| Falcosidekick | Brain/monitored VM | Falco HTTP -> ES | `/etc/falcosidekick/{config.yaml,falcosidekick.env}` | Falco may detect locally but ARIA sees nothing. |
| Telegraf | Brain/monitored VM | host metrics -> ES | `/etc/telegraf/telegraf.conf`, `telegraf.d/` | Metrics/infrastructure investigations stale. |
| Redis | Compose `aria-redis`, Redis 7 | API/worker state | named volume `redis-data`; host 6380 -> 6379 | Cache/cursors/pub-sub/performance state fail; file fallbacks are partial. |
| ARIA API | Compose Python/FastAPI | REST/WS -> SQLite/ES/Redis | `.env`, `/app/data`; 8001 | UI/API unavailable; worker may continue. |
| ARIA worker | Compose Python | ES -> SQLite/Redis/Ansible/LLM | `main.py`, `SKIP_RESPONSE_API=1` | No fresh ingest/correlation/investigation/verification; API reads stale state. |
| ARIA frontend | Compose Next.js | browser -> API/WS | build-time public URLs; container 3000, host 3001 | Users lose dashboard; backend continues. |
| SQLite | bind-mounted `./data` | ARIA workflow persistence | `DB_PATH=data/investigations.db` | Single point of operational-state failure. |
| Ansible | API/worker image | approved playbook -> SSH target | asset `ansible_config_json`, env secret refs | Automated diagnostics/remediation unavailable; monitoring remains. |
| LLM | external or Ollama | grounded context -> analysis/playbook | provider keys/host in `.env` | Rule fallback may continue; AI quality/features degrade. |

## 4. Ports, protocols, URLs, and exposure

| Port | Direction | Purpose | Exposure guidance/evidence |
|---|---|---|---|
| 22/tcp | admin/Brain -> hosts | SSH/Ansible | Trusted admin/Brain CIDR only. |
| 1514/tcp+udp | monitored -> Brain | Wazuh agent events | Monitored networks only. |
| 1515/tcp | monitored -> Brain | Wazuh enrollment | Monitored networks only. |
| 55000/tcp | admin/bootstrap -> Brain | Wazuh API | Internal only. |
| 2801/tcp | Falco -> same-host sidekick | Runtime event reception | Script binds local flow; do not expose publicly. |
| 9200/tcp HTTPS | agents/ARIA -> Brain | Elasticsearch ingest/query | Repository firewall script opens it, but production should restrict to monitored/Brain networks. |
| 5601/tcp HTTPS | analyst -> Brain | Kibana | VPN/analyst CIDR only. |
| 6379/tcp container, 6380 host | API/worker -> Redis | Cache/state | Compose exposes 6380; production should bind internal/loopback only. |
| 8001/tcp HTTP | browser/frontend -> API | REST, docs, WebSocket | Put behind authenticated TLS reverse proxy; CORS configured. |
| 3000/tcp container, 3001 host | browser -> frontend | Dashboard | Compose access URL is `http://<brain>:3001`; report sometimes says 3000 for non-Compose deployment. |
| 11434/tcp (default) | worker -> Ollama | Local LLM | Only if Ollama selected; no Compose service. |
| 7687/tcp | none active | Neo4j placeholder | Disabled; no implemented dependency. |

Source port table: `aria-report/chapters/02-cloud-and-monitoring.tex`; application mappings: `Front_end + back_end/docker-compose.yml`.

## 5. Networks, volumes, paths, and credentials

### Compose

- No explicit network is defined; Compose creates its default bridge network.
- `redis-data` is the only named volume.
- API and worker bind-mount `./data:/app/data` and `./.env:/app/.env`.
- Frontend has no persistent volume.
- API waits for Redis health; worker uses simple `depends_on` and can start before API readiness.
- Images use mutable `ghaziiii/aria_project:{redis,backend,worker,frontend}-latest` tags.

Evidence: both `Front_end + back_end/docker-compose.yml` and duplicate `Docker-compose files/docker-compose.yml`.

### Persistent and operational paths

- ARIA DB: `Front_end + back_end/data/investigations.db`.
- Ticket DB: `data/artifacts/tickets.db`.
- Redis: named volume `redis-data` with AOF.
- Playbooks/inventories/evidence: `data/playbooks/`, `data/evidence/`.
- Cursors/seen IDs: `data/cursors/`, `data/seen_ids/`.
- Backups: `data/backups/`; worker keeps seven in its current loop despite separate retention settings.
- Application logs: container stdout/journald; legacy `/var/log/aria`; logrotate config at `deploy/logrotate/aria`.
- Monitored bootstrap log: `/var/log/aria-monitored-vm-setup.log`.
- Elastic data/logs: `/var/lib/elasticsearch`, `/var/log/elasticsearch`.
- Agent/service logs: `/var/ossec/logs/ossec.log`, `/var/log/suricata/`, `journalctl -u <service>`.

### Environment/configuration groups

`config/settings.py` is authoritative. Major groups: Elasticsearch credentials/TLS/index patterns; Redis host/port/db/password; API/CORS/rate limits; JWT/admin authorization; LLM provider keys/model/Ollama; deprecated OpenSOAR; local ingestion and correlation; Ansible global/default and per-asset secret references; auto-approval/safety/staged remediation; notification; multi-server; performance thresholds/anomaly/auto-remediation; data paths/backups.

`.env.example` is incomplete relative to the current `.env` and settings. The live `.env` includes many additional workflow, performance, multi-server, safety, and per-asset secret variables. Secret values were not reproduced in this audit.

Credential references and problems:

- `Ansible+script--setup-the-VMS-via_Ansible/inventory.ini` includes a plaintext root password.
- Its `playbook.yml` includes a plaintext Elasticsearch password and hard-coded central IP.
- `config/ansible_inventory` disables host-key checking and contains public IPs.
- `config/keys/` contains private-key-looking files in the working tree (ignored by Git); permissions/rotation were not verified.
- `.env.backup.*` files are tracked in the embedded Git repository and may contain historical secrets.
- `response/auth.py` hard-codes the JWT signing secret.
- `siem_setup.sh` hard-codes a Kibana saved-object encryption key and writes service credentials into configs.

## 6. Empty-cloud-to-working-platform sequence

This is the dependency-correct sequence supported by repository evidence. It is a runbook map, not authorization to execute it.

1. **Provision cloud foundation (manual/not automated here).** Create VPC/subnet, security group, private addressing, EIP only if required, DNS if desired, and an Ubuntu 24 central ECS. Create monitored Ubuntu/Debian VMs. Evidence of Huawei topology only: `aria-report/chapters/02-cloud-and-monitoring.tex`.
2. **Size storage and retention.** No minimum is documented. The demonstrated Brain was 64 vCPU/128 GB. Allocate persistent disk for `/var/lib/elasticsearch`, ARIA `data/`, Redis AOF, logs, and backups. Define ES retention before ingest.
3. **Establish access.** Administrative SSH keys/users and sudo, NTP/time sync, outbound access to Elastic/Wazuh/Falco/Influx/GitHub package repositories, and a trusted CIDR/VPN.
4. **Apply security-group rules.** Allow 22 from admins; 1514/1515 from monitored hosts; 9200 from approved forwarders/Brain; 55000 internally; 5601 from analysts; ARIA 3001/8001 only via trusted access or reverse proxy. Do not expose Redis.
5. **Prepare Brain OS.** Ubuntu package sources, `curl`, `gpg`, `wget`, `tar`, `ca-certificates`, `unzip`, `git`, `iproute2`; Docker/Compose if using application Compose (`setup_script_telegraf.sh`).
6. **Harden the host.** Review then apply `hardening_setup.sh`; note it changes UFW and SSH and can lock out an operator if key access/CIDR is wrong.
7. **Install search core first.** Review/run `siem_setup.sh`: Elastic/Kibana/Filebeat 7.17.13, local CA/certs, passwords, TLS, system modules. The script can purge an existing installation when selected; never run blindly.
8. **Install tools in dependency order.** `wazuh_setup.sh`; `suricata_setup.sh`; `setup-falco-server-elastic.sh`; `telegraf_setup.sh`; then `detection_rules_setup.sh`. The orchestrator is `setup_script_telegraf.sh`; `setup_script.sh` only forwards to it.
9. **Validate foundation.** All systemd services active, ES health non-red, index families exist, Kibana reachable.
10. **Prepare ARIA configuration.** Copy values conceptually from `.env.example` but reconcile against `config/settings.py`; set strong unique secrets, internal URLs, CORS/public API URLs, source patterns, and optional LLM/Ansible. Do not reuse repository credentials.
11. **Deploy ARIA application.** `docker compose pull` then `docker compose up -d` is the documented path, using the four prebuilt images. Source build definitions exist (`Dockerfile.backend`, `frontend/Dockerfile`) but Compose uses remote images.
12. **Seed/admin accounts.** Account seed tooling exists at `scripts/demo/seed_accounts.py`; exact production bootstrap policy is not documented. Confirm a super-admin can authenticate.
13. **Validate application.** API health/docs, frontend, worker heartbeats, Redis ping, ES connectivity, and pipeline page.
14. **Onboard each monitored server** using Section 7 below.
15. **Observe before acting.** Validate sources, leave remediation disabled, configure/test Ansible, then enable remediation per asset only after approval controls and backups are confirmed.

## 7. Exact new monitored-VM onboarding procedure

### Canonical-source warning

There is no declared canonical copy. `Front_end + back_end/scripts/vm-onboarding/bootstrap_monitored_vm.sh` and `Aria_Tools_SetUp/.../bootstrap_monitored_vm.sh` are byte-identical (SHA-256 `2a2cc2...`), while `Ansible+script--setup-the-VMS-via_Ansible/bootstrap_monitored_vm.sh` is newer/different (`d0aa8e...`) and includes an environment field. The Ansible playbook uses its colocated copy. Choose and review one before future execution; this audit does not declare them interchangeable.

### Prerequisites

- Supported script logic assumes Debian/Ubuntu with root/sudo, systemd, apt/dpkg, network interface/default route, and outbound package repository access.
- Unique lowercase asset/VM name, environment, IP/hostname.
- Monitored VM can reach central HTTPS 9200 and Wazuh 1514/1515; Brain can reach Wazuh API 55000 and later SSH 22 if remediation is enabled.
- Central ES username/password and preferably CA certificate; default `TLS_MODE=insecure` is a risk.
- Wazuh group and manager address; capture interface if auto-detection is unsuitable.
- Explicit safety confirmation `I_UNDERSTAND_THIS_IS_A_MONITORED_VM` for non-interactive use.

### Direct script path

Use the reviewed `scripts/vm-onboarding/bootstrap_monitored_vm.sh` on the monitored VM as root. Supported selection flags are `--all`, `--wazuh`, `--filebeat`, `--suricata`, `--falco`, and `--telegraf`; identity/endpoint flags include `--vm-name`, `--environment` in the newer copy, `--ip`, `--es-ip`/`--es-url`, `--es-user`, `--es-ca`, `--wazuh-manager`, `--wazuh-group`, and `--interface`. Non-interactive mode reads the password from `ARIA_ES_PASSWORD`, not a CLI argument.

The script:

1. Refuses a central-looking host unless explicitly confirmed.
2. Waits for apt locks; it does not need the Ansible wrapper's force-kill behavior.
3. Tests ES reachability/authentication before installing.
4. Installs/configures selected services.
5. Creates per-asset indices: `filebeat-<vm>-*`, `falco-<vm>-*`, `telegraf-<vm>-*`; Wazuh remains shared and is scoped by agent identity.
6. Verifies service activity and index visibility, posts a Falco test event, and attempts to obtain the Wazuh agent ID.
7. Prints a JSON body for `POST /api/v1/assets`, with `remediation_enabled:false`.

Important implementation defect: the current primary bootstrap payload sets Wazuh `host_name` and `agent_name` from `VM_ENVIRONMENT` at lines around 1418 rather than `VM_NAME`. The newer Ansible copy must be checked for the same behavior. Do not trust the generated Wazuh attribution without inspecting the printed payload and manager agent identity.

### Ansible wrapper path

`Ansible+script--setup-the-VMS-via_Ansible/playbook.yml` targets group `[monitored_vms]`, copies its local bootstrap to `/tmp/bootstrap_monitored_vm.sh`, derives `_vm_name` from `ansible_hostname`, passes non-interactive arguments, and provides the ES password via environment. It also stops/disables unattended upgrades and aggressively kills apt/dpkg/debconf processes and removes locks before `dpkg --configure -a`; this is operationally dangerous and should not be used on production hosts without review.

The example `inventory.ini` contains a real-looking public IP/root password and must not be reused. Replace with inventory/vault-backed secrets and host-key verification.

### Register and validate in ARIA

1. Authenticate as super-admin and create the asset via `/settings/assets` or `POST /api/v1/assets` with the generated/sanitized payload (`api/routes/assets.py`).
2. Confirm source patterns and identity fields manually, especially Wazuh agent name/ID.
3. Run `POST /api/v1/assets/{asset_id}/validate`. It queries ES patterns and records validation state.
4. Confirm the asset appears in the selector and asset list.
5. Confirm expected data in alerts, runtime investigations, metrics, IPS/dashboard, and pipeline status for that `asset_id`.
6. Leave remediation disabled until per-asset Ansible configuration is added and `/api/v1/assets/{asset_id}/ansible/test-connection` succeeds.

### Validation commands inferred from scripts

On the monitored host:

```bash
systemctl status wazuh-agent filebeat suricata falcosidekick telegraf --no-pager -l
journalctl -u wazuh-agent -u filebeat -u suricata -u falcosidekick -u telegraf -n 120 --no-pager
tail -n 120 /var/log/aria-monitored-vm-setup.log
filebeat test config -c /etc/filebeat/filebeat.yml
```

On the Brain host (supply credentials securely; examples intentionally omit them):

```bash
systemctl status elasticsearch kibana filebeat wazuh-manager suricata falcosidekick telegraf fail2ban
curl -k https://127.0.0.1:9200/_cluster/health
curl -k 'https://127.0.0.1:9200/_cat/indices/filebeat-<asset>-*,falco-<asset>-*,telegraf-<asset>-*?v'
curl http://127.0.0.1:8001/health
docker compose ps
docker compose logs --tail=200 api worker redis frontend
```

These commands are diagnostics only but may reveal sensitive data; use trusted terminals and do not put passwords in shell history.

### Decommissioning

No complete safe decommission workflow exists. The bootstrap references `delete_set_up.sh --all`, but that file is absent. The API offers `DELETE /api/v1/assets/{asset_id}`, which removes only the registry record (`api/routes/assets.py`); it does not stop agents, revoke Wazuh enrollment, remove SSH access, delete ES data, or revoke credentials.

Required manual sequence pending a real runbook:

1. Disable `remediation_enabled`, then disable the asset in ARIA.
2. Revoke/remove Brain-to-host Ansible credentials and inventory references.
3. Stop/disable or uninstall monitored agents under a separately reviewed host-change plan.
4. Remove/revoke Wazuh agent enrollment centrally.
5. Decide retention/legal hold for per-asset ES indices; do not delete by default.
6. Rotate any shared ES credential exposed to the host.
7. Delete the ARIA asset only after audit/history retention behavior is confirmed.

Steps 2–6 are operational recommendations, not automated repository behavior.

## 8. Brain VM validation and troubleshooting entry points

Startup order: Elasticsearch -> Kibana/Filebeat -> Wazuh/Suricata/Falco/Telegraf -> Redis -> API -> worker -> frontend -> monitored assets.

Health entry points:

- Elastic: `/_cluster/health`, `/_cat/indices`, `/var/log/elasticsearch`, journald.
- Kibana: `/api/status`, journald.
- Wazuh: `systemctl status wazuh-manager`, `/var/ossec/logs/ossec.log`, API 55000.
- Collectors: `systemctl status ...`, `/var/log/suricata`, Filebeat test output.
- ARIA: `/health`, `/api/v1/health`, `/docs`, `/api/v1/pipeline/status`, `/api/v1/monitoring/*`, worker heartbeats.
- Containers: `docker compose ps` and service logs.
- SQLite: file existence/permissions and backup directory; use maintenance scripts only under a change window (`scripts/maintenance/backup_db.sh`, `restore_db.sh`).
- Runtime QA: `.systemd/runtime-qa-watchdog.*`, `scripts/validation/runtime_qa_watchdog.py` (not a general platform monitor).

## 9. Backup and recovery map

Confirmed: the worker copies SQLite daily and retains seven files in `main.py`; maintenance backup/restore shell scripts exist; Redis uses AOF in a named volume. Not found: Elasticsearch snapshot repository/policy, tested full-stack restore, off-host backup, encryption, immutable backup, RPO/RTO, Wazuh/Kibana config backup, or a Compose volume backup runbook. Treat the Brain VM and its local disk as a single failure domain.

## Ready for Next Work

The operational model is clear enough to plan non-invasive ownership work. Safest next documents: canonical-source decision for onboarding, immutable image/version manifest, security-group matrix, secret inventory/rotation plan, backup/restore drill plan, route authorization matrix, and a complete decommission runbook.
