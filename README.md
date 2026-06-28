<!-- ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ -->
<div align="center">

<img src="assets/readme/aria-title.svg" alt="ARIA — Adaptive Response Intelligence Automation" width="780"/>

<h3>The local-first SOC / SOAR platform that <em>investigates</em> and <em>responds</em> — not just alerts.</h3>

<p>
ARIA turns the security telemetry you already collect into <b>correlated incidents</b>, <b>AI-driven investigations</b>, and <b>approval-gated Ansible remediation</b> — then verifies the fix against Elasticsearch and archives the case. No upstream SaaS required.
</p>

<p>
<img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
<img src="https://img.shields.io/badge/Next.js-16-000000?style=for-the-badge&logo=nextdotjs&logoColor=white"/>
<img src="https://img.shields.io/badge/Elasticsearch-9.x-005571?style=for-the-badge&logo=elasticsearch&logoColor=white"/>
<br/>
<img src="https://img.shields.io/badge/Redis-async-DC382D?style=for-the-badge&logo=redis&logoColor=white"/>
<img src="https://img.shields.io/badge/Ansible-remediation-EE0000?style=for-the-badge&logo=ansible&logoColor=white"/>
<img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white"/>
<img src="https://img.shields.io/badge/SQLite-WAL%20%2B%20FTS5-003B57?style=for-the-badge&logo=sqlite&logoColor=white"/>
</p>

<p>
<img src="https://img.shields.io/badge/Wazuh-EDR-3578E5?style=flat-square&logo=wazuh&logoColor=white"/>
<img src="https://img.shields.io/badge/Suricata-IDS%2FIPS-EE3424?style=flat-square"/>
<img src="https://img.shields.io/badge/Falco-runtime-00AEC7?style=flat-square&logo=falco&logoColor=white"/>
<img src="https://img.shields.io/badge/Telegraf-metrics-22ADF6?style=flat-square&logo=influxdb&logoColor=white"/>
<img src="https://img.shields.io/badge/MITRE_ATT&CK-mapped-C7252B?style=flat-square"/>
<img src="https://img.shields.io/badge/LLM-Ollama_·_Gemini_·_OpenRouter_·_NVIDIA_NIM-7C3AED?style=flat-square"/>
</p>

<p><sub>Final-year engineering project (PFE) — <b>ESPRIT</b> × <b>Huawei</b> · 2025–2026 · by Ghazi Mabrouki</sub></p>

</div>

<!-- ░░░░░░░░░░░░░░░░░░░░░░░░░ HERO ░░░░░░░░░░░░░░░░░░░░░░░░░ -->
<div align="center">

<img src="assets/readme/aria-hero.gif" alt="ARIA in action — login, dashboard, incident correlation, AI investigation, verified response" width="92%"/>

<sub><i>Sign-in → live SOC dashboard → incident correlation → autonomous AI investigation → approval-gated, ES-verified response.</i></sub>

</div>

---

## 🧭 Why ARIA exists

Most SOC stacks stop at **detection** — they hand an analyst a wall of alerts and walk away. ARIA closes the loop:

> **Telemetry → Incident → Investigation → *Approved Action* → Verification → Archive.**

It reads the telemetry already flowing into Elasticsearch (Wazuh, Suricata, Falco, Telegraf), **normalizes and enriches** it, **correlates** related signals into incidents, **investigates** them with an LLM, proposes a **staged Ansible playbook**, executes **only after a human approves**, then **re-queries Elasticsearch to prove the threat is gone** before archiving the case with full evidence.

Everything runs on a single **Brain VM** you control. The LLM can be a local **Ollama** model — your data never has to leave the box.

---

## 🌊 The detection-to-response pipeline

<div align="center">
<img src="assets/readme/aria-pipeline.svg" alt="ARIA detection-to-response pipeline" width="96%"/>
</div>

<table>
<tr>
<td width="33%" valign="top">

**① Ingest & normalize**
Worker polls Elasticsearch, maps each source (Wazuh / Suricata / Falco / Filebeat / generic) into one canonical alert schema, normalizes severity, extracts IOCs.

</td>
<td width="33%" valign="top">

**② Enrich & de-noise**
GeoIP, MITRE ATT&CK, threat-intel and campaign tagging; **3-tier dedup** (Redis → memory → SQLite) and **Sigma** noise filtering keep the signal clean.

</td>
<td width="33%" valign="top">

**③ Correlate**
A 7-level correlation hierarchy groups alerts into **incidents**, tracks kill-chain phase, and links Suricata ↔ Wazuh views of the same event.

</td>
</tr>
<tr>
<td valign="top">

**④ Investigate (AI)**
Evidence collection → LLM root-cause → a **staged remediation plan** (evidence · dry-run · containment · hardening · forensics · verification). A deterministic path exists when you'd rather not trust the model.

</td>
<td valign="top">

**⑤ Respond (gated)**
Nothing executes without **explicit approval**, protected by an admin secret. Ansible runs in stages with **dry-run**, firewall safety and **rollback** built in.

</td>
<td valign="top">

**⑥ Verify & archive**
A delayed Elasticsearch recurrence query plus active state checks decide the **fix status**. The case — evidence, playbook, AI analysis — is archived and exportable to **PDF**.

</td>
</tr>
</table>

---

## 🤖 The signature feature: an auditable investigation state machine

Every case — security, infrastructure, or runtime — walks the **same eight-step workflow**. No black box: each step shows its evidence, its command output, and its exit code.

<div align="center">
<img src="assets/readme/aria-workflow.gif" alt="ARIA SOC workflow — eight auditable steps from incident to archive" width="94%"/>
</div>

```
 Incident ─▶ Evidence ─▶ AI Root-Cause ─▶ Remediation Plan ─▶ Approval ─▶ Ansible ─▶ Verification ─▶ Archived
   sel.        collect      LLM analysis      staged playbook    human       staged       ES re-query     evidence
                                                                 gate        exec         + state         + PDF
```

---

## 🛰️ One platform, many lenses

<div align="center">
<img src="assets/readme/aria-telemetry.gif" alt="ARIA modules — dashboard, performance, infrastructure anomalies, AI assistant, archives" width="92%"/>
</div>

<table>
<tr>
<th>🛡️ Security Operations</th>
<th>📈 Infrastructure & Performance</th>
<th>🧬 Runtime Security</th>
</tr>
<tr>
<td valign="top">

- Real-time **SOC dashboard** (severity, MITRE, trends, health)
- **Alerts** with IOC extraction & related-incident pivots
- **Incident** correlation & one-click *Investigate*
- **IPS Map** — live attack paths on a world map
- **Whitelist** management (IP / subnet / domain)

</td>
<td valign="top">

- **Performance** — live CPU / memory / disk / network from Telegraf
- **Top processes** by CPU & memory, per host
- **Infrastructure anomalies** auto-diagnosed by AI
- Resource gauges, thresholds & root-cause cards

</td>
<td valign="top">

- **Falco**-driven host & container behavior analysis
- Process / file / privilege-escalation classification
- Threat classification with confidence + decision routing
- Diagnostics-only by default; remediation behind approval

</td>
</tr>
<tr>
<th>🧠 AI Intelligence</th>
<th>🌐 Multi-server</th>
<th>📦 System Management</th>
</tr>
<tr>
<td valign="top">

- **AI Assistant** — context-aware chat across the whole estate
- **AI Operator** — natural language → Ansible, with confirmation
- Pluggable LLM: **Ollama**, Gemini, OpenRouter, NVIDIA NIM
- Deterministic bypass for trust-critical actions

</td>
<td valign="top">

- **Monitored assets** with per-asset scoping
- Roles: **super_admin** & **server_user**
- Per-asset index patterns & credentials
- Onboard a new VM with a single bootstrap script

</td>
<td valign="top">

- **Archives** with verified fix status & **PDF** export
- Full **audit log** of every state change
- **Settings center** (data sources, AI, workflow, Ansible…)
- WebSocket-driven live updates everywhere

</td>
</tr>
</table>

<details>
<summary><b>📸 Click to expand the full screenshot gallery</b></summary>

<br/>

| Sign-in | Security Dashboard |
|:--:|:--:|
| <img src="assets/readme/shots/login.png" width="100%"/> | <img src="assets/readme/shots/dashboard.png" width="100%"/> |

| Incident Correlation | AI Investigation (live) |
|:--:|:--:|
| <img src="assets/readme/shots/incidents.png" width="100%"/> | <img src="assets/readme/shots/investigation.png" width="100%"/> |

| Auditable SOC Workflow | AI Security Assistant |
|:--:|:--:|
| <img src="assets/readme/shots/workflow.png" width="100%"/> | <img src="assets/readme/shots/assistant.png" width="100%"/> |

| Performance Monitoring | Infrastructure Anomaly |
|:--:|:--:|
| <img src="assets/readme/shots/performance.png" width="100%"/> | <img src="assets/readme/shots/infrastructure.png" width="100%"/> |

| Verified Archive (PDF-exportable) | |
|:--:|:--:|
| <img src="assets/readme/shots/archive.png" width="100%"/> | |

</details>

---

## 🏗️ Architecture at a glance

```mermaid
flowchart TB
    subgraph Brain["🧠 Brain VM / central platform"]
        direction TB
        subgraph Native["Native monitoring & security services"]
            ES[Elasticsearch :9200]
            KB[Kibana :5601]
            WZ[Wazuh Manager :1514/1515]
            SUR[Suricata]
            FAL[Falco]
            FSK[Falcosidekick :2801]
            FB[Filebeat]
            TG[Telegraf]
            F2[Fail2Ban / UFW / SSH hardening]
        end
        subgraph Compose["🐳 ARIA Docker Compose"]
            API[ARIA API :8001]
            WRK[ARIA worker]
            RDS[Redis :6380]
            FE[Next.js frontend :3001]
        end
        DB[(SQLite investigations.db)]
    end

    subgraph Monitored["🖥️ Monitored VM / server"]
        AGT[Wazuh Agent]
        MSUR[Suricata]
        MFAL[Falco + Falcosidekick]
        MFB[Filebeat]
        MTG[Telegraf]
    end

    Analyst["👤 SOC Analyst"] --> FE
    FE --> API
    API --> DB
    API --> RDS
    WRK --> ES
    WRK --> DB
    WRK --> RDS
    WRK -.->|SSH :22| Monitored
    ES --> KB
    AGT --> WZ
    MSUR --> MFB --> ES
    MFAL --> ES
    MTG --> ES
    FB --> ES
    TG --> ES
    FAL --> FSK --> ES
    SUR --> FB
    WZ -.-> FB
```

```mermaid
flowchart LR
    A[Monitored VM telemetry] --> B[(Elasticsearch)]
    B --> C[ARIA worker<br/>poll · map · enrich · dedup · correlate]
    C --> D[(SQLite alerts & incidents)]
    D --> E[AI investigation]
    E --> F{approval-gated<br/>Ansible response}
    F --> G[Elasticsearch verification]
    G --> H[archive + PDF]
    H --> I[FastAPI + Next.js dashboard]
```

*Confirmed from current source.*

---

## 🧱 Tech stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.12 · FastAPI · async SQLAlchemy 2.0 + aiosqlite · async Redis · httpx |
| **State** | SQLite (WAL + FTS5) — `data/investigations.db` · hand-rolled migrations |
| **Frontend** | Next.js 16 (App Router) · React · SWR · WebSocket · shadcn/ui · Tailwind |
| **Detection** | Wazuh · Suricata · Falco / Falcosidekick · Filebeat · Telegraf |
| **Source of truth** | Elasticsearch (read-only) + Kibana |
| **Response** | Ansible (staged, dry-run, rollback) via subprocess |
| **AI / LLM** | Ollama (local default) · Google Gemini · OpenRouter · NVIDIA NIM — `provider=auto` |
| **Auth** | JWT (python-jose) · bcrypt (passlib) · admin-secret gating |
| **Packaging** | Docker Compose (redis · api · worker · frontend) · reportlab (PDF) |

---

## 🚀 Deployment roles

| Role | Hosts | Does **not** host |
|---|---|---|
| **Brain VM / central platform** | Elasticsearch, Kibana, Wazuh Manager, Filebeat, Suricata, Falco/Falcosidekick, Telegraf, host hardening **+** the ARIA Compose stack (Redis, API, worker, frontend). | Monitored endpoints' agents or duplicated worker logic. |
| **Monitored VM / server** | Wazuh Agent, Filebeat, Suricata, Falco/Falcosidekick, Telegraf — sends telemetry to the Brain VM. | ARIA API, worker, Redis, SQLite, Kibana, Elasticsearch, Wazuh Manager. |
| **Native services** | Installed by `aria-tools-setup/tools/setup_script_telegraf.sh` (systemd). | These are not Docker Compose services. |
| **ARIA Compose** | `redis`, `api`, `worker`, `frontend` from `aria-application/docker-compose.yml`. | These do not replace Elasticsearch/Wazuh/Kibana. |

### Safe deployment order

```mermaid
flowchart LR
    A[Prepare Brain VM & network] --> B[Configure ARIA .env outside git]
    B --> C[Run scripts/install_brain_vm.sh]
    C --> D[Validate native tools & containers]
    D --> E[Onboard monitored VMs separately]
    E --> F[Keep remediation disabled until Ansible/SSH is validated]
```

---

## 🗂️ Repository map

```text
aria-application/    ARIA FastAPI backend, worker, Next.js frontend, Docker Compose
aria-tools-setup/    Native Brain VM monitoring/security tool installer scripts
ansible-vm-setup/    Ansible wrapper for monitored-VM onboarding (sanitize before use)
docker-compose/      Duplicate Compose reference (not the primary authority)
aria-report/         Final-year project report and historical diagrams (reference only)
docs/                Authoritative documentation
scripts/             Operational wrappers, including install_brain_vm.sh
assets/              README media (generated GIFs, animated SVGs, screenshots)
```

---

## 📚 Documentation

- [Architecture](docs/architecture/ARIA_ARCHITECTURE.md) — component placement, data flow, diagrams
- [Brain VM setup](docs/deployment/BRAIN_VM_SETUP.md) — exact central deployment guide
- [Monitored VM onboarding](docs/deployment/MONITORED_VM_ONBOARDING.md) — agent onboarding boundaries
- [Validation & troubleshooting](docs/operations/VALIDATION_AND_TROUBLESHOOTING.md) — safe operational checks
- [Security & secrets](docs/operations/SECURITY_AND_SECRETS.md) — secret handling and current limitations
- [Backup & decommission limitations](docs/operations/BACKUP_AND_DECOMMISSION_LIMITATIONS.md) — what recovery exists and what does not

---

## ⚠️ Safety warnings

- The central setup scripts in `aria-tools-setup/tools/` may **install, purge, reconfigure, start, stop, or harden services** on the host they run on. Run them only on the intended Brain VM, only after review.
- Secrets — `.env`, passwords, tokens, private keys, live inventories, runtime evidence — must **never be committed**.
- The Ansible material in `ansible-vm-setup/` and historical content contains plaintext credentials and must be **sanitized and rotated** before production use.

## 🚧 Confirmed limitations

- **Single central platform** — one Brain VM with local Elasticsearch; no clustering or HA.
- **SQLite workflow state** — operational state lives in a local SQLite database.
- **Published Docker images** — Compose uses mutable `latest` tags.
- **Backup/recovery incomplete** — full-stack, off-host, or DR procedures are not proven.
- **Production hardening required** — TLS termination, exposure boundaries, authorization coverage, SSH host-key verification, and secrets handling need review before production.
- **Not implemented** — Kafka, active Neo4j, Kubernetes, Terraform, SSO, automated cloud provisioning.

---

## 🎓 Project context

ARIA is a final-year engineering graduation project (**PFE**) developed at **ESPRIT** in partnership with **Huawei** (academic year 2025–2026) by **Ghazi Mabrouki**. The full report and presentation material live under [`aria-report/`](aria-report/) and should be treated as **historical/reference** material — current source code overrides it where they conflict.

<div align="center">
<br/>
<sub>Built for analysts who want their tools to <b>act</b>, not just alert. ⚡</sub>
</div>
