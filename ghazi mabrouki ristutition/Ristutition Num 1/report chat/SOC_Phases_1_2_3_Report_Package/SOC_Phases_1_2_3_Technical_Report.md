# SOC Platform Technical Report - Phases 1, 2 and 3

**Project theme:** Intelligent SOC platform for centralized monitoring, backend intelligence, investigation, and controlled response.  
**Prepared on:** 2026-04-28  
**Scope:** Phase 1 - Security Monitoring Foundation, Phase 2 - Huawei Cloud Infrastructure, Phase 3 - Backend Intelligence Layer.

---

## Executive Summary

The project is built progressively. Phase 1 creates the security monitoring foundation by collecting logs, alerts, runtime detections, and metrics using Wazuh, Suricata, Falco, Telegraf, Filebeat, Elasticsearch, and Kibana. Phase 2 provides the Huawei Cloud infrastructure required to host this stack with controlled networking, compute resources, storage, public access through an Elastic IP, and security group protection. Phase 3 adds the backend intelligence layer that transforms raw Elasticsearch data into actionable SOC objects: normalized alerts, correlated incidents, investigations, AI-generated summaries and playbooks, controlled remediation, verification, archives, IPS map events, performance monitoring, AI Assistant interactions, and AI Operator actions.

The complete logic is:

```text
Security Tools -> Elasticsearch -> Backend Intelligence -> Frontend SOC Operations
```

---

# Phase 1 - Security Monitoring Foundation

## 1. Objective

Phase 1 is the visibility foundation of the platform. Its role is to make the infrastructure observable before any backend intelligence or automation is added.

The phase covers:

- Network visibility through Suricata.
- Host and endpoint visibility through Wazuh.
- Runtime and container visibility through Falco.
- Resource and infrastructure visibility through Telegraf.
- Log collection and forwarding through Filebeat and Falcosidekick.
- Central storage and search through Elasticsearch.
- Dashboards and analysis through Kibana.

## 2. Architecture and Data Flow

The architecture starts from security and monitoring sources, moves through the forwarding layer, and ends at the SIEM core.

**Diagram to insert:** Diagram 1 - Global Architecture & Data Flow.

### Data flow

| Source | Forwarding path | Destination |
|---|---|---|
| System logs | Filebeat | Elasticsearch |
| Authentication logs | Filebeat | Elasticsearch |
| Suricata network events | `eve.json` -> Filebeat | Elasticsearch |
| Wazuh host alerts | Filebeat | Elasticsearch |
| Falco runtime alerts | Falcosidekick | Elasticsearch |
| Telegraf metrics | Direct output | Elasticsearch |
| Elasticsearch data | Kibana | Dashboards and analysis |

## 3. Deployment, Ports, Configuration and Requirements

Phase 1 can run on a single Ubuntu host. The main system services are Elasticsearch, Kibana, Filebeat, Suricata, Wazuh Manager, and Telegraf. Falco and Falcosidekick are deployed as Docker services.

**Diagram to insert:** Diagram 2 - Deployment, Technical Setup & Requirements.

### Main ports

| Service | Port | Purpose |
|---|---:|---|
| Elasticsearch | 9200 HTTPS | API, indexing, search |
| Kibana | 5601 HTTPS | Web interface |
| Wazuh Manager | 1514 TCP | Agent events |
| Wazuh Manager | 1515 TCP | Agent registration |
| Falcosidekick | 2801 HTTP | Falco event receiver |

### Main configuration files

| Tool | Main configuration path |
|---|---|
| Elasticsearch | `/etc/elasticsearch/*` |
| Kibana | `/etc/kibana/kibana.yml` |
| Filebeat | `/etc/filebeat/filebeat.yml`, `/etc/filebeat/modules.d/*` |
| Suricata | `/etc/suricata/suricata.yaml` |
| Wazuh | `/var/ossec/*` |
| Falco / Falcosidekick | `docker-compose.yml`, `.env` |
| Telegraf | `/etc/telegraf/telegraf.conf` |

### Hardware requirements

| Level | CPU | RAM | Disk |
|---|---:|---:|---:|
| Minimum lab | 4 cores | 8 GB | 50 GB |
| Recommended | 8 cores | 16 GB | 100 GB |

## 4. Visibility Layers and Tool Roles

**Diagram to insert:** Diagram 3 - Visibility Layers & Tool Roles.

| Layer | Tool | Role |
|---|---|---|
| Network | Suricata | Detects suspicious traffic, scans, IDS alerts |
| Host / Endpoint | Wazuh | Detects failed logins, file changes, host alerts |
| Runtime / Container | Falco | Detects suspicious syscalls, processes, containers |
| Resource / Infrastructure | Telegraf | Collects CPU, RAM, disk, network, load metrics |
| Collection | Filebeat / Falcosidekick | Ships logs and alerts to Elasticsearch |
| Central Analysis | Elasticsearch | Stores, indexes, and searches all data |
| Visualization | Kibana | Provides dashboards and analysis |

## 5. Phase 1 Outcome

Phase 1 transforms isolated monitoring tools into a coherent visibility architecture. It provides the data foundation required for the backend.

---

# Phase 2 - Huawei Cloud Infrastructure

## 1. Objective

Phase 2 moves the project from local design to a real cloud-hosted environment using Huawei Cloud.

The goal is to provision a secure, isolated, and sized infrastructure for running the SOC monitoring stack.

## 2. Cloud Infrastructure

**Diagram to insert:** Diagram 4 - Huawei Cloud Infrastructure Foundation.

### Main cloud components

| Component | Value / role |
|---|---|
| Cloud provider | Huawei Cloud |
| Network | VPC / private network |
| Subnet | Private subnet for internal communication |
| Security | Security group with controlled firewall rules |
| Public access | Elastic IP `193.95.30.97` |
| Compute | ECS virtual machine |
| Operating system | Ubuntu Server |
| vCPU | 64 vCPU |
| RAM | 128 GB |
| Storage | 100 GB |
| Hosted stack | Elasticsearch, Kibana, Wazuh, Suricata, Falco, Telegraf, Filebeat |

## 3. Security Group Strategy

The security group should expose only what is needed:

| Service | Port | Recommendation |
|---|---:|---|
| SSH | 22 | Restrict to admin IP |
| Kibana | 5601 | Restrict to analyst/VPN/admin network |
| Elasticsearch | 9200 | Keep internal, not public |
| Wazuh events | 1514 | Allow only if external agents are used |
| Wazuh registration | 1515 | Allow only if external agents are used |
| Falcosidekick | 2801 | Internal only |

## 4. Phase 2 Outcome

Phase 2 provides the infrastructure backbone for the SOC platform: controlled compute, storage, private networking, EIP, and firewall rules.

---

# Phase 3 - Backend Intelligence Layer

## 1. Main Idea

After Phases 1 and 2, the platform has security data in Elasticsearch and dashboards in Kibana. However, Elasticsearch mostly contains raw technical documents. Phase 3 transforms that raw data into SOC intelligence.

The backend intelligence layer includes:

- Alert ingestion and enrichment.
- Incident correlation.
- Watcher and investigation lifecycle.
- AI response engine.
- Approval, execution, verification, and archive.
- Performance monitoring and remediation.
- IPS attack visualization.
- Contextual AI Assistant.
- AI Operator for natural-language to Ansible operations.

The developer documentation index identifies these eight per-feature technical documents, their backend entries, frontend pages, and known status gaps.

**Diagram to insert:** Diagram 5 - Global Phase 3 Backend Intelligence Layer.

## 2. Alert Ingestion and Enrichment Pipeline

The alert pipeline polls Elasticsearch indices for Wazuh, Suricata, Falco, Filebeat, and custom patterns. It normalizes, deduplicates, filters noise, enriches with GeoIP/MITRE, tracks campaigns, checks whitelist entries, persists alerts locally, and can forward upstream.

**Diagrams to insert:** Diagram 6 - Alert Ingestion & Enrichment Pipeline; Diagram 7 - Cursor-Based Elasticsearch Polling; Diagram 8 - Raw Document to Clean SOC Alert; Diagram 9 - Enrichment and Context Building.

### Core logic

```text
ES raw documents -> poller -> mapper -> dedup -> noise/severity filter -> enrichment -> campaign tracking -> whitelist -> SQLite Alert
```

### Main files

| File | Role |
|---|---|
| `pipeline/poller/main.py` | Forwarder loop and cursor management |
| `pipeline/poller/alert_processor.py` | Main `process_single_alert()` pipeline |
| `pipeline/mappers/*.py` | Source-specific mappers |
| `pipeline/enrichment/geoip.py` | GeoIP enrichment |
| `pipeline/enrichment/mitrecraft.py` | MITRE mapping |
| `pipeline/dedup.py` | Deduplication |
| `pipeline/noise_learner.py` | Auto-learned noise filtering |

### Result

The backend creates a normalized `Alert` record with source, source ID, title, severity, category, source/destination IPs, hostname, tags, IOCs, metadata, and occurrence count.

## 3. Local Storage and SOC Data Model

**Diagram to insert:** Diagram 10 - Local Storage and SOC Data Model.

The backend uses a local SQLite data model to maintain alerts, incidents, investigations, approvals, playbook runs, fix verification, and archives.

Important entities:

| Table | Purpose |
|---|---|
| `Alert` | Stores clean alerts |
| `Incident` | Stores grouped security cases |
| `AlertIncidentLink` | Links alerts to incidents with correlation confidence |
| `Investigation` | Stores investigation context and AI output |
| `PlaybookApproval` | Stores approval decisions |
| `PlaybookRun` | Stores execution results |
| `FixVerification` | Stores verification verdicts |
| `Archive` | Preserves resolved case history |

## 4. Incidents and Correlation

The incident module correlates related alerts into incidents using attack patterns, kill-chain progression, time-window clustering, shared observables, and MITRE overlap.

**Diagram to insert:** Diagram 11 - Incident Correlation.

### Creation triggers

- Critical alerts always create an incident.
- Known patterns such as SSH brute force, port scan, malware, or C2 create incidents.
- Kill chain with two or more MITRE phases creates incidents.
- Medium severity plus multiple recent alerts can create an incident.

### Example

Three Wazuh SSH brute-force alerts plus one Suricata port scan from the same source IP within 10 minutes can create a critical incident.

## 5. Watcher and Investigations

The watcher polls for open incidents without investigations, creates `Investigation` rows, builds context, and triggers the AI engine.

**Diagram to insert:** Diagram 12 - Watcher and Investigation Creation.

### Investigation context includes

- Timeline of linked alerts.
- IOCs: IPs, ports, services, domains, hashes, usernames, file paths.
- MITRE tactics and techniques.
- Behavioral indicators.
- Authentication pattern analysis.
- Attack type.
- Dynamic risk score.

## 6. AI Response Engine

The AI Response Engine generates investigation summaries, narratives, risk assessments, and Ansible playbooks. It supports multi-provider LLM routing, circuit breaker protection, fallback generation, structured parsing, storage, and auto-approval evaluation.

**Diagram to insert:** Diagram 13 - AI Response Engine.

### Processing logic

```text
Investigation context -> circuit breaker -> prompt builder -> LLM -> parser -> Investigation storage -> approval check
```

### Output

- `Investigation.summary`
- `Investigation.narrative`
- `Investigation.risk_score`
- `Investigation.playbook_yaml`
- possible `PlaybookApproval` row
- WebSocket update

## 7. Approval, Execution, Verification and Archive

Generated remediation should not be executed blindly. It goes through guardrails, confidence checks, human or automatic approval, Ansible execution, fix verification, and archive.

**Diagram to insert:** Diagram 14 - Approval, Execution, Verification and Archive.

### Possible verification outcomes

| Outcome | Meaning |
|---|---|
| `likely_fixed` | Remediation succeeded and symptoms stopped |
| `not_fixed` | Alerts or metric anomalies continue |
| `inconclusive` | Evidence is not clear |
| `playbook_failed_but_quiet` | Playbook failed but symptoms stopped |

## 8. Performance Monitoring and Remediation

Performance monitoring polls `telegraf-*` metrics, stores current metrics/history/baselines in Redis, detects anomalies using thresholds and statistical baselines, determines root cause and playbook type, creates performance investigations, and verifies results after remediation.

**Diagram to insert:** Diagram 15 - Performance Monitoring and Remediation.

### Metrics

- CPU usage and I/O wait.
- Memory used percentage.
- Disk used percentage and inode usage.
- Network received/sent/drops.
- Load average.
- Procstat CPU/memory.
- Netstat TCP established connections.

## 9. IPS Attack Visualization

IPS Attack Visualization merges local and upstream alerts into geo-enriched events, deduplicates them, geolocates sources, categorizes attacks, derives lifecycle, and serves map data, statistics, live events, filters, and links.

**Diagram to insert:** Diagram 16 - IPS Attack Visualization.

### Lifecycle examples

| Lifecycle | Meaning |
|---|---|
| `active` | Attack visible but no response completed |
| `investigating` | Investigation exists |
| `mitigated` | Remediation or verification indicates mitigation |
| `blocked` | Response chain indicates block/remediation complete |

## 10. AI Assistant

The Contextual AI Assistant allows operators to ask questions about SOC data. It extracts keywords, fetches entities from SQLite/Redis/ES, ranks records by relevance, builds a context prompt, calls an LLM or fallback, suggests actions, and persists the conversation.

**Diagram to insert:** Diagram 17 - Contextual AI Assistant.

## 11. AI Operator

The AI Operator translates natural-language operational requests into Ansible playbooks. It reasons about intent, matches templates, generates playbooks if needed, stores pending runs, auto-executes low-risk read-only checks, requires approval for mutating actions, runs Ansible, parses output, and returns structured analysis.

**Diagram to insert:** Diagram 18 - AI Operator.

### Example templates

- Disk usage.
- RAM usage.
- CPU processes.
- Open ports.
- SSH failures.
- Service status.
- Firewall rules.
- Docker containers.
- File read.
- Package check.

## 12. Background Jobs and Reliability

The backend runs several background jobs:

| Task | Role |
|---|---|
| Alert Forwarder | Polls Elasticsearch and processes alerts |
| Incident Correlation | Groups related alerts into incidents |
| Incident Watcher | Creates investigations from open incidents |
| Performance Poller | Reads Telegraf metrics |
| Performance Monitoring | Detects anomalies and triggers response |
| Retry Queue | Re-sends failed upstream alerts |
| Watchdog | Logs memory and process health |
| Backup | Copies DB, cursor state, tickets, logs |

## 13. Known Gaps to Close

From the developer package:

- `api/routes/performance.py` Part B is incomplete for disk-analysis, history, and root-cause endpoints.
- `api/routes/incidents.py` was truncated during delivery.
- Frontend pages for `/metrics`, `/assistant`, and `/operator` need verification.
- `api/routes/monitoring.py` may need export if it exists.

---

# Conclusion

Phase 1 creates visibility. Phase 2 provides the cloud infrastructure. Phase 3 transforms raw data into SOC intelligence and operations.

The final platform logic is:

```text
Monitor -> Centralize -> Analyze -> Correlate -> Investigate -> Respond -> Verify -> Archive
```

The result is a SOC platform capable of monitoring multiple layers, hosting them on Huawei Cloud, and transforming telemetry into actionable operations through a backend intelligence layer.

---

# Diagram Appendix

All Mermaid diagrams are provided in the separate file:

```text
SOC_Phase_Diagrams_Mermaid.md
```

---

# Source Documentation Used

- `INDEX.md`
- `core_alert_pipeline.md`
- `core_incidents.md`
- `core_watcher.md`
- `core_ai_response.md`
- `performance_monitoring.md`
- `ips_map.md`
- `ai_assistant.md`
- `ai_operator.md`
