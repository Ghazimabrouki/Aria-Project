# Weekly Progress Report — OpenSOAR / SOC Backend

| | |
|:---|:---|
| **Period** | April 14 – April 18, 2026 |
| **Author** | Ghazi Mabrouki |
| **Project** | Huawei PFE — SOC Pipeline & Observability Integration |
| **Overall Goals** | 1. Strengthen the SOC pipeline, observability integration, and AI enrichment validation.<br>2. Improve Telegraf-based metrics ingestion and dashboard automation.<br>3. Ensure Falco events are indexed and visible in OpenSearch/Elasticsearch.<br>4. Prepare local AI enrichment setup and consolidate technical validation. |

---

## 1. Executive Summary

This week was dedicated to hardening the data-collection and observability layers of the SOC backend. We consolidated the backend architecture documentation, resolved Falco-to-OpenSearch visibility issues, streamlined Telegraf metrics ingestion by reusing existing Filebeat backend settings, automated Kibana dashboard onboarding, and prepared the end-to-end pipeline logic for Python backend modules. The week concluded with full end-to-end testing and an updated technical report.

---

## 2. Day-by-Day Breakdown

### Day 1 — Review SOC Backend Architecture & Consolidate Documentation

| Field | Detail |
|:---|:---|
| **Task** | Review SOC backend architecture and consolidate technical documentation |
| **Progress** | Reviewed backend architecture, data flow, active modules, and main production gaps. Consolidated all notes into a single project-documentation file. |
| **Courses Learned (I-Learning)** | LAB KOOLAB (NETWORK) |
| **Difficulties Faced** | Large codebase to summarize |
| **Support Needed** | Door Access |

**Key Activities:**
- Mapped the complete data-flow from alert ingestion (Wazuh, Suricata, Falco, Filebeat) through Elasticsearch, enrichment, forwarding, AI investigation, and remediation.
- Catalogued active modules and identified production gaps (missing ASN GeoIP DB, aggressive incident-creation rules, partial observable extraction).
- Produced a consolidated technical-reference document for the team.

---

### Day 2 — Patch Falco Pipeline for OpenSearch/Elasticsearch Visibility

| Field | Detail |
|:---|:---|
| **Task** | Patch Falco pipeline for OpenSearch/Elasticsearch visibility |
| **Progress** | Adjusted the Falco setup flow so events are forwarded correctly and become visible through proper credential resolution and indexing. |
| **Courses Learned (I-Learning)** | — |
| **Difficulties Faced** | Falco / OpenSearch compatibility |
| **Support Needed** | Door Access |

**Key Activities:**
- Diagnosed credential-resolution failures between Falco outputs and the OpenSearch ingestion endpoint.
- Updated indexing templates and index-pattern matching so Falco security events land in the correct searchable indices.
- Verified end-to-end visibility in OpenSearch Discover / Kibana.

---

### Day 3 — Improve Telegraf Integration & Kibana Dashboard Automation

| Field | Detail |
|:---|:---|
| **Task** | Improve Telegraf integration and Kibana dashboard automation |
| **Progress** | Improved the Telegraf path by reusing Filebeat backend settings, automating dashboard import, and setting the metrics dashboard as the landing page. |
| **Courses Learned (I-Learning)** | LAB KOOLAB (NETWORK) |
| **Difficulties Faced** | Dynamic backend settings |
| **Support Needed** | Door Access |

**Key Activities:**
- Aligned Telegraf output configuration with existing Filebeat backend settings (Elasticsearch URL, credentials, TLS) to avoid duplicated secret management.
- Scripted automatic import of the SOC metrics dashboard into Kibana.
- Set the metrics dashboard as the default Kibana landing page for faster operator access.

---

### Day 4 — Prepare End-to-End Pipeline Logic (Python Backend)

| Field | Detail |
|:---|:---|
| **Task** | Start prepare logic of pipelines of the backend python |
| **Progress** | Drafted the END-2-END architecture for the Python backend pipeline modules. |
| **Courses Learned (I-Learning)** | — |
| **Difficulties Faced** | Resource and integration planning |
| **Support Needed** | Door Access |

**Key Activities:**
- Designed the end-to-end flow: ES poll → mapper → enrichment → deduplication → forwarder → incident watcher → AI engine → approval → Ansible execution → fix verification → archive.
- Identified required Python modules, async task boundaries, and inter-process communication points.
- Documented resource requirements (Redis cursors, SQLite session handling, NVIDIA NIM API quotas).

---

### Day 5 — End-to-End Testing & Weekly Technical Report Update

| Field | Detail |
|:---|:---|
| **Task** | Test end-to-end logic and update weekly technical report |
| **Progress** | Reviewed the end-to-end workflow, highlighted strengths and remaining gaps. |
| **Courses Learned (I-Learning)** | — |
| **Difficulties Faced** | Some modules still partial |
| **Support Needed** | Door Access |

**Key Activities:**
- Ran end-to-end validation of the pipeline from alert ingestion through AI investigation.
- Confirmed working components: Elasticsearch polling, mappers, GeoIP/MITRE enrichment, OpenSOAR forwarding, data-usage pipeline, incident watcher.
- Flagged partially implemented modules for next-sprint attention (observable-extraction depth, correlation multi-dimensionality).
- Produced this weekly technical report.

---

## 3. Goals vs. Achievement

| Goal | Status | Evidence |
|:---|:---|:---|
| **Goal 1:** Improve Telegraf-based metrics ingestion and dashboard automation | ✅ Completed | Telegraf reusing Filebeat settings; automated dashboard import; metrics dashboard set as landing page |
| **Goal 2:** Ensure Falco events are indexed and visible in OpenSearch/Elasticsearch | ✅ Completed | Falco events now visible in OpenSearch after credential-resolution and indexing fixes |
| **Goal 3:** Prepare local AI enrichment setup and consolidate technical validation | 🔄 In Progress | Architecture documented; NVIDIA NIM integration verified in prior week; full local validation pending next sprint |

---

## 4. Cross-Cutting Difficulties & Support Needs

| Difficulty | Impact | Mitigation / Request |
|:---|:---|:---|
| Large codebase to summarize | Slower initial onboarding | Documentation now consolidated; future reviews will be faster |
| Falco / OpenSearch compatibility | Blocked security-event visibility | Resolved through credential and index-template fixes |
| Dynamic backend settings | Telegraf config drift | Unified Telegraf + Filebeat settings under one config source |
| Resource and integration planning | Pipeline architecture delays | END-2-END architecture document completed |
| Some modules still partial | Incomplete E2E automation | Flagged for next sprint; no blockers for current deliverables |
| **Door Access** | Daily logistics | Support needed to maintain regular on-site presence |

---

## 5. Lessons Learned (I-Learning)

- **LAB KOOLAB (NETWORK)** — Reinforced understanding of network-layer configurations and how they affect log-shipping pipelines (Falco → OpenSearch, Telegraf → Elasticsearch).
- **Configuration Reuse** — Aligning Telegraf with existing Filebeat backend settings eliminated redundant credential management and reduced misconfiguration risk.
- **Index Lifecycle Management** — Proper index templates and credential resolution are critical for observability tools to trust and display security events.

---

## 6. Next Week Priorities

1. **Complete local AI enrichment validation** — Verify NVIDIA NIM / Ollama fallback chains in the local environment.
2. **Address partial modules** — Deepen observable extraction and expand correlation dimensions (dest_ip, username, hostname).
3. **Aggressive incident-creation rule review** — Tune Rule #10 (`tracked_count >= 1`) to reduce noise.
4. **GeoIP ASN database** — Acquire and integrate MaxMind GeoLite2-ASN.mmdb.
5. **Operator onboarding** — Walk the SOC team through the new consolidated documentation and automated Kibana dashboards.

---

## 7. Files / Artifacts Produced

| Artifact | Location / Status |
|:---|:---|
| Consolidated backend architecture notes | Project documentation file (Day 1) |
| Falco pipeline patch | Applied to Falco output + OpenSearch index templates (Day 2) |
| Telegraf integration improvements | `config/telegraf_procstat.conf` + Kibana dashboard import script (Day 3) |
| END-2-END pipeline architecture | Architecture document (Day 4) |
| Weekly technical report | This file (Day 5) |

---

*Report compiled on: April 17, 2026*
