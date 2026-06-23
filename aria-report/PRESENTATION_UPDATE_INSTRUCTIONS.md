# ARIA Presentation Update Instructions

> **Source file to update:** `ghazi mabrouki ristutition/english Version1.pptx`
> **Reference / canonical version:** `aria-report/presentation-restructured.pptx`
> **All diagrams:** `aria-report/assets/diagrams/`
> **All screenshots:** `aria-report/assets/screenshots/` and `ARIA Screenshots/`

## Executive recommendation

**Do not patch the old deck slide-by-slide.** The cleanest and fastest path is:

1. Open `aria-report/presentation-restructured.pptx` as the new base.
2. Copy over only the official ESPRIT cover page / school branding from `english Version1.pptx` if required.
3. Insert the real screenshots listed below into Slide 27.
4. Export to PDF.

If your worker must instead modify `english Version1.pptx`, the detailed instructions below are the exact changes required to bring it to the same level.

---

## 1. Critical text corrections (must fix)

These are factual errors or inconsistencies that were fixed in the restructured deck.

| Location in old deck | Current (wrong/outdated) | Change to |
|---|---|---|
| Slide 9 — Security Strategy table | Backend API **8000/8001** | Backend API **8001** only |
| Slide 9 — Security Strategy table | Keep Elasticsearch line correct: *Never publicly exposed* | Keep it, and add **Redis** as internal-only (port 6379) |
| Slide 25 — Non-Functional Requirements | **“Elasticsearch expose publiquement”** under Security | Remove this line completely. Replace with **“Elasticsearch internal-only; no public exposure”** |
| Slide 7 — Huawei Cloud Environment | Public IP `193.95.30.97` shown in full | Redact or replace with placeholder `203.0.113.x` / `your.elastic.ip` |
| Slide 7 / 31 | 64 vCPU / 128 GB RAM shown as production sizing | Keep only if it is the real deployed sizing; otherwise label as “reference sizing” |
| Slide 11 — Phase 3 overview | Lists 12 steps as text only | Add the explicit **“12-Step Intelligence Pipeline”** diagram / numbered flow |
| Slide 5 — Phase 1 result | Mentions only native + Docker services | Add **Redis** as a Compose service used by ARIA |
| Slide 13 / 17 / 19 / 21 | “Local Storage (SQLite)” only | Clarify: **SQLite** for operational data, **Redis** for cache / dedup / cursors / metrics |
| Slide 21 — Operational modules | “AI Operator N” (text is cut off) | Complete the AI Operator description and add its diagram |
| Slide 25 — NFRs | Missing validation/test numbers | Add: **910 tests**, **146 Python modules**, API root returns `200 OK` |
| Slide 29 — Methodology | “3 major phases corresponding to functional deliverables” | Keep phases as deliverables, but emphasize **2-week Agile sprints**, not phase-based sprints |

---

## 2. Structural reorganization (recommended final order)

The restructured deck uses this **10-section, 36-slide flow**. Reorder the old slides to match:

1. **Title** — ARIA / Adaptive Response Intelligence Automation
2. **Problem Statement** — SOC operations are fragmented and slow
3. **Project Objectives** — Three pillars: visibility, intelligence, controlled response
4. **State of the Art** — SOC/SOAR market landscape table
5. **Identified Gap** — What is missing today
6. **Three-Phase Roadmap** — Phase 1 → Phase 2 → Phase 3
7. **High-Level Architecture** — Four-tier SOC automation stack
8. **Deployment Architecture** — Brain VM + Monitored VM on Huawei Cloud
9. **Phase 1: Visibility Layers & Tools**
10. **Phase 1: Data Flow**
11. **Phase 1: Central Setup Script Flow**
12. **Phase 1: Hardening & Validation**
13. **Phase 2: Huawei Cloud Topology**
14. **Phase 2: Security Strategy & Ports**
15. **The 12-Step Intelligence Pipeline**
16. **Phase 3: Alert Ingestion**
17. **Phase 3: Normalization**
18. **Phase 3: Deduplication & Noise Filtering**
19. **Phase 3: Incident Correlation**
20. **Phase 3: Investigation Lifecycle**
21. **Phase 3: AI Response Engine**
22. **Phase 3: Approval → Execution → Verification → Archive**
23. **Phase 3: Performance Monitoring & Remediation**
24. **Phase 3: IPS Attack Visualization**
25. **Phase 3: AI Assistant & AI Operator**
26. **Frontend Navigation Map**
27. **Key Dashboards** *(screenshot collage)*
28. **End-to-End SOC Scenario**
29. **Onboarding a New Server**
30. **Asset Payload & Validation**
31. **Production Deployment Workflow**
32. **Functional Requirements**
33. **Non-Functional Requirements**
34. **Methodology & Testing**
35. **Results & Achievements**
36. **Thank You / Q&A**

---

## 3. Slides to remove from the old deck

- **Slide 8** — empty slide.
- **Slide 12** — Table of Contents that currently sits in the middle of Phase 3. Either delete it or move it to Slide 2/3.
- **Slides 14, 16, 18, 20** — empty placeholder slides between step slides.
- **Slides 33–53** — title-only “Diagram 1 … Diagram 14” and “Phase 1 Architecture” placeholders. Replace each with the actual diagram image (see list below).
- **Slide 54** — duplicate “Existing Solutions” divider; merge content into Slide 4/5.
- **Slide 56–57** — duplicate architecture overview; merge into Slide 7/8.

---

## 4. Diagrams to insert / replace

All files are in `aria-report/assets/diagrams/`.

### Global / architecture diagrams

| Slide topic | Diagram file to use |
|---|---|
| High-Level Architecture | `aria_component_architecture.png` |
| Deployment Architecture (Brain VM + Monitored VM) | `cloud_deployment_diagram.png` |
| Global Data Flow (Phase 1) | `monitoring_data_flow.png` |
| Huawei Cloud Environment | `phase2_huawei_cloud_environment.png` |
| Frontend Navigation Map | `frontend_navigation_map.png` |

### Phase 1 diagrams

| Slide topic | Diagram file to use |
|---|---|
| Visibility Layers & Tools | `phase1_visibility_layers.png` |
| Central Setup Script Flow | `act_central_setup.png` |

### Phase 3 diagrams (replace old “Diagram 1–14” placeholders)

| Old placeholder | Diagram file to use |
|---|---|
| Diagram 1 — Global Phase 3 Backend Intelligence Layer | `phase3_global_backend.png` |
| Diagram 2 — Alert Ingestion & Enrichment Pipeline | `seq_alert_ingestion.png` |
| Diagram 3 — Cursor-Based Elasticsearch Polling | `phase3_cursor_polling.png` |
| Diagram 4 — Raw Document to Clean SOC Alert | `phase3_raw_to_alert.png` |
| Diagram 5 — Enrichment and Context Building | `phase3_enrichment_context.png` |
| Diagram 6 — Local Storage and SOC Data Model | `phase3_data_model.png` |
| Diagram 7 — Incident Correlation | `phase3_incident_correlation.png` |
| Diagram 8 — Watcher and Investigation Creation | `phase3_watcher_investigation.png` |
| Diagram 9 — AI Response Engine | `phase3_ai_response.png` |
| Diagram 10 — Approval, Execution, Verification and Archive | `phase3_approval_execution.png` |
| Diagram 11 — Performance Monitoring and Remediation | `phase3_performance_remediation.png` |
| Diagram 12 — IPS Attack Visualization | `feature_ips_dataflow.png` |
| Diagram 13 — AI Assistant | `phase3_ai_assistant.png` |
| Diagram 14 — AI Operator | `phase3_ai_operator.png` |

### Extra diagrams that strengthen the deck

Use these if you need more detail on specific slides:

- `investigation_state_machine.png` — Slide 20 Investigation Lifecycle
- `act_monitored_bootstrap.png` — Slide 29 Onboarding
- `seq_production_rollout.png` — Slide 31 Production Deployment
- `feature_metrics_dataflow.png` — if you add a dedicated Metrics slide
- `feature_dashboard_dataflow.png` — if you add a dedicated Dashboard slide

---

## 5. Screenshots to provide for Slide 27 “Key Dashboards”

Use these representative screenshots from `aria-report/assets/screenshots/`. Crop or annotate them so they are readable on a slide.

| View | Screenshot file |
|---|---|
| Dashboard overview | `aria_dashboard.png` or `app_dashboard_2.png` |
| Alerts list + detail | `app_alerts_list.png` + `app_alert_detail.png` |
| Incident timeline | `app_incident_timeline.png` |
| Investigation AI result | `app_investigation_ai.png` |
| IPS world map | `aria_ips_map.jpg` or `app_ips_events.jpg` |
| Runtime security | `aria_runtime_list.png` or `aria_runtime_evidence.png` |
| Infrastructure metrics | `app_metrics_2.png` or `aria_metrics.png` |
| AI assistant chat | `aria_assistant.png` or `app_assistant_chat.png` |
| Settings / assets | `aria_settings_overview.png` or `app_assets_list.png` |
| API health check | `aria_api_root.png` |

> **Important:** Before using any screenshot, blur or crop out any real passwords, API keys, private IPs, or secret headers. Use placeholders like `Configured` / `Replace secret` where needed.

---

## 6. New content to add (not present in old deck)

Add these as new slides or merge into existing ones:

1. **End-to-End SOC Scenario** — Walk through one concrete chain:
   - Wazuh SSH brute-force alert
   - Normalized + enriched (GeoIP, MITRE T1110)
   - Correlated into incident
   - AI generates summary + Ansible playbook
   - Analyst approves (admin-secret gate)
   - Ansible blocks source IP + hardens sshd
   - Verifier confirms no new brute-force events
   - Case archived with audit trail

2. **Onboarding a New Server** — Show the bootstrap flow:
   - Bootstrap script installs Wazuh agent, Filebeat, Falco, Telegraf
   - Registers with central Elasticsearch
   - ARIA creates `MonitoredAsset` record
   - Source validation confirms data arrival

3. **Asset Payload Example** — Add the JSON payload used to register an asset:
   ```json
   {
     "name": "dash-linux",
     "host": "192.168.1.20",
     "sources": {
       "wazuh": "wazuh-alerts-4.x-*",
       "suricata": "filebeat-*",
       "falco": "falco-events-*",
       "telegraf": "telegraf-*"
     },
     "ansible": {
       "user": "ansible",
       "ssh_key_ref": "dash-linux-key",
       "become": true
     }
   }
   ```

4. **Production Deployment Workflow** — Show staged rollout: install central stack → validate telemetry → deploy ARIA backend → deploy frontend → onboard first monitored server → enable remediation.

5. **Validation & Testing Numbers** — Add to Methodology or Results:
   - 146 Python modules
   - 910 automated tests
   - API root returns `200 OK`
   - Backend build/lint passes
   - Frontend TypeScript/build passes
   - Multi-server asset scoping validated

6. **Redis role** — Mention Redis is used for cursors, cache, deduplication, and performance metrics.

7. **Neo4j / Kafka clarification** — State that Neo4j is a disabled placeholder and Kafka is not implemented, to avoid examiner questions.

---

## 7. Branding / cover page

- Title should read **“ARIA — Adaptive Response Intelligence Automation”** (not “Intelligent Platform for Supervision and Security Automated”).
- Subtitle: **“AI-Assisted Security Operations, Incident Response, and Remediation Platform”**.
- Keep author name, school, host organization (Huawei Technologies — Tunis, Tunisia), and academic year.
- If the school requires the official ESPRIT cover page, use the one from `aria-report/frontmatter/cover-page.tex` / `assets/cover/esprit-cover-front.png` as reference.

---

## 8. Final deliverable checklist

Before presenting, verify:

- [ ] All backend/API port references are **8001** (not 8000/8001).
- [ ] Elasticsearch is described as **internal-only** everywhere.
- [ ] Redis appears in architecture/deployment slides.
- [ ] The 12-step pipeline is shown as a numbered diagram, not just a list.
- [ ] All old “Diagram 1–14” placeholder slides now contain real images.
- [ ] Slide 27 uses real, redacted screenshots.
- [ ] No real public IP, password, or secret appears in any screenshot or diagram.
- [ ] Validation numbers (910 tests, 146 modules, API 200 OK) are present.
- [ ] Spelling/language checked (e.g. “expose publiquement”, “Workflow d'Approval”, “Phase 3 transforme” mixed in English slides).
- [ ] Exported to PDF for backup.

---

## Assets to hand to your worker

Provide your worker with:

1. This instruction file.
2. The old deck: `ghazi mabrouki ristutition/english Version1.pptx`.
3. The new reference deck: `aria-report/presentation-restructured.pptx`.
4. The diagrams folder: `aria-report/assets/diagrams/`.
5. The screenshots folder: `aria-report/assets/screenshots/`.
6. (Optional) the raw screenshots folder: `ARIA Screenshots/`.
