# OpenSOAR ARIA — Presentation Slides

> **Project**: Adaptive Response Intelligence Automation (ARIA)  
> **Author**: Ghazi Mabrouki  
> **Institution**: Huawei PFE — ISI Kef  
> **Date**: April 2026  
> **Version**: 2.0 (Verified against Current Codebase)

---

## Slide 1 — Title

# **ARIA: AI-Powered Security Orchestration, Automation & Response**

**Ghazi Mabrouki**

Institut Supérieur d'Informatique du Kef

Professional Final Year Project (PFE) — Huawei Technologies

April 2026

---

## Slide 2 — The Problem

# SOC Alert Fatigue is Real

### Alert Volume in Our Environment

| Source | Alerts | Type |
|--------|--------|------|
| Wazuh | 130 | Host IDS |
| Falco | 648 | Container runtime |
| Suricata | 1,799 | Network IDS |
| **Total** | **2,577** | — |

### The Manual Bottleneck (per incident)
1. Read alert → 2 min
2. Investigate source IP, process, rule → 5 min
3. Correlate with other alerts → 10 min
4. Write remediation playbook → 15 min
5. Get approval, execute → 10 min

**Total: 42 minutes per incident**

### Meanwhile, attackers move in minutes

---

## Slide 3 — The Solution

# ARIA: From Alert to Fix in Under 2 Minutes

```
[Alert] → [AI Analysis] → [Playbook] → [Approve] → [Execute] → [Verify]
  0s         30s            20s          10s         30s          15s
                                                    ──────────────────
                                                     Total: ~105 seconds
```

### What ARIA Does
- **Ingests** 4 security sources into a local SQLite database
- **Correlates** alerts into incidents using 13 attack-type rules
- **Generates** AI investigations with Ansible playbooks via local LLM
- **Presents** them for one-click analyst approval
- **Executes** approved playbooks via Ansible with SSH pre-flight validation
- **Verifies** fixes and archives results

### Key Differentiator
**Zero cloud AI dependencies** — All inference runs locally via Ollama

---

## Slide 4 — Architecture Overview

# Four-Layer Architecture

```
┌─────────────────────────────────────────┐
│  FRONTEND — Next.js 16 + Tailwind      │  15 pages, real-time WebSocket
│  56,948 lines TypeScript               │  Dashboard, Alerts, Incidents,
├─────────────────────────────────────────┤  Investigations, IPS Map, Metrics
│  API — FastAPI + 16 route modules       │  REST + 3 WebSocket channels
│  SQLite async (aiosqlite)              │  13 SQLAlchemy models
├─────────────────────────────────────────┤
│  INTELLIGENCE — AI Engine + Watcher     │  LLM prompts, playbook generation
│  Ansible executor, auto-approval        │  4-layer hybrid approval system
├─────────────────────────────────────────┤
│  PIPELINE — Poller + Mappers + Enrich   │  4 ES sources, GeoIP, Sigma noise
│  Incident correlation, forwarder        │  3-layer dedup, campaign detection
├─────────────────────────────────────────┤
│  DATA — SQLite + Redis + Elasticsearch │  2,577 alerts, 202 incidents
│  MaxMind GeoLite2 databases            │  423 investigations
└─────────────────────────────────────────┘
```

---

## Slide 5 — Alert Ingestion Pipeline

# How Alerts Enter the System

### Sources
| Source | Count | Index Pattern |
|--------|-------|---------------|
| Wazuh | 130 | `wazuh-alerts-4.x-*` |
| Falco | 648 | `falco-events-*` |
| Suricata | 1,799 | `filebeat-*` (eve alerts) |

### Pipeline Steps
1. **Poll** Elasticsearch every 10 seconds (parallel across sources)
2. **Map** raw docs → normalized alerts (source-specific mappers)
3. **Enrich** GeoIP (country, city, ASN, coordinates)
4. **Filter** Sigma noise rules + auto-learned noise
5. **Deduplicate** — 3-layer: in-memory → Redis (5min) → DB check
6. **Track** campaigns (group repeated alerts by IP + rule)
7. **Persist** to local SQLite shadow database
8. **Forward** to upstream OpenSOAR (best-effort, 3 retries)

### Key Achievement
**Zero duplicates** across 2,577 alerts using disk-persisted seen IDs

---

## Slide 6 — Incident Correlation

# From Alerts to Incidents

### Correlation Logic
```
Alerts with same key (IP / hostname / container) within 15 minutes
    ↓
Severity-weighted threshold:
  Critical → Always create incident
  High     → Needs 2+ high alerts
  Medium   → Needs 2+ medium alerts
  Low      → Never creates incident
```

### 13 Attack Types Detected

| Category | Detection |
|----------|-----------|
| Brute Force | Auth failures ≥ 5, ratio ≥ 0.3 |
| Malware | ET malware signatures, known IOCs |
| Web Attack | SQLi, XSS, LFI patterns |
| Cryptomining | xmrig, stratum, CPU spike |
| Container Escape | chroot, namespace changes |
| Privilege Escalation | setuid, sudo abuse |
| Network Scan | Port scan, ET SCAN |
| Ransomware | File deletion spike |
| Data Exfiltration | Large outbound transfer |
| Lateral Movement | SMB/RDP anomalies |
| Credential Dump | Mimikatz, hashdump |
| Supply Chain | Package manager in containers |
| Command & Control | DGA domains, beacon patterns |

---

## Slide 7 — AI Investigation Engine

# How AI Generates Investigations

### Prompt Structure (5 Sections)
```
SECTION 1 — Executive Summary
SECTION 2 — Attack Chain Analysis
SECTION 3 — Threat Intelligence
SECTION 4 — Risk Assessment (0-10)
SECTION 5 — Remediation Playbook (Ansible YAML)
```

### LLM Resilience
- **Circuit breaker**: 5 failures → 120s cooldown
- **Adaptive timeout**: Adjusts based on history
- **Fallback analysis**: Rule-based playbook on timeout/error
- **Multi-pass parser**: Extracts YAML, validates, repairs

### Local Inference
- Primary: **Ollama** (qwen3:8b)
- Alternative: Google Gemini
- **No API keys required for local mode**

---

## Slide 8 — Approval Workflow

# Analyst in the Loop

```
┌─────────────────┐     ┌─────────────┐     ┌─────────────────┐
│ AI generates    │ →   │ Analyst     │ →   │ Approve / Edit  │
│ investigation   │     │ reviews     │     │ / Decline       │
│ + playbook YAML │     │ in web UI   │     │                 │
└─────────────────┘     └─────────────┘     └─────────────────┘
                                                    │
                            ┌───────────────────────┼───────────────┐
                            ▼                       ▼               ▼
                      ┌──────────┐          ┌──────────┐     ┌──────────┐
                      │ APPROVE  │          │  EDIT    │     │ DECLINE  │
                      │ → Ansible│          │ → Modify │     │ → Archive│
                      │   execute│          │   YAML   │     │          │
                      └──────────┘          └──────────┘     └──────────┘
                            │
                            ▼
                      ┌──────────┐
                      │ Fix      │
                      │ Verify   │
                      │ (ES check│
                      │ 5 min)   │
                      └──────────┘
```

### Auto-Approve System (4 Layers)
```
Guardrails → Static Pass → Dynamic Learning → AI Confidence → Decision
(never)      (always)      (history-based)    (0.85 threshold)
```

---

## Slide 9 — Ansible Execution Engine

# Production-Grade Playbook Execution

### Pre-Flight Validation
1. ✅ YAML syntax check (`yaml.safe_load`)
2. ✅ Ansible syntax check (`ansible-playbook --syntax-check`)
3. ✅ SSH connection test (password or key-based)
4. ✅ Host replacement ("ghazi" → "target")
5. ✅ Jinja2 template fixup ("{ item }" → "{{ item }}")
6. ✅ Whitelist check (never block trusted IPs)

### Error Recovery
- **SSH auth failure** → Status = `pending` (retryable, not failed)
- **Connection refused** → Status = `failed` with specific reason
- **Dry-run mode** → Simulates when `ANSIBLE_ENABLED=false`

### Execution Capture
- Line-by-line stdout/stderr via asyncio subprocess
- Exit code mapping to specific failure reasons
- Full output stored in PlaybookRun record

---

## Slide 10 — Performance Monitoring

# Hardware Resource Auto-Remediation

### Metrics Polled (every 30s from Telegraf → ES)

| Metric | Warning | Critical | Auto-Action |
|--------|---------|----------|-------------|
| CPU | 70% | 90% | Restart top CPU process |
| Memory | 75% | 85% | Clear caches, restart service |
| Disk | 80% | 90% | `apt autoremove`, vacuum journals |
| Inodes | 80% | 90% | Clean inodes |
| Network | 100 MB/s | 500 MB/s | Audit connections, rate limit |

### Host: `ghazi`
- **Disk usage**: 89.8% (warning threshold 80%)
- **Auto-remediation**: Generates cleanup playbook automatically

### Cooldown: 30 minutes per anomaly type
Prevents alert spam while maintaining responsiveness.

---

## Slide 11 — Results & Metrics

# What We Built

### Codebase
| Metric | Value |
|--------|-------|
| Python backend | 38,889 lines |
| TypeScript frontend | 56,948 lines |
| Test files | 16 |
| API routes | 16 |
| DB models | 13 |
| Tests passing | **188 / 188** |

### Operational Data
| Metric | Value |
|--------|-------|
| Alerts ingested | 2,577 |
| Incidents created | 202 |
| Investigations | 423 |
| Approved & executed | 6 |
| Completed | 37 |
| Archived | 104 |

### Key Achievements
- ✅ **Zero cloud AI dependencies** — All LLM inference is local (Ollama)
- ✅ **Full upstream independence** — Works even when remote SOAR is down
- ✅ **Triple dedup** — 0 duplicate alerts across restarts
- ✅ **13 attack types** — Comprehensive classification
- ✅ **4-layer auto-approval** — Guardrails + static + dynamic + AI confidence
- ✅ **Dynamic playbooks** — Metric-aware, not static templates
- ✅ **Production Ansible** — Syntax validation, SSH pre-flight, error recovery

---

## Slide 12 — Challenges & Solutions

# What We Overcame

| Challenge | Solution |
|-----------|----------|
| **220 failed investigations** | YAML quoting fix for colons, Jinja2 template repair, retry-from-failed workflow |
| **Upstream unreachable** | Local SQLite shadow DB — full operation without remote; retry queue every 5 min |
| **Alert duplicates** | 3-layer dedup: memory → Redis → DB + disk-persisted seen IDs |
| **Falco without source_ip** | Correlation key hierarchy: IP → hostname → container → agent → alert_id |
| **AI returns invalid YAML** | Multi-pass parser: extract code block → yaml.safe_load → structural repair |
| **AI timeout/unavailable** | Circuit breaker + adaptive timeout + rule-based fallback playbooks |
| **Performance 0 hosts** | Fixed asyncio event-loop mismatch in ES client initialization |
| **Archives page crash** | Rebuilt production bundle after Turbopack HMR corruption |
| **Dead UI on edit** | Added assigned_to, tags, username columns across DB + API + frontend |
| **SSH auth failures** | Pre-flight SSH test; auth failures set status to pending (retryable) |

---

## Slide 13 — Architecture Diagram (for Defense)

# End-to-End Data Flow

```
┌─────────┐   ┌─────────┐   ┌─────────────┐   ┌─────────────┐
│  Wazuh  │   │  Falco  │   │  Suricata   │   │  Telegraf   │
│  (130)  │   │  (648)  │   │   (1,799)   │   │  (metrics)  │
└────┬────┘   └────┬────┘   └──────┬──────┘   └──────┬──────┘
     │             │               │                  │
     └─────────────┴───────────────┘                  │
                   │                                   │
                   ▼                                   ▼
          ┌─────────────────┐                 ┌─────────────────┐
          │  Elasticsearch  │                 │  Elasticsearch  │
          │  (Alert Source) │                 │  (Telegraf ES)  │
          └────────┬────────┘                 └────────┬────────┘
                   │ POLL every 10s                    │ POLL every 30s
                   ▼                                   ▼
          ┌─────────────────┐                 ┌─────────────────┐
          │  Alert Pipeline │                 │  Performance    │
          │  - Map/Enrich   │                 │  Monitor        │
          │  - Deduplicate  │                 │  - Detect       │
          │  - Forward      │                 │  - Generate     │
          └────────┬────────┘                 └────────┬────────┘
                   │                                   │
                   ▼                                   ▼
          ┌─────────────────┐                 ┌─────────────────┐
          │  Incident Watcher │               │  Dynamic        │
          │  (every 15s)      │               │  Playbook Gen   │
          │  - Fast/Full scan │               └────────┬────────┘
          │  - AI Engine      │                        │
          └────────┬────────┘                        │
                   │                                   │
                   ▼                                   ▼
          ┌─────────────────┐                 ┌─────────────────┐
          │  Investigation  │◄────────────────│  Performance    │
          │  (awaiting_     │                 │  Investigation  │
          │   approval)     │                 │                 │
          └────────┬────────┘                 └─────────────────┘
                   │
         ┌────────┴────────┐
         ▼                 ▼
    ┌─────────┐      ┌─────────┐
    │ Approve │      │ Decline │
    └────┬────┘      └────┬────┘
         │                │
         ▼                ▼
  ┌─────────────┐   ┌─────────┐
  │   Ansible   │   │ Archive │
  │  Execution  │   │         │
  └──────┬──────┘   └─────────┘
         │
         ▼
  ┌─────────────┐
  │ Fix Verify  │
  │ (ES re-check)│
  └──────┬──────┘
         │
         ▼
    ┌─────────┐
    │ Archive │
    └─────────┘
```

---

## Slide 14 — Thank You

# Questions?

## **ARIA**
### AI-Powered Security Orchestration, Automation & Response

**Ghazi Mabrouki**

PFE — Institut Supérieur d'Informatique du Kef
Huawei Technologies

---

**Repository**: `git@github.com:Ghazimabrouki/Project-PFE-ARIA.git`

**Demo**: Frontend at `localhost:3000`, API at `localhost:8001`

**Test suite**: `pytest tests/` — 188/188 passing

---

*End of Presentation*
