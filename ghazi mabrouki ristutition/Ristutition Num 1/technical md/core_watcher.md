# Core SOC Workflow — Watcher & Investigations

## 1. Feature name
Incident Watcher & Investigation Lifecycle

## 2. Purpose
Poll for open incidents without investigations, build comprehensive investigation context (IOCs, timeline, MITRE, behavioral indicators, auth patterns), create `Investigation` rows, and trigger the AI engine.

## 3. Input
- SQLite `Incident` rows with `status=open` and no linked `Investigation`.
- Linked `Alert` rows + `AlertIncidentLink`.

## 4. Processing steps
1. **Scan** (`response/watcher/main.py`) — Fast scan (recent 50) every cycle; full scan (paginated) every 60 cycles.
2. **Skip whitelist** — Incidents with whitelisted source IPs are skipped.
3. **Create investigation** — Insert `Investigation` with `status="pending"`.
4. **Build context** (`context_builder.py`) — Extract:
   - Timeline of all alerts
   - IOCs: IPs, ports, services, domains, hashes, usernames, file paths
   - MITRE tactics/techniques
   - Behavioral indicators: auth failures, recon, execution, exfil, malware
   - Auth pattern analysis: failed→successful login detection
   - Attack type determination
   - Dynamic risk score (0-100)
5. **Trigger AI** — Spawn `_run_ai_engine()` as background task.

## 5. Output
- SQLite `Investigation` rows with rich context JSON.
- Background AI engine task.

## 6. Main files
| File | Role |
|------|------|
| `response/watcher/main.py` | Polling loop, investigation creation |
| `response/watcher/context_builder.py` | Context assembly |
| `response/db.py` | Async SQLite session |
| `response/models.py` | `Investigation`, `InvestigationAlert` |

## 7. API endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/investigations` | List |
| GET | `/investigations/{id}` | Detail |
| POST | `/investigations/{id}/approve` | Approve playbook |
| POST | `/investigations/{id}/decline` | Decline playbook |
| POST | `/investigations/{id}/run` | Execute playbook |
| GET | `/investigations/{id}/status` | Poll status |

## 8. Database tables
- `Investigation`
- `InvestigationAlert`

## 9. Background jobs
- **Incident Watcher** (every `INCIDENT_WATCHER_INTERVAL`, default 15s)
- **Stuck Recovery** — detects investigations stuck in `running` or `pending` for too long

## 10. Frontend page
- **Route**: `/investigations`
- **Features**: Investigation cards, AI summary preview, approval buttons, execution logs.

## 11. Example
Open incident with 5 alerts → watcher creates `Investigation` → context builder finds 2 source IPs, MITRE `T1110` + `T1078`, failed→successful auth pattern → risk score 78 → AI engine triggered.

## 12. Known limitations
- Watcher runs continuously; high incident volume may spawn many concurrent AI tasks.
- Stuck recovery relies on time thresholds; very long-running playbooks may be incorrectly flagged.
