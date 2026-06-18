# Core SOC Workflow — Incidents & Correlation

## 1. Feature name
Incident Correlation & Management

## 2. Purpose
Automatically correlate alerts into incidents using kill-chain progression, attack patterns, and time-window clustering; calculate dynamic severity; generate human-readable titles; and maintain local SQLite shadow incidents.

## 3. Input
- Normalized alert payloads from Alert Pipeline.
- Existing incidents and their linked alerts from SQLite.
- Tracked campaign signals.

## 4. Processing steps
1. **Evaluate creation** (`pipeline/datausage/incident_manager.py`) — Critical alerts always create; attack patterns (ssh_brute_force, port_scan, malware, c2) always create; kill chain (2+ MITRE phases) always create; medium + 2+ recent alerts/15min create.
2. **Calculate severity** — Escalate if kill chain detected or multi-source detection.
3. **Generate title** — Human-readable using campaign type, attack pattern, MITRE phase, or rule name.
4. **Local shadow** (`local_incident_manager.py`) — `_ensure_local_incident()` creates `Incident` + `AlertIncidentLink` rows; propagates whitelist status.
5. **Correlation** — `correlator.py` links alerts by shared IOCs, time proximity, and MITRE tactic overlap.

## 5. Output
- SQLite `Incident` rows with severity, status, title.
- `AlertIncidentLink` rows with `correlation_confidence`.

## 6. Main files
| File | Role |
|------|------|
| `pipeline/datausage/incident_manager.py` | Creation logic, severity, titles |
| `pipeline/datausage/local_incident_manager.py` | Local SQLite shadow |
| `pipeline/correlators/correlator.py` | IOC + time + MITRE correlation |
| `pipeline/correlators/observable_manager.py` | Extract and track observables |
| `api/routes/incidents.py` | CRUD + list + manual create *(truncated mid-delivery)* |

## 7. API endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/incidents` | List with filters |
| GET | `/incidents/{id}` | Detail |
| POST | `/incidents` | Manual create *(route truncated in delivery)* |

## 8. Database tables
- `Incident`
- `AlertIncidentLink` (`correlation_confidence`)

## 9. Background jobs
- **Incident Correlation** (every `INCIDENT_CORRELATION_INTERVAL`, default 30s)

## 10. Frontend page
- **Route**: `/incidents`
- **Features**: Incident cards, timeline, linked alerts, severity badges.

## 11. Example
3 Wazuh SSH brute-force alerts + 1 Suricata port scan from same source IP within 10 min → kill chain `reconnaissance + initial_access` detected → incident created with severity `critical`, title `SSH Brute Force & Port Scan Campaign from 185.220.101.4`.

## 12. Known limitations
- `api/routes/incidents.py` was truncated during delivery; final routes and helpers missing.
- Correlation is local-only in local mode; upstream mode relies on upstream incident creation.
