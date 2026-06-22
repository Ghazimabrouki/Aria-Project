# Technical Documentation Index

Consolidated per-feature technical docs for OpenSOAR backend & frontend.

| # | Feature | Doc File | Backend Entry | Frontend Page | Status |
|---|---------|----------|---------------|---------------|--------|
| 1 | Performance Monitoring | `performance_monitoring.md` | `api/routes/performance.py` | `/metrics` | API Part B incomplete |
| 2 | IPS Map | `ips_map.md` | `api/routes/ips.py` | `/ips` | Complete |
| 3 | AI Assistant | `ai_assistant.md` | `api/routes/assistant.py` | `/assistant` | Frontend not verified |
| 4 | AI Operator | `ai_operator.md` | `api/routes/operator.py` | `/operator` | Frontend not verified |
| 5 | Alert Pipeline | `core_alert_pipeline.md` | `pipeline/poller/main.py` | `/alerts` | Complete |
| 6 | Incidents & Correlation | `core_incidents.md` | `pipeline/datausage/incident_manager.py` | `/incidents` | API truncated |
| 7 | Watcher & Investigations | `core_watcher.md` | `response/watcher/main.py` | `/investigations` | Complete |
| 8 | AI Response | `core_ai_response.md` | `response/ai_engine/main.py` | `/investigations` | Complete |

## Template used (11 fields + limitations)
1. Feature name
2. Purpose
3. Input
4. Processing steps
5. Output
6. Main files
7. API endpoints
8. Database tables
9. Background jobs
10. Frontend page
11. Example
12. Known limitations

## Active gaps to close
1. `api/routes/performance.py` lines 1001–1531 (disk-analysis, history, root-cause)
2. `api/routes/incidents.py` from truncation point to EOF
3. Verify frontend pages exist: `frontend/app/(dashboard)/metrics/page.tsx`, `/assistant/page.tsx`, `/operator/page.tsx`
4. Export `api/routes/monitoring.py` if it exists
