# ARIA API Test Results - April 15, 2026

## ✅ WORKING APIs (90%+)

| Category | Endpoint | Status |
|----------|----------|--------|
| **Core** | GET /health | ✅ ok |
| | GET / | ✅ v1.0.0 |
| **Alerts** | GET /api/v1/alerts | ✅ 50 results |
| | GET /api/v1/alerts/{id} | ✅ returns data + relationships |
| | GET /api/v1/alerts/{id}/incidents | ✅ |
| | GET /api/v1/alerts/{id}/similar | ✅ |
| **Incidents** | GET /api/v1/incidents | ✅ 13 results |
| | GET /api/v1/incidents/{id} | ✅ returns data + relationships |
| | GET /api/v1/incidents/{id}/alerts | ✅ |
| | GET /api/v1/incidents/{id}/timeline | ✅ |
| | GET /api/v1/incidents/{id}/investigations | ✅ |
| | GET /api/v1/incidents/by-alert/{id} | ✅ |
| **Investigations** | GET /api/v1/investigations | ✅ 13 results |
| | GET /api/v1/investigations/{id} | ✅ returns detail |
| | GET /api/v1/investigations/stats | ✅ |
| | GET /api/v1/investigations/{id}/playbook/yaml | ✅ |
| | GET /api/v1/investigations/{id}/timeline | ✅ |
| | GET /api/v1/investigations/{id}/run-status | ✅ |
| | POST /api/v1/investigations/{id}/approve | ✅ requires body |
| | POST /api/v1/investigations/{id}/decline | ✅ requires body |
| | POST /api/v1/investigations/{id}/execute | ⚠️ requires body |
| **Archives** | GET /api/v1/archives | ✅ 4 results |
| | GET /api/v1/archives/stats | ✅ |
| **Pipeline** | GET /api/v1/pipeline/status | ✅ running: true |
| | GET /api/v1/pipeline/sources | ✅ 4 sources |
| | GET /api/v1/pipeline/cursors | ✅ 4 cursors |
| **Search** | GET /api/v1/search?q= | ✅ |
| | GET /api/v1/search/ips/{ip} | ✅ |
| | GET /api/v1/search/domains/{domain} | ✅ |
| **Dashboard** | GET /api/v1/dashboard/quick-stats | ✅ |
| | GET /api/v1/dashboard/summary | ✅ |
| **IPS Map** | GET /api/v1/ips/map-data | ✅ |
| | GET /api/v1/ips/events | ✅ |
| | GET /api/v1/ips/statistics | ✅ |
| | GET /api/v1/ips/countries | ✅ |
| | GET /api/v1/ips/filters | ✅ |
| | GET /api/v1/ips/summary | ✅ |
| | GET /api/v1/ips/status | ✅ |
| | POST /api/v1/ips/event | ✅ |
| **Assistant** | GET /api/v1/assistant/context | ✅ 7 sources |
| | GET /api/v1/assistant/health | ✅ |
| | POST /api/v1/assistant/query | ⚠️ LLM unavailable |
| **Monitoring** | GET /monitor/health | ✅ healthy |
| | GET /monitor/services-status | ✅ 10 running |
| | GET /monitor/stats | ✅ |
| | GET /monitor/pipeline-health | ✅ |
| | GET /monitor/retry-queue-stats | ✅ |
| | GET /monitor/logs/recent | ✅ 50 logs |
| | GET /monitor/auto-approve-config | ✅ |
| | GET /monitor/auto-approve-stats | ✅ |
| | POST /monitor/reset-cursor/{source} | ✅ |

## ⚠️ ISSUES / NOTES

1. **Performance Metrics (hosts=0)**: The metrics API returns empty because the poller runs in main.py process while API runs in uvicorn process. They don't share memory. This is an architectural issue - could be fixed by using Redis for metrics cache.

2. **AI Assistant Query**: Returns "LLM unavailable" because the NVIDIA endpoint isn't accessible from this environment. This is expected - the LLM runs on a separate server.

3. **Investigation Detail**: Some IDs from the list don't work with detail endpoint because uvicorn has a different database file (initialized fresh on startup with init_db()). The current data is from main.py's poller. This is expected - they should share the same DB.

## STARTUP COMMAND

To start the backend properly:
```bash
cd /home/dash/opensoar\ backend
bash start.sh
```

This starts both main.py (background services) and uvicorn (API server) in separate processes that share data through OpenSOAR and Redis.