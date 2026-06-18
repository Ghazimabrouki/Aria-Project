# OpenSOAR — Comprehensive Technical Reference

> **Scope**: Complete API endpoint reference, frontend component inventory, database schema diagram, and pipeline data-flow trace.

---

## Table of Contents

1. [Complete API Endpoint Reference](#1-complete-api-endpoint-reference)
2. [Frontend Component Inventory](#2-frontend-component-inventory)
3. [Database Schema Diagram](#3-database-schema-diagram)
4. [Pipeline Data-Flow Diagram](#4-pipeline-data-flow-diagram)

---

## 1. Complete API Endpoint Reference

### Root Application (`api/app.py`)

| Method | Path | Query Params | Request Body | Response (Key Fields) | Description |
|--------|------|--------------|--------------|----------------------|-------------|
| `GET` | `/` | — | — | `service`, `version`, `endpoints` | Service root |
| `GET` | `/health` | — | — | `{"status": "ok"}` | Basic health check |
| `GET` | `/api/v1/health` | — | — | `{"status": "ok"}` | API-namespace health |
| `GET` | `/dashboard` | — | — | HTML | Approval dashboard UI page |
| `POST` | `/api/v1/investigations/trigger-watch` | — | — | `{"message": "Watcher triggered..."}` | Manual watcher trigger |

### Adaptive System (`api/routes/adaptive.py`) — Prefix: `/adaptive`

| Method | Path | Response (Key Fields) | Description |
|--------|------|----------------------|-------------|
| `GET` | `/adaptive/status` | `timeout`, `retry`, `concurrency`, `metrics` | Adaptive system status |
| `GET` | `/adaptive/metrics` | Detailed metrics dict | Detailed metrics |
| `POST` | `/adaptive/reset-metrics` | `message`, `status` | Reset metrics |
| `GET` | `/adaptive/health` | `status`, `adaptive_system` | Health check |

### Alerts (`api/routes/alerts.py`) — Prefix: `/api/v1/alerts`

| Method | Path | Query Params | Response (Key Fields) | Description |
|--------|------|--------------|----------------------|-------------|
| `GET` | `/api/v1/alerts` | `source`, `severity`, `status`, `limit=50` (≤200), `offset=0` (≥0) | `alerts[]`, `total`, `limit`, `offset` | List/filter alerts |
| `GET` | `/api/v1/alerts/{alert_id}` | — | `data`, `relationships`, `actions` | Single alert detail |
| `GET` | `/api/v1/alerts/{alert_id}/incidents` | — | `alert_id`, `incidents[]`, `total` | Incidents containing alert |
| `GET` | `/api/v1/alerts/{alert_id}/similar` | `limit=10` (1–100) | `alert_id`, `match_criteria`, `alerts[]`, `total` | Similar alerts |

### Approval UI (`api/routes/approval_ui.py`)

| Method | Path | Response | Description |
|--------|------|----------|-------------|
| `GET` | `/approve/{investigation_id}` | HTML page | Human approval page |

### Archives (`api/routes/archives.py`) — Prefix: `/api/v1/archives`

| Method | Path | Query Params | Response (Key Fields) | Description |
|--------|------|--------------|----------------------|-------------|
| `GET` | `/api/v1/archives` | `severity`, `fix_status`, `source_ip`, `mitre_tactic`, `limit=50` (≤200), `offset=0` | `archives[]`, `total` | Search archives |
| `GET` | `/api/v1/archives/stats` | — | `total_archived`, `fix_success_rate_pct`, `by_fix_status`, `by_severity` | Archive stats |
| `GET` | `/api/v1/archives/{archive_id}` | — | Full archive + `full_context` | Archive detail |
| `GET` | `/api/v1/archives/{archive_id}/original-incident` | — | `original_incident` | Incident snapshot |
| `GET` | `/api/v1/archives/{archive_id}/alerts` | — | `alerts[]`, `total` | Archived alerts |
| `GET` | `/api/v1/archives/by-investigation/{investigation_id}` | — | `exists`, `archive_id`, `investigation_id`, `incident_id`, `incident_title`, `fix_status`, `fix_detail`, `archived_at` | Find archive by investigation |

### AI Assistant (`api/routes/assistant.py`) — Prefix: `/api/v1/assistant`

| Method | Path | Request Body | Response (Key Fields) | Description |
|--------|------|--------------|----------------------|-------------|
| `POST` | `/api/v1/assistant/query` | `{question: string, context?: object, sources?: string[]}` | AI answer dict | Ask the AI assistant |
| `GET` | `/api/v1/assistant/context` | — | `available_sources[]`, `query_tips[]` | Available data sources |
| `GET` | `/api/v1/assistant/sources` | — | `sources`, `connection_status` | Source statistics |
| `GET` | `/api/v1/assistant/health` | — | `status`, `llm_enabled`, `model`, `sources` | LLM health check |

### Dashboard (`api/routes/dashboard.py`) — Prefix: `/api/v1/dashboard`

| Method | Path | Response (Key Fields) | Description |
|--------|------|----------------------|-------------|
| `GET` | `/api/v1/dashboard/summary` | `alerts`, `incidents`, `investigations`, `archives`, `navigation[]` | Full dashboard counts |
| `GET` | `/api/v1/dashboard/quick-stats` | `alerts`, `incidents`, `investigations`, `pending_approvals`, `archives` | Header/footer stats |

### Incidents (`api/routes/incidents.py`) — Prefix: `/api/v1/incidents`

| Method | Path | Query Params | Response (Key Fields) | Description |
|--------|------|--------------|----------------------|-------------|
| `GET` | `/api/v1/incidents` | `status`, `severity`, `limit=50` (≤200), `offset=0` (≥0) | `incidents[]`, `total`, `limit`, `offset` | List/filter incidents |
| `GET` | `/api/v1/incidents/{incident_id}` | — | `data`, `relationships`, `actions` | Incident detail |
| `GET` | `/api/v1/incidents/{incident_id}/alerts` | — | `incident_id`, `alerts[]`, `total` | Alerts in incident |
| `GET` | `/api/v1/incidents/{incident_id}/investigations` | — | `incident_id`, `investigations[]`, `total` | Local investigations |
| `GET` | `/api/v1/incidents/{incident_id}/timeline` | — | `incident_id`, `incident_title`, `current_status`, `events[]`, `total_events` | Full timeline |
| `GET` | `/api/v1/incidents/suggestions` | — | Suggestion groups | Unlinked alert groups |
| `GET` | `/api/v1/incidents/by-alert/{alert_id}` | — | `alert_id`, `incidents[]`, `total` | Reverse lookup |

### Investigations (`api/routes/investigations.py`) — Prefix: `/api/v1/investigations`

| Method | Path | Query Params / Body | Response (Key Fields) | Description |
|--------|------|---------------------|----------------------|-------------|
| `GET` | `/api/v1/investigations` | `status`, `severity`, `source`, `limit=50` (≤200), `offset=0` | `investigations[]`, `total`, `offset`, `limit` | List investigations |
| `GET` | `/api/v1/investigations/stats` | — | `pending`, `awaiting_approval`, `approved`, `declined`, `running`, `completed`, `failed`, `archived`, `total` | Status counts |
| `GET` | `/api/v1/investigations/{id}` | — | Full `Investigation` detail | Investigation detail |
| `PATCH` | `/api/v1/investigations/{id}/playbook` | `{playbook_yaml: string}` | `message` | Edit playbook |
| `PUT` | `/api/v1/investigations/{id}/playbook` | `{playbook_yaml: string}` | `message` | Alias for PATCH |
| `GET` | `/api/v1/investigations/{id}/playbook/yaml` | — | `investigation_id`, `yaml`, `valid` | Raw playbook YAML |
| `POST` | `/api/v1/investigations/{id}/execute` | `{decided_by: string="analyst"}` | `message`, `investigation_id`, `status`, `run_status_url` | Execute directly |
| `POST` | `/api/v1/investigations/{id}/approve` | `{decided_by: string="analyst"}` | `message`, `investigation_id` | Approve & run |
| `POST` | `/api/v1/investigations/{id}/decline` | `{decided_by: string="analyst", reason?: string}` | `message`, `investigation_id` | Decline & archive |
| `POST` | `/api/v1/investigations/{id}/archive` | — | `message`, `investigation_id` | Manual archive |
| `GET` | `/api/v1/investigations/{id}/run-status` | — | `status`, `exit_code`, `output`, `started_at`, `finished_at` | Ansible run status |
| `GET` | `/api/v1/investigations/{id}/alerts` | — | `investigation_id`, `alerts[]` | Linked alerts |
| `GET` | `/api/v1/investigations/{id}/timeline` | — | `investigation_id`, `incident_title`, `current_status`, `events[]` | Timeline |

### IPS Attack Visualization (`api/routes/ips.py`) — Prefix: `/api/v1/ips`

| Method | Path | Query Params | Request Body | Response (Key Fields) | Description |
|--------|------|--------------|--------------|----------------------|-------------|
| `POST` | `/api/v1/ips/event` | — | `Dict` | `status`, `event_id` | Store single attack event |
| `POST` | `/api/v1/ips/events/bulk` | — | `List[Dict]` | `status`, `events_count` | Store multiple events |
| `DELETE` | `/api/v1/ips/events` | — | — | `status` | Clear all stored events |
| `GET` | `/api/v1/ips/map-data` | `limit=50` (≤100), `time_range?` (min), `severity?`, `country?`, `lifecycle?` | — | `attacks[]`, `paths[]`, `count`, `timestamp` | World map data |
| `GET` | `/api/v1/ips/events` | `limit=20` (≤100), `offset=0`, `severity?`, `country?`, `protocol?`, `category?`, `lifecycle?` | — | `events[]`, `total`, `limit`, `offset` | Paginated events |
| `GET` | `/api/v1/ips/events/live` | `limit=50` (≤100), `severity?`, `country?`, `lifecycle?` | — | `events[]`, `count`, `timestamp` | Live events table |
| `GET` | `/api/v1/ips/statistics` | `severity?`, `country?`, `lifecycle?` | — | `total_attacks`, `unique_sources`, `unique_targets`, `active_events`, `by_severity`, `by_category`, `by_protocol`, `by_lifecycle`, `top_countries`, `top_isps`, `top_sources`, `timestamp` | Attack statistics |
| `GET` | `/api/v1/ips/statistics/industries` | — | — | `industries[]`, `total` | By industry |
| `GET` | `/api/v1/ips/statistics/targets` | — | — | `targets[]`, `total` | Most targeted hosts |
| `GET` | `/api/v1/ips/statistics/attack-types` | — | — | `attack_types[]`, `total` | Most common attack types |
| `GET` | `/api/v1/ips/countries` | — | — | `countries[]`, `total` | By country |
| `GET` | `/api/v1/ips/filters` | — | — | `severities[]`, `categories[]`, `protocols[]`, `countries[]` | Filter options |
| `GET` | `/api/v1/ips/status` | — | — | `status`, `events_stored`, `unique_sources`, `total_processed` | Health check |
| `GET` | `/api/v1/ips/status/detailed` | — | — | `status`, `events`, `statistics`, `timestamp` | Detailed health |
| `GET` | `/api/v1/ips/summary` | `severity?`, `country?`, `lifecycle?` | — | `total`, `active`, `unique_sources`, `critical`, `high`, `medium`, `low` | Quick summary |
| `GET` | `/api/v1/ips/health` | — | — | Same as `/status` | Alias |
| `GET` | `/api/v1/ips/{event_id}` | — | — | Full event dict | Single event |

### Monitoring (`api/routes/monitoring.py`) — Prefix: `/monitor`

| Method | Path | Query Params | Response (Key Fields) | Description |
|--------|------|--------------|----------------------|-------------|
| `GET` | `/monitor/stats` | — | `SystemStats` | Overall system stats |
| `GET` | `/monitor/investigations` | `status?`, `limit=50` (1–200), `offset=0` | `InvestigationMetrics[]` | Investigations list |
| `GET` | `/monitor/investigations/{id}` | — | Full detail dict | Investigation details |
| `GET` | `/monitor/playbook-runs` | `status?`, `limit=50` (1–200) | `runs[]` | Ansible executions |
| `GET` | `/monitor/health` | — | `status`, `database`, `timestamp` | Health + DB connectivity |
| `GET` | `/monitor/pipeline-health` | — | `timestamp`, `stages`, `overall_status`, `unhealthy_stages[]` | Pipeline stage health |
| `GET` | `/monitor/services-status` | — | `services`, `timestamp`, `total_running`, `total_disabled` | Background service statuses |
| `GET` | `/monitor/stuck-investigations` | — | `count`, `stuck_investigations[]` | Stuck investigations |
| `GET` | `/monitor/execution-stats` | — | `ExecutionStats` | Ansible statistics |
| `POST` | `/monitor/reset-cursor/{source}` | `hours_ago=24` | `source`, `new_cursor`, `message` | Reset poller cursor |
| `GET` | `/monitor/auto-approve-stats` | — | `total_decisions`, `auto_approved`, `human_review_required`, `auto_approve_rate` | Auto-approve stats |
| `GET` | `/monitor/auto-approve-config` | — | `enabled`, `method`, `static`, `guardrails`, `dynamic`, `ai`, `notifications` | Auto-approve config |
| `GET` | `/monitor/retry-queue-stats` | — | `status`, `pending_count`, `by_retry_count` | Retry queue stats |
| `GET` | `/monitor/forwarder-status` | — | `sources`, `pipeline`, `timestamp` | Forwarder status |
| `GET` | `/monitor/services/{service}/logs` | `limit=50` (≤200) | `service`, `logs[]`, `total` | Service logs |
| `GET` | `/monitor/services/{service}/errors` | `limit=20` (≤100) | `service`, `errors[]`, `total`, `related_investigation_ids[]` | Service errors |
| `GET` | `/monitor/logs/recent` | `limit=50` (≤200), `level?` | `logs[]`, `total`, `filters` | Recent backend logs |
| `GET` | `/monitor/investigations/{id}/dependencies` | — | `investigation_id`, `incident_id`, `target_host`, `status`, `created_at`, `dependencies` | Dependency graph |

### Performance Metrics (`api/routes/performance.py`) — Prefix: `/api/v1/metrics`

| Method | Path | Query Params | Response (Key Fields) | Description |
|--------|------|--------------|----------------------|-------------|
| `GET` | `/api/v1/metrics/dashboard` | — | `hosts[]`, `timestamp`, `count` | All hosts dashboard |
| `GET` | `/api/v1/metrics/hosts` | — | `hosts[]`, `count`, `configured_hosts` | Monitored hosts |
| `GET` | `/api/v1/metrics/thresholds` | — | `cpu`, `memory`, `disk`, `disk_inodes`, `network_in` | Thresholds |
| `GET` | `/api/v1/metrics/status` | — | `enabled`, `poll_interval`, `hosts_configured`, `anomaly_detection`, `auto_remediation` | System status |
| `GET` | `/api/v1/metrics/health` | — | `status`, `service`, `timestamp` | Health |
| `GET` | `/api/v1/metrics/health/detailed` | — | `status`, `service`, `enabled`, `components`, `timestamp` | Detailed health |
| `GET` | `/api/v1/metrics/alerts` | `host?`, `severity?`, `limit=50` (≤200) | `alerts[]`, `total`, `filters` | Performance alerts |
| `GET` | `/api/v1/metrics/{host}` | — | `hostname`, `ip`, `last_update`, `alert_status`, `cpu`, `memory`, `disk`, `network`, `load`, `connections`, `processes`, `procstat_missing` | Host detail |
| `GET` | `/api/v1/metrics/{host}/history` | `metric="cpu"`, `limit=100` (1–1000) | `host`, `metric`, `data_points[]`, `count` | Historical time-series |
| `GET` | `/api/v1/metrics/{host}/root-cause` | — | `host`, `timestamp`, `current_issues[]`, `root_cause`, `confidence`, `recommended_action`, `recent_alerts`, `top_processes` | AI root-cause |
| `GET` | `/api/v1/metrics/{host}/relationships` | — | `host`, `metrics`, `performance_alerts`, `investigations`, `relationships` | Combined view |
| `GET` | `/api/v1/metrics/{host}/alerts` | `severity?`, `limit=50` (≤200) | `host`, `alerts[]`, `total` | Host alerts |
| `GET` | `/api/v1/metrics/{host}/investigations` | `limit=50` (≤200) | `host`, `investigations[]`, `total` | Host investigations |

### Pipeline Traceability (`api/routes/pipeline.py`) — Prefix: `/api/v1/pipeline`

| Method | Path | Query Params | Response (Key Fields) | Description |
|--------|------|--------------|----------------------|-------------|
| `GET` | `/api/v1/pipeline/status` | — | `running`, `poll_interval`, `batch_size`, `description` | Pipeline status |
| `GET` | `/api/v1/pipeline/sources` | — | `sources[]` | Per-source stats |
| `GET` | `/api/v1/pipeline/stats` | — | `total_processed`, `error_rate`, `avg_processing_time`, `sources_monitored`, `poll_interval`, `total_alerts`, `total_incidents`, `total_investigations` | Aggregate stats |
| `GET` | `/api/v1/pipeline/cursors` | — | `cursors` | Current cursors |
| `GET` | `/api/v1/pipeline/sources/{source}/stats` | `limit=100` (≤1000) | `source`, `cursor`, `documents_tracked`, `tracking_enabled`, `index_pattern` | Source detail |
| `GET` | `/api/v1/pipeline/sources/{source}/reset` | `hours_ago=24` (1–168) | `source`, `new_cursor`, `message` | Reset cursor |
| `GET` | `/api/v1/pipeline/trace/alert/{alert_id}` | — | `alert_id`, `steps[]` | Alert trace |
| `GET` | `/api/v1/pipeline/trace/source/{source_id}` | — | `source_id`, `found`, `alert_id`, `title`, `source`, `created_at`, `link` | Find by ES doc ID |

### Unified Search (`api/routes/search.py`) — Prefix: `/api/v1/search`

| Method | Path | Query Params | Response (Key Fields) | Description |
|--------|------|--------------|----------------------|-------------|
| `GET` | `/api/v1/search` | `q` (required), `limit=10` (≤50) | `query`, `results` (alerts[], incidents[], investigations[]), `counts` | Global search |
| `GET` | `/api/v1/search/ips/{ip}` | `limit=20` (≤50) | `ip`, `results`, `counts` | IP search |
| `GET` | `/api/v1/search/domains/{domain}` | `limit=20` (≤50) | `domain`, `results`, `counts` | Domain search |
| `GET` | `/api/v1/search/investigations/{investigation_id}/trace` | — | `investigation_id`, `steps[]`, `navigation` | Investigation trace |

### WebSocket (`api/websocket.py`)

| Method | Path | Behavior | Description |
|--------|------|----------|-------------|
| `WS` | `/ws/investigations` | Bidirectional JSON; broadcasts investigation lifecycle events | Investigation updates |
| `WS` | `/ws/performance` | Bidirectional JSON; broadcasts performance alerts | Performance alerts |
| `WS` | `/ws/system` | Bidirectional JSON; broadcasts system health | System health |
| `WS` | `/ws` | Subscribes to all channels | Catch-all events |
| `GET` | `/ws/health` | `status`, `connections` (per-channel counts), `timestamp` | WS health |

---

## 2. Frontend Component Inventory

### 2.1 Pages (`frontend/app/(dashboard)/`)

| File | Route | Main Purpose | Key State / Hooks | Major Child Components | API Endpoints |
|------|-------|--------------|-------------------|------------------------|---------------|
| `app/layout.tsx` | *(root)* | Root layout with fonts (Inter, JetBrains Mono), metadata, Vercel Analytics. | — | — | — |
| `page.tsx` | `/` | Security Dashboard: stats, charts, recent activity, quick actions. | `searchQuery`, `useSWR` on dashboard data, `useWSSubscription` | `StatCard`, `AlertsChart`, `SeverityChart`, `ActivityFeed`, `QuickActions` | `dashboardAPI.getSummary()`, `dashboardAPI.getQuickStats()`, `investigationsAPI.getStats()`, `alertsAPI.list()`, `incidentsAPI.list()`, `investigationsAPI.list()` |
| `alerts/page.tsx` | `/alerts` | Paginated alert list with filters and detail sheet for IOCs + relationships. | `offset`, `source`, `severity`, `status`, `selectedAlertId`, `useSWR`, `useSearchParams`, `useWSSubscription` | `PageHeader`, `DataTable`, `SeverityBadge`, `StatusBadge`, `Sheet`, `Tabs` | `alertsAPI.list(...)`, `alertsAPI.get(id)` |
| `incidents/page.tsx` | `/incidents` | Paginated incident list with filters. | `offset`, `status`, `severity`, `useSWR`, `useSearchParams`, `useWSSubscription` | `PageHeader`, `DataTable`, `SeverityBadge`, `StatusBadge` | `incidentsAPI.list(...)` |
| `incidents/[id]/page.tsx` | `/incidents/:id` | Incident detail: overview, timeline, linked alerts, investigations. | `useSWR`, `useRouter` | `PageHeader`, `SeverityBadge`, `StatusBadge`, `Tabs`, `ScrollArea` | `incidentsAPI.get(id)`, `incidentsAPI.getAlerts(id)`, `incidentsAPI.getTimeline(id)`, `incidentsAPI.getInvestigations(id)` |
| `investigations/page.tsx` | `/investigations` | Investigation list with status filter and overview cards. | `offset`, `status`, `useSWR`, `useWSSubscription` | `PageHeader`, `DataTable`, `StatusBadge`, `Card` | `investigationsAPI.list(...)`, `investigationsAPI.getStats()` |
| `investigations/[id]/page.tsx` | `/investigations/:id` | Investigation detail: AI analysis, playbook YAML, timeline, actions. | `decline dialog`, `reason`, `actioning`, `error`, `useSWR`, `useWSSubscription` | `PageHeader`, `SeverityBadge`, `StatusBadge`, `Tabs`, `Dialog`, `Progress` | `investigationsAPI.get(id)`, `investigationsAPI.getTimeline(id)`, `investigationsAPI.approve()`, `investigationsAPI.decline()`, `investigationsAPI.execute()` |
| `archives/page.tsx` | `/archives` | Archived incidents list with fix-status filter and stats. | `offset`, `fixStatusFilter`, `useSWR` | `PageHeader`, `DataTable`, `SeverityBadge`, `FixStatusBadge`, `Card` | `archivesAPI.list(...)`, `archivesAPI.getStats()` |
| `archives/[id]/page.tsx` | `/archives/:id` | Archive detail: severity, fix status, alerts, AI analysis, playbook. | `useSWR`, `useRouter` | `PageHeader`, `SeverityBadge`, `FixStatusBadge`, `Tabs`, `ScrollArea` | `archivesAPI.get(id)`, `archivesAPI.getAlerts(id)` |
| `assistant/page.tsx` | `/assistant` | AI Security Assistant chat interface. | `messages`, `input`, `isLoading`, `showScrollButton`, `useRef` | `PageHeader`, `Card`, `ScrollArea`, `Textarea`, `Button` | `aiAPI.query({question})` |
| `search/page.tsx` | `/search` | Global search across alerts, incidents, investigations. | `query`, `debouncedQuery`, `selectedTypes`, `useSearchParams`, `useSWR` | `PageHeader`, `Input`, `Checkbox`, `Card`, `Badge` | `searchAPI.search(query)` |
| `pipeline/page.tsx` | `/pipeline` | Pipeline status, throughput stats, flow visualization. | `useSWR`, `useCallback` | `PageHeader`, `StatusBadge`, `Card`, `Progress` | `pipelineAPI.getSources()`, `pipelineAPI.getStats()` |
| `monitoring/page.tsx` | `/monitoring` | Backend service health grid and detailed status. | `useSWR` (15s refresh) | `PageHeader`, `StatusBadge`, `Card` | `monitoringAPI.getServicesStatus()` |
| `metrics/page.tsx` | `/metrics` | Hardware metrics per host: CPU, memory, disk, network, charts. | `selectedHost`, `timeRange`, multiple `useSWR`, `useWSSubscription` | `PageHeader`, `Card`, `Tabs`, `Progress`, `AreaChart` (recharts), `ScrollArea` | `metricsAPI.getDashboard()`, `metricsAPI.getHost(host)`, `metricsAPI.getHostHistory(host, ...)` |
| `ips/page.tsx` | `/ips` | Real-time IPS attack map with animated paths, live events, stats, filters. | `autoRefresh`, `refreshInterval`, `severityFilter`, `countryFilter`, `protocolFilter`, `lifecycleFilter`, `activeAttacks`, `projectionScale/Center`, multiple `useSWR` | `PageHeader`, `Card`, `ComposableMap` (react-simple-maps), `AnimatedCounter`, `Progress`, `ScrollArea`, `Badge`, `Button` | `ipsAPI.getMapData(...)`, `ipsAPI.getLiveEvents(...)`, `ipsAPI.getStatistics(...)`, `ipsAPI.getSummary(...)`, `ipsAPI.getFilters()` |

### 2.2 Major Shared Components (`frontend/components/`)

| File | Props Interface | Purpose |
|------|-----------------|---------|
| `app-sidebar.tsx` | none | Collapsible sidebar with nav links, WS indicator, theme toggle. |
| `page-header.tsx` | `PageHeaderProps` (`title`, `description?`, `onRefresh?`, `isLoading?`, `actions?`, `isLive?`, `badge?`) | Sticky page header with title, live badge, refresh button. |
| `theme-provider.tsx` | `ThemeProviderProps` (from `next-themes`) | Wrapper around `next-themes` ThemeProvider. |
| `data-table.tsx` | `DataTableProps<T>` (`columns`, `data`, `page`, `totalPages`, `onPageChange`, `onRowClick?`, `isLoading?`, `emptyMessage?`) | Reusable paginated table. |
| `severity-badge.tsx` | `SeverityBadgeProps` (`severity: string \| number`, `className?`) | Styled severity labels (Critical / High / Medium / Low). |
| `status-badge.tsx` | `StatusBadgeProps` (`status: string`, `className?`) | Styled status labels with dot/pulse. |
| `live-indicator.tsx` | `LiveIndicatorProps` (`status?`, `showLabel?`, `className?`) | Animated connection indicators. |
| `animated-counter.tsx` | `AnimatedCounterProps` (`value`, `duration?`, `className?`, `prefix?`, `suffix?`, `decimals?`) | Animated number ticker. |
| `playbook-viewer.tsx` | `PlaybookViewerProps` (`playbook`, `canApprove?`, `canExecute?`, `onApprove?`, `onDecline?`, `onExecute?`, `isLoading?`) | Displays playbook steps with actions. |
| `yaml-viewer.tsx` | `YamlViewerProps` (`yaml`, `title?`, `maxHeight?`, `showLineNumbers?`, `showCopyButton?`, `showDownloadButton?`, `className?`) | Syntax-highlighted YAML viewer. |

### 2.3 Dashboard Widgets (`frontend/components/dashboard/`)

| File | Props Interface | Purpose |
|------|-----------------|---------|
| `stat-card.tsx` | `StatCardProps` (`title`, `value`, `subtitle?`, `icon`, `trend?`, `variant?`, `className?`, `onClick?`) | Animated stat card with hover gradient. |
| `alerts-chart.tsx` | `AlertsChartProps` (`data: TrendData[]`) | 24h alerts trend area chart (Recharts). |
| `severity-chart.tsx` | `SeverityChartProps` (`data: SeverityCount[]`) | Donut pie chart for severity breakdown. |
| `activity-feed.tsx` | `ActivityFeedProps` (`activities: ActivityItem[]`) | Scrollable recent activity list. |
| `quick-actions.tsx` | `QuickActionsProps` (`pendingApprovals`, `activeInvestigations`) | Quick-action card with shortcuts. |

### 2.4 Key Type Interfaces (`frontend/lib/api.ts`)

| Category | Key Interfaces |
|----------|----------------|
| Alerts | `Alert`, `AlertIOCs`, `AlertRelationships`, `AlertDetailResponse`, `AlertListResponse` |
| Incidents | `Incident`, `IncidentRelationships`, `IncidentDetailResponse`, `IncidentListResponse`, `TimelineEvent`, `IncidentTimeline` |
| Investigations | `Investigation`, `InvestigationStats`, `InvestigationListResponse`, `InvestigationTimeline`, `Playbook`, `PlaybookStep`, `PlaybookYamlResponse`, `AIAnalysis` |
| Archives | `Archive`, `ArchiveStats`, `ArchiveListResponse`, `ArchiveDetailResponse` |
| Dashboard | `DashboardSummary`, `QuickStats`, `DashboardStats`, `TrendData`, `SeverityCount`, `ActivityItem` |
| Metrics | `MetricHost`, `HostMetrics`, `HostCPU`, `HostMemory`, `HostDisk`, `HostNetwork`, `HostLoad`, `HostConnections`, `HostProcess`, `MetricsDashboardResponse`, `MetricsHostDetailResponse`, `MetricsHistoryResponse`, `MetricsRootCauseResponse`, `MetricsThresholds`, `MetricsStatusResponse`, `MetricsAlertResponse` |
| Monitoring | `ServiceStatus`, `ServicesStatus`, `ServiceHealth`, `ServiceLogsResponse`, `ServiceErrorsResponse`, `StuckInvestigationsResponse`, `MonitorHealth` |
| Search | `SearchResponse`, `SearchResult`, `IPSearchResponse`, `DomainSearchResponse`, `SearchInvestigation` |
| IPS Map | `IPSAttack`, `IPSAttackSource`, `IPSAttackDestination`, `IPSPath`, `IPSMapDataResponse`, `IPSLiveEvent`, `IPSLiveEventsResponse`, `IPSStatisticsResponse`, `IPSCountriesResponse`, `IPSFiltersResponse`, `IPSSummaryResponse` |
| AI Assistant | `AssistantContext`, `AssistantHealth`, `AssistantSourcesResponse`, `AssistantQueryRequest`, `AssistantQueryResponse` |

### 2.5 WebSocket (`frontend/lib/websocket.tsx`)

| Export | Type / Signature | Purpose |
|--------|------------------|---------|
| `WebSocketProvider` | React component | Maintains WS connection with auto-reconnect. |
| `useWebSocket()` | Hook | Access WS context. |
| `useWSSubscription` | Hook `(eventType, callback) => void` | Subscribe to specific event types. |
| `WSEventType` | Union | `"investigation_updated" \| "performance_alert" \| "system_health"` |
| `WSMessage` | Interface | Base shape of incoming messages. |

---

## 3. Database Schema Diagram

### 3.1 Engine & Session Configuration

| Property | Value |
|----------|-------|
| **File** | `response/db.py` |
| **Dialect / Driver** | `sqlite+aiosqlite` |
| **Echo** | `False` |
| **Connect args** | `{"check_same_thread": False}` |
| **Session factory** | `AsyncSessionLocal` (`async_sessionmaker`, `expire_on_commit=False`) |
| **DB file path** | `data/investigations.db` (relative to project root) |
| **Initialization** | `init_db()` runs `Base.metadata.create_all()` on startup |

### 3.2 Entity Relationship Diagram (Text)

```
┌─────────────────────┐
│   investigations    │
│   (Investigation)   │
└──────────┬──────────┘
           │
           │ 1 ┌─────────────────────────┐
             ▼ │                         │
    ┌─────────────────────┐              │
    │ investigation_alerts│              │
    │(InvestigationAlert) │              │
    └─────────────────────┘              │
           │                             │
           │ 1 ┌─────────────────────┐   │
             ▼ │                     │   │
    ┌─────────────────────┐          │   │
    │ playbook_approvals  │          │   │
    │  (PlaybookApproval) │          │   │
    └─────────────────────┘          │   │
           │                         │   │
           │ 1 ┌─────────────────────┐   │
             ▼ │                     │   │
    ┌─────────────────────┐          │   │
    │   playbook_runs     │          │   │
    │   (PlaybookRun)     │          │   │
    └─────────────────────┘          │   │
           │                         │   │
           │ 1 ┌─────────────────────┐   │
             ▼ │                     │   │
    ┌─────────────────────┐          │   │
    │  fix_verifications  │          │   │
    │ (FixVerification)   │          │   │
    └─────────────────────┘          │   │
           │                         │   │
           │ 1 ┌─────────────────────┐   │
             ▼ │                     │   │
    ┌─────────────────────┐          │   │
    │      archives       │◄─────────┘   │
    │     (Archive)       │              │
    └─────────────────────┘              │
```

All child tables cascade-delete when an `investigations` row is deleted.

### 3.3 Table: `investigations`

**Model:** `Investigation` (`response/models.py`)

| Column | Python Type | SQLAlchemy Type | Default | Nullable | PK | Index | Unique |
|--------|-------------|-----------------|---------|----------|----|-------|--------|
| `id` | `str` | `String(36)` | `_uuid()` | No | ✅ | — | — |
| `incident_id` | `str` | `String(36)` | — | No | — | ✅ | ✅ |
| `incident_title` | `str` | `Text` | `""` | No | — | — | — |
| `incident_severity` | `str` | `String(20)` | `"medium"` | No | — | — | — |
| `incident_status` | `str` | `String(20)` | `"open"` | No | — | — | — |
| `status` | `str` | `String(30)` | `"pending"` | No | — | ✅ | — |
| `ai_summary` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `ai_narrative` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `ai_risk` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `playbook_yaml` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `playbook_valid` | `bool` | `Boolean` | `False` | No | — | — | — |
| `target_host` | `Optional[str]` | `String(255)` | — | Yes | — | — | — |
| `target_user` | `str` | `String(100)` | `"root"` | No | — | — | — |
| `source_ips` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `hostnames` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `mitre_tactics` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `source` | `str` | `String(50)` | `"general"` | No | — | — | — |
| `ai_error` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `created_at` | `datetime` | `DateTime(timezone=True)` | `_now()` | No | — | — | — |
| `updated_at` | `datetime` | `DateTime(timezone=True)` | `_now()` | No | — | — | — |

**Relationships:** `alerts` (1:N), `approval` (1:1), `run` (1:1), `verification` (1:1), `archive` (1:1) — all cascade delete orphan.

### 3.4 Table: `investigation_alerts`

**Model:** `InvestigationAlert`

| Column | Python Type | SQLAlchemy Type | Default | Nullable | PK | FK | Index |
|--------|-------------|-----------------|---------|----------|----|----|-------|
| `id` | `str` | `String(36)` | `_uuid()` | No | ✅ | — | — |
| `investigation_id` | `str` | `String(36)` | — | No | — | `investigations.id` ON DELETE CASCADE | ✅ |
| `alert_id` | `str` | `String(36)` | — | No | — | — | ✅ |
| `alert_json` | `str` | `Text` | — | No | — | — | — |
| `severity` | `str` | `String(20)` | `"medium"` | No | — | — | — |
| `source` | `str` | `String(50)` | `""` | No | — | — | — |
| `title` | `str` | `Text` | `""` | No | — | — | — |
| `created_at` | `datetime` | `DateTime(timezone=True)` | `_now()` | No | — | — | — |

### 3.5 Table: `playbook_approvals`

**Model:** `PlaybookApproval`

| Column | Python Type | SQLAlchemy Type | Default | Nullable | PK | FK | Unique |
|--------|-------------|-----------------|---------|----------|----|----|--------|
| `id` | `str` | `String(36)` | `_uuid()` | No | ✅ | — | — |
| `investigation_id` | `str` | `String(36)` | — | No | — | `investigations.id` ON DELETE CASCADE | ✅ |
| `decision` | `str` | `String(20)` | — | No | — | — | — |
| `decided_by` | `str` | `String(255)` | `"analyst"` | No | — | — | — |
| `decided_at` | `datetime` | `DateTime(timezone=True)` | `_now()` | No | — | — | — |
| `reason` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `edited_playbook` | `Optional[str]` | `Text` | — | Yes | — | — | — |

### 3.6 Table: `playbook_runs`

**Model:** `PlaybookRun`

| Column | Python Type | SQLAlchemy Type | Default | Nullable | PK | FK | Unique |
|--------|-------------|-----------------|---------|----------|----|----|--------|
| `id` | `str` | `String(36)` | `_uuid()` | No | ✅ | — | — |
| `investigation_id` | `str` | `String(36)` | — | No | — | `investigations.id` ON DELETE CASCADE | ✅ |
| `status` | `str` | `String(20)` | `"running"` | No | — | — | — |
| `output` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `exit_code` | `Optional[int]` | `Integer` | — | Yes | — | — | — |
| `started_at` | `datetime` | `DateTime(timezone=True)` | `_now()` | No | — | — | — |
| `finished_at` | `Optional[datetime]` | `DateTime(timezone=True)` | — | Yes | — | — | — |

### 3.7 Table: `fix_verifications`

**Model:** `FixVerification`

| Column | Python Type | SQLAlchemy Type | Default | Nullable | PK | FK | Unique |
|--------|-------------|-----------------|---------|----------|----|----|--------|
| `id` | `str` | `String(36)` | `_uuid()` | No | ✅ | — | — |
| `investigation_id` | `str` | `String(36)` | — | No | — | `investigations.id` ON DELETE CASCADE | ✅ |
| `status` | `str` | `String(20)` | `"checking"` | No | — | — | — |
| `new_alerts_found` | `int` | `Integer` | `0` | No | — | — | — |
| `checked_at` | `datetime` | `DateTime(timezone=True)` | `_now()` | No | — | — | — |
| `detail` | `Optional[str]` | `Text` | — | Yes | — | — | — |

### 3.8 Table: `archives`

**Model:** `Archive`

| Column | Python Type | SQLAlchemy Type | Default | Nullable | PK | FK | Index |
|--------|-------------|-----------------|---------|----------|----|----|-------|
| `id` | `str` | `String(36)` | `_uuid()` | No | ✅ | — | — |
| `investigation_id` | `str` | `String(36)` | — | No | — | `investigations.id` ON DELETE CASCADE | — |
| `incident_id` | `str` | `String(36)` | — | No | — | — | ✅ |
| `full_context_json` | `str` | `Text` | — | No | — | — | — |
| `source_ips` | `Optional[str]` | `Text` | — | Yes | — | ✅ |
| `hostnames` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `mitre_tactics` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `severity` | `str` | `String(20)` | `"medium"` | No | — | — | — |
| `fix_status` | `str` | `String(30)` | `"unknown"` | No | — | — | — |
| `incident_title` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `fix_detail` | `Optional[str]` | `Text` | — | Yes | — | — | — |
| `archived_at` | `datetime` | `DateTime(timezone=True)` | `_now()` | No | — | ✅ |

### 3.9 Constraints Summary

- **Unique:** `investigations.incident_id`, `playbook_approvals.investigation_id`, `playbook_runs.investigation_id`, `fix_verifications.investigation_id`, `archives.investigation_id`
- **Indexed:** `investigations.incident_id`, `investigations.status`, `investigation_alerts.investigation_id`, `investigation_alerts.alert_id`, `archives.incident_id`, `archives.source_ips`, `archives.archived_at`
- **Foreign Keys:** All child tables → `investigations.id` with `ON DELETE CASCADE`
- **Cascade Rules:** All relationships specify `cascade="all, delete-orphan"`

---

## 4. Pipeline Data-Flow Diagram

This section traces the complete lifecycle of an alert from ingestion in Elasticsearch through OpenSOAR forwarding, incident creation, AI investigation, remediation, verification, and finally archival.

---

### Phase 1: Ingestion (Elasticsearch Polling)

#### Step 1.1 — Forwarder Loop Startup
- **File/Function:** `pipeline/poller/main.py` → `run_forwarder(shutdown_event)`
- **Transformation:** Initializes the poller loop, authenticates to OpenSOAR via `client.authenticate()`, builds `index_patterns` for `wazuh`, `falco`, `filebeat`, and optionally `suricata`.
- **Decisions:**
  - Exits immediately if `settings.opensoar_enabled == False`.
  - Aborts if a poll cycle exceeds 120s.
- **Async Boundary:** `async` main loop running indefinitely.

#### Step 1.2 — Per-Source Polling
- **File/Function:** `pipeline/poller/main.py` → `poll_source(source, index_pattern)`
- **Transformation:** Builds an ES `range` query on `@timestamp` using the cursor from `cursor_manager._get_cursor(source)`. For `filebeat`, adds extra filters: `fileset.name=eve` AND `suricata.eve.event_type=alert`.
- **Decisions:**
  - If no hits, returns `(0, 0)`.
  - If ES query fails, logs and returns `(0, 0)`.
- **Async Boundary:** `await search_alerts(...)` (ES I/O). All sources are polled in parallel via `asyncio.gather(*tasks, return_exceptions=True)`.

#### Step 1.3 — Hit Deduplication (Within Batch)
- **File/Function:** `pipeline/poller/main.py` → inside `poll_source()` loop
- **Transformation:** Iterates over `hits`. Maintains `processed_ids` set per batch.
- **Decisions:**
  - If `es_id in processed_ids` → `duplicates += 1`, skip.
  - If `_is_ever_seen(source, es_id)` (global file-based seen-IDs cache) → skip.
- **Storage/Send:** Updates `latest_ts` cursor via `_advance_timestamp()`.

---

### Phase 2: Mapping (Raw ES Doc → OpenSOAR Alert Schema)

#### Step 2.1 — Source-Specific Mapper Dispatch
- **File/Function:** `pipeline/mappers/__init__.py` → `map_alert(source, payload)`
- **Transformation:** Looks up mapper in `MAPPERS` dict (`wazuh`, `falco`, `suricata`, `filebeat`, `generic`). Falls back to `generic` if unknown.
- **Decisions:** If mapper missing or throws, returns original payload (graceful degradation).

#### Step 2.2 — Wazuh Mapping
- **File/Function:** `pipeline/mappers/wazuh.py` → `map_wazuh_alert(doc)`
- **Transformation:**
  - Extracts `rule`, `data`, `agent`, `mitre`, `syscheck`, `decoder`, `manager`.
  - Calls `pipeline.enrichment.sigma.is_noise_alert()` to filter noisy alerts **before** full mapping.
  - Validates doc has `rule` + `agent` structures (`_validate_wazuh_doc`).
  - Maps Wazuh `rule.level` → OpenSOAR severity via `map_severity(rule_level, "wazuh")`.
  - Extracts IPs via `pipeline.mappers.ip_extractor.extract_ips(doc, "wazuh")`.
  - Builds `tags` (`wazuh-level-X`, `wazuh-rule-ID`, `mitre-tactic-*`, `mitre-technique-*`, `mitre-ID`).
  - Builds `iocs` (IPs, hashes from `syscheck`, URLs, usernames).
  - Builds `observables` (structured array of IPs, domains, hashes).
  - Builds `metadata` (agent info, decoder, manager, MITRE tactics/techniques/IDs).
- **Decisions:** Raises `ValueError` if sigma noise filter matches or doc validation fails. On unexpected exception, returns `_build_fallback_alert()`.

#### Step 2.3 — Suricata Mapping
- **File/Function:** `pipeline/mappers/suricata.py` → `map_suricata_alert(doc)`
- **Transformation:**
  - Navigates `doc["suricata"]["eve"]["alert"]` for signature, category, signature_id.
  - Applies `_is_noisy_alert()` with hardcoded protocol-noise patterns.
  - Calls `sigma.is_noise_alert("suricata", doc)`.
  - Maps category + signature to severity via `_map_category_to_severity()` (1=low, 4=critical).
  - Extracts IPs via `ip_extractor.extract_ips(doc, "suricata")`.
  - Builds network flow description, HTTP/DNS/TLS/fileinfo context.
  - Builds `iocs` (IPs, ports, domains, URLs, file hashes).
  - Builds `observables`.
  - **Calls `pipeline.enrichment.mitre.enrich_with_mitre(alert)`** to dynamically inject MITRE tags.
- **Decisions:** Raises `ValueError` if missing signature or sigma noise matched.

#### Step 2.4 — Falco Mapping
- **File/Function:** `pipeline/mappers/falco.py` → `map_falco_alert(doc)`
- **Transformation:**
  - Validates doc has `priority`, `rule`, `output` and is NOT Wazuh data.
  - Maps Falco `priority` string → severity via `map_severity(priority, "falco")`.
  - Extracts IPs, builds container/K8s/process metadata from `output_fields`.
  - Builds `observables`.
  - **Calls `pipeline.enrichment.mitre.enrich_with_mitre(alert)`**.
- **Decisions:** Raises `ValueError` on sigma noise or validation failure.

#### Step 2.5 — Filebeat Mapping
- **File/Function:** `pipeline/mappers/filebeat.py` → `map_filebeat_alert(doc)`
- **Transformation:**
  - Checks if doc is a Suricata EVE alert (`fileset.name == "eve"` and `event_type == "alert"`).
  - If not, raises `ValueError` to skip non-Suricata Filebeat events.
  - If valid, delegates entirely to `map_suricata_alert(doc)`.

#### Step 2.6 — Generic Fallback Mapping
- **File/Function:** `pipeline/mappers/generic.py` → `map_generic_alert(doc)`
- **Transformation:**
  - Uses `FIELD_MAPPINGS` to heuristically extract common fields across 60+ possible field names (source_ip, dest_ip, hostname, severity, title, description, timestamp, action, protocol, port).
  - Auto-detects source type by inspecting first 300 chars of doc string (`wazuh`, `falco`, `suricata`, `crowdstrike`, `aws_guardduty`, etc.).
  - Normalizes numeric/string severity to 0-10 scale (`_normalize_severity`), then calls `map_severity(level, "generic")`.
  - Builds title from multiple fallback fields; builds description from available fields or constructs one from IPs/hosts/protocol.
- **Decisions:** If no meaningful title found, defaults to `"Generic Security Alert"`.

#### Step 2.7 — Severity Mapping
- **File/Function:** `pipeline/mappers/severity.py` → `map_severity(level, source)`
- **Transformation:** Converts source-specific levels to unified OpenSOAR scale:
  - **Wazuh:** level ≥10 → critical, ≥7 → high, ≥4 → medium, else low.
  - **Falco:** emergency/alert/critical → critical; error → high; warning/notice → medium; info/informational/debug → low.
  - **Suricata:** 1→low, 2→medium, 3→high, 4→critical.
  - **Generic:** ≥10 critical, ≥7 high, ≥4 medium, else low.

---

### Phase 3: Enrichment & Filtering

#### Step 3.1 — Alert Processing Entry Point
- **File/Function:** `pipeline/poller/alert_processor.py` → `process_single_alert(es_id, source_doc, source, mapper, latest_ts)`
- **Transformation:** Orchestrates mapping, deduplication, noise filtering, severity filtering, enrichment, campaign detection, and forwarding.
- **Decisions (in order):**
  1. **Map** → if `ValueError` (validation/noise), return `skipped=1`. If unexpected exception, return `map_errors=1`.
  2. **Set `source_id`** if missing.
  3. **Deduplication** → if `is_duplicate(source, payload)` returns True, return `dedup_skipped=1`.
  4. **Noise Learning** → `track_alert_for_noise(payload)` (always runs).
  5. **Auto-Noise Filter** → if `is_auto_noise(payload)` returns True, return `skipped=1`.
  6. **Severity Filter** → if `SEVERITY_ORDER[alert_severity] < SEVERITY_ORDER[min_severity]`, return `skipped=1`.
- **Async Boundary:** `await is_duplicate()` (Redis I/O). Rest is sync.

#### Step 3.2 — Source-Specific Deduplication
- **File/Function:** `pipeline/services/dedup.py` → `is_duplicate(source, payload)`
- **Transformation:** Generates a source-specific dedup key:
  - **Wazuh:** `agent_id + rule_id + source_ip`
  - **Falco:** `hostname + container_id + rule_name`
  - **Suricata:** `signature_id + src_ip + dst_ip + dst_port`
  - **Filebeat:** threat intel grouped by `rule_name` only; active attacks by `rule_name + src_ip + dst_ip`.
- **Decisions:**
  - Threat intel alerts use extended TTL (`THREAT_INTEL_TTL = 300s`).
  - Checks Redis first, then in-memory `_memory_cache` fallback.
  - If duplicate → returns `True`; otherwise sets Redis key with TTL and returns `False`.
- **Storage/Send:** Writes to Redis (`opensoar:dedup:{hash}`) with 5-minute TTL.
- **Async Boundary:** `await _redis_get()` / `await _redis_set()`.

#### Step 3.3 — Noise Learning
- **File/Function:** `pipeline/services/noise_learner.py` → `track_alert_for_noise(alert)` and `is_auto_noise(alert)`
- **Transformation:** Tracks alert frequency by `source|title` key in `_alert_tracker`. Auto-generates noise rules when `count >= 10` within `TIME_WINDOW` (1 hour) and `<20%` are high/critical severity.
- **Decisions:** `is_auto_noise()` loads `data/artifacts/auto_noise_rules.json` and returns `True` if title contains any learned pattern.
- **Storage/Send:** Reads/writes `data/artifacts/noise_data.json` and `data/artifacts/auto_noise_rules.json`.

#### Step 3.4 — Sigma Noise Filtering
- **File/Function:** `pipeline/enrichment/sigma.py` → `is_noise_alert(source, doc)`
- **Transformation:** Loads YAML Sigma rules from `config/sigma_rules`. Evaluates `detection.selection` against document fields using `contains|startswith|endswith|equals|regex` operators.
- **Decisions:**
  - **NEVER filters** if attack patterns present (malware, brute force, exploit, C2, etc.).
  - **NEVER filters** critical/high severity.
  - **NEVER filters** threat intel indicators (Spamhaus, CINS, etc.).
  - Only returns `True` for true low-value noise.
- **Storage/Send:** Reads `config/sigma_rules/*.yml` into `_loaded_rules` cache.

#### Step 3.5 — MITRE ATT&CK Enrichment
- **File/Function:** `pipeline/enrichment/mitre.py` → `enrich_with_mitre(alert)` → `dynamic_mitre_mapping(...)`
- **Transformation:**
  - Analyzes `title + category + signature + description + rule_name` against `_MITRE_KEYWORD_MAP` (189 keyword-to-technique mappings).
  - Calculates confidence score (10-100) based on keyword overlap, high-confidence context patterns, and severity penalty.
  - Deduplicates techniques, then injects tags: `mitre-T{ID}`, `mitre-conf-high/medium/low`.
  - Stores full technique objects in `alert["mitre_techniques"]`.
- **Decisions:** Returns alert unchanged if no text to analyze.

#### Step 3.6 — GeoIP & Cloud Provider Enrichment
- **File/Function:** `pipeline/enrichment/geoip.py` → `enrich_alert(alert)` → `enrich_ip(ip_str)`
- **Transformation:**
  - Checks if IP is private (`_is_private`).
  - If public, performs GeoIP2 City/ASN lookup (`_geoip_lookup`).
  - Detects cloud provider from ASN org name dynamically (`_detect_provider_from_asn`) with 20+ provider keywords.
  - Falls back to hardcoded `_CLOUD_IP_RANGES` for AWS, Azure, Google Cloud, DigitalOcean, OVH, Hetzner.
  - Final fallback to `ip-api.com` free API.
  - Injects tags: `internal-source/internal-target`, `src-country-{CC}`, `dst-country-{CC}`, `src-AS{number}`, `src-provider-{Name}`.
  - Prepends network context to `alert["description"]`.
- **Decisions:** Skips GeoIP lookup for private IPs.
- **Storage/Send:** In-memory lazy-loaded GeoIP2 readers. No external DB writes.

#### Step 3.7 — Threat Intel IP Tracking
- **File/Function:** `pipeline/poller/alert_processor.py` → inside `process_single_alert()`
- **Transformation:** If `_is_threat_intel(clean_payload)`, adds source IP to `_THREAT_INTEL_IPS[rule]` set and appends unique IP count to description.
- **Decisions:** Only runs for blocklist-style alerts (DROP, CINS, Spamhaus).

#### Step 3.8 — Campaign / Multi-Signal Correlation
- **File/Function:** `pipeline/services/correlator.py` → `track_alert(alert)`
- **Transformation:**
  - Tracks alerts by `source_ip`, `dest_ip`, `username`, `hostname` in in-memory dictionaries with 24-hour TTL.
  - Detects campaign type (`ssh_brute_force`, `port_scan`, `threat_intel_hit`, `web_attack`) via keyword scoring.
  - If `total_alerts >= 3` or `unique_sources >= 2` with `total_alerts >= 2`, returns campaign context string.
- **Decisions:** If campaign detected, prepends campaign description to `alert["description"]`.

---

### Phase 4: Forwarding to OpenSOAR

#### Step 4.1 — Pattern Tracking & Repeated-Alert Grouping
- **File/Function:** `pipeline/poller/alert_processor.py` → inside `process_single_alert()`
- **Transformation:** Computes `pattern_key = source + source_ip + rule_name`. Loads `_PATTERN_TRACKING` from disk (`data/artifacts/pattern_tracking.json`).
- **Decisions:**
  - If existing tracking has `alert_id` → calls `client.update_alert()` to increment `occurrence_count` on the existing OpenSOAR alert. Returns `sent=1` (grouped).
  - If no existing tracking → proceeds to create new alert.
- **Storage/Send:** Reads/writes `data/artifacts/pattern_tracking.json`.

#### Step 4.2 — Send Alert to OpenSOAR API
- **File/Function:** `pipeline/sender.py` → `OpenSOARClient.send_alert(alert_data)`
- **Transformation:** Authenticates via Bearer token (`/api/v1/auth/login`). Posts mapped alert to `POST /api/v1/webhooks/alerts`.
- **Decisions:**
  - Handles 401 by re-authenticating once.
  - Handles 429 with exponential backoff (max 4 retries, base delay 2s, respects `Retry-After` header).
  - If 422 → returns `{"status": "already_exists"}`.
  - On timeout/network errors → raises after retries exhausted.
- **Storage/Send:** HTTP POST to OpenSOAR webhook. Returns `alert_id`.
- **Async Boundary:** `await _post_with_retry()` (HTTP I/O with retry loop).

#### Step 4.3 — Post-Forward Data Usage Pipeline (Background)
- **File/Function:** `pipeline/poller/alert_processor.py` → `asyncio.create_task(_process_alert_data_usage(alert_id, clean_payload))`
- **Transformation:** Spawns background task after successful forward. Triggers WebSocket broadcast (`ws_manager.broadcast("performance", {"type": "alert_created", ...})`).
- **Async Boundary:** Fire-and-forget `asyncio.create_task()`.

---

### Phase 5: Data Usage & Incident Creation

#### Step 5.1 — Data Usage Orchestrator
- **File/Function:** `pipeline/datausage/orchestrator.py` → `process_alert(alert_id, alert_data)`
- **Transformation:** Runs four stages sequentially inside `try/except` blocks:
  1. **Observables** → `observable_manager.auto_create_from_alert()`
  2. **AI Triage** → `ai_pipeline.smart_triage_and_apply()`
  3. **Incident Correlation** → `incident_manager.process_alert()`
  4. **Alert Enrichment** → `alert_manager.auto_enrich_alert()`
- **Decisions:** Each stage is isolated; failure in one does not stop the next.
- **Storage/Send:** Updates in-memory `_stats` counters.
- **Async Boundary:** `await` each stage sequentially.

#### Step 5.2 — Incident Manager (Correlation & Auto-Creation)
- **File/Function:** `pipeline/datausage/incident_manager.py` → `process_alert(alert_id, alert_data)`
- **Transformation:**
  - Extracts MITRE tactics, attack patterns, cloud provider, campaign type, country.
  - Computes `kill_chain` progression via `detect_kill_chain_progression()`.
  - Decides `should_create_incident()` based on 12 strict rules:
    - Noise alerts (ICMP, etc.) → never create.
    - Critical severity → always create.
    - Attack patterns (SSH brute force, port scan, malware, C2, web attack, DDoS) → always create.
    - Campaign detected → always create.
    - Kill chain (2+ MITRE phases) → always create.
    - Spamhaus DROP → always create.
    - High severity + MITRE tactics → create.
    - Medium + high-risk tactic → create.
    - Standalone CINS without attack pattern → DON'T create.
    - 2+ tracked alerts from same source → create.
    - Low severity → DON'T create.
  - If creating, generates title via `generate_incident_title()`, tags via `generate_incident_tags()`, severity via `calculate_incident_severity()`.
  - First checks `_find_or_update_existing_incident()` to prevent duplicates by `source_ip`. Searches local cache (`data/artifacts/incident_cache.json`) then OpenSOAR API (`list_incidents` + `get_incident_alerts`).
  - If existing incident found, escalates severity if new alert is higher severity.
  - If no existing incident, calls `client.create_incident()` then `client.link_alert_to_incident()`.
  - Updates local `_incident_cache` and saves to disk.
- **Storage/Send:**
  - Reads/writes `data/artifacts/incident_cache.json` and `data/artifacts/incident_links.json`.
  - Creates Incident in OpenSOAR via API.
- **Async Boundary:** Multiple `await client.list_incidents()`, `await client.get_incident()`, `await client.create_incident()`, `await client.link_alert_to_incident()`.

#### Step 5.3 — Alert Manager (Auto-Enrichment)
- **File/Function:** `pipeline/datausage/alert_manager.py` → `auto_enrich_alert(alert_id, alert_data, incident_id)`
- **Transformation:**
  - If `incident_id` present → calls `auto_update_on_incident_link()` to PATCH alert status from `new` → `investigating`.
  - Calls `auto_set_determination()` to calculate determination:
    - Noise patterns → `benign`
    - High-risk MITRE tactics or malicious attack patterns or Spamhaus or critical severity → `malicious`
    - Default → `unknown`
    - Only updates if current determination is `unknown`.
  - Calls `auto_enrich_comment()` to post GeoIP, cloud provider, MITRE tactics/techniques, and campaign context as a comment on the alert.
- **Storage/Send:** PATCH/POST to OpenSOAR `/api/v1/alerts/{id}` and `/api/v1/alerts/{id}/comments`.
- **Async Boundary:** `await client.update_alert()`, `await client.add_comment()`.

---

### Phase 6: Investigation (Watcher & AI Engine)

#### Step 6.1 — Incident Watcher Loop
- **File/Function:** `response/watcher/main.py` → `watch_incidents(shutdown_event)`
- **Transformation:** Polls OpenSOAR for open incidents in a paginated loop (`limit=100`, max `offset=1000`). Fetches full alert details for each incident via `reader.get_incident_alerts()` and `reader.get_alert()`.
- **Decisions:**
  - Skips incidents already in local DB (`known_ids`).
  - Skips incidents with `alert_count < settings.incident_min_alerts`.
  - If no full alerts fetched, stores empty list (prevents infinite retry).
- **Storage/Send:** Reads from OpenSOAR API.
- **Async Boundary:** `await reader.list_incidents()` (pagination loop). Also runs stuck-recovery tasks (`_retry_pending_investigations`, `_execute_approved_investigations`, `_check_stuck_investigations`, `_recover_stuck_running_investigations`).

#### Step 6.2 — Investigation Context Building
- **File/Function:** `response/watcher/context_builder.py` → `_build_investigation_context(incident, alerts)`
- **Transformation:**
  - Extracts comprehensive IOCs: source IPs, dest IPs, hostnames, usernames, processes, file paths, domains, hashes, ports, protocols, services.
  - Builds timeline, behavioral indicators (auth failures, reconnaissance, execution, exfiltration, malware, web attack, DoS, privilege escalation).
  - Performs authentication pattern analysis (`_analyze_authentication_patterns`) to detect brute force + successful login sequences.
  - Determines attack type (`_determine_attack_type`) and calculates dynamic risk score (`_calculate_risk_score`, 0-100).
  - Extracts MITRE tactics/techniques from tags.
  - Preserves full alert data in `all_alerts_data`.
- **Decisions:** None (pure aggregation).

#### Step 6.3 — Investigation DB Record Creation
- **File/Function:** `response/watcher/investigation_db.py` → `_create_investigation(incident, context)` and `_store_alerts(inv_id, alerts)`
- **Transformation:**
  - Generates UUID. Determines `target_host` (priority: hostname → dest_ip → source_ip → `settings.ansible_remote_host` → `localhost`).
  - Determines `target_user` (priority: context username → `settings.ansible_remote_user` → `root`).
  - Inserts `Investigation` row with `status="pending"`, NULL AI fields.
  - `_store_alerts()` inserts each alert as `InvestigationAlert` row with full `alert_json` blob.
- **Storage/Send:** Inserts into local SQL DB (`Investigation`, `InvestigationAlert` tables).
- **Async Boundary:** `async with AsyncSessionLocal()` for both inserts.

#### Step 6.4 — AI Engine Trigger
- **File/Function:** `response/watcher/ai_runner.py` → `_run_ai_engine(investigation_id, context)`
- **Transformation:** Acquires `_ai_semaphore` (concurrency limit = 4). Calls `response.ai_engine.main.run_investigation()`.
- **Decisions:** On exception, updates investigation row with `ai_error` and `status="pending"`.
- **Async Boundary:** `async with _ai_semaphore` (async semaphore). Fire-and-forget from watcher (`asyncio.create_task`).

#### Step 6.5 — AI Engine Execution
- **File/Function:** `response/ai_engine/main.py` → `run_investigation(investigation_id, context)`
- **Transformation:**
  - Updates DB `status="pending"`.
  - Builds prompt via `response.ai_engine.prompt_builder._build_prompt(context)`.
  - Checks circuit breaker (`_get_circuit_breaker().can_proceed()`).
  - Calls LLM via `response.ai_engine.llm_clients._call_llm(prompt)` with adaptive timeout.
  - **Provider decision:** Google Gemini gets `timeout + 30s`; Ollama gets `timeout + 120s`.
  - Parses response via `response.ai_engine.response_parser._parse_ai_response()` and validates playbook YAML via `_validate_playbook()`.
  - On timeout or any LLM error → falls back to `_generate_fallback_ai_result()` (rule-based summary + generic Ansible playbook with IP blocking).
  - On success, updates investigation with `ai_summary`, `ai_narrative`, `ai_risk`, `playbook_yaml`, `playbook_valid`, `status="awaiting_approval"`.
  - Calls `response.auto_approve.apply_auto_approve()`; if auto-approved, broadcasts status change and skips notification.
  - If not auto-approved, sends approval notification via `response.notification.send_approval_notification()`.
- **Decisions:**
  - Empty response (no summary and no playbook) → status remains failed.
  - Circuit breaker open → rate-limited, returns False.
  - Auto-approve triggered → status jumps to `approved` and execution begins.
- **Storage/Send:** Updates `Investigation` row in local DB.
- **Async Boundary:** `await _call_llm(prompt)` (external LLM API). Multiple DB updates.

---

### Phase 7: Remediation (Ansible Execution)

#### Step 7.1 — Playbook Execution
- **File/Function:** `response/ansible_exec.py` → `execute_playbook(investigation_id)`
- **Transformation:**
  - Loads `Investigation` + `PlaybookApproval` from DB.
  - Uses `approval.edited_playbook` if available; otherwise uses `investigation.playbook_yaml`.
  - Validates target host resolvability; falls back to `settings.ansible_remote_host`.
  - Replaces playbook `hosts:` value with `target` to match inventory group.
  - Fixes common AI-generated Jinja2 syntax errors (e.g., `source: "{ item }"` → `source: "{{ item }}"`).
  - Validates YAML syntax (`yaml.safe_load`) and Ansible syntax (`ansible-playbook --syntax-check`).
  - Writes playbook to `PLAYBOOKS_DIR/{investigation_id}.yml` and inventory to `PLAYBOOKS_DIR/{investigation_id}_inventory`.
  - Tests SSH connection via `_test_ssh_connection()` (uses `sshpass` if password auth, else key-based).
  - If SSH auth fails → sets investigation status to `pending` (allows retry with corrected credentials) instead of `failed`.
  - Runs `ansible-playbook -i inventory playbook.yml -v` via `asyncio.create_subprocess_exec()`.
  - Streams stdout/stderr line-by-line.
- **Decisions:**
  - If `settings.ansible_enabled == False` → dry run: updates run record as `skipped`, investigation as `completed`, and still triggers fix verifier.
  - Exit code 0 → `completed`.
  - Exit code -15 → `failed` (timeout).
  - Exit code >0 → analyzes output for `Permission denied`, `Connection refused`, `UNREACHABLE`, `FAILED` and sets `failure_reason`.
- **Storage/Send:** Creates `PlaybookRun` record in DB. Updates `Investigation` status.
- **Async Boundary:** `await _test_ssh_connection()`, `await _run_ansible()`, `async with AsyncSessionLocal()`.

#### Step 7.2 — Fix Verifier Scheduling
- **File/Function:** `response/ansible_exec.py` → `_trigger_fix_verifier(investigation_id)`
- **Transformation:** Sleeps for `settings.fix_verify_wait_minutes * 60` seconds, then calls `response.fix_verifier.verify_fix()`.
- **Decisions:** Runs regardless of playbook exit code (even on failure).
- **Async Boundary:** `await asyncio.sleep(wait_seconds)` inside `asyncio.create_task()`.

---

### Phase 8: Verification

#### Step 8.1 — Fix Verification
- **File/Function:** `response/fix_verifier.py` → `verify_fix(investigation_id)`
- **Transformation:**
  - Loads investigation + alerts + playbook run from DB.
  - Calls `_query_es_for_recurrence()` to count new ES alerts matching original `rule_name`s in the time window since playbook finished.
  - Calls `_active_verify_remediation()` to check if same source IPs or target host still generate alerts in the last 5 minutes.
  - Determines verdict:
    - **Playbook failed + 0 new alerts** → `playbook_failed_but_quiet`
    - **Playbook failed + new alerts** → `playbook_failed_problem_worse`
    - **0 new alerts + active verification passed** → `likely_fixed`
    - **1-2 new alerts + active verification passed** → `inconclusive`
    - **3+ new alerts or active verification failed** → `not_fixed`
  - Saves `FixVerification` record.
  - Posts comment to first alert of the OpenSOAR incident via `_post_opensoar_comment()`.
  - Triggers archiver.
- **Storage/Send:**
  - Queries Elasticsearch (`es.count()` on wazuh, falco, filebeat indices).
  - Inserts `FixVerification` row in local DB.
  - Posts comment to OpenSOAR `/api/v1/alerts/{id}/comments`.
- **Async Boundary:** Multiple `await es.count()` calls, DB inserts, HTTP POST to OpenSOAR.

---

### Phase 9: Archival

#### Step 9.1 — Archive Investigation
- **File/Function:** `response/archiver.py` → `archive_investigation(investigation_id, fix_status)`
- **Transformation:**
  - Checks if `Archive` row already exists; idempotent skip if yes.
  - Loads full investigation with all relations (`alerts`, `approval`, `run`, `verification`) using `selectinload`.
  - Loads linked `Incident` record.
  - Builds complete JSON snapshot via `_build_full_context()` including:
    - Investigation metadata
    - All alert JSONs
    - AI summary/narrative/risk/playbook
    - Approval decision
    - Playbook run status/output/exit code/duration
    - Fix verification status
    - Full incident details
  - Serializes to JSON string.
- **Decisions:** If `inv.verification` exists, uses its status; if declined approval, uses `"declined"`.
- **Storage/Send:**
  - Inserts `Archive` row in local DB.
  - Updates `Investigation.status = "archived"`.
- **Async Boundary:** `async with AsyncSessionLocal()`.

---

### Parallel Branch: Performance Anomaly Detection

These modules run in a separate performance monitoring loop but produce alerts that also flow into OpenSOAR.

#### A.1 — Anomaly Detection
- **File/Function:** `pipeline/enrichment/anomaly_detector.py` → `anomaly_detector.detect_all(metrics)`
- **Transformation:** Runs hybrid detection on `HostMetrics`:
  - Threshold checks for CPU, memory, disk usage, disk inodes, load average, network bytes/sec.
  - Statistical anomaly detection (stddev from baseline stored in Redis) if `performance_anomaly_use_statistical=True`.
- **Decisions:** Cooldown enforced via `performance_redis.is_in_cooldown()`. Returns list of `AnomalyResult` objects.

#### A.2 — Root Cause Analysis
- **File/Function:** `pipeline/enrichment/root_cause.py` → `root_cause_analyzer.analyze_anomaly(metrics, anomaly_type, current_value, device)`
- **Transformation:** If `performance_anomaly_use_ai=True`, builds LLM prompt with system state and calls `_call_llm()`. Parses JSON response for explanation, confidence, affected process, evidence, remediation type.
- **Decisions:** If AI disabled or fails, returns fallback explanation without AI.

---

### Summary of Key Async Boundaries

| Boundary | File/Function | Purpose |
|----------|---------------|---------|
| **ES Poll** | `poll_source()` | `await search_alerts()` |
| **Redis Dedup** | `is_duplicate()` | `await _redis_get()` / `await _redis_set()` |
| **OpenSOAR Send** | `send_alert()` | `await _post_with_retry()` |
| **Data Usage** | `_process_alert_data_usage()` | `asyncio.create_task()` (fire-and-forget) |
| **Incident Search/Create** | `incident_manager` | Multiple `await client.*()` API calls |
| **Watcher Poll** | `watch_incidents()` | `await reader.list_incidents()` pagination |
| **DB Inserts** | `_create_investigation()` | `async with AsyncSessionLocal()` |
| **AI Engine** | `_run_ai_engine()` | `async with _ai_semaphore` + `await _call_llm()` |
| **Ansible Run** | `execute_playbook()` | `await _test_ssh_connection()` + `await _run_ansible()` (subprocess) |
| **Fix Verify Delay** | `_trigger_fix_verifier()` | `await asyncio.sleep()` in background task |
| **ES Recheck** | `verify_fix()` | `await es.count()` on multiple indices |
| **Archive** | `archive_investigation()` | `async with AsyncSessionLocal()` |

---

*Document generated from live codebase analysis.*
