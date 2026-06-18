# Performance Monitoring — Technical Documentation

## 1. Feature name
Performance Monitoring & Remediation

## 2. Purpose
Continuously poll host-level metrics from Elasticsearch (`telegraf-*`), detect anomalies using statistical baselines and configurable thresholds, generate dynamic Ansible remediation playbooks, surface a real-time dashboard, and track full lifecycle from alert → investigation → approval → execution → verification.

## 3. Input
- **Elasticsearch `telegraf-*` indices**: CPU (`cpu.usage_iowait`, `cpu.usage_user`, `cpu.usage_system`), memory (`mem.used_percent`), disk (`disk.used_percent`, `disk.inodes_used_percent`), network (`net.bytes_recv`, `net.bytes_sent`, `net.drop_in`), system load (`system.load1`), procstat (`procstat.cpu_usage`, `procstat.memory_rss`), netstat (`netstat.tcp_established`), disk_dir (`disk_dir.size`).
- **Runtime configuration**: Thresholds from `config/settings.py` (`PERFORMANCE_CPU_WARNING`, `PERFORMANCE_CPU_CRITICAL`, etc.); `PERFORMANCE_ENABLED` toggle.
- **Historical baselines**: Stored in Redis (mean, std, p95, p99 per host/metric).

## 4. Processing steps
1. **Poll** (`pipeline/performance_poller.py`): Query ES per host for each metric type in parallel; validate freshness (5 min fresh / 10 min stale).
2. **Store** (`core/redis_performance.py`): Write current metrics to Redis (TTL 300s); append to time-series history (max 1,000 points); update rolling baseline.
3. **Detect** (`pipeline/datausage/performance_orchestrator.py`): `AnomalyDetector.detect_all()` compares current values against thresholds + baselines; applies cooldown to prevent flapping.
4. **Root Cause** (`pipeline/datausage/performance_orchestrator.py`): `_determine_playbook_type()` maps anomaly type + top processes → playbook type (e.g., `cpu_high_nginx`, `disk_full_root`).
5. **Alert** (`pipeline/datausage/performance_orchestrator.py`): Creates performance alert object; broadcasts via WebSocket; stores alert in Redis sorted set.
6. **Investigate** (`pipeline/datausage/performance_orchestrator.py`): `_create_performance_investigation()` builds `PlaybookContext`, calls `generate_dynamic_playbook()`, creates `Investigation` row with `status="awaiting_approval"`.
7. **Approve / Execute** (`response/auto_approve.py` + `response/ansible_exec.py`): Auto-approval guardrails → static/dynamic/AI confidence checks → human approval via UI → Ansible execution with SSH pre-check.
8. **Verify** (`response/fix_verifier.py`): Re-query ES for metric recurrence; update `FixVerification` verdict.

## 5. Output
- **Redis**: `opensoar:performance:metrics:<host>`, `:history:<host>:<metric>`, `:baseline:<host>:<metric>`, `:alerts`, `:cooldown:<host>:<type>`.
- **SQLite**: `Investigation` (type="performance"), `PlaybookApproval`, `PlaybookRun`, `FixVerification`.
- **WebSocket**: `performance` channel broadcasts anomaly events.
- **API**: JSON dashboards, per-host metrics, alert history, thresholds.
- **Disk**: Dynamic playbooks written to `data/playbooks/`.

## 6. Main files
| File | Role |
|------|------|
| `pipeline/performance_poller.py` | ES polling & `HostMetrics` aggregation |
| `pipeline/datausage/performance_orchestrator.py` | Cycle orchestration, anomaly → investigation bridge |
| `pipeline/response/dynamic_playbook.py` | Dynamic playbook generation from `PlaybookContext` |
| `pipeline/response/performance_playbook.py` | Static Jinja2 templates for known scenarios |
| `core/redis_performance.py` | Redis time-series, baselines, cooldowns, alerts |
| `api/routes/performance.py` | Dashboard, host detail, alert history, health endpoints |
| `response/auto_approve.py` | 4-layer auto-approval |
| `response/ansible_exec.py` | Playbook execution engine |
| `response/fix_verifier.py` | Post-remediation verification |

## 7. API endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/performance/dashboard` | All hosts with latest metrics, alert status, top processes |
| GET | `/performance/thresholds` | Current threshold configuration |
| GET | `/performance/status` | High-level subsystem status |
| GET | `/performance/health` | Liveness (ES, Redis, Telegraf, poller cache) |
| GET | `/performance/health/detailed` | Per-component health with latency |
| GET | `/performance/alerts` | Performance alert history (host/severity filters) |
| GET | `/performance/{host}` | Specific host metrics (Redis → poller cache fallback) |
| GET | `/performance/{host}/disk-analysis` | Disk usage breakdown *(Part B incomplete)* |
| GET | `/performance/{host}/history` | Metric time-series for charts *(Part B incomplete)* |
| GET | `/performance/{host}/root-cause` | Root-cause text + suggested playbook type *(Part B incomplete)* |

## 8. Database tables
- `Investigation` — `status`, `playbook_yaml`, `target_host`, `created_at`, `anomaly_type`
- `PlaybookApproval` — `investigation_id`, `decision`, `decided_by`, `decided_at`
- `PlaybookRun` — `investigation_id`, `status`, `output`, `started_at`, `completed_at`
- `FixVerification` — `investigation_id`, `status`, `details`, `verified_at`

## 9. Background jobs
- **Performance Poller**: `run_performance_monitoring_cycle()` invoked by `main.py` at `PERFORMANCE_POLL_INTERVAL` (default 60s).
- **Anomaly Detection**: Statistical baseline comparison + threshold breach detection.
- **Auto-Approval Evaluator**: Triggered after investigation creation; runs guardrails → static → dynamic → AI confidence layers.
- **Fix Verifier**: Triggered after `PlaybookRun` completion; re-queries ES for recurrence.

## 10. Frontend page
- **Route**: `/metrics` (expected under `frontend/app/(dashboard)/metrics/page.tsx`)
- **Features**: Host cards with CPU/mem/disk sparklines, severity badges, alert history table, per-host drill-down.
- **Status**: Frontend page was not returned in source exploration; may need verification against repository.

## 11. Example
1. Telegraf reports `cpu.usage_user=95%` on `web-01`.
2. Poller fetches metric; Redis baseline shows mean=30%, std=5%.
3. AnomalyDetector flags `cpu_critical` (z-score > threshold + above `PERFORMANCE_CPU_CRITICAL`).
4. Orchestrator determines top process is `nginx` → playbook type `cpu_high_nginx`.
5. Dynamic playbook generated: `ansible.builtin.service` restart nginx + `shell` pgrep check.
6. Investigation created (`status=awaiting_approval`).
7. Auto-approve: severity=critical, risk=65, no suspicious auth → AI confidence=0.82 → `approved`.
8. Ansible runs; fix verifier checks ES 5 min later — CPU down to 25% → `likely_fixed`.

## 12. Known limitations
- `api/routes/performance.py` Part B incomplete: `/{host}/disk-analysis`, `/{host}/history`, `/{host}/root-cause` endpoint bodies were cut off during delivery and may need re-export.
- `/metrics` frontend page not verified: No source file was returned for the metrics dashboard page; confirm existence in repository.
- No concrete DB examples: No seed/fixture data exists for performance investigations in the repository.
- `api/routes/monitoring.py`: Listed in scope but not delivered; may overlap with performance health endpoints.
