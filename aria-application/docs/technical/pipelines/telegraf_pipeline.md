# Telegraf Metrics Lifecycle — Complete Pipeline Trace

> **Document**: End-to-end trace of performance metrics from Telegraf collection to dashboard display  
> **Source**: Telegraf Agent → Elasticsearch → Redis → Dashboard  
> **Last Updated**: April 20, 2026

---

## High-Level Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 0: TELEGRAF AGENT                                     │
│  Config: config/telegraf_procstat.conf                                                  │
│  ├─ CPU: usage_idle, usage_user, usage_system, usage_iowait                             │
│  ├─ Memory: used_percent, used, available                                               │
│  ├─ Disk: used_percent, used, free, inodes_used_percent per device                      │
│  ├─ Network: bytes_recv, bytes_sent                                                     │
│  ├─ System: load1, load5, load15, n_cpus                                                │
│  ├─ Processes: running, sleeping, total, total_threads                                  │
│  ├─ Netstat: tcp_established, tcp_listen, udp_socket                                    │
│  ├─ Procstat: per-process CPU, memory, threads (monitors: nginx, apache, postgres,     │
│  │   mysql, redis, java, python, node, docker)                                          │
│  └─ Disk Dirs: du -sh /* output (if exec plugin configured)                             │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │ (writes to ES)
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 1: ELASTICSEARCH                                      │
│  Index: telegraf-*                                                                       │
│  Documents: one per measurement per host per interval                                   │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 2: PERFORMANCE POLLER                                 │
│  File: pipeline/performance_poller.py :: PerformancePoller.poll_once()                  │
│  Started by: main.py as background task (run_performance_poller)                        │
│                                                                                          │
│  STEP 1: Discover hosts                                                                 │
│    └─ _get_hosts_from_telegraf()                                                        │
│       → ES terms aggregation on tag.host over telegraf-*, now-1h                        │
│       → Filters by settings.performance_hosts_list if configured                        │
│                                                                                          │
│  STEP 2: Fetch metrics per host (8 parallel ES queries)                                 │
│    └─ _get_latest_metrics_for_host(host, since)                                         │
│       ├─ cpu → size=1, sort @timestamp desc → calculate usage = 100 - usage_idle        │
│       ├─ mem → size=1 → used_percent, used, available                                   │
│       ├─ disk → size=10 → deduplicate by (device, path)                                 │
│       ├─ net → size=1 → bytes_recv, bytes_sent                                          │
│       ├─ processes → aggregate counts (running, sleeping, total, total_threads)         │
│       ├─ system → load1, load5, load15, n_cpus                                          │
│       ├─ netstat → tcp_established, tcp_listen, udp_socket                              │
│       ├─ procstat → size=3000 → filter kernel threads, dedup by PID,                   │
│       │             sort by CPU desc, keep top 15                                       │
│       └─ disk_dir → directory sizes from du -sh /* (if configured)                      │
│                                                                                          │
│  STEP 3: Freshness check                                                                │
│    ├─ FRESH: < 300 seconds old → accept                                                │
│    ├─ STALE: 300-600 seconds → warn but accept                                          │
│    └─ TOO OLD: > 600 seconds → drop host entirely                                       │
│                                                                                          │
│  Output: Dict[str, HostMetrics] → stored in self._host_metrics_cache                    │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 3: REDIS STORAGE                                      │
│  File: core/redis_performance.py :: PerformanceRedis                                    │
│                                                                                          │
│  CURRENT METRICS:                                                                        │
│    Key: opensoar:performance:metrics:{host}                                             │
│    Value: JSON blob of all metrics per host                                             │
│    TTL: 300 seconds                                                                      │
│                                                                                          │
│  HISTORY (time series):                                                                  │
│    Key: opensoar:performance:history:{host}:{metric}                                    │
│    Value: Redis list of {timestamp, value} objects                                      │
│    Max length: 1000 points                                                               │
│    TTL: 2 days                                                                           │
│    Metrics tracked: cpu, memory, disk (max used%), network (bytes_recv), load (load_1)  │
│                                                                                          │
│  BASELINE (statistics):                                                                  │
│    Key: opensoar:performance:baseline:{host}:{metric}                                   │
│    Value: {mean, std, p95, p99, count, updated_at}                                      │
│    Computed from: last 2880 history points (24h @ 30s intervals)                        │
│    TTL: 2 days                                                                           │
│                                                                                          │
│  COOLDOWN (alert suppression):                                                           │
│    Key: opensoar:performance:cooldown:{host}:{alert_type}                               │
│    TTL: performance_alert_cooldown_minutes * 60 (default 30 min = 1800s)                │
│                                                                                          │
│  ALERT HISTORY:                                                                          │
│    Key: opensoar:performance:alerts:{alert_id}                                          │
│    + Sorted sets: opensoar:performance:alerts:host:{host}                               │
│                     opensoar:performance:alerts:global                                  │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 4: PERFORMANCE ORCHESTRATOR                           │
│  File: pipeline/datausage/performance_orchestrator.py                                   │
│  Entry: run_performance_monitoring_cycle()                                              │
│  Loop: start_performance_monitoring() sleeps 30s between cycles                         │
│                                                                                          │
│  STEP 1: Poll metrics                                                                   │
│    └─ PerformancePoller().poll_once() → metrics_dict                                    │
│                                                                                          │
│  STEP 2: Store in Redis                                                                 │
│    ├─ store_current_metrics(host, metrics)                                              │
│    ├─ append_to_history(host, "cpu", cpu_value)                                         │
│    ├─ append_to_history(host, "memory", mem_value)                                      │
│    ├─ append_to_history(host, "disk", max_disk_used_percent)                            │
│    ├─ append_to_history(host, "network", bytes_recv)                                    │
│    └─ append_to_history(host, "load", load_1)                                           │
│                                                                                          │
│  STEP 3: Anomaly Detection                                                              │
│    └─ AnomalyDetector().detect_all(metrics)                                             │
│       ├─ detect_cpu_anomaly()                                                           │
│       │   ├─ Threshold: warning > 80%, critical > 95%                                   │
│       │   └─ Statistical: deviation > 3σ from baseline (if enabled)                     │
│       ├─ detect_memory_anomaly()                                                        │
│       │   ├─ Threshold: warning > 80%, critical > 90%                                   │
│       │   └─ Statistical: same pattern                                                  │
│       ├─ detect_disk_anomaly()                                                          │
│       │   ├─ Threshold: warning > 80%, critical > 90%                                   │
│       │   ├─ Inode threshold: warning > 80%, critical > 90%                             │
│       │   └─ Iterates ALL disk devices, picks worst                                     │
│       ├─ detect_load_anomaly()                                                          │
│       │   ├─ Normalized load: load_1 / n_cpus                                           │
│       │   ├─ Warning > 2.5, Critical > 4.0                                              │
│       │   └─ Statistical check                                                          │
│       └─ detect_network_anomaly()                                                       │
│           ├─ Rate computed from previous history point                                  │
│           ├─ Warning: > performance_network_in_warning                                  │
│           └─ Critical: > performance_network_in_critical                                │
│                                                                                          │
│  STEP 4: Cooldown Check                                                                 │
│    └─ detector.should_create_alert(host, anomaly_type)                                  │
│       → Checks Redis cooldown key                                                       │
│       → Returns False if in cooldown (prevents alert spam)                              │
│                                                                                          │
│  STEP 5: Root Cause Analysis                                                            │
│    └─ analyze_performance_root_cause(metrics, anomaly_type, current_value)              │
│       → LLM-based or heuristic analysis                                                 │
│       → Returns: remediation_type, affected_process, evidence[], explanation,           │
│                  confidence                                                              │
│                                                                                          │
│  STEP 6: Alert Generation                                                               │
│    └─ performance_alert_generator.generate_alert(...)                                   │
│       ├─ Severity: normal→low, warning→medium, critical→high                            │
│       ├─ Auto-remediable check: anomaly_type in allowlist?                              │
│       │   Allowlist: cpu_high_nginx, cpu_high_java, cpu_high_apache,                    │
│       │   memory_high_java, memory_high_redis, disk_full_root,                          │
│       │   disk_full_var_log, disk_full_docker                                           │
│       ├─ Title: "Performance Alert - {anomaly_type} on {host}"                          │
│       │   (Disk: includes path, fstype, used%, free GB)                                 │
│       ├─ Metrics snapshot: CPU, memory, disk, network, load, processes, connections     │
│       └─ Evidence, root_cause, affected_process, recommended_action                     │
│                                                                                          │
│  STEP 7: WebSocket Broadcast                                                            │
│    └─ broadcast_performance_alert(alert) → channel "performance"                        │
│                                                                                          │
│  STEP 8: Upstream Forward (best effort)                                                 │
│    └─ _send_alert_to_opensoar(alert)                                                    │
│       → client.create_alert("performance", alert)                                       │
│       → On success: alert["id"] = upstream_alert_id                                     │
│       → On failure: continues anyway (local-first architecture)                         │
│                                                                                          │
│  STEP 9: Investigation Creation (if auto_remediable)                                    │
│    └─ _create_performance_investigation(alert, host, metrics, anomaly)                  │
│       ├─ Generate dynamic playbook via generate_dynamic_playbook()                      │
│       ├─ Build markdown description with metrics snapshot                               │
│       ├─ Create Investigation: status="awaiting_approval", source="performance"        │
│       ├─ Store playbook_yaml, playbook_valid=True                                       │
│       ├─ target_host = host                                                             │
│       └─ Link alert to investigation via InvestigationAlert                             │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 5: DYNAMIC PLAYBOOK GENERATION                        │
│  File: pipeline/response/dynamic_playbook.py                                            │
│  Entry: generate_dynamic_playbook(context, root_cause_result)                           │
│                                                                                          │
│  PlaybookContext fields:                                                                │
│    host, anomaly_type, current_value, threshold, remediation_type,                      │
│    affected_process, evidence[], top_processes[], disk_device, disk_path                │
│                                                                                          │
│  Remediation type → task generator mapping:                                             │
│    ├─ "restart_service" → _generate_process_tasks()                                     │
│    │   ├─ nginx → systemctl reload nginx                                                │
│    │   ├─ redis → redis-cli FLUSHDB / BGSAVE / restart                                  │
│    │   ├─ java → jcmd GC.run / restart                                                  │
│    │   ├─ mysql → SHOW PROCESSLIST / FLUSH / OPTIMIZE                                   │
│    │   └─ generic → ps + systemctl restart                                              │
│    ├─ "clear_memory" → _generate_memory_tasks()                                         │
│    │   ├─ echo 3 > /proc/sys/vm/drop_caches                                             │
│    │   ├─ sync; echo 3 > /proc/sys/vm/drop_caches                                       │
│    │   └─ redis-cli FLUSHDB (if redis detected)                                         │
│    ├─ "clean_logs" / "clean_temp" / "resize_disk" → _generate_disk_tasks()             │
│    │   ├─ Log cleanup: truncate -s 0 /var/log/*.log                                     │
│    │   ├─ Temp cleanup: rm -rf /tmp/*                                                   │
│    │   ├─ Docker prune: docker system prune -f                                          │
│    │   ├─ APT cleanup: apt-get clean                                                    │
│    │   └─ Journal cleanup: journalctl --vacuum-time=1d                                  │
│    ├─ "scale" → _generate_cpu_tasks()                                                   │
│    │   ├─ ps -eo pid,pcpu,comm --sort=-pcpu                                             │
│    │   ├─ Process tree analysis                                                         │
│    │   └─ Scaling recommendations                                                       │
│    └─ "investigate" → Generic info-gathering tasks                                      │
│       ├─ uptime, free -h, df -h, iostat, vmstat                                        │
│       └─ netstat/ss connections                                                         │
│                                                                                          │
│  YAML serialization: _build_playbook_yaml()                                             │
│    ├─ Handles YAML special chars (:, #, [, ], {, }, ", ') via _yaml_value()             │
│    ├─ Requires become: yes                                                              │
│    └─ Returns raw Ansible YAML string                                                   │
└─────────────────────────────────────────────┬───────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              PHASE 6: PERFORMANCE DASHBOARD                              │
│  Backend: api/routes/performance.py                                                     │
│  Frontend: frontend/app/(dashboard)/metrics/page.tsx                                    │
│                                                                                          │
│  API ENDPOINTS:                                                                          │
│    GET /dashboard         → All hosts, latest metrics, alert status                     │
│    GET /hosts             → List of monitored hostnames                                 │
│    GET /thresholds        → Current warning/critical thresholds                         │
│    GET /{host}            → Single host metrics + top processes                         │
│    GET /{host}/disk-analysis → Exact disk consumers (du -sh or Ansible fallback)        │
│    GET /{host}/history    → Historical data points from Redis                           │
│    GET /{host}/root-cause → On-the-fly threshold-based issue detection                  │
│    GET /{host}/alerts     → Host-specific performance alerts                            │
│    GET /{host}/investigations → Investigations for host from SQLite                     │
│                                                                                          │
│  DATA FLOW FOR DASHBOARD:                                                               │
│    1. Try Redis: performance_redis.get_all_current_metrics()                            │
│    2. Fallback: performance_poller.get_cached_metrics() (in-memory)                     │
│    3. Alert status: compare metrics against thresholds on-the-fly                       │
│                                                                                          │
│  FRONTEND UI:                                                                           │
│    ├─ Host selector with status dots (normal/warning/critical)                          │
│    ├─ Overview cards: CPU %, Memory %, Disk %, Load Average                             │
│    ├─ Recharts AreaCharts: CPU, Memory, Network history (last 24h)                      │
│    ├─ Tabs: Overview / Network / Disk / Processes                                       │
│    ├─ Disk tab: per-device progress bars, exact consumers, heuristics                   │
│    ├─ Process tab: top CPU and top memory tables                                        │
│    └─ WebSocket: auto-refreshes on performance_alert events                             │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Anomaly Detection Detail

```
HostMetrics arrives from poller
    │
    ▼
┌────────────────────────────────────┐
│ detect_cpu_anomaly()              │
│   ├─ Threshold check:             │
│   │   warning  > 80%              │
│   │   critical > 95%              │
│   └─ Statistical check (optional):│
│       deviation = |value - mean| / std
│       > 5σ → critical             │
│       > 3σ → warning              │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│ detect_memory_anomaly()           │
│   ├─ Threshold: warning > 80%     │
│   │             critical > 90%    │
│   └─ Statistical: same pattern    │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│ detect_disk_anomaly()             │
│   ├─ Iterate ALL disk_devices     │
│   ├─ For each device:             │
│   │   used_percent > threshold?   │
│   │   inodes_used_percent > threshold?
│   └─ Pick WORST device            │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│ detect_load_anomaly()             │
│   ├─ normalized = load_1 / n_cpus │
│   ├─ warning  > 2.5               │
│   └─ critical > 4.0               │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│ detect_network_anomaly()          │
│   ├─ Rate = (current - previous) / time_delta
│   ├─ Compare against thresholds   │
│   └─ Historical baseline check    │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│ should_create_alert()?            │
│   ├─ Check Redis cooldown key     │
│   │   TTL = 30 minutes            │
│   └─ Returns True/False           │
└────────────────────────────────────┘
```

---

## Performance Alert → Investigation Flow

```
Anomaly detected (e.g., disk at 89.8%)
    │
    ▼
┌────────────────────────────────────┐
│ generate_alert()                  │
│   ├─ Severity: warning → medium   │
│   ├─ auto_remediable?             │
│   │   disk_full in allowlist?     │──YES──▶ auto_remediable=True
│   └─ Title: "Performance Alert - │
│       Disk / (ext4) at 89.8%      │
│       (5.2GB free)"               │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│ _send_alert_to_opensoar()         │
│   ├─ Try upstream (best effort)   │
│   └─ Continue regardless          │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│ _create_performance_investigation()│
│   ├─ generate_dynamic_playbook()  │
│   │   → disk_full → clean_logs    │
│   │   tasks (truncate, apt clean, │
│   │   journalctl vacuum)          │
│   ├─ Build description markdown   │
│   ├─ Create Investigation:        │
│   │   status="awaiting_approval"  │
│   │   source="performance"        │
│   │   playbook_yaml=generated     │
│   │   target_host=host            │
│   └─ Create InvestigationAlert    │
│       link                        │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│ Dashboard shows:                  │
│   "Critical Alert: Host ghazi has │
│    elevated resource usage"       │
│   Disk: 91.1%                     │
│   Investigation awaiting approval │
└────────────────────────────────────┘
    │
    ▼
┌────────────────────────────────────┐
│ Analyst clicks "Approve"          │
│   → execute_playbook()            │
│   → ansible-playbook -i inventory │
│     playbook.yml                  │
│   → FixVerifier re-queries ES     │
│   → If fixed → Archive            │
└────────────────────────────────────┘
```

---

## Threshold Configuration

| Metric | Warning | Critical | Config Key |
|--------|---------|----------|------------|
| CPU | 80% | 95% | `performance_cpu_warning` / `performance_cpu_critical` |
| Memory | 80% | 90% | `performance_memory_warning` / `performance_memory_critical` |
| Disk | 80% | 90% | `performance_disk_warning` / `performance_disk_critical` |
| Disk Inodes | 80% | 90% | `performance_disk_inode_warning` / `performance_disk_inode_critical` |
| Network In | configurable | configurable | `performance_network_in_warning` / `performance_network_in_critical` |
| Load (normalized) | 2.5 | 4.0 | Hardcoded |

---

## Code Reference Index

| Phase | File | Key Function | Line ~ |
|-------|------|--------------|--------|
| Config | `config/telegraf_procstat.conf` | procstat plugin | — |
| Poll | `pipeline/performance_poller.py` | `PerformancePoller.poll_once()` | 554 |
| Hosts | `pipeline/performance_poller.py` | `_get_hosts_from_telegraf()` | 151 |
| Metrics | `pipeline/performance_poller.py` | `_get_latest_metrics_for_host()` | 189 |
| HostMetrics | `pipeline/performance_poller.py` | `HostMetrics` dataclass | 32 |
| Redis Store | `core/redis_performance.py` | `store_current_metrics()` | 66 |
| Redis History | `core/redis_performance.py` | `append_to_history()` | 119 |
| Redis Baseline | `core/redis_performance.py` | `update_baseline()` | 170 |
| Redis Cooldown | `core/redis_performance.py` | `should_create_alert()` | 372 |
| Orchestrator | `pipeline/datausage/performance_orchestrator.py` | `run_performance_monitoring_cycle()` | 39 |
| Orchestrator | `pipeline/datausage/performance_orchestrator.py` | `start_performance_monitoring()` | 477 |
| Anomaly | `pipeline/enrichment/anomaly_detector.py` | `AnomalyDetector.detect_all()` | 331 |
| Anomaly | `pipeline/enrichment/anomaly_detector.py` | `detect_cpu_anomaly()` | varies |
| Root Cause | `pipeline/enrichment/anomaly_detector.py` | `analyze_performance_root_cause()` | varies |
| Alert Gen | `pipeline/alerts/performance_alert.py` | `generate_alert()` | 116 |
| Alert Gen | `pipeline/alerts/performance_alert.py` | `_determine_auto_remediable()` | 71 |
| Playbook | `pipeline/response/dynamic_playbook.py` | `generate_dynamic_playbook()` | 480 |
| Playbook | `pipeline/response/dynamic_playbook.py` | `_generate_disk_tasks()` | varies |
| Invest | `pipeline/datausage/performance_orchestrator.py` | `_create_performance_investigation()` | 280 |
| Dashboard API | `api/routes/performance.py` | `get_dashboard_metrics()` | 22 |
| Dashboard API | `api/routes/performance.py` | `get_host_disk_analysis()` | 1031 |
| Frontend | `frontend/app/(dashboard)/metrics/page.tsx` | MetricsPage | 1 |
| Assistant | `response/assistant.py` | `_search_performance_metrics()` | 523 |
| Assistant | `response/assistant.py` | `_get_disk_consumers()` | varies |
