# OpenSOAR ARIA — Core Logic & Algorithms

> **Project**: Adaptive Response Intelligence Automation (ARIA)  
> **Author**: Ghazi Mabrouki  
> **Date**: April 2026  
> **Version**: 2.0 (Verified against Current Codebase)

---

## 1. Alert Ingestion & Deduplication

### 1.1 Three-Layer Dedup

```
Layer 1: In-Memory Cache (per-cycle)
  - Key: f"{source}:{es_id}"
  - Scope: Single forwarder cycle (~10s)
  - Prevents intra-batch duplicates from ES pagination

Layer 2: Redis Cache (cross-cycle)
  - Key: f"seen_alert:{source}:{es_id}"
  - TTL: 5 minutes
  - Prevents re-processing same ES doc across polling cycles

Layer 3: Database Check (persistent)
  - Query: SELECT id FROM alerts WHERE source = ? AND source_id = ?
  - Guarantees no duplicates in SQLite across restarts
```

### 1.2 Seen ID Persistence

Per-source JSON files (`data/seen_ids/{source}.json`) store processed ES document IDs:

```python
def _save_seen_ids(source: str):
    """Persist seen IDs to disk after EVERY batch."""
    path = SEEN_IDS_DIR / f"{source}.json"
    seen = _load_seen_ids(source)  # merge with existing
    seen.update(processed_this_batch)
    path.write_text(json.dumps(list(seen)))
```

**Critical fix (current behavior)**: Saves after every batch with `processed_ids`, not just when upstream forward succeeds. This prevents local SQLite inserts from causing re-processing on restart.

### 1.3 Pattern Tracking (Campaign Detection)

Repeated alerts from the same source IP + rule combination are grouped:

```python
def _get_pattern_key(source: str, source_ip: str, rule_name: str) -> str:
    return f"{source}:{source_ip}:{rule_name}"

# On repeated alert: update occurrence count instead of creating new upstream alert
_PATTERN_TRACKING[pattern_key] = {
    "alert_id": upstream_alert_id,
    "occurrence_count": existing_count + 1,
    "first_seen": iso_timestamp,
    "last_seen": iso_timestamp,
}
```

---

## 2. Incident Correlation Algorithm

### 2.1 Should Create Incident?

```python
def should_create_incident(alerts: List[Alert]) -> bool:
    if not alerts:
        return False

    severities = sorted([a.severity for a in alerts], 
                       key=severity_rank, reverse=True)
    highest = severities[0]

    # Critical: always create incident
    if highest == "critical":
        return True

    # High: needs 2+ high alerts from same correlation key within 15 min
    if highest == "high":
        high_count = sum(1 for s in severities if s == "high")
        return high_count >= 2

    # Medium: needs 2+ medium alerts from same key within 15 min
    if highest == "medium":
        med_count = sum(1 for s in severities if s == "medium")
        return med_count >= 2

    # Low: never creates incident
    return False
```

**Fix applied**: Removed `tracked_count >= 1` catch-all that incorrectly created incidents for single low-priority alerts.

### 2.2 Correlation Key Resolution

Hierarchical fallback for alerts without `source_ip` (common for Falco container alerts):

```python
def get_correlation_key(alert: Alert) -> str:
    if alert.source_ip:
        return f"ip:{alert.source_ip}"
    if alert.hostname:
        return f"host:{alert.hostname}"
    if alert.container_id:
        return f"container:{alert.container_id}"
    if alert.agent_name:
        return f"agent:{alert.agent_name}"
    return f"alert:{alert.id}"  # Fallback: no grouping
```

### 2.3 Attack Type Detection (13 Types)

```python
def detect_attack_type(alerts: List[Alert]) -> str:
    rule_names = " ".join(a.rule_name or "" for a in alerts).lower()

    # Direct signature matching
    if "brute" in rule_names or "login" in rule_names:
        failures = count_auth_failures(alerts)
        total = count_auth_attempts(alerts)
        if failures >= 5 or (total > 0 and failures / total >= 0.3):
            return "brute_force"

    mining_procs = ["xmrig", "minerd", "stratum", "cgminer"]
    if any(p in rule_names for p in mining_procs):
        return "cryptomining"

    if "escape" in rule_names or "chroot" in rule_names:
        return "container_escape"

    if "privilege" in rule_names or "setuid" in rule_names:
        return "privilege_escalation"

    if "malware" in rule_names:
        return "malware"

    web_patterns = ["sql injection", "xss", "lfi", "rfi", "directory traversal"]
    if any(p in rule_names for p in web_patterns):
        return "web_attack"

    if "scan" in rule_names or "port" in rule_names:
        return "network_scan"

    if "ransomware" in rule_names or "deletion" in rule_names:
        return "ransomware"

    if "exfil" in rule_names or "large" in rule_names:
        return "data_exfiltration"

    if "lateral" in rule_names or "smb" in rule_names:
        return "lateral_movement"

    if "credential" in rule_names or "mimikatz" in rule_names:
        return "credential_dump"

    if "c2" in rule_names or "beacon" in rule_names:
        return "command_and_control"

    return "unknown"
```

---

## 3. AI Investigation Engine

### 3.1 Prompt Structure

```
You are a senior security analyst investigating an incident.

INCIDENT: {title}
SEVERITY: {severity}
AFFECTED HOSTS: {hostnames}
SOURCE IPs: {source_ips}
ALERTS ({count}):
{alert_summaries}

Generate a structured investigation with these sections:

SECTION 1 — Executive Summary
[2-3 sentences]

SECTION 2 — Attack Chain Analysis
[Step-by-step narrative]

SECTION 3 — Threat Intelligence
[Known IOCs, CVEs, attribution]

SECTION 4 — Risk Assessment (0-10)
[Score with justification]

SECTION 5 — Remediation Playbook
[Ansible YAML]
```

### 3.2 Response Parsing

```python
def _parse_ai_response(raw: str) -> dict:
    """Extract 5 sections from LLM output."""
    sections = {
        "summary": _extract_between(raw, "SECTION 1", "SECTION 2"),
        "narrative": _extract_between(raw, "SECTION 2", "SECTION 3"),
        "threat_intel": _extract_between(raw, "SECTION 3", "SECTION 4"),
        "risk": _extract_between(raw, "SECTION 4", "SECTION 5"),
        "playbook_yaml": _extract_yaml_block(raw),
        "verification": _extract_between(raw, "Verification", None),
    }
    return sections
```

### 3.3 Playbook Validation

```python
def _validate_playbook(yaml_str: str) -> bool:
    if not yaml_str:
        return False
    try:
        parsed = yaml.safe_load(yaml_str)
        # Must be a list of plays
        return isinstance(parsed, list) and len(parsed) > 0
    except yaml.YAMLError:
        return False
```

### 3.4 Fallback Generation

On `asyncio.TimeoutError` or any LLM exception:

```python
fallback = _generate_fallback_ai_result(context)
await _update_investigation(
    investigation_id,
    status="awaiting_approval",
    ai_summary=fallback["summary"],
    ai_narrative=fallback["narrative"],
    ai_risk=fallback["risk"],
    playbook_yaml=fallback["playbook_yaml"],
    playbook_valid=True,
)
```

---

## 4. Auto-Approve Decision Logic

### 4.1 Four-Layer Flow

```
Investigation created (ai_complete)
    ↓
[Layer 1] Static Guardrails
    ├── Critical severity? → BLOCK
    ├── Risk score > 75? → BLOCK
    ├── Blocked attack type? → BLOCK
    └── Suspicious auth pattern? → BLOCK
    ↓ (if not blocked)
[Layer 2] Static Pass
    ├── Low severity + risk ≤ 25 + alerts ≤ 10? → AUTO-APPROVE
    ↓ (if not passed)
[Layer 3] Dynamic Learning
    ├── Confidence tracker has enough data? → Decision based on history
    ↓ (if no data)
[Layer 4] AI Confidence
    ├── Score ≥ 0.85? → AUTO-APPROVE
    ├── Score ≥ 0.50? → HIGH-PRIORITY QUEUE
    └── Score < 0.50? → HUMAN REVIEW
```

### 4.2 AI Confidence Scoring

```python
def score_for_auto_approve(investigation: Investigation) -> float:
    score = 0.0
    
    # 1. Playbook validity (+0.25)
    if investigation.playbook_valid:
        score += 0.25
    else:
        return 0.0  # Invalid = never auto-approve
    
    # 2. Playbook completeness (+0.25)
    phases = {
        "containment": any(k in playbook.lower() for k in ["block", "drop", "isolate"]),
        "hardening": any(k in playbook.lower() for k in ["harden", "secure", "patch"]),
        "forensics": any(k in playbook.lower() for k in ["evidence", "audit", "log"]),
        "verification": any(k in playbook.lower() for k in ["verify", "check", "validate"]),
    }
    score += (sum(phases.values()) / 4.0) * 0.25
    
    # 3. Risk level (+0.30) — lower risk = higher confidence
    risk_map = {"low": 0.30, "medium": 0.20, "high": 0.10, "critical": 0.0}
    score += risk_map.get(severity, 0.10)
    
    # Critical = blocked regardless
    if severity == "critical":
        return score  # Will be rejected by guardrails anyway
    
    # 4. Summary quality (+0.20)
    combined = f"{summary} {narrative}"
    is_fallback = any(marker in combined.lower() for marker in [
        "fallback analysis", "llm unavailable", "llm timeout"
    ])
    score += 0.05 if is_fallback else 0.20
    
    return round(score, 2)
```

---

## 5. Performance Anomaly Detection

### 5.1 Hybrid Detection

```python
class AnomalyDetector:
    async def detect_all(self, metrics: HostMetrics) -> List[Anomaly]:
        anomalies = []
        
        # 1. Threshold-based detection
        anomalies.extend(self._threshold_check(metrics))
        
        # 2. Statistical detection (24h baseline)
        if settings.performance_anomaly_use_statistical:
            anomalies.extend(await self._statistical_check(metrics))
        
        # 3. AI-assisted detection
        if settings.performance_anomaly_use_ai:
            anomalies.extend(await self._ai_check(metrics))
        
        return anomalies
```

### 5.2 Threshold Configuration

```python
THRESHOLDS = {
    "cpu":     {"warning": 70, "critical": 90},
    "memory":  {"warning": 75, "critical": 85},
    "disk":    {"warning": 80, "critical": 90},
    "inodes":  {"warning": 80, "critical": 90},
    "network": {"warning": 100_000_000, "critical": 500_000_000},  # bytes/s
}
```

### 5.3 Cooldown Enforcement

```python
async def should_create_alert(host: str, anomaly_type: str) -> bool:
    key = f"perf_alert_cooldown:{host}:{anomaly_type}"
    exists = await redis.exists(key)
    if exists:
        return False
    await redis.setex(key, 1800, "1")  # 30 minutes
    return True
```

---

## 6. Dynamic Playbook Generation

### 6.1 Task Selection Matrix

| Anomaly Type | Condition | Tasks |
|-------------|-----------|-------|
| `disk_full_root` | `/` > 90% | `apt autoremove`, vacuum journals, clean apt cache |
| `disk_full_var_log` | `/var/log` > 90% | Vacuum logs, rotate, compress |
| `cpu_high_nginx` | CPU > 90%, nginx top | Restart nginx, check workers, clear caches |
| `cpu_high_java` | CPU > 90%, java top | GC analysis, heap dump, restart service |
| `cpu_high_apache` | CPU > 90%, apache top | Restart httpd, check modules, clear caches |
| `memory_high_redis` | Mem > 85%, redis top | Restart redis, check maxmemory, eviction |
| `memory_high_java` | Mem > 85%, java top | Heap analysis, GC tuning, restart |

### 6.2 YAML Safe Quoting

```python
def _yaml_value(value: str) -> str:
    """
    Quote YAML strings containing special characters.
    Fixes: "Disk usage: 89.8%" causes YAML parsing error
           because colons signal key-value pairs.
    """
    if not isinstance(value, str):
        return str(value)
    unsafe = ': #[]{}|>*!\'"\n\r\t'
    if any(c in value for c in unsafe) or value.startswith(('-', ' ')):
        escaped = value.replace('"', '\\"')
        return f'"{escaped}"'
    return value
```

---

## 7. Ansible Execution Flow

### 7.1 Pre-Flight Sequence

```
1. YAML validation          → yaml.safe_load()
2. Ansible syntax check     → ansible-playbook --syntax-check
3. Host replacement         → "ghazi" → "target"
4. Jinja2 fixup             → "{ item }" → "{{ item }}"
5. Whitelist check          → is_whitelisted(target_host)?
6. SSH connection test      → sshpass ssh -o ConnectTimeout=10
    ├── auth_failed         → status = "pending" (retryable)
    ├── connection_refused  → status = "failed"
    ├── host_unreachable    → status = "failed"
    └── success             → proceed to execution
```

### 7.2 Exit Code Mapping

| Exit Code | Status | Failure Reason |
|-----------|--------|----------------|
| 0 | `completed` | Success |
| > 0 | `failed` | Analyzed from output |
| -15 | `failed` | timeout (SIGTERM) |
| -9 | `failed` | killed (SIGKILL) |

Output analysis:
- `"Permission denied"` → `permission_denied`
- `"Connection refused"` → `connection_refused`
- `"UNREACHABLE"` → `unreachable`
- `"FAILED"` → `task_failed` (with count)

---

## 8. Investigation State Machine

### 8.1 Valid Transitions

```python
_ALLOWED_TRANSITIONS = {
    "pending": {"running", "declined"},
    "running": {"awaiting_approval", "completed", "failed"},
    "awaiting_approval": {"approved", "declined"},
    "approved": {"running"},
    "completed": {"archived"},
    "failed": {"archived", "approved"},   # retry path
    "declined": {"archived"},
}
```

### 8.2 Frontend Action Visibility

```typescript
const canApprove = status === "awaiting_approval" || 
                   (status === "failed" && playbook_yaml);
const canDecline = status === "awaiting_approval" || status === "failed";
const canExecute = status === "approved" || status === "awaiting_approval";
const canEdit = status === "awaiting_approval" || status === "failed";
const canArchive = status in ["completed", "failed", "declined"];
```

---

## 9. Watcher Cycle Logic

### 9.1 Dual-Mode Scanning

```python
FULL_SCAN_INTERVAL = 60  # cycles

cycle_count += 1
is_full_scan = cycle_count % FULL_SCAN_INTERVAL == 0

if is_full_scan:
    # Full scan: paginate ALL open incidents (expensive, every 15 min)
    incidents = paginate_all_open_incidents(limit=100, max_offset=1000)
else:
    # Fast scan: only 50 most recent (cheap, every 15s)
    incidents = fetch_recent_open_incidents(limit=50)
```

### 9.2 Background Maintenance (Every Cycle)

```python
# 1. Retry pending investigations that never got AI processing
await _retry_pending_investigations()

# 2. Execute any approved investigations not yet run
await _execute_approved_investigations()

# 3. Alert on stuck investigations
await _check_stuck_investigations()

# 4. Auto-recover running investigations stuck > 30 min
await _recover_stuck_running_investigations()

# 5. Refresh existing investigations with new alerts (every 5 cycles)
if cycle_count % 5 == 0:
    await _refresh_existing_investigations(reader)
```

---

## 10. Upstream Resilience

### 10.1 Best-Effort Forwarding with Retry Queue

```python
async def forward_alert(alert: dict) -> bool:
    for attempt in range(3):
        try:
            result = await client.send_alert(alert)
            if result.get("alert_id"):
                return True
        except (ConnectError, TimeoutException) as e:
            if attempt < 2:
                await asyncio.sleep(0.5 * (2 ** attempt))
                continue
    
    # All retries failed — queue for later
    await retry_queue.add(alert, str(e), retry_count=0)
    return False

# Retry queue processor runs every 5 minutes
async def process_retry_queue():
    failed = await retry_queue.get_all()
    for alert in failed:
        success = await forward_alert(alert)
        if success:
            await retry_queue.remove(alert["id"])
```

### 10.2 Local Fallback Pattern

```python
@app.get("/api/v1/ips/map")
async def get_ips_map():
    try:
        upstream_data = await fetch_from_upstream()
        if upstream_data:
            return upstream_data
    except UpstreamError:
        pass
    # Fallback: query local alerts with GeoIP data
    return await get_local_ips_map()
```

---

## 10. Alert & Metrics Pipeline Documentation

Complete end-to-end lifecycle traces for every data source:

| Source | Document | Description |
|--------|----------|-------------|
| **Suricata** | [`suricata_pipeline.md`](./suricata_pipeline.md) | Network IDS alerts from Filebeat/Suricata ES index through mapping, dedup, incident creation, investigation, and IPS map display |
| **Falco** | [`falco_pipeline.md`](./falco_pipeline.md) | Container runtime security alerts from Falco ES index through container-aware mapping, noise filtering, correlation by hostname/container_id, and IPS map visibility rules |
| **Wazuh** | [`wazuh_pipeline.md`](./wazuh_pipeline.md) | Host IDS alerts from Wazuh ES index through level-based severity mapping, Suricata cross-correlation, and the current upstream outage (stopped Apr 16) |
| **Telegraf** | [`telegraf_pipeline.md`](./telegraf_pipeline.md) | Performance metrics from Telegraf agent through ES polling, Redis storage, anomaly detection, dynamic playbook generation, and dashboard display |

Each document includes:
- Multi-phase flow diagrams
- Decision gate details — what gets filtered at each step
- Field transformation tables: Raw ES → Mapper → SQLite
- Source-specific incident creation decision trees
- Complete code reference index (file, function, line number)

---

*End of Core Logic Document*
