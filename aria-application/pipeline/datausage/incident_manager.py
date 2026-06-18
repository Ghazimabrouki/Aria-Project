"""
Smart Incident Manager — Multi-signal correlation & auto incident creation.

Uses enriched alert data (MITRE ATT&CK, GeoIP, cloud provider, campaigns)
to intelligently create and manage incidents in OpenSOAR.

Logic:
  1. Track EVERY alert with a source_ip (build correlation state)
  2. Create incidents when patterns emerge — not just for "critical" alerts
  3. Group related alerts by IP + tactic + time window
  4. Escalate severity based on kill chain progression and multi-source detection
  5. Background cycle catches missed patterns via OpenSOAR suggestions
  6. Auto-escalate when new high-severity alerts arrive on existing incidents

Real-world scenarios handled:
  - SSH brute force attacks (multiple failed logins from same IP)
  - Port scans (Suricata ET SCAN rules)
  - Malware/C2 traffic (compromised hosts, suspicious URLs)
  - Cloud provider attacks (AWS, Azure, DigitalOcean, OVH, Hetzner)
  - Kill chain attacks (multi-stage from recon to exfiltration)
  - Spamhaus DROP-listed IPs (known malicious)
"""

import json
import time
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
import structlog

from pipeline.sender import client
from pipeline.services.correlator import track_alert, _campaign_tracker

logger = structlog.get_logger()

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _calculate_group_severity(alerts: list) -> str:
    """Calculate severity for a group of alerts from suggestions."""
    if not alerts:
        return "medium"

    sev_values = [a.get("severity", "low") for a in alerts if a.get("severity")]
    if not sev_values:
        return "medium"

    max_sev = max(sev_values, key=lambda s: SEVERITY_ORDER.get(s, 0))
    return max_sev


# Lockheed Martin Cyber Kill Chain phases (standard SOC terminology)
# Maps MITRE ATT&CK tactics to kill chain phases for progression detection
KILL_CHAIN_PHASES = [
    {"name": "Reconnaissance", "tactics": ["Reconnaissance", "Resource Development"]},
    {"name": "Weaponization", "tactics": []},  # Typically pre-attack intelligence
    {
        "name": "Delivery",
        "tactics": ["Initial Access"],
    },
    {
        "name": "Exploitation",
        "tactics": ["Execution"],
    },
    {
        "name": "Installation",
        "tactics": [
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
        ],
    },
    {
        "name": "Command and Control",
        "tactics": ["Command and Control"],
    },
    {
        "name": "Actions on Objectives",
        "tactics": ["Collection", "Exfiltration", "Impact"],
    },
]

HIGH_RISK_TACTICS = {
    "Initial Access",
    "Execution",
    "Exfiltration",
    "Impact",
    "Credential Access",
    "Lateral Movement",
    "Command and Control",
}

NOISE_RULES = {
    "GPL ICMP",
    "PING",
    "ICMP PING",
    "ECHO_REQUEST",
    "Keepalive",
    "heartbeat",
    "ntp",
}

ATTACK_PATTERNS = {
    # More precise patterns - require specific evidence
    "ssh_brute_force": [
        "authentication failed",
        "login failed",
        "failed password",
        "invalid user",
        "max authentication attempts",
        "pam_unix",
        "sshd: authentication failure",
        "brute force",
        "bruteforce",
        "ssh brute",
        "password guessing",
    ],
    "port_scan": [
        "horizontal portscan",
        "vertical portscan",
        "nmap detection",
        "zmap detected",
        "masscan detected",
        "port scan detected",
        "nmap",
        "et scan",
        "scan",
        "reconnaissance",
        "sweep",
    ],
    "malware": [
        "malware detected",
        "trojan detected",
        "ransomware detected",
        "infected file",
        "malicious executable",
        "virus detected",
        "malware",
        "trojan",
        "backdoor",
    ],
    "c2": [
        "command and control",
        "c2 communication",
        "botnet",
        "beacon callback",
        "c&c communication",
        "c2",
        "callback",
    ],
    "web_attack": [
        "sql injection attempt",
        "xss attempt",
        "csrf attempt",
        "lfi attempt",
        "rfi attempt",
        "directory traversal attempt",
        "web shell detected",
        "webshell upload",
        "sql injection",
        "xss",
        "lfi",
        "rfi",
        "directory traversal",
        "command injection",
        "remote code execution",
        "rce",
    ],
    "ddos": [
        "ddos attack",
        "denial of service",
        "flood attack",
        "amplification attack",
        "syn flood",
    ],
    "spamhaus": ["spamhaus drop", "drop list", "blocklisted ip", "listed traffic"],
    "lateral_movement": [
        "lateral movement detected",
        "pass the hash",
        "psexec execution",
        "winrm lateral",
    ],
    "privilege_escalation": [
        "privilege escalation detected",
        "root escalation",
        "sudo abuse",
        "capability abuse",
    ],
    "data_exfiltration": [
        "data exfiltration",
        "data theft",
        "large data upload",
        "data transfer detected",
        "dns tunneling",
    ],
}

INCIDENT_LINKS_FILE = Path("data/artifacts/incident_links.json")
INCIDENT_CACHE_FILE = Path("data/artifacts/incident_cache.json")

_incident_cache: Dict[str, Dict[str, Any]] = {}
_processed_alerts: Set[str] = set()
_local_incidents: Dict[str, Dict[str, Any]] = {}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _load_links() -> Set[str]:
    global _processed_alerts
    if not _processed_alerts and INCIDENT_LINKS_FILE.exists():
        try:
            data = json.loads(INCIDENT_LINKS_FILE.read_text())
            _processed_alerts = set(data) if isinstance(data, list) else set()
        except Exception:
            _processed_alerts = set()
    return _processed_alerts


def _save_links() -> None:
    try:
        INCIDENT_LINKS_FILE.parent.mkdir(parents=True, exist_ok=True)
        INCIDENT_LINKS_FILE.write_text(json.dumps(list(_processed_alerts)))
    except Exception:
        pass


def _load_incident_cache() -> Dict[str, Dict[str, Any]]:
    global _incident_cache, _local_incidents
    if not _incident_cache and INCIDENT_CACHE_FILE.exists():
        try:
            data = json.loads(INCIDENT_CACHE_FILE.read_text())
            _incident_cache = data.get("correlation_cache", {})
            _local_incidents = data.get("local_incidents", {})
        except Exception:
            pass
    return _incident_cache


def _save_incident_cache() -> None:
    try:
        INCIDENT_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        INCIDENT_CACHE_FILE.write_text(
            json.dumps(
                {
                    "correlation_cache": _incident_cache,
                    "local_incidents": _local_incidents,
                    "updated_at": _now_utc().isoformat(),
                }
            )
        )
    except Exception:
        pass


def _extract_mitre_tactics(alert_payload: dict) -> List[str]:
    tactics = []
    for tag in alert_payload.get("tags") or []:
        if tag.startswith("mitre-tactic-"):
            tactic = tag.replace("mitre-tactic-", "")
            if tactic not in tactics:
                tactics.append(tactic)
    if not tactics:
        desc = (
            (alert_payload.get("description") or "")
            + " "
            + (alert_payload.get("title") or "")
        )
        for phase in KILL_CHAIN_PHASES:
            for tactic in phase["tactics"]:
                if tactic.lower() in desc.lower() and tactic not in tactics:
                    tactics.append(tactic)
    return tactics


def _extract_attack_pattern(alert_payload: dict) -> Optional[str]:
    """Extract attack pattern type from alert content using word-boundary matching."""
    import re
    title = (alert_payload.get("title") or "").lower()
    desc = (alert_payload.get("description") or "").lower()
    category = (alert_payload.get("category") or "").lower()
    combined = title + " " + desc + " " + category

    for pattern_name, keywords in ATTACK_PATTERNS.items():
        for kw in keywords:
            # Multi-word phrases (contains space) are specific enough for substring match
            if " " in kw:
                if kw in combined:
                    return pattern_name
            else:
                # Single words use word-boundary regex to avoid false positives
                # e.g., "scan" should not match "scandal", "background", "subscription"
                if re.search(r'\b' + re.escape(kw) + r'\b', combined):
                    return pattern_name

    # Category-based fallback for common Suricata ET categories
    category_fallbacks = {
        "web application attack": "web_attack",
        "attempted administrator privilege gain": "privilege_escalation",
        "attempted user privilege gain": "privilege_escalation",
        "executable code was detected": None,  # Too generic — can be legit software
        "trojan activity": "c2",
        # "misc attack" is Suricata's catch-all for threat intel hits (CINS, Spamhaus, etc.)
        # It is NOT a web attack. Map to None so the actual rule name is used in the title.
        "misc attack": None,
        "attempted information leak": "info_disclosure",
        "network trojan detected": "c2",
        "unsuccessful user privilege gain": "privilege_escalation",
        "successful administrator privilege gain": "privilege_escalation",
    }
    for cat_pattern, pattern_name in category_fallbacks.items():
        if cat_pattern in category:
            return pattern_name

    return None


def _extract_cloud_provider(alert_payload: dict) -> Optional[str]:
    for tag in alert_payload.get("tags") or []:
        if tag.startswith("src-provider-"):
            return tag.replace("src-provider-", "")
        if tag.startswith("dst-provider-"):
            return tag.replace("dst-provider-", "")

    desc = alert_payload.get("description") or ""
    providers = [
        "AWS",
        "Azure",
        "Google Cloud",
        "DigitalOcean",
        "OVH",
        "Hetzner",
        "Cloudflare",
        "Linode",
        "Vultr",
        "Alibaba",
    ]
    for provider in providers:
        if provider.lower() in desc.lower():
            return provider

    org = alert_payload.get("geo_org", "")
    if org:
        org_lower = org.lower()
        if "amazon" in org_lower or "aws" in org_lower:
            return "AWS"
        if "microsoft" in org_lower or "azure" in org_lower:
            return "Azure"
        if "google" in org_lower:
            return "Google Cloud"
        if "digitalocean" in org_lower:
            return "DigitalOcean"
        if "ovh" in org_lower:
            return "OVH"
        if "hetzner" in org_lower:
            return "Hetzner"
    return None


def _extract_campaign_type(alert_payload: dict) -> Optional[str]:
    desc = alert_payload.get("description") or ""
    if "Campaign:" in desc:
        match = re.search(r"Campaign:\s*([A-Za-z][A-Za-z\s]+?)\s+from\s+\d", desc)
        if match:
            return match.group(1).strip()
        match = re.search(r"Campaign:\s*([^|(]+)", desc)
        if match:
            return match.group(1).strip()
    return None


def _extract_country(alert_payload: dict) -> Optional[str]:
    for tag in alert_payload.get("tags") or []:
        if tag.startswith("src-country-"):
            return tag.replace("src-country-", "")
    return None


def _extract_dest_ip(alert_payload: dict) -> Optional[str]:
    dest_ip = alert_payload.get("dest_ip") or ""
    if dest_ip and not dest_ip.startswith(("10.", "192.168.", "172.16.")):
        return dest_ip
    if dest_ip:
        return dest_ip
    return None


def _get_mitre_phase(tactic: str) -> Optional[str]:
    for phase in KILL_CHAIN_PHASES:
        if tactic in phase["tactics"]:
            return phase["name"]
    return None


def _normalize_attack_type(pattern: str) -> str:
    """Convert attack pattern to human-readable name."""
    mapping = {
        "ssh_brute_force": "SSH Brute Force Attack",
        "port_scan": "Port Scan Activity",
        "malware": "Malware Detection",
        "c2": "Command & Control Traffic",
        "web_attack": "Web Application Attack",
        "ddos": "DDoS Attack",
        "spamhaus": "Malicious IP Traffic",
        "lateral_movement": "Lateral Movement Attempt",
        "privilege_escalation": "Privilege Escalation",
        "data_exfiltration": "Data Exfiltration",
    }
    return mapping.get(pattern, pattern.replace("_", " ").title())


def detect_kill_chain_progression(tactics: List[str]) -> Dict[str, Any]:
    if not tactics:
        return {"detected": False, "phases": [], "phase_count": 0}

    phases_hit = set()
    for tactic in tactics:
        phase = _get_mitre_phase(tactic)
        if phase:
            phases_hit.add(phase)

    return {
        "detected": len(phases_hit) >= 2,
        "phases": sorted(phases_hit),
        "phase_count": len(phases_hit),
    }


def _get_correlation_key(alert_payload: dict) -> str:
    """
    Extract the best correlation identifier from an alert.
    
    Hierarchy (most specific to least):
    1. source_ip + attack_pattern
    2. ja3_hash (C2 fingerprint across IPs)
    3. domain (shared C2 domain across hosts)
    4. file_hash (malware hash across hosts)
    5. username (compromised account across hosts)
    6. process_path (suspicious process across hosts)
    7. source_ip alone
    8. hostname
    9. container_id / container_name
    10. agent_name
    11. alert_id (last resort)
    """
    source_ip = alert_payload.get("source_ip") or ""
    attack_pattern = _extract_attack_pattern(alert_payload) or ""
    if source_ip and attack_pattern:
        return f"{source_ip}/{attack_pattern}"
    
    # Non-IP correlation: JA3 hash (TLS fingerprint for C2 detection)
    metadata = alert_payload.get("metadata", {}) or {}
    iocs = alert_payload.get("iocs", {}) or {}
    observables = alert_payload.get("observables", []) or []
    
    ja3 = metadata.get("tls_ja3") or (iocs.get("ja3", [None] or [None]))[0]
    if ja3:
        return f"ja3:{ja3}"
    
    # Non-IP correlation: domain (C2 domain, DNS query, TLS SNI)
    domains = iocs.get("domain", [])
    if domains:
        # Use first domain but sanitize for key storage
        domain = str(domains[0]).lower().strip()
        if domain and "." in domain:
            return f"domain:{domain}"
    
    # Non-IP correlation: file hash (malware propagation)
    hashes = iocs.get("hash", [])
    if hashes:
        h = str(hashes[0]).lower().strip()
        if len(h) >= 32:
            return f"hash:{h[:64]}"
    
    # Non-IP correlation: username (compromised account)
    usernames = iocs.get("username", [])
    if usernames:
        user = str(usernames[0]).lower().strip()
        if user:
            return f"user:{user}"
    
    # Non-IP correlation: process path (suspicious execution)
    processes = iocs.get("process", [])
    if processes:
        proc = str(processes[0]).lower().strip()
        if proc:
            return f"process:{proc[:100]}"
    
    # IP-based fallbacks
    if source_ip:
        return source_ip

    hostname = alert_payload.get("hostname") or ""
    if hostname:
        return f"host:{hostname}"

    container_id = alert_payload.get("container_id") or ""
    if container_id:
        return f"container:{container_id[:12]}"

    container_name = alert_payload.get("container_name") or ""
    if container_name:
        return f"container:{container_name}"

    agent_name = alert_payload.get("agent_name") or ""
    if agent_name:
        return f"agent:{agent_name}"

    # Last resort: use the alert's own ID so it doesn't get lost
    alert_id = alert_payload.get("id") or alert_payload.get("source_id") or ""
    if alert_id:
        return f"alert:{alert_id}"

    return "unknown"


def build_correlation_key(alert_payload: dict) -> str:
    source_ip = alert_payload.get("source_ip") or ""
    tactics = sorted(_extract_mitre_tactics(alert_payload))
    campaign = _extract_campaign_type(alert_payload) or ""
    tactic_str = ",".join(tactics[:3])
    return f"{source_ip}|{tactic_str}|{campaign}"


def _is_noise_alert(alert_payload: dict) -> bool:
    title = (alert_payload.get("title") or "").lower()
    for noise in NOISE_RULES:
        if noise.lower() in title:
            return True
    return False


def _count_recent_alerts(correlation_key: str, window_minutes: int = 15) -> int:
    """Count how many alerts for this correlation key arrived within the time window."""
    if correlation_key not in _incident_cache:
        return 0
    entry = _incident_cache[correlation_key]
    timestamps = entry.get("alert_timestamps", {})
    if not timestamps:
        return 0
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=window_minutes)
    count = 0
    for ts_str in timestamps.values():
        try:
            ts = datetime.fromisoformat(ts_str)
            if ts >= cutoff:
                count += 1
        except ValueError:
            continue
    return count


def should_create_incident(
    alert_payload: dict, signals: dict, tracked_count: int
) -> bool:
    """
    Decide if this alert should trigger incident creation.

    Rules:
      1. Noise alerts (ICMP, protocol noise) → never create
      2. Critical severity → always create (real emergency)
      3. Attack patterns: SSH brute force, port scan, malware, C2 → create immediately
      4. Kill chain (2+ MITRE phases) → always create
      5. Spamhaus DROP (high confidence threat intel) → create
      6. High severity + MITRE tactics → create
      7. Medium severity + HIGH-RISK tactic → create
      8. CINS without attack pattern → DON'T create (just blocklist)
      9. Low severity → DON'T create (just track)
      10. Medium severity without special context → REQUIRE 2+ recent alerts from same IP within 15 min
    """
    if _is_noise_alert(alert_payload):
        return False

    severity = alert_payload.get("severity", "low")
    tactics = signals.get("mitre_tactics", [])
    high_risk = signals.get("high_risk_tactics", [])
    campaign = signals.get("campaign_type")
    kill_chain = signals.get("kill_chain", {})
    cloud = signals.get("cloud_provider")
    attack_pattern = signals.get("attack_pattern")
    is_spamhaus = signals.get("is_spamhaus_drop", False)
    is_cins = signals.get("is_cins", False)
    source_ip = alert_payload.get("source_ip", "")
    corr_key = signals.get("correlation_key") or _get_correlation_key(alert_payload)

    # 1. Critical severity → always create
    if severity == "critical":
        return True

    # 2. Attack patterns → create immediately
    if attack_pattern in ["ssh_brute_force", "port_scan", "malware", "c2", "web_attack", "ddos"]:
        return True

    # 3. Campaign detected → create
    if campaign:
        return True

    # 4. Kill chain (2+ MITRE phases) → create
    if kill_chain.get("detected"):
        return True

    # 5. Spamhaus DROP → create
    if is_spamhaus:
        return True

    # 6. High severity + MITRE tactics → create
    if severity == "high" and tactics:
        return True

    # 7. High severity + cloud provider → create
    if severity == "high" and cloud:
        return True

    # 8. Medium severity + HIGH-RISK tactic → create
    if severity == "medium" and high_risk:
        return True

    # 9. Standalone CINS → don't create (just blocklist, not an attack)
    if is_cins and not attack_pattern:
        return False

    # 10. Low severity → don't create
    if severity == "low":
        return False

    # 11. Medium severity without special context:
    #     Require 2+ alerts from same correlation key within 15 minutes
    if severity == "medium":
        recent_count = _count_recent_alerts(corr_key, window_minutes=15)
        if recent_count >= 2:
            return True
        # Single medium alert with no context → track only, wait for more
        return False

    return False


def calculate_incident_severity(existing_alerts: list, new_alert: dict) -> str:
    all_alerts = existing_alerts + [new_alert] if new_alert else existing_alerts
    sev_values = [a.get("severity", "low") for a in all_alerts if a.get("severity")]
    base_sev = (
        max(sev_values, key=lambda s: SEVERITY_ORDER.get(s, 0)) if sev_values else "low"
    )
    base_score = SEVERITY_ORDER.get(base_sev, 0)

    all_tactics = set()
    all_sources = set()
    for a in all_alerts:
        for t in _extract_mitre_tactics(a):
            all_tactics.add(t)
        src = a.get("source", "unknown")
        if src:
            all_sources.add(src)

    kill_chain = detect_kill_chain_progression(list(all_tactics))
    escalation = 0
    if kill_chain["detected"]:
        escalation += 1
    if len(all_sources) >= 3:
        escalation += 1

    final_score = min(base_score + escalation, 3)
    return {v: k for k, v in SEVERITY_ORDER.items()}.get(final_score, base_sev)


def _format_time_range(alerts: list) -> str:
    """Extract time range from alerts for display."""
    timestamps = []
    for a in alerts:
        ts = a.get("created_at") or a.get("event_time") or a.get("timestamp")
        if ts:
            try:
                if isinstance(ts, str):
                    ts = ts.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(ts)
                    timestamps.append(dt)
            except Exception:
                pass

    if not timestamps:
        return ""

    earliest = min(timestamps)
    latest = max(timestamps)
    span = latest - earliest

    if span.total_seconds() < 60:
        time_str = f"{int(span.total_seconds())}s"
    elif span.total_seconds() < 3600:
        time_str = f"{int(span.total_seconds() / 60)}m"
    elif span.total_seconds() < 86400:
        time_str = f"{int(span.total_seconds() / 3600)}h"
    else:
        time_str = f"{int(span.total_seconds() / 86400)}d"

    return f"{earliest.strftime('%H:%M')}–{latest.strftime('%H:%M')} UTC ({time_str})"


def generate_incident_title(
    signals: dict, alert_payload: dict, alert_count: int = 0
) -> str:
    campaign = signals.get("campaign_type")
    attack_pattern = signals.get("attack_pattern")
    source_ip = alert_payload.get("source_ip") or "unknown"
    country = signals.get("country")
    tactics = signals.get("mitre_tactics", [])
    severity = alert_payload.get("severity", "low")
    hostname = alert_payload.get("hostname", "")
    dest_ip = _extract_dest_ip(alert_payload)
    kill_chain = signals.get("kill_chain", {})

    # Use actual rule name from the alert - more accurate
    rule_name = alert_payload.get("rule_name", "")

    # If we have a specific campaign (verified attack pattern), use it
    if campaign:
        title = f"{campaign} — {source_ip}"
        if country:
            title += f" ({country})"
        if alert_count > 1:
            title += f" [{alert_count} alerts]"
        return title

    # If we have a verified attack pattern (not just "scan" keyword), use it
    if attack_pattern and not kill_chain.get("detected"):
        title = f"{_normalize_attack_type(attack_pattern)} — {source_ip}"
        if country:
            title += f" ({country})"
        if alert_count > 1:
            title += f" [{alert_count} alerts]"
        return title

    # If we have kill chain progression, use standard phase names
    if kill_chain.get("detected"):
        phases = kill_chain.get("phases", [])
        if phases:
            # Show the actual kill chain progression (e.g., "Reconnaissance → Initial Access")
            phase_chain = " → ".join([p for p in phases if isinstance(p, str)])
            title = f"Kill Chain: {phase_chain} — {source_ip}"
        else:
            title = f"Multi-Phase Activity — {source_ip}"

        if country:
            title += f" ({country})"
        if alert_count > 1:
            title += f" [{alert_count} alerts]"
        return title

    # If we have MITRE tactics, use the actual tactic name from alert
    if tactics:
        # Prefer the highest-risk tactic
        high_risk = [t for t in tactics if t in HIGH_RISK_TACTICS]
        selected_tactic = high_risk[0] if high_risk else tactics[0]

        # If we have rule name, incorporate it
        if rule_name:
            # Shorten rule name to first part
            short_rule = rule_name.split("|")[0].split("[")[0].strip()[:50]
            title = f"{short_rule} — {source_ip}"
        else:
            title = f"{selected_tactic} — {source_ip}"

        if country:
            title += f" ({country})"
        if alert_count > 1:
            title += f" [{alert_count} alerts]"
        return title

    # Critical severity - use actual title
    if severity == "critical":
        actual_title = alert_payload.get("title", "Security Alert")
        title = f"{actual_title[:80]} — {source_ip}"
        if hostname:
            title += f" on {hostname}"
        return title

    # Default: use actual alert title or rule name with context
    # Categorize threat intel alerts clearly
    category = alert_payload.get("category", "")
    title = alert_payload.get("title", "")
    
    if rule_name:
        short_rule = rule_name.split("|")[0].strip()[:60]
        # Prefix threat intel alerts for clarity
        if category == "threat-intel" or any(k in short_rule.lower() for k in ("cins", "spamhaus", "dshield", "block list")):
            title = f"Threat Intel: {short_rule}"
        else:
            title = short_rule
    elif title:
        title = title[:80]
    else:
        title = "Security Alert"
    
    # Add source/attacker context
    if source_ip and source_ip != "unknown":
        title += f" — {source_ip}"
    elif hostname:
        title += f" — {hostname}"
    
    # Add target context
    if dest_ip and dest_ip != source_ip:
        title += f" → {dest_ip}"
    
    # Add country
    if country:
        title += f" ({country})"
    
    # Add alert count for multi-alert incidents
    if alert_count > 1:
        title += f" [{alert_count} alerts]"
    
    return title[:200]


def generate_incident_tags(signals: dict, alert_payload: dict) -> List[str]:
    tags = []
    tactics = signals.get("mitre_tactics", [])
    for tactic in tactics:
        tags.append(f"mitre-tactic-{tactic}")

    cloud = signals.get("cloud_provider")
    if cloud:
        tags.append(f"cloud-{cloud}")

    campaign = signals.get("campaign_type")
    if campaign:
        tags.append(f"campaign-{campaign.lower().replace(' ', '-')}")

    attack_pattern = signals.get("attack_pattern")
    if attack_pattern:
        tags.append(f"attack-{attack_pattern}")

    is_spamhaus = signals.get("is_spamhaus_drop", False)
    if is_spamhaus:
        tags.append("malicious-ip")
        tags.append("spamhaus-drop")

    sources = set()
    src = alert_payload.get("source", "")
    if src:
        sources.add(src)
    for s in sources:
        tags.append(f"source-{s}")

    kill_chain = signals.get("kill_chain", {})
    if kill_chain.get("detected"):
        tags.append("kill-chain")
        phases = kill_chain.get("phases", [])
        if "Prep" in phases and "Objective" in phases:
            tags.append("full-kill-chain")
        elif len(phases) >= 3:
            tags.append("advanced-kill-chain")
        for phase in phases:
            tags.append(f"phase-{phase.lower()}")

    if signals.get("high_risk_tactics"):
        tags.append("high-risk")

    return list(set(tags))


def _find_matching_local_incident(alert_payload: dict) -> Optional[str]:
    corr_key = _get_correlation_key(alert_payload)
    if corr_key and corr_key in _incident_cache:
        cached = _incident_cache[corr_key]
        incident_id = cached.get("incident_id")
        if incident_id:
            return incident_id
    return None


def _is_incident_recent(cached: dict, max_age_minutes: int = 30) -> bool:
    """Check if the cached incident's last_seen is within the time window."""
    from datetime import datetime, timezone, timedelta
    last_seen_str = cached.get("last_seen")
    if not last_seen_str:
        return False
    try:
        last_seen = datetime.fromisoformat(last_seen_str)
        return datetime.now(timezone.utc) - last_seen < timedelta(minutes=max_age_minutes)
    except ValueError:
        return False


async def _find_or_update_existing_incident(
    alert_payload: dict, signals: dict
) -> Optional[str]:
    """
    Find an existing incident for this IP, or update if severity is higher.
    Returns incident_id if found/updated, None if no existing incident.
    Time window: only matches incidents active within last 30 minutes.
    """
    source_ip = alert_payload.get("source_ip") or ""
    corr_key = _get_correlation_key(alert_payload)
    if not source_ip:
        return None

    new_severity = alert_payload.get("severity", "medium")
    new_sev_score = SEVERITY_ORDER.get(new_severity, 0)

    # First check local cache
    if corr_key in _incident_cache:
        cached = _incident_cache[corr_key]
        existing_incident_id = cached.get("incident_id")
        if existing_incident_id and _is_incident_recent(cached, max_age_minutes=30):
            # Check if we need to escalate severity
            current_max = cached.get("max_severity", "low")
            current_score = SEVERITY_ORDER.get(current_max, 0)

            if new_sev_score > current_score:
                try:
                    result = await client.get_incident(existing_incident_id)
                    current_incident_sev = result.get("severity", "low")
                    current_incident_score = SEVERITY_ORDER.get(current_incident_sev, 0)

                    if new_sev_score > current_incident_score:
                        new_incident_sev = {
                            v: k for k, v in SEVERITY_ORDER.items()
                        }.get(new_sev_score, new_severity)
                        await client.update_incident(
                            existing_incident_id, {"severity": new_incident_sev}
                        )
                        cached["max_severity"] = new_severity
                        _save_incident_cache()
                        logger.info(
                            "incident_escalated_via_cache",
                            incident_id=existing_incident_id,
                            new_severity=new_incident_sev,
                        )
                except Exception as e:
                    logger.warning(
                        "escalation_via_cache_failed",
                        incident_id=existing_incident_id,
                        error=str(e)[:100],
                    )

            return existing_incident_id

    # If not in local cache or too old, search OpenSOAR
    try:
        result = await client.list_incidents(limit=50, status="open")
        incidents = result.get("incidents", [])

        for inc in incidents:
            inc_id = inc.get("id", "")
            inc_title = inc.get("title", "")
            created_at = inc.get("created_at", "")

            # Skip incidents older than 30 minutes (prevent linking to stale incidents)
            from datetime import datetime, timezone, timedelta
            try:
                inc_created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
                if datetime.now(timezone.utc) - inc_created > timedelta(minutes=30):
                    continue
            except (ValueError, TypeError):
                pass

            # Check if incident title contains this source IP
            if source_ip in inc_title:
                # Avoid mixing unrelated attack types from the same IP
                attack_pattern = signals.get("attack_pattern")
                if attack_pattern:
                    normalized = _normalize_attack_type(attack_pattern)
                    if normalized.lower() not in inc_title.lower():
                        # Same IP but different attack pattern — keep searching
                        pass
                    else:
                        # Merge with existing tracking data — don't wipe alert history
                        existing_entry = _incident_cache.get(corr_key, {})
                        _incident_cache[corr_key] = {
                            **existing_entry,
                            "incident_id": inc_id,
                            "last_seen": _now_utc().isoformat(),
                            "max_severity": new_severity,
                            "campaign_type": signals.get("campaign_type"),
                        }
                        _save_incident_cache()

                        # Check escalation
                        current_incident_sev = inc.get("severity", "low")
                        current_incident_score = SEVERITY_ORDER.get(current_incident_sev, 0)
                        if new_sev_score > current_incident_score:
                            new_incident_sev = {v: k for k, v in SEVERITY_ORDER.items()}.get(
                                new_sev_score, new_severity
                            )
                            await client.update_incident(inc_id, {"severity": new_incident_sev})
                            logger.info(
                                "incident_escalated_via_opensoar",
                                incident_id=inc_id,
                                new_severity=new_incident_sev,
                            )

                        return inc_id
                else:
                    # Merge with existing tracking data — don't wipe alert history
                    existing_entry = _incident_cache.get(corr_key, {})
                    _incident_cache[corr_key] = {
                        **existing_entry,
                        "incident_id": inc_id,
                        "last_seen": _now_utc().isoformat(),
                        "max_severity": new_severity,
                        "campaign_type": signals.get("campaign_type"),
                    }
                    _save_incident_cache()

                    # Check escalation
                    current_incident_sev = inc.get("severity", "low")
                    current_incident_score = SEVERITY_ORDER.get(current_incident_sev, 0)
                    if new_sev_score > current_incident_score:
                        new_incident_sev = {v: k for k, v in SEVERITY_ORDER.items()}.get(
                            new_sev_score, new_severity
                        )
                        await client.update_incident(inc_id, {"severity": new_incident_sev})
                        logger.info(
                            "incident_escalated_via_opensoar",
                            incident_id=inc_id,
                            new_severity=new_incident_sev,
                        )

                    return inc_id

            # Also check alerts linked to incident
            try:
                inc_alerts = await client.get_incident_alerts(inc_id)
                if inc_alerts:
                    for inc_alert in inc_alerts:
                        alert_ip = None
                        if isinstance(inc_alert, dict):
                            alert_ip = inc_alert.get("source_ip")
                        elif isinstance(inc_alert, str):
                            try:
                                alert_details = await client.get_alert(inc_alert)
                                alert_ip = alert_details.get("source_ip")
                            except Exception:
                                continue
                        if alert_ip == source_ip:
                            # Merge with existing tracking data — don't wipe alert history
                            existing_entry = _incident_cache.get(corr_key, {})
                            _incident_cache[corr_key] = {
                                **existing_entry,
                                "incident_id": inc_id,
                                "last_seen": _now_utc().isoformat(),
                                "max_severity": new_severity,
                                "campaign_type": signals.get("campaign_type"),
                            }
                            _save_incident_cache()
                            return inc_id
            except Exception:
                continue
    except Exception as e:
        logger.warning("opensoar_incident_search_failed", error=str(e)[:100])

    return None


async def _find_matching_opensoar_incident(alert_payload: dict) -> Optional[str]:
    corr_key = _get_correlation_key(alert_payload)
    source_ip = alert_payload.get("source_ip") or ""
    hostname = alert_payload.get("hostname") or ""

    try:
        result = await client.list_incidents(limit=50, status="open")
        incidents = result.get("incidents", [])
        for inc in incidents:
            inc_id = inc.get("id", "")
            inc_title = inc.get("title", "")
            # Fast path: check title for correlation key
            if source_ip and source_ip in inc_title:
                return inc_id
            if hostname and hostname in inc_title:
                return inc_id
            # Slow path: check incident alerts
            try:
                inc_alerts = await client.get_incident_alerts(inc_id)
                for inc_alert in inc_alerts:
                    if isinstance(inc_alert, dict):
                        if inc_alert.get("source_ip") == source_ip:
                            return inc_id
                        if hostname and inc_alert.get("hostname") == hostname:
                            return inc_id
                    elif isinstance(inc_alert, str):
                        try:
                            alert_details = await client.get_alert(inc_alert)
                            if alert_details.get("source_ip") == source_ip:
                                return inc_id
                            if hostname and alert_details.get("hostname") == hostname:
                                return inc_id
                        except Exception:
                            continue
            except Exception:
                continue
    except Exception as e:
        logger.warning("opensoar_incident_search_failed", error=str(e)[:100])

    return None


# ─── Local SQLite shadow store helpers ────────────────────────────────────

async def _ensure_local_incident(
    upstream_id: str,
    title: str,
    description: str,
    severity: str,
    source_ip: str,
    alert_ids: list[str],
    tags: list[str] = None,
) -> Optional[str]:
    """Create or update a local Incident shadow record for an upstream incident."""
    from sqlalchemy import select, insert, update
    from response.db import AsyncSessionLocal
    from response.models import Incident, AlertIncidentLink, Alert
    from core.whitelist import is_whitelisted

    try:
        async with AsyncSessionLocal() as session:
            # Check if local incident already exists by external_id
            result = await session.execute(
                select(Incident).where(Incident.external_id == upstream_id)
            )
            existing = result.scalar_one_or_none()

            # Determine whitelist status from source_ip and linked alerts
            whitelisted = False
            if source_ip and await is_whitelisted(source_ip):
                whitelisted = True

            if existing:
                local_id = existing.id
                # Carry over existing whitelist status
                whitelisted = whitelisted or existing.whitelisted
                # Update fields
                await session.execute(
                    update(Incident)
                    .where(Incident.id == local_id)
                    .values(
                        title=title or existing.title,
                        description=description or existing.description,
                        severity=severity or existing.severity,
                        source_ips=[source_ip] if source_ip else existing.source_ips,
                        alert_ids=list(set((existing.alert_ids or []) + alert_ids)),
                        whitelisted=whitelisted,
                        updated_at=_now_utc(),
                    )
                )
            else:
                import uuid
                local_id = str(uuid.uuid4())
                await session.execute(
                    insert(Incident).values(
                        id=local_id,
                        external_id=upstream_id,
                        title=title,
                        description=description,
                        severity=severity,
                        status="open",
                        source_ips=[source_ip] if source_ip else None,
                        alert_ids=alert_ids,
                        tags=tags or [],
                        whitelisted=whitelisted,
                        created_at=_now_utc(),
                        updated_at=_now_utc(),
                    )
                )

            # Link alerts — resolve upstream IDs to local Alert.id first
            for alert_id in alert_ids:
                local_alert_id = await _resolve_alert_id_to_local(alert_id, session)
                if not local_alert_id:
                    continue
                # If any linked alert is whitelisted, propagate to incident
                if not whitelisted:
                    alert_result = await session.execute(
                        select(Alert.whitelisted).where(Alert.id == local_alert_id)
                    )
                    if alert_result.scalar_one_or_none():
                        whitelisted = True
                        await session.execute(
                            update(Incident)
                            .where(Incident.id == local_id)
                            .values(whitelisted=True)
                        )
                try:
                    await session.execute(
                        insert(AlertIncidentLink).values(
                            alert_id=local_alert_id,
                            incident_id=local_id,
                            correlation_confidence="high",
                            correlation_reason="auto-created from incident_manager",
                            linked_at=_now_utc(),
                        )
                    )
                except Exception:
                    pass  # Link may already exist

            await session.commit()
            logger.info("local_incident_ensured", upstream_id=upstream_id, local_id=local_id, whitelisted=whitelisted)
            return local_id
    except Exception as e:
        logger.warning("local_incident_ensure_failed", upstream_id=upstream_id, error=str(e)[:100])
        return None


async def _resolve_alert_id_to_local(alert_id: str, session) -> Optional[str]:
    """Resolve an alert ID (local UUID or upstream ID) to a local Alert.id."""
    from sqlalchemy import select
    from response.models import Alert

    # If it's already a local UUID that exists, return it
    result = await session.execute(select(Alert.id).where(Alert.id == alert_id))
    local_id = result.scalar_one_or_none()
    if local_id:
        return local_id

    # Try resolving via external_id
    result = await session.execute(
        select(Alert.id).where(Alert.external_id == alert_id)
    )
    return result.scalar_one_or_none()


async def _link_alert_to_local_incident(
    upstream_incident_id: str, alert_id: str, source_ip: str
) -> bool:
    """Link an alert to the local shadow incident (find by external_id).
    alert_id may be a local UUID or an upstream ID — resolves automatically."""
    from sqlalchemy import select, insert, update
    from response.db import AsyncSessionLocal
    from response.models import Incident, AlertIncidentLink, Alert
    from core.whitelist import is_whitelisted

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(Incident).where(Incident.external_id == upstream_incident_id)
            )
            local_incident = result.scalar_one_or_none()
            if not local_incident:
                return False

            # Resolve to local alert ID (handles upstream vs local IDs)
            local_alert_id = await _resolve_alert_id_to_local(alert_id, session)
            if not local_alert_id:
                # No local alert yet — just record the upstream ID on the incident
                current_ids = set(local_incident.alert_ids or [])
                current_ids.add(alert_id)
                local_incident.alert_ids = list(current_ids)
                # Still check source_ip whitelist even without local alert
                if source_ip and not local_incident.whitelisted and await is_whitelisted(source_ip):
                    local_incident.whitelisted = True
                await session.commit()
                return False

            # Check if linked alert is whitelisted
            if not local_incident.whitelisted:
                alert_result = await session.execute(
                    select(Alert.whitelisted, Alert.source_ip).where(Alert.id == local_alert_id)
                )
                alert_row = alert_result.first()
                if alert_row:
                    alert_whitelisted, alert_source_ip = alert_row
                    if alert_whitelisted or (alert_source_ip and await is_whitelisted(alert_source_ip)):
                        await session.execute(
                            update(Incident)
                            .where(Incident.id == local_incident.id)
                            .values(whitelisted=True)
                        )

            try:
                await session.execute(
                    insert(AlertIncidentLink).values(
                        alert_id=local_alert_id,
                        incident_id=local_incident.id,
                        correlation_confidence="high",
                        correlation_reason="auto-linked from incident_manager",
                        linked_at=_now_utc(),
                    )
                )
            except Exception:
                pass  # Already linked

            # Update alert_ids on incident (store upstream ID for reference)
            current_ids = set(local_incident.alert_ids or [])
            current_ids.add(alert_id)
            local_incident.alert_ids = list(current_ids)
            await session.commit()
            return True
    except Exception as e:
        logger.warning("local_link_failed", upstream_id=upstream_incident_id, alert_id=alert_id, error=str(e)[:100])
        return False


async def _create_new_incident(
    signals: dict,
    alert_payload: dict,
    upstream_alert_id: str,
    alert_count: int = 1,
    local_alert_id: Optional[str] = None,
) -> Optional[str]:
    title = generate_incident_title(signals, alert_payload, alert_count)
    tags = generate_incident_tags(signals, alert_payload)
    severity = alert_payload.get("severity", "medium")

    description_parts = []

    campaign = signals.get("campaign_type")
    kill_chain = signals.get("kill_chain", {})
    tactics = signals.get("mitre_tactics", [])
    cloud = signals.get("cloud_provider")
    country = signals.get("country")
    source_ip = alert_payload.get("source_ip", "")
    dest_ip = _extract_dest_ip(alert_payload)

    if campaign:
        description_parts.append(f"Attack Type: {campaign}")

    if kill_chain.get("detected"):
        description_parts.append(f"Kill Chain: {' → '.join(kill_chain['phases'])}")

    if tactics:
        description_parts.append(f"MITRE ATT&CK: {', '.join(tactics)}")

    if cloud:
        description_parts.append(f"Infrastructure: {cloud}")

    if country:
        description_parts.append(f"Origin: {country}")

    description_parts.append(f"Source: {source_ip}")

    if dest_ip:
        description_parts.append(f"Target: {dest_ip}")

    description = " | ".join(description_parts)

    try:
        result = await client.create_incident(
            title=title,
            description=description,
            severity=severity,
            tags=tags,
        )
        incident_id = result.get("id", "")
        if incident_id:
            logger.info(
                "incident_created",
                incident_id=incident_id,
                title=title[:100],
                severity=severity,
                tags=tags,
            )
            # Also create local shadow incident
            link_alert = local_alert_id or upstream_alert_id
            await _ensure_local_incident(
                upstream_id=incident_id,
                title=title,
                description=description,
                severity=severity,
                source_ip=source_ip,
                alert_ids=[link_alert],
                tags=tags,
            )
            return incident_id
    except Exception as e:
        logger.error("incident_creation_failed", title=title[:100], error=str(e)[:100])

    return None


async def _track_alert(
    upstream_alert_id: str,
    alert_payload: dict,
    signals: dict,
    local_alert_id: Optional[str] = None,
    correlation_key: str = None,
) -> int:
    """Track alert in local cache. Returns current count for this correlation key."""
    key = correlation_key or _get_correlation_key(alert_payload)
    if not key:
        return 0

    if key not in _incident_cache:
        _incident_cache[key] = {
            "alert_ids": [],
            "incident_id": None,
            "first_seen": _now_utc().isoformat(),
            "last_seen": _now_utc().isoformat(),
            "campaign_type": signals.get("campaign_type"),
            "tactics": set(),
            "sources": set(),
            "max_severity": "low",
            "dest_ips": set(),
            "alert_timestamps": {},
            "correlation_key": key,
            "source_ip": alert_payload.get("source_ip") or "",
        }

    entry = _incident_cache[key]
    if upstream_alert_id not in entry["alert_ids"]:
        entry["alert_ids"].append(upstream_alert_id)

    # Store timestamp for time-window calculations
    entry["alert_timestamps"][upstream_alert_id] = _now_utc().isoformat()

    for t in signals.get("mitre_tactics", []):
        entry["tactics"].add(t)

    src = alert_payload.get("source", "")
    if src:
        entry["sources"].add(src)

    dest_ip = _extract_dest_ip(alert_payload)
    if dest_ip:
        entry["dest_ips"].add(dest_ip)

    current_sev = alert_payload.get("severity", "low")
    if SEVERITY_ORDER.get(current_sev, 0) > SEVERITY_ORDER.get(
        entry.get("max_severity", "low"), 0
    ):
        entry["max_severity"] = current_sev

    entry["last_seen"] = _now_utc().isoformat()
    _save_incident_cache()

    return len(entry["alert_ids"])


async def _link_alert_to_existing_incident(
    incident_id: str,
    upstream_alert_id: str,
    correlation_key: str,
    local_alert_id: Optional[str] = None,
) -> bool:
    success = await client.link_alert_to_incident(incident_id, upstream_alert_id)
    if success:
        _processed_alerts.add(upstream_alert_id)
        _save_links()

        if correlation_key and correlation_key in _incident_cache:
            if upstream_alert_id not in _incident_cache[correlation_key]["alert_ids"]:
                _incident_cache[correlation_key]["alert_ids"].append(upstream_alert_id)
            _incident_cache[correlation_key]["last_seen"] = _now_utc().isoformat()
            _save_incident_cache()

        # Also link locally using local alert ID if available
        link_alert = local_alert_id or upstream_alert_id
        await _link_alert_to_local_incident(incident_id, link_alert, correlation_key)

        logger.info(
            "alert_linked_to_incident",
            upstream_alert_id=upstream_alert_id,
            local_alert_id=local_alert_id,
            incident_id=incident_id,
        )
    return success


async def process_alert(
    upstream_alert_id: str,
    alert_payload: dict,
    local_alert_id: Optional[str] = None,
) -> dict:
    """
    Main entry point — process a forwarded alert for incident correlation.
    Called from poller.py after successful alert forward.

    Flow:
      1. Extract signals (MITRE, campaign, cloud, country, kill chain)
      2. Check if already linked to an incident (BEFORE tracking so time
         window uses true last activity, not the current alert)
      3. If yes → link alert to existing incident
      4. If no → track alert in local cache
      5. Decide if should create incident
      6. If yes → create incident + link alert
      7. If no → just track, wait for more alerts
    """
    from config import get_settings
    settings = get_settings()

    if not settings.upstream_enabled:
        from pipeline.datausage.local_incident_manager import process_alert_local
        return await process_alert_local(
            alert_id=upstream_alert_id,
            alert_payload=alert_payload,
            local_alert_id=local_alert_id,
        )

    _load_links()
    _load_incident_cache()

    if upstream_alert_id in _processed_alerts:
        return {"action": "skipped", "incident_id": "", "reason": "already_processed"}

    # Skip incident correlation for whitelisted alerts
    if alert_payload.get("whitelisted"):
        logger.info(
            "alert_skipped_whitelisted",
            upstream_alert_id=upstream_alert_id,
            local_alert_id=local_alert_id,
            source_ip=alert_payload.get("source_ip", ""),
        )
        return {"action": "skipped", "incident_id": "", "reason": "whitelisted"}

    # Use correlation key instead of requiring source_ip
    # Falco/container alerts may not have IPs but still need incident creation
    corr_key = _get_correlation_key(alert_payload)
    source_ip = alert_payload.get("source_ip") or ""

    mitre_tactics = _extract_mitre_tactics(alert_payload)
    cloud_provider = _extract_cloud_provider(alert_payload)
    campaign_type = _extract_campaign_type(alert_payload)
    country = _extract_country(alert_payload)
    attack_pattern = _extract_attack_pattern(alert_payload)
    kill_chain = detect_kill_chain_progression(mitre_tactics)
    high_risk_tactics = [t for t in mitre_tactics if t in HIGH_RISK_TACTICS]

    title_lower = (alert_payload.get("title") or "").lower()
    is_spamhaus = (
        "spamhaus" in title_lower
        or "drop" in title_lower
        or "listed traffic" in title_lower
    )
    is_cins = "cins" in title_lower or "poor reputation" in title_lower

    signals = {
        "mitre_tactics": mitre_tactics,
        "cloud_provider": cloud_provider,
        "campaign_type": campaign_type,
        "country": country,
        "attack_pattern": attack_pattern,
        "kill_chain": kill_chain,
        "high_risk_tactics": high_risk_tactics,
        "source_ip": source_ip,
        "correlation_key": corr_key,
        "is_spamhaus_drop": is_spamhaus,
        "is_cins": is_cins,
    }

    # 1. Check for existing incident FIRST (before tracking) so the 30-min
    #    time-window check uses the TRUE last activity time, not the current alert.
    existing_incident_id = await _find_or_update_existing_incident(
        alert_payload, signals
    )

    if existing_incident_id:
        await _link_alert_to_existing_incident(
            existing_incident_id, upstream_alert_id, corr_key,
            local_alert_id=local_alert_id,
        )

        return {
            "action": "linked",
            "incident_id": existing_incident_id,
            "reason": "matched_existing_incident",
        }

    # 2. Track the alert (adds to cache, updates last_seen)
    tracked_count = await _track_alert(
        upstream_alert_id, alert_payload, signals, local_alert_id=local_alert_id,
        correlation_key=corr_key
    )

    # 3. Decide whether this alert warrants a new incident
    if not should_create_incident(alert_payload, signals, tracked_count):
        logger.debug(
            "alert_tracked_no_incident",
            upstream_alert_id=upstream_alert_id,
            local_alert_id=local_alert_id,
            source_ip=source_ip,
            severity=alert_payload.get("severity", "low"),
            tactics=mitre_tactics,
            tracked_count=tracked_count,
        )
        return {
            "action": "tracked",
            "incident_id": "",
            "reason": "waiting_for_more_signals",
        }

    incident_id = await _create_new_incident(
        signals, alert_payload, upstream_alert_id,
        local_alert_id=local_alert_id,
    )
    if incident_id:
        # Try to link, but don't fail if linking fails - incident is already created
        link_success = await client.link_alert_to_incident(incident_id, upstream_alert_id)

        _processed_alerts.add(upstream_alert_id)
        _save_links()

        if corr_key:
            _incident_cache[corr_key]["incident_id"] = incident_id
            _save_incident_cache()

        _local_incidents[incident_id] = {
            "alert_ids": [upstream_alert_id],
            "source_ip": source_ip,
            "created_at": _now_utc().isoformat(),
            "signals": {k: v for k, v in signals.items() if k != "kill_chain"},
        }
        _save_incident_cache()

        # Also link locally using local alert ID
        link_alert = local_alert_id or upstream_alert_id
        await _link_alert_to_local_incident(incident_id, link_alert, source_ip)

        logger.info(
            "incident_created_and_linked"
            if link_success
            else "incident_created_pending_link",
            upstream_alert_id=upstream_alert_id,
            local_alert_id=local_alert_id,
            incident_id=incident_id,
            linked=link_success,
        )
        return {
            "action": "created",
            "incident_id": incident_id,
            "reason": "new_incident_created",
        }


async def _check_and_escalate_incident(
    correlation_key: str, new_severity: str
) -> Optional[dict]:
    """Check if we should escalate an existing incident based on new alert severity."""
    if correlation_key not in _incident_cache:
        return None

    cached = _incident_cache[correlation_key]
    existing_incident_id = cached.get("incident_id")
    if not existing_incident_id:
        return None

    current_max = cached.get("max_severity", "low")
    new_score = SEVERITY_ORDER.get(new_severity, 0)
    current_score = SEVERITY_ORDER.get(current_max, 0)

    if new_score > current_score:
        try:
            result = await client.get_incident(existing_incident_id)
            current_incident_sev = result.get("severity", "low")
            current_incident_score = SEVERITY_ORDER.get(current_incident_sev, 0)

            if new_score > current_incident_score:
                new_incident_sev = {v: k for k, v in SEVERITY_ORDER.items()}.get(
                    new_score, new_severity
                )
                await client.update_incident(
                    existing_incident_id, {"severity": new_incident_sev}
                )
                cached["max_severity"] = new_severity
                _save_incident_cache()

                logger.info(
                    "incident_escalated",
                    incident_id=existing_incident_id,
                    old_severity=current_incident_sev,
                    new_severity=new_incident_sev,
                    correlation_key=correlation_key,
                )
                return {
                    "old_severity": current_incident_sev,
                    "new_severity": new_incident_sev,
                }
        except Exception as e:
            logger.warning(
                "incident_escalation_failed",
                incident_id=existing_incident_id,
                error=str(e)[:100],
            )

    return None


async def run_correlation_cycle() -> int:
    """
    Background correlation cycle — runs every 5 minutes.
    Fetches OpenSOAR suggestions, enhances with our data, creates missing incidents.
    Also checks tracked IPs that haven't been promoted to incidents yet.
    """
    from config import get_settings
    settings = get_settings()

    if not settings.upstream_enabled:
        from pipeline.datausage.local_incident_manager import run_local_correlation_cycle
        return await run_local_correlation_cycle()

    _load_links()
    _load_incident_cache()

    incidents_created = 0

    # Memoization cache for whitelist checks during this cycle
    _whitelist_cache: dict[str, bool] = {}

    async def _cached_is_whitelisted(value: str) -> bool:
        if value in _whitelist_cache:
            return _whitelist_cache[value]
        try:
            from core.whitelist import is_whitelisted
            result = await is_whitelisted(value)
            _whitelist_cache[value] = result
            return result
        except Exception as e:
            logger.warning("whitelist_check_failed_during_cycle", value=value, error=str(e)[:100])
            _whitelist_cache[value] = False
            return False

    # Phase 1: Process OpenSOAR suggestions
    try:
        suggestions = await client.get_incident_suggestions()
        if suggestions and isinstance(suggestions, str):
            # Upstream returned an error string or unexpected format
            logger.debug("incident_suggestions_unexpected_format", response_type="str", response=suggestions[:100])
            suggestions = None

        if suggestions:
            groups = []
            if isinstance(suggestions, dict) and "groups" in suggestions:
                groups = suggestions["groups"]
            elif isinstance(suggestions, list):
                groups = suggestions

            for group in groups:
                if not isinstance(group, dict):
                    continue

                source_ip = group.get("source_ip", "")
                alert_count = group.get("alert_count", 0)

                alerts_in_group = group.get("alerts", [])
                if not alerts_in_group or len(alerts_in_group) < 2:
                    continue

                alert_ids = []
                alert_details = []
                for a in alerts_in_group:
                    if isinstance(a, dict):
                        aid = a.get("id", "")
                        if aid:
                            alert_ids.append(aid)
                            alert_details.append(a)
                    elif isinstance(a, str):
                        alert_ids.append(a)

                if not alert_ids or len(alert_ids) < 2:
                    continue

                # Use source_ip or hostname as identifier
                if not source_ip and alert_details:
                    source_ip = alert_details[0].get("source_ip", "")

                # If still no source_ip, try using hostname
                if not source_ip and alert_details:
                    hostname = alert_details[0].get("hostname", "")
                    if hostname:
                        source_ip = f"host:{hostname}"  # Mark as hostname-based

                # Allow processing even without source_ip (for performance alerts by hostname)
                use_hostname = not source_ip and alert_details
                if use_hostname:
                    source_ip = alert_details[0].get("hostname", "") or "unknown-host"

                if not source_ip:
                    continue

                # Skip if source_ip is whitelisted
                if await _cached_is_whitelisted(source_ip):
                    logger.debug("correlation_cycle_whitelisted_skipped", source_ip=source_ip, reason="source_ip_whitelisted")
                    continue

                corr_key = source_ip
                if alert_details:
                    corr_key = _get_correlation_key(alert_details[0])

                if corr_key in _incident_cache and _incident_cache[corr_key].get(
                    "incident_id"
                ):
                    existing_id = _incident_cache[corr_key]["incident_id"]
                    for aid in alert_ids:
                        if aid not in _processed_alerts:
                            await client.link_alert_to_incident(existing_id, aid)
                            _processed_alerts.add(aid)
                    continue

                if not alert_details:
                    for aid in alert_ids[:10]:
                        try:
                            details = await client.get_alert(aid)
                            alert_details.append(details)
                        except Exception:
                            pass

                if not alert_details:
                    continue

                all_tactics = set()
                all_campaigns = set()
                all_sources = set()
                cloud_provider = None
                country = None
                dest_ips = set()
                for ad in alert_details:
                    for t in _extract_mitre_tactics(ad):
                        all_tactics.add(t)
                    camp = _extract_campaign_type(ad)
                    if camp:
                        all_campaigns.add(camp)
                    src = ad.get("source", "")
                    if src:
                        all_sources.add(src)
                    if not cloud_provider:
                        cloud_provider = _extract_cloud_provider(ad)
                    if not country:
                        country = _extract_country(ad)
                    did = _extract_dest_ip(ad)
                    if did:
                        dest_ips.add(did)

                kill_chain = detect_kill_chain_progression(list(all_tactics))
                campaign_type = list(all_campaigns)[0] if all_campaigns else None

                # Extract attack pattern from aggregated alerts
                combined_text = " ".join(
                    [
                        (ad.get("title", "") or "")
                        + " "
                        + (ad.get("description", "") or "")
                        for ad in alert_details
                    ]
                ).lower()
                attack_pattern = None
                for pattern_name, keywords in ATTACK_PATTERNS.items():
                    for kw in keywords:
                        if kw in combined_text:
                            attack_pattern = pattern_name
                            break
                    if attack_pattern:
                        break

                # Calculate severity for the group of alerts
                severity = _calculate_group_severity(alert_details)

                first_alert = alert_details[0]
                corr_key = _get_correlation_key(first_alert)

                signals = {
                    "mitre_tactics": list(all_tactics),
                    "cloud_provider": cloud_provider,
                    "campaign_type": campaign_type,
                    "country": country,
                    "attack_pattern": attack_pattern,
                    "kill_chain": kill_chain,
                    "source_ip": source_ip,
                }

                time_range = _format_time_range(alert_details)
                title = generate_incident_title(
                    signals, first_alert, len(alert_details)
                )
                tags = generate_incident_tags(signals, first_alert)
                severity = _calculate_group_severity(alert_details)

                description_parts = []
                if campaign_type:
                    description_parts.append(f"Attack Type: {campaign_type}")
                if kill_chain.get("detected"):
                    description_parts.append(
                        f"Kill Chain: {' → '.join(kill_chain['phases'])}"
                    )
                if all_tactics:
                    description_parts.append(
                        f"MITRE ATT&CK: {', '.join(sorted(all_tactics))}"
                    )
                if cloud_provider:
                    description_parts.append(f"Infrastructure: {cloud_provider}")
                if country:
                    description_parts.append(f"Origin: {country}")
                description_parts.append(f"Source: {source_ip}")
                if dest_ips:
                    description_parts.append(f"Targets: {', '.join(sorted(dest_ips))}")
                if time_range:
                    description_parts.append(f"Time Window: {time_range}")
                description_parts.append(
                    f"Alerts: {len(alert_details)} from sources: {', '.join(sorted(all_sources))}"
                )

                description = " | ".join(description_parts)

                try:
                    result = await client.create_incident(
                        title=title,
                        description=description,
                        severity=severity,
                        tags=tags,
                    )
                    incident_id = result.get("id", "")
                    if incident_id:
                        linked = 0
                        for aid in alert_ids:
                            if await client.link_alert_to_incident(incident_id, aid):
                                linked += 1
                                _processed_alerts.add(aid)

                        if corr_key:
                            _incident_cache[corr_key] = {
                                "alert_ids": alert_ids,
                                "incident_id": incident_id,
                                "first_seen": _now_utc().isoformat(),
                                "last_seen": _now_utc().isoformat(),
                                "campaign_type": campaign_type,
                            }
                            _save_incident_cache()

                        _save_links()
                        incidents_created += 1

                        logger.info(
                            "correlation_cycle_incident_created",
                            incident_id=incident_id,
                            title=title[:100],
                            alerts_linked=linked,
                            severity=severity,
                        )
                except Exception as e:
                    logger.warning(
                        "correlation_cycle_incident_failed",
                        source_ip=source_ip,
                        error=str(e)[:100],
                    )
    except Exception as e:
        logger.warning("correlation_cycle_suggestions_failed", error=str(e)[:100])

    # Phase 2: Check tracked IPs that haven't been promoted yet
    for ip, data in list(_incident_cache.items()):
        if data.get("incident_id"):
            continue

        alert_ids = data.get("alert_ids", [])
        if len(alert_ids) < 2:
            continue

        max_sev = data.get("max_severity", "low")
        tactics = data.get("tactics", set())
        if isinstance(tactics, list):
            tactics = set(tactics)

        kill_chain = detect_kill_chain_progression(list(tactics))
        campaign = data.get("campaign_type")

        should_promote = (
            SEVERITY_ORDER.get(max_sev, 0) >= 2
            or kill_chain["detected"]
            or campaign is not None
            or len(alert_ids) >= 3
        )

        if not should_promote:
            continue

        # Skip if tracked IP is whitelisted
        actual_source_ip = data.get("source_ip", "") or ip
        if await _cached_is_whitelisted(actual_source_ip):
            logger.debug("correlation_cycle_whitelisted_skipped", source_ip=actual_source_ip, reason="tracked_ip_whitelisted")
            continue

        alert_details = []
        for aid in alert_ids[:5]:
            try:
                details = await client.get_alert(aid)
                alert_details.append(details)
            except Exception:
                pass

        if not alert_details:
            continue

        # Extract attack pattern from alerts
        combined_text = " ".join(
            [
                (ad.get("title", "") or "") + " " + (ad.get("description", "") or "")
                for ad in alert_details
            ]
        ).lower()
        attack_pattern = None
        for pattern_name, keywords in ATTACK_PATTERNS.items():
            for kw in keywords:
                if kw in combined_text:
                    attack_pattern = pattern_name
                    break
            if attack_pattern:
                break

        actual_source_ip = data.get("source_ip", "") or ip
        signals = {
            "mitre_tactics": list(tactics),
            "cloud_provider": _extract_cloud_provider(alert_details[0]),
            "campaign_type": campaign,
            "country": _extract_country(alert_details[0]),
            "attack_pattern": attack_pattern,
            "kill_chain": kill_chain,
            "high_risk_tactics": [t for t in tactics if t in HIGH_RISK_TACTICS],
            "source_ip": actual_source_ip,
        }

        time_range = _format_time_range(alert_details)
        title = generate_incident_title(signals, alert_details[0], len(alert_ids))
        tags = generate_incident_tags(signals, alert_details[0])
        severity = calculate_incident_severity(alert_details, {})

        description_parts = []
        if campaign:
            description_parts.append(f"Attack Type: {campaign}")
        if kill_chain.get("detected"):
            description_parts.append(f"Kill Chain: {' → '.join(kill_chain['phases'])}")
        if tactics:
            description_parts.append(f"MITRE ATT&CK: {', '.join(sorted(tactics))}")
        cloud = _extract_cloud_provider(alert_details[0])
        if cloud:
            description_parts.append(f"Infrastructure: {cloud}")
        country = _extract_country(alert_details[0])
        if country:
            description_parts.append(f"Origin: {country}")
        description_parts.append(f"Source: {actual_source_ip}")
        dest_ips = data.get("dest_ips", set())
        if isinstance(dest_ips, set) and dest_ips:
            description_parts.append(f"Targets: {', '.join(sorted(dest_ips))}")
        if time_range:
            description_parts.append(f"Time Window: {time_range}")
        description_parts.append(f"Alerts: {len(alert_ids)}")

        description = " | ".join(description_parts)

        try:
            result = await client.create_incident(
                title=title,
                description=description,
                severity=severity,
                tags=tags,
            )
            incident_id = result.get("id", "")
            if incident_id:
                linked = 0
                for aid in alert_ids:
                    if await client.link_alert_to_incident(incident_id, aid):
                        linked += 1
                        _processed_alerts.add(aid)

                _incident_cache[ip]["incident_id"] = incident_id
                _save_incident_cache()
                _save_links()
                incidents_created += 1

                logger.info(
                    "tracked_ip_promoted_to_incident",
                    incident_id=incident_id,
                    source_ip=ip,
                    alerts_linked=linked,
                    severity=severity,
                )
        except Exception as e:
            logger.warning(
                "promote_tracked_ip_failed", source_ip=ip, error=str(e)[:100]
            )

    _cleanup_stale_cache()

    if incidents_created > 0:
        logger.info("correlation_cycle_complete", incidents_created=incidents_created)

    return incidents_created


def _cleanup_stale_cache() -> None:
    now = time.time()
    stale_ips = []
    for ip, data in _incident_cache.items():
        if data.get("incident_id"):
            continue
        last_seen = data.get("last_seen", "")
        if last_seen:
            try:
                ls = datetime.fromisoformat(last_seen)
                if (now - ls.timestamp()) > 86400:
                    stale_ips.append(ip)
            except Exception:
                pass

    for ip in stale_ips:
        del _incident_cache[ip]

    _campaign_tracker_copy = dict(_campaign_tracker)
    for ip, data in _campaign_tracker_copy.items():
        if now - data.get("last_seen", 0) > 86400:
            del _campaign_tracker[ip]

    if stale_ips:
        _save_incident_cache()


class IncidentManager:
    """
    High-level incident manager interface for external callers.
    Wraps the module-level functions for OOP-style usage.
    """

    def _calculate_incident_severity(self, alerts: List[dict]) -> str:
        """Calculate incident severity from a list of alerts."""
        if not alerts:
            return "low"

        severities = [a.get("severity", "low") for a in alerts]
        all_tactics = []
        for a in alerts:
            all_tactics.extend(a.get("mitre_tactics", []))

        high_risk = {
            "Exfiltration",
            "Impact",
            "Command and Control",
            "Initial Access",
            "Execution",
            "Credential Access",
            "Lateral Movement",
        }
        tactic_risk = sum(1 for t in all_tactics if t in high_risk)

        if "critical" in severities or tactic_risk >= 2:
            return "critical"
        if "high" in severities or tactic_risk >= 1:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"

    def _build_incident_tags(self, alerts: List[dict]) -> List[str]:
        """Build tags from a list of alerts."""
        tags = set()
        sources = set()
        tactics = set()
        cloud = set()
        for alert in alerts:
            src = alert.get("source")
            if src:
                sources.add(src)
            for t in alert.get("mitre_tactics", []):
                tactics.add(t.lower().replace(" ", "-"))
            cp = alert.get("cloud_provider")
            if cp:
                cloud.add(cp.lower())
        for s in sources:
            tags.add(f"source:{s}")
        for t in tactics:
            tags.add(f"mitre:{t}")
        for c in cloud:
            tags.add(f"cloud:{c}")
        if len(sources) > 1:
            tags.add("multi-source")
        return list(tags)

    def _detect_kill_chain_progression(self, alerts: List[dict]) -> Dict[str, Any]:
        """Detect kill chain progression from alerts."""
        all_tactics = []
        for alert in alerts:
            all_tactics.extend(alert.get("mitre_tactics", []))
        if len(all_tactics) <= 1:
            return {}
        result = {}
        for t in all_tactics:
            result[t.lower().replace(" ", "-")] = True
        return result

    def get_stats(self) -> dict:
        """Get incident manager stats."""
        _load_incident_cache()
        return {
            "created": len(_local_incidents),
            "linked_alerts": len(_processed_alerts),
            "tracked_ips": len(_incident_cache),
            "ips_with_incidents": sum(
                1 for d in _incident_cache.values() if d.get("incident_id")
            ),
            "ips_waiting": sum(
                1 for d in _incident_cache.values() if not d.get("incident_id")
            ),
        }

    async def process_alert(self, alert_id: str, alert_payload: dict, local_alert_id: Optional[str] = None) -> dict:
        return await process_alert(upstream_alert_id=alert_id, alert_payload=alert_payload, local_alert_id=local_alert_id)

    async def run_correlation_cycle(self) -> int:
        return await run_correlation_cycle()

    def get_cache_stats(self) -> dict:
        _load_incident_cache()
        return {
            "tracked_ips": len(_incident_cache),
            "processed_alerts": len(_processed_alerts),
            "local_incidents": len(_local_incidents),
            "ips_with_incidents": sum(
                1 for d in _incident_cache.values() if d.get("incident_id")
            ),
            "ips_waiting": sum(
                1 for d in _incident_cache.values() if not d.get("incident_id")
            ),
        }


def get_correlation_stats() -> dict:
    """Get correlation stats for pipeline stats aggregation."""
    _load_incident_cache()
    return {
        "tracked_ips": len(_incident_cache),
        "processed_alerts": len(_processed_alerts),
        "local_incidents": len(_local_incidents),
        "ips_with_incidents": sum(
            1 for d in _incident_cache.values() if d.get("incident_id")
        ),
    }
