"""
Campaign Detection & Multi-Signal Correlation Engine.
Groups related alerts from multiple sources (Wazuh + Suricata + Falco) into campaigns.
Tracks per-IP activity across time windows and detects attack patterns.
"""

import time
import structlog
from typing import Dict, Any, List, Optional
from collections import defaultdict

logger = structlog.get_logger()

# Campaign tracking by multiple dimensions
_campaign_tracker: Dict[str, Dict[str, Any]] = {}
_dest_ip_tracker: Dict[str, Dict[str, Any]] = {}
_username_tracker: Dict[str, Dict[str, Any]] = {}
_hostname_tracker: Dict[str, Dict[str, Any]] = {}

# Campaign TTL: 24 hours
CAMPAIGN_TTL = 86400

# Minimum alerts to consider a campaign
MIN_ALERTS_FOR_CAMPAIGN = 3

# Known campaign patterns - more precise matching
_CAMPAIGN_PATTERNS = {
    "ssh_brute_force": {
        # Must have actual authentication failure evidence
        "keywords": ["authentication failed", "login failed", "failed password", "invalid user", "pam_unix", "sshd: authentication failure", "max authentication attempts reached"],
        "sources": ["wazuh", "suricata"],
        "description": "SSH Brute Force Attack",
    },
    "port_scan": {
        # Must have actual scanning evidence, not just detection of probe
        "keywords": ["nmap", "zmap", "masscan", "sipvicious", "friendly-scanner", "port scan", "horizontal portscan"],
        "sources": ["suricata"],
        "description": "Port/Service Scanning",
    },
    "threat_intel_hit": {
        "keywords": ["drop list", "block listed", "cins active", "spamhaus", "compromised host", "dshield"],
        "sources": ["suricata"],
        "description": "Threat Intelligence Match",
    },
    "web_attack": {
        # Must have actual web attack evidence
        "keywords": ["sql injection", "xss attempt", "csrf attempt", "directory traversal attempt", "lfi attempt", "rfi attempt", "web shell", "webshell"],
        "sources": ["suricata", "wazuh"],
        "description": "Web Application Attack",
    },
}


def _cleanup_old_campaigns() -> None:
    """Remove expired campaign entries."""
    now = time.time()
    for tracker in [_campaign_tracker, _dest_ip_tracker, _username_tracker, _hostname_tracker]:
        expired = [key for key, data in tracker.items() if now - data.get("last_seen", 0) > CAMPAIGN_TTL]
        for key in expired:
            del tracker[key]


def _detect_campaign_type(alerts: List[Dict[str, Any]]) -> Optional[str]:
    """Detect the type of campaign based on alert patterns."""
    titles = " ".join(a.get("title", "").lower() for a in alerts)
    sources = set(a.get("source", "") for a in alerts)
    
    best_match = None
    best_score = 0
    
    for campaign_type, pattern in _CAMPAIGN_PATTERNS.items():
        score = 0
        # Check keyword matches
        for keyword in pattern["keywords"]:
            if keyword in titles:
                score += 1
        # Check source overlap
        if sources & set(pattern["sources"]):
            score += 2
        if score > best_score:
            best_score = score
            best_match = campaign_type
    
    if best_match and best_score >= 2:
        return best_match
    return None


def track_alert(alert: Dict[str, Any]) -> Optional[str]:
    """Track an alert and detect if it's part of a campaign.
    
    Returns campaign context string if alert is part of a campaign, None otherwise.
    Tracks by: source_ip, dest_ip, username, hostname
    """
    src_ip = alert.get("source_ip", "")
    dest_ip = alert.get("dest_ip", "")
    username = alert.get("username", "")
    hostname = alert.get("hostname", "")
    
    if not src_ip and not dest_ip and not username and not hostname:
        return None
    
    _cleanup_old_campaigns()
    
    now = time.time()
    contexts = []
    
    # Track by source_ip
    if src_ip:
        context = _track_dimension(src_ip, _campaign_tracker, alert, now, "source_ip")
        if context:
            contexts.append(context)
    
    # Track by dest_ip
    if dest_ip:
        context = _track_dimension(dest_ip, _dest_ip_tracker, alert, now, "dest_ip")
        if context:
            contexts.append(context)
    
    # Track by username
    if username:
        context = _track_dimension(username, _username_tracker, alert, now, "username")
        if context:
            contexts.append(context)
    
    # Track by hostname
    if hostname:
        context = _track_dimension(hostname, _hostname_tracker, alert, now, "hostname")
        if context:
            contexts.append(context)
    
    if contexts:
        return " | ".join(contexts)
    return None


def _track_dimension(key: str, tracker: Dict[str, Dict[str, Any]], alert: Dict[str, Any], now: float, dimension: str) -> Optional[str]:
    """Track alert by a specific dimension (ip, username, hostname)."""
    if key not in tracker:
        tracker[key] = {
            "alerts": [],
            "sources": set(),
            "titles": set(),
            "first_seen": now,
            "last_seen": now,
            "severity_counts": defaultdict(int),
        }
    
    track = tracker[key]
    track["alerts"].append(alert)
    track["sources"].add(alert.get("source", "unknown"))
    track["titles"].add(alert.get("title", ""))
    track["last_seen"] = now
    
    sev = alert.get("severity", "low")
    track["severity_counts"][sev] += 1
    
    if len(track["alerts"]) > 100:
        track["alerts"] = track["alerts"][-100:]
    
    total_alerts = len(track["alerts"])
    unique_sources = len(track["sources"])
    unique_titles = len(track["titles"])
    
    is_campaign = (
        total_alerts >= MIN_ALERTS_FOR_CAMPAIGN or
        (unique_sources >= 2 and total_alerts >= 2)
    )
    
    if is_campaign:
        campaign_type = _detect_campaign_type(track["alerts"])
        campaign_name = _CAMPAIGN_PATTERNS.get(campaign_type, {}).get("description", "Suspicious Activity")
        
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        highest_sev = max(track["severity_counts"].keys(), key=lambda s: sev_order.get(s, 0))
        
        time_span = now - track["first_seen"]
        if time_span < 3600:
            time_str = f"{int(time_span / 60)}m"
        elif time_span < 86400:
            time_str = f"{int(time_span / 3600)}h"
        else:
            time_str = f"{int(time_span / 86400)}d"
        
        return (
            f"{campaign_name} via {dimension}={key} "
            f"({total_alerts} alerts, {unique_sources} sources, {time_str} window)"
        )
    
    return None
