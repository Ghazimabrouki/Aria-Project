"""
Dynamic Noise Learning Module.
Auto-identifies noise patterns by analyzing alert frequency, severity, and value.
Generates Sigma-like rules automatically based on observed patterns.
"""

import json
import time
import structlog
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import defaultdict

logger = structlog.get_logger()

# Storage for noise learning data
_NOISE_DATA_FILE = Path("data/artifacts/noise_data.json")
_NOISE_RULES_FILE = Path("data/artifacts/auto_noise_rules.json")

# Thresholds for auto-detection
MIN_ALERT_COUNT = 10  # Minimum alerts before considering as noise
MAX_SEVERITY_FOR_NOISE = "medium"  # Alerts above this severity won't be auto-flagged
TIME_WINDOW = 3600  # 1 hour window for analysis

# Severity order
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# In-memory tracking
_alert_tracker: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
    "count": 0,
    "severities": defaultdict(int),
    "first_seen": 0,
    "last_seen": 0,
    "sources": set(),
    "ips": set(),
})


def _load_noise_data() -> Dict[str, Any]:
    """Load existing noise learning data."""
    if _NOISE_DATA_FILE.exists():
        try:
            with open(_NOISE_DATA_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_noise_data(data: Dict[str, Any]) -> None:
    """Save noise learning data."""
    try:
        _NOISE_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_NOISE_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.warning("noise_data_save_failed", error=str(e))


def _load_auto_rules() -> List[Dict[str, Any]]:
    """Load auto-generated noise rules."""
    if _NOISE_RULES_FILE.exists():
        try:
            with open(_NOISE_RULES_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _save_auto_rules(rules: List[Dict[str, Any]]) -> None:
    """Save auto-generated noise rules."""
    try:
        _NOISE_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_NOISE_RULES_FILE, 'w') as f:
            json.dump(rules, f, indent=2)
    except Exception as e:
        logger.warning("auto_rules_save_failed", error=str(e))


def track_alert_for_noise(alert: Dict[str, Any]) -> None:
    """Track an alert for noise analysis."""
    title = alert.get("title", "")
    source = alert.get("source", "")
    severity = alert.get("severity", "low")
    src_ip = alert.get("source_ip", "")
    
    if not title:
        return
    
    key = f"{source}|{title}"
    tracker = _alert_tracker[key]
    
    now = time.time()
    tracker["count"] += 1
    tracker["severities"][severity] += 1
    tracker["last_seen"] = now
    
    if tracker["first_seen"] == 0:
        tracker["first_seen"] = now
    
    tracker["sources"].add(source)
    if src_ip:
        tracker["ips"].add(src_ip)


def analyze_and_generate_rules() -> List[Dict[str, Any]]:
    """Analyze tracked alerts and generate noise rules.
    
    Returns list of auto-generated noise rules.
    """
    now = time.time()
    auto_rules = []
    
    for key, data in _alert_tracker.items():
        # Skip if not enough data
        if data["count"] < MIN_ALERT_COUNT:
            continue
        
        # Skip if time window not met
        if now - data["first_seen"] < TIME_WINDOW:
            continue
        
        # Check if mostly low/medium severity
        high_sev_count = sum(
            count for sev, count in data["severities"].items()
            if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(MAX_SEVERITY_FOR_NOISE, 0)
        )
        
        # If most alerts are low/medium severity, consider as noise
        if high_sev_count / data["count"] < 0.2:  # Less than 20% high/critical
            source, title = key.split("|", 1)
            
            # Generate noise rule
            rule = {
                "type": "auto_generated",
                "source": source,
                "pattern": title[:100],
                "match_type": "contains",
                "confidence": min(1.0, data["count"] / 50),
                "alert_count": data["count"],
                "severity_distribution": dict(data["severities"]),
                "unique_ips": len(data["ips"]),
                "created_at": now,
            }
            auto_rules.append(rule)
    
    # Sort by confidence (highest first)
    auto_rules.sort(key=lambda x: x["confidence"], reverse=True)
    
    # Save rules
    if auto_rules:
        _save_auto_rules(auto_rules)
        logger.info("auto_noise_rules_generated", count=len(auto_rules))
    
    return auto_rules


def is_auto_noise(alert: Dict[str, Any]) -> bool:
    """Check if alert matches auto-generated noise rules."""
    title = alert.get("title", "")
    source = alert.get("source", "")
    
    if not title:
        return False
    
    auto_rules = _load_auto_rules()
    
    for rule in auto_rules:
        if rule.get("source") != source:
            continue
        
        pattern = rule.get("pattern", "")
        match_type = rule.get("match_type", "contains")
        
        if match_type == "contains" and pattern.lower() in title.lower():
            logger.debug("auto_noise_matched", rule=pattern[:50], source=source)
            return True
    
    return False


def get_noise_stats() -> Dict[str, Any]:
    """Get noise learning statistics."""
    total_tracked = sum(d["count"] for d in _alert_tracker.values())
    auto_rules = _load_auto_rules()
    
    return {
        "total_alerts_tracked": total_tracked,
        "unique_patterns": len(_alert_tracker),
        "auto_rules_generated": len(auto_rules),
        "top_patterns": [
            {"pattern": k, "count": v["count"], "severity": dict(v["severities"])}
            for k, v in sorted(
                _alert_tracker.items(),
                key=lambda x: x[1]["count"],
                reverse=True
            )[:10]
        ],
    }
