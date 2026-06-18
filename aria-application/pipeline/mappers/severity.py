"""
Severity mapping utilities for different security sources.
Maps source-specific severity levels to OpenSOAR standard (low, medium, high, critical).
"""

from typing import Any


def map_severity(level: Any, source: str) -> str:
    """
    Map source-specific severity to OpenSOAR standard.
    
    Expected levels: 0-3=low, 4-6=medium, 7-9=high, 10+=critical
    
    Args:
        level: The severity level from the source (int, str, etc.)
        source: The source type (wazuh, falco, suricata, filebeat)
    
    Returns:
        OpenSOAR severity: low, medium, high, or critical
    """
    try:
        lvl = int(level) if level else 0
    except (ValueError, TypeError):
        lvl = 0
    
    # Direct mapping using new range
    if source == "wazuh":
        return _map_wazuh_severity(lvl)
    elif source == "falco":
        return _map_falco_severity(level)
    elif source == "suricata":
        return _map_suricata_severity(lvl)
    else:
        return _map_default_severity(lvl)


def _map_wazuh_severity(level: int) -> str:
    """Wazuh levels: 1-15"""
    if level >= 10:
        return "critical"
    elif level >= 7:
        return "high"
    elif level >= 4:
        return "medium"
    else:
        return "low"


def _map_falco_severity(priority: Any) -> str:
    """Falco priorities: EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, INFORMATIONAL, DEBUG"""
    priority_map = {
        "emergency": "critical",
        "alert": "critical",
        "critical": "critical",
        "error": "high",
        "warning": "medium",
        "notice": "medium",
        "info": "low",
        "informational": "low",
        "debug": "low",
    }
    return priority_map.get(str(priority).lower(), "medium")


def _map_suricata_severity(severity: int) -> str:
    """Suricata severity: 1=low, 2=medium, 3=high, 4=critical"""
    suricata_severity_map = {
        1: "low",
        2: "medium",
        3: "high",
        4: "critical",
    }
    return suricata_severity_map.get(severity, "medium")


def _map_default_severity(level: int) -> str:
    """Default mapping for unknown sources - uses 0-10+ scale"""
    if level >= 10:
        return "critical"
    elif level >= 7:
        return "high"
    elif level >= 4:
        return "medium"
    else:
        return "low"
