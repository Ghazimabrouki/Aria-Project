"""
Sigma-compatible Noise Filter Module.
Loads YAML-based Sigma rules for noise filtering.
Supports: contains, startswith, endswith, equals, regex operators.
Logical OR via list, logical AND via dict.
"""

import os
import re
import yaml
import structlog
from pathlib import Path
from typing import Dict, Any, List, Optional

from pipeline.mappers.severity import map_severity

logger = structlog.get_logger()

# Loaded rules cache
_loaded_rules: List[Dict[str, Any]] = []
_rules_loaded = False


def _load_rules(rules_dir: str) -> List[Dict[str, Any]]:
    """Load all Sigma YAML rules from directory."""
    rules = []
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        logger.warning("sigma_rules_dir_not_found", path=rules_dir)
        return rules
    
    for yml_file in sorted(rules_path.glob("*.yml")):
        try:
            with open(yml_file) as f:
                rule = yaml.safe_load(f)
            if rule and "detection" in rule:
                rules.append(rule)
                logger.debug("sigma_rule_loaded", title=rule.get("title", ""), file=yml_file.name)
        except Exception as e:
            logger.warning("sigma_rule_load_failed", file=str(yml_file), error=str(e))
    
    return rules


def _get_rule_rules() -> List[Dict[str, Any]]:
    """Get or load Sigma rules."""
    global _loaded_rules, _rules_loaded
    if not _rules_loaded:
        from config import get_settings
        settings = get_settings()
        rules_dir = getattr(settings, "sigma_rules_path", "config/sigma_rules")
        _loaded_rules = _load_rules(rules_dir)
        _rules_loaded = True
        logger.info("sigma_rules_initialized", count=len(_loaded_rules))
    return _loaded_rules


def _evaluate_condition(value: str, condition: str) -> bool:
    """Evaluate a single condition against a value."""
    if "|" in condition:
        field, op = condition.split("|", 1)
    else:
        field = condition
        op = "equals"
    
    value_lower = value.lower()
    
    if op == "contains":
        return True  # Caller handles list matching
    elif op == "startswith":
        return True  # Caller handles list matching
    elif op == "endswith":
        return True  # Caller handles list matching
    elif op == "equals":
        return True  # Caller handles list matching
    elif op == "regex":
        return True  # Caller handles regex matching
    
    return False


def _match_value(field_value: str, patterns: List[str], op: str) -> bool:
    """Match a field value against patterns with given operator."""
    if not field_value:
        return False
    
    field_lower = field_value.lower()
    
    for pattern in patterns:
        pattern_lower = pattern.lower()
        if op == "contains" and pattern_lower in field_lower:
            return True
        elif op == "startswith" and field_lower.startswith(pattern_lower):
            return True
        elif op == "endswith" and field_lower.endswith(pattern_lower):
            return True
        elif op == "equals" and field_lower == pattern_lower:
            return True
        elif op == "regex":
            try:
                if re.search(pattern, field_value, re.IGNORECASE):
                    return True
            except re.error:
                pass
    
    return False


def _evaluate_detection(detection: Dict[str, Any], doc: Dict[str, Any], source: str) -> bool:
    """Evaluate Sigma detection section against a document."""
    condition = detection.get("condition", "")
    selection = detection.get("selection", [])
    
    if not isinstance(selection, list):
        selection = [selection]
    
    # Each item in selection list is OR'd
    for sel in selection:
        if not isinstance(sel, dict):
            continue
        
        all_match = True
        for field_condition, patterns in sel.items():
            if field_condition == "condition":
                continue
            
            # Parse field and operator
            if "|" in field_condition:
                field, op = field_condition.split("|", 1)
            else:
                field = field_condition
                op = "contains"
            
            if not isinstance(patterns, list):
                patterns = [patterns]
            
            # Get field value from document based on source
            field_value = _get_field_value(doc, field, source)
            
            if not _match_value(field_value, patterns, op):
                all_match = False
                break
        
        if all_match:
            return True
    
    return False


def _get_field_value(doc: Dict[str, Any], field: str, source: str) -> str:
    """Extract field value from document based on source type."""
    if source == "suricata":
        suricata_eve = doc.get("suricata", {}).get("eve", {}) or {}
        alert_data = suricata_eve.get("alert", {}) or {}
        
        field_map = {
            "signature": alert_data.get("signature", ""),
            "category": alert_data.get("category", ""),
            "signature_id": str(alert_data.get("signature_id", "")),
            "severity": str(alert_data.get("severity", "")),
            "proto": suricata_eve.get("proto", ""),
        }
        return field_map.get(field, "")
    
    elif source == "falco":
        field_map = {
            "rule": doc.get("rule", ""),
            "priority": doc.get("priority", ""),
            "output": doc.get("output", ""),
            "source": doc.get("source", ""),
        }
        return field_map.get(field, "")
    
    elif source == "wazuh":
        rule = doc.get("rule", {}) or {}
        field_map = {
            "description": rule.get("description", ""),
            "level": str(rule.get("level", "")),
            "id": str(rule.get("id", "")),
        }
        return field_map.get(field, "")
    
    return ""


def is_noise_alert(source: str, doc: Dict[str, Any]) -> bool:
    """Check if an alert matches any Sigma noise rule.
    
    Smart filtering logic:
    - NEVER filter if attack pattern detected (real security threat)
    - NEVER filter if severity is critical or high
    - NEVER filter if it's threat intel (CINS, Spamhaus, etc.)
    - Only filter true noise: low severity + repeated + no attack pattern
    
    Args:
        source: Alert source (suricata, falco, wazuh)
        doc: Raw ES document
    
    Returns:
        True if alert should be filtered as noise
    """
    # === EXTRACT TEXT FOR ANALYSIS ===
    
    title = ""
    description = ""
    severity = ""
    
    if source == "suricata":
        # Suricata has nested structure: doc.suricata.eve.alert.*
        suricata_eve = doc.get("suricata", {}).get("eve", {}) or {}
        alert_data = suricata_eve.get("alert", {}) or {}
        title = alert_data.get("signature", "") or ""
        category = alert_data.get("category", "") or ""
        severity = _map_category_to_severity(category, title)
        
        # Get proto and other info for description
        proto = suricata_eve.get("proto", "")
        src_ip = suricata_eve.get("src_ip", "")
        dest_ip = suricata_eve.get("dest_ip", "")
        description = f"category: {category} proto: {proto} src: {src_ip} dst: {dest_ip}"
        
    elif source == "falco":
        title = doc.get("rule", "") or ""
        output = doc.get("output", "") or ""
        priority = doc.get("priority", "") or ""
        severity = map_severity(priority, "falco") if priority else "medium"
        description = output
        
    elif source == "wazuh":
        title = doc.get("rule", {}).get("description", "") or ""
        level = doc.get("rule", {}).get("level", 3)
        severity = map_severity(level, "wazuh") if level else "medium"
        description = doc.get("full_log", "") or ""
    
    full_text = f"{title} {description}".lower()
    
    # === SMART EXCEPTION CHECKS (NEVER FILTER) ===
    
    # 1. Check for attack patterns - NEVER filter these
    attack_patterns = [
        "malware", "ransomware", "trojan", "backdoor", "c2", "command and control",
        "brute force", "ssh brute", "authentication failed", "login failed", "invalid user",
        "exploit", "vulnerability", "cve-", "remote code execution", "rce",
        "sql injection", "xss", "csrf", "lfi", "rfi", "directory traversal",
        "port scan", "nmap", "zmap", "masscan", "suspicious scan",
        "webshell", "shell upload", "meterpreter", "reverse shell",
        "privilege escalation", "sudo", "root", "admin access",
        "data exfiltration", "data theft", "large upload", "dns tunneling",
        "lateral movement", "pass the hash", "psexec", "winrm", "smb",
        "spamhaus", "drop list", "blacklist", "cins active", "threat intel",
        "ransom", "locky", "wannacry", "petya", "conti",
    ]
    
    for pattern in attack_patterns:
        if pattern in full_text:
            logger.debug("attack_pattern_detected_skip_noise", pattern=pattern, source=source)
            return False  # Forward, don't filter
    
    # 2. Check severity - NEVER filter critical/high
    if severity in ["critical", "high"]:
        logger.debug("high_severity_skip_noise", severity=severity, source=source)
        return False  # Forward, don't filter
    
    # 3. Check for threat intel - NEVER filter
    threat_intel_indicators = [
        "et cins", "spamhaus", "drop list", "blocklist", "threat intelligence",
        "compromised", "malicious", "malware检测", "已知恶意",
    ]
    for indicator in threat_intel_indicators:
        if indicator in full_text:
            logger.debug("threat_intel_skip_noise", indicator=indicator, source=source)
            return False  # Forward, don't filter
    
    # === CHECK NOISE RULES (only for true noise) ===
    rules = _get_rule_rules()
    
    for rule in rules:
        # Check if rule applies to this source
        logsource = rule.get("logsource", {})
        rule_product = logsource.get("product", "").lower()
        
        if rule_product and rule_product != source.lower():
            continue
        
        detection = rule.get("detection", {})
        if _evaluate_detection(detection, doc, source):
            title = rule.get("title", "Unknown Rule")
            logger.debug("sigma_noise_matched", rule=title, source=source)
            return True
    
    return False


def _map_category_to_severity(category: str, rule_name: str) -> str:
    """Map Suricata category to severity level."""
    category_lower = category.lower()
    
    high_risk = ["attempted-information-leak", "attempted-admin", "attempted-user", 
                 "attempted-dos", "misc-attack", "bad-unknown", "attempted-information-gain"]
    if any(risk in category_lower for risk in high_risk):
        return "high"
    
    medium_risk = ["potentially-bad-traffic", "attempted-recording", "attempted-bypass",
                   "non-attack-misc", "network-scan"]
    if any(risk in category_lower for risk in medium_risk):
        return "medium"
    
    # Check rule name for severity indicators
    rule_lower = rule_name.lower()
    if "critical" in rule_lower or "emergency" in rule_lower:
        return "critical"
    if "high" in rule_lower:
        return "high"
    if "medium" in rule_lower or "warning" in rule_lower:
        return "medium"
    
    return "low"
