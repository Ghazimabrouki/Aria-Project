"""
Generic Alert Mapper.
Handles ANY unknown security source by extracting common fields.

This mapper serves as a fallback when source-specific mappers don't match.
It tries to extract common fields (IP, severity, title, etc.) from any format.
"""

import re
from typing import Any, Dict, Optional
from pipeline.mappers.severity import map_severity


# Common field name mappings across different security sources
FIELD_MAPPINGS = {
    "source_ip": [
        "source_ip", "src_ip", "src", "client_ip", "clientip",
        "agent.ip", "event.src_ip", "srcaddr", "source_address",
        "origin", "clientAddress", "remote_ip", "attacker_ip",
        "actor.ip_address", "actor.ip", "source.ip", "srcaddr",
    ],
    "dest_ip": [
        "dest_ip", "dst_ip", "dst", "server_ip", "serverip",
        "agent.destination.ip", "event.dest_ip", "dstaddr", "dest_address",
        "target_ip", "victim_ip", "target", "destination",
    ],
    "hostname": [
        "hostname", "host", "host.name", "agent.name", "event.hostname",
        "output_fields.hostname", "output_fields.host", "output_fields.aria_asset_name",
        "computer_name", "machine_name", "target_host", "dest_host",
        "server_name", "instance", "instance_id",
    ],
    "username": [
        "username", "user", "user.name", "user_id", "account",
        "actor.user_name", "actor.username", "principal.name", "subject.name",
        "src_user", "user_account", "effective_user", "owner", "initiated_by",
    ],
    "severity": [
        "severity", "level", "priority", "event.severity",
        "risk_score", "score", "threat_level", "alert_level",
        "criticality", "importance",
    ],
    "title": [
        "title", "name", "rule", "event.name", "alert", "rule_name",
        "description", "message", "summary", "alert_title",
        "event_title", "notification", "rule_description",
    ],
    "description": [
        "description", "message", "details", "full_log", "event.description",
        "log", "info", "details", "raw_message", "event_message",
        "content", "text", "body",
    ],
    "timestamp": [
        "@timestamp", "timestamp", "time", "event.created",
        "event_time", "eventTime", "date", "datetime",
        "generated_at", "created_at", "modified_at",
    ],
    "action": [
        "action", "event.action", "operation", "event_type",
        "category", "type", "event_category", "rule_type",
    ],
    "protocol": [
        "protocol", "proto", "network.protocol", "event.protocol",
        "transport", "ip_protocol",
    ],
    "port": [
        "src_port", "source_port", "event.src_port",
        "dest_port", "destination_port", "event.dest_port",
        "port", "target_port",
    ],
}


def _extract_field(doc: Dict[str, Any], field_list: list) -> Optional[str]:
    """Try to extract a field from multiple possible names."""
    for field_name in field_list:
        # Check direct field
        if field_name in doc:
            value = doc[field_name]
            if value:
                if isinstance(value, str):
                    return value
                elif isinstance(value, (int, float, bool)):
                    return str(value)
        
        # Check nested (dot notation)
        parts = field_name.split(".")
        if len(parts) > 1:
            current = doc
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    break
            else:
                if current:
                    if isinstance(current, str):
                        return current
                    elif isinstance(current, (int, float, bool)):
                        return str(current)
        
        # Check nested dict directly (e.g., "host": {"hostname": "x"})
        for key in doc:
            if isinstance(doc[key], dict):
                if field_name in doc[key]:
                    value = doc[key][field_name]
                    if value:
                        if isinstance(value, str):
                            return value
                        elif isinstance(value, (int, float, bool)):
                            return str(value)
        
        # Special handling for known nested structures (CrowdStrike, etc.)
        # e.g., "actor": {"user_name": "root", "ip_address": "1.2.3.4"}
        for key in doc:
            if isinstance(doc[key], dict):
                nested = doc[key]
                # Try to find field in any level of nested dict
                for nested_key, nested_val in nested.items():
                    if nested_key == field_name and nested_val:
                        if isinstance(nested_val, str):
                            return nested_val
                        elif isinstance(nested_val, (int, float, bool)):
                            return str(nested_val)
    
    return None


def _extract_ips(text: str) -> list:
    """Extract IP addresses from text."""
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    return ip_pattern.findall(text)


def _extract_severity(doc: Dict[str, Any]) -> str:
    """Extract and normalize severity."""
    severity = _extract_field(doc, FIELD_MAPPINGS["severity"])
    if not severity:
        return "medium"
    
    severity_lower = severity.lower()
    
    # Map common severity values
    severity_map = {
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "error": "high",
        "warn": "medium",
        "warning": "medium",
        "medium": "medium",
        "info": "low",
        "information": "low",
        "low": "low",
        "debug": "low",
        "trace": "low",
    }
    
    return severity_map.get(severity_lower, "medium")


def map_generic_alert(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map any alert document to OpenSOAR format.
    
    Tries to extract common fields regardless of the source format.
    Falls back gracefully when fields are not available.
    """
    # Extract all available fields
    source_ip = _extract_field(doc, FIELD_MAPPINGS["source_ip"])
    dest_ip = _extract_field(doc, FIELD_MAPPINGS["dest_ip"])
    hostname = _extract_field(doc, FIELD_MAPPINGS["hostname"])
    username = _extract_field(doc, FIELD_MAPPINGS["username"])
    title = _extract_field(doc, FIELD_MAPPINGS["title"])
    description = _extract_field(doc, FIELD_MAPPINGS["description"])
    timestamp = _extract_field(doc, FIELD_MAPPINGS["timestamp"])
    action = _extract_field(doc, FIELD_MAPPINGS["action"])
    protocol = _extract_field(doc, FIELD_MAPPINGS["protocol"])
    
    # Extract port info - check nested structures
    src_port = doc.get("src_port") or doc.get("source_port")
    if not src_port and "event" in doc and isinstance(doc["event"], dict):
        src_port = doc["event"].get("src_port")
    if not src_port and "network" in doc and isinstance(doc["network"], dict):
        src_port = doc["network"].get("source_port")
        
    dest_port = doc.get("dest_port") or doc.get("destination_port")
    if not dest_port and "event" in doc and isinstance(doc["event"], dict):
        dest_port = doc["event"].get("dest_port")
    if not dest_port and "network" in doc and isinstance(doc["network"], dict):
        dest_port = doc["network"].get("destination_port")
    
    # Get severity - handle both string and numeric
    raw_severity = None
    
    # Try to get numeric severity first
    for field_name in FIELD_MAPPINGS["severity"]:
        if field_name in doc:
            raw_severity = doc[field_name]
            break
    
    # If not found as direct field, try extraction
    if not raw_severity:
        raw_severity = _extract_field(doc, FIELD_MAPPINGS["severity"])
    
    severity = map_severity(_normalize_severity(raw_severity), "generic")
    
    # Build title from available info
    final_title = None
    
    # Priority 1: direct title field
    if title and isinstance(title, str):
        final_title = title
    
    # Priority 2: action field
    if not final_title and action and isinstance(action, str):
        final_title = action
    
    # Priority 3: event.name
    if not final_title:
        event = doc.get("event")
        if isinstance(event, dict):
            final_title = event.get("name")
    
    # Priority 4: service.action.actionType (AWS GuardDuty format)
    if not final_title:
        service = doc.get("service")
        if isinstance(service, dict):
            act = service.get("action")
            if isinstance(act, dict):
                at = act.get("actionType")
                # Handle different structures
                if isinstance(at, str):
                    final_title = at
                elif isinstance(at, dict):
                    # actionType might be nested - try to extract string value
                    if "name" in at:
                        final_title = at.get("name")
                # Also check for 'description' as fallback title
                if not final_title:
                    desc = act.get("description")
                    if isinstance(desc, str):
                        final_title = desc
    
    # Priority 5: other title-like fields
    if not final_title:
        for key in ["summary", "alert", "notification", "finding"]:
            if key in doc:
                val = doc[key]
                if isinstance(val, str):
                    final_title = val
                    break
                elif isinstance(val, dict):
                    tv = val.get("title") or val.get("name")
                    if tv and isinstance(tv, str):
                        final_title = tv
                    break
    
    # Final title validation - must be clean string
    final_title = str(final_title) if final_title and isinstance(final_title, str) and '{' not in final_title else "Generic Security Alert"
    final_title = final_title[:200]
    
    # Build description from available info
    if not description:
        # Try to get from event.description or service.action.description
        event = doc.get("event")
        if isinstance(event, dict):
            description = event.get("description")
        if not description:
            service = doc.get("service")
            if isinstance(service, dict):
                action_data = service.get("action")
                if isinstance(action_data, dict):
                    description = action_data.get("description")
        
        # If still no description, build from other fields
        if not description:
            description_parts = []
            if source_ip:
                description_parts.append(f"Source: {source_ip}")
            if dest_ip:
                description_parts.append(f"Destination: {dest_ip}")
            if hostname:
                description_parts.append(f"Host: {hostname}")
            if username:
                description_parts.append(f"User: {username}")
            if protocol:
                description_parts.append(f"Protocol: {protocol}")
            description = " | ".join(description_parts) if description_parts else title
    
    # Ensure description is a string
    if not description or not isinstance(description, str):
        description = final_title
    else:
        description = description[:2000]
    
    # Try to detect source from document structure
    source = "generic"
    doc_str = str(doc).lower()[:300]  # Check first 300 chars
    if "wazuh" in doc_str:
        source = "wazuh"
    elif "falco" in doc_str:
        source = "falco"
    elif "suricata" in doc_str:
        source = "suricata"
    elif "crowdstrike" in doc_str or "falcon" in doc_str:
        source = "crowdstrike"
    elif "aws" in doc_str or "guardduty" in doc_str:
        source = "aws_guardduty"
    elif "azure" in doc_str or "sentinel" in doc_str:
        source = "azure_sentinel"
    elif "google" in doc_str or "chronicle" in doc_str:
        source = "google_chronicle"
    elif "qualys" in doc_str or " Nessus" in doc_str:
        source = "qualys"
    
    # Build the mapped alert
    mapped = {
        "source": source,
        "source_id": doc.get("_id") or doc.get("id") or "",
        "title": final_title,
        "description": description,
        "severity": severity,
        "status": "new",
        "source_ip": source_ip or "",
        "dest_ip": dest_ip or "",
        "hostname": hostname or "",
        "username": username or "",
        "timestamp": timestamp or "",
        "action": action or "",
        "protocol": protocol or "",
    }
    
    # Add port info if available
    if src_port:
        mapped["src_port"] = str(src_port)
    if dest_port:
        mapped["dest_port"] = str(dest_port)
    
    # Add asset_id_hint for multi-server resolution
    if hostname:
        mapped["asset_id_hint"] = hostname
    
    # Add any raw payload for reference
    if doc:
        # Store a cleaned version (avoid huge payloads)
        cleaned = {k: v for k, v in doc.items() if isinstance(v, (str, int, float, bool))}
        if len(str(cleaned)) < 10000:
            mapped["raw_payload"] = cleaned
    
    return mapped


def _normalize_severity(severity: Any) -> int:
    """Convert severity string/number to level number (for map_severity).
    
    map_severity expects: 0-3=low, 4-6=medium, 7-9=high, 10+=critical
    """
    if not severity:
        return 3  # default medium
    
    # Handle numeric severity (CrowdStrike uses 1-100, AWS uses 0-10)
    if isinstance(severity, (int, float)):
        num = int(severity)
        
        # CrowdStrike: 1-100 (85+=critical, 70-84=high, 40-69=medium, <40=low)
        if num >= 85:
            return 10  # critical
        elif num >= 70:
            return 7   # high
        elif num >= 40:
            return 4   # medium
        else:
            return 2    # low
    
    severity_lower = str(severity).lower()
    
    severity_levels = {
        "critical": 10,
        "crit": 10,
        "high": 7,
        "error": 7,
        "medium": 4,
        "warn": 4,
        "warning": 4,
        "low": 2,
        "info": 1,
        "information": 1,
        "debug": 0,
    }
    
    return severity_levels.get(severity_lower, 3)