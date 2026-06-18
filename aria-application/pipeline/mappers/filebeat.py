"""
Filebeat alert mapper.
Maps Filebeat alert fields to OpenSOAR format.
Handles generic Filebeat alerts and Suricata alerts embedded in Filebeat.
"""

import re
from typing import Dict, Any, List, Optional
from pipeline.mappers.severity import map_severity
from pipeline.mappers.ip_extractor import extract_ips
from pipeline.mappers.suricata import map_suricata_alert


def map_filebeat_alert(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map Filebeat alert fields to OpenSOAR format.
    NOTE: Only Suricata events are sent. All other Filebeat events are skipped.
    """
    try:
        suricata_eve = doc.get("suricata", {}).get("eve", {})
        fileset_name = doc.get("fileset", {}).get("name", "")

        is_suricata_alert = (
            fileset_name == "eve" and
            suricata_eve.get("event_type") == "alert"
        )

        if not is_suricata_alert:
            raise ValueError(
                f"Filebeat event is not Suricata alert (fileset={fileset_name}). "
                "Only Suricata events are processed. Skipping."
            )

        return map_suricata_alert(doc)
        
    except Exception as e:
        import structlog
        logger = structlog.get_logger()
        logger.debug("filebeat_skip_non_suricata", error=str(e), fileset=doc.get("fileset", {}).get("name"))
        raise


def _extract_timestamp(doc: Dict[str, Any]) -> str:
    """Extract timestamp in ISO8601 format."""
    ts = doc.get("@timestamp") or doc.get("timestamp")
    if ts:
        ts_str = str(ts)
        if not ts_str.endswith("Z") and "+" not in ts_str and "-" not in ts_str[-6:]:
            ts_str = ts_str + "Z"
        elif "+" in ts_str and not ts_str.endswith("Z"):
            ts_str = ts_str.replace("+00:00", "Z").replace("+0000", "Z")
        return ts_str
    return ""


def _map_generic_filebeat(doc: Dict[str, Any], rule: Dict, event: Dict) -> Dict[str, Any]:
    rule_name = (
        rule.get("name") or
        rule.get("description") or
        doc.get("rule_name") or
        event.get("action") or
        event.get("category") or
        doc.get("message", "")
    )
    rule_level = rule.get("level", 3)

    if not rule_name:
        original = event.get("original", "")
        if original and isinstance(original, str):
            try:
                parsed = __import__("json").loads(original)
                rule_name = (
                    parsed.get("rule", {}).get("name") or
                    parsed.get("message") or
                    parsed.get("event", {}).get("action") or
                    ""
                )
            except (ValueError, TypeError, AttributeError):
                pass

    if not rule_name:
        rule_name = doc.get("message", "Untitled Alert")[:100]

    title = rule_name
    if not rule.get("name") and rule_name:
        title = re.sub(r'^\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s*', '', rule_name)

    src_ip, dst_ip = extract_ips(doc, "filebeat")
    hostname = _extract_hostname(doc)

    source_tags = [t for t in doc.get("tags", []) if t and isinstance(t, str)]

    iocs = _build_iocs(src_ip, dst_ip, doc)
    observables = _build_observables(src_ip, dst_ip, doc)
    metadata = _build_metadata(doc)
    event_time = _extract_timestamp(doc)

    return {
        "source": "filebeat",
        "source_id": doc.get("_id", ""),
        "title": title[:200] if title else "Untitled Alert",
        "description": doc.get("message", title)[:2000],
        "severity": map_severity(rule_level, "filebeat"),
        "status": "new",
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "hostname": hostname,
        "rule_name": title[:100] if title else "",
        "tags": source_tags,
        "iocs": iocs,
        "event_time": event_time,
        "observables": observables,
        "metadata": metadata,
    }


def _extract_hostname(doc: Dict[str, Any]) -> str:
    host = doc.get("host", {})
    if isinstance(host, dict):
        return host.get("name", "")
    elif host:
        return str(host)
    return ""


def _build_iocs(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    doc: Dict,
) -> Dict:
    """Extract IOCs from filebeat doc."""
    iocs: Dict[str, list] = {}

    ips = list(filter(None, set([src_ip, dst_ip])))
    if ips:
        iocs["ip"] = ips

    user_agent = doc.get("user_agent", {})
    if isinstance(user_agent, dict):
        ua = user_agent.get("original")
        if ua:
            iocs["user_agent"] = [ua]

    url_data = doc.get("url", {})
    if isinstance(url_data, dict):
        full_url = url_data.get("full") or url_data.get("original")
        if full_url:
            iocs["url"] = [full_url]
        domain = url_data.get("domain")
        if domain:
            iocs["domain"] = [domain]

    return iocs


def _build_observables(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    doc: Dict,
) -> List[Dict[str, Any]]:
    """Build structured observables array."""
    observables = []
    
    if src_ip:
        observables.append({"type": "ip", "value": src_ip, "direction": "src"})
    if dst_ip:
        observables.append({"type": "ip", "value": dst_ip, "direction": "dst"})
    
    url_data = doc.get("url", {})
    if isinstance(url_data, dict):
        domain = url_data.get("domain")
        if domain:
            observables.append({"type": "domain", "value": domain})
    
    return observables


def _build_metadata(doc: Dict) -> Dict[str, Any]:
    """Build filebeat-specific metadata."""
    metadata = {}
    
    agent = doc.get("agent", {})
    if agent:
        metadata["agent_hostname"] = agent.get("hostname", "")
        metadata["agent_id"] = agent.get("id", "")
        metadata["agent_type"] = agent.get("type", "")
    
    service = doc.get("service", {})
    if service:
        metadata["service_type"] = service.get("type", "")
    
    fileset = doc.get("fileset", {})
    if fileset:
        metadata["fileset_name"] = fileset.get("name", "")
    
    network = doc.get("network", {})
    if network:
        metadata["network_direction"] = network.get("direction", "")
        metadata["network_protocol"] = network.get("protocol", "")
        metadata["network_transport"] = network.get("transport", "")
    
    return metadata


def _build_fallback_alert(doc: Dict[str, Any], source: str) -> Dict[str, Any]:
    """Build a minimal alert when mapping fails."""
    title = (
        doc.get("rule", {}).get("name") or
        doc.get("message") or
        "Untitled Alert"
    )[:100]
    
    event_time = _extract_timestamp(doc)
    
    return {
        "source": source,
        "source_id": doc.get("_id", ""),
        "title": str(title)[:200],
        "description": str(doc.get("message", title))[:2000],
        "severity": map_severity(doc.get("rule", {}).get("level", 3), source),
        "status": "new",
        "source_ip": None,
        "dest_ip": None,
        "hostname": _extract_hostname(doc),
        "rule_name": str(title)[:100],
        "tags": [f"{source}-fallback"],
        "iocs": {},
        "event_time": event_time,
        "observables": [],
        "metadata": {},
    }
