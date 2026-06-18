"""
Falco alert mapper.
Maps Falco alert fields to OpenSOAR format.
"""

from typing import Dict, Any, List, Optional
from pipeline.mappers.severity import map_severity
from pipeline.mappers.ip_extractor import extract_ips
from pipeline.enrichment.mitre import enrich_with_mitre
from pipeline.enrichment.sigma import is_noise_alert as sigma_is_noise


def map_falco_alert(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Map Falco alert fields to OpenSOAR format."""
    try:
        if sigma_is_noise("falco", doc):
            raise ValueError(f"Noisy alert filtered: {doc.get('rule', '')}")
        
        _validate_falco_doc(doc)

        rule_name = doc.get("rule", "Untitled Alert")
        priority = doc.get("priority", "warning")
        output = doc.get("output", "")
        hostname = doc.get("hostname", "")
        output_fields = doc.get("output_fields", {}) or {}
        tags_list = doc.get("tags", []) or []
        
        # Extract timestamp
        event_time = _extract_timestamp(doc)

        src_ip, dst_ip = extract_ips(doc, "falco")
        tags = _build_tags(priority, tags_list)
        iocs = _build_iocs(src_ip, dst_ip, output_fields)
        
        # Build observables
        observables = _build_observables(src_ip, dst_ip, output_fields, doc)
        
        # Build metadata
        metadata = _build_metadata(hostname, output_fields, priority, doc)

        alert = {
            "source": "falco",
            "source_id": doc.get("_id", ""),
            "title": rule_name[:200] if rule_name else "Untitled Alert",
            "description": output[:2000] if output else rule_name,
            "severity": map_severity(priority, "falco"),
            "status": "new",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "hostname": hostname or "unknown",
            "rule_name": rule_name[:100] if rule_name else "Untitled Alert",
            "tags": tags,
            "iocs": iocs,
            "event_time": event_time,
            "observables": observables,
            "metadata": metadata,
        }
        
        # Add MITRE ATT&CK tags
        alert = enrich_with_mitre(alert)
        
        return alert
    except ValueError as e:
        raise
    except Exception as e:
        import structlog
        logger = structlog.get_logger()
        logger.warning("falco_map_exception", error=str(e), doc_keys=list(doc.keys()))
        return _build_fallback_alert(doc, "falco")


def _validate_falco_doc(doc: Dict[str, Any]) -> None:
    """Validate this is actually a Falco document, not from another source."""
    has_priority = "priority" in doc
    has_output = "output" in doc
    # Handle output_fields being string or wrong type
    output_fields = doc.get("output_fields")
    has_output_fields = output_fields and isinstance(output_fields, dict)
    has_rule = "rule" in doc
    
    if not (has_priority and has_rule and has_output):
        raise ValueError(
            f"Not a Falco document: missing priority/rule/output. "
            f"Found fields: {', '.join(list(doc.keys())[:8])}"
        )
    
    if doc.get("manager") or (doc.get("agent") and doc.get("full_log")):
        raise ValueError(
            "This looks like Wazuh data (has manager/agent/full_log), not Falco"
        )
    
    priority = doc.get("priority", "").lower()
    valid_priorities = [
        "emergency", "alert", "critical", "error", 
        "warning", "notice", "info", "informational", "debug"
    ]
    if priority and priority not in valid_priorities:
        raise ValueError(
            f"Invalid Falco priority: {priority} (expected one of {valid_priorities})"
        )


def _extract_timestamp(doc: Dict[str, Any]) -> str:
    """Extract timestamp in ISO8601 format."""
    ts = doc.get("@timestamp") or doc.get("time") or doc.get("timestamp")
    if ts:
        ts_str = str(ts)
        if not ts_str.endswith("Z") and "+" not in ts_str and "-" not in ts_str[-6:]:
            ts_str = ts_str + "Z"
        elif "+" in ts_str and not ts_str.endswith("Z"):
            ts_str = ts_str.replace("+00:00", "Z").replace("+0000", "Z")
        return ts_str
    return ""


def _build_tags(priority: str, source_tags: list) -> list:
    tags = [f"falco-priority-{priority}"]
    for t in source_tags:
        if t and isinstance(t, str):
            tags.append(t)
    return tags


def _build_iocs(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    output_fields: Dict,
) -> Dict:
    """Extract IOCs from Falco alert for OpenSOAR enrichment."""
    iocs: Dict[str, list] = {}

    ips = list(filter(None, set([src_ip, dst_ip])))
    if ips:
        iocs["ip"] = ips

    container_id = output_fields.get("container.id")
    if container_id:
        iocs["container_id"] = [container_id]

    proc = output_fields.get("proc.name") or output_fields.get("proc.cmdline")
    if proc:
        iocs["process"] = [str(proc)]

    fd_name = output_fields.get("fd.name")
    if fd_name:
        iocs["filepath"] = [fd_name]

    return iocs


def _build_observables(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    output_fields: Dict,
    doc: Dict,
) -> List[Dict[str, Any]]:
    """Build structured observables array."""
    observables = []
    
    # IPs
    if src_ip:
        observables.append({"type": "ip", "value": src_ip, "direction": "src"})
    if dst_ip:
        observables.append({"type": "ip", "value": dst_ip, "direction": "dst"})
    
    # Container ID
    container_id = output_fields.get("container.id")
    if container_id:
        observables.append({"type": "container_id", "value": container_id})
    
    # Process
    proc_name = output_fields.get("proc.name")
    if proc_name:
        observables.append({"type": "process", "value": str(proc_name), "name": "proc_name"})
    
    proc_cmdline = output_fields.get("proc.cmdline")
    if proc_cmdline:
        observables.append({"type": "process", "value": str(proc_cmdline), "name": "cmdline"})
    
    # User
    user_name = output_fields.get("user.name")
    if user_name:
        observables.append({"type": "user", "value": str(user_name), "name": "user_name"})
    
    # File path
    fd_name = output_fields.get("fd.name")
    if fd_name:
        observables.append({"type": "filepath", "value": str(fd_name)})
    
    # Container image
    container_image = output_fields.get("container.image.repository")
    if container_image:
        observables.append({"type": "container_image", "value": str(container_image)})
    
    return observables


def _build_metadata(
    hostname: str,
    output_fields: Dict,
    priority: str,
    doc: Dict,
) -> Dict[str, Any]:
    """Build Falco-specific metadata."""
    metadata = {
        "hostname": hostname,
    }
    
    # Container info
    container_id = output_fields.get("container.id")
    if container_id:
        metadata["container_id"] = container_id
        metadata["container_name"] = output_fields.get("container.name", "")
        metadata["container_image"] = output_fields.get("container.image.repository", "")
        metadata["container_image_tag"] = output_fields.get("container.image.tag", "")
    
    # Kubernetes info
    k8s_pod = output_fields.get("k8s.pod.name")
    if k8s_pod:
        metadata["pod_name"] = k8s_pod
        metadata["namespace"] = output_fields.get("k8s.ns.name", "")
        metadata["k8s_cluster"] = output_fields.get("k8s.cluster.name", "")
    
    # Process info
    proc_name = output_fields.get("proc.name")
    if proc_name:
        metadata["process_name"] = proc_name
    
    proc_cmdline = output_fields.get("proc.cmdline")
    if proc_cmdline:
        metadata["process_cmdline"] = proc_cmdline
    
    proc_exepath = output_fields.get("proc.exepath")
    if proc_exepath:
        metadata["process_exepath"] = proc_exepath
    
    proc_pname = output_fields.get("proc.pname")
    if proc_pname:
        metadata["process_parent"] = proc_pname
    
    # User info
    user_name = output_fields.get("user.name")
    if user_name:
        metadata["user_name"] = user_name
        metadata["user_uid"] = output_fields.get("user.uid", "")
    
    # File descriptor info
    fd_type = output_fields.get("fd.type")
    if fd_type:
        metadata["fd_type"] = fd_type
    
    fd_lport = output_fields.get("fd.lport")
    fd_rport = output_fields.get("fd.rport")
    if fd_lport:
        metadata["fd_lport"] = fd_lport
    if fd_rport:
        metadata["fd_rport"] = fd_rport
    
    # Event type
    evt_type = output_fields.get("evt.type")
    if evt_type:
        metadata["event_type"] = evt_type
    
    # Source
    source = doc.get("source", "")
    if source:
        metadata["falco_source"] = source
    
    # UUID if present
    uuid = doc.get("uuid", "")
    if uuid:
        metadata["falco_uuid"] = uuid
    
    return metadata


def _build_fallback_alert(doc: Dict[str, Any], source: str) -> Dict[str, Any]:
    """Build a minimal alert when mapping fails - graceful degradation."""
    title = doc.get("rule", "Untitled Alert")
    output = doc.get("output", "")
    event_time = _extract_timestamp(doc)
    
    return {
        "source": source,
        "source_id": doc.get("_id", ""),
        "title": str(title)[:200],
        "description": str(output)[:2000] if output else str(title)[:2000],
        "severity": map_severity(doc.get("priority", "warning"), source),
        "status": "new",
        "source_ip": None,
        "dest_ip": None,
        "hostname": doc.get("hostname", "unknown"),
        "rule_name": str(title)[:100],
        "tags": [f"{source}-fallback"],
        "iocs": {},
        "event_time": event_time,
        "observables": [],
        "metadata": {},
    }
