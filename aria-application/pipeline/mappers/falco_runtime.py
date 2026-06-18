"""
Falco Runtime Alert Mapper.

Maps Falco events to OpenSOAR runtime security alerts.
This is the enhanced mapper for the Runtime Security module.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

import structlog

from pipeline.mappers.severity import map_severity
from pipeline.enrichment.mitre import enrich_with_mitre

logger = structlog.get_logger()


def map_falco_runtime_alert(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Map a Falco document to a runtime security alert."""
    try:
        _validate_falco_doc(doc)
    except ValueError as e:
        logger.warning("falco_runtime_invalid_doc", error=str(e))
        raise

    rule_name = doc.get("rule", "Unknown Rule")
    priority = doc.get("priority", "warning")
    output = doc.get("output", "")
    hostname = doc.get("hostname", "")
    output_fields = doc.get("output_fields", {}) or {}
    if not hostname:
        hostname = output_fields.get("hostname") or output_fields.get("host") or ""
    tags_list = doc.get("tags", []) or []
    source_id = doc.get("_id", "")

    # Build runtime context using the new engine
    from response.runtime_ai_engine.context_builder import build_runtime_context

    runtime_context = build_runtime_context(doc)

    # Severity comes from the rule-aware classifier in context builder
    severity = runtime_context.severity

    # Extract network IPs if available
    source_ip = output_fields.get("fd_sip") or output_fields.get("fd_cip")
    dest_ip = output_fields.get("fd_dip")
    source_port = output_fields.get("fd_sport")
    dest_port = output_fields.get("fd_dport")
    l4_proto = output_fields.get("fd_l4proto")

    # Build observables from output_fields (using recovered process names from runtime_context)
    observables = _build_observables(output_fields, doc, runtime_context, source_ip, dest_ip, source_port, dest_port, l4_proto)

    # Build metadata
    metadata = _build_metadata(output_fields, priority, doc, runtime_context, source_ip, dest_ip, source_port, dest_port, l4_proto)

    # Build IOCs (using recovered process names)
    iocs = _build_iocs(output_fields, runtime_context)

    # Extract timestamp
    event_time = _extract_timestamp(doc)

    alert = {
        "source": "falco",
        "source_id": source_id,
        "title": rule_name[:200] if rule_name else "Untitled Runtime Event",
        "description": output[:2000] if output else rule_name,
        "severity": severity,
        "status": "new",
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "hostname": hostname or "unknown",
        "rule_name": rule_name[:100] if rule_name else "Untitled Rule",
        "tags": _build_tags(priority, tags_list, runtime_context.runtime_category),
        "iocs": iocs,
        "event_time": event_time,
        "observables": observables,
        "metadata": metadata,
        "investigation_type": "runtime",  # NEW: marks this as a runtime security alert
        "runtime_category": runtime_context.runtime_category,
        "runtime_context": runtime_context.to_dict(),
        "asset_id_hint": hostname or "",
    }

    # Add MITRE enrichment
    alert = enrich_with_mitre(alert)

    logger.info(
        "falco_runtime_alert_mapped",
        rule=rule_name,
        category=runtime_context.runtime_category,
        severity=severity,
        host=hostname,
        intervention=runtime_context.is_intervention_required,
    )

    return alert


def _validate_falco_doc(doc: Dict[str, Any]) -> None:
    """Validate this is actually a Falco document."""
    if not isinstance(doc, dict):
        raise ValueError("Falco document must be a dict")

    has_priority = "priority" in doc
    has_output = "output" in doc
    has_rule = "rule" in doc

    if not (has_priority and has_rule and has_output):
        raise ValueError(
            f"Not a Falco document: missing priority/rule/output. "
            f"Found fields: {', '.join(list(doc.keys())[:8])}"
        )

    priority = str(doc.get("priority", "")).lower()
    valid_priorities = [
        "emergency", "alert", "critical", "error",
        "warning", "notice", "info", "informational", "debug",
    ]
    if priority and priority not in valid_priorities:
        raise ValueError(f"Invalid Falco priority: {priority}")


def _build_tags(priority: str, source_tags: List[str], category: str) -> List[str]:
    """Build tags for the runtime alert."""
    tags = [
        f"falco-priority-{priority}",
        f"runtime-category-{category}",
        "runtime-security",
        "falco",
    ]
    for t in source_tags:
        if t and isinstance(t, str):
            tags.append(t)
    return tags


def _build_iocs(output_fields: Dict[str, Any], runtime_context) -> Dict[str, list]:
    """Extract IOCs from Falco output_fields."""
    iocs: Dict[str, list] = {}

    container_id = output_fields.get("container_id")
    if container_id and container_id != "host":
        iocs["container_id"] = [str(container_id)]

    proc = runtime_context.proc_name or output_fields.get("proc_name") or runtime_context.proc_cmdline or output_fields.get("proc_cmdline")
    if proc:
        iocs["process"] = [str(proc)]

    fd_name = output_fields.get("fd_name")
    if fd_name and fd_name not in ["<NA>", "", None]:
        iocs["filepath"] = [str(fd_name)]

    user = output_fields.get("user_name")
    if user:
        iocs["user"] = [str(user)]

    return iocs


def _build_observables(
    output_fields: Dict[str, Any],
    doc: Dict[str, Any],
    runtime_context,
    source_ip: Any = None,
    dest_ip: Any = None,
    source_port: Any = None,
    dest_port: Any = None,
    l4_proto: Any = None,
) -> List[Dict[str, Any]]:
    """Build observables list for the runtime alert."""
    observables = []

    # Process observable — use recovered names from runtime_context when available
    proc_name = runtime_context.proc_name or output_fields.get("proc_name")
    proc_cmdline = runtime_context.proc_cmdline or output_fields.get("proc_cmdline")
    if proc_name:
        observables.append({
            "type": "process",
            "value": proc_name,
            "description": proc_cmdline or proc_name,
        })

    # File observable
    fd_name = output_fields.get("fd_name")
    if fd_name and fd_name not in ["<NA>", "", None]:
        observables.append({
            "type": "file",
            "value": fd_name,
            "description": f"File accessed by {proc_name}",
        })

    # Network observable
    if source_ip or dest_ip:
        net_desc = f"Network {l4_proto or 'traffic'}"
        if source_ip and source_port:
            net_desc += f" from {source_ip}:{source_port}"
        elif source_ip:
            net_desc += f" from {source_ip}"
        if dest_ip and dest_port:
            net_desc += f" to {dest_ip}:{dest_port}"
        elif dest_ip:
            net_desc += f" to {dest_ip}"
        observables.append({
            "type": "network",
            "value": f"{source_ip or 'unknown'}->{dest_ip or 'unknown'}",
            "description": net_desc,
        })

    # User observable
    user_name = output_fields.get("user_name")
    if user_name:
        observables.append({
            "type": "user",
            "value": user_name,
            "description": f"UID {output_fields.get('user_uid', 'unknown')}",
        })

    # Container observable
    container_id = output_fields.get("container_id")
    if container_id and container_id != "host":
        observables.append({
            "type": "container",
            "value": container_id,
            "description": output_fields.get("container_name", container_id),
        })

    # Host observable
    hostname = doc.get("hostname") or output_fields.get("evt_hostname")
    if hostname:
        observables.append({
            "type": "host",
            "value": hostname,
            "description": "Affected host",
        })

    return observables


def _build_metadata(
    output_fields: Dict[str, Any],
    priority: str,
    doc: Dict[str, Any],
    runtime_context,
    source_ip: Any = None,
    dest_ip: Any = None,
    source_port: Any = None,
    dest_port: Any = None,
    l4_proto: Any = None,
) -> Dict[str, Any]:
    """Build rich metadata for the runtime alert."""
    container_id = output_fields.get("container_id", "host")
    return {
        "falco_priority": priority,
        "falco_rule": doc.get("rule", ""),
        "falco_tags": doc.get("tags", []),
        "falco_uuid": doc.get("uuid", ""),
        "falco_source": doc.get("source", "syscall"),
        "output_fields": output_fields,
        "runtime_category": runtime_context.runtime_category,
        "is_intervention_required": runtime_context.is_intervention_required,
        "is_expected_admin_activity": runtime_context.is_expected_admin_activity,
        "mitre_techniques": runtime_context.mitre_techniques,
        # Top-level container_id for dedup contract compatibility
        "container_id": container_id,
        "process_tree": {
            "proc_name": runtime_context.proc_name or output_fields.get("proc_name"),
            "proc_pid": output_fields.get("proc_pid"),
            "proc_pname": output_fields.get("proc_pname"),
            "proc_ppid": output_fields.get("proc_ppid"),
            "proc_cmdline": runtime_context.proc_cmdline or output_fields.get("proc_cmdline"),
            "proc_exepath": output_fields.get("proc_exepath"),
            "ancestors": runtime_context.proc_ancestors,
        },
        "container": {
            "id": container_id,
            "name": output_fields.get("container_name", "host"),
            "image_repo": output_fields.get("container_image_repository"),
            "image_tag": output_fields.get("container_image_tag"),
        },
        "kubernetes": {
            "namespace": output_fields.get("k8s_ns_name"),
            "pod": output_fields.get("k8s_pod_name"),
        },
        "network": {
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": source_port,
            "dest_port": dest_port,
            "protocol": l4_proto,
        },
        "event": {
            "type": output_fields.get("evt_type"),
            "category": output_fields.get("evt_category"),
            "time": doc.get("time"),
        },
    }


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
    return datetime.now(timezone.utc).isoformat()
