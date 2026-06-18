"""
Wazuh alert mapper.
Maps Wazuh alert fields to OpenSOAR format.
"""

import re
from typing import Any, Dict, List, Optional
from pipeline.mappers.severity import map_severity
from pipeline.mappers.ip_extractor import extract_ips
from pipeline.enrichment.sigma import is_noise_alert as sigma_is_noise


def map_wazuh_alert(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Map Wazuh alert fields to OpenSOAR format."""
    try:
        rule = doc.get("rule", {}) or {}
        if sigma_is_noise("wazuh", doc):
            raise ValueError(f"Noisy alert filtered: {rule.get('description', '')}")
        
        _validate_wazuh_doc(doc)

        data = doc.get("data", {}) or {}
        agent = doc.get("agent", {}) or {}
        mitre = rule.get("mitre", {}) or {}
        syscheck = doc.get("syscheck", {}) or {}
        decoder = doc.get("decoder", {}) or {}
        manager = doc.get("manager", {}) or {}

        rule_name = rule.get("name") or None
        rule_desc = rule.get("description", "")
        rule_level = rule.get("level", 3)
        rule_id = str(rule.get("id", ""))
        full_log = doc.get("full_log", "")

        # Skip very low-value alerts by default, BUT allow high-context ones
        # (Sysmon process creation = level 1, but is critical for execution detection)
        if rule_level < 3:
            groups = rule.get("groups", []) or []
            groups_lower = [str(g).lower() for g in groups]
            has_mitre = bool(rule.get("mitre", {}).get("id"))
            is_sysmon = any("sysmon" in g for g in groups_lower)
            is_windows_security = any("windows_security" in g for g in groups_lower)
            is_fim = any("syscheck" in g for g in groups_lower)
            
            if not (has_mitre or is_sysmon or is_windows_security or is_fim):
                raise ValueError(f"Low-value alert filtered (level {rule_level}): {rule_desc}")
        
        # Extract timestamp
        event_time = _extract_timestamp(doc)

        title = _extract_title(rule_name, rule_desc, full_log)
        description = full_log or rule_desc or title
        hostname = _extract_hostname(agent)
        src_ip, dst_ip = extract_ips(doc, "wazuh")
        category = _categorize_wazuh_alert(rule)
        tags = _build_tags(rule_level, mitre, rule_id)
        iocs = _build_iocs(src_ip, dst_ip, data, syscheck)
        
        # Build observables
        observables = _build_observables(src_ip, dst_ip, data, syscheck)
        
        # Build metadata
        metadata = _build_metadata(agent, rule, mitre, decoder, manager, data)
        metadata["wazuh_rule_description"] = rule_desc
        metadata["wazuh_agent_id"] = agent.get("id", "") if isinstance(agent, dict) else ""
        metadata["category"] = category

        return {
            "source": "wazuh",
            "source_id": doc.get("_id", ""),
            "title": title[:200] if title else "Untitled Wazuh Alert",
            "description": description[:2000] if description else title,
            "severity": map_severity(rule_level, "wazuh"),
            "status": "new",
            "category": category,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "hostname": hostname or "unknown",
            "rule_name": rule_desc[:100] if rule_desc else title[:100],
            "tags": tags,
            "iocs": iocs,
            "event_time": event_time,
            "observables": observables,
            "metadata": metadata,
            "asset_id_hint": agent.get("id", "") or agent.get("name", "") or hostname or "",
        }
    except ValueError as e:
        raise
    except Exception as e:
        import structlog
        logger = structlog.get_logger()
        logger.warning("wazuh_map_exception", error=str(e), doc_keys=list(doc.keys()))
        return _build_fallback_alert(doc, "wazuh")


def _validate_wazuh_doc(doc: Dict[str, Any]) -> None:
    """Validate this is actually a Wazuh document, not from another source."""
    has_rule = doc.get("rule") and isinstance(doc.get("rule"), dict)
    has_agent = doc.get("agent") and isinstance(doc.get("agent"), dict)
    
    if not (has_rule and has_agent):
        raise ValueError(
            f"Not a Wazuh document: missing rule/agent structure. "
            f"Found fields: {', '.join(list(doc.keys())[:8])}"
        )
    
    rule = doc.get("rule", {})
    if not rule.get("id"):
        raise ValueError(f"Wazuh rule missing id: {rule.get('id', 'N/A')}")
    
    if doc.get("priority") and doc.get("output_fields"):
        raise ValueError("This looks like Falco data (has priority/output_fields), not Wazuh")


def _extract_timestamp(doc: Dict[str, Any]) -> str:
    """Extract timestamp in ISO8601 format."""
    ts = doc.get("@timestamp") or doc.get("timestamp") or doc.get("time")
    if ts:
        ts_str = str(ts)
        if not ts_str.endswith("Z") and "+" not in ts_str and "-" not in ts_str[-6:]:
            ts_str = ts_str + "Z"
        elif "+" in ts_str and not ts_str.endswith("Z"):
            ts_str = ts_str.replace("+00:00", "Z").replace("+0000", "Z")
        return ts_str
    return ""


def _extract_title(rule_name: Optional[str], rule_desc: str, full_log: str) -> str:
    if rule_name:
        return rule_name
    elif rule_desc:
        return rule_desc
    elif full_log:
        return full_log[:100]
    return "Untitled Alert"


def _extract_hostname(agent: Any) -> str:
    if isinstance(agent, dict):
        return agent.get("name", "")
    elif agent:
        return str(agent)
    return ""


def _build_tags(level: int, mitre: Dict, rule_id: str) -> list:
    tags = [f"wazuh-level-{level}"]
    if rule_id:
        tags.append(f"wazuh-rule-{rule_id}")
    if mitre:
        tactics = mitre.get("tactic", [])
        techniques = mitre.get("technique", [])
        ids = mitre.get("id", [])
        for tactic in tactics:
            if tactic:
                tags.append(f"mitre-tactic-{tactic}")
        for technique in techniques:
            if technique:
                tags.append(f"mitre-technique-{technique}")
        for mid in ids:
            if mid:
                tags.append(f"mitre-{mid}")
    return tags


def _build_iocs(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    data: Dict,
    syscheck: Dict,
) -> Dict:
    """Extract IOCs (IPs, file hashes, usernames) for OpenSOAR enrichment."""
    iocs: Dict[str, list] = {}

    ips = list(filter(None, set([src_ip, dst_ip])))
    if ips:
        iocs["ip"] = ips

    hashes = []
    for algo in ("md5_after", "sha1_after", "sha256_after"):
        h = syscheck.get(algo)
        if h:
            hashes.append(h)
    win_hashes = data.get("win", {}).get("eventdata", {}).get("hashes", "")
    if win_hashes:
        for part in win_hashes.split(","):
            part = part.strip()
            if "=" in part:
                part = part.split("=", 1)[1]
            if part and len(part) >= 32:
                hashes.append(part)
    if hashes:
        iocs["hash"] = list(set(hashes))

    url = data.get("url")
    if url:
        iocs["url"] = [url]

    user = data.get("srcuser") or data.get("dstuser")
    if user:
        iocs["username"] = [user]
    
    # Process name
    process = data.get("process")
    if process:
        iocs.setdefault("process", []).append(process)
    
    # File path
    file_path = data.get("file") or data.get("path")
    if file_path:
        iocs.setdefault("filepath", []).append(file_path)
    
    # Windows image path
    win_image = data.get("win", {}).get("eventdata", {}).get("image")
    if win_image:
        iocs.setdefault("filepath", []).append(win_image)
    
    # Command line (truncated for IOC storage)
    cmd = data.get("command")
    if cmd and len(str(cmd)) < 500:
        iocs.setdefault("command", []).append(str(cmd))

    return iocs


def _build_observables(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    data: Dict,
    syscheck: Dict,
) -> List[Dict[str, Any]]:
    """Build structured observables array."""
    observables = []
    
    # IPs
    if src_ip:
        observables.append({"type": "ip", "value": src_ip, "direction": "src"})
    if dst_ip:
        observables.append({"type": "ip", "value": dst_ip, "direction": "dst"})
    
    # Domain from URL
    url = data.get("url")
    if url:
        domain = _extract_domain_from_url(url)
        if domain:
            observables.append({"type": "domain", "value": domain})
    
    # File hashes
    for algo, key in [("md5", "md5_after"), ("sha1", "sha1_after"), ("sha256", "sha256_after")]:
        h = syscheck.get(key)
        if h:
            observables.append({"type": "hash", "value": h, "algo": algo})
    
    # Hashes from Windows
    win_hashes = data.get("win", {}).get("eventdata", {}).get("hashes", "")
    if win_hashes:
        for part in win_hashes.split(","):
            part = part.strip()
            if "=" in part:
                parts = part.split("=", 1)
                algo = parts[0].lower()
                value = parts[1] if len(parts) > 1 else ""
                if value and len(value) >= 32:
                    observables.append({"type": "hash", "value": value, "algo": algo})
    
    # Process
    process = data.get("process")
    if process:
        observables.append({"type": "process", "value": process})
    
    # File path
    file_path = data.get("file") or data.get("path")
    if file_path:
        observables.append({"type": "filepath", "value": file_path})
    
    # Windows image path
    win_image = data.get("win", {}).get("eventdata", {}).get("image")
    if win_image:
        observables.append({"type": "filepath", "value": win_image, "source": "win_event"})
    
    # Windows command line
    win_cmd = data.get("win", {}).get("eventdata", {}).get("commandLine")
    if win_cmd:
        observables.append({"type": "command", "value": win_cmd[:200], "source": "win_event"})
    
    # Windows Event ID
    win_event_id = data.get("win", {}).get("system", {}).get("eventID")
    if win_event_id:
        observables.append({"type": "win_event_id", "value": str(win_event_id)})
    
    return observables


def _categorize_wazuh_alert(rule: Dict[str, Any]) -> str:
    """Categorize alert based on Wazuh rule name, description, and groups."""
    rule_name = (rule.get("name") or "").lower()
    rule_desc = (rule.get("description") or "").lower()
    combined = rule_name + " " + rule_desc
    groups = rule.get("groups", []) or []
    groups_lower = [str(g).lower() for g in groups]

    # Most specific: check rule name/description first
    # Brute-force patterns
    if any(k in combined for k in (
        "brute force", "bruteforce", "multiple failed logins",
        "password guessing", "credential stuffing", "missed the password"
    )):
        return "brute-force"

    # Privilege escalation
    if any(k in combined for k in (
        "sudo", "su -", "privilege escalation", "administrator privilege",
        "root access", "executed as root", "elevated privileges"
    )):
        return "privilege-escalation"

    # Web attacks
    if any(k in combined for k in (
        "sql injection", "sqli", "xss", "directory traversal",
        "command injection", "lfi", "rfi", "web shell", "webshell"
    )):
        return "web-attack"

    # Reconnaissance
    if any(k in combined for k in (
        "port scan", "nmap", "scan detected", "reconnaissance",
        "sweep", "network scan"
    )):
        return "reconnaissance"

    # Malware
    if any(k in combined for k in (
        "malware", "trojan", "virus", "backdoor", "rootkit",
        "coinminer", "mining"
    )):
        return "malware"

    # DoS
    if any(k in combined for k in (
        "denial of service", "dos", "ddos", "flood"
    )):
        return "dos"

    # C2
    if any(k in combined for k in (
        "command and control", "c2", "botnet", "beacon", "callback"
    )):
        return "c2"

    # Exfiltration
    if any(k in combined for k in (
        "exfiltration", "data exfiltration", "data leakage"
    )):
        return "exfiltration"

    # Threat intel
    if any(k in combined for k in (
        "threat intel", "blocked threat", "block list", "reputation",
        "known compromised"
    )):
        return "threat-intel"

    # Generic group-based fallbacks
    auth_keywords = {"authentication", "login", "sshd", "pam", "windows_security", "active_directory"}
    network_keywords = {"network", "firewall", "iptables", "ids", "suricata", "connection"}
    malware_keywords = {"virus", "malware", "trojan", "rootkit", "md5", "sha256", "yara"}

    if any(k in g for g in groups_lower for k in auth_keywords):
        return "authentication"
    if any(k in g for g in groups_lower for k in network_keywords):
        return "network"
    if any(k in g for g in groups_lower for k in malware_keywords):
        return "malware"
    if any("sysmon" in g or "windows" in g or "linux" in g for g in groups_lower):
        return "system"
    return "other"


def _extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc.split(":")[0]
    except Exception:
        pass
    return None


def _build_metadata(
    agent: Dict,
    rule: Dict,
    mitre: Dict,
    decoder: Dict,
    manager: Dict,
    data: Dict,
) -> Dict[str, Any]:
    """Build Wazuh-specific metadata with full SOC field extraction."""
    metadata = {
        "agent_id": agent.get("id", "") if isinstance(agent, dict) else "",
        "agent_name": agent.get("name", "") if isinstance(agent, dict) else "",
    }
    
    # Agent OS (critical for OS-aware remediation)
    if isinstance(agent, dict):
        agent_os = agent.get("os", {}) or {}
        if agent_os.get("name"):
            metadata["agent_os_name"] = agent_os["name"]
        if agent_os.get("version"):
            metadata["agent_os_version"] = agent_os["version"]
        if agent.get("ip"):
            metadata["agent_ip"] = agent["ip"]
    
    if rule.get("id"):
        metadata["rule_id"] = str(rule.get("id"))
    if rule.get("level"):
        metadata["rule_level"] = rule.get("level")
    if rule.get("groups"):
        metadata["rule_groups"] = rule["groups"]
    if rule.get("frequency"):
        metadata["rule_frequency"] = rule["frequency"]
    if rule.get("firedtimes"):
        metadata["rule_firedtimes"] = rule["firedtimes"]
    
    # Decoder info
    if decoder:
        metadata["decoder"] = decoder.get("name", "")
        metadata["decoder_parent"] = decoder.get("parent", "")
    
    # Manager info
    if manager:
        metadata["manager_name"] = manager.get("name", "")
    
    # Location (log source path like /var/log/auth.log or Sysmon)
    doc_location = data.get("location", "")
    if doc_location:
        metadata["location"] = doc_location
    
    # MITRE (preserve Wazuh's high-confidence mapping)
    if mitre:
        tactics = mitre.get("tactic", [])
        techniques = mitre.get("technique", [])
        ids = mitre.get("id", [])
        if tactics:
            metadata["mitre_tactics"] = [t for t in tactics if t]
        if techniques:
            metadata["mitre_techniques"] = [t for t in techniques if t]
        if ids:
            metadata["mitre_ids"] = [i for i in ids if i]
    
    # Additional data fields (endpoint context)
    if data.get("srcip"):
        metadata["data_src_ip"] = data.get("srcip")
    if data.get("dstip"):
        metadata["data_dst_ip"] = data.get("dstip")
    if data.get("srcuser"):
        metadata["data_src_user"] = data.get("srcuser")
    if data.get("dstuser"):
        metadata["data_dst_user"] = data.get("dstuser")
    if data.get("action"):
        metadata["data_action"] = data.get("action")
    if data.get("command"):
        metadata["data_command"] = data["command"]
    if data.get("type"):
        metadata["data_type"] = data["type"]
    if data.get("status"):
        metadata["data_status"] = data["status"]
    
    # Process info
    if data.get("process"):
        metadata["data_process"] = data["process"]
    if data.get("process_id"):
        metadata["data_process_id"] = data["process_id"]
    if data.get("parent_process"):
        metadata["data_parent_process"] = data["parent_process"]
    if data.get("parent_pid"):
        metadata["data_parent_pid"] = data["parent_pid"]
    
    # File info
    if data.get("file"):
        metadata["data_file"] = data["file"]
    if data.get("path"):
        metadata["data_path"] = data["path"]
    
    # Windows Event ID (critical for Windows SOC analysis)
    win_data = data.get("win", {}) or {}
    if win_data:
        win_system = win_data.get("system", {}) or {}
        if win_system.get("eventID"):
            metadata["win_event_id"] = win_system["eventID"]
        if win_system.get("channel"):
            metadata["win_channel"] = win_system["channel"]
        win_eventdata = win_data.get("eventdata", {}) or {}
        if win_eventdata.get("targetUserName"):
            metadata["win_target_user"] = win_eventdata["targetUserName"]
        if win_eventdata.get("subjectUserName"):
            metadata["win_subject_user"] = win_eventdata["subjectUserName"]
        if win_eventdata.get("image"):
            metadata["win_image_path"] = win_eventdata["image"]
        if win_eventdata.get("commandLine"):
            metadata["win_command_line"] = win_eventdata["commandLine"]
        if win_eventdata.get("parentImage"):
            metadata["win_parent_image"] = win_eventdata["parentImage"]
    
    return metadata


def _build_fallback_alert(doc: Dict[str, Any], source: str) -> Dict[str, Any]:
    """Build a minimal alert when mapping fails - graceful degradation."""
    title = (
        doc.get("rule", {}).get("name") or
        doc.get("message") or
        doc.get("full_log", "")[:100] or
        "Untitled Wazuh Alert"
    )
    
    event_time = _extract_timestamp(doc)
    
    return {
        "source": source,
        "source_id": doc.get("_id", ""),
        "title": str(title)[:200],
        "description": str(doc.get("full_log", doc.get("message", title)))[:2000],
        "severity": map_severity(doc.get("rule", {}).get("level", 3), source),
        "status": "new",
        "source_ip": None,
        "dest_ip": None,
        "hostname": doc.get("agent", {}).get("name") if isinstance(doc.get("agent"), dict) else None,
        "rule_name": str(title)[:100],
        "tags": [f"{source}-fallback"],
        "iocs": {},
        "event_time": event_time,
        "observables": [],
        "metadata": {},
    }
