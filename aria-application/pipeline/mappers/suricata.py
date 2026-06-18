"""
Suricata alert mapper.
Maps Suricata alert fields to OpenSOAR format.
Suricata alerts are embedded in Filebeat documents.
"""

from typing import Dict, Any, List, Optional
from pipeline.mappers.severity import map_severity
from pipeline.mappers.ip_extractor import extract_ips
from pipeline.enrichment.mitre import enrich_with_mitre
from pipeline.enrichment.sigma import is_noise_alert as sigma_is_noise

# Emerging Threats (ET) SID → MITRE ATT&CK technique mapping
# High-confidence mapping for common ET rules
_ET_SID_MITRE_MAP = {
    # Reconnaissance
    2000000: ("T1595", "Active Scanning"),  # ET SCAN
    2012647: ("T1595", "Active Scanning"),  # ET SCAN Possible Nmap
    # Initial Access
    2011803: ("T1190", "Exploit Public-Facing Application"),  # ET WEB_SERVER
    2012272: ("T1190", "Exploit Public-Facing Application"),  # ET WEB_SPECIFIC_APPS
    2021234: ("T1190", "Exploit Public-Facing Application"),  # ET WEB_SERVER SQL Injection
    2010104: ("T1190", "Exploit Public-Facing Application"),  # ET WEB_SERVER cmd execution
    # Execution
    2015718: ("T1059", "Command and Scripting Interpreter"),  # ET CURRENT_EVENTS
    # Persistence
    2002802: ("T1547", "Boot or Logon Autostart Execution"),  # ET MALWARE
    # Privilege Escalation
    2009995: ("T1548", "Abuse Elevation Control Mechanism"),  # ET ATTACK
    # Credential Access
    2012843: ("T1110", "Brute Force"),  # ET SCAN Multiple SSH
    2001219: ("T1110", "Brute Force"),  # ET SCAN Multiple FTP
    # Command and Control
    2009701: ("T1071", "Application Layer Protocol"),  # ET TROJAN
    2014297: ("T1071", "Application Layer Protocol"),  # ET MALWARE
    # Exfiltration
    2009700: ("T1041", "Exfiltration Over C2 Channel"),  # ET TROJAN
    # Defense Evasion
    2024898: ("T1027", "Obfuscated Files or Information"),  # ET POLICY
}


def map_suricata_alert(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Map Suricata alert fields to OpenSOAR format."""
    suricata_eve = doc.get("suricata", {}).get("eve", {}) or {}
    alert_data = suricata_eve.get("alert", {}) or {}
    
    rule_name = alert_data.get("signature") or ""
    rule_id = alert_data.get("signature_id", "")
    category = alert_data.get("category") or ""

    if not rule_name:
        raise ValueError("Suricata alert missing signature - skipping noise")

    if _is_noisy_alert(rule_name, category, doc):
        raise ValueError(f"Noisy alert filtered at mapper: {rule_name}")

    if sigma_is_noise("suricata", doc):
        raise ValueError(f"Noisy alert filtered: {rule_name}")

    # Extract timestamp
    event_time = _extract_timestamp(doc)

    suricata_severity = _map_category_to_severity(category, rule_name)
    src_ip, dst_ip = extract_ips(doc, "suricata")
    hostname = _extract_hostname(doc)

    proto = suricata_eve.get("proto", "").upper() or "UNKNOWN"
    src_port = suricata_eve.get("src_port")
    dest_port = suricata_eve.get("dest_port")
    flow = suricata_eve.get("flow", {}) or {}
    flow_id = suricata_eve.get("flow_id")

    description = _build_clean_description(
        rule_name, category, rule_id, src_ip, dst_ip, src_port, dest_port, proto, suricata_eve
    )

    tags = _build_tags(rule_id, category, proto)
    iocs = _build_iocs(src_ip, dst_ip, src_port, dest_port, suricata_eve)
    
    # Build observables
    observables = _build_observables(src_ip, dst_ip, src_port, dest_port, suricata_eve)
    
    # Build metadata
    metadata = _build_metadata(
        alert_data, suricata_eve, flow, hostname, src_port, dest_port, proto, rule_id, category
    )
    
    # Asset identity hint for multi-server resolution
    host = doc.get("host", {}) or {}
    agent = doc.get("agent", {}) or {}
    asset_id_hint = host.get("name", "") or agent.get("name", "") or agent.get("hostname", "") or hostname or ""
    
    # SID-based MITRE ATT&CK mapping (high-confidence vs keyword guessing)
    sid_mitre = None
    if rule_id:
        try:
            sid_int = int(rule_id)
            sid_mitre = _ET_SID_MITRE_MAP.get(sid_int)
            if sid_mitre:
                metadata["mitre_technique_id"] = sid_mitre[0]
                metadata["mitre_technique_name"] = sid_mitre[1]
                metadata["mitre_source"] = "et_sid_mapping"
        except (ValueError, TypeError):
            pass
    
    # IPS-specific enrichment
    alert_action = alert_data.get("action", "")
    metadata["ips_action"] = "blocked" if alert_action in ("blocked", "drop") or "drop" in rule_name.lower() else "allowed"
    metadata["attack_status"] = _determine_attack_status(event_time)
    metadata["flow_id"] = flow_id
    payload = suricata_eve.get("payload_printable", "")
    if payload:
        metadata["payload_printable"] = payload[:200]

    # Inject SID-based MITRE tag before keyword enrichment
    if sid_mitre:
        tags.append(f"mitre-{sid_mitre[0]}")
        tags.append("mitre-source-sid")
    
    alert = {
        "source": "suricata",
        "source_id": "",
        "title": rule_name[:200],
        "description": description[:2000],
        "severity": map_severity(suricata_severity, "suricata"),
        "status": "new",
        "category": _map_suricata_category_to_opensoar(category, rule_name),
        "source_ip": src_ip,
        "dest_ip": dst_ip,
        "hostname": hostname,
        "rule_name": rule_name[:100],
        "tags": tags,
        "iocs": iocs,
        "event_time": event_time,
        "observables": observables,
        "metadata": metadata,
        "asset_id_hint": asset_id_hint,
    }
    
    # Add dynamic MITRE ATT&CK tags (preserves existing SID-based tags)
    alert = enrich_with_mitre(alert)
    
    return alert


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


def _map_suricata_category_to_opensoar(category: str, rule_name: str) -> str:
    """Map Suricata alert.category / rule name to OpenSOAR operational category."""
    cat = (category or "").lower()
    sig = (rule_name or "").lower()

    # C2 / command and control
    if any(x in cat for x in ["command and control", "c2", "botnet", "trojan"]):
        return "c2"

    # Malware
    if any(x in cat for x in ["malware", "coinminer", "mining"]):
        return "malware"

    # Exfiltration
    if any(x in cat for x in ["data exfiltration", "exfiltration", "data leakage"]):
        return "exfiltration"

    # Web attack
    if any(x in cat for x in [
        "web application attack", "sql injection", "xss", "cross site scripting",
        "directory traversal", "command injection", "code injection", "lfi", "rfi",
    ]):
        return "web-attack"
    if any(x in sig for x in ["sql injection", "sqli", "xss", "directory traversal", "command injection", "lfi", "rfi"]):
        return "web-attack"

    # Brute-force
    if any(x in cat for x in ["brute force", "brute-force", "credential stuffing", "password guessing"]):
        return "brute-force"
    if any(x in sig for x in ["brute force", "brute-force", "password guess", "credential stuffing"]):
        return "brute-force"

    # DoS
    if any(x in cat for x in ["denial of service", "dos", "ddos"]):
        return "dos"

    # Threat intel
    if any(x in cat for x in ["threat intelligence", "block list", "blocklist", "reputation"]):
        return "threat-intel"
    if any(x in sig for x in ["drop ", "cins active threat", "spamhaus", "block listed", "threat intelligence", "known compromised"]):
        return "threat-intel"

    # Privilege escalation
    if any(x in cat for x in ["privilege escalation", "elevation of privilege", "attempted administrator", "successful administrator"]):
        return "privilege-escalation"

    # Info disclosure
    if any(x in cat for x in ["attempted information leak", "information disclosure", "information leak"]):
        return "info-disclosure"

    # Reconnaissance
    if any(x in cat for x in ["network scan", "scan", "reconnaissance", "detection of a network scan"]):
        return "reconnaissance"
    if any(x in sig for x in ["scan", "nmap", "zmap", "masscan", "sipvicious", "friendly-scanner"]):
        return "reconnaissance"

    # Intrusion
    if any(x in cat for x in ["intrusion", "attempted admin", "successful admin", "attempted user", "successful user"]):
        return "intrusion"

    # Suspicious
    if any(x in cat for x in ["suspicious", "anomaly", "potentially bad traffic", "misc attack"]):
        return "suspicious"

    # Informational
    if any(x in cat for x in ["informational", "not suspicious", "misc activity", "generic protocol"]):
        return "informational"

    # Default
    return "network"


def _is_noisy_alert(signature: str, category: str, doc: Dict) -> bool:
    """Filter out known noisy/low-value Suricata alerts.
    
    Only block truly useless patterns. Security events like scans,
    protocol anomalies, and stream issues should be forwarded with
    appropriate severity mapping.
    """
    sig_lower = signature.lower()
    cat_lower = category.lower()

    noisy_patterns = [
        "byte_jump",
        "byte_extract",
        "test only",
        "connection established",
        "expected application layer traffic",
        # Protocol noise that's not actionable
        "packet with invalid timestamp",
        "stream excessive retransmissions",
        "stream suspected rst injection",
        "stream 3way handshake wrong seq",
        "stream established packet out of window",
        "stream reassembly overlap with different data",
        "stream shutdown rst invalid ack",
        "stream packet with invalid ack",
        "http unable to match response to request",
        "http request line incomplete",
        "http host header ambiguous",
        "http host part of uri is invalid",
        "http response buffer too long",
        "http invalid response chunk len",
        "ssh invalid banner",
        "applayer wrong direction first data",
        "applayer detect protocol only one direction",
        "applayer mismatch protocol both directions",
        "tls multiple sni extensions",
        "tls invalid record type",
        # Informational - not security-relevant
        "ssh-2.0-go version string",
        "gnu/linux apt user-agent",
        "go-http-client user-agent",
        "go http client user-agent",
    ]

    for pattern in noisy_patterns:
        if pattern in sig_lower:
            return True

    if "application layer" in cat_lower and "not present" in sig_lower:
        return True

    return False


def _build_clean_description(
    rule_name: str,
    category: str,
    rule_id: str,
    src_ip: Optional[str],
    dst_ip: Optional[str],
    src_port: Any,
    dest_port: Any,
    proto: str,
    eve: Dict,
) -> str:
    """Build organized, clean description."""
    parts = []

    parts.append(f"Rule: {rule_name}")
    if rule_id:
        parts.append(f"SID: {rule_id}")
    if category:
        parts.append(f"Category: {category}")

    if src_ip or dst_ip or proto:
        flow = f"Flow: {proto} "
        if src_ip:
            flow += f"{src_ip}"
            if src_port:
                flow += f":{src_port}"
        flow += " → "
        if dst_ip:
            flow += f"{dst_ip}"
            if dest_port:
                flow += f":{dest_port}"
        else:
            flow += "?"
        parts.append(flow)

    http = eve.get("http", {}) or {}
    dns = eve.get("dns", {}) or {}
    tls = eve.get("tls", {}) or {}

    if http:
        http_method = http.get("http_method", "")
        http_host = http.get("hostname", "")
        http_status = http.get("status")
        http_ua = http.get("http_user_agent", "")
        http_xff = http.get("xff", "")
        http_parts = []
        if http_method:
            http_parts.append(http_method)
        if http_host:
            http_parts.append(http_host)
        if http_status:
            http_parts.append(f"status={http_status}")
        if http_ua:
            http_parts.append(f"UA={http_ua[:60]}")
        if http_xff:
            http_parts.append(f"XFF={http_xff}")
        if http_parts:
            parts.append(f"HTTP: {' '.join(http_parts)}")

    if dns and dns.get("query"):
        parts.append(f"DNS Query: {dns.get('query')}")

    if tls:
        tls_parts = []
        if tls.get("sni"):
            tls_parts.append(f"SNI={tls['sni']}")
        if tls.get("ja3", {}).get("hash"):
            tls_parts.append(f"JA3={tls['ja3']['hash'][:16]}...")
        if tls.get("version"):
            tls_parts.append(f"ver={tls['version']}")
        if tls_parts:
            parts.append(f"TLS: {' '.join(tls_parts)}")

    ssh = eve.get("ssh", {}) or {}
    if ssh:
        ssh_client = ssh.get("client", {})
        ssh_server = ssh.get("server", {})
        if ssh_client.get("software_version") or ssh_server.get("software_version"):
            parts.append(f"SSH: client={ssh_client.get('software_version', '?')} server={ssh_server.get('software_version', '?')}")

    fileinfo = eve.get("fileinfo", {}) or {}
    if fileinfo:
        filename = fileinfo.get("filename", "")
        md5 = fileinfo.get("md5", "")
        sha256 = fileinfo.get("sha256", "")
        if filename:
            parts.append(f"File: {filename}")
        if sha256:
            parts.append(f"SHA256: {sha256}")
        elif md5:
            parts.append(f"MD5: {md5}")

    flow = eve.get("flow", {}) or {}
    if flow and (flow.get("bytes_toclient") or flow.get("bytes_toserver")):
        bytes_to = flow.get("bytes_toclient", 0)
        bytes_from = flow.get("bytes_toserver", 0)
        parts.append(f"Flow: {bytes_from}B→ / {bytes_to}B←")

    return " | ".join(parts)


def _build_tags(rule_id: str, category: str, proto: str) -> list:
    """Build clean tag list."""
    tags = ["suricata"]
    
    if rule_id:
        tags.append(f"sid-{rule_id}")
    
    if category:
        clean_category = category.replace(" ", "-").lower()
        tags.append(f"cat-{clean_category}")
    
    if proto:
        tags.append(f"proto-{proto.upper()}")
    
    return tags


def _build_iocs(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    src_port: Any,
    dest_port: Any,
    eve: Dict,
) -> Dict:
    """Extract IOCs from Suricata alert."""
    iocs: Dict[str, list] = {}

    ips = list(filter(None, set([src_ip, dst_ip])))
    if ips:
        iocs["ip"] = ips

    if src_ip or dst_ip:
        ports = set()
        if src_port and src_ip:
            ports.add(str(src_port))
        if dest_port and dst_ip:
            ports.add(str(dest_port))
        if ports:
            iocs["port"] = sorted(list(ports))

    dns = eve.get("dns", {}) or {}
    dns_query = dns.get("query")
    if dns_query:
        iocs["domain"] = [dns_query]

    http = eve.get("http", {}) or {}
    http_host = http.get("hostname")
    http_url = http.get("url")
    
    if http_host:
        iocs.setdefault("domain", [])
        if http_host not in iocs["domain"]:
            iocs["domain"].append(http_host)
    
    if http_host and http_url:
        url = f"http://{http_host}{http_url}"
        iocs["url"] = [url]

    tls = eve.get("tls", {}) or {}
    tls_sni = tls.get("sni")
    if tls_sni:
        iocs.setdefault("domain", [])
        if tls_sni not in iocs["domain"]:
            iocs["domain"].append(tls_sni)
    tls_ja3 = tls.get("ja3", {}).get("hash")
    if tls_ja3:
        iocs.setdefault("ja3", []).append(tls_ja3)
    tls_ja3s = tls.get("ja3s", {}).get("hash")
    if tls_ja3s:
        iocs.setdefault("ja3s", []).append(tls_ja3s)

    fileinfo = eve.get("fileinfo", {}) or {}
    if fileinfo:
        for algo in ("sha256", "sha1", "md5"):
            h = fileinfo.get(algo)
            if h:
                iocs.setdefault("hash", []).append(f"{algo}:{h}")
        
        filename = fileinfo.get("filename")
        if filename:
            iocs["filepath"] = [filename]

    community_id = eve.get("community_id")
    if community_id:
        iocs.setdefault("community_id", []).append(community_id)

    return iocs


def _build_observables(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    src_port: Any,
    dest_port: Any,
    eve: Dict,
) -> List[Dict[str, Any]]:
    """Build structured observables array."""
    observables = []
    
    # IPs
    if src_ip:
        observables.append({"type": "ip", "value": src_ip, "direction": "src"})
    if dst_ip:
        observables.append({"type": "ip", "value": dst_ip, "direction": "dst"})
    
    # Ports
    if src_port:
        observables.append({"type": "port", "value": str(src_port), "direction": "src"})
    if dest_port:
        observables.append({"type": "port", "value": str(dest_port), "direction": "dst"})
    
    # Domain from DNS
    dns = eve.get("dns", {}) or {}
    dns_query = dns.get("query")
    if dns_query:
        observables.append({"type": "domain", "value": dns_query, "source": "dns"})
    
    # Domain from HTTP
    http = eve.get("http", {}) or {}
    http_host = http.get("hostname")
    if http_host:
        observables.append({"type": "domain", "value": http_host, "source": "http"})
    
    # Domain from TLS SNI
    tls = eve.get("tls", {}) or {}
    tls_sni = tls.get("sni")
    if tls_sni:
        observables.append({"type": "domain", "value": tls_sni, "source": "tls"})
    
    # JA3 hashes from TLS
    tls_ja3 = tls.get("ja3", {}).get("hash")
    if tls_ja3:
        observables.append({"type": "ja3", "value": tls_ja3, "source": "tls"})
    tls_ja3s = tls.get("ja3s", {}).get("hash")
    if tls_ja3s:
        observables.append({"type": "ja3s", "value": tls_ja3s, "source": "tls"})
    
    # URL from HTTP
    http_url = http.get("url")
    if http_host and http_url:
        full_url = f"http://{http_host}{http_url}"
        observables.append({"type": "url", "value": full_url})
    
    # File hashes
    fileinfo = eve.get("fileinfo", {}) or {}
    if fileinfo:
        for algo in ("md5", "sha1", "sha256"):
            h = fileinfo.get(algo)
            if h:
                observables.append({"type": "hash", "value": h, "algo": algo})
        
        filename = fileinfo.get("filename")
        if filename:
            observables.append({"type": "filepath", "value": filename})
    
    # Community ID for cross-sensor correlation
    community_id = eve.get("community_id")
    if community_id:
        observables.append({"type": "community_id", "value": community_id})
    
    return observables


def _build_metadata(
    alert_data: Dict,
    suricata_eve: Dict,
    flow: Dict,
    hostname: str,
    src_port: Any,
    dest_port: Any,
    proto: str,
    rule_id: str,
    category: str,
) -> Dict[str, Any]:
    """Build Suricata-specific metadata."""
    metadata = {
        "hostname": hostname,
    }
    
    # Alert details
    if alert_data.get("signature_id"):
        metadata["signature_id"] = alert_data.get("signature_id")
    if alert_data.get("gid"):
        metadata["alert_gid"] = alert_data.get("gid")
    if alert_data.get("rev"):
        metadata["alert_rev"] = alert_data.get("rev")
    if category:
        metadata["category"] = category
    
    # Network info
    if proto:
        metadata["protocol"] = proto
    
    if src_port:
        metadata["src_port"] = src_port
    if dest_port:
        metadata["dst_port"] = dest_port
    
    # Flow info from eve
    if flow:
        if flow.get("src_ip"):
            metadata["flow_src_ip"] = flow.get("src_ip")
        if flow.get("dest_ip"):
            metadata["flow_dst_ip"] = flow.get("dest_ip")
        if flow.get("src_port"):
            metadata["flow_src_port"] = flow.get("src_port")
        if flow.get("dest_port"):
            metadata["flow_dst_port"] = flow.get("dest_port")
    
    # Interface
    in_iface = suricata_eve.get("in_iface")
    if in_iface:
        metadata["ingress_interface"] = in_iface
    
    # Event type
    event_type = suricata_eve.get("event_type")
    if event_type:
        metadata["event_type"] = event_type
    
    # Packet source
    pkt_src = suricata_eve.get("pkt_src")
    if pkt_src:
        metadata["packet_source"] = pkt_src
    
    # HTTP details
    http = suricata_eve.get("http", {}) or {}
    if http:
        http_method = http.get("http_method")
        if http_method:
            metadata["http_method"] = http_method
        http_host = http.get("hostname")
        if http_host:
            metadata["http_host"] = http_host
        http_url = http.get("url")
        if http_url:
            metadata["http_url"] = http_url
        http_user_agent = http.get("http_user_agent")
        if http_user_agent:
            metadata["http_user_agent"] = http_user_agent
        http_status = http.get("status")
        if http_status:
            metadata["http_status"] = http_status
        http_xff = http.get("xff")
        if http_xff:
            metadata["http_xff"] = http_xff
        http_referer = http.get("http_refer")
        if http_referer:
            metadata["http_referer"] = http_referer
    
    # DNS details
    dns = suricata_eve.get("dns", {}) or {}
    if dns:
        dns_query = dns.get("query")
        if dns_query:
            metadata["dns_query"] = dns_query
        dns_rcode = dns.get("rcode")
        if dns_rcode is not None:
            metadata["dns_rcode"] = dns_rcode
        dns_rrname = dns.get("rrname")
        if dns_rrname:
            metadata["dns_rrname"] = dns_rrname
        dns_type = dns.get("rrtype")
        if dns_type:
            metadata["dns_type"] = dns_type
    
    # TLS details
    tls = suricata_eve.get("tls", {}) or {}
    if tls:
        tls_sni = tls.get("sni")
        if tls_sni:
            metadata["tls_sni"] = tls_sni
        tls_version = tls.get("version")
        if tls_version:
            metadata["tls_version"] = tls_version
        tls_subject = tls.get("subject")
        if tls_subject:
            metadata["tls_subject"] = tls_subject
        tls_issuer = tls.get("issuer")
        if tls_issuer:
            metadata["tls_issuer"] = tls_issuer
        tls_fingerprint = tls.get("fingerprint")
        if tls_fingerprint:
            metadata["tls_fingerprint"] = tls_fingerprint
        tls_ja3 = tls.get("ja3", {}).get("hash")
        if tls_ja3:
            metadata["tls_ja3"] = tls_ja3
        tls_ja3s = tls.get("ja3s", {}).get("hash")
        if tls_ja3s:
            metadata["tls_ja3s"] = tls_ja3s
    
    # SSH details
    ssh = suricata_eve.get("ssh", {}) or {}
    if ssh:
        ssh_client = ssh.get("client", {})
        if ssh_client.get("software_version"):
            metadata["ssh_client_version"] = ssh_client["software_version"]
        if ssh_client.get("proto_version"):
            metadata["ssh_proto_version"] = ssh_client["proto_version"]
        ssh_server = ssh.get("server", {})
        if ssh_server.get("software_version"):
            metadata["ssh_server_version"] = ssh_server["software_version"]
    
    # Flow volume (critical for exfiltration/beaconing detection)
    if flow:
        if flow.get("bytes_toclient") is not None:
            metadata["flow_bytes_toclient"] = flow["bytes_toclient"]
        if flow.get("bytes_toserver") is not None:
            metadata["flow_bytes_toserver"] = flow["bytes_toserver"]
        if flow.get("pkts_toclient") is not None:
            metadata["flow_pkts_toclient"] = flow["pkts_toclient"]
        if flow.get("pkts_toserver") is not None:
            metadata["flow_pkts_toserver"] = flow["pkts_toserver"]
        if flow.get("start"):
            metadata["flow_start"] = flow["start"]
        if flow.get("end"):
            metadata["flow_end"] = flow["end"]
    
    # Community ID (cross-sensor flow correlation)
    community_id = suricata_eve.get("community_id")
    if community_id:
        metadata["community_id"] = community_id
    
    # VLAN
    vlan = suricata_eve.get("vlan")
    if vlan:
        metadata["vlan"] = vlan
    
    # Network direction
    network = suricata_eve.get("network", {}) or {}
    if network.get("direction"):
        metadata["network_direction"] = network["direction"]
    if network.get("transport"):
        metadata["network_transport"] = network["transport"]
    
    return metadata


def _map_category_to_severity(category: str, signature: str = "") -> int:
    """Map Suricata category to severity (1-4)
    
    Severity levels:
    1 = low (informational, reconnaissance, misc activity)
    2 = medium (threat intel blocklists, suspicious traffic, anomalies)
    3 = high (active attacks, targeted exploits, port scans)
    4 = critical (active exploitation, known C2, data exfiltration)
    """
    if not category:
        return 2

    category_lower = category.lower()
    sig_lower = signature.lower()
    
    # === LOW: ICMP PING (just network probes, no actual attack) ===
    # Must check this FIRST before any other category
    if 'icmp ping' in sig_lower or 'icmp' in sig_lower and 'ping' in sig_lower:
        return 1
    if sig_lower.startswith('gpl icmp') or sig_lower.startswith('et icmp'):
        return 1
    
    # Critical: active exploitation, known C2, data exfiltration
    if any(x in category_lower for x in [
        'attempted administrator',
        'successful administrator',
        'successful user',
        'web application attack',
        'trojan',
        'c2',
        'command and control',
        'data exfiltration',
    ]):
        return 4
    
    # Check signature for known critical indicators
    if any(x in sig_lower for x in [
        'known compromised',
        'hostile host',
        'apt',
        'malware c2',
        'exploit kit',
    ]):
        return 4
    
    # High: active attacks, targeted exploits, port scans
    if any(x in sig_lower for x in [
        'sql injection',
        'xss',
        'command injection',
        'rce',
        'remote code execution',
        'suspicious inbound',
    ]):
        # But NOT if it's a threat intel blocklist match
        if any(x in sig_lower for x in [
            'drop ',
            'cins active threat',
            'spamhaus',
            'block listed',
            'threat intelligence',
        ]):
            return 2
        return 3
    
    # High: actual attack indicators (not passive blocklist matches)
    if any(x in category_lower for x in [
        'malware',
        'intrusion',
        'attempted information leak',
    ]):
        return 3
    
    # Medium: threat intel blocklists (passive matches, not active attacks)
    # MUST check this BEFORE 'potentially bad traffic' category
    if any(x in sig_lower for x in [
        'drop ',
        'cins active threat',
        'spamhaus',
        'block listed',
        'threat intelligence',
    ]):
        return 2
    
    # High: potentially bad traffic (but NOT threat intel blocklists)
    if 'potentially bad traffic' in category_lower:
        return 3
    
    # Medium: misc attack category (includes blocklist matches)
    if 'misc attack' in category_lower:
        return 2
    
    # Medium: scans, protocol issues, anomalies
    if any(x in category_lower for x in [
        'network scan',
        'detection of a network scan',
        'suspicious',
        'anomaly',
        'generic protocol',
        'not suspicious',
        'misc activity',
    ]):
        return 2
    
    # Low: reconnaissance, DNS queries, info gathering
    if any(x in sig_lower for x in [
        'scan',
        'nmap',
        'zmap',
        'masscan',
        'sipvicious',
        'friendly-scanner',
        'dns named version',
        'dns zone transfer',
    ]):
        return 1
    
    # Default: low
    return 1


def _determine_attack_status(event_time: str) -> str:
    """Return 'active' if event_time is within last 15 minutes, else 'stopped'."""
    from datetime import datetime, timezone, timedelta
    try:
        ts = datetime.fromisoformat(str(event_time).replace("Z", "+00:00"))
        if datetime.now(timezone.utc) - ts <= timedelta(minutes=15):
            return "active"
    except Exception:
        pass
    return "stopped"


def _extract_hostname(doc: Dict[str, Any]) -> str:
    host = doc.get("host", {})
    if isinstance(host, dict):
        return host.get("name", "")
    elif host:
        return str(host)
    return ""
