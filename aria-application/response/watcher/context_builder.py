def _build_investigation_context(incident: dict, alerts: list[dict]) -> dict:
    """Build comprehensive context for AI analysis - ALL data preserved."""
    from collections import defaultdict
    import re
    from datetime import datetime

    # ========== COMPREHENSIVE DATA EXTRACTION ==========

    # Multiple data structures for different analysis needs
    timeline = []
    source_ips = set()
    dest_ips = set()
    hostnames = set()
    usernames = set()
    processes = set()
    file_paths = set()
    domains = set()
    hashes = set()
    ports = set()
    protocols = set()
    services = set()
    iocs = defaultdict(set)
    mitre_tactics = set()
    mitre_techniques = set()
    tags = set()
    alert_types = set()
    alert_sources = defaultdict(int)
    rule_names = []

    # Behavioral indicators
    behavioral = defaultdict(int)

    # Full alert data preservation (for detailed analysis)
    all_alerts_data = []

    for idx, alert in enumerate(alerts):
        # ====== BASIC EXTRACTION ======
        timestamp = alert.get("created_at", "") or alert.get("timestamp", "")

        # Safely extract source IP
        alert_source = alert.get("source")
        if isinstance(alert_source, dict):
            src_ip = alert_source.get("ip")
        else:
            src_ip = alert.get("source_ip")

        # Safely extract dest IP and hostname
        alert_dest = alert.get("destination")
        if isinstance(alert_dest, dict):
            hostname = alert_dest.get("hostname")
            dst_ip = alert_dest.get("ip")
        else:
            hostname = alert.get("hostname")
            dst_ip = alert.get("dest_ip")

        # Port and protocol
        src_port = alert.get("source_port")
        dest_port = alert.get("dest_port")
        protocol = alert.get("protocol", "").upper()

        # Title, description, rule_name
        title = alert.get("title", "")
        description = alert.get("description", "")
        rule_name = alert.get("rule_name", "") or title

        # Source system
        source_system = alert.get("source", "unknown")
        if isinstance(source_system, dict):
            source_system = source_system.get("name", "unknown")
        alert_sources[source_system] += 1
        rule_names.append(rule_name)

        # Severity
        severity = alert.get("severity", "medium")

        # ====== TIMELINE ======
        timeline.append({
            "idx": idx + 1,
            "time": timestamp,
            "severity": severity,
            "source": source_system,
            "title": title,
            "hostname": hostname,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "port": dest_port,
            "protocol": protocol,
        })

        # ====== IOCs EXTRACTION ======
        if src_ip and src_ip not in ["", "unknown", "null"]:
            source_ips.add(src_ip)
            iocs["source_ips"].add(src_ip)

            # Behavioral: detect scan patterns
            if src_ip.startswith(("10.", "192.168", "172.")):
                behavioral["internal_attacker"] += 1
            else:
                behavioral["external_attacker"] += 1

        if dst_ip and dst_ip not in ["", "unknown", "null"]:
            dest_ips.add(dst_ip)
            iocs["dest_ips"].add(dst_ip)

        if hostname and hostname not in ["", "unknown", "null"]:
            hostnames.add(hostname)

        # Ports and services
        if dest_port:
            try:
                ports.add(int(dest_port))
                # Common port mapping
                port_services = {
                    22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
                    80: "http", 443: "https", 3306: "mysql", 5432: "postgres",
                    6379: "redis", 8080: "http-proxy", 1433: "mssql",
                    21: "ftp", 110: "pop3", 143: "imap", 445: "smb",
                    3389: "rdp", 27017: "mongodb"
                }
                if dest_port in port_services:
                    services.add(port_services[dest_port])
            except (ValueError, TypeError, KeyError):
                pass

        if protocol:
            protocols.add(protocol)

        # ====== ADVANCED IOCs ======
        # Extract usernames
        for field in [title, description]:
            user_matches = re.findall(r'(?:user|username|account)[:\s=]+([a-zA-Z0-9_-]+)', str(field), re.I)
            for u in user_matches:
                if len(u) > 2 and len(u) < 32:
                    usernames.add(u)

        # Extract file paths
        path_matches = re.findall(r'(/[a-zA-Z0-9_./-]+)', str(description))
        for p in path_matches:
            if len(p) > 3 and not p.startswith("/proc"):
                file_paths.add(p)

        # Extract domains
        domain_matches = re.findall(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})', str(description))
        for d in domain_matches:
            if not d.startswith(("www", "http", "ftp")):
                domains.add(d)

        # Extract hashes
        hash_patterns = [
            (r'\b([a-fA-F0-9]{32})\b', "md5"),
            (r'\b([a-fA-F0-9]{40})\b', "sha1"),
            (r'\b([a-fA-F0-9]{64})\b', "sha256"),
        ]
        for pattern, hash_type in hash_patterns:
            matches = re.findall(pattern, str(description))
            for h in matches:
                hashes.add(f"{hash_type}:{h}")

        # ====== TAGS AND MITRE ======
        alert_tags = alert.get("tags", [])
        if isinstance(alert_tags, list):
            for tag in alert_tags:
                if isinstance(tag, str):
                    tags.add(tag)

                    # MITRE extraction
                    if tag.startswith("mitre-tactic-"):
                        mitre_tactics.add(tag.replace("mitre-tactic-", ""))
                    elif tag.startswith("mitre-"):
                        if "-" in tag:
                            parts = tag.split("-", 1)
                            if len(parts) > 1:
                                if parts[1].isdigit():
                                    mitre_techniques.add(parts[0].replace("mitre-", ""))
                                    mitre_tactics.add(_technique_to_tactic(parts[0]))
                                else:
                                    mitre_tactics.add(parts[1])

        # ====== ALERT TYPE DETECTION ======
        alert_types.add(source_system)

        # ====== SMART BEHAVIORAL PATTERN DETECTION ======
        title_lower = title.lower()
        desc_lower = description.lower() if description else ""
        rule_lower = rule_name.lower()
        combined = f"{title_lower} {desc_lower} {rule_lower}"

        # --- AUTHENTICATION ATTACKS (strict - only actual failures/attacks) ---
        # Exclude success/session events explicitly
        is_auth_success = any(x in combined for x in [
            "authentication success", "login session opened", "login session closed",
            "session opened for user", "session closed for user", "accepted password",
            "accepted publickey"
        ])
        is_auth_failure = any(x in combined for x in [
            "brute force", "authentication failure", "authentication failed",
            "failed password", "invalid user", "non-existent user",
            "multiple failed login", "maximum authentication attempts",
            "user login failed", "missed the password"
        ])

        if is_auth_failure and not is_auth_success:
            behavioral["auth_failure"] += 1
        elif is_auth_success:
            behavioral["auth_success"] += 1

        # --- RECONNAISSANCE / SCANNING ---
        if any(x in combined for x in [
            "scan", "port scan", "probe", "reconnaissance", "suspicious inbound",
            "unexpected udp", "unexpected tcp"
        ]):
            behavioral["reconnaissance"] += 1

        # --- CODE EXECUTION ---
        if any(x in combined for x in [
            "execution", "shell", "cmd execution", "bash", "powershell",
            "command execution", "reverse shell", "bind shell"
        ]):
            behavioral["execution"] += 1

        # --- DATA EXFILTRATION ---
        if any(x in combined for x in [
            "exfiltration", "data transfer", "large upload", "large download",
            "unusual outbound", "covert channel"
        ]):
            behavioral["exfiltration"] += 1

        # --- MALWARE ---
        if any(x in combined for x in [
            "malware", "virus", "trojan", "backdoor", "ransomware",
            "cryptominer", "rootkit"
        ]):
            behavioral["malware"] += 1

        # --- WEB ATTACK ---
        if any(x in combined for x in [
            "sql injection", "xss", "cross-site", "csrf", "path traversal",
            "remote file inclusion", "local file inclusion", "command injection",
            "web attack", "web shell"
        ]):
            behavioral["web_attack"] += 1

        # --- DoS / DDoS ---
        if any(x in combined for x in [
            "denial of service", "ddos", "flood", "amplification",
            "syn flood", "resource exhaustion"
        ]):
            behavioral["dos"] += 1

        # --- PRIVILEGE ESCALATION ---
        if any(x in combined for x in [
            "privilege escalation", "sudo", "to root", "uid 0",
            "capabilities", "setuid"
        ]):
            behavioral["privilege_escalation"] += 1

        # --- CONTAINER ESCAPE (Falco-specific) ---
        if any(x in combined for x in [
            "write below", "read sensitive file", "bpf program",
            "unexpected connection", "contact ec2", "contact metadata",
            "terminal shell", "modify binary", "exec binary"
        ]):
            behavioral["container_escape"] += 1

        # --- FILE INTEGRITY ---
        if any(x in combined for x in [
            "integrity checksum", "file added", "file deleted",
            "file modified", "permission change", "unauthorized change"
        ]):
            behavioral["file_integrity"] += 1

        # --- SYSTEM MODIFICATION ---
        if any(x in combined for x in [
            "new user", "new group", "user added", "group added",
            "dpkg installed", "package installed", "rpm installed",
            "kernel module", "systemd service"
        ]):
            behavioral["system_modification"] += 1

        # --- LATERAL MOVEMENT ---
        if any(x in combined for x in [
            "lateral movement", "pass the hash", "pass the ticket",
            "remote service", "wmi execution", "psexec"
        ]):
            behavioral["lateral_movement"] += 1

        # --- NETWORK ANOMALY ---
        if any(x in combined for x in [
            "poor reputation", "cins", "tor exit", "proxy",
            "suspicious inbound", "suspicious outbound", "unexpected traffic"
        ]):
            behavioral["network_anomaly"] += 1

        # ====== PRESERVE FULL ALERT DATA ======
        all_alerts_data.append({
            "idx": idx + 1,
            "alert_id": alert.get("id"),
            "timestamp": timestamp,
            "severity": severity,
            "source": source_system,
            "title": title,
            "description": description[:500] if description else "",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "hostname": hostname,
            "dest_port": dest_port,
            "protocol": protocol,
            "tags": list(alert_tags) if isinstance(alert_tags, list) else [],
            "raw_fields": {k: v for k, v in alert.items()
                          if k not in ["id", "created_at", "timestamp", "title", "description"]}
        })

    # ====== SORT TIMELINE ======
    timeline.sort(key=lambda x: x["time"] or "")

    # ====== ENHANCED CONTEXT-AWARE ANALYSIS ======
    auth_analysis = _analyze_authentication_patterns(alerts, timeline)

    # ====== CALCULATE DURATION ======
    duration_minutes = None
    if timeline and timeline[0].get("time") and timeline[-1].get("time"):
        try:
            start = datetime.fromisoformat(timeline[0]["time"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(timeline[-1]["time"].replace("Z", "+00:00"))
            duration_minutes = int((end - start).total_seconds() / 60)
        except (ValueError, TypeError, KeyError):
            pass

    # ====== STRUCTURED RAW-FIELD EXTRACTION (P2.1) ======
    network_evidence = {
        "http_requests": [],
        "tls_connections": [],
        "dns_queries": [],
        "ssh_sessions": [],
        "flow_volumes": [],
        "ja3_fingerprints": set(),
        "user_agents": set(),
        # Suricata-rich metadata (preserved for analyst review)
        "payloads": [],
        "geo_locations": [],
        "ips_actions": set(),
        "directions": set(),
        "community_ids": set(),
        "categories": set(),
        "signature_ids": set(),
        "flow_ids": set(),
    }
    endpoint_evidence = {
        "commands": [],
        "processes": [],
        "file_changes": [],
        "registry_changes": [],
        "users": [],
        "windows_events": [],
    }
    
    for alert in alerts:
        metadata = alert.get("metadata", {}) or {}
        source_system = alert.get("source", "")
        
        # Suricata network evidence
        if source_system in ("suricata", "filebeat"):
            if metadata.get("http_url") or metadata.get("http_host"):
                network_evidence["http_requests"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "host": metadata.get("http_host"),
                    "url": metadata.get("http_url"),
                    "method": metadata.get("http_method"),
                    "status": metadata.get("http_status"),
                    "user_agent": metadata.get("http_user_agent"),
                    "xff": metadata.get("http_xff"),
                    "source_ip": alert.get("source_ip"),
                })
            if metadata.get("tls_sni") or metadata.get("tls_ja3"):
                network_evidence["tls_connections"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "sni": metadata.get("tls_sni"),
                    "ja3": metadata.get("tls_ja3"),
                    "ja3s": metadata.get("tls_ja3s"),
                    "version": metadata.get("tls_version"),
                    "subject": metadata.get("tls_subject"),
                    "source_ip": alert.get("source_ip"),
                })
                if metadata.get("tls_ja3"):
                    network_evidence["ja3_fingerprints"].add(metadata["tls_ja3"])
            if metadata.get("dns_query"):
                network_evidence["dns_queries"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "query": metadata.get("dns_query"),
                    "rcode": metadata.get("dns_rcode"),
                    "type": metadata.get("dns_type"),
                })
            if metadata.get("ssh_client_version"):
                network_evidence["ssh_sessions"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "client_version": metadata.get("ssh_client_version"),
                    "server_version": metadata.get("ssh_server_version"),
                    "proto_version": metadata.get("ssh_proto_version"),
                })
            if metadata.get("flow_bytes_toclient") is not None:
                network_evidence["flow_volumes"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "bytes_toclient": metadata.get("flow_bytes_toclient"),
                    "bytes_toserver": metadata.get("flow_bytes_toserver"),
                    "pkts_toclient": metadata.get("flow_pkts_toclient"),
                    "pkts_toserver": metadata.get("flow_pkts_toserver"),
                })
            if metadata.get("http_user_agent"):
                network_evidence["user_agents"].add(metadata["http_user_agent"])
            # Rich Suricata metadata for analyst review
            if metadata.get("payload_printable"):
                network_evidence["payloads"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "payload": metadata["payload_printable"][:500],
                    "source_ip": alert.get("source_ip"),
                })
            if metadata.get("_geo"):
                geo = metadata["_geo"]
                if isinstance(geo, dict):
                    network_evidence["geo_locations"].append({
                        "time": alert.get("timestamp") or alert.get("created_at"),
                        "country": geo.get("country_name") or geo.get("country_code"),
                        "city": geo.get("city_name"),
                        "location": geo.get("location"),
                        "source_ip": alert.get("source_ip"),
                    })
            if metadata.get("ips_action"):
                network_evidence["ips_actions"].add(metadata["ips_action"])
            if metadata.get("network_direction"):
                network_evidence["directions"].add(metadata["network_direction"])
            if metadata.get("community_id"):
                network_evidence["community_ids"].add(metadata["community_id"])
            if alert.get("category"):
                network_evidence["categories"].add(alert["category"])
            if metadata.get("signature_id"):
                network_evidence["signature_ids"].add(str(metadata["signature_id"]))
            elif metadata.get("sid"):
                network_evidence["signature_ids"].add(str(metadata["sid"]))
            if metadata.get("flow_id"):
                network_evidence["flow_ids"].add(str(metadata["flow_id"]))

        # Wazuh endpoint evidence
        if source_system == "wazuh":
            if metadata.get("data_command"):
                endpoint_evidence["commands"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "command": metadata["data_command"],
                    "user": metadata.get("data_src_user") or metadata.get("data_dst_user"),
                    "host": alert.get("hostname"),
                })
            if metadata.get("data_process"):
                endpoint_evidence["processes"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "process": metadata["data_process"],
                    "pid": metadata.get("data_process_id"),
                    "parent": metadata.get("data_parent_process"),
                    "user": metadata.get("data_src_user"),
                    "host": alert.get("hostname"),
                })
            if metadata.get("data_file") or metadata.get("data_path"):
                endpoint_evidence["file_changes"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "file": metadata.get("data_file") or metadata.get("data_path"),
                    "host": alert.get("hostname"),
                    "action": metadata.get("data_action"),
                })
            if metadata.get("win_event_id"):
                endpoint_evidence["windows_events"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "event_id": metadata["win_event_id"],
                    "channel": metadata.get("win_channel"),
                    "target_user": metadata.get("win_target_user"),
                    "image": metadata.get("win_image_path"),
                    "command_line": metadata.get("win_command_line"),
                    "host": alert.get("hostname"),
                })
            if metadata.get("win_target_user") or metadata.get("data_src_user"):
                endpoint_evidence["users"].append({
                    "time": alert.get("timestamp") or alert.get("created_at"),
                    "user": metadata.get("win_target_user") or metadata.get("data_src_user"),
                    "host": alert.get("hostname"),
                })
    
    # Deduplicate and limit
    for key in ["http_requests", "tls_connections", "dns_queries", "ssh_sessions", "flow_volumes", "payloads", "geo_locations"]:
        seen = set()
        unique = []
        for item in network_evidence[key]:
            item_hash = str(item.get("url") or item.get("sni") or item.get("query") or item.get("client_version") or item.get("payload") or item.get("country") or "")
            if item_hash and item_hash not in seen:
                seen.add(item_hash)
                unique.append(item)
        network_evidence[key] = unique[:20]  # Limit to 20 unique items
    network_evidence["ja3_fingerprints"] = sorted(list(network_evidence["ja3_fingerprints"]))[:10]
    network_evidence["user_agents"] = sorted(list(network_evidence["user_agents"]))[:10]
    # Convert sets to sorted lists for JSON serialization
    network_evidence["ips_actions"] = sorted(list(network_evidence["ips_actions"]))
    network_evidence["directions"] = sorted(list(network_evidence["directions"]))
    network_evidence["community_ids"] = sorted(list(network_evidence["community_ids"]))
    network_evidence["categories"] = sorted(list(network_evidence["categories"]))
    network_evidence["signature_ids"] = sorted(list(network_evidence["signature_ids"]))
    network_evidence["flow_ids"] = sorted(list(network_evidence["flow_ids"]))
    
    for key in ["commands", "processes", "file_changes", "windows_events", "users"]:
        endpoint_evidence[key] = endpoint_evidence[key][:20]

    attack_type = _determine_attack_type(
        behavioral, iocs, mitre_tactics, services,
        auth_analysis, alert_sources, rule_names, len(alerts)
    )

    # ====== PROOF-OF-COMPROMISE DETECTION (P2.2) ======
    proof_of_compromise = {
        "compromised": False,
        "indicators": [],
        "confidence": "low",
    }
    
    # Indicator 1: Failed auth followed by successful auth from same IP
    if auth_analysis["is_suspicious"] and auth_analysis["suspicious_timeline"]:
        proof_of_compromise["compromised"] = True
        proof_of_compromise["confidence"] = "high"
        for ip in auth_analysis["suspicious_timeline"]:
            proof_of_compromise["indicators"].append(
                f"IP {ip} had failed logins followed by successful authentication"
            )
    
    # Indicator 2: Web attack + file modification on same host
    if attack_type in ("web_attack", "execution"):
        web_attack_hosts = set()
        file_change_hosts = set()
        for alert in alerts:
            src = alert.get("source", "")
            host = alert.get("hostname", "")
            if src in ("suricata", "filebeat") and host:
                web_attack_hosts.add(host)
            if src == "wazuh" and host and alert.get("metadata", {}).get("data_file"):
                file_change_hosts.add(host)
        common_hosts = web_attack_hosts & file_change_hosts
        if common_hosts:
            proof_of_compromise["compromised"] = True
            if proof_of_compromise["confidence"] == "low":
                proof_of_compromise["confidence"] = "medium"
            for host in common_hosts:
                proof_of_compromise["indicators"].append(
                    f"Host {host} had web attack followed by file modification"
                )
    
    # Indicator 3: Malware alert + suspicious process execution
    if attack_type in ("malware", "c2"):
        malware_hosts = set()
        suspicious_procs = set()
        for alert in alerts:
            host = alert.get("hostname", "")
            if alert.get("source") == "wazuh" and alert.get("metadata", {}).get("data_process"):
                proc = alert["metadata"]["data_process"]
                if any(p in proc.lower() for p in ["powershell", "cmd.exe", "bash", "python", "perl"]):
                    suspicious_procs.add(f"{host}:{proc}")
            if host and alert.get("source") in ("suricata", "wazuh"):
                malware_hosts.add(host)
        if suspicious_procs:
            proof_of_compromise["compromised"] = True
            if proof_of_compromise["confidence"] == "low":
                proof_of_compromise["confidence"] = "medium"
            for proc in suspicious_procs:
                proof_of_compromise["indicators"].append(
                    f"Suspicious process execution detected: {proc}"
                )
    
    # Indicator 4: Privilege escalation + root access
    if attack_type == "privilege_escalation" or behavioral.get("privilege_escalation", 0) > 0:
        if auth_analysis["root_access"]:
            proof_of_compromise["compromised"] = True
            proof_of_compromise["confidence"] = "high"
            proof_of_compromise["indicators"].append(
                f"Root access detected after privilege escalation signals"
            )

    # ====== ASSET CRITICALITY INFERENCE (P2.3) ======
    asset_roles = {}
    for alert in alerts:
        host = alert.get("hostname", "")
        if not host:
            continue
        if host not in asset_roles:
            # Infer role from hostname patterns and ports
            role = "unknown"
            h_lower = host.lower()
            if any(x in h_lower for x in ["web", "www", "nginx", "apache", "frontend"]):
                role = "web"
            elif any(x in h_lower for x in ["db", "database", "mysql", "postgres", "mongo", "sql"]):
                role = "database"
            elif any(x in h_lower for x in ["dc", "domain", "ad.", "ldap"]):
                role = "domain_controller"
            elif any(x in h_lower for x in ["mail", "smtp", "exchange", "mx"]):
                role = "mail"
            elif any(x in h_lower for x in ["dev", "test", "staging", "lab"]):
                role = "development"
            else:
                # Infer from ports
                metadata = alert.get("metadata", {}) or {}
                dst_port = metadata.get("dst_port") or alert.get("dest_port")
                if dst_port:
                    port = int(dst_port) if isinstance(dst_port, (int, str)) and str(dst_port).isdigit() else 0
                    if port in (80, 443, 8080, 8443):
                        role = "web"
                    elif port in (22, 3389):
                        role = "bastion"
                    elif port in (3306, 5432, 1433, 27017):
                        role = "database"
                    elif port in (25, 587, 993):
                        role = "mail"
            asset_roles[host] = role

    # ====== DETERMINE HIGHEST SEVERITY ======
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    highest_severity = "medium"
    max_severity = 2
    for alert in alerts:
        sev = alert.get("severity", "medium").lower()
        if sev in severity_map and severity_map[sev] > max_severity:
            highest_severity = sev
            max_severity = severity_map[sev]

    # ====== RISK SCORE CALCULATION ======
    risk_score = _calculate_risk_score(
        severity_map.get(highest_severity, 2),
        len(source_ips),
        len(dest_ips),
        len(alerts),
        duration_minutes or 0,
        behavioral
    )

    # Enhance risk score based on auth analysis
    if auth_analysis["is_suspicious"]:
        risk_score = min(risk_score + 20, 100)

    # ====== BUILD COMPREHENSIVE CONTEXT ======
    return {
        "incident": incident,

        # Full timeline - ALL events preserved
        "timeline": timeline,
        "timeline_count": len(timeline),

        # Authentication pattern analysis (smart filtering)
        "auth_analysis": auth_analysis,

        # Complete IOC set
        "all_iocs": {
            "source_ips": sorted(list(iocs.get("source_ips", set()))),
            "dest_ips": sorted(list(iocs.get("dest_ips", set()))),
            "hostnames": sorted(list(hostnames)),
            "usernames": sorted(list(usernames)),
            "domains": sorted(list(domains)),
            "file_paths": sorted(list(file_paths)),
            "hashes": sorted(list(hashes)),
            "ports": sorted([int(p) for p in ports]),
            "services": sorted(list(services)),
            "protocols": sorted(list(protocols)),
        },

        # MITRE
        "mitre_tactics": sorted(list(mitre_tactics)),
        "mitre_techniques": sorted(list(mitre_techniques)),

        # Assets
        "hostnames": sorted(list(hostnames)),
        "source_ips": sorted(list(source_ips)),
        "dest_ips": sorted(list(dest_ips)),

        # Statistics
        "duration_minutes": duration_minutes,
        "alert_count": len(alerts),
        "highest_severity": highest_severity,
        "risk_score": risk_score,

        # Behavioral analysis
        "behavioral_indicators": dict(behavioral),
        "attack_type": attack_type,
        "alert_sources": dict(alert_sources),

        # All tags
        "tags": sorted(list(tags)),
        "alert_types": sorted(list(alert_types)),

        # Full alert data for deep analysis
        "alerts": all_alerts_data,

        # Structured network and endpoint evidence
        "network_evidence": network_evidence,
        "endpoint_evidence": endpoint_evidence,
        
        # Proof of compromise assessment
        "proof_of_compromise": proof_of_compromise,
        
        # Asset criticality
        "asset_roles": asset_roles,

        # Summary stats
        "summary": {
            "unique_attackers": len(source_ips),
            "unique_targets": len(dest_ips),
            "unique_hosts": len(hostnames),
            "attack_duration": duration_minutes,
            "total_alerts": len(alerts),
            "primary_attack_method": attack_type,
            # Auth analysis summary
            "failed_login_count": len(auth_analysis["failed_logins"]),
            "successful_login_count": len(auth_analysis["successful_logins"]),
            "root_access_count": len(auth_analysis["root_access"]),
            "is_suspicious_auth": auth_analysis["is_suspicious"],
            "auth_risk_indicators": auth_analysis["risk_indicators"],
            # Compromise assessment summary
            "compromised": proof_of_compromise["compromised"],
            "compromise_confidence": proof_of_compromise["confidence"],
            "compromise_indicators": proof_of_compromise["indicators"],
            # Evidence counts
            "http_requests": len(network_evidence["http_requests"]),
            "tls_connections": len(network_evidence["tls_connections"]),
            "dns_queries": len(network_evidence["dns_queries"]),
            "commands_observed": len(endpoint_evidence["commands"]),
            "processes_observed": len(endpoint_evidence["processes"]),
            "file_changes_observed": len(endpoint_evidence["file_changes"]),
            "windows_events_observed": len(endpoint_evidence["windows_events"]),
            # Suricata-rich evidence counts
            "payloads_observed": len(network_evidence["payloads"]),
            "geo_locations_observed": len(network_evidence["geo_locations"]),
            "ips_actions": len(network_evidence["ips_actions"]),
            "signature_ids": len(network_evidence["signature_ids"]),
            "flow_ids": len(network_evidence["flow_ids"]),
            "categories": len(network_evidence["categories"]),
        }
    }


def _technique_to_tactic(technique: str) -> str:
    """Map MITRE technique to tactic."""
    technique_tactic_map = {
        "T1059": "Execution", "T1204": "Execution", "T1203": "Execution",
        "T1566": "Initial Access", "T1190": "Initial Access", "T1133": "Initial Access",
        "T1005": "Collection", "T1119": "Collection",
        "T1041": "Exfiltration", "T1048": "Exfiltration",
        "T1053": "Execution", "T1200": "Privilege Escalation",
        "T1068": "Privilege Escalation", "T1548": "Privilege Escalation",
        "T1082": "Discovery", "T1087": "Discovery", "T1083": "Discovery",
        "T1040": "Discovery", "T1086": "Discovery",
    }
    return technique_tactic_map.get(technique, "unknown")


def _determine_attack_type(
    behavioral: dict,
    iocs: dict,
    mitre_tactics: set,
    services: set,
    auth_analysis: dict,
    alert_sources: dict,
    rule_names: list,
    total_alerts: int
) -> str:
    """
    Determine primary attack type from behavioral indicators, alert sources,
    rule names, and authentication analysis.

    Uses a multi-factor scoring system with confidence thresholds and ratio checks
    to avoid over-classification.
    """
    from collections import Counter

    if total_alerts == 0:
        return "unknown"

    # --- FACTOR 1: Rule-name based explicit classification ---
    # Some rule names explicitly state the attack type
    rule_scores = Counter()
    for rule in rule_names:
        rl = rule.lower()
        if any(x in rl for x in ["brute force", "bruteforce"]):
            rule_scores["brute_force"] += 3
        if any(x in rl for x in ["port scan", "portscan", "reconnaissance"]):
            rule_scores["port_scan"] += 3
        if any(x in rl for x in ["sql injection", "xss", "web attack", "csrf"]):
            rule_scores["web_attack"] += 3
        if any(x in rl for x in ["malware", "virus", "trojan", "backdoor"]):
            rule_scores["malware"] += 3
        if any(x in rl for x in ["exfiltration", "data transfer", "covert channel"]):
            rule_scores["exfiltration"] += 3
        if any(x in rl for x in ["dos", "ddos", "flood", "denial of service"]):
            rule_scores["dos"] += 3
        if any(x in rl for x in ["privilege escalation", "privesc"]):
            rule_scores["privilege_escalation"] += 3
        if any(x in rl for x in ["container escape", "write below", "bpf program"]):
            rule_scores["container_escape"] += 3
        if any(x in rl for x in ["integrity checksum", "file integrity"]):
            rule_scores["file_integrity"] += 3
        if any(x in rl for x in ["lateral movement", "pass the hash", "wmi"]):
            rule_scores["lateral_movement"] += 3

    # --- FACTOR 2: Behavioral scoring with ratio awareness ---
    # Count total behavioral indicators to calculate ratios
    total_behavioral = sum(behavioral.values())
    if total_behavioral == 0:
        total_behavioral = 1  # Avoid division by zero

    def _behavioral_ratio(key: str) -> float:
        return behavioral.get(key, 0) / total_behavioral

    def _has_ratio(key: str, min_ratio: float = 0.25, min_count: int = 1) -> bool:
        return behavioral.get(key, 0) >= min_count and _behavioral_ratio(key) >= min_ratio

    scores = Counter()

    # Brute force: requires BOTH auth failures AND suspicious auth analysis
    # OR very high auth failure ratio with explicit brute force rule names
    auth_failures = behavioral.get("auth_failure", 0)
    auth_successes = behavioral.get("auth_success", 0)
    if auth_failures > 0:
        if auth_analysis.get("is_suspicious"):
            # Confirmed brute force: failed logins followed by success
            scores["brute_force"] = auth_failures * 4
        elif auth_failures >= 5 and _behavioral_ratio("auth_failure") >= 0.4:
            # High volume of auth failures, dominant in incident
            scores["brute_force"] = auth_failures * 3
        elif rule_scores["brute_force"] > 0:
            # Explicit brute force rules detected
            scores["brute_force"] = auth_failures * 2 + rule_scores["brute_force"]
        elif auth_failures >= 3 and auth_successes == 0:
            # Some failures but no confirmed compromise - moderate confidence
            scores["brute_force"] = auth_failures * 1

    # Port scan / Reconnaissance
    if _has_ratio("reconnaissance", min_ratio=0.2, min_count=2):
        scores["port_scan"] = behavioral["reconnaissance"] * 3
    elif rule_scores["port_scan"] > 0:
        scores["port_scan"] = rule_scores["port_scan"]

    # Web attack
    if _has_ratio("web_attack", min_ratio=0.2, min_count=1):
        scores["web_attack"] = behavioral["web_attack"] * 3
    elif rule_scores["web_attack"] > 0:
        scores["web_attack"] = rule_scores["web_attack"]

    # Malware
    if _has_ratio("malware", min_ratio=0.15, min_count=1):
        scores["malware"] = behavioral["malware"] * 4
    elif rule_scores["malware"] > 0:
        scores["malware"] = rule_scores["malware"]

    # Data exfiltration
    if _has_ratio("exfiltration", min_ratio=0.15, min_count=1):
        scores["exfiltration"] = behavioral["exfiltration"] * 4
    elif rule_scores["exfiltration"] > 0:
        scores["exfiltration"] = rule_scores["exfiltration"]

    # DoS
    if _has_ratio("dos", min_ratio=0.2, min_count=1):
        scores["dos"] = behavioral["dos"] * 3
    elif rule_scores["dos"] > 0:
        scores["dos"] = rule_scores["dos"]

    # Privilege escalation
    if _has_ratio("privilege_escalation", min_ratio=0.15, min_count=1):
        scores["privilege_escalation"] = behavioral["privilege_escalation"] * 4
    elif rule_scores["privilege_escalation"] > 0:
        scores["privilege_escalation"] = rule_scores["privilege_escalation"]

    # Execution
    if _has_ratio("execution", min_ratio=0.2, min_count=1):
        scores["execution"] = behavioral["execution"] * 2

    # Container escape (Falco-specific)
    if _has_ratio("container_escape", min_ratio=0.15, min_count=1):
        scores["container_escape"] = behavioral["container_escape"] * 4
    elif rule_scores["container_escape"] > 0:
        scores["container_escape"] = rule_scores["container_escape"]

    # File integrity
    if _has_ratio("file_integrity", min_ratio=0.15, min_count=1):
        scores["file_integrity"] = behavioral["file_integrity"] * 3
    elif rule_scores["file_integrity"] > 0:
        scores["file_integrity"] = rule_scores["file_integrity"]

    # System modification
    if _has_ratio("system_modification", min_ratio=0.15, min_count=1):
        scores["system_modification"] = behavioral["system_modification"] * 3

    # Lateral movement
    if _has_ratio("lateral_movement", min_ratio=0.15, min_count=1):
        scores["lateral_movement"] = behavioral["lateral_movement"] * 4
    elif rule_scores["lateral_movement"] > 0:
        scores["lateral_movement"] = rule_scores["lateral_movement"]

    # Network anomaly
    if _has_ratio("network_anomaly", min_ratio=0.2, min_count=1):
        scores["network_anomaly"] = behavioral["network_anomaly"] * 2

    # --- FACTOR 3: MITRE-based detection (adds confidence) ---
    if "Initial Access" in mitre_tactics:
        scores["brute_force"] += 2
        scores["execution"] += 1
    if "Execution" in mitre_tactics:
        scores["execution"] += 2
        scores["malware"] += 1
    if "Persistence" in mitre_tactics:
        scores["malware"] += 2
        scores["system_modification"] += 2
    if "Privilege Escalation" in mitre_tactics:
        scores["privilege_escalation"] += 3
    if "Collection" in mitre_tactics:
        scores["exfiltration"] += 2
    if "Exfiltration" in mitre_tactics:
        scores["exfiltration"] += 3
    if "Defense Evasion" in mitre_tactics:
        scores["container_escape"] += 2
        scores["file_integrity"] += 2

    # --- FACTOR 4: Source-based detection ---
    # Falco-dominant incidents with container violations
    falco_ratio = alert_sources.get("falco", 0) / total_alerts if total_alerts else 0
    if falco_ratio >= 0.3 and behavioral.get("container_escape", 0) > 0:
        scores["container_escape"] += 3
    if falco_ratio >= 0.3 and behavioral.get("privilege_escalation", 0) > 0:
        scores["privilege_escalation"] += 2

    # --- DECISION: Pick attack type with confidence check ---
    if not scores:
        return "unknown"

    # Sort by score descending
    sorted_scores = scores.most_common()
    top_type, top_score = sorted_scores[0]

    # Confidence checks:
    # 1. Must have a minimum absolute score
    if top_score < 3:
        return "unknown"

    # 2. Must significantly beat the second place (or there is no second place)
    if len(sorted_scores) > 1:
        second_score = sorted_scores[1][1]
        # If second place is within 50% of first, it's ambiguous
        if second_score > 0 and top_score / second_score < 1.5:
            return "mixed"

    # 3. If brute_force has low confidence (no suspicious auth, low ratio), downgrade
    if top_type == "brute_force" and top_score < 8:
        if not auth_analysis.get("is_suspicious"):
            # No confirmed compromise pattern - might just be normal auth noise
            if behavioral.get("auth_failure", 0) < 5:
                return "unknown"

    return top_type


def _calculate_risk_score(severity: int, attacker_count: int, target_count: int,
                          alert_count: int, duration: int, behavioral: dict) -> float:
    """Calculate dynamic risk score (0-100)."""
    import math

    # Base score from severity
    base_score = severity * 20  # 20, 40, 60, 80

    # Attack scale factor
    scale = min(math.log10(attacker_count + 1) * 10, 30)

    # Target count factor
    target_factor = min(target_count * 5, 20)

    # Alert volume factor
    volume_factor = min(alert_count / 10, 15)

    # Duration factor (longer = worse)
    duration_factor = min(duration / 60 * 5, 15) if duration else 0

    # Behavioral severity
    behavior_score = 0
    critical_behaviors = ["malware", "exfiltration", "privilege_escalation",
                          "execution", "container_escape", "lateral_movement"]
    for b in critical_behaviors:
        if behavioral.get(b, 0) > 0:
            behavior_score += 10

    total = base_score + scale + target_factor + volume_factor + duration_factor + behavior_score
    total = min(round(total, 1), 100)

    return total


def _analyze_authentication_patterns(alerts: list[dict], timeline: list[dict]) -> dict:
    """
    Analyze authentication events for smart context-aware filtering.
    Returns analysis that helps determine if auth events are suspicious or normal.
    """
    from collections import defaultdict

    auth_analysis = {
        "failed_logins": [],
        "successful_logins": [],
        "sudo_usage": [],
        "root_access": [],
        "suspicious_timeline": [],  # Failed then succeeded
        "is_suspicious": False,
        "risk_indicators": [],
    }

    for alert in alerts:
        title = alert.get("title", "").lower()
        description = alert.get("description", "").lower()
        source_ip = alert.get("source_ip", "")
        timestamp = alert.get("timestamp") or alert.get("created_at", "")

        # Failed authentication - STRICT matching
        if any(x in title for x in [
            "failed password", "authentication failure", "authentication failed",
            "invalid user", "non-existent user", "multiple failed login",
            "maximum authentication attempts", "user login failed",
            "missed the password", "brute force"
        ]):
            auth_analysis["failed_logins"].append({
                "ip": source_ip,
                "time": timestamp,
                "title": alert.get("title", ""),
                "description": description[:200]
            })

        # Successful authentication - STRICT matching
        if any(x in title for x in [
            "accepted password", "accepted publickey", "authentication success"
        ]):
            auth_analysis["successful_logins"].append({
                "ip": source_ip,
                "time": timestamp,
                "title": alert.get("title", ""),
                "description": description[:200]
            })

        # Sudo / root usage
        if "sudo" in title or "to root" in description:
            auth_analysis["sudo_usage"].append({
                "ip": source_ip,
                "time": timestamp,
                "title": alert.get("title", ""),
                "description": description[:200]
            })
            if "to root" in description or "sudo" in title:
                auth_analysis["root_access"].append({
                    "ip": source_ip,
                    "time": timestamp,
                    "title": alert.get("title", "")
                })

    # Analyze timeline: check if failed logins were followed by successful
    failed_ips = {f["ip"] for f in auth_analysis["failed_logins"] if f["ip"]}
    success_ips = {s["ip"] for s in auth_analysis["successful_logins"] if s["ip"]}

    # Find IPs that failed then succeeded (potential brute force + success)
    compromised_ips = failed_ips & success_ips
    if compromised_ips:
        auth_analysis["is_suspicious"] = True
        auth_analysis["risk_indicators"].append(
            f"Possible compromised accounts: {len(compromised_ips)} IPs had failed then successful logins"
        )
        auth_analysis["suspicious_timeline"] = list(compromised_ips)

    # Check for many failed from same IP
    ip_failure_count = defaultdict(int)
    for f in auth_analysis["failed_logins"]:
        if f["ip"]:
            ip_failure_count[f["ip"]] += 1

    for ip, count in ip_failure_count.items():
        if count >= 5:
            auth_analysis["is_suspicious"] = True
            auth_analysis["risk_indicators"].append(
                f"Brute force attempt detected: {ip} had {count} failed attempts"
            )

    # Check for root access from unexpected IPs
    if auth_analysis["root_access"]:
        # If root access happened after many failures, it's suspicious
        if len(auth_analysis["failed_logins"]) >= 3:
            auth_analysis["is_suspicious"] = True
            auth_analysis["risk_indicators"].append(
                "Root access after authentication failures - possible privilege escalation"
            )

    return auth_analysis
