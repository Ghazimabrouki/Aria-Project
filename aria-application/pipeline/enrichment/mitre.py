"""
Dynamic MITRE ATT&CK Mapping Module.
Auto-maps alerts to MITRE techniques based on keyword analysis.
No hardcoded SID mappings - works for ALL alert types automatically.

Enhanced with:
- Confidence scores based on match quality
- Context-aware scoring (severity, attack patterns)
- Multi-field analysis for higher accuracy
"""

from typing import Dict, Any, List, Set

# Context keywords that boost confidence
HIGH_CONFIDENCE_PATTERNS = [
    "malware", "ransomware", "trojan", "backdoor", "c2", "command and control",
    "brute force", "exploit", "vulnerability", "cve-", "payload",
    "lateral movement", "privilege escalation", "credential dump",
    "data exfiltration", "reverse shell", "webshell", "rootkit",
]

MEDIUM_CONFIDENCE_PATTERNS = [
    "suspicious", "anomalous", "unusual", "attempted", "failed",
    "detected", "blocked", "alert", "warning", "threat",
]

LOW_SEVERITY_INDICATORS = ["info", "debug", "low"]

# Dynamic keyword-to-MITRE technique mapping
# Each entry: (keywords to match, technique_id, tactic, technique_name)
_MITRE_KEYWORD_MAP = [
    # Reconnaissance
    (["scan", "nmap", "zmap", "masscan", "recon", "probe", "enumerat", "discovery"], 
     "T1595", "Reconnaissance", "Active Scanning"),
    (["dns", "named version", "zone transfer", "dns query"], 
     "T1590", "Reconnaissance", "Gather Victim Network Information"),
    (["whois", "domain", "registration"], 
     "T1589", "Reconnaissance", "Gather Victim Identity Information"),
    (["port", "service", "banner", "version"], 
     "T1595", "Reconnaissance", "Active Scanning"),
    
    # Resource Development
    (["staging", "infrastructure", "domain", "certificate"], 
     "T1583", "Resource Development", "Acquire Infrastructure"),
    
    # Initial Access
    (["exploit", "vulnerability", "cve", "remote code", "rce", "command injection"], 
     "T1190", "Initial Access", "Exploit Public-Facing Application"),
    (["phishing", "spear", "email", "attachment", "link"], 
     "T1566", "Initial Access", "Phishing"),
    (["valid account", "credential", "password", "login", "auth"], 
     "T1078", "Initial Access", "Valid Accounts"),
    (["supply chain", "third party", "vendor"], 
     "T1195", "Initial Access", "Supply Chain Compromise"),
    (["drive-by", "download", "watering hole"], 
     "T1189", "Initial Access", "Drive-by Compromise"),
    
    # Execution
    (["command", "shell", "script", "execute", "run", "binary", "payload"], 
     "T1059", "Execution", "Command and Scripting Interpreter"),
    (["scheduled task", "cron", "at job", "launchd"], 
     "T1053", "Execution", "Scheduled Task/Job"),
    (["user execution", "run", "open", "click"], 
     "T1204", "Execution", "User Execution"),
    (["container", "docker", "kubernetes", "pod", "image"], 
     "T1610", "Execution", "Deploy Container"),
    (["powershell", "cmd", "bash", "sh", "zsh"], 
     "T1059", "Execution", "Command and Scripting Interpreter"),
    
    # Persistence
    (["persistence", "startup", "autostart", "boot", "init", "systemd"], 
     "T1547", "Persistence", "Boot or Logon Autostart Execution"),
    (["backdoor", "reverse shell", "callback", "beacon"], 
     "T1571", "Command and Control", "Non-Standard Port"),
    (["registry", "key", "modify", "create"], 
     "T1547", "Persistence", "Boot or Logon Autostart Execution"),
    (["web shell", "webshell", "web shell"], 
     "T1505", "Persistence", "Server Software Component"),
    
    # Privilege Escalation
    (["privilege", "escalat", "setuid", "setgid", "sudo", "root", "admin"], 
     "T1548", "Privilege Escalation", "Abuse Elevation Control Mechanism"),
    (["token", "impersonat", "steal"], 
     "T1134", "Privilege Escalation", "Access Token Manipulation"),
    (["container escape", "privileged container", "sensitive mount", "excessively capable"], 
     "T1611", "Privilege Escalation", "Escape to Host"),
    (["kernel", "module", "driver", "exploit"], 
     "T1068", "Privilege Escalation", "Exploitation for Privilege Escalation"),
    
    # Defense Evasion
    (["evasion", "obfuscat", "encode", "encrypt", "hide", "stealth"], 
     "T1027", "Defense Evasion", "Obfuscated Files or Information"),
    (["disable", "stop", "kill", "terminate", "antivirus", "edr", "firewall"], 
     "T1562", "Defense Evasion", "Impair Defenses"),
    (["delete", "clean", "wipe", "history", "log", "artifact"], 
     "T1070", "Defense Evasion", "Indicator Removal"),
    (["masquerad", "spoof", "fake", "impersonat"], 
     "T1036", "Defense Evasion", "Masquerading"),
    (["modify", "binary", "directory", "permission", "chmod"], 
     "T1222", "Defense Evasion", "File and Directory Permissions Modification"),
    (["bpf", "ebpf", "trace", "hook"], 
     "T1595", "Reconnaissance", "Active Scanning"),
    
    # Credential Access
    (["brute force", "password guess", "credential stuffing", "dictionary"], 
     "T1110", "Credential Access", "Brute Force"),
    (["credential dump", "mimikatz", "lsass", "sam", "ntds"], 
     "T1003", "Credential Access", "OS Credential Dumping"),
    (["keylog", "keystroke", "input capture"], 
     "T1056", "Credential Access", "Input Capture"),
    (["token", "cookie", "session", "ticket", "kerberos"], 
     "T1550", "Lateral Movement", "Use Alternate Authentication Material"),
    (["sniff", "capture", "network", "packet"], 
     "T1040", "Credential Access", "Network Sniffing"),
    
    # Discovery
    (["discover", "enumerate", "list", "query", "scan"], 
     "T1087", "Discovery", "Account Discovery"),
    (["network", "share", "smb", "admin", "share"], 
     "T1135", "Discovery", "Network Share Discovery"),
    (["system", "info", "config", "setting", "environment"], 
     "T1082", "Discovery", "System Information Discovery"),
    (["file", "directory", "search", "find"], 
     "T1083", "Discovery", "File and Directory Discovery"),
    (["permission", "access", "privilege", "group"], 
     "T1069", "Discovery", "Permission Groups Discovery"),
    
    # Lateral Movement
    (["lateral", "remote", "ssh", "rdp", "smb", "psexec", "wmi"], 
     "T1021", "Lateral Movement", "Remote Services"),
    (["pass the hash", "pass the ticket", "ptt", "pth"], 
     "T1550", "Lateral Movement", "Use Alternate Authentication Material"),
    (["internal", "spread", "propagat", "worm"], 
     "T1021", "Lateral Movement", "Remote Services"),
    
    # Collection
    (["collect", "gather", "capture", "record", "screen", "clipboard"], 
     "T1113", "Collection", "Screen Capture"),
    (["data", "file", "document", "email", "archive"], 
     "T1005", "Collection", "Data from Local System"),
    (["input", "capture", "keylog", "clipboard"], 
     "T1056", "Collection", "Input Capture"),
    (["camera", "webcam", "microphone", "audio"], 
     "T1123", "Collection", "Audio Capture"),
    
    # Command and Control
    (["c2", "c&c", "command and control", "beacon", "callback"], 
     "T1071", "Command and Control", "Application Layer Protocol"),
    (["dns tunnel", "dns query high entropy", "dga", "domain generation"], 
     "T1071.004", "Command and Control", "DNS"),
    (["encrypted", "https", "ssl", "tls", "certificat"], 
     "T1573", "Command and Control", "Encrypted Channel"),
    (["proxy", "redirector", "tunnel", "relay"], 
     "T1090", "Command and Control", "Proxy"),
    (["http", "post", "get", "user-agent", "header", "authorization"], 
     "T1071.001", "Command and Control", "Web Protocols"),
    (["drop", "block listed", "cins active threat", "spamhaus", "threat intelligence"], 
     "T1595", "Reconnaissance", "Active Scanning"),
    
    # Exfiltration
    (["exfil", "upload", "transfer", "send", "copy", "download"], 
     "T1041", "Exfiltration", "Exfiltration Over C2 Channel"),
    (["dns tunnel", "icmp tunnel", "alternative protocol"], 
     "T1048", "Exfiltration", "Exfiltration Over Alternative Protocol"),
    (["large transfer", "bulk", "archive", "compress"], 
     "T1560", "Collection", "Archive Collected Data"),
    
    # Impact
    (["ransom", "encrypt file", "extort", "demand"], 
     "T1486", "Impact", "Data Encrypted for Impact"),
    (["destroy", "wipe", "delete", "corrupt"], 
     "T1485", "Impact", "Data Destruction"),
    (["deface", "modify", "replace", "tamper"], 
     "T1491", "Impact", "Defacement"),
    (["denial of service", "dos", "ddos", "flood", "amplify"], 
     "T1498", "Impact", "Network Denial of Service"),
    (["resource hijack", "mine", "cryptocurrency", "bitcoin"], 
     "T1496", "Impact", "Resource Hijacking"),
    (["inhibit recovery", "backup", "restore", "shadow copy"], 
     "T1490", "Impact", "Inhibit System Recovery"),
    
    # Suspicious/Threat Intel
    (["suspicious", "anomalous", "unusual", "unexpected", "abnormal"], 
     "T1595", "Reconnaissance", "Active Scanning"),
    (["malware", "trojan", "virus", "worm", "rat"], 
     "T1204", "Execution", "User Execution"),
    (["apt", "advanced persistent", "nation state"], 
     "T1595", "Reconnaissance", "Active Scanning"),
    (["known compromised", "hostile host", "malicious"], 
     "T1595", "Reconnaissance", "Active Scanning"),
]


def _extract_keywords(text: str) -> List[str]:
    """Extract relevant keywords from text for MITRE mapping."""
    if not text:
        return []
    return text.lower().split()


def _find_best_match(text: str, severity: str = "") -> List[Dict[str, str]]:
    """Find the best MITRE technique match for given text.
    
    Uses keyword overlap scoring to find the most relevant technique.
    Includes confidence scoring based on match quality and context.
    """
    if not text:
        return []
    
    text_lower = text.lower()
    results = []
    
    # Check context for confidence adjustment
    has_high_confidence = any(p in text_lower for p in HIGH_CONFIDENCE_PATTERNS)
    has_medium_confidence = any(p in text_lower for p in MEDIUM_CONFIDENCE_PATTERNS)
    is_low_severity = any(ind in (severity or "").lower() for ind in LOW_SEVERITY_INDICATORS)
    
    for keywords, tech_id, tactic, tech_name in _MITRE_KEYWORD_MAP:
        score = 0
        matched = []
        for kw in keywords:
            if kw in text_lower:
                score += 1
                matched.append(kw)
        
        if score > 0:
            # Base confidence from keyword matches
            confidence = min(score * 20, 60)  # 0-60 from matches
            
            # Boost for attack pattern keywords
            if has_high_confidence:
                confidence += 30
            elif has_medium_confidence:
                confidence += 15
            
            # Penalty for low severity
            if is_low_severity:
                confidence = max(confidence - 20, 10)
            
            confidence = min(max(confidence, 10), 100)  # Clamp 10-100
            
            results.append({
                "id": tech_id,
                "tactic": tactic,
                "technique": tech_name,
                "score": score,
                "confidence": confidence,
                "matched": matched,
            })
    
    # Sort by score (highest first), then confidence
    results.sort(key=lambda x: (x["score"], x["confidence"]), reverse=True)
    return results[:3]  # Return top 3 matches


def _deduplicate_techniques(techniques: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Remove duplicate techniques, keeping highest scored."""
    seen_ids = set()
    unique = []
    for t in techniques:
        tid = t.get("id", "")
        if tid and tid not in seen_ids:
            seen_ids.add(tid)
            unique.append(t)
    return unique


def dynamic_mitre_mapping(title: str = "", category: str = "", signature: str = "", 
                          description: str = "", rule_name: str = "", 
                          severity: str = "") -> List[Dict[str, str]]:
    """Dynamically map alert content to MITRE ATT&CK techniques.
    
    Analyzes all available text fields and returns best matching techniques.
    No hardcoded mappings - works for ANY alert type.
    Includes confidence scoring based on match quality and context.
    """
    # Combine all text fields for analysis
    combined_text = " ".join(filter(None, [
        title, category, signature, description, rule_name
    ]))
    
    if not combined_text:
        return []
    
    # Find best matches with severity context
    results = _find_best_match(combined_text, severity)
    
    # Deduplicate
    return _deduplicate_techniques(results)


def format_mitre_tags(techniques: List[Dict[str, str]]) -> List[str]:
    """Format MITRE techniques into tag list."""
    tags = []
    seen_ids = set()
    for t in techniques:
        tid = t.get("id", "")
        # Remove leading T if present to avoid double-T
        if tid.startswith("T"):
            tid = tid[1:]
        if tid and tid not in seen_ids:
            seen_ids.add(tid)
            tags.append(f"mitre-T{tid}")
            if t.get("tactic"):
                tags.append(f"mitre-tactic-{t['tactic']}")
            if t.get("technique"):
                tags.append(f"mitre-technique-{t['technique']}")
    return tags


def enrich_with_mitre(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich alert with dynamic MITRE ATT&CK tags."""
    title = alert.get("title", "")
    rule_name = alert.get("rule_name", "")
    description = alert.get("description", "")
    category = alert.get("metadata", {}).get("category", "")
    signature = alert.get("metadata", {}).get("signature", "")
    severity = alert.get("severity", "")
    
    # Dynamic mapping with severity context
    techniques = dynamic_mitre_mapping(
        title=title,
        category=category,
        signature=signature,
        description=description,
        rule_name=rule_name,
        severity=severity,
    )
    
    if techniques:
        tags = alert.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        
        # PRESERVE existing high-confidence MITRE tags from sources like Wazuh
        # that already provide accurate ATT&CK mappings. Only remove our own
        # keyword-generated tags so we can re-evaluate them.
        existing_mitre_ids = set()
        existing_mitre_tactics = []
        existing_mitre_techniques = []
        preserved_tags = []
        
        for t in tags:
            t_lower = t.lower()
            if t_lower.startswith("mitre-tactic-"):
                existing_mitre_tactics.append(t)
            elif t_lower.startswith("mitre-technique-"):
                existing_mitre_techniques.append(t)
            elif t_lower.startswith("mitre-t") and len(t) > 8 and t[7:8].isdigit():
                existing_mitre_ids.add(t)
                preserved_tags.append(t)
            elif not t_lower.startswith("mitre-conf-"):
                preserved_tags.append(t)
        
        # Rebuild tag list: preserve non-MITRE + source-provided MITRE
        tags = preserved_tags + existing_mitre_tactics + existing_mitre_techniques
        
        # Add new keyword-mapped MITRE tags ONLY if not already present
        for t in techniques:
            tid = t.get("id", "")
            conf = t.get("confidence", 0)
            if tid.startswith("T"):
                tid = tid[1:]
            if tid:
                tag_name = f"mitre-T{tid}"
                if tag_name not in existing_mitre_ids:
                    tags.append(tag_name)
                    # Mark keyword-derived mappings with lower confidence
                    if conf >= 70:
                        tags.append(f"mitre-conf-medium")  # keyword-derived = max medium
                    else:
                        tags.append(f"mitre-conf-low")
        
        alert["tags"] = tags
        
        # Also store techniques in alert for UI display
        alert["mitre_techniques"] = techniques
    
    return alert
