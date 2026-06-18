def _build_prompt(context: dict) -> str:
    """Build comprehensive AI prompt with ALL available data."""
    import json

    incident = context["incident"]
    timeline = context["timeline"]
    iocs = context["all_iocs"]
    behavioral = context.get("behavioral_indicators", {})
    attack_type = context.get("attack_type", "unknown")
    risk_score = context.get("risk_score", 50)
    summary = context.get("summary", {})

    # ====== COMPREHENSIVE TIMELINE (ALL EVENTS) ======
    timeline_text = ""
    for i, e in enumerate(timeline):
        time_str = e.get("time", "unknown")[:19] if e.get("time") else "unknown"
        sev = e.get("severity", "?").upper()
        src = e.get("source", "?")
        title = e.get("title", "")[:80]
        host = e.get("hostname", "")
        src_ip = e.get("source_ip", "")
        dst_ip = e.get("dest_ip", "")
        port = e.get("port", "")

        line = f"  [{i+1:02d}] {time_str} [{sev}] {src}: {title}"
        if host:
            line += f" | host:{host}"
        if src_ip:
            line += f" | attacker:{src_ip}"
        if dst_ip:
            line += f" -> {dst_ip}"
        if port:
            line += f":{port}"
        timeline_text += line + "\n"

    # ====== COMPLETE IOC EXTRACTION ======
    ioc_parts = []

    if iocs.get("source_ips"):
        ips = iocs["source_ips"]
        ioc_parts.append(f"ATTACKER IPs ({len(ips)}): {', '.join(ips[:10])}")
        if len(ips) > 10:
            ioc_parts.append(f"  + {len(ips)-10} more")

    if iocs.get("dest_ips"):
        ips = iocs["dest_ips"]
        ioc_parts.append(f"TARGET IPs ({len(ips)}): {', '.join(ips[:10])}")
        if len(ips) > 10:
            ioc_parts.append(f"  + {len(ips)-10} more")

    if iocs.get("hostnames"):
        hosts = iocs["hostnames"]
        ioc_parts.append(f"AFFECTED HOSTS: {', '.join(hosts[:5])}")

    if iocs.get("usernames"):
        ioc_parts.append(f"USERNAMES: {', '.join(iocs['usernames'][:5])}")

    if iocs.get("ports"):
        ports = [str(p) for p in iocs["ports"]]
        ioc_parts.append(f"TARGET PORTS: {', '.join(ports[:10])}")

    if iocs.get("services"):
        ioc_parts.append(f"SERVICES: {', '.join(iocs['services'])}")

    if iocs.get("domains"):
        ioc_parts.append(f"SUSPICIOUS DOMAINS: {', '.join(iocs['domains'][:5])}")

    if iocs.get("file_paths"):
        ioc_parts.append(f"FILE PATHS: {', '.join(iocs['file_paths'][:3])}")

    if iocs.get("hashes"):
        ioc_parts.append(f"FILE HASHES: {', '.join(iocs['hashes'][:3])}")

    ioc_text = "\n".join(ioc_parts) if ioc_parts else "None extracted"

    # ====== BEHAVIORAL ANALYSIS ======
    behavioral_text = ""
    if behavioral:
        sorted_behaviors = sorted(behavioral.items(), key=lambda x: x[1], reverse=True)
        behavioral_text = "DETECTED BEHAVIORS:\n"
        for btype, count in sorted_behaviors:
            if count > 0:
                severity = "CRITICAL" if count > 5 else "HIGH" if count > 2 else "MODERATE"
                behavioral_text += f"  - {btype.replace('_', ' ').title()}: {count} events [{severity}]\n"

    # ====== ATTACK TYPE SPECIFIC GUIDANCE ======
    attack_type_guidance = {
        "brute_force": """
BRUTE FORCE CONSIDERATIONS:
- For SSH/PAM brute-force with ONLY failed login attempts and NO successful authentication: this is a credential access attempt, NOT a confirmed compromise. Do NOT claim lateral movement, compromise, or persistence.
- Block attacker IPs at firewall using shell with EXPLICIT source IP only: `iptables -A INPUT -s 47.253.11.8 -j DROP`. NEVER use `{{ item }}`, NEVER use `0.0.0.0/0`, NEVER use empty variables.
- ABSOLUTE RULE: NEVER use `{{ attacker_ips[0] }}`, `{{ item }}`, or any unresolved Jinja2 variable as a firewall source. Hard-code the exact IP address in the shell command.
- NEVER recommend `systemctl isolate`, `reboot`, `shutdown`, or stopping the SSH service for brute-force incidents.
- NEVER modify `/etc/ssh/sshd_config`, `/etc/pam.d/`, `/etc/sudoers`, or any authentication policy file.
- NEVER run generic package updates (apt upgrade, dnf update, yum update) as brute-force remediation.
- NEVER use `ansible.builtin.iptables` module — always use `ansible.builtin.shell` with explicit IP.
- Audit successful logins after attack window for compromise. If NO successful login is found, state clearly: "No successful authentication confirmed."
- Enable or verify fail2ban (or similar brute-force protection) if available.
- Check for password spray patterns across multiple users.
- Include precise rollback: `iptables -D INPUT -s 47.253.11.8 -j DROP` (exact same IP as the block rule).""",

        "port_scan": """
PORT SCAN CONSIDERATIONS:
- Implement rate limiting on targeted services
- Update IDS/IPS rules to detect reconnaissance scans
- Review and restrict unnecessary network exposure
- Enable connection tracking and SYN flood protection
- Consider network segmentation review
- Check for subsequent exploitation attempts after scan""",

        "web_attack": """
WEB ATTACK CONSIDERATIONS:
- Check WAF logs for attack details and payloads
- Block attacker IP at application layer (e.g., nginx deny) or network layer using shell: `iptables -A INPUT -s <attacker_ip> -j DROP` (always specify source IP)
- Review and sanitize input validation across all endpoints
- Check for SQL injection, XSS, RCE, or LFI payloads in logs
- Verify application integrity and check for successful exploitation
- Review user sessions for unauthorized access""",

        "malware": """
MALWARE CONSIDERATIONS:
- Quarantine affected systems immediately
- Block file execution for suspicious paths and hashes
- Kill malicious processes and remove persistence mechanisms
- Collect memory/disk artifacts for forensics
- Check lateral movement indicators across the network
- Update EDR/antivirus signatures and scan all endpoints""",

        "exfiltration": """
DATA EXFILTRATION CONSIDERATIONS:
- Block external destinations at firewall using shell: `iptables -A OUTPUT -d <bad_ip> -j DROP` (always specify destination IP on OUTPUT chain)
- Enable DLP monitoring and review data access patterns
- Audit user sessions and file access logs
- Check for covert channels (DNS tunneling, ICMP, steganography)
- Review email and web traffic logs for data leaks
- Assess scope: what data was accessed and potentially stolen""",

        "dos": """
DoS/DDoS CONSIDERATIONS:
- Enable rate limiting and connection throttling
- Block amplification sources and known bad IP ranges using shell: `iptables -A INPUT -s <bad_ip> -j DROP` (always specify source IP)
- Activate DDoS protection (CloudFlare, AWS Shield, etc.)
- Scale infrastructure or enable autoscaling if applicable
- Implement traffic filtering upstream
- Review logs to identify attack vectors and botnets""",

        "privilege_escalation": """
PRIVILEGE ESCALATION CONSIDERATIONS:
- Audit recent sudo/admin commands and execution history
- Check for newly created user accounts or group memberships
- Review sudoers configuration and sudoers.d files
- Verify SSH authorized_keys for unauthorized entries
- Check crontabs, systemd timers, and startup items for persistence
- Scan for SUID binaries and kernel exploits""",

        "execution": """
CODE EXECUTION CONSIDERATIONS:
- Kill suspicious processes immediately
- Isolate affected systems from the network
- Review process execution history and parent-child relationships
- Check for reverse shells, bind shells, or web shells
- Audit cron jobs, scheduled tasks, and startup items
- Review script execution and PowerShell/command line history""",

        "container_escape": """
CONTAINER ESCAPE CONSIDERATIONS:
- Isolate the compromised container and host immediately
- Review Falco alerts for the full chain of container violations
- Check for writes to sensitive host paths (/etc, /root, /proc, /sys)
- Audit BPF program loading and kernel module insertion
- Review container runtime logs (docker, containerd, cri-o)
- Check for privilege escalation within containers (privileged mode, cap_add)
- Scan the host for persistence mechanisms installed from the container""",

        "file_integrity": """
FILE INTEGRITY CONSIDERATIONS:
- Identify all modified/added/deleted files and assess impact
- Compare against known-good baselines or backups
- Check file permissions and ownership changes
- Scan modified files for malware or backdoors
- Review who made the changes and from where
- Restore critical system files from trusted sources if compromised
- Update file integrity monitoring (FIM) rules""",

        "system_modification": """
SYSTEM MODIFICATION CONSIDERATIONS:
- Audit all newly created users and groups
- Review installed packages against approved software inventory
- Check systemd services, cron jobs, and startup items
- Verify kernel modules and drivers are legitimate
- Review SSH keys, authorized_keys, and known_hosts
- Check for hidden accounts or backdoor users
- Validate system configuration files against baselines""",

        "lateral_movement": """
LATERAL MOVEMENT CONSIDERATIONS:
- Identify all systems the attacker has accessed
- Block lateral movement paths by restricting SMB/RDP/SSH/WMI/WinRM access using shell firewall rules with explicit source IPs (never block management/admin IPs)
- Audit credential usage across multiple hosts
- Check for pass-the-hash, pass-the-ticket, or golden ticket activity
- Review remote service creation and scheduled task execution
- Reset credentials for all potentially compromised accounts
- Enable enhanced logging on lateral movement protocols""",

        "network_anomaly": """
NETWORK ANOMALY CONSIDERATIONS:
- Block traffic from poor-reputation IPs and networks using shell: `iptables -A INPUT -s <bad_ip> -j DROP` (always specify source IP)
- Review firewall rules and network segmentation
- Check for unexpected protocols, ports, or destinations
- Analyze traffic volume and patterns for exfiltration
- Review DNS queries for DGA or tunneling indicators
- Check proxy and NAT logs for hidden connections
- Update threat intelligence feeds and blocklists""",

        "mixed": """
MIXED ATTACK CONSIDERATIONS:
This incident shows indicators of multiple attack types. Analyze carefully:
- Identify the INITIAL COMPROMISE vector (the first entry point)
- Map the full attack chain from initial access to current state
- Address the most severe component first (containment)
- Check for attacker pivoting between techniques
- The playbook should handle the PRIMARY threat while monitoring for secondary threats
- Consider staged remediation: contain first, then investigate each attack vector""",
    }

    attack_guidance = attack_type_guidance.get(attack_type, """
GENERAL INCIDENT CONSIDERATIONS:
- Isolate affected systems
- Block malicious IPs and domains
- Collect and preserve forensic evidence
- Review logs for scope and impact
- Check for persistence mechanisms
- Verify no lateral movement occurred""")

    # ====== PROOF OF COMPROMISE ======
    poc = context.get("proof_of_compromise", {})
    if poc.get("compromised"):
        poc_text = f"""PROOF OF COMPROMISE DETECTED (confidence: {poc.get('confidence', 'unknown').upper()}):
"""
        for indicator in poc.get("indicators", []):
            poc_text += f"  - {indicator}\n"
    else:
        poc_text = "PROOF OF COMPROMISE: No definitive compromise indicators detected. Treat as suspicious activity requiring investigation."

    # ====== ASSET CRITICALITY ======
    asset_roles = context.get("asset_roles", {})
    if asset_roles:
        asset_text = "ASSET CRITICALITY:\n"
        for host, role in sorted(asset_roles.items()):
            criticality = "HIGH" if role in ("domain_controller", "database") else "MEDIUM" if role in ("web", "mail") else "LOW"
            asset_text += f"  - {host}: role={role}, criticality={criticality}\n"
    else:
        asset_text = "ASSET CRITICALITY: Unknown (no hostname metadata available)"

    # ====== NETWORK & ENDPOINT EVIDENCE ======
    net_ev = context.get("network_evidence", {})
    endpoint_ev = context.get("endpoint_evidence", {})
    evidence_text = ""
    if net_ev.get("http_requests"):
        evidence_text += f"  HTTP requests: {len(net_ev['http_requests'])} unique\n"
    if net_ev.get("tls_connections"):
        evidence_text += f"  TLS connections: {len(net_ev['tls_connections'])} unique\n"
    if net_ev.get("dns_queries"):
        evidence_text += f"  DNS queries: {len(net_ev['dns_queries'])} unique\n"
    if net_ev.get("ja3_fingerprints"):
        evidence_text += f"  JA3 fingerprints: {', '.join(net_ev['ja3_fingerprints'][:5])}\n"
    if endpoint_ev.get("commands"):
        evidence_text += f"  Commands observed: {len(endpoint_ev['commands'])}\n"
    if endpoint_ev.get("processes"):
        evidence_text += f"  Processes observed: {len(endpoint_ev['processes'])}\n"
    if endpoint_ev.get("file_changes"):
        evidence_text += f"  File changes: {len(endpoint_ev['file_changes'])}\n"
    if not evidence_text:
        evidence_text = "  No structured network or endpoint evidence extracted."

    # ====== MITRE COVERAGE ======
    mitre_text = ", ".join(context.get("mitre_tactics", [])) or "None detected"
    techniques = ", ".join(context.get("mitre_techniques", [])) or "None detected"

    # ====== RISK ASSESSMENT ======
    risk_level = "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 30 else "LOW"

    # ====== SUMMARY STATS ======
    stats = f"""
ATTACK STATISTICS:
- Unique attackers: {summary.get('unique_attackers', '?')}
- Unique targets: {summary.get('unique_targets', '?')}
- Attack duration: {summary.get('attack_duration', '?')} minutes
- Total events: {summary.get('total_alerts', '?')}
- Primary method: {summary.get('primary_attack_method', 'unknown').replace('_', ' ').title()}
"""

    # ====== BUILD COMPREHENSIVE PROMPT ======
    return f"""You are a senior SOC analyst with expertise in threat detection, incident response, and automated remediation. Analyze this security incident comprehensively and generate a tailored remediation playbook.

{'='*60}
INCIDENT OVERVIEW
{'='*60}
Title: {incident.get('title', 'Security Incident')[:100]}
Severity: {context.get('highest_severity', 'medium').upper()} | Risk Score: {risk_score}/100 ({risk_level})
Duration: {context.get('duration_minutes', 'unknown')} minutes | Total Events: {len(timeline)}
Attack Type Detected: {attack_type.replace('_', ' ').upper()}
MITRE Tactics: {mitre_text}
MITRE Techniques: {techniques}

{stats}

{'='*60}
TIMELINE - COMPLETE ATTACK SEQUENCE (ALL {len(timeline)} EVENTS)
{'='*60}
{timeline_text}

{'='*60}
INTELLIGENCE - ALL IOCs EXTRACTED
{'='*60}
{ioc_text}

{behavioral_text}

{poc_text}

{asset_text}

{'='*60}
STRUCTURED EVIDENCE SUMMARY
{'='*60}
{evidence_text}

{'='*60}
ATTACK-TYPE SPECIFIC GUIDANCE
{'='*60}
{attack_guidance}

{'='*60}
REQUIRED OUTPUT FORMAT
{'='*60}
Provide your analysis in EXACTLY this format with the exact headers:

## INCIDENT SUMMARY
[2-3 sentences: What happened, who was targeted, what was the impact]

## ATTACK CHAIN ANALYSIS
[Step-by-step reconstruction of the attack:
1. [Initial access method]
2. [Reconnaissance performed]
3. [Tools/tactics used]
4. [Actions on objectives]
5. [Persistence mechanisms if any]
6. [Impact caused]]

## THREAT INTELLIGENCE
[All relevant IOCs and threat context:
- Attacker IPs and ports used
- Target systems and services
- Files/processes involved
- Domains if any
- MITRE techniques used
- Any TTPs observed]

## RISK ASSESSMENT
[Risk level and justification
What could happen if not remediated
Business impact if applicable]

## ROOT CAUSE ANALYSIS
[Identify the root cause:
- What vulnerability, misconfiguration, or weakness allowed this attack?
- Was this an external or insider threat?
- What was the initial access vector?
- Cite specific evidence from the timeline to support your conclusion]

## AFFECTED ASSET INVENTORY
[List all affected assets with their roles and criticality:
- Hostname / IP: role, criticality level, evidence of compromise
- Which assets are confirmed compromised vs merely contacted
- Business function of each asset]

## IMPACT ASSESSMENT
[Assess the impact:
- Confidentiality: Was data accessed or exfiltrated? Cite evidence.
- Integrity: Were systems or files modified? Cite evidence.
- Availability: Were services disrupted? Cite evidence.
- Business impact: What is the operational consequence?]

## TIMELINE GAPS AND ANOMALIES
[Identify any gaps or anomalies:
- Missing time periods where attacker activity may have occurred
- Unexplained log entries or out-of-sequence events
- Data sources that should have logged but didn't
- Anomalous patterns that don't fit the primary attack type]

## CONFIDENCE SCORING
[For each major assertion above, provide a confidence level (High/Medium/Low) and brief justification:
- Compromise confirmed: [High/Medium/Low] - reason
- Attack type identified: [High/Medium/Low] - reason
- Root cause determined: [High/Medium/Low] - reason
- Impact assessed: [High/Medium/Low] - reason]

## REMEDIATION PLAYBOOK
Generate a complete Ansible playbook as a YAML code block. The playbook MUST:
- Be valid Ansible YAML starting with `---`
- Target the affected host(s): {', '.join(iocs.get('hostnames', ['target']))}
- Use `become: yes` for privileged operations
- Include variable definitions for attacker_ips, target_ips, investigation_id
- Follow this structure:
  * Phase 1: Immediate containment (block exact attacker IPs ONLY — never isolate systems for brute-force)
  * Phase 2: Service-specific hardening (based on the attack type guidance above)
  * Phase 3: Detection and forensics (collect evidence, audit logs)
  * Phase 4: Verification (confirm blocks are active, check service health)
- Use `ignore_errors: yes` and `failed_when: false` for non-critical tasks
- Use proper Jinja2 syntax: `{{{{ item }}}}` in loops, `{{{{ variable }}}}` for vars
- CRITICAL: ONLY use `ansible.builtin.*` modules. NEVER use `community.general.*`, `community.docker.*`, or any other non-core modules.
- NEVER use `ansible.builtin.iptables` module. If you need firewall rules, use `ansible.builtin.shell` with EXPLICIT syntax: `shell: iptables -A INPUT -s {{ attacker_ip }} -j DROP`. ALWAYS specify `-s <source_ip>`. NEVER use `-d <destination_ip>` on the INPUT chain. NEVER drop port 22 without a specific source IP.
- NEVER block the target host's own IP addresses or management/admin access.
- NEVER use: `tail -f`, `watch`, `top`, `while true`, or any command that runs indefinitely (Ansible will hang forever).
- NEVER use: `systemctl isolate`, `reboot`, `shutdown`, `halt`, `poweroff` (too disruptive for automated remediation).
- NEVER modify `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/`, `/etc/pam.d/`, or SSH authentication policy for brute-force incidents.
- NEVER use: `rm -rf`, `mkfs`, `dd` (destructive file operations).
- NEVER use: `apt upgrade`, `apt dist-upgrade`, `dnf update`, `yum update` as generic remediation (full-system updates are NOT targeted remediation).
- NEVER modify `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/pam.d/`, or `/etc/polkit-1/` via lineinfile/copy/template (too dangerous to automate).
- NEVER use broad `chmod -R` or `chown -R` on system paths like `/`, `/etc`, `/usr`, `/var`.
- For SSH brute-force: use EXPLICIT IP addresses in shell commands: `shell: "iptables -A INPUT -s '47.253.11.8' -j DROP"`. NEVER use `{{ item }}` or unresolved Jinja2 variables as firewall sources.
- Quoted Jinja2 in shell commands: `shell: "iptables -A INPUT -s '{{ attacker_ip }}' -j DROP"` (quote variables inside shell strings) — ONLY when the variable is guaranteed to resolve to a single explicit IP.

```yaml
---
- name: Remediation - {incident.get('title', 'Incident')[:50]}
  hosts: {iocs.get('hostnames', ['target'])[0] if iocs.get('hostnames') else 'target'}
  become: yes
  gather_facts: yes
  vars:
    attacker_ips: {json.dumps(iocs.get('source_ips', [])[:10])}
    target_ips: {json.dumps(iocs.get('dest_ips', [])[:5])}
    investigation_id: "{context.get('incident', {}).get('id', 'unknown')}"
    risk_level: "{risk_level}"
    attack_type: "{attack_type}"
  tasks:
    # Generate context-specific tasks here based on the incident details above
```

## ROLLBACK PLAYBOOK
After the remediation playbook, generate a SECOND YAML code block containing a rollback playbook that reverses every state-changing task above (removes firewall rules, restores config, restarts services, etc.). This MUST:
- Use the same hosts and vars
- Only reverse actions that actually change system state (not log collection or audit tasks)
- Be immediately executable to undo the remediation if it causes problems
- If no state changes are made in the remediation playbook, state: "No rollback required — playbook is read-only."

## VERIFICATION PROCEDURE
[How to verify the remediation worked:
1. Check that attacker IPs are blocked
2. Verify no new similar alerts
3. Confirm services still functional
4. Review logs for post-remediation activity]

## STRUCTURED METADATA (JSON)
After all sections above, provide a JSON code block with this EXACT structure for programmatic parsing:
```json
{{
  "compromised": true/false,
  "compromise_confidence": "high|medium|low",
  "attack_type": "{attack_type}",
  "primary_vector": "description of initial access",
  "affected_assets": [
    {{"host": "hostname", "ip": "x.x.x.x", "role": "web|db|dc", "compromised": true/false, "confidence": "high|medium|low"}}
  ],
  "impact": {{
    "confidentiality": "none|suspected|confirmed",
    "integrity": "none|suspected|confirmed",
    "availability": "none|suspected|confirmed",
    "business_impact": "minimal|moderate|severe|critical"
  }},
  "mitre_techniques": ["T####", ...],
  "attacker_ips": ["x.x.x.x", ...],
  "target_ips": ["x.x.x.x", ...],
  "recommended_actions": ["action1", "action2"],
  "risk_score": 0-100,
  "investigation_quality": "thorough|adequate|incomplete"
}}
```

EVIDENCE CITATION REQUIREMENTS:
- Every factual claim MUST cite at least one specific alert index [N] or timestamp from the timeline
- Distinguish between PROVEN facts and SUSPICIOUS indicators
- If you are uncertain, state the uncertainty explicitly
- Do not invent IOCs, hostnames, or events not present in the data
- Do not claim privilege escalation, compromise, lateral movement, or persistence without explicit evidence from the alerts
- Distinguish expected container startup behavior from actual compromise attempts
- Only correlate alerts that share source IP, destination IP, host, user, process, container, service, or close time window (within 10 minutes). Weak correlations should be labeled "possible but unproven" or treated as separate incidents
- If evidence is insufficient, state "insufficient evidence to determine root cause" rather than fabricating a kill-chain narrative

IMPORTANT:
- Do NOT echo the guidance text verbatim. Generate ORIGINAL, CONTEXT-SPECIFIC tasks based on the actual IOCs and timeline above.
- Every task must reference actual IPs, hosts, ports, or files from the incident data.
- The playbook must be immediately executable without manual editing.
"""


def _get_attack_type_tasks(attack_type: str, iocs: dict) -> str:
    """Generate attack-type specific tasks for the playbook (used by fallback)."""

    tasks_map = {
        "brute_force": """
    # Brute force specific tasks
    - name: Audit failed SSH login attempts
      shell: grep "Failed password" /var/log/auth.log | tail -100
      register: ssh_auth_failures
      failed_when: false

    - name: Check for successful login after attack
      shell: grep "Accepted password" /var/log/auth.log | tail -20
      register: ssh_success
      failed_when: false

    - name: Review last logins for compromised accounts
      shell: last -50 | head -30
      register: last_logins
      failed_when: false

    - name: Enable fail2ban if available
      service:
        name: fail2ban
        state: started
      failed_when: false
      ignore_errors: yes""",

        "port_scan": """
    # Port scan specific tasks
    - name: Check connection tracking
      shell: conntrack -L | wc -l
      register: conntrack_count
      failed_when: false

    - name: Review firewall drops
      shell: iptables -L -n -v | grep DROP | head -20
      register: firewall_drops
      failed_when: false

    - name: Check for SYN flood indicators
      shell: netstat -s | grep -i overflow
      register: syn_stats
      failed_when: false""",

        "web_attack": """
    # Web attack specific tasks
    - name: Check Apache/nginx error logs
      shell: tail -100 /var/log/apache2/error.log 2>/dev/null || tail -100 /var/log/nginx/error.log 2>/dev/null || echo "No web logs"
      register: web_logs
      failed_when: false

    - name: Check for SQL injection patterns
      shell: grep -r -i "sql syntax" /var/log/apache2/ 2>/dev/null | tail -20 || echo "No SQL injection detected"
      register: sqli_check
      failed_when: false

    - name: Review access logs for attack patterns
      shell: tail -500 /var/log/apache2/access.log 2>/dev/null | grep -E "500|403|404" | tail -30
      register: web_errors
      failed_when: false""",

        "malware": """
    # Malware specific tasks
    - name: Check for suspicious processes
      shell: ps aux | grep -vE "root|UID" | head -50
      register: process_list
      failed_when: false

    - name: Check recently modified files
      shell: find /tmp /var/tmp -type f -mmin -60 2>/dev/null
      register: recent_files
      failed_when: false

    - name: Check crontabs for persistence
      shell: ls -la /etc/cron.d /var/spool/cron/crontabs 2>/dev/null
      register: cron_jobs
      failed_when: false

    - name: Check SSH authorized keys
      shell: cat ~/.ssh/authorized_keys 2>/dev/null || echo "No keys"
      register: ssh_keys
      failed_when: false""",

        "exfiltration": """
    # Data exfiltration specific tasks
    - name: Check for large data transfers
      shell: ss -tan | grep ESTAB | awk '{{print $4}}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20
      register: network_connections
      failed_when: false

    - name: Review outbound traffic
      shell: iptables -L OUTPUT -n -v | head -30
      register: outbound_traffic
      failed_when: false

    - name: Check for unusual ports
      shell: ss -tuln | grep -vE "22|80|443|3306|5432"
      register: unusual_ports
      failed_when: false""",

        "privilege_escalation": """
    # Privilege escalation specific tasks
    - name: Check sudo permissions
      shell: sudo -l 2>/dev/null || echo "No sudo access"
      register: sudo_perms
      failed_when: false

    - name: Check for new users
      shell: lastlog | grep -v "Never"
      register: new_users
      failed_when: false

    - name: Check sudoers file changes
      shell: ls -la /etc/sudoers /etc/sudoers.d/
      register: sudoers_files
      failed_when: false

    - name: Check for SUID binaries
      shell: find / -perm -4000 -type f 2>/dev/null | head -20
      register: suid_bins
      failed_when: false""",

        "container_escape": """
    # Container escape specific tasks
    - name: Check for privileged containers
      shell: docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null || crictl ps 2>/dev/null || echo "No container runtime"
      register: containers
      failed_when: false

    - name: Check container runtime security options
      shell: docker info 2>/dev/null | grep -i security || echo "No docker security info"
      register: docker_security
      failed_when: false

    - name: Audit host path mounts
      shell: docker inspect $(docker ps -q) 2>/dev/null | grep -i '"Source"' | head -20 || echo "No mounts"
      register: mounts
      failed_when: false""",

        "file_integrity": """
    # File integrity specific tasks
    - name: Check for recently modified system files
      shell: find /etc /usr/bin /usr/sbin -type f -mmin -120 2>/dev/null | head -30
      register: recent_system_files
      failed_when: false

    - name: Check file permissions on critical binaries
      shell: ls -la /usr/bin/sudo /usr/bin/passwd /usr/bin/su 2>/dev/null
      register: critical_perms
      failed_when: false

    - name: Check for hidden files in system directories
      shell: find /etc /tmp /var/tmp -name '.*' -type f 2>/dev/null | head -20
      register: hidden_files
      failed_when: false""",

        "system_modification": """
    # System modification specific tasks
    - name: Check for recently created users
      shell: grep -E 'useradd|adduser' /var/log/auth.log 2>/dev/null | tail -20 || echo "No user additions"
      register: new_users_log
      failed_when: false

    - name: Check installed packages
      shell: dpkg -l 2>/dev/null | tail -30 || rpm -qa 2>/dev/null | tail -30 || echo "No package manager"
      register: packages
      failed_when: false

    - name: Check for new systemd services
      shell: systemctl list-units --type=service --state=running 2>/dev/null | tail -20 || echo "No systemd"
      register: services
      failed_when: false""",

        "lateral_movement": """
    # Lateral movement specific tasks
    - name: Check active network connections
      shell: ss -tanp 2>/dev/null | head -30 || netstat -tanp 2>/dev/null | head -30
      register: active_connections
      failed_when: false

    - name: Check for SMB/RDP connections
      shell: ss -tan | grep -E ':445|:3389' 2>/dev/null || echo "No SMB/RDP connections"
      register: lateral_ports
      failed_when: false

    - name: Review SSH connections
      shell: ss -tan | grep ':22' 2>/dev/null | head -20 || echo "No SSH connections"
      register: ssh_connections
      failed_when: false""",

        "network_anomaly": """
    # Network anomaly specific tasks
    - name: Check for connections to poor-reputation IPs
      shell: ss -tan 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20
      register: external_connections
      failed_when: false

    - name: Review DNS queries
      shell: cat /var/log/syslog 2>/dev/null | grep -i dns | tail -20 || journalctl -u systemd-resolved 2>/dev/null | tail -20 || echo "No DNS logs"
      register: dns_queries
      failed_when: false

    - name: Check for unusual protocols
      shell: ss -tan | grep -vE '22|80|443' 2>/dev/null | head -20 || echo "No unusual protocols"
      register: unusual_protocols
      failed_when: false""",
    }

    # Default tasks for unknown or other attack types
    default_tasks = """
    - name: Capture system state snapshot
      shell: uptime && free -h && df -h
      register: system_state
      failed_when: false

    - name: Review recent system events
      shell: tail -50 /var/log/syslog 2>/dev/null || journalctl -n 50
      register: system_events
      failed_when: false"""

    return tasks_map.get(attack_type, default_tasks)
