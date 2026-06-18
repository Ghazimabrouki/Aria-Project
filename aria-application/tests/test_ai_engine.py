"""Unit tests for AI engine: prompt builder and response parser."""

import pytest

from response.ai_engine.response_parser import _parse_ai_response, _validate_playbook, _quality_gate_check
from response.ai_engine.prompt_builder import _build_prompt, _get_attack_type_tasks


class TestParseAIResponse:
    """Test _parse_ai_response with various LLM output formats."""

    def test_perfect_response(self):
        """Parser handles a well-formatted response with all sections."""
        text = """
## INCIDENT SUMMARY
A brute force attack was detected against the SSH service on web1.

## ATTACK CHAIN ANALYSIS
1. Attacker scanned for open SSH ports
2. Proceeded to brute force admin account
3. Multiple failed login attempts observed

## THREAT INTELLIGENCE
- Attacker IPs: 1.2.3.4, 5.6.7.8
- Target: web1 (10.0.0.1:22)
- MITRE: T1110

## RISK ASSESSMENT
High risk. If successful, attacker gains full system access.

## REMEDIATION PLAYBOOK
```yaml
---
- name: Block attacker
  hosts: web1
  tasks:
    - name: Drop attacker IP
      iptables:
        chain: INPUT
        source: "1.2.3.4"
        jump: DROP
```

## VERIFICATION PROCEDURE
1. Check iptables rules are active
2. Monitor for new brute force attempts
"""
        result = _parse_ai_response(text)
        assert "brute force attack" in result["summary"].lower()
        assert "scanned for open SSH" in result["narrative"]
        assert "Attacker IPs: 1.2.3.4" in result["threat_intel"]
        assert "High risk" in result["risk"]
        assert "Block attacker" in result["playbook_yaml"]
        assert "Check iptables" in result["verification"]

    def test_variant_headers(self):
        """Parser accepts both old and new header variants."""
        text = """
## SUMMARY
Short summary here.

## ATTACK NARRATIVE
Narrative content.

## RISK ASSESSMENT
Risk is medium.

## REMEDIATION PLAYBOOK
```yaml
---
- name: Test
  hosts: localhost
```
"""
        result = _parse_ai_response(text)
        assert "Short summary" in result["summary"]
        assert "Narrative content" in result["narrative"]
        assert "Risk is medium" in result["risk"]
        assert "Test" in result["playbook_yaml"]

    def test_think_block_removal(self):
        """Parser strips <think> blocks (DeepSeek R1)."""
        text = """
<thinking>
Let me analyze this incident step by step.
First, I need to identify the attack type.
</thinking>

## INCIDENT SUMMARY
Malware detected on host srv01.

## REMEDIATION PLAYBOOK
```yaml
---
- name: Kill malware
  hosts: srv01
```
"""
        result = _parse_ai_response(text)
        assert "Malware detected" in result["summary"]
        assert "thinking" not in result["summary"].lower()
        assert "step by step" not in result["summary"].lower()

    def test_risk_section_does_not_bleed(self):
        """Risk section stops at REMEDIATION PLAYBOOK, not end of text."""
        text = """
## RISK ASSESSMENT
The risk is critical. Immediate action required.

## REMEDIATION PLAYBOOK
```yaml
---
- name: Fix
  hosts: localhost
```

## VERIFICATION PROCEDURE
Verify the fix worked.
"""
        result = _parse_ai_response(text)
        assert "critical" in result["risk"].lower()
        assert "Fix" not in result["risk"]
        assert "Verify" not in result["risk"]
        assert "Fix" in result["playbook_yaml"]

    def test_missing_sections(self):
        """Parser handles responses with missing sections."""
        text = """
## INCIDENT SUMMARY
Only summary present.

## REMEDIATION PLAYBOOK
```yaml
---
- name: Test
  hosts: localhost
```
"""
        result = _parse_ai_response(text)
        assert "Only summary" in result["summary"]
        assert result["narrative"] == ""
        assert result["threat_intel"] == ""
        assert result["risk"] == ""
        assert result["verification"] == ""
        assert "Test" in result["playbook_yaml"]

    def test_empty_response(self):
        """Parser handles empty string."""
        result = _parse_ai_response("")
        assert result["summary"] == ""
        assert result["playbook_yaml"] == ""

    def test_yaml_without_fence(self):
        """Parser falls back to raw YAML detection."""
        text = """
## INCIDENT SUMMARY
Summary text.

## REMEDIATION PLAYBOOK
---
- name: Raw YAML
  hosts: localhost
  tasks:
    - debug:
        msg: "hello"
"""
        result = _parse_ai_response(text)
        assert "Raw YAML" in result["playbook_yaml"]

    def test_case_insensitive_headers(self):
        """Parser matches headers case-insensitively."""
        text = """
## incident summary
Lowercase summary.

## attack chain analysis
Lowercase narrative.

## Risk Assessment
Mixed case risk.
"""
        result = _parse_ai_response(text)
        assert "Lowercase summary" in result["summary"]
        assert "Lowercase narrative" in result["narrative"]
        assert "Mixed case risk" in result["risk"]

    def test_new_sections_parsed(self):
        """Parser extracts Phase 2 enriched sections."""
        text = """
## INCIDENT SUMMARY
A brute force attack was detected.

## ATTACK CHAIN ANALYSIS
1. Attacker scanned for open SSH ports
2. Proceeded to brute force admin account

## THREAT INTELLIGENCE
- Attacker IPs: 1.2.3.4

## RISK ASSESSMENT
High risk.

## ROOT CAUSE ANALYSIS
Weak password policy allowed brute force success.

## AFFECTED ASSET INVENTORY
- web1 (10.0.0.1): role=web, criticality=MEDIUM

## IMPACT ASSESSMENT
Confidentiality: suspected. Integrity: none. Availability: none.

## TIMELINE GAPS AND ANOMALIES
No logs between 02:00 and 02:30 UTC.

## CONFIDENCE SCORING
Compromise confirmed: High - successful auth observed.

## REMEDIATION PLAYBOOK
```yaml
---
- name: Block attacker
  hosts: web1
  tasks:
    - name: Drop IP
      ansible.builtin.iptables:
        chain: INPUT
        source: "1.2.3.4"
        jump: DROP
```

## VERIFICATION PROCEDURE
Check iptables.

## STRUCTURED METADATA (JSON)
```json
{
  "compromised": true,
  "compromise_confidence": "high",
  "attack_type": "brute_force",
  "primary_vector": "SSH brute force",
  "affected_assets": [
    {"host": "web1", "ip": "10.0.0.1", "role": "web", "compromised": true, "confidence": "high"}
  ],
  "impact": {
    "confidentiality": "suspected",
    "integrity": "none",
    "availability": "none",
    "business_impact": "moderate"
  },
  "mitre_techniques": ["T1110"],
  "attacker_ips": ["1.2.3.4"],
  "target_ips": ["10.0.0.1"],
  "recommended_actions": ["block_ip", "reset_password"],
  "risk_score": 75,
  "investigation_quality": "thorough"
}
```
"""
        result = _parse_ai_response(text)
        assert "brute force attack" in result["summary"].lower()
        assert "Weak password policy" in result["root_cause"]
        assert "web1" in result["asset_inventory"]
        assert "Confidentiality: suspected" in result["impact"]
        assert "No logs between" in result["timeline_gaps"]
        assert "Compromise confirmed: High" in result["confidence"]
        assert result["structured_metadata"] is not None
        assert result["structured_metadata"]["compromised"] is True
        assert result["structured_metadata"]["attack_type"] == "brute_force"
        assert result["structured_metadata"]["impact"]["business_impact"] == "moderate"

    def test_structured_metadata_fallback(self):
        """Parser tries fallback JSON extraction when block is malformed."""
        text = """
## INCIDENT SUMMARY
Summary here.

## STRUCTURED METADATA (JSON)
```json
{
  "compromised": true,
  "attack_type": "malware",
  "primary_vector": "phishing",
  "impact": {"business_impact": "severe"}
}
```
"""
        result = _parse_ai_response(text)
        assert result["structured_metadata"]["compromised"] is True
        assert result["structured_metadata"]["impact"]["business_impact"] == "severe"


class TestQualityGates:
    """Test _quality_gate_check scoring and thresholds."""

    def test_perfect_response_passes(self):
        parsed = {
            "summary": "A detailed incident summary with enough length to pass.",
            "narrative": "1. Initial access via phishing. 2. Reconnaissance performed. 3. Tools used.",
            "threat_intel": "IPs: 1.2.3.4",
            "risk": "High risk if not remediated.",
            "root_cause": "Unpatched vulnerability CVE-2024-1234.",
            "asset_inventory": "web1 (10.0.0.1): web server.",
            "impact": "Confidentiality: suspected. Integrity: none. Availability: none.",
            "timeline_gaps": "No gaps detected.",
            "confidence": "Compromise confirmed: High - evidence present.",
            "playbook_yaml": "---\n- name: Test\n  hosts: localhost\n",
            "verification": "Check logs.",
            "structured_metadata": {"compromised": True, "attack_type": "phishing", "primary_vector": "email", "impact": {"business_impact": "moderate"}},
        }
        quality = _quality_gate_check(parsed, "inv-123")
        assert quality["passed"] is True
        assert quality["overall_score"] >= 60
        assert quality["scores"]["playbook"] == 100

    def test_missing_playbook_fails(self):
        parsed = {
            "summary": "Short.",
            "narrative": "",
            "threat_intel": "",
            "risk": "",
            "root_cause": "",
            "asset_inventory": "",
            "impact": "",
            "timeline_gaps": "",
            "confidence": "",
            "playbook_yaml": "",
            "verification": "",
            "structured_metadata": None,
        }
        quality = _quality_gate_check(parsed, "inv-123")
        assert quality["passed"] is False
        assert "playbook_missing" in quality["warnings"]
        assert quality["scores"]["playbook"] == 0

    def test_no_evidence_citations_warns(self):
        parsed = {
            "summary": "A detailed incident summary with enough length to pass easily.",
            "narrative": "Attacker gained access. No citation markers here.",
            "threat_intel": "",
            "risk": "",
            "root_cause": "Root cause is known and documented here with detail.",
            "asset_inventory": "",
            "impact": "Impact is moderate and well understood by the team.",
            "timeline_gaps": "",
            "confidence": "Confidence is high based on available evidence sources.",
            "playbook_yaml": "---\n- name: Test\n  hosts: localhost\n",
            "verification": "",
            "structured_metadata": {"compromised": False, "attack_type": "scan", "primary_vector": "network", "impact": {"business_impact": "minimal"}},
        }
        quality = _quality_gate_check(parsed, "inv-123")
        assert "no_evidence_citations" in quality["warnings"]
        assert quality["scores"]["evidence_citation"] == 20

    def test_invalid_playbook_yaml_scores_low(self):
        parsed = {
            "summary": "A detailed incident summary with enough length to pass easily.",
            "narrative": "1. Initial access. 2. Reconnaissance.",
            "threat_intel": "",
            "risk": "",
            "root_cause": "Root cause is known and documented here with sufficient detail.",
            "asset_inventory": "",
            "impact": "Impact is moderate and well understood.",
            "timeline_gaps": "",
            "confidence": "Confidence is high based on evidence.",
            "playbook_yaml": "not valid yaml: [broken",
            "verification": "",
            "structured_metadata": {"compromised": False, "attack_type": "scan", "primary_vector": "network", "impact": {"business_impact": "minimal"}},
        }
        quality = _quality_gate_check(parsed, "inv-123")
        assert "playbook_invalid_yaml" in quality["warnings"]
        assert quality["scores"]["playbook"] == 50

    def test_structured_metadata_missing_keys_warns(self):
        parsed = {
            "summary": "A detailed incident summary with enough length to pass easily.",
            "narrative": "1. Initial access. 2. Reconnaissance.",
            "threat_intel": "",
            "risk": "",
            "root_cause": "Root cause is known.",
            "asset_inventory": "",
            "impact": "Impact is moderate.",
            "timeline_gaps": "",
            "confidence": "Confidence is high.",
            "playbook_yaml": "---\n- name: Test\n  hosts: localhost\n",
            "verification": "",
            "structured_metadata": {"compromised": True},  # missing attack_type, primary_vector, impact
        }
        quality = _quality_gate_check(parsed, "inv-123")
        assert any("structured_metadata_missing_keys" in w for w in quality["warnings"])
        assert quality["scores"]["structured_metadata"] == 70


class TestValidatePlaybook:
    """Test _validate_playbook YAML validation."""

    def test_valid_playbook_list(self):
        yaml_text = """---
- name: Test play
  hosts: localhost
  tasks:
    - debug:
        msg: "hello"
"""
        assert _validate_playbook(yaml_text) is True

    def test_valid_playbook_dict(self):
        # Ansible requires a LIST of plays, not a dict
        yaml_text = """---
- name: Test play
  hosts: localhost
  tasks:
    - debug:
        msg: "hello"
"""
        assert _validate_playbook(yaml_text) is True

    def test_invalid_yaml_syntax(self):
        yaml_text = """---
- name: Test
  hosts: localhost
  tasks:
    - debug: msg: "unquoted: colon"
"""
        assert _validate_playbook(yaml_text) is False

    def test_empty_string(self):
        assert _validate_playbook("") is False

    def test_too_short(self):
        assert _validate_playbook("---") is False

    def test_none_parsed(self):
        """YAML that parses to None (e.g., just comments)."""
        yaml_text = """---
# Just a comment
"""
        assert _validate_playbook(yaml_text) is False

    def test_empty_list(self):
        yaml_text = """---
[]
"""
        assert _validate_playbook(yaml_text) is False

    def test_list_of_non_dicts(self):
        yaml_text = """---
- "just a string"
- 123
"""
        assert _validate_playbook(yaml_text) is False


class TestBuildPrompt:
    """Test _build_prompt structure and content."""

    def test_prompt_includes_all_sections(self):
        context = {
            "incident": {"title": "Test Incident", "id": "inc-123"},
            "timeline": [
                {"time": "2024-01-01T00:00:00", "severity": "high", "source": "wazuh", "title": "SSH brute force"},
            ],
            "all_iocs": {
                "source_ips": ["1.2.3.4"],
                "dest_ips": ["10.0.0.1"],
                "hostnames": ["web1"],
            },
            "behavioral_indicators": {"auth_failure": 5},
            "attack_type": "brute_force",
            "risk_score": 75,
            "highest_severity": "high",
            "duration_minutes": 10,
            "mitre_tactics": ["Initial Access"],
            "mitre_techniques": ["T1110"],
            "summary": {
                "unique_attackers": 1,
                "unique_targets": 1,
                "attack_duration": 10,
                "total_alerts": 5,
                "primary_attack_method": "brute_force",
            },
            "proof_of_compromise": {"compromised": True, "confidence": "high", "indicators": ["Auth success after brute force"]},
            "asset_roles": {"web1": "web"},
            "network_evidence": {"http_requests": [], "tls_connections": [], "dns_queries": [], "ja3_fingerprints": []},
            "endpoint_evidence": {"commands": [], "processes": [], "file_changes": []},
        }
        prompt = _build_prompt(context)

        # Verify all required headers are in the prompt
        assert "## INCIDENT SUMMARY" in prompt
        assert "## ATTACK CHAIN ANALYSIS" in prompt
        assert "## THREAT INTELLIGENCE" in prompt
        assert "## RISK ASSESSMENT" in prompt
        assert "## ROOT CAUSE ANALYSIS" in prompt
        assert "## AFFECTED ASSET INVENTORY" in prompt
        assert "## IMPACT ASSESSMENT" in prompt
        assert "## TIMELINE GAPS AND ANOMALIES" in prompt
        assert "## CONFIDENCE SCORING" in prompt
        assert "## REMEDIATION PLAYBOOK" in prompt
        assert "## VERIFICATION PROCEDURE" in prompt
        assert "## STRUCTURED METADATA (JSON)" in prompt

        # Verify incident data is embedded
        assert "Test Incident" in prompt
        assert "1.2.3.4" in prompt
        assert "web1" in prompt
        assert "SSH brute force" in prompt
        assert "brute_force" in prompt
        assert "T1110" in prompt

        # Verify Phase 2 enriched context
        assert "PROOF OF COMPROMISE" in prompt
        assert "Auth success after brute force" in prompt
        assert "ASSET CRITICALITY" in prompt
        assert "role=web" in prompt
        assert "STRUCTURED EVIDENCE SUMMARY" in prompt

    def test_prompt_does_not_contain_hardcoded_tasks(self):
        """The generative prompt should NOT contain pre-filled attack tasks."""
        context = {
            "incident": {"title": "Test", "id": "inc-123"},
            "timeline": [],
            "all_iocs": {"source_ips": ["1.2.3.4"], "hostnames": ["web1"]},
            "behavioral_indicators": {},
            "attack_type": "brute_force",
            "risk_score": 50,
            "highest_severity": "medium",
            "duration_minutes": 5,
            "mitre_tactics": [],
            "mitre_techniques": [],
            "summary": {
                "unique_attackers": 1,
                "unique_targets": 1,
                "attack_duration": 5,
                "total_alerts": 1,
                "primary_attack_method": "brute_force",
            },
            "proof_of_compromise": {"compromised": False, "confidence": "low", "indicators": []},
            "asset_roles": {},
            "network_evidence": {},
            "endpoint_evidence": {},
        }
        prompt = _build_prompt(context)

        # Should contain GUIDANCE, not pre-filled tasks
        assert "CONSIDERATIONS" in prompt
        assert "Block attacker IPs at firewall" in prompt  # guidance
        assert "fail2ban" in prompt  # guidance

        # Should NOT contain the old hardcoded task blocks
        assert "grep \"Failed password\"" not in prompt
        assert "service:\n        name: fail2ban" not in prompt

    def test_prompt_instructs_generative_tasks(self):
        """Prompt explicitly tells LLM to generate original tasks."""
        context = {
            "incident": {"title": "Test", "id": "inc-123"},
            "timeline": [],
            "all_iocs": {"source_ips": ["1.2.3.4"]},
            "behavioral_indicators": {},
            "attack_type": "malware",
            "risk_score": 80,
            "highest_severity": "critical",
            "duration_minutes": 5,
            "mitre_tactics": [],
            "mitre_techniques": [],
            "summary": {
                "unique_attackers": 1,
                "unique_targets": 1,
                "attack_duration": 5,
                "total_alerts": 1,
                "primary_attack_method": "malware",
            },
            "proof_of_compromise": {"compromised": False, "confidence": "low", "indicators": []},
            "asset_roles": {},
            "network_evidence": {},
            "endpoint_evidence": {},
        }
        prompt = _build_prompt(context)

        assert "Generate context-specific tasks" in prompt or "ORIGINAL, CONTEXT-SPECIFIC tasks" in prompt
        assert "Do NOT echo the guidance text verbatim" in prompt

    def test_attack_type_guidance_included(self):
        """Each attack type includes relevant guidance."""
        context = {
            "incident": {"title": "Test", "id": "inc-123"},
            "timeline": [],
            "all_iocs": {"source_ips": ["1.2.3.4"]},
            "behavioral_indicators": {},
            "attack_type": "exfiltration",
            "risk_score": 60,
            "highest_severity": "high",
            "duration_minutes": 30,
            "mitre_tactics": [],
            "mitre_techniques": [],
            "summary": {
                "unique_attackers": 1,
                "unique_targets": 2,
                "attack_duration": 30,
                "total_alerts": 10,
                "primary_attack_method": "exfiltration",
            },
            "proof_of_compromise": {"compromised": False, "confidence": "low", "indicators": []},
            "asset_roles": {},
            "network_evidence": {},
            "endpoint_evidence": {},
        }
        prompt = _build_prompt(context)

        assert "DATA EXFILTRATION CONSIDERATIONS" in prompt
        assert "Block external destinations" in prompt
        assert "covert channels" in prompt


class TestGetAttackTypeTasks:
    """Test _get_attack_type_tasks fallback function."""

    def test_brute_force_tasks(self):
        tasks = _get_attack_type_tasks("brute_force", {})
        assert "grep \"Failed password\"" in tasks
        assert "fail2ban" in tasks

    def test_malware_tasks(self):
        tasks = _get_attack_type_tasks("malware", {})
        assert "suspicious processes" in tasks
        assert "crontabs" in tasks

    def test_unknown_attack_type(self):
        tasks = _get_attack_type_tasks("unknown_attack", {})
        assert "system state snapshot" in tasks
        assert "system events" in tasks

    def test_port_scan_tasks(self):
        tasks = _get_attack_type_tasks("port_scan", {})
        assert "conntrack" in tasks
        assert "SYN flood" in tasks
