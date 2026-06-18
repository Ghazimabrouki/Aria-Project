import json
import re

import yaml


# Headers the prompt requests (primary) and variants the parser should accept
_SECTION_HEADERS = {
    "summary": ["## INCIDENT SUMMARY", "## SUMMARY"],
    "narrative": ["## ATTACK CHAIN ANALYSIS", "## ATTACK NARRATIVE"],
    "threat_intel": ["## THREAT INTELLIGENCE"],
    "risk": ["## RISK ASSESSMENT"],
    "root_cause": ["## ROOT CAUSE ANALYSIS", "## ROOT CAUSE"],
    "asset_inventory": ["## AFFECTED ASSET INVENTORY", "## ASSET INVENTORY", "## AFFECTED ASSETS"],
    "impact": ["## IMPACT ASSESSMENT", "## IMPACT"],
    "timeline_gaps": ["## TIMELINE GAPS AND ANOMALIES", "## TIMELINE GAPS", "## ANOMALIES"],
    "confidence": ["## CONFIDENCE SCORING", "## CONFIDENCE"],
    "playbook": ["## REMEDIATION PLAYBOOK"],
    "rollback": ["## ROLLBACK PLAYBOOK", "## ROLLBACK"],
    "verification": ["## VERIFICATION PROCEDURE", "## VERIFICATION"],
}


def _parse_ai_response(text: str) -> dict:
    """
    Extract the sections from AI response.
    Returns dict with keys for all parsed sections plus structured_metadata.
    """
    result = {
        "summary": "",
        "narrative": "",
        "threat_intel": "",
        "risk": "",
        "root_cause": "",
        "asset_inventory": "",
        "impact": "",
        "timeline_gaps": "",
        "confidence": "",
        "playbook_yaml": "",
        "rollback_yaml": "",
        "verification": "",
        "structured_metadata": None,
    }

    if not text:
        return result

    # Remove <think>...</think> blocks (deepseek-r1 chain-of-thought)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    def _extract_section(primary_markers: list[str], end_markers: list[str]) -> str:
        """Extract text between first matching primary marker and first end marker."""
        primary_pattern = "|".join(re.escape(m) for m in primary_markers)
        end_pattern = "|".join(re.escape(m) for m in end_markers) if end_markers else ""

        if end_pattern:
            pattern = rf"(?:{primary_pattern})\s*(.*?)(?={end_pattern}|$)"
        else:
            pattern = rf"(?:{primary_pattern})\s*(.*)$"

        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else ""

    # Collect all known headers for end-marker construction
    all_header_keys = list(_SECTION_HEADERS.keys())

    def _headers_after(key: str) -> list[str]:
        """Return all header strings that come after the given key in the document."""
        idx = all_header_keys.index(key)
        headers = []
        for k in all_header_keys[idx + 1:]:
            headers.extend(_SECTION_HEADERS[k])
        return headers

    result["summary"] = _extract_section(
        _SECTION_HEADERS["summary"], _headers_after("summary")
    )
    result["narrative"] = _extract_section(
        _SECTION_HEADERS["narrative"], _headers_after("narrative")
    )
    result["threat_intel"] = _extract_section(
        _SECTION_HEADERS["threat_intel"], _headers_after("threat_intel")
    )
    result["risk"] = _extract_section(
        _SECTION_HEADERS["risk"], _headers_after("risk")
    )
    result["root_cause"] = _extract_section(
        _SECTION_HEADERS["root_cause"], _headers_after("root_cause")
    )
    result["asset_inventory"] = _extract_section(
        _SECTION_HEADERS["asset_inventory"], _headers_after("asset_inventory")
    )
    result["impact"] = _extract_section(
        _SECTION_HEADERS["impact"], _headers_after("impact")
    )
    result["timeline_gaps"] = _extract_section(
        _SECTION_HEADERS["timeline_gaps"], _headers_after("timeline_gaps")
    )
    result["confidence"] = _extract_section(
        _SECTION_HEADERS["confidence"], _headers_after("confidence")
    )
    result["verification"] = _extract_section(
        _SECTION_HEADERS["verification"], _headers_after("verification")
    )
    result["rollback_yaml"] = _extract_section(
        _SECTION_HEADERS["rollback"], _headers_after("rollback")
    )

    # Extract YAML playbook from fenced code block
    yaml_match = re.search(r"```yaml\s*(.*?)```", text, re.DOTALL)
    if yaml_match:
        raw_yaml = yaml_match.group(1).strip()
        if raw_yaml.startswith("```"):
            raw_yaml = raw_yaml.split("```")[0].strip()
        if not raw_yaml.startswith("---"):
            raw_yaml = "---\n" + raw_yaml
        result["playbook_yaml"] = raw_yaml
    else:
        yaml_match = re.search(r"(---\s*\n.*)", text, re.DOTALL)
        if yaml_match:
            result["playbook_yaml"] = yaml_match.group(1).strip()

    # Extract structured JSON metadata block
    json_match = re.search(r"```json\s*(.*?)```", text, re.DOTALL)
    if json_match:
        raw_json = json_match.group(1).strip()
        if raw_json.startswith("```"):
            raw_json = raw_json.split("```")[0].strip()
        try:
            result["structured_metadata"] = json.loads(raw_json)
        except json.JSONDecodeError:
            # Try to extract the largest JSON object from the text
            result["structured_metadata"] = _extract_fallback_json(raw_json)

    return result


def _extract_fallback_json(text: str) -> dict | None:
    """Try to find a valid JSON object inside a partially broken block."""
    # Look for the outermost {...} pair
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    continue
    return None


def _quality_gate_check(parsed: dict, investigation_id: str = "") -> dict:
    """
    Evaluate the parsed AI response against quality criteria.
    Returns a dict with scores, warnings, and overall pass/fail.
    """
    import structlog
    logger = structlog.get_logger()

    warnings = []
    scores = {}

    # Gate 1: Summary presence and length
    summary = parsed.get("summary", "")
    if len(summary) < 30:
        warnings.append("summary_too_short")
        scores["summary"] = 0
    elif len(summary) < 80:
        scores["summary"] = 50
    else:
        scores["summary"] = 100

    # Pre-compute full_text for groundedness and citation checks
    narrative = parsed.get("narrative", "")
    full_text = "\n".join([
        summary, narrative,
        parsed.get("threat_intel", ""),
        parsed.get("risk", ""),
        parsed.get("root_cause", ""),
        parsed.get("impact", ""),
    ])
    full_text_lower = full_text.lower()

    # Gate 2: Narrative presence and structure + groundedness checks
    if len(narrative) < 50:
        warnings.append("narrative_too_short")
        scores["narrative"] = 0
    elif any(marker in narrative.lower() for marker in ("initial access", "reconnaissance", "step")):
        # Penalize hallucinated kill-chains
        hallucination_markers = [
            "kill chain", "kill-chain", "apt group", "advanced persistent threat",
            "state-sponsored", "nation-state", "sophisticated attacker",
        ]
        if any(m in full_text_lower for m in hallucination_markers):
            warnings.append("possible_hallucinated_kill_chain")
            scores["narrative"] = 40
        else:
            scores["narrative"] = 100
    else:
        scores["narrative"] = 70

    # Gate 3: Playbook presence and validity
    playbook = parsed.get("playbook_yaml", "")
    if not playbook:
        warnings.append("playbook_missing")
        scores["playbook"] = 0
    elif _validate_playbook(playbook):
        scores["playbook"] = 100
    else:
        warnings.append("playbook_invalid_yaml")
        scores["playbook"] = 50

    # Gate 4: Evidence-based assertions (check for citation patterns like [1], [2])
    citation_count = len(re.findall(r"\[\d+\]", full_text))
    if citation_count >= 3:
        scores["evidence_citation"] = 100
    elif citation_count >= 1:
        scores["evidence_citation"] = 60
        warnings.append("few_evidence_citations")
    else:
        scores["evidence_citation"] = 20
        warnings.append("no_evidence_citations")

    # Gate 5: Root cause analysis presence
    root_cause = parsed.get("root_cause", "")
    if len(root_cause) < 30:
        warnings.append("root_cause_missing_or_short")
        scores["root_cause"] = 0
    else:
        scores["root_cause"] = 100

    # Gate 6: Impact assessment presence
    impact = parsed.get("impact", "")
    if len(impact) < 20:
        warnings.append("impact_assessment_missing_or_short")
        scores["impact"] = 0
    else:
        scores["impact"] = 100

    # Gate 7: Confidence scoring presence
    confidence = parsed.get("confidence", "")
    if len(confidence) < 20:
        warnings.append("confidence_scoring_missing")
        scores["confidence"] = 0
    else:
        scores["confidence"] = 100

    # Gate 9: Rollback playbook presence (required for mutating playbooks)
    rollback = parsed.get("rollback_yaml", "")
    playbook = parsed.get("playbook_yaml", "")
    if not playbook:
        scores["rollback"] = 100  # No playbook = no rollback needed
    elif rollback and len(rollback) > 50 and not rollback.lower().startswith("no rollback required"):
        scores["rollback"] = 100
    else:
        # Check if playbook actually mutates state
        mutating_modules = ("ansible.builtin.iptables", "ansible.builtin.service", "ansible.builtin.shell",
                           "ansible.builtin.command", "ansible.builtin.lineinfile", "ansible.builtin.blockinfile",
                           "ansible.builtin.file", "ansible.builtin.copy", "ansible.builtin.template")
        has_mutating = False
        try:
            pb = yaml.safe_load(playbook)
            if isinstance(pb, list):
                for play in pb:
                    if isinstance(play, dict):
                        for task in play.get("tasks", []):
                            if isinstance(task, dict):
                                for key in task:
                                    if any(key.startswith(m) or key == m.split(".")[-1] for m in mutating_modules):
                                        has_mutating = True
                                        break
        except Exception:
            pass
        if has_mutating:
            warnings.append("rollback_playbook_missing_for_mutating_tasks")
            scores["rollback"] = 0
        else:
            scores["rollback"] = 100  # Read-only playbook doesn't need rollback

    # Gate 8: Structured metadata
    metadata = parsed.get("structured_metadata")
    if metadata and isinstance(metadata, dict):
        scores["structured_metadata"] = 100
        # Validate required keys
        required_keys = {"compromised", "attack_type", "primary_vector", "impact"}
        missing = required_keys - set(metadata.keys())
        if missing:
            warnings.append(f"structured_metadata_missing_keys: {missing}")
            scores["structured_metadata"] = 70
    else:
        warnings.append("structured_metadata_missing")
        scores["structured_metadata"] = 0

    # Overall score: weighted average
    weights = {
        "summary": 0.10,
        "narrative": 0.10,
        "playbook": 0.15,
        "evidence_citation": 0.15,
        "root_cause": 0.10,
        "impact": 0.10,
        "confidence": 0.10,
        "rollback": 0.10,
        "structured_metadata": 0.10,
    }
    total_weight = sum(weights.values())
    overall_score = sum(scores.get(k, 0) * weights[k] for k in weights) / total_weight

    # Pass threshold: 60/100, must have valid playbook, rollback required for mutating
    passed = overall_score >= 60 and scores["playbook"] >= 50 and scores["rollback"] >= 50

    if warnings:
        logger.warning("ai_response_quality_gates",
                      investigation_id=investigation_id,
                      overall_score=round(overall_score, 1),
                      passed=passed,
                      warnings=warnings,
                      scores=scores)
    else:
        logger.info("ai_response_quality_gates_passed",
                    investigation_id=investigation_id,
                    overall_score=round(overall_score, 1))

    return {
        "passed": passed,
        "overall_score": round(overall_score, 1),
        "scores": scores,
        "warnings": warnings,
    }


def _sanitize_playbook_yaml(playbook_yaml: str, investigation_id: str = "") -> str:
    """
    Post-process AI-generated playbook to fix known hallucinations and unsafe patterns.
    """
    import structlog
    logger = structlog.get_logger()
    
    if not playbook_yaml:
        return playbook_yaml
    
    # 1. Replace known fake/hallucinated Ansible modules with real ones
    module_replacements = {
        # Fake modules → real modules
        r"community\.general\.network\.firewall": "ansible.builtin.iptables",
        r"community\.general\.firewall": "ansible.builtin.iptables",
        r"community\.general\.parec": "ansible.builtin.iptables",
        r"ansible\.netfilter\.firewall_rule": "ansible.builtin.iptables",
        r"community\.general\.waflib": "ansible.builtin.iptables",
        r"community\.docker\.docker_host": "ansible.builtin.command",
        r"community\.general\.ufw_rule": "community.general.ufw",
    }
    
    # Catch bare module names that the AI sometimes hallucinates without namespace
    bare_module_replacements = {
        r"^\s+route:\s*$": "ansible.builtin.command: cmd=route -n",
    }
    
    for fake_module, real_module in module_replacements.items():
        if re.search(fake_module, playbook_yaml):
            logger.warning("ai_playbook_fake_module_replaced",
                         investigation_id=investigation_id,
                         fake=fake_module, real=real_module)
            playbook_yaml = re.sub(fake_module, real_module, playbook_yaml)
    
    # 2. Fix playbook names that contain colons (breaks YAML parsing)
    def _quote_name(match):
        name_value = match.group(1).strip()
        if ':' in name_value and not (name_value.startswith('"') and name_value.endswith('"')):
            escaped = name_value.replace('"', '\\"')
            return f'- name: "{escaped}"'
        return match.group(0)
    
    playbook_yaml = re.sub(r'^- name:\s*(.+)$', _quote_name, playbook_yaml, flags=re.MULTILINE)
    
    # 3. Strip placeholder comments that the AI sometimes adds
    placeholder_patterns = [
        r"#\s*Replace with actual.*$",
        r"#\s*Add more specific.*$",
        r"#\s*Replace \w+_name.*$",
    ]
    for pattern in placeholder_patterns:
        playbook_yaml = re.sub(pattern, "", playbook_yaml, flags=re.MULTILINE | re.IGNORECASE)
    
    # 4. Ensure iptables module uses valid parameters
    playbook_yaml = re.sub(r"remote_ip:", "source:", playbook_yaml)
    playbook_yaml = re.sub(r"firewall_name:", "comment:", playbook_yaml)
    playbook_yaml = re.sub(r"dport: any", "", playbook_yaml)
    playbook_yaml = re.sub(r"protocol: any", "", playbook_yaml)
    playbook_yaml = re.sub(r"state: disabled", "state: present", playbook_yaml)
    
    # 4a. Strip AI hallucinated annotations / notes that leak into YAML
    # The LLM sometimes appends VALIDATION_NOTES, NOTES, or markdown headers after the playbook
    annotation_markers = [
        r"^VALIDATION_NOTES:.*$",
        r"^VALIDATION\s+NOTES:.*$",
        r"^NOTES?:.*$",
        r"^NOTE:.*$",
        r"^WARNING:.*$",
        r"^##\s+ROLLBACK.*$",
        r"^##\s+VERIFICATION.*$",
        r"^##\s+STRUCTURED\s+METADATA.*$",
        r"^##\s+REMEDIATION\s+PLAYBOOK.*$",
    ]
    for pattern in annotation_markers:
        # Split on the marker and keep only the part before it
        parts = re.split(pattern, playbook_yaml, flags=re.MULTILINE | re.IGNORECASE)
        if len(parts) > 1:
            playbook_yaml = parts[0].rstrip()
            logger.warning("ai_playbook_stripped_annotation",
                         investigation_id=investigation_id,
                         pattern=pattern)
    
    # 5. Fix common Jinja2 typos in shell commands
    playbook_yaml = re.sub(r"\{\{\s*([^}]+?)\s*\}\s*\}", r"{{ \1}}", playbook_yaml)
    playbook_yaml = re.sub(r"\{\{\s*([^}]+?)\s+\}\}", r"{{ \1}}", playbook_yaml)
    playbook_yaml = re.sub(r"\{\{\s*([^}]+?[^\s}])\}\}", r"{{ \1 }}", playbook_yaml)
    
    # 6. Fix shell/command tasks where the value starts with a comment
    def _fix_shell_comment(match):
        indent = match.group(1)
        module = match.group(2)
        rest = match.group(3)
        lines = rest.split('\n')
        cleaned = [l for l in lines if not l.strip().startswith('#')]
        if cleaned:
            return f"{indent}{module}: |\n" + '\n'.join(f"{indent}  {l.strip()}" for l in cleaned)
        return f"{indent}{module}: echo 'placeholder'"
    
    playbook_yaml = re.sub(
        r"^(\s+)(ansible\.builtin\.(?:shell|command)):\s*(#.*(?:\n\1\s+.*)*)",
        _fix_shell_comment,
        playbook_yaml,
        flags=re.MULTILINE
    )
    
    # Clean up extra blank lines from removals
    playbook_yaml = re.sub(r'\n{3,}', '\n\n', playbook_yaml)
    
    return playbook_yaml


def _validate_playbook(playbook_yaml: str) -> bool:
    """Check that the generated YAML is valid Ansible playbook syntax.
    
    Two-stage validation:
    1. YAML structural validation (pyyaml)
    2. Ansible syntax-check (ansible-playbook --syntax-check)
    """
    import structlog
    import tempfile
    import subprocess
    import os
    logger = structlog.get_logger()
    
    if not playbook_yaml or len(playbook_yaml) < 20:
        return False
    
    # Stage 1: YAML structural validation
    try:
        parsed = yaml.safe_load(playbook_yaml)
        if parsed is None:
            return False
        if isinstance(parsed, list) and len(parsed) > 0:
            if not isinstance(parsed[0], dict):
                return False
        elif isinstance(parsed, dict):
            if len(parsed) == 0:
                return False
        else:
            return False
    except yaml.YAMLError:
        return False
    
    # Stage 2: Ansible syntax-check validation
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, prefix="opensoar_syntax_check_"
        ) as tmp:
            tmp.write(playbook_yaml)
            tmp_path = tmp.name
        
        cmd = [
            "ansible-playbook",
            "--syntax-check",
            "-i", "/dev/null",
            tmp_path,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        os.unlink(tmp_path)
        
        if result.returncode != 0:
            logger.warning(
                "ansible_syntax_check_failed",
                stderr=result.stderr[:500] if result.stderr else "",
                stdout=result.stdout[:500] if result.stdout else "",
            )
            return False
        
        return True
    except FileNotFoundError:
        # ansible-playbook not installed — skip syntax-check, rely on YAML validation only
        logger.debug("ansible_playbook_not_found_skipping_syntax_check")
        return True
    except subprocess.TimeoutExpired:
        logger.warning("ansible_syntax_check_timeout")
        return False
    except Exception as e:
        logger.warning("ansible_syntax_check_error", error=str(e))
        return False


def _ai_grounding_quality_check(parsed: dict, context: dict, investigation_id: str = "") -> dict:
    """
    Evaluate AI output for evidence grounding, hallucination risk, and analyst usefulness.
    Returns dict with scores, status, and reasons.
    """
    import structlog
    logger = structlog.get_logger()

    summary = parsed.get("summary", "")
    narrative = parsed.get("narrative", "")
    full_text = f"{summary}\n{narrative}"
    full_text_lower = full_text.lower()

    alerts = context.get("alerts", [])
    alert_ids = [a.get("id", "") for a in alerts if a.get("id")]
    alert_sources = list({a.get("source", "") for a in alerts if a.get("source")})
    source_ips = context.get("source_ips", [])
    hostnames = context.get("hostnames", [])
    mitre_tactics = context.get("mitre_tactics", [])
    attack_type = context.get("attack_type", "unknown")

    scores = {}
    reasons = []

    # Gate 1: Summary must not be empty
    if not summary or len(summary.strip()) < 30:
        scores["summary_presence"] = 0
        reasons.append("empty_or_too_short_summary")
    else:
        scores["summary_presence"] = 100

    # Gate 2: Evidence citations — must reference alert IDs, timestamps, or specific fields
    has_alert_refs = any(aid in full_text for aid in alert_ids[:5])
    has_ip_refs = any(ip in full_text for ip in source_ips[:3])
    has_hostname_refs = any(h in full_text for h in hostnames[:3])
    has_timestamp_pattern = bool(re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}", full_text))
    citation_score = 0
    if has_alert_refs:
        citation_score += 40
    if has_ip_refs:
        citation_score += 20
    if has_hostname_refs:
        citation_score += 20
    if has_timestamp_pattern:
        citation_score += 20
    scores["evidence_grounding"] = citation_score
    if citation_score < 60:
        reasons.append(f"weak_evidence_grounding (score={citation_score}/100)")

    # Gate 3: Hallucination checks — unsupported claims
    hallucination_terms = [
        "web application attack", "web app attack", "sql injection", "xss attack",
        "privilege escalation", "privilege-escalation",
        "apt", "advanced persistent threat", "apt group", "state-sponsored", "nation-state",
        "kill chain", "kill-chain", "lateral movement", "lateral-movement",
        "persistence", "persistent backdoor", "c2 beacon", "command and control",
        "compromise", "system compromised", "host compromised",
    ]

    def _is_negated(text: str, term: str) -> bool:
        """Check if a term is preceded by a negation within 20 chars."""
        idx = text.find(term)
        if idx < 0:
            return False
        before = text[max(0, idx - 20):idx]
        # Use regex to detect negation words as whole words before the term
        return bool(re.search(r"\b(no|not|without|never)\s+$", before))

    found_hallucinations = []
    for term in hallucination_terms:
        if term in full_text_lower:
            # Skip negated terms (e.g., "No lateral movement confirmed")
            if _is_negated(full_text_lower, term):
                continue
            # Only flag as hallucination if evidence doesn't support it
            # For MITRE tactics, check if they're actually in the alert context
            if "mitre" in term or "apt" in term or "kill chain" in term:
                if not mitre_tactics:
                    found_hallucinations.append(term)
            elif "web" in term or "sql" in term or "xss" in term:
                # Check if any alert source is suricata/waf with web-related rule
                web_sources = {"suricata", "waf", "nginx", "apache"}
                if not any(s in web_sources for s in alert_sources):
                    found_hallucinations.append(term)
            elif "lateral movement" in term or "compromise" in term:
                # SSH brute-force specific: only failed logins does NOT equal compromise or lateral movement
                if attack_type == "brute_force":
                    # Check if there's evidence of successful login or post-auth activity
                    has_successful_login = any(
                        "accepted" in str(a.get("title", "")).lower() or
                        "successful" in str(a.get("title", "")).lower() or
                        "session opened" in str(a.get("title", "")).lower()
                        for a in alerts
                    )
                    if not has_successful_login:
                        found_hallucinations.append(f"{term} (no successful login evidence)")
                else:
                    found_hallucinations.append(term)
            else:
                found_hallucinations.append(term)

    # Extra penalty for system isolation recommendations in brute-force without compromise evidence
    if attack_type == "brute_force" and ("isolate" in full_text_lower or "systemctl isolate" in full_text_lower):
        # Skip if "isolate" is negated
        iso_idx = full_text_lower.find("isolate")
        iso_negated = False
        if iso_idx >= 0:
            before = full_text_lower[max(0, iso_idx - 20):iso_idx]
            iso_negated = bool(re.search(r"\b(no|not|without|never|do not)\s+$", before))
        has_successful_login = any(
            "accepted" in str(a.get("title", "")).lower() or
            "successful" in str(a.get("title", "")).lower() or
            "session opened" in str(a.get("title", "")).lower()
            for a in alerts
        )
        if not iso_negated and not has_successful_login:
            found_hallucinations.append("isolate system (unjustified for brute-force without compromise)")

    if found_hallucinations:
        scores["hallucination_risk"] = max(0, 100 - len(found_hallucinations) * 25)
        reasons.append(f"possible_hallucinations: {', '.join(found_hallucinations[:3])}")
    else:
        scores["hallucination_risk"] = 100

    # Gate 4: Source type distinction
    source_mentions = []
    if "wazuh" in full_text_lower:
        source_mentions.append("wazuh")
    if "suricata" in full_text_lower or "filebeat" in full_text_lower:
        source_mentions.append("network")
    if "falco" in full_text_lower:
        source_mentions.append("falco")
    expected_sources = set()
    for s in alert_sources:
        s_lower = s.lower()
        if "wazuh" in s_lower:
            expected_sources.add("wazuh")
        if "suricata" in s_lower or "filebeat" in s_lower:
            expected_sources.add("network")
        if "falco" in s_lower:
            expected_sources.add("falco")
    if expected_sources and not source_mentions:
        scores["source_distinction"] = 20
        reasons.append("no_source_type_distinction")
    elif expected_sources and len(source_mentions) < len(expected_sources):
        scores["source_distinction"] = 60
        reasons.append("incomplete_source_type_distinction")
    else:
        scores["source_distinction"] = 100

    # Gate 5: Analyst usefulness — actionable specificity
    actionable_markers = ["block", "isolate", "restart", "disable", "remove", "quarantine", "alert"]
    has_actionable = any(m in full_text_lower for m in actionable_markers)
    if not has_actionable and parsed.get("playbook_yaml"):
        scores["analyst_usefulness"] = 40
        reasons.append("summary_lacks_actionable_recommendations")
    else:
        scores["analyst_usefulness"] = 100

    # Gate 6: Confidence language — must not claim certainty without evidence
    certainty_markers = ["definitely", "certainly", "absolutely", "without doubt", "confirmed compromise"]
    found_certainty = [m for m in certainty_markers if m in full_text_lower]
    if found_certainty and not has_alert_refs:
        scores["confidence_appropriateness"] = 30
        reasons.append(f"unjustified_certainty: {', '.join(found_certainty[:2])}")
    else:
        scores["confidence_appropriateness"] = 100

    # Overall scoring
    weights = {
        "summary_presence": 0.20,
        "evidence_grounding": 0.25,
        "hallucination_risk": 0.25,
        "source_distinction": 0.10,
        "analyst_usefulness": 0.10,
        "confidence_appropriateness": 0.10,
    }
    total_weight = sum(weights.values())
    overall_score = sum(scores.get(k, 0) * weights[k] for k in weights) / total_weight

    # Status thresholds
    if scores["summary_presence"] == 0:
        status = "failed"
    elif overall_score >= 75 and scores["hallucination_risk"] >= 75:
        status = "passed"
    elif overall_score >= 50 and scores["hallucination_risk"] >= 50:
        status = "weak"
    else:
        status = "failed"

    if reasons:
        logger.warning("ai_grounding_quality_check",
                      investigation_id=investigation_id,
                      status=status,
                      overall_score=round(overall_score, 1),
                      reasons=reasons,
                      scores=scores)
    else:
        logger.info("ai_grounding_quality_check_passed",
                    investigation_id=investigation_id,
                    overall_score=round(overall_score, 1))

    return {
        "status": status,
        "overall_score": round(overall_score, 1),
        "scores": scores,
        "reasons": reasons,
    }
