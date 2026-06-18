"""
Parse infrastructure AI analysis responses into structured data.
"""

import json
import re
from typing import Dict, Any, Optional

import structlog

logger = structlog.get_logger()


def _extract_json_from_text(text: str) -> Optional[str]:
    """Extract JSON object from text that may contain markdown or extra prose."""
    if not text:
        return None

    text = text.strip()

    # Try direct JSON parse first
    if text.startswith("{") and text.endswith("}"):
        return text

    # Look for JSON inside markdown code blocks
    code_block_pattern = r"```(?:json)?\s*([\s\S]*?)```"
    matches = re.findall(code_block_pattern, text)
    for match in matches:
        match = match.strip()
        if match.startswith("{") and match.endswith("}"):
            return match

    # Look for the first { and last } in the text
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]

    return None


def parse_infrastructure_analysis(raw_response: str) -> Dict[str, Any]:
    """
    Parse the AI response into a structured infrastructure analysis dict.

    Returns a dict with defaults for any missing fields.
    """
    defaults = {
        "resource_impacted": "unknown",
        "responsible_process": None,
        "responsible_service": None,
        "issue_start_time": None,
        "behavior_classification": "unknown",
        "impact_assessment": "Unknown impact",
        "root_cause": "Analysis failed — fallback response",
        "confidence": 0.0,
        "explanation": "The AI did not return a valid analysis.",
        "immediate_mitigation": {
            "action": "Investigate manually",
            "risk": "Unknown",
            "expected_outcome": "Manual investigation required",
            "system_impact": "None from automated action",
            "rollback_feasible": True,
        },
        "long_term_optimization": {
            "action": "Review resource limits and capacity planning",
            "risk": "Low",
            "expected_outcome": "Better resource allocation",
            "system_impact": "None",
        },
        "suggested_playbook_tasks": [],
    }

    if not raw_response:
        logger.warning("infrastructure_analysis_empty_response")
        return defaults

    json_str = _extract_json_from_text(raw_response)
    if not json_str:
        logger.warning("infrastructure_analysis_no_json_found", raw_preview=raw_response[:200])
        defaults["explanation"] = f"AI returned non-JSON response: {raw_response[:300]}"
        return defaults

    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.warning("infrastructure_analysis_json_decode_failed", error=str(e), raw_preview=raw_response[:200])
        defaults["explanation"] = f"JSON decode error: {e}. Raw: {raw_response[:300]}"
        return defaults

    if not isinstance(parsed, dict):
        logger.warning("infrastructure_analysis_not_dict", type=type(parsed).__name__)
        return defaults

    # Merge parsed data with defaults
    result = {**defaults, **parsed}

    # Normalize nested dicts
    for key in ("immediate_mitigation", "long_term_optimization"):
        if isinstance(result.get(key), dict):
            result[key] = {**defaults[key], **result[key]}
        elif result.get(key) is None:
            result[key] = defaults[key]

    # Normalize responsible_process
    proc = result.get("responsible_process")
    if isinstance(proc, str):
        result["responsible_process"] = {"name": proc, "pid": 0}
    elif not isinstance(proc, dict):
        result["responsible_process"] = None

    # Validate confidence
    try:
        result["confidence"] = float(result.get("confidence", 0))
    except (ValueError, TypeError):
        result["confidence"] = 0.0

    logger.info(
        "infrastructure_analysis_parsed",
        resource=result.get("resource_impacted"),
        service=result.get("responsible_service"),
        confidence=result["confidence"],
    )

    return result
