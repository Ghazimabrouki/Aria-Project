"""
Infrastructure AI Engine Orchestrator.

Analyzes resource anomalies using SRE-mode AI and generates safe playbooks.
"""

import asyncio
import json
from typing import Dict, Any, Optional

import structlog

from config import get_settings
from response.ai_engine.llm_clients import _call_llm
from .context_builder import ResourceContext, build_resource_context
from .prompt_builder import build_sre_analysis_prompt
from .response_parser import parse_infrastructure_analysis
from .playbook_generator import generate_safe_playbook
from .diagnostic_interpreter import interpret_diagnostic_results

logger = structlog.get_logger()


async def analyze_resource_anomaly(
    host: str,
    metrics,
    anomaly_type: str,
    current_value: float,
    threshold: float,
    severity: str,
    metrics_history: Optional[list] = None,
    baseline_deviation: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyze a resource anomaly using SRE-mode AI.

    Returns a dict with:
        - analysis: structured analysis result
        - context: ResourceContext dataclass
        - playbook_yaml: safe Ansible playbook
        - description: markdown summary for the investigation
    """
    settings = get_settings()

    # Build structured resource context
    context = build_resource_context(
        host=host,
        metrics=metrics,
        anomaly_type=anomaly_type,
        current_value=current_value,
        threshold=threshold,
        severity=severity,
        metrics_history=metrics_history,
        baseline_deviation=baseline_deviation,
    )

    # Build SRE prompt
    prompt = build_sre_analysis_prompt(context, metrics_history)

    # Call LLM with timeout
    try:
        raw_response = await asyncio.wait_for(
            _call_llm(prompt),
            timeout=getattr(settings, "llm_timeout", getattr(settings, "ollama_timeout", 60)),
        )
    except asyncio.TimeoutError:
        logger.warning("infrastructure_ai_timeout", host=host, resource_type=context.resource_type)
        raw_response = None
    except Exception as e:
        logger.error("infrastructure_ai_failed", host=host, error=str(e))
        raw_response = None

    # Parse response
    if raw_response:
        analysis = parse_infrastructure_analysis(raw_response)
    else:
        analysis = parse_infrastructure_analysis("")
        analysis["explanation"] = f"AI analysis timed out for {context.resource_type} anomaly on {host}"
        analysis["root_cause"] = f"{context.resource_type.upper()} at {current_value:.1f}{context.unit} — manual investigation required"

    # Update context with AI results
    context.root_cause_confidence = analysis.get("confidence", 0.0)

    # Generate pure diagnostic playbook (no mitigation)
    affected_service = analysis.get("responsible_service", context.affected_service)

    try:
        playbook_yaml = generate_safe_playbook(
            resource_type=context.resource_type,
            affected_service=affected_service or "unknown",
            mitigation_action="investigate",
            host=host,
        )
    except ValueError as e:
        logger.error("infrastructure_playbook_generation_failed", error=str(e))
        playbook_yaml = _generate_fallback_playbook(context)

    # Build markdown description
    description = _build_investigation_description(context, analysis, {})

    return {
        "analysis": analysis,
        "context": context,
        "playbook_yaml": playbook_yaml,
        "description": description,
        "resource_context_json": _context_to_dict(context),
    }


def _context_to_dict(context: ResourceContext) -> Dict[str, Any]:
    """Convert ResourceContext to a plain dict for JSON storage."""
    from dataclasses import asdict
    return asdict(context)


def _build_investigation_description(
    context: ResourceContext,
    analysis: Dict[str, Any],
    mitigation: Dict[str, Any],
) -> str:
    """Build a markdown description for the investigation."""

    proc = analysis.get("responsible_process") or context.affected_process or {}
    service = analysis.get("responsible_service", context.affected_service or "unknown")
    long_term = analysis.get("long_term_optimization", {})

    top_procs = "\n".join(
        f"- {p.get('name', 'unknown')}: CPU={p.get('cpu_percent', 0):.1f}%, MEM={p.get('memory_rss', 0) / 1024 / 1024:.1f}MB"
        for p in context.top_processes[:5]
    )

    return f"""## Infrastructure Resource Anomaly

### Resource Details
- **Type:** {context.resource_type.upper()}
- **Host:** {context.affected_host}
- **Current Value:** {context.current_value:.1f} {context.unit}
- **Threshold:** {context.threshold:.1f} {context.unit}
- **Severity:** {context.severity}
- **Trend:** {context.historical_trend}
- **Baseline Deviation:** {context.baseline_deviation or "unknown"}

### Root Cause Analysis
**Confidence:** {analysis.get('confidence', 0):.0%}

{analysis.get('root_cause', 'Analysis pending')}

### Responsible Process/Service
- **Service:** {service}
- **Process:** {proc.get('name', 'unknown')} (PID {proc.get('pid', 'unknown')})
- **Classification:** {analysis.get('behavior_classification', 'unknown')}

### Impact Assessment
{analysis.get('impact_assessment', 'No impact assessment available')}

### Top Processes
{top_procs or 'No process data available'}

### Suggested Immediate Mitigation
**Action:** {mitigation.get('action', 'None')}
**Risk:** {mitigation.get('risk', 'Unknown')}
**Expected Outcome:** {mitigation.get('expected_outcome', 'Unknown')}
**System Impact:** {mitigation.get('system_impact', 'Unknown')}
**Rollback Feasible:** {mitigation.get('rollback_feasible', False)}

### Long-Term Optimization
**Action:** {long_term.get('action', 'None')}
**Risk:** {long_term.get('risk', 'Unknown')}
**Expected Outcome:** {long_term.get('expected_outcome', 'Unknown')}

### AI Explanation
{analysis.get('explanation', 'No detailed explanation available')}
"""


def _generate_fallback_playbook(context: ResourceContext) -> str:
    """Generate a minimal fallback playbook when AI generation fails."""
    import yaml

    tasks = [
        {
            "name": f"Diagnose {context.resource_type} issue",
            "ansible.builtin.shell": f"echo 'Investigating {context.resource_type} anomaly on {context.affected_host}'",
            "changed_when": False,
        },
        {
            "name": "Collect system metrics",
            "ansible.builtin.shell": "uptime && free -h && df -h | head -5",
            "changed_when": False,
            "failed_when": False,
        },
    ]

    playbook = [{
        "name": f"Fallback Investigation — {context.resource_type.upper()} on {context.affected_host}",
        "hosts": context.affected_host,
        "become": True,
        "gather_facts": False,
        "tasks": tasks,
    }]

    return yaml.safe_dump(playbook, sort_keys=False, default_flow_style=False)


async def generate_infrastructure_playbook(
    resource_type: str,
    affected_service: str,
    mitigation_action: str,
    host: str = "target",
) -> str:
    """Public API to generate a safe infrastructure playbook."""
    return generate_safe_playbook(
        resource_type=resource_type,
        affected_service=affected_service,
        mitigation_action=mitigation_action,
        host=host,
    )


async def interpret_diagnostic_output(
    context: ResourceContext,
    diagnostic_output: str,
) -> Dict[str, Any]:
    """
    Interpret raw diagnostic output like an expert SRE.

    This is the second AI call in the diagnostic pipeline — called AFTER
    the diagnostic playbook has run and collected evidence from the target.

    Returns structured DiagnosticFindings dict.
    """
    return await interpret_diagnostic_results(context, diagnostic_output)
