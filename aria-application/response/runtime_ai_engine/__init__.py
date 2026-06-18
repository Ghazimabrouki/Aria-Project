"""
Runtime Security AI Engine.

Handles Falco runtime security events with a diagnostic-first approach:
1. Build RuntimeContext from Falco alert data
2. Generate diagnostic playbooks (read-only)
3. Interpret diagnostic output (rule-based primary, AI fallback)
4. Generate safe remediation playbooks when escalated
"""

from response.runtime_ai_engine.context_builder import RuntimeContext, build_runtime_context
from response.runtime_ai_engine.playbook_generator import generate_runtime_diagnostic_playbook
from response.runtime_ai_engine.diagnostic_interpreter import interpret_runtime_diagnostic
from response.runtime_ai_engine.remediation_playbook_generator import generate_runtime_remediation_playbook

__all__ = [
    "RuntimeContext",
    "build_runtime_context",
    "generate_runtime_diagnostic_playbook",
    "interpret_runtime_diagnostic",
    "generate_runtime_remediation_playbook",
]
