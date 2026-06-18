"""
Infrastructure AI Engine — SRE-mode analysis for resource alerts.

Analyzes CPU, memory, disk, and network anomalies like an expert
infrastructure engineer, not a SOC analyst.
"""

from .main import analyze_resource_anomaly, generate_infrastructure_playbook, interpret_diagnostic_output

__all__ = ["analyze_resource_anomaly", "generate_infrastructure_playbook", "interpret_diagnostic_output"]
