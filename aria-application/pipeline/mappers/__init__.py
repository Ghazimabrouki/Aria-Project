"""
Field mappers for different security sources.
Each mapper transforms ES documents to OpenSOAR alert format.

Priority order:
1. Source-specific mappers (wazuh, falco, suricata, filebeat)
2. Generic mapper (fallback for unknown sources)
"""

from pipeline.mappers.wazuh import map_wazuh_alert
from pipeline.mappers.falco_runtime import map_falco_runtime_alert
from pipeline.mappers.filebeat import map_filebeat_alert
from pipeline.mappers.suricata import map_suricata_alert
from pipeline.mappers.generic import map_generic_alert
from pipeline.mappers.severity import map_severity


MAPPERS = {
    "wazuh": map_wazuh_alert,
    "falco": map_falco_runtime_alert,
    "filebeat": map_filebeat_alert,
    "suricata": map_suricata_alert,
    "generic": map_generic_alert,  # Fallback for unknown sources
}


def map_alert(source: str, payload: dict) -> dict:
    """
    Map an ES document to OpenSOAR format.
    
    Args:
        source: The source type (wazuh, falco, filebeat, suricata, generic)
        payload: The Elasticsearch document
    
    Returns:
        Mapped alert in OpenSOAR format
    
    Logic:
        1. Try source-specific mapper if available
        2. Fall back to generic mapper for unknown sources
        3. If mapping fails, return original payload
    """
    mapper = MAPPERS.get(source)
    
    # If no specific mapper, use generic fallback
    if not mapper:
        mapper = MAPPERS.get("generic")
    
    if not mapper:
        return payload
    
    try:
        return mapper(payload)
    except Exception as e:
        # If generic also fails, return original payload
        return payload