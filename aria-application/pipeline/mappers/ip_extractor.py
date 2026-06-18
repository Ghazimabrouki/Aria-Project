"""
IP extraction utilities for different security sources.
Extracts source and destination IPs from various document formats.
"""

import re
from typing import Optional, Dict, Any


def extract_ips(doc: Dict[str, Any], source_type: str) -> tuple[Optional[str], Optional[str]]:
    """
    Extract source and destination IPs from an ES document.
    
    Args:
        doc: The Elasticsearch document
        source_type: The source type (wazuh, falco, filebeat, suricata)
    
    Returns:
        Tuple of (source_ip, dest_ip)
    """
    if source_type == "wazuh":
        return _extract_wazuh_ips(doc)
    elif source_type == "falco":
        return _extract_falco_ips(doc)
    elif source_type == "suricata":
        return _extract_suricata_ips(doc)
    else:
        return _extract_filebeat_ips(doc)


def _extract_wazuh_ips(doc: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Extract IPs from Wazuh alerts"""
    src_ip = doc.get("src_ip") or doc.get("source_ip")
    dst_ip = doc.get("dst_ip") or doc.get("dest_ip")
    
    data = doc.get("data", {})
    if isinstance(data, dict):
        if not src_ip:
            src_ip = data.get("srcip") or data.get("src_ip")
        if not dst_ip:
            dst_ip = data.get("dstip") or data.get("dst_ip")
    
    full_log = doc.get("full_log", "")
    if not src_ip and full_log:
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', full_log)
        if ip_match:
            src_ip = ip_match.group(1)
    
    return src_ip, dst_ip


def _extract_falco_ips(doc: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Extract IPs from Falco alerts"""
    src_ip = doc.get("source_ip")
    dst_ip = doc.get("dest_ip")
    
    output = doc.get("output", "")
    if not src_ip and output:
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
        if ip_match:
            src_ip = ip_match.group(1)
    
    output_fields = doc.get("output_fields", {})
    if not src_ip and output_fields:
        for key, value in output_fields.items():
            if isinstance(value, str) and re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', value):
                src_ip = value
                break
    
    return src_ip, dst_ip


def _extract_filebeat_ips(doc: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Extract IPs from generic Filebeat alerts"""
    src_ip = None
    dst_ip = None
    
    source_data = doc.get("source", {})
    dest_data = doc.get("destination", {})
    
    if isinstance(source_data, dict):
        src_ip = source_data.get("ip")
    if isinstance(dest_data, dict):
        dst_ip = dest_data.get("ip")
    
    if not src_ip:
        src_ip = doc.get("source_ip") or doc.get("src_ip")
    if not dst_ip:
        dst_ip = doc.get("dest_ip") or doc.get("dst_ip")
    
    if not src_ip and doc.get("message"):
        msg = doc.get("message", "")
        ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', msg)
        if ip_matches:
            src_ip = ip_matches[0]
            if len(ip_matches) > 1:
                dst_ip = ip_matches[1]
    
    return src_ip, dst_ip


def _extract_suricata_ips(doc: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Extract IPs from Suricata alerts"""
    source_data = doc.get("source", {})
    dest_data = doc.get("destination", {})
    
    src_ip = source_data.get("ip") if isinstance(source_data, dict) else None
    dst_ip = dest_data.get("ip") if isinstance(dest_data, dict) else None
    
    if not src_ip:
        suricata_eve = doc.get("suricata", {}).get("eve", {})
        flow = suricata_eve.get("flow", {})
        src_ip = flow.get("src_ip")
        if not dst_ip:
            dst_ip = flow.get("dest_ip")
    
    return src_ip, dst_ip