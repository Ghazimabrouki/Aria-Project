"""
Enrichment modules for alert data.
Provides dynamic IP enrichment, MITRE ATT&CK mapping, and Sigma-based noise filtering.
"""

from pipeline.enrichment.geoip import enrich_alert, enrich_ip
from pipeline.enrichment.mitre import enrich_with_mitre, dynamic_mitre_mapping
from pipeline.enrichment.sigma import is_noise_alert
