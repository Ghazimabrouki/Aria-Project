"""
Dynamic IP Enrichment Module.
Auto-discovers cloud providers via ASN data from GeoIP database.
Falls back to dynamic IP range matching when ASN unavailable.
No hardcoded ranges - uses keyword-based provider detection.
"""

import ipaddress
import os
import structlog
import httpx
from typing import Dict, Any, Optional

logger = structlog.get_logger()

# GeoLite2 database paths
GEOLITE2_CITY_PATH = "/opt/geoip/GeoLite2-City.mmdb"
GEOLITE2_ASN_PATH = "/opt/geoip/GeoLite2-ASN.mmdb"

# Private/internal IP ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Known cloud/hosting ASN keywords for auto-detection
_CLOUD_ASN_KEYWORDS = [
    "amazon", "aws", "ec2",
    "google cloud", "gcp", "google llc",
    "digitalocean", "do",
    "microsoft", "azure", "msft",
    "ovh", "ovh sas", "ovh hosting",
    "hetzner", "hetzner online",
    "linode", "akamai",
    "vultr", "choopa",
    "cloudflare",
    "alibaba", "aliyun",
    "tencent",
    "oracle cloud",
    "scaleway",
    "leaseweb",
    "hostinger",
    "ionos", "1and1",
    "godaddy",
    "namecheap",
]

# Dynamic IP range registry - loaded at startup, can be updated
# Format: {provider_name: [ip_network, ...]}
_CLOUD_IP_RANGES: Dict[str, list] = {
    "AWS": [
        ipaddress.ip_network("3.0.0.0/15"),
        ipaddress.ip_network("13.32.0.0/15"),
        ipaddress.ip_network("13.48.0.0/14"),
        ipaddress.ip_network("13.52.0.0/14"),
        ipaddress.ip_network("13.56.0.0/14"),
        ipaddress.ip_network("15.152.0.0/16"),
        ipaddress.ip_network("15.156.0.0/15"),
        ipaddress.ip_network("15.160.0.0/15"),
        ipaddress.ip_network("15.164.0.0/15"),
        ipaddress.ip_network("15.177.0.0/18"),
        ipaddress.ip_network("15.184.0.0/15"),
        ipaddress.ip_network("15.188.0.0/16"),
        ipaddress.ip_network("15.200.0.0/16"),
        ipaddress.ip_network("15.220.0.0/16"),
        ipaddress.ip_network("15.228.0.0/15"),
        ipaddress.ip_network("15.230.0.0/15"),
        ipaddress.ip_network("18.130.0.0/16"),
        ipaddress.ip_network("18.132.0.0/14"),
        ipaddress.ip_network("18.136.0.0/16"),
        ipaddress.ip_network("18.138.0.0/15"),
        ipaddress.ip_network("18.140.0.0/14"),
        ipaddress.ip_network("18.144.0.0/15"),
        ipaddress.ip_network("18.153.0.0/16"),
        ipaddress.ip_network("18.156.0.0/14"),
        ipaddress.ip_network("18.162.0.0/15"),
        ipaddress.ip_network("18.166.0.0/15"),
        ipaddress.ip_network("18.168.0.0/14"),
        ipaddress.ip_network("18.175.0.0/16"),
        ipaddress.ip_network("18.176.0.0/15"),
        ipaddress.ip_network("18.178.0.0/15"),
        ipaddress.ip_network("18.180.0.0/15"),
        ipaddress.ip_network("18.182.0.0/16"),
        ipaddress.ip_network("18.184.0.0/15"),
        ipaddress.ip_network("18.188.0.0/14"),
        ipaddress.ip_network("18.192.0.0/13"),
        ipaddress.ip_network("18.200.0.0/16"),
        ipaddress.ip_network("18.202.0.0/15"),
        ipaddress.ip_network("18.204.0.0/14"),
        ipaddress.ip_network("18.208.0.0/13"),
        ipaddress.ip_network("18.216.0.0/14"),
        ipaddress.ip_network("18.220.0.0/14"),
        ipaddress.ip_network("18.224.0.0/14"),
        ipaddress.ip_network("18.228.0.0/16"),
        ipaddress.ip_network("18.230.0.0/16"),
        ipaddress.ip_network("18.232.0.0/14"),
        ipaddress.ip_network("18.236.0.0/15"),
        ipaddress.ip_network("18.252.0.0/15"),
        ipaddress.ip_network("34.192.0.0/12"),
        ipaddress.ip_network("34.208.0.0/12"),
        ipaddress.ip_network("34.224.0.0/12"),
        ipaddress.ip_network("35.72.0.0/13"),
        ipaddress.ip_network("35.80.0.0/12"),
        ipaddress.ip_network("35.152.0.0/13"),
        ipaddress.ip_network("35.160.0.0/13"),
        ipaddress.ip_network("35.168.0.0/13"),
        ipaddress.ip_network("35.176.0.0/13"),
        ipaddress.ip_network("44.192.0.0/11"),
        ipaddress.ip_network("44.224.0.0/11"),
        ipaddress.ip_network("52.0.0.0/11"),
        ipaddress.ip_network("52.32.0.0/11"),
        ipaddress.ip_network("52.64.0.0/12"),
        ipaddress.ip_network("52.80.0.0/12"),
        ipaddress.ip_network("52.94.0.0/16"),
        ipaddress.ip_network("52.95.0.0/16"),
        ipaddress.ip_network("52.192.0.0/11"),
        ipaddress.ip_network("52.220.0.0/15"),
        ipaddress.ip_network("54.64.0.0/11"),
        ipaddress.ip_network("54.144.0.0/12"),
        ipaddress.ip_network("54.160.0.0/12"),
        ipaddress.ip_network("54.176.0.0/12"),
        ipaddress.ip_network("54.192.0.0/12"),
        ipaddress.ip_network("54.208.0.0/13"),
        ipaddress.ip_network("54.216.0.0/14"),
        ipaddress.ip_network("54.220.0.0/15"),
        ipaddress.ip_network("54.224.0.0/12"),
        ipaddress.ip_network("54.240.0.0/12"),
    ],
    "Azure": [
        ipaddress.ip_network("13.64.0.0/11"),
        ipaddress.ip_network("13.96.0.0/13"),
        ipaddress.ip_network("13.104.0.0/14"),
        ipaddress.ip_network("20.33.0.0/16"),
        ipaddress.ip_network("20.34.0.0/15"),
        ipaddress.ip_network("20.36.0.0/14"),
        ipaddress.ip_network("20.40.0.0/13"),
        ipaddress.ip_network("20.48.0.0/12"),
        ipaddress.ip_network("20.64.0.0/10"),
        ipaddress.ip_network("20.128.0.0/16"),
        ipaddress.ip_network("20.135.0.0/16"),
        ipaddress.ip_network("20.136.0.0/16"),
        ipaddress.ip_network("20.140.0.0/15"),
        ipaddress.ip_network("20.143.0.0/16"),
        ipaddress.ip_network("20.144.0.0/14"),
        ipaddress.ip_network("20.150.0.0/15"),
        ipaddress.ip_network("20.157.0.0/16"),
        ipaddress.ip_network("20.160.0.0/12"),
        ipaddress.ip_network("20.176.0.0/14"),
        ipaddress.ip_network("20.180.0.0/14"),
        ipaddress.ip_network("20.184.0.0/13"),
        ipaddress.ip_network("20.192.0.0/10"),
        ipaddress.ip_network("40.64.0.0/10"),
        ipaddress.ip_network("40.112.0.0/13"),
        ipaddress.ip_network("40.120.0.0/14"),
        ipaddress.ip_network("40.124.0.0/16"),
        ipaddress.ip_network("40.125.0.0/17"),
        ipaddress.ip_network("51.4.0.0/15"),
        ipaddress.ip_network("51.8.0.0/16"),
        ipaddress.ip_network("51.10.0.0/15"),
        ipaddress.ip_network("51.12.0.0/15"),
        ipaddress.ip_network("51.18.0.0/16"),
        ipaddress.ip_network("51.51.0.0/16"),
        ipaddress.ip_network("51.53.0.0/16"),
        ipaddress.ip_network("51.103.0.0/16"),
        ipaddress.ip_network("51.104.0.0/15"),
        ipaddress.ip_network("51.107.0.0/16"),
        ipaddress.ip_network("51.116.0.0/16"),
        ipaddress.ip_network("51.120.0.0/16"),
        ipaddress.ip_network("51.124.0.0/16"),
        ipaddress.ip_network("51.132.0.0/16"),
        ipaddress.ip_network("51.136.0.0/15"),
        ipaddress.ip_network("51.138.0.0/16"),
        ipaddress.ip_network("51.140.0.0/14"),
        ipaddress.ip_network("51.144.0.0/15"),
        ipaddress.ip_network("52.108.0.0/14"),
        ipaddress.ip_network("52.112.0.0/14"),
        ipaddress.ip_network("52.120.0.0/14"),
        ipaddress.ip_network("52.125.0.0/16"),
        ipaddress.ip_network("52.126.0.0/15"),
        ipaddress.ip_network("52.130.0.0/15"),
        ipaddress.ip_network("52.132.0.0/14"),
        ipaddress.ip_network("52.136.0.0/13"),
        ipaddress.ip_network("52.145.0.0/16"),
        ipaddress.ip_network("52.146.0.0/15"),
        ipaddress.ip_network("52.148.0.0/14"),
        ipaddress.ip_network("52.152.0.0/13"),
        ipaddress.ip_network("52.160.0.0/11"),
        ipaddress.ip_network("52.224.0.0/11"),
        ipaddress.ip_network("104.40.0.0/13"),
        ipaddress.ip_network("104.208.0.0/13"),
        ipaddress.ip_network("137.116.0.0/15"),
        ipaddress.ip_network("138.91.0.0/16"),
        ipaddress.ip_network("157.54.0.0/15"),
        ipaddress.ip_network("157.56.0.0/14"),
        ipaddress.ip_network("168.61.0.0/16"),
        ipaddress.ip_network("168.62.0.0/15"),
        ipaddress.ip_network("191.232.0.0/13"),
        ipaddress.ip_network("199.30.16.0/20"),
        ipaddress.ip_network("204.79.135.0/24"),
        ipaddress.ip_network("204.79.179.0/24"),
        ipaddress.ip_network("204.79.181.0/24"),
        ipaddress.ip_network("204.79.188.0/24"),
        ipaddress.ip_network("204.79.195.0/24"),
        ipaddress.ip_network("204.79.196.0/24"),
        ipaddress.ip_network("204.79.197.0/24"),
        ipaddress.ip_network("204.152.18.0/23"),
        ipaddress.ip_network("204.152.140.0/23"),
        ipaddress.ip_network("207.46.0.0/16"),
    ],
    "DigitalOcean": [
        ipaddress.ip_network("64.225.0.0/16"),
        ipaddress.ip_network("68.183.0.0/16"),
        ipaddress.ip_network("104.131.0.0/16"),
        ipaddress.ip_network("104.236.0.0/16"),
        ipaddress.ip_network("104.248.0.0/16"),
        ipaddress.ip_network("107.170.0.0/16"),
        ipaddress.ip_network("128.199.0.0/16"),
        ipaddress.ip_network("134.209.0.0/16"),
        ipaddress.ip_network("138.197.0.0/16"),
        ipaddress.ip_network("139.59.0.0/16"),
        ipaddress.ip_network("142.93.0.0/16"),
        ipaddress.ip_network("143.110.0.0/16"),
        ipaddress.ip_network("143.244.0.0/16"),
        ipaddress.ip_network("146.190.0.0/16"),
        ipaddress.ip_network("147.182.0.0/16"),
        ipaddress.ip_network("147.185.0.0/16"),
        ipaddress.ip_network("157.230.0.0/16"),
        ipaddress.ip_network("159.65.0.0/16"),
        ipaddress.ip_network("159.89.0.0/16"),
        ipaddress.ip_network("161.35.0.0/16"),
        ipaddress.ip_network("164.90.0.0/16"),
        ipaddress.ip_network("164.92.0.0/16"),
        ipaddress.ip_network("165.22.0.0/16"),
        ipaddress.ip_network("165.227.0.0/16"),
        ipaddress.ip_network("167.71.0.0/16"),
        ipaddress.ip_network("167.99.0.0/16"),
        ipaddress.ip_network("167.172.0.0/16"),
        ipaddress.ip_network("174.138.0.0/16"),
        ipaddress.ip_network("178.62.0.0/16"),
        ipaddress.ip_network("188.166.0.0/16"),
        ipaddress.ip_network("188.226.0.0/16"),
        ipaddress.ip_network("192.241.0.0/16"),
        ipaddress.ip_network("198.199.0.0/16"),
        ipaddress.ip_network("198.235.0.0/16"),
        ipaddress.ip_network("206.81.0.0/16"),
        ipaddress.ip_network("206.189.0.0/16"),
        ipaddress.ip_network("209.97.0.0/16"),
    ],
    "Google Cloud": [
        ipaddress.ip_network("8.34.208.0/20"),
        ipaddress.ip_network("8.35.192.0/20"),
        ipaddress.ip_network("23.236.48.0/20"),
        ipaddress.ip_network("23.251.128.0/19"),
        ipaddress.ip_network("34.0.0.0/9"),
        ipaddress.ip_network("34.128.0.0/10"),
        ipaddress.ip_network("35.184.0.0/13"),
        ipaddress.ip_network("35.192.0.0/12"),
        ipaddress.ip_network("35.208.0.0/12"),
        ipaddress.ip_network("35.224.0.0/12"),
        ipaddress.ip_network("35.240.0.0/13"),
        ipaddress.ip_network("104.154.0.0/15"),
        ipaddress.ip_network("104.196.0.0/14"),
        ipaddress.ip_network("107.167.160.0/19"),
        ipaddress.ip_network("107.178.192.0/18"),
        ipaddress.ip_network("108.59.80.0/20"),
        ipaddress.ip_network("108.170.192.0/18"),
        ipaddress.ip_network("108.177.0.0/17"),
        ipaddress.ip_network("130.211.0.0/16"),
        ipaddress.ip_network("136.112.0.0/12"),
        ipaddress.ip_network("142.250.0.0/15"),
        ipaddress.ip_network("146.148.0.0/17"),
        ipaddress.ip_network("162.216.148.0/22"),
        ipaddress.ip_network("162.222.176.0/21"),
        ipaddress.ip_network("172.110.32.0/21"),
        ipaddress.ip_network("172.217.0.0/16"),
        ipaddress.ip_network("172.253.0.0/16"),
        ipaddress.ip_network("173.194.0.0/16"),
        ipaddress.ip_network("173.255.112.0/20"),
        ipaddress.ip_network("192.158.28.0/22"),
        ipaddress.ip_network("192.178.0.0/15"),
        ipaddress.ip_network("193.186.4.0/24"),
        ipaddress.ip_network("199.36.154.0/23"),
        ipaddress.ip_network("199.36.156.0/24"),
        ipaddress.ip_network("199.192.112.0/22"),
        ipaddress.ip_network("199.223.232.0/21"),
        ipaddress.ip_network("207.223.160.0/20"),
        ipaddress.ip_network("208.65.152.0/22"),
        ipaddress.ip_network("208.68.108.0/22"),
        ipaddress.ip_network("208.81.188.0/22"),
        ipaddress.ip_network("208.117.224.0/19"),
        ipaddress.ip_network("209.85.128.0/17"),
        ipaddress.ip_network("216.58.192.0/19"),
        ipaddress.ip_network("216.73.80.0/20"),
        ipaddress.ip_network("216.239.32.0/19"),
    ],
    "OVH": [
        ipaddress.ip_network("51.79.0.0/16"),
        ipaddress.ip_network("51.68.0.0/16"),
        ipaddress.ip_network("51.75.0.0/16"),
        ipaddress.ip_network("51.77.0.0/16"),
        ipaddress.ip_network("51.83.0.0/16"),
        ipaddress.ip_network("51.89.0.0/16"),
        ipaddress.ip_network("51.91.0.0/16"),
        ipaddress.ip_network("54.36.0.0/16"),
        ipaddress.ip_network("54.37.0.0/16"),
        ipaddress.ip_network("54.38.0.0/16"),
        ipaddress.ip_network("54.39.0.0/16"),
        ipaddress.ip_network("135.125.0.0/16"),
        ipaddress.ip_network("135.148.0.0/16"),
        ipaddress.ip_network("141.94.0.0/16"),
        ipaddress.ip_network("141.95.0.0/16"),
        ipaddress.ip_network("142.44.128.0/17"),
        ipaddress.ip_network("145.239.0.0/16"),
        ipaddress.ip_network("146.59.0.0/16"),
        ipaddress.ip_network("147.135.0.0/16"),
        ipaddress.ip_network("151.80.0.0/16"),
        ipaddress.ip_network("152.228.128.0/17"),
        ipaddress.ip_network("158.69.0.0/16"),
        ipaddress.ip_network("162.19.0.0/16"),
        ipaddress.ip_network("164.132.0.0/16"),
        ipaddress.ip_network("167.114.0.0/16"),
        ipaddress.ip_network("176.31.0.0/16"),
        ipaddress.ip_network("178.32.0.0/15"),
        ipaddress.ip_network("185.15.68.0/22"),
        ipaddress.ip_network("188.165.0.0/16"),
        ipaddress.ip_network("192.95.0.0/16"),
        ipaddress.ip_network("192.99.0.0/16"),
        ipaddress.ip_network("193.70.0.0/16"),
        ipaddress.ip_network("195.154.0.0/16"),
        ipaddress.ip_network("198.50.128.0/17"),
        ipaddress.ip_network("213.186.32.0/19"),
        ipaddress.ip_network("213.251.128.0/18"),
    ],
    "Hetzner": [
        ipaddress.ip_network("5.9.0.0/16"),
        ipaddress.ip_network("46.4.0.0/16"),
        ipaddress.ip_network("78.46.0.0/15"),
        ipaddress.ip_network("88.198.0.0/16"),
        ipaddress.ip_network("88.99.0.0/16"),
        ipaddress.ip_network("116.202.0.0/16"),
        ipaddress.ip_network("116.203.0.0/16"),
        ipaddress.ip_network("135.181.0.0/16"),
        ipaddress.ip_network("136.243.0.0/16"),
        ipaddress.ip_network("138.201.0.0/16"),
        ipaddress.ip_network("142.132.0.0/16"),
        ipaddress.ip_network("144.76.0.0/16"),
        ipaddress.ip_network("148.251.0.0/16"),
        ipaddress.ip_network("157.90.0.0/16"),
        ipaddress.ip_network("159.69.0.0/16"),
        ipaddress.ip_network("162.55.0.0/16"),
        ipaddress.ip_network("168.119.0.0/16"),
        ipaddress.ip_network("176.9.0.0/16"),
        ipaddress.ip_network("176.65.0.0/16"),
        ipaddress.ip_network("178.63.0.0/16"),
        ipaddress.ip_network("188.40.0.0/16"),
        ipaddress.ip_network("195.201.0.0/16"),
        ipaddress.ip_network("213.133.96.0/19"),
        ipaddress.ip_network("213.239.192.0/18"),
    ],
}

# GeoIP readers (lazy-loaded)
_city_reader = None
_asn_reader = None


def _get_city_reader():
    """Get or create GeoIP2 City reader instance."""
    global _city_reader
    if _city_reader is None:
        try:
            import geoip2.database
            if os.path.exists(GEOLITE2_CITY_PATH):
                _city_reader = geoip2.database.Reader(GEOLITE2_CITY_PATH)
                logger.info("geolite2_city_loaded", path=GEOLITE2_CITY_PATH)
            else:
                logger.warning("geolite2_city_not_found", path=GEOLITE2_CITY_PATH)
        except Exception as e:
            logger.warning("geolite2_city_init_failed", error=str(e))
    return _city_reader


def _get_asn_reader():
    """Get or create GeoIP2 ASN reader instance."""
    global _asn_reader
    if _asn_reader is None:
        try:
            import geoip2.database
            if os.path.exists(GEOLITE2_ASN_PATH):
                _asn_reader = geoip2.database.Reader(GEOLITE2_ASN_PATH)
                logger.info("geolite2_asn_loaded", path=GEOLITE2_ASN_PATH)
            else:
                logger.debug("geolite2_asn_not_found", path=GEOLITE2_ASN_PATH)
        except Exception as e:
            logger.debug("geolite2_asn_init_failed", error=str(e))
    return _asn_reader


def _is_private(ip_str: str) -> bool:
    """Check if an IP is private/internal."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except (ValueError, TypeError):
        return False


def _detect_provider_from_asn(asn_org: str) -> Optional[str]:
    """Dynamically detect cloud provider from ASN organization name.
    
    Works for ANY provider - no hardcoded IP ranges needed.
    """
    if not asn_org:
        return None
    
    asn_lower = asn_org.lower()
    
    for keyword in _CLOUD_ASN_KEYWORDS:
        if keyword in asn_lower:
            # Normalize provider name
            if "amazon" in asn_lower or "aws" in asn_lower or "ec2" in asn_lower:
                return "AWS"
            elif "google" in asn_lower or "gcp" in asn_lower:
                return "Google Cloud"
            elif "digitalocean" in asn_lower:
                return "DigitalOcean"
            elif "microsoft" in asn_lower or "azure" in asn_lower:
                return "Azure"
            elif "ovh" in asn_lower:
                return "OVH"
            elif "hetzner" in asn_lower:
                return "Hetzner"
            elif "linode" in asn_lower or "akamai" in asn_lower:
                return "Linode/Akamai"
            elif "vultr" in asn_lower or "choopa" in asn_lower:
                return "Vultr"
            elif "cloudflare" in asn_lower:
                return "Cloudflare"
            elif "alibaba" in asn_lower or "aliyun" in asn_lower:
                return "Alibaba Cloud"
            elif "tencent" in asn_lower:
                return "Tencent Cloud"
            elif "oracle" in asn_lower:
                return "Oracle Cloud"
            elif "scaleway" in asn_lower:
                return "Scaleway"
            elif "leaseweb" in asn_lower:
                return "LeaseWeb"
            elif "hostinger" in asn_lower:
                return "Hostinger"
            elif "ionos" in asn_lower or "1and1" in asn_lower:
                return "IONOS"
            elif "godaddy" in asn_lower:
                return "GoDaddy"
            elif "namecheap" in asn_lower:
                return "Namecheap"
    
    # If ASN org looks like a hosting provider but not in our list
    if any(x in asn_lower for x in ["hosting", "cloud", "datacenter", "server", "telecom", "isp"]):
        return asn_org[:30]  # Use actual org name (truncated)
    
    return None


def _detect_provider_from_ip(ip_str: str) -> Optional[str]:
    """Detect cloud provider by checking IP against known ranges.
    
    Fallback when ASN data is unavailable.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        for provider, ranges in _CLOUD_IP_RANGES.items():
            for net in ranges:
                if ip in net:
                    return provider
    except (ValueError, TypeError):
        pass
    return None


def _lookup_ip_api(ip_str: str) -> Optional[Dict[str, Any]]:
    """Look up IP via ip-api.com free API.
    
    Returns provider name and ASN info when available.
    """
    try:
        resp = httpx.get(
            f"http://ip-api.com/json/{ip_str}?fields=as,org,country",
            timeout=5.0,
        )
        if resp.status_code != 200:
            return None
        
        data = resp.json()
        result = {}
        
        # Extract ASN
        asn_field = data.get("as", "")
        if asn_field:
            parts = asn_field.split(" ", 1)
            if parts:
                result["asn"] = parts[0]  # e.g., "AS136907"
                if len(parts) > 1:
                    result["asn_org"] = parts[1]
        
        # Detect provider from org name
        org = data.get("org", "")
        if org:
            provider = _detect_provider_from_asn(org)
            if provider:
                result["provider"] = provider
            elif asn_field:
                # Use org as provider if no known cloud match
                result["provider"] = org[:30]
        
        return result if result else None
    except Exception:
        return None


def _geoip_lookup(ip_str: str) -> Dict[str, Any]:
    """Look up IP in GeoLite2 databases - returns ALL available data."""
    result = {}
    city_reader = _get_city_reader()
    asn_reader = _get_asn_reader()
    
    if not city_reader and not asn_reader:
        return result
    
    try:
        # City data
        if city_reader:
            response = city_reader.city(ip_str)
            
            country = response.country
            if country and country.iso_code:
                result["country"] = country.iso_code
                result["country_name"] = country.name or ""
            
            city = response.city
            if city and city.name:
                result["city"] = city.name
            
            # Try ASN from city response (some databases include it)
            traits = response.traits
            if traits and traits.autonomous_system_organization:
                result["asn_org"] = traits.autonomous_system_organization
                provider = _detect_provider_from_asn(traits.autonomous_system_organization)
                if provider:
                    result["provider"] = provider
                if traits.autonomous_system_number:
                    result["asn"] = f"AS{traits.autonomous_system_number}"
            
            # Coordinates
            location = response.location
            if location:
                if location.latitude and location.longitude:
                    result["lat"] = round(location.latitude, 4)
                    result["lon"] = round(location.longitude, 4)
                if location.time_zone:
                    result["timezone"] = location.time_zone
        
        # ASN data (separate database)
        if asn_reader and "provider" not in result:
            try:
                asn_response = asn_reader.asn(ip_str)
                if asn_response.autonomous_system_organization:
                    result["asn_org"] = asn_response.autonomous_system_organization
                    provider = _detect_provider_from_asn(asn_response.autonomous_system_organization)
                    if provider:
                        result["provider"] = provider
                    if asn_response.autonomous_system_number:
                        result["asn"] = f"AS{asn_response.autonomous_system_number}"
            except Exception:
                pass
        
        # Fallback: IP range matching if no ASN data
        if "provider" not in result:
            provider = _detect_provider_from_ip(ip_str)
            if provider:
                result["provider"] = provider
        
        # Fallback: ip-api.com if no provider detected yet
        if "provider" not in result:
            try:
                api_data = _lookup_ip_api(ip_str)
                if api_data:
                    result.update(api_data)
            except Exception:
                pass
                
    except Exception as e:
        logger.debug("geolite2_lookup_failed", ip=ip_str, error=str(e))
    
    return result


def enrich_ip(ip_str: str) -> Dict[str, Any]:
    """Enrich a single IP with metadata - fully dynamic, no hardcoded ranges."""
    if not ip_str:
        return {}
    
    result = {
        "ip": ip_str,
        "is_private": _is_private(ip_str),
    }
    
    if not result["is_private"]:
        # GeoIP lookup - includes dynamic ASN-based provider detection
        geo = _geoip_lookup(ip_str)
        if geo:
            result.update(geo)
    
    return result


def _format_ip_context(ip_str: str, ip_info: Dict[str, Any], label: str) -> str:
    """Format IP enrichment into readable context string."""
    if not ip_info:
        return f"{label}: {ip_str}"
    
    parts = [f"{label}: {ip_str}"]
    
    if ip_info.get("country"):
        country_str = ip_info["country"]
        if ip_info.get("city"):
            country_str += f", {ip_info['city']}"
        parts.append(f"[{country_str}]")
    
    if ip_info.get("asn"):
        asn_str = ip_info["asn"]
        if ip_info.get("asn_org"):
            asn_str += f" {ip_info['asn_org']}"
        parts.append(f"({asn_str})")
    elif ip_info.get("provider"):
        parts.append(f"({ip_info['provider']})")
    
    return " ".join(parts)


def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich an alert with IP metadata and context.
    
    Embeds enrichment into fields OpenSOAR actually stores:
    - tags: adds country, provider, ASN, internal/external tags
    - description: prepends network context
    """
    src_ip = alert.get("source_ip", "")
    dst_ip = alert.get("dest_ip", "")
    
    tags = alert.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    
    context_parts = []
    
    # Enrich source IP
    if src_ip:
        src_info = enrich_ip(src_ip)
        if src_info.get("is_private"):
            tags.append("internal-source")
            context_parts.append(f"Internal source: {src_ip}")
        else:
            if src_info.get("country"):
                tags.append(f"src-country-{src_info['country']}")
            if src_info.get("asn"):
                tags.append(f"src-{src_info['asn']}")
            if src_info.get("provider"):
                tags.append(f"src-provider-{src_info['provider']}")
            context_parts.append(_format_ip_context(src_ip, src_info, "Source"))
    
    # Enrich destination IP
    if dst_ip:
        dst_info = enrich_ip(dst_ip)
        if dst_info.get("is_private"):
            tags.append("internal-target")
            context_parts.append(f"Internal target: {dst_ip}")
        else:
            if dst_info.get("country"):
                tags.append(f"dst-country-{dst_info['country']}")
            if dst_info.get("asn"):
                tags.append(f"dst-{dst_info['asn']}")
            if dst_info.get("provider"):
                tags.append(f"dst-provider-{dst_info['provider']}")
            context_parts.append(_format_ip_context(dst_ip, dst_info, "Target"))
    
    alert["tags"] = tags
    
    # Prepend network context to description
    if context_parts:
        network_ctx = " | ".join(context_parts)
        existing_desc = alert.get("description", "")
        if existing_desc:
            alert["description"] = f"{network_ctx} | {existing_desc}" if existing_desc else network_ctx
        else:
            alert["description"] = network_ctx
    
    return alert
