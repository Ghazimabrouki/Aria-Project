"""
Observable Manager.
Observables CRUD + auto-IOC extraction from alerts + enrichment with GeoIP/MITRE/cloud data.

Enhanced with:
- Full payload scanning (not just title/description)
- Username extraction
- Port extraction
- Multiple field sources
"""

import asyncio
import json
import structlog
from typing import Optional, Dict, Any, List, Set
import re

from pipeline.sender import client
from config import get_settings

logger = structlog.get_logger()

DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
HASH_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
HASH_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
USERNAME_PATTERN = re.compile(r'(?:user|username|uid|account|actor|principal|subject)[:=]\s*([a-zA-Z0-9_-]+)', re.IGNORECASE)
PORT_PATTERN = re.compile(r'(?:port|dst_port|src_port|dest_port|target_port)[:=]?\s*(\d+)', re.IGNORECASE)
FILE_PATH_PATTERN = re.compile(r'(?:file|path|script)[:=]?\s*(/[a-zA-Z0-9_/.-]+|/[a-zA-Z0-9_/.-]+|[a-zA-Z]:\\[a-zA-Z0-9_\\.-]+)', re.IGNORECASE)

PRIVATE_IP_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.")


class ObservableManager:
    def __init__(self):
        self._created_count = 0
        self._skipped_count = 0
        self._enriched_count = 0
        self._observable_cache: Dict[str, str] = {}

    def _extract_all_text(self, alert_data: dict) -> str:
        """Extract ALL text content from alert for scanning."""
        # Start with common fields
        text_parts = []
        
        for field in ["title", "description", "description", "action", "rule_name", "full_log"]:
            val = alert_data.get(field)
            if val and isinstance(val, str):
                text_parts.append(val)
        
        # Add raw_payload values
        raw = alert_data.get("raw_payload", {})
        if raw and isinstance(raw, dict):
            for key, val in raw.items():
                if isinstance(val, str):
                    text_parts.append(f"{key}: {val}")
                elif isinstance(val, (int, float, bool)):
                    text_parts.append(f"{key}: {val}")
        
        # Convert entire dict to string for pattern scanning
        all_json = json.dumps(alert_data)
        
        return " ".join(text_parts) + " " + all_json

    def extract_iocs(self, alert_data: dict) -> Dict[str, List[str]]:
        """Extract IOCs from alert data with enhanced scanning."""
        iocs: Dict[str, Set[str]] = {
            "ip": set(),
            "domain": set(),
            "file_hash": set(),
            "url": set(),
            "email": set(),
            "hostname": set(),
            "username": set(),
            "port": set(),
        }

        # 1. Extract from specific fields (prioritize)
        for field_name in ["source_ip", "dest_ip"]:
            val = alert_data.get(field_name, "")
            if val and IP_PATTERN.match(val):
                if not val.startswith(PRIVATE_IP_PREFIXES):
                    iocs["ip"].add(val)

        # 2. Extract hostname
        hostname = alert_data.get("hostname", "")
        if hostname:
            iocs["hostname"].add(hostname)
            if DOMAIN_PATTERN.match(hostname):
                iocs["domain"].add(hostname)

        # 3. Extract username from username field
        username = alert_data.get("username", "")
        if username:
            iocs["username"].add(str(username))

        # 4. Extract ports from port fields
        for field_name in ["src_port", "dest_port", "port", "src_port", "dest_port"]:
            val = alert_data.get(field_name)
            if val:
                port_str = str(val)
                if port_str.isdigit() and 0 < int(port_str) < 65536:
                    iocs["port"].add(port_str)

        # 5. Scan ALL text content for patterns
        all_text = self._extract_all_text(alert_data)

        # Extract domains
        for match in DOMAIN_PATTERN.findall(all_text):
            if not match.startswith(("www.", "localhost")):
                iocs["domain"].add(match)

        # Extract IPs from text
        for match in IP_PATTERN.findall(all_text):
            if not match.startswith(PRIVATE_IP_PREFIXES):
                iocs["ip"].add(match)

        # Extract hashes
        for match in HASH_SHA256.findall(all_text):
            iocs["file_hash"].add(match)
        for match in HASH_MD5.findall(all_text):
            iocs["file_hash"].add(match)

        # Extract URLs
        for match in URL_PATTERN.findall(all_text):
            iocs["url"].add(match)

        # Extract emails
        for match in EMAIL_PATTERN.findall(all_text):
            iocs["email"].add(match)

        # Extract usernames from patterns
        for match in USERNAME_PATTERN.findall(all_text):
            if match and len(match) < 50:
                iocs["username"].add(match)

        # Extract ports from patterns
        for match in PORT_PATTERN.findall(all_text):
            if 0 < int(match) < 65536:
                iocs["port"].add(match)

        # 6. Also scan raw_payload more thoroughly
        raw_payload = alert_data.get("raw_payload", {})
        if raw_payload and isinstance(raw_payload, dict):
            raw_str = json.dumps(raw_payload)[:10000]
            
            # Additional hash extraction
            for match in HASH_SHA256.findall(raw_str):
                iocs["file_hash"].add(match)
            for match in HASH_MD5.findall(raw_str):
                iocs["file_hash"].add(match)
            
            # Username from raw payload
            for match in USERNAME_PATTERN.findall(raw_str):
                if match and len(match) < 50:
                    iocs["username"].add(match)

        # Clean and return
        return {k: list(v) for k, v in iocs.items() if v}

    async def create_observable(
        self,
        observable_type: str,
        value: str,
        source: str = "pipeline",
        alert_id: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if not get_settings().upstream_enabled:
            logger.debug("observable_create_skipped_upstream_disabled", type=observable_type)
            return None
        cache_key = f"{observable_type}:{value}"
        if cache_key in self._observable_cache:
            self._skipped_count += 1
            return None

        payload: Dict[str, Any] = {
            "type": observable_type,
            "value": value,
            "source": source,
        }
        if alert_id:
            payload["alert_id"] = alert_id
        if incident_id:
            payload["incident_id"] = incident_id

        try:
            resp = await client._get_http().post(
                "/api/v1/observables",
                json=payload,
                headers=client._auth_headers(),
            )
            if resp.status_code == 422:
                self._observable_cache[cache_key] = "exists"
                self._skipped_count += 1
                return None
            resp.raise_for_status()
            result = resp.json()
            self._observable_cache[cache_key] = result.get("id", "")
            self._created_count += 1
            logger.debug("observable_created", type=observable_type, value=value[:50])
            return result
        except Exception as e:
            if "422" in str(e) or "already exists" in str(e).lower():
                self._observable_cache[cache_key] = "exists"
                self._skipped_count += 1
            else:
                logger.error("create_observable_failed", type=observable_type, value=value[:50], error=str(e))
            return None

    async def add_enrichment(
        self,
        observable_id: str,
        source: str,
        data: dict,
        malicious: bool = False,
        score: int = 0,
    ) -> Optional[Dict[str, Any]]:
        if not get_settings().upstream_enabled:
            return None
        try:
            resp = await client._get_http().post(
                f"/api/v1/observables/{observable_id}/enrichments",
                json={
                    "source": source,
                    "data": data,
                    "malicious": malicious,
                    "score": score,
                },
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            result = resp.json()
            self._enriched_count += 1
            return result
        except Exception as e:
            logger.error("add_enrichment_failed", observable_id=observable_id, error=str(e))
            return None

    async def list_observables(
        self,
        observable_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        if not get_settings().upstream_enabled:
            return {"observables": [], "total": 0}
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if observable_type:
            params["type"] = observable_type

        try:
            resp = await client._get_http().get(
                "/api/v1/observables",
                params=params,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("list_observables_failed", error=str(e))
            return {"observables": [], "total": 0}

    async def get_observable(self, observable_id: str) -> Optional[Dict[str, Any]]:
        if not get_settings().upstream_enabled:
            return None
        try:
            resp = await client._get_http().get(
                f"/api/v1/observables/{observable_id}",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("get_observable_failed", observable_id=observable_id, error=str(e))
            return None

    async def auto_create_from_alert(self, alert_id: str, alert_data: dict) -> List[Dict[str, Any]]:
        iocs = self.extract_iocs(alert_data)
        created = []

        for ioc_type, values in iocs.items():
            for value in values[:20]:
                observable = await self.create_observable(
                    observable_type=ioc_type,
                    value=value,
                    source=f"alert:{alert_id}",
                    alert_id=alert_id,
                )
                if observable:
                    await self._auto_enrich_observable(observable["id"], ioc_type, value, alert_data)
                    created.append(observable)

        if created:
            logger.info("observables_auto_created", alert_id=alert_id, count=len(created))

        return created

    async def _auto_enrich_observable(self, observable_id: str, ioc_type: str, value: str, alert_data: dict) -> None:
        enrichment_data = {}
        malicious = False
        score = 0

        if ioc_type == "ip":
            geo_country = alert_data.get("geo_country")
            geo_city = alert_data.get("geo_city")
            cloud_provider = alert_data.get("cloud_provider")
            is_org = alert_data.get("geo_org")

            if geo_country:
                enrichment_data["geoip"] = {
                    "country": geo_country,
                    "city": geo_city,
                    "org": is_org,
                }

            if cloud_provider:
                enrichment_data["cloud_provider"] = cloud_provider
                score += 20

            threat_intel = alert_data.get("threat_intel", False)
            if threat_intel:
                enrichment_data["threat_intel"] = True
                malicious = True
                score += 80

        if ioc_type == "domain":
            if "malware" in alert_data.get("title", "").lower() or "c2" in alert_data.get("title", "").lower():
                malicious = True
                score += 70

        if ioc_type == "file_hash":
            rule_name = alert_data.get("rule_name", "").lower()
            if any(kw in rule_name for kw in ["malware", "trojan", "ransomware", "suspicious"]):
                malicious = True
                score += 75

        mitre_tactics = alert_data.get("mitre_tactics", [])
        if mitre_tactics:
            enrichment_data["mitre_tactics"] = mitre_tactics
            if any(t in mitre_tactics for t in ["exfiltration", "impact", "command-and-control"]):
                score += 30

        if enrichment_data:
            await self.add_enrichment(
                observable_id=observable_id,
                source="pipeline-auto",
                data=enrichment_data,
                malicious=malicious,
                score=min(score, 100),
            )

    def get_stats(self) -> Dict[str, int]:
        return {
            "created": self._created_count,
            "skipped_duplicates": self._skipped_count,
            "enriched": self._enriched_count,
            "cached": len(self._observable_cache),
        }


observable_manager = ObservableManager()
