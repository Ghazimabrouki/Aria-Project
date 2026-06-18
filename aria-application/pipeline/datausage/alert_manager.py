"""
Alert Manager.
Alerts CRUD + activities + comments + bulk operations + smart auto-enrichment.
"""

import asyncio
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from pipeline.sender import client
from config import get_settings

logger = structlog.get_logger()


class AlertManager:
    def __init__(self):
        self._enrichment_cache: Dict[str, dict] = {}

    async def list_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        partner: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        if source:
            params["source"] = source
        if partner:
            params["partner"] = partner

        try:
            resp = await client._get_http().get(
                "/api/v1/alerts",
                params=params,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("list_alerts_failed", error=str(e))
            return {"alerts": [], "total": 0}

    async def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        if not get_settings().upstream_enabled:
            return None
        try:
            resp = await client._get_http().get(
                f"/api/v1/alerts/{alert_id}",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("get_alert_failed", alert_id=alert_id, error=str(e))
            return None

    async def update_alert(self, alert_id: str, updates: dict) -> Optional[Dict[str, Any]]:
        return await client.update_alert(alert_id, updates)

    async def delete_alert(self, alert_id: str) -> bool:
        if not get_settings().upstream_enabled:
            return False
        try:
            resp = await client._get_http().delete(
                f"/api/v1/alerts/{alert_id}",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            logger.info("alert_deleted", alert_id=alert_id)
            return True
        except Exception as e:
            logger.error("delete_alert_failed", alert_id=alert_id, error=str(e))
            return False

    async def get_alert_runs(self, alert_id: str) -> Dict[str, Any]:
        try:
            resp = await client._get_http().get(
                f"/api/v1/alerts/{alert_id}/runs",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("get_alert_runs_failed", alert_id=alert_id, error=str(e))
            return {"runs": [], "total": 0}

    async def claim_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await client._get_http().post(
                f"/api/v1/alerts/{alert_id}/claim",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info("alert_claimed", alert_id=alert_id)
            return result
        except Exception as e:
            logger.error("claim_alert_failed", alert_id=alert_id, error=str(e))
            return None

    async def bulk_update_alerts(
        self,
        alert_ids: List[str],
        action: str,
        resolve_reason: Optional[str] = None,
        determination: Optional[str] = None,
        assigned_to: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "alert_ids": alert_ids,
            "action": action,
        }
        if resolve_reason:
            payload["resolve_reason"] = resolve_reason
        if determination:
            payload["determination"] = determination
        if assigned_to:
            payload["assigned_to"] = assigned_to
        if severity:
            payload["severity"] = severity

        try:
            resp = await client._get_http().post(
                "/api/v1/alerts/bulk",
                json=payload,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info("bulk_update_alerts", count=len(alert_ids), action=action, updated=result.get("updated", 0))
            return result
        except Exception as e:
            logger.error("bulk_update_alerts_failed", error=str(e))
            return {"updated": 0, "failed": len(alert_ids), "errors": [str(e)]}

    async def list_activities(self, alert_id: str, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        try:
            resp = await client._get_http().get(
                f"/api/v1/alerts/{alert_id}/activities",
                params={"limit": limit, "offset": offset},
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("list_activities_failed", alert_id=alert_id, error=str(e))
            return {"activities": [], "total": 0}

    async def add_comment(self, alert_id: str, text: str) -> Optional[Dict[str, Any]]:
        if not get_settings().upstream_enabled:
            logger.debug("add_comment_skipped_upstream_disabled", alert_id=alert_id)
            return None
        try:
            resp = await client._get_http().post(
                f"/api/v1/alerts/{alert_id}/comments",
                json={"text": text},
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            result = resp.json()
            logger.debug("comment_added", alert_id=alert_id, text_preview=text[:50])
            return result
        except Exception as e:
            logger.error("add_comment_failed", alert_id=alert_id, error=str(e))
            return None

    async def edit_comment(self, alert_id: str, comment_id: str, text: str) -> Optional[Dict[str, Any]]:
        if not get_settings().upstream_enabled:
            return None
        try:
            resp = await client._get_http().patch(
                f"/api/v1/alerts/{alert_id}/comments/{comment_id}",
                json={"text": text},
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("edit_comment_failed", alert_id=alert_id, comment_id=comment_id, error=str(e))
            return None

    async def auto_enrich_comment(self, alert_id: str, alert_data: dict) -> Optional[Dict[str, Any]]:
        if alert_id in self._enrichment_cache:
            return None

        enrichment_parts = []

        geo_country = alert_data.get("geo_country")
        geo_city = alert_data.get("geo_city")
        if geo_country:
            location = f"{geo_city}, {geo_country}" if geo_city else geo_country
            enrichment_parts.append(f"Source location: {location}")

        cloud_provider = alert_data.get("cloud_provider")
        if cloud_provider:
            enrichment_parts.append(f"Cloud provider: {cloud_provider}")

        mitre_tactics = alert_data.get("mitre_tactics", [])
        if mitre_tactics:
            # Handle both string and dict formats
            tactics_list = [str(t) if isinstance(t, str) else t.get("tactic", "unknown") for t in mitre_tactics[:5]]
            tactics_str = ", ".join(tactics_list)
            enrichment_parts.append(f"MITRE ATT&CK: {tactics_str}")

        mitre_techniques = alert_data.get("mitre_techniques", [])
        if mitre_techniques:
            # Handle both string and dict formats
            techniques_list = [str(t) if isinstance(t, str) else t.get("technique", "unknown") for t in mitre_techniques[:5]]
            techniques_str = ", ".join(techniques_list)
            enrichment_parts.append(f"Techniques: {techniques_str}")

        campaign = alert_data.get("campaign_context")
        if campaign:
            enrichment_parts.append(f"Campaign: {campaign}")

        if not enrichment_parts:
            return None

        comment_text = "Auto-enrichment:\n" + "\n".join(f"- {p}" for p in enrichment_parts)
        result = await self.add_comment(alert_id, comment_text)
        if result:
            self._enrichment_cache[alert_id] = {"commented_at": datetime.now(timezone.utc).isoformat()}
            logger.info("alert_auto_enriched_comment", alert_id=alert_id)
        return result

    async def auto_assign_by_severity(self, alert_ids: List[str]) -> Dict[str, Any]:
        from pipeline.datausage.auth_manager import auth_manager

        # Fetch actual alert data to determine severity
        alerts = []
        for aid in alert_ids:
            alert = await self.get_alert(aid)
            if alert:
                alerts.append(alert)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        alerts.sort(key=lambda a: severity_order.get(a.get("severity", "medium"), 3))

        critical_high = [a["id"] for a in alerts if a.get("severity") in ("critical", "high")]
        if critical_high:
            analyst = await auth_manager.find_analyst_by_role("admin")
            if analyst:
                return await self.bulk_update_alerts(
                    alert_ids=critical_high,
                    action="assign",
                    assigned_to=analyst["id"],
                )

        return {"updated": 0, "failed": len(alert_ids)}

    HIGH_RISK_TACTICS = {"Exfiltration", "Impact", "Command and Control", "Initial Access", 
                        "Execution", "Credential Access", "Lateral Movement"}

    MALICIOUS_ATTACK_PATTERNS = {"malware", "c2", "ssh_brute_force", "lateral_movement", 
                                 "privilege_escalation", "data_exfiltration", "spamhaus"}

    NOISE_PATTERNS = {"icmp", "ping", "echo_request", "keepalive", "heartbeat", "ntp"}

    async def auto_update_on_incident_link(self, alert_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Auto-update alert status when linked to incident.
        Status changes from 'new' to 'investigating' when alert is part of an incident.
        """
        try:
            current = await self.get_alert(alert_id)
            if not current:
                return None

            current_status = current.get("status", "new")
            if current_status != "new":
                logger.debug("alert_status_not_new", alert_id=alert_id, status=current_status)
                return None

            result = await self.update_alert(alert_id, {"status": "investigating"})
            if result:
                logger.info(
                    "alert_status_updated_to_investigating",
                    alert_id=alert_id,
                    incident_id=incident_id,
                )
            return result
        except Exception as e:
            logger.error("auto_update_status_failed", alert_id=alert_id, error=str(e)[:100])
            return None

    def _calculate_determination(self, alert_data: dict) -> str:
        """
        Calculate determination based on alert characteristics.
        
        Rules (priority order):
        1. If noise pattern (ICMP, ping, etc.) → benign
        2. If MITRE tactic is high-risk (Exfiltration, Impact, C2) → malicious
        3. If attack pattern is malicious → malicious
        4. If Spamhaus DROP listed → malicious
        5. If severity is critical → malicious
        6. If MITRE tactic is benign-related → unknown
        7. Default → unknown
        """
        title = (alert_data.get("title") or "").lower()
        description = (alert_data.get("description") or "").lower()
        combined = title + " " + description
        
        for noise in self.NOISE_PATTERNS:
            if noise in combined:
                return "benign"

        mitre_tactics = []
        for tag in (alert_data.get("tags") or []):
            if tag.startswith("mitre-tactic-"):
                tactic = tag.replace("mitre-tactic-", "")
                mitre_tactics.append(tactic)
        
        high_risk_count = sum(1 for t in mitre_tactics if t in self.HIGH_RISK_TACTICS)
        if high_risk_count >= 1:
            return "malicious"

        for pattern in self.MALICIOUS_ATTACK_PATTERNS:
            if pattern in combined:
                return "malicious"

        if "spamhaus" in combined or "drop" in combined:
            return "malicious"

        severity = alert_data.get("severity", "low")
        if severity == "critical":
            return "malicious"

        benign_tactics = {"Defense Evasion", "Discovery"}
        if any(t in benign_tactics for t in mitre_tactics):
            return "unknown"

        return "unknown"

    async def auto_set_determination(self, alert_id: str, alert_data: dict) -> Optional[Dict[str, Any]]:
        """
        Auto-set determination based on alert characteristics.
        Uses MITRE tactics, attack patterns, and severity to determine if alert is malicious.
        """
        try:
            current = await self.get_alert(alert_id)
            if not current:
                return None

            current_determination = current.get("determination", "unknown")
            if current_determination != "unknown":
                logger.debug("alert_determination_already_set", alert_id=alert_id, determination=current_determination)
                return None

            determination = self._calculate_determination(alert_data)
            if determination == "unknown":
                logger.debug("alert_determination_unknown_skipping", alert_id=alert_id)
                return None

            result = await self.update_alert(alert_id, {"determination": determination})
            if result:
                logger.info(
                    "alert_determination_auto_set",
                    alert_id=alert_id,
                    determination=determination,
                )
            return result
        except Exception as e:
            logger.error("auto_set_determination_failed", alert_id=alert_id, error=str(e)[:100])
            return None

    async def auto_enrich_alert(self, alert_id: str, alert_data: dict, incident_id: Optional[str] = None) -> dict:
        """
        Complete alert enrichment: status + determination + comments.
        Combines all auto-enrichment features in one call.
        """
        results = {"alert_id": alert_id, "actions": {}}

        if incident_id:
            status_result = await self.auto_update_on_incident_link(alert_id, incident_id)
            results["actions"]["status_update"] = status_result is not None

        determination_result = await self.auto_set_determination(alert_id, alert_data)
        results["actions"]["determination_set"] = determination_result is not None

        comment_result = await self.auto_enrich_comment(alert_id, alert_data)
        results["actions"]["comment_added"] = comment_result is not None

        return results

    async def auto_resolve_on_incident_close(self, alert_ids: List[str], resolve_reason: str = "Related incident closed") -> Dict[str, Any]:
        """
        Bulk resolve alerts when their related incident is closed.
        """
        if not alert_ids:
            return {"updated": 0, "failed": 0}

        return await self.bulk_update_alerts(
            alert_ids=alert_ids,
            action="resolve",
            resolve_reason=resolve_reason,
            determination="malicious",
        )


alert_manager = AlertManager()
