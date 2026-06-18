"""
Action Executor.
Actions list + smart auto-execution based on IOC type + severity gating.
"""

import asyncio
import structlog
from typing import Optional, Dict, Any, List

from pipeline.sender import client
from config import get_settings

logger = structlog.get_logger()


class ActionExecutor:
    def __init__(self):
        self._actions_cache: Optional[List[Dict[str, Any]]] = None
        self._cache_time: float = 0
        self._cache_ttl = 300
        self._execution_count = 0
        self._failure_count = 0
        self._auto_execute_rules: List[dict] = [
            {
                "ioc_type": "ip",
                "condition": "threat_intel or malicious_score >= 70",
                "action_pattern": ["block", "ban", "deny", "firewall"],
                "min_severity": "high",
            },
            {
                "ioc_type": "ip",
                "condition": "campaign or mitre_exfiltration",
                "action_pattern": ["block", "isolate"],
                "min_severity": "critical",
            },
            {
                "ioc_type": "hostname",
                "condition": "mitre_execution and mitre_persistence",
                "action_pattern": ["isolate", "quarantine", "disable"],
                "min_severity": "high",
            },
            {
                "ioc_type": "file_hash",
                "condition": "malware or trojan or ransomware",
                "action_pattern": ["quarantine", "delete", "block"],
                "min_severity": "high",
            },
            {
                "ioc_type": "email",
                "condition": "phishing or spam",
                "action_pattern": ["block", "delete", "quarantine"],
                "min_severity": "medium",
            },
            {
                "ioc_type": "domain",
                "condition": "malware or c2 or phishing",
                "action_pattern": ["block", "sinkhole", "blacklist"],
                "min_severity": "high",
            },
        ]

    async def list_actions(self, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        try:
            params = {}
            if ioc_type:
                params["ioc_type"] = ioc_type

            resp = await client._get_http().get(
                "/api/v1/actions",
                params=params,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("list_actions_failed", error=str(e))
            return []

    async def execute_action(
        self,
        action_name: str,
        ioc_type: str,
        ioc_value: str,
        alert_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        payload: Dict[str, Any] = {
            "action_name": action_name,
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
        }
        if alert_id:
            payload["alert_id"] = alert_id

        try:
            resp = await client._get_http().post(
                "/api/v1/actions/execute",
                json=payload,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            result = resp.json()
            self._execution_count += 1
            logger.info(
                "action_executed",
                action=action_name,
                ioc_type=ioc_type,
                ioc_value=ioc_value[:50],
                status=result.get("status"),
            )
            return result
        except Exception as e:
            self._failure_count += 1
            logger.error(
                "execute_action_failed",
                action=action_name,
                ioc_type=ioc_type,
                ioc_value=ioc_value[:50],
                error=str(e),
            )
            return None

    async def list_available_actions(self) -> List[Dict[str, Any]]:
        if self._actions_cache:
            return self._actions_cache

        actions = await self.list_actions()
        self._actions_cache = actions
        return actions

    def match_actions_for_alert(self, alert_data: dict) -> List[Dict[str, Any]]:
        severity = alert_data.get("severity", "low")
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        alert_sev_level = severity_order.get(severity, 0)

        mitre_tactics = [t.lower() for t in alert_data.get("mitre_tactics", [])]
        title = alert_data.get("title", "").lower()
        rule_name = alert_data.get("rule_name", "").lower()
        text_content = f"{title} {rule_name}"

        iocs = {
            "ip": alert_data.get("source_ip", ""),
            "hostname": alert_data.get("hostname", ""),
        }

        matched_actions = []

        for rule in self._auto_execute_rules:
            min_sev_level = severity_order.get(rule.get("min_severity", "critical"), 3)
            if alert_sev_level < min_sev_level:
                continue

            ioc_type = rule["ioc_type"]
            ioc_value = iocs.get(ioc_type, "")
            if not ioc_value:
                continue

            condition_met = False
            condition = rule.get("condition", "").lower()

            if "threat_intel" in condition and alert_data.get("threat_intel"):
                condition_met = True
            if "malicious_score" in condition:
                score = alert_data.get("malicious_score", 0)
                threshold = int(condition.split(">=")[-1].strip()) if ">=" in condition else 70
                if score >= threshold:
                    condition_met = True
            if "campaign" in condition and alert_data.get("campaign_context"):
                condition_met = True
            if "mitre_exfiltration" in condition and "exfiltration" in mitre_tactics:
                condition_met = True
            if "mitre_execution" in condition and "execution" in mitre_tactics:
                condition_met = True
            if "mitre_persistence" in condition and "persistence" in mitre_tactics:
                condition_met = True
            if any(kw in text_content for kw in ["malware", "trojan", "ransomware", "phishing", "c2", "spam"]):
                for kw in ["malware", "trojan", "ransomware", "phishing", "c2", "spam"]:
                    if kw in condition and kw in text_content:
                        condition_met = True
                        break

            if not condition_met:
                continue

            matched_actions.append({
                "rule": rule,
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "action_patterns": rule["action_pattern"],
            })

        return matched_actions

    async def auto_execute_for_alert(self, alert_id: str, alert_data: dict) -> List[Dict[str, Any]]:
        matched = self.match_actions_for_alert(alert_data)
        if not matched:
            return []

        available_actions = await self.list_available_actions()
        if not available_actions:
            return []

        available_action_names = {a["name"].lower(): a for a in available_actions}
        results = []

        for match in matched:
            for pattern in match["action_patterns"]:
                for action_name, action_def in available_action_names.items():
                    if pattern in action_name:
                        if match["ioc_type"] in action_def.get("ioc_types", []):
                            result = await self.execute_action(
                                action_name=action_name,
                                ioc_type=match["ioc_type"],
                                ioc_value=match["ioc_value"],
                                alert_id=alert_id,
                            )
                            if result:
                                results.append({
                                    "action": action_name,
                                    "ioc_type": match["ioc_type"],
                                    "ioc_value": match["ioc_value"],
                                    "result": result,
                                })
                                break

        if results:
            logger.info("actions_auto_executed", alert_id=alert_id, count=len(results))

        return results

    def get_stats(self) -> Dict[str, int]:
        return {
            "executed": self._execution_count,
            "failures": self._failure_count,
            "rules_count": len(self._auto_execute_rules),
        }


action_executor = ActionExecutor()
