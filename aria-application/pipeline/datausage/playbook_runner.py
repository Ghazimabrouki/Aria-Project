"""
Playbook Runner.
Playbooks CRUD + smart triggering + runs tracking + auto-retry.
"""

import asyncio
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from pipeline.sender import client
from config import get_settings

logger = structlog.get_logger()


class PlaybookRunner:
    def __init__(self):
        self._playbooks_cache: Optional[List[Dict[str, Any]]] = None
        self._cache_time: float = 0
        self._cache_ttl = 300
        self._trigger_count = 0
        self._failure_count = 0
        self._retry_count = 0
        self._trigger_rules: List[dict] = []

    async def list_playbooks(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        if self._playbooks_cache and not force_refresh and (datetime.now(timezone.utc).timestamp() - self._cache_time) < self._cache_ttl:
            return self._playbooks_cache

        try:
            resp = await client._get_http().get(
                "/api/v1/playbooks",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._playbooks_cache = resp.json()
            self._cache_time = datetime.now(timezone.utc).timestamp()
            enabled = sum(1 for p in self._playbooks_cache if p.get("enabled"))
            logger.debug("playbooks_cached", total=len(self._playbooks_cache), enabled=enabled)
            return self._playbooks_cache
        except Exception as e:
            logger.error("list_playbooks_failed", error=str(e))
            return self._playbooks_cache or []

    async def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await client._get_http().get(
                f"/api/v1/playbooks/{playbook_id}",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("get_playbook_failed", playbook_id=playbook_id, error=str(e))
            return None

    async def update_playbook(self, playbook_id: str, updates: dict) -> Optional[Dict[str, Any]]:
        try:
            resp = await client._get_http().patch(
                f"/api/v1/playbooks/{playbook_id}",
                json=updates,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            self._playbooks_cache = None
            logger.info("playbook_updated", playbook_id=playbook_id)
            return resp.json()
        except Exception as e:
            logger.error("update_playbook_failed", playbook_id=playbook_id, error=str(e))
            return None

    async def run_playbook(self, playbook_id: str, alert_id: str, input_data: Optional[dict] = None) -> Optional[str]:
        payload: Dict[str, Any] = {"alert_id": alert_id}
        if input_data:
            payload["input_data"] = input_data

        try:
            resp = await client._get_http().post(
                f"/api/v1/playbooks/{playbook_id}/run",
                json=payload,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            result = resp.json()
            self._trigger_count += 1
            run_id = result if isinstance(result, str) else str(result)
            logger.info("playbook_triggered", playbook_id=playbook_id, alert_id=alert_id, run_id=run_id)
            return run_id
        except Exception as e:
            self._failure_count += 1
            logger.error("run_playbook_failed", playbook_id=playbook_id, alert_id=alert_id, error=str(e))
            return None

    async def run_playbook_with_retry(self, playbook_id: str, alert_id: str, input_data: Optional[dict] = None, max_retries: int = 1) -> Optional[str]:
        result = await self.run_playbook(playbook_id, alert_id, input_data)
        if result:
            return result

        for attempt in range(max_retries):
            logger.info("playbook_retry", playbook_id=playbook_id, alert_id=alert_id, attempt=attempt + 1)
            await asyncio.sleep(2 ** attempt)
            result = await self.run_playbook(playbook_id, alert_id, input_data)
            if result:
                self._retry_count += 1
                return result

        return None

    async def list_runs(self, status: Optional[str] = None, playbook_id: Optional[str] = None, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if playbook_id:
            params["playbook_id"] = playbook_id

        try:
            resp = await client._get_http().get(
                "/api/v1/runs",
                params=params,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("list_runs_failed", error=str(e))
            return {"runs": [], "total": 0}

    async def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await client._get_http().get(
                f"/api/v1/runs/{run_id}",
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("get_run_failed", run_id=run_id, error=str(e))
            return None

    def match_playbooks_for_alert(self, alert_data: dict) -> List[Dict[str, Any]]:
        if not self._playbooks_cache:
            return []

        severity = alert_data.get("severity", "low")
        source = alert_data.get("source", "")
        mitre_tactics = alert_data.get("mitre_tactics", [])
        cloud_provider = alert_data.get("cloud_provider", "")
        rule_name = alert_data.get("rule_name", "").lower()

        matched = []
        for playbook in self._playbooks_cache:
            if not playbook.get("enabled"):
                continue

            name = playbook.get("name", "").lower()
            description = playbook.get("description", "").lower()
            combined = f"{name} {description}"

            score = 0

            if severity in ("critical", "high") and any(kw in combined for kw in ["critical", "high", "incident", "response"]):
                score += 3

            if source == "falco" and any(kw in combined for kw in ["container", "docker", "kubernetes", "falco"]):
                score += 5

            if source == "suricata" and any(kw in combined for kw in ["network", "suricata", "traffic", "ids"]):
                score += 5

            if source == "wazuh" and any(kw in combined for kw in ["wazuh", "endpoint", "host", "file"]):
                score += 5

            for tactic in mitre_tactics:
                if tactic.lower() in combined:
                    score += 4

            if cloud_provider and cloud_provider.lower() in combined:
                score += 3

            if any(kw in rule_name for kw in ["brute", "scan", "malware", "exfil"]):
                if any(kw in combined for kw in ["brute", "scan", "malware", "exfil"]):
                    score += 2

            if score >= 3:
                matched.append({"playbook": playbook, "score": score})

        matched.sort(key=lambda x: x["score"], reverse=True)
        return [m["playbook"] for m in matched[:3]]

    async def auto_trigger_for_alert(self, alert_id: str, alert_data: dict) -> List[str]:
        playbooks = self.match_playbooks_for_alert(alert_data)
        triggered = []

        for playbook in playbooks:
            run_id = await self.run_playbook_with_retry(
                playbook_id=playbook["id"],
                alert_id=alert_id,
                input_data={"source": alert_data.get("source"), "severity": alert_data.get("severity")},
            )
            if run_id:
                triggered.append(run_id)

        if triggered:
            logger.info("playbooks_auto_triggered", alert_id=alert_id, count=len(triggered))

        return triggered

    def get_stats(self) -> Dict[str, int]:
        return {
            "triggered": self._trigger_count,
            "failures": self._failure_count,
            "retries": self._retry_count,
            "cached_playbooks": len(self._playbooks_cache) if self._playbooks_cache else 0,
        }


playbook_runner = PlaybookRunner()
