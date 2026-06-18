"""
AI Pipeline.
All /ai/* endpoints + smart auto-triage/summarize/correlate/resolve.

Uses NVIDIA NIM API directly (bypasses OpenSOAR server AI endpoints).
"""

import asyncio
import structlog
import json
from typing import Optional, Dict, Any, List

from pipeline.sender import client
from config import get_settings

logger = structlog.get_logger()

# Try to import local LLM from response engine (NVIDIA/Google/etc)
try:
    from response.ai_engine import _call_llm as _local_llm
    _HAS_LOCAL_LLM = True
except Exception as e:
    logger.warning("local_llm_import_failed", error=str(e))
    _local_llm = None
    _HAS_LOCAL_LLM = False


class AIPipeline:
    def __init__(self):
        self._triage_cache: Dict[str, dict] = {}
        self._summary_cache: Dict[str, str] = {}
        self._triage_count = 0
        self._resolve_count = 0
        self._correlate_count = 0

    async def _call_local_ai(self, prompt: str, task_type: str) -> Optional[str]:
        """Call local LLM (NVIDIA/Google) instead of OpenSOAR server."""
        if not _HAS_LOCAL_LLM:
            return None
        try:
            result = await _local_llm(prompt)
            logger.info("local_ai_completed", task_type=task_type, response_len=len(result) if result else 0)
            return result
        except Exception as e:
            logger.error("local_ai_failed", task_type=task_type, error=str(e))
            return None

    async def summarize_alert(self, alert_id: str) -> Optional[str]:
        if alert_id in self._summary_cache:
            return self._summary_cache[alert_id]

        # Try local NVIDIA AI first
        if _HAS_LOCAL_LLM:
            prompt = f"""Summarize this security alert in 2-3 sentences. Be concise and actionable.
Alert ID: {alert_id}

Return ONLY the summary text, no extra formatting."""
            summary = await self._call_local_ai(prompt, "summarize")
            if summary:
                self._summary_cache[alert_id] = summary
                logger.debug("ai_summary_generated_local", alert_id=alert_id, summary_preview=summary[:80])
                return summary

        return None

    async def triage_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        if alert_id in self._triage_cache:
            return self._triage_cache[alert_id]

        # Try local NVIDIA AI first
        if _HAS_LOCAL_LLM:
            prompt = f"""Analyze this security alert. Return ONLY valid JSON with these fields:
{{"severity": "low", "confidence": 75, "recommended_action": "investigate", "tags": ["tag1"]}}

Alert ID: {alert_id}
Respond with ONLY JSON, no markdown."""
            result_str = await self._call_local_ai(prompt, "triage")
            if result_str:
                try:
                    # Try to extract JSON from response
                    import re
                    json_match = re.search(r'\{.*\}', result_str, re.DOTALL)
                    if json_match:
                        result = json.loads(json_match.group())
                        self._triage_cache[alert_id] = result
                        self._triage_count += 1
                        logger.info("ai_triage_completed_local", alert_id=alert_id)
                        return result
                except (json.JSONDecodeError, AttributeError):
                    logger.warning("ai_triage_parse_failed", alert_id=alert_id, raw=result_str[:100])

        return None

    async def generate_playbook(self, description: str) -> Optional[str]:
        # Try local NVIDIA AI first
        if _HAS_LOCAL_LLM:
            prompt = f"""Generate an Ansible playbook (YAML) to remediate this security issue:
{description}

Provide valid Ansible YAML with:
- name: playbook name
- hosts: target hosts
- tasks: remediation steps
- Use ansible.posix.authorized_key, systemd,iptables modules as needed"""
            playbook = await self._call_local_ai(prompt, "generate_playbook")
            if playbook:
                logger.info("ai_playbook_generated_local", description_preview=description[:50])
                return playbook

        # Fallback to OpenSOAR server (skipped when upstream disabled)
        if not get_settings().upstream_enabled:
            logger.debug("ai_generate_playbook_skipped_upstream_disabled")
            return None
        try:
            resp = await client._get_http().post(
                "/api/v1/ai/generate-playbook",
                json={"description": description},
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            result = resp.json()
            playbook_code = result if isinstance(result, str) else str(result)
            logger.info("ai_playbook_generated", description_preview=description[:50])
            return playbook_code
        except Exception as e:
            logger.error("ai_generate_playbook_failed", error=str(e))
            return None

    async def auto_resolve_alerts(self, alert_ids: List[str]) -> Optional[str]:
        if not alert_ids:
            return None

        if _HAS_LOCAL_LLM:
            prompt = f"""Analyze these alerts and determine if they should be auto-resolved.
Alert IDs: {alert_ids}

Respond with ONLY JSON: {{"resolve": true, "reason": "explanation", "confidence": 75}}"""
            result_str = await self._call_local_ai(prompt, "auto_resolve")
            if result_str:
                self._resolve_count += len(alert_ids)
                logger.info("ai_auto_resolve_evaluated_local", count=len(alert_ids))
                return result_str

        return None

    async def correlate_alerts(self, alert_ids: List[str]) -> Optional[str]:
        if len(alert_ids) < 2:
            return None

        if _HAS_LOCAL_LLM:
            prompt = f"""Determine if these alerts are related (same campaign/attack).
Alert IDs: {alert_ids}

Respond with ONLY JSON: {{"related": true, "campaign_name": "optional", "confidence": 75, "reason": "explanation"}}"""
            result_str = await self._call_local_ai(prompt, "correlate")
            if result_str:
                self._correlate_count += 1
                logger.info("ai_correlate_completed_local", count=len(alert_ids))
                return result_str

        return None

    async def smart_triage_and_apply(self, alert_id: str, alert_data: dict) -> Dict[str, Any]:
        from pipeline.datausage.alert_manager import alert_manager

        severity = alert_data.get("severity", "low")
        mitre_tactics = alert_data.get("mitre_tactics", [])
        campaign = alert_data.get("campaign_context", "")

        should_triage = (
            severity in ("medium", "high") or
            len(mitre_tactics) >= 2 or
            campaign
        )

        triage_result = None
        if should_triage:
            triage_result = await self.triage_alert(alert_id)

        auto_resolve_candidates = []
        if severity == "low" and not mitre_tactics and not campaign:
            auto_resolve_candidates.append(alert_id)

        summary = None
        if severity in ("critical", "high"):
            summary = await self.summarize_alert(alert_id)

        applied = {
            "triaged": triage_result is not None,
            "summarized": summary is not None,
            "auto_resolve_queued": len(auto_resolve_candidates) > 0,
        }

        if auto_resolve_candidates:
            await self.auto_resolve_alerts(auto_resolve_candidates)

        if summary:
            await alert_manager.add_comment(
                alert_id,
                f"AI Summary:\n{summary}",
            )

        return applied

    def get_stats(self) -> Dict[str, int]:
        return {
            "triage_count": self._triage_count,
            "resolve_count": self._resolve_count,
            "correlate_count": self._correlate_count,
            "triage_cache_size": len(self._triage_cache),
            "summary_cache_size": len(self._summary_cache),
        }


ai_pipeline = AIPipeline()
