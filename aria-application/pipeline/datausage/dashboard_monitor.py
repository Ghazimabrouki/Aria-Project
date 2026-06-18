"""
Dashboard Monitor.
Dashboard stats + trend analysis + anomaly detection + SOC metrics.
"""

import asyncio
import structlog
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
from collections import deque

from pipeline.sender import client
from config import get_settings

logger = structlog.get_logger()


class DashboardMonitor:
    def __init__(self):
        self._stats_history: deque[dict] = deque(maxlen=288)
        self._anomalies: List[dict] = []
        self._last_stats: Optional[dict] = None
        self._check_interval = 300
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def get_stats(self, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            params = {}
            if tenant_id:
                params["tenant_id"] = tenant_id

            resp = await client._get_http().get(
                "/api/v1/dashboard/stats",
                params=params,
                headers=client._auth_headers(),
            )
            resp.raise_for_status()
            result = resp.json()
            self._last_stats = result
            self._stats_history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stats": result,
            })
            return result
        except Exception as e:
            logger.error("get_dashboard_stats_failed", error=str(e))
            return None

    def detect_anomalies(self) -> List[dict]:
        if len(self._stats_history) < 12:
            return []

        recent = list(self._stats_history)[-12:]
        older = list(self._stats_history)[:-12]

        if not older:
            return []

        new_anomalies = []

        for key in ["total_alerts", "open_alerts", "critical_alerts", "open_incidents"]:
            if not isinstance(recent[-1].get("stats"), dict):
                continue
            if key not in recent[-1]["stats"]:
                continue

            recent_values = [h["stats"].get(key, 0) for h in recent if isinstance(h.get("stats"), dict) and key in h["stats"]]
            older_values = [h["stats"].get(key, 0) for h in older if isinstance(h.get("stats"), dict) and key in h["stats"]]

            if not recent_values or not older_values:
                continue

            recent_avg = sum(recent_values) / len(recent_values)
            older_avg = sum(older_values) / len(older_values)

            if older_avg == 0:
                if recent_avg > 5:
                    new_anomalies.append({
                        "metric": key,
                        "type": "new_activity",
                        "current": recent_avg,
                        "baseline": older_avg,
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    })
            else:
                change_pct = ((recent_avg - older_avg) / older_avg) * 100
                if change_pct > 50:
                    new_anomalies.append({
                        "metric": key,
                        "type": "spike",
                        "current": recent_avg,
                        "baseline": older_avg,
                        "change_pct": round(change_pct, 1),
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    })
                elif change_pct < -50:
                    new_anomalies.append({
                        "metric": key,
                        "type": "drop",
                        "current": recent_avg,
                        "baseline": older_avg,
                        "change_pct": round(change_pct, 1),
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    })

        self._anomalies.extend(new_anomalies)
        self._anomalies = self._anomalies[-100:]

        return new_anomalies

    def get_trends(self) -> Dict[str, Any]:
        if len(self._stats_history) < 2:
            return {"available": False, "message": "Insufficient data"}

        history = list(self._stats_history)
        first = history[0]
        last = history[-1]

        if not isinstance(first.get("stats"), dict) or not isinstance(last.get("stats"), dict):
            return {"available": False, "message": "Invalid stats format"}

        trends = {}
        for key in first["stats"]:
            if isinstance(first["stats"].get(key), (int, float)) and isinstance(last["stats"].get(key), (int, float)):
                first_val = first["stats"][key]
                last_val = last["stats"][key]
                if first_val > 0:
                    change_pct = ((last_val - first_val) / first_val) * 100
                    trends[key] = {
                        "first": first_val,
                        "current": last_val,
                        "change": last_val - first_val,
                        "change_pct": round(change_pct, 1),
                        "direction": "up" if change_pct > 0 else "down" if change_pct < 0 else "stable",
                    }
                else:
                    trends[key] = {
                        "first": first_val,
                        "current": last_val,
                        "change": last_val - first_val,
                        "direction": "new" if last_val > 0 else "stable",
                    }

        return {
            "available": True,
            "data_points": len(history),
            "time_span": f"{len(history) * self._check_interval / 3600:.1f}h",
            "trends": trends,
        }

    def generate_soc_report(self) -> Dict[str, Any]:
        stats = self._last_stats or {}
        trends = self.get_trends()
        anomalies = self._anomalies[-10:]

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "current_stats": stats,
            "trends": trends,
            "recent_anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "data_points": len(self._stats_history),
        }

    async def start_background_monitor(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._background_loop())
        logger.info("dashboard_monitor_background_started", interval=self._check_interval)

    async def stop_background_monitor(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("dashboard_monitor_background_stopped")

    async def _background_loop(self) -> None:
        while self._running:
            try:
                stats = await self.get_stats()
                if stats:
                    anomalies = self.detect_anomalies()
                    if anomalies:
                        for anomaly in anomalies:
                            logger.warning(
                                "dashboard_anomaly_detected",
                                metric=anomaly["metric"],
                                type=anomaly["type"],
                                change=anomaly.get("change_pct"),
                            )
            except Exception as e:
                logger.error("dashboard_monitor_background_error", error=str(e))
            await asyncio.sleep(self._check_interval)


dashboard_monitor = DashboardMonitor()
