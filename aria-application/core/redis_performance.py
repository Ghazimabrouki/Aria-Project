"""
Performance Metrics Redis Storage.

Stores time-series data for performance metrics in Redis.
Part of the Server Performance Monitoring System (v1.0).
"""

import json
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

import structlog
from core.redis import get_redis_client

logger = structlog.get_logger()

# Redis keys
METRICS_KEY_PREFIX = "opensoar:performance:metrics"
HISTORY_KEY_PREFIX = "opensoar:performance:history"
BASELINE_KEY_PREFIX = "opensoar:performance:baseline"
ALERT_COOLDOWN_PREFIX = "opensoar:performance:cooldown"

# TTL settings
METRICS_TTL_SECONDS = 300  # 5 minutes for current metrics
HISTORY_TTL_DAYS = 2  # 2 days for history


@dataclass
class MetricDataPoint:
    """Single metric data point."""

    timestamp: str
    value: float


@dataclass
class HostBaseline:
    """Statistical baseline for a host metric."""

    mean: float = 0.0
    std: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    sample_count: int = 0
    last_updated: str = ""


class PerformanceRedis:
    """Redis storage for performance metrics."""

    def __init__(self):
        self._redis = None
        self._redis_loop = None

    async def _get_redis(self):
        import asyncio
        current_loop = asyncio.get_running_loop()
        if self._redis is None or self._redis_loop is not current_loop:
            self._redis = await get_redis_client()
            self._redis_loop = current_loop
        return self._redis

    async def store_current_metrics(self, host: str, metrics: Dict[str, Any]) -> bool:
        """Store current metrics for a host."""
        try:
            redis = await self._get_redis()
            key = f"{METRICS_KEY_PREFIX}:{host}"

            data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics": metrics,
            }

            await redis.setex(key, METRICS_TTL_SECONDS, json.dumps(data))
            return True
        except Exception as e:
            logger.error("store_metrics_failed", host=host, error=str(e))
            return False

    async def get_current_metrics(self, host: str) -> Optional[Dict[str, Any]]:
        """Get current metrics for a host."""
        try:
            redis = await self._get_redis()
            key = f"{METRICS_KEY_PREFIX}:{host}"

            data = await redis.get(key)
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            logger.error("get_metrics_failed", host=host, error=str(e))
            return None

    async def get_all_current_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get current metrics for all hosts."""
        try:
            redis = await self._get_redis()
            keys = []
            async for key in redis.scan_iter(f"{METRICS_KEY_PREFIX}:*"):
                keys.append(key)

            result = {}
            for key in keys:
                key_str = key.decode() if isinstance(key, bytes) else key
                host = key_str.split(":")[-1]
                data = await redis.get(key)
                if data:
                    data_str = data.decode() if isinstance(data, bytes) else data
                    result[host] = json.loads(data_str)

            return result
        except Exception as e:
            logger.error("get_all_metrics_failed", error=str(e))
            return {}

    async def append_to_history(
        self, host: str, metric_name: str, value: float
    ) -> bool:
        """Append a value to metric history."""
        try:
            redis = await self._get_redis()
            key = f"{HISTORY_KEY_PREFIX}:{host}:{metric_name}"

            data_point = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "value": value,
            }

            # Use list, keep last 1000 points ( ~8 hours at 30s intervals)
            await redis.lpush(key, json.dumps(data_point))
            await redis.ltrim(key, 0, 999)  # Keep max 1000 points

            # Set TTL on the key
            await redis.expire(key, HISTORY_TTL_DAYS * 86400)

            return True
        except Exception as e:
            logger.error(
                "append_history_failed", host=host, metric=metric_name, error=str(e)
            )
            return False

    async def get_history(
        self, host: str, metric_name: str, limit: int = 100
    ) -> List[MetricDataPoint]:
        """Get historical values for a metric."""
        try:
            redis = await self._get_redis()
            key = f"{HISTORY_KEY_PREFIX}:{host}:{metric_name}"

            data = await redis.lrange(key, 0, limit - 1)

            result = []
            for item in data:
                point = json.loads(item)
                result.append(
                    MetricDataPoint(timestamp=point["timestamp"], value=point["value"])
                )

            return result
        except Exception as e:
            logger.error(
                "get_history_failed", host=host, metric=metric_name, error=str(e)
            )
            return []

    async def update_baseline(self, host: str, metric_name: str) -> bool:
        """Update statistical baseline for a metric from history."""
        try:
            history = await self.get_history(
                host, metric_name, limit=2880
            )  # 24 hours at 30s

            if len(history) < 10:
                return False  # Not enough data

            values = [point.value for point in history]

            # Calculate statistics
            mean = sum(values) / len(values)
            sorted_values = sorted(values)
            p95 = sorted_values[int(len(values) * 0.95)]
            p99 = sorted_values[int(len(values) * 0.99)]

            # Standard deviation
            variance = sum((x - mean) ** 2 for x in values) / len(values)
            std = variance**0.5

            baseline = HostBaseline(
                mean=mean,
                std=std,
                p95=p95,
                p99=p99,
                sample_count=len(values),
                last_updated=datetime.now(timezone.utc).isoformat(),
            )

            # Store baseline
            redis = await self._get_redis()
            key = f"{BASELINE_KEY_PREFIX}:{host}:{metric_name}"
            await redis.set(key, json.dumps(asdict(baseline)))
            await redis.expire(key, HISTORY_TTL_DAYS * 86400)

            logger.info(
                "baseline_updated",
                host=host,
                metric=metric_name,
                mean=round(mean, 2),
                std=round(std, 2),
                p95=round(p95, 2),
                samples=len(values),
            )

            return True
        except Exception as e:
            logger.error(
                "update_baseline_failed", host=host, metric=metric_name, error=str(e)
            )
            return False

    async def get_baseline(self, host: str, metric_name: str) -> Optional[HostBaseline]:
        """Get statistical baseline for a metric."""
        try:
            redis = await self._get_redis()
            key = f"{BASELINE_KEY_PREFIX}:{host}:{metric_name}"

            data = await redis.get(key)
            if data:
                return HostBaseline(**json.loads(data))
            return None
        except Exception as e:
            logger.error(
                "get_baseline_failed", host=host, metric=metric_name, error=str(e)
            )
            return None

    async def set_alert_cooldown(self, host: str, alert_type: str) -> bool:
        """Set cooldown to prevent alert spam."""
        try:
            redis = await self._get_redis()
            settings = self._get_settings()
            cooldown_seconds = settings.performance_alert_cooldown_minutes * 60

            key = f"{ALERT_COOLDOWN_PREFIX}:{host}:{alert_type}"
            await redis.setex(key, cooldown_seconds, "1")

            return True
        except Exception as e:
            logger.error("set_cooldown_failed", error=str(e))
            return False

    async def is_in_cooldown(self, host: str, alert_type: str) -> bool:
        """Check if alert is in cooldown period."""
        try:
            redis = await self._get_redis()
            key = f"{ALERT_COOLDOWN_PREFIX}:{host}:{alert_type}"

            exists = await redis.exists(key)
            return exists > 0
        except Exception as e:
            return False

    def _get_settings(self):
        from config import get_settings

        return get_settings()

    # ─── Alert History Storage ─────────────────────────────────────────────────

    ALERT_HISTORY_PREFIX = "opensoar:performance:alerts"
    ALERT_HISTORY_TTL_DAYS = 7  # Keep alerts for 7 days

    async def store_alert(self, alert: Dict[str, Any]) -> bool:
        """Store a performance alert in history."""
        try:
            redis = await self._get_redis()
            alert_id = alert.get("id", str(uuid.uuid4()))
            host = alert.get("host", "unknown")

            # Store alert data
            key = f"{self.ALERT_HISTORY_PREFIX}:{alert_id}"
            await redis.set(key, json.dumps(alert))
            await redis.expire(key, self.ALERT_HISTORY_TTL_DAYS * 86400)

            # Convert timestamp to Unix timestamp for zadd (zadd requires float)
            timestamp_str = alert.get(
                "timestamp", datetime.now(timezone.utc).isoformat()
            )
            try:
                ts = datetime.fromisoformat(
                    timestamp_str.replace("Z", "+00:00")
                ).timestamp()
            except Exception:
                ts = datetime.now(timezone.utc).timestamp()

            # Add to host's alert list (sorted by timestamp)
            host_key = f"{self.ALERT_HISTORY_PREFIX}:host:{host}"
            await redis.zadd(host_key, {alert_id: ts})
            await redis.expire(host_key, self.ALERT_HISTORY_TTL_DAYS * 86400)

            # Add to global alert list
            global_key = f"{self.ALERT_HISTORY_PREFIX}:all"
            await redis.zadd(global_key, {alert_id: ts})
            await redis.expire(global_key, self.ALERT_HISTORY_TTL_DAYS * 86400)

            return True
        except Exception as e:
            logger.error("store_alert_failed", error=str(e))
            return False

    async def get_alert_history(
        self,
        host: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Get alert history with optional filtering."""
        try:
            redis = await self._get_redis()

            # Get alert IDs based on filter
            if host:
                key = f"{self.ALERT_HISTORY_PREFIX}:host:{host}"
            else:
                key = f"{self.ALERT_HISTORY_PREFIX}:all"

            # Get most recent alerts (highest scores = most recent)
            alert_ids = await redis.zrevrange(key, 0, limit - 1)

            if not alert_ids:
                return []

            alerts = []
            for alert_id in alert_ids:
                alert_key = f"{self.ALERT_HISTORY_PREFIX}:{alert_id}"
                data = await redis.get(alert_key)
                if data:
                    alert = json.loads(data)
                    # Apply severity filter
                    if severity and alert.get("severity") != severity:
                        continue
                    alerts.append(alert)

            return alerts[:limit]
        except Exception as e:
            logger.error("get_alert_history_failed", error=str(e))
            return []

    # ─── Generic get/set for custom keys (like performance_incidents) ───
    async def get(self, key: str) -> Optional[Any]:
        """Get a value by key with retry logic."""
        for attempt in range(3):
            try:
                redis = await self._get_redis()
                data = await redis.get(key)
                if data:
                    return json.loads(data)
                return None
            except Exception as e:
                if attempt == 2:
                    logger.error("redis_get_failed", key=key, error=str(e))
                    return None
                await asyncio.sleep(0.5 * (2**attempt))
        return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value by key with retry logic."""
        for attempt in range(3):
            try:
                redis = await self._get_redis()
                serialized = json.dumps(value)
                if ttl:
                    await redis.setex(key, ttl, serialized)
                else:
                    await redis.set(key, serialized)
                return True
            except Exception as e:
                if attempt == 2:
                    logger.error("redis_set_failed", key=key, error=str(e))
                    return False
                await asyncio.sleep(0.5 * (2**attempt))
        return False


# Singleton instance
performance_redis = PerformanceRedis()


# Helper functions
async def store_performance_metrics(host: str, metrics: Dict[str, Any]) -> bool:
    """Store current performance metrics."""
    return await performance_redis.store_current_metrics(host, metrics)


async def get_performance_metrics_history(
    host: str, metric: str, limit: int = 100
) -> List[MetricDataPoint]:
    """Get historical data for a metric."""
    return await performance_redis.get_history(host, metric, limit)


async def get_metric_baseline(host: str, metric: str) -> Optional[HostBaseline]:
    """Get baseline for a metric."""
    return await performance_redis.get_baseline(host, metric)
