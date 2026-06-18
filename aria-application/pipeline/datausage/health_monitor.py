"""
Health Monitor with Circuit Breaker Pattern.
GET /api/v1/health + latency tracking + automatic degradation handling.
"""

import asyncio
import time
import structlog
from typing import Optional, Dict, Any, List
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pipeline.sender import client
from config import get_settings

logger = structlog.get_logger()


@dataclass
class HealthCheckResult:
    timestamp: float
    latency_ms: float
    healthy: bool
    status_code: int = 0
    error: str = ""


@dataclass
class CircuitBreaker:
    state: str = "closed"
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    last_success_time: float = 0.0
    failure_threshold: int = 3
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 1

    @property
    def is_open(self) -> bool:
        if self.state == "open":
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = "half-open"
                self.success_count = 0
                logger.info("circuit_breaker_half_open")
                return False
            return True
        return False

    def _check_state_transition(self) -> None:
        if self.state == "open" and time.time() - self.last_failure_time >= self.recovery_timeout:
            self.state = "half-open"
            self.success_count = 0
            logger.info("circuit_breaker_half_open")

    def record_success(self) -> None:
        self.last_success_time = time.time()
        if self.state == "half-open":
            self.success_count += 1
            if self.success_count >= self.half_open_max_calls:
                self.state = "closed"
                self.failure_count = 0
                logger.info("circuit_breaker_closed", recovery_time=round(time.time() - self.last_failure_time, 1))
        else:
            self.failure_count = 0

    def record_failure(self) -> None:
        self.last_failure_time = time.time()
        self.failure_count += 1
        if self.state != "open" and self.failure_count >= self.failure_threshold:
            self.state = "open"
            logger.warning("circuit_breaker_opened", failures=self.failure_count)


class HealthMonitor:
    def __init__(self):
        self._circuit_breaker = CircuitBreaker()
        self._history: deque[HealthCheckResult] = deque(maxlen=1000)
        self._last_check: Optional[HealthCheckResult] = None
        self._check_interval = 30
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def check_health(self) -> HealthCheckResult:
        if self._circuit_breaker.is_open:
            logger.warning("health_check_skipped_circuit_open")
            return HealthCheckResult(
                timestamp=time.time(),
                latency_ms=0,
                healthy=False,
                error="Circuit breaker open",
            )

        start = time.time()
        try:
            resp = await client._get_http().get("/api/v1/health")
            latency_ms = (time.time() - start) * 1000
            healthy = resp.status_code == 200

            result = HealthCheckResult(
                timestamp=time.time(),
                latency_ms=round(latency_ms, 2),
                healthy=healthy,
                status_code=resp.status_code,
            )

            if healthy:
                self._circuit_breaker.record_success()
            else:
                self._circuit_breaker.record_failure()

            self._history.append(result)
            self._last_check = result

            if not healthy:
                logger.warning("health_check_failed", status=resp.status_code, latency_ms=latency_ms)

            return result

        except Exception as e:
            latency_ms = (time.time() - start) * 1000
            self._circuit_breaker.record_failure()

            result = HealthCheckResult(
                timestamp=time.time(),
                latency_ms=round(latency_ms, 2),
                healthy=False,
                error=str(e)[:100],
            )
            self._history.append(result)
            self._last_check = result

            logger.error("health_check_error", error=str(e)[:100])
            return result

    async def check_and_log(self) -> bool:
        result = await self.check_health()
        if result.healthy:
            logger.debug("opensoar_healthy", latency_ms=result.latency_ms)
        return result.healthy

    def get_stats(self) -> Dict[str, Any]:
        if not self._history:
            return {"status": "unknown", "checks": 0}

        checks = list(self._history)
        healthy_count = sum(1 for c in checks if c.healthy)
        total = len(checks)
        latencies = [c.latency_ms for c in checks if c.latency_ms > 0]

        if not latencies:
            return {"status": "degraded", "checks": total, "healthy": 0, "unhealthy": total}

        sorted_latencies = sorted(latencies)
        p50 = sorted_latencies[len(sorted_latencies) // 2]
        p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)]
        p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)]

        uptime_pct = (healthy_count / total * 100) if total > 0 else 0

        return {
            "status": "healthy" if self._circuit_breaker.state == "closed" else self._circuit_breaker.state,
            "circuit_breaker": self._circuit_breaker.state,
            "checks": total,
            "healthy": healthy_count,
            "unhealthy": total - healthy_count,
            "uptime_pct": round(uptime_pct, 2),
            "latency_p50_ms": round(p50, 2),
            "latency_p95_ms": round(p95, 2),
            "latency_p99_ms": round(p99, 2),
            "last_check": self._last_check.timestamp if self._last_check else None,
            "last_healthy": self._last_check.healthy if self._last_check else False,
        }

    def is_healthy(self) -> bool:
        return not self._circuit_breaker.is_open

    async def start_background_check(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._background_loop())
        logger.info("health_monitor_background_started", interval=self._check_interval)

    async def stop_background_check(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("health_monitor_background_stopped")

    async def _background_loop(self) -> None:
        while self._running:
            try:
                await self.check_and_log()
            except Exception as e:
                logger.error("health_monitor_background_error", error=str(e))
            await asyncio.sleep(self._check_interval)


health_monitor = HealthMonitor()
