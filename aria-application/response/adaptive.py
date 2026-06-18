"""
Adaptive System for OpenSOAR Response Engine.

Provides dynamic, self-tuning behavior based on real-time metrics.
"""
import asyncio
import math
import random
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import structlog

logger = structlog.get_logger()


@dataclass
class AdaptiveConfig:
    """Configuration bounds for adaptive system."""
    # Timeout bounds - for NVIDIA Qwen (~10-30s typical)
    timeout_min: int = 30
    timeout_max: int = 120
    timeout_base: int = 45
    
    # Retry rate bounds  
    retry_min_interval: int = 1
    retry_max_interval: int = 60
    
    # Concurrency bounds
    concurrency_min: int = 1
    concurrency_max: int = 4
    concurrency_default: int = 2
    
    # Stabilization (prevent flapping)
    min_change_interval: int = 15
    stabilization_required: int = 2


class ErrorClassifier:
    """Classify errors for intelligent retry decisions."""
    
    @staticmethod
    def categorize(error_msg: str) -> str:
        if not error_msg:
            return "unknown"
        
        error_lower = error_msg.lower()
        
        if "timeout" in error_lower:
            return "timeout"
        elif "parse" in error_lower or "json" in error_lower or "yaml" in error_lower:
            return "parse_error"
        elif "connection" in error_lower or "network" in error_lower or "refused" in error_lower:
            return "network_error"
        elif "validation" in error_lower or "invalid" in error_lower:
            return "validation_error"
        elif "permission" in error_lower or "unauthorized" in error_lower or "forbidden" in error_lower:
            return "auth_error"
        elif "not found" in error_lower or "404" in error_lower:
            return "not_found_error"
        elif "rate limit" in error_lower or "429" in error_lower or "too many requests" in error_lower:
            return "rate_limit"
        elif "openrouter" in error_lower:
            return "rate_limit"  # OpenRouter rate limits
        else:
            return "unknown"


class MetricsCollector:
    """Thread-safe metrics collection for adaptive decisions."""
    
    def __init__(self, config: AdaptiveConfig):
        self._config = config
        self._lock = asyncio.Lock()
        
        # Response time tracking
        self._response_times: deque = deque(maxlen=100)
        self._last_response_time: Optional[float] = None
        
        # Investigation tracking
        self._investigations_completed = 0
        self._investigations_failed = 0
        
        # Error tracking
        self._error_counts: Dict[str, int] = {}
        
        # Concurrency tracking
        self._concurrent_requests = 0
        self._peak_concurrent = 0
        
        # Queue tracking
        self._pending_queue_depth = 0
        
        # Timestamps
        self._last_error_time: Optional[float] = None
        self._last_success_time: Optional[float] = None
    
    async def record_ollama_response(self, duration: float, success: bool):
        """Record Ollama response time and success."""
        async with self._lock:
            self._response_times.append(duration)
            self._last_response_time = duration
            
            if success:
                self._investigations_completed += 1
                self._last_success_time = time.time()
            else:
                self._investigations_failed += 1
                self._last_error_time = time.time()
    
    async def record_error(self, error_type: str):
        """Record error by type."""
        async with self._lock:
            self._error_counts[error_type] = self._error_counts.get(error_type, 0) + 1
    
    async def record_concurrent_start(self):
        """Record start of concurrent operation."""
        async with self._lock:
            self._concurrent_requests += 1
            self._peak_concurrent = max(self._peak_concurrent, self._concurrent_requests)
    
    async def record_concurrent_end(self):
        """Record end of concurrent operation."""
        async with self._lock:
            self._concurrent_requests = max(0, self._concurrent_requests - 1)
    
    async def update_queue_depth(self, depth: int):
        """Update pending queue depth."""
        async with self._lock:
            self._pending_queue_depth = depth
    
    # Getters
    async def get_avg_response_time(self) -> float:
        async with self._lock:
            if not self._response_times:
                return 0
            return sum(self._response_times) / len(self._response_times)
    
    async def get_success_rate(self) -> float:
        async with self._lock:
            total = self._investigations_completed + self._investigations_failed
            if total == 0:
                return 1.0
            return self._investigations_completed / total
    
    async def get_error_rate(self, error_type: str) -> float:
        async with self._lock:
            total = sum(self._error_counts.values())
            if total == 0:
                return 0
            return self._error_counts.get(error_type, 0) / total
    
    async def get_current_concurrent(self) -> int:
        async with self._lock:
            return self._concurrent_requests
    
    async def get_peak_concurrent(self) -> int:
        async with self._lock:
            return self._peak_concurrent
    
    async def get_queue_depth(self) -> int:
        async with self._lock:
            return self._pending_queue_depth
    
    async def get_status(self) -> Dict[str, Any]:
        async with self._lock:
            return {
                "avg_response_time": sum(self._response_times) / len(self._response_times) if self._response_times else 0,
                "investigations_completed": self._investigations_completed,
                "investigations_failed": self._investigations_failed,
                "success_rate": self._investigations_completed / max(1, self._investigations_completed + self._investigations_failed),
                "error_counts": dict(self._error_counts),
                "current_concurrent": self._concurrent_requests,
                "peak_concurrent": self._peak_concurrent,
                "queue_depth": self._pending_queue_depth
            }


class AdaptiveTimeout:
    """Dynamic timeout based on model, prompt length, and performance."""
    
    # Model-specific baselines (seconds)
    MODEL_BASELINES = {
        "qwen3:8b": 90,
        "qwen2.5:7b": 60,
        "deepseek-r1:14b": 45,
        "llama3:8b": 45,
        "mistral:7b": 40,
        "gemini-2.0-flash": 15,
        "gemini-1.5-flash": 20,
        "gemini-pro": 30,
    }
    
    def __init__(self, config: AdaptiveConfig, metrics: MetricsCollector):
        self._config = config
        self._metrics = metrics
        self._current_timeout = config.timeout_base
    
    async def calculate_timeout(self, prompt_length: int, model: str = "qwen3:8b") -> int:
        # Get model baseline
        model_base = self.MODEL_BASELINES.get(model, 60)
        
        # Prompt scaling with logarithmic diminishing returns
        prompt_factor = 10 * (1 + math.log10(1 + prompt_length / 500))
        
        # Base timeout
        base = model_base + prompt_factor
        
        # Performance adjustment
        avg_response = await self._metrics.get_avg_response_time()
        
        if avg_response > model_base:
            scale = min(avg_response / model_base, 2.0)
            base = base * scale
        
        # Apply bounds
        self._current_timeout = max(
            self._config.timeout_min,
            min(base, self._config.timeout_max)
        )
        
        logger.debug(
            "adaptive_timeout_calculated",
            prompt_length=prompt_length,
            model=model,
            calculated_timeout=int(self._current_timeout),
            avg_response=avg_response
        )
        
        return int(self._current_timeout)
    
    async def get_current_timeout(self) -> int:
        return int(self._current_timeout)


class AdaptiveRetryRate:
    """Smart retry with system-health awareness."""
    
    def __init__(self, config: AdaptiveConfig, metrics: MetricsCollector):
        self._config = config
        self._metrics = metrics
        self._current_interval = config.retry_min_interval
        self._retry_counts: Dict[str, int] = {}
        self._last_retry_time: Dict[str, float] = {}  # Per-investigation last retry time
    
    async def should_retry(self, investigation_id: str, error_type: Optional[str]) -> tuple[bool, int]:
        current_time = time.time()
        
        # Track retry count
        if investigation_id not in self._retry_counts:
            self._retry_counts[investigation_id] = 0
        
        retry_count = self._retry_counts[investigation_id]
        
        # Get system health
        success_rate = await self._metrics.get_success_rate()
        queue_depth = await self._metrics.get_queue_depth()
        
        # Get time since last retry for this specific investigation
        last_time = self._last_retry_time.get(investigation_id, 0)
        elapsed = current_time - last_time
        
        # Calculate wait based on error type + system health
        if error_type == "timeout":
            wait = self._config.retry_min_interval * (2 ** min(retry_count, 6))
            
            # System struggling? Add extra delay
            if success_rate < 0.5:
                wait *= 2
            if queue_depth > 10:
                wait *= 1.5
                
        elif error_type == "network_error":
            # Network errors are often transient - shorter backoff
            wait = min(5 * (retry_count + 1), 30)
            
        elif error_type == "parse_error":
            # Parse errors won't fix themselves
            if retry_count >= 3:
                return False, 0
            wait = 10

        elif error_type == "rate_limit":
            # Rate limiting - much longer backoff needed for API rate limits
            # Also add extra delay for sequential processing
            wait = 120 * (2 ** min(retry_count, 4))  # 120, 240, 480, 960, 1920 seconds
            wait = min(wait, 3000)  # Max 50 minutes
            
        elif error_type == "auth_error":
            # Auth errors won't fix with retry
            return False, 0
            
        else:
            # Unknown error or first try - NO wait needed for immediate retry
            # (error_type None means never tried before)
            if error_type is None and retry_count == 0:
                wait = 0  # Immediate retry on first attempt
            else:
                wait = min(self._config.retry_min_interval + (retry_count * 10), 120)
        
        # Add jitter
        wait = wait * (0.8 + random.random() * 0.4)
        
        # Rate limit check - use per-investigation timing
        if elapsed < wait:
            return False, int(wait - elapsed)
        
        # Update tracking
        self._retry_counts[investigation_id] = retry_count + 1
        self._last_retry_time[investigation_id] = current_time
        
        return True, 0
    
    async def record_success(self, investigation_id: str):
        """Reset retry count on success."""
        self._retry_counts.pop(investigation_id, None)
        self._last_retry_time.pop(investigation_id, None)


class CircuitBreaker:
    """Circuit breaker to prevent cascading failures."""
    
    def __init__(self, failure_threshold: int = 3, recovery_timeout: int = 300):
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._state = "closed"  # closed, open, half-open
    
    def record_failure(self):
        """Record a failure and potentially open the circuit."""
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._failure_count >= self._failure_threshold:
            self._state = "open"
            logger.warning("circuit_breaker_opened", 
                         failures=self._failure_count,
                         recovery_timeout=self._recovery_timeout)
    
    def record_success(self):
        """Record a success and potentially close the circuit."""
        if self._state == "half-open":
            self._state = "closed"
            self._failure_count = 0
            logger.info("circuit_breaker_closed")
    
    def can_proceed(self) -> tuple[bool, int]:
        """Check if requests can proceed. Returns (can_proceed, wait_seconds)."""
        if self._state == "closed":
            return True, 0
        
        if self._state == "open":
            # Check if recovery timeout has passed
            if self._last_failure_time and (time.time() - self._last_failure_time) > self._recovery_timeout:
                self._state = "half-open"
                logger.info("circuit_breaker_half_open")
                return True, 0
            
            # Still in recovery period
            remaining = self._recovery_timeout - (time.time() - self._last_failure_time)
            return False, int(remaining)
        
        # half-open - allow one request through
        return True, 0
    
    def get_state(self) -> dict:
        """Get current circuit breaker state."""
        return {
            "state": self._state,
            "failure_count": self._failure_count,
            "last_failure": self._last_failure_time
        }
    
    async def get_current_interval(self) -> int:
        return int(self._current_interval)


class AdaptiveConcurrency:
    """Self-tuning concurrency with hysteresis."""
    
    def __init__(self, config: AdaptiveConfig, metrics: MetricsCollector):
        self._config = config
        self._metrics = metrics
        self._current_limit = config.concurrency_default
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._stabilization_counter = 0
        self._last_change_time = 0
        
        # Initialize semaphore
        self._semaphore = asyncio.Semaphore(self._current_limit)
    
    async def acquire(self, investigation_id: str):
        """Acquire semaphore slot."""
        await self._semaphore.acquire()
        await self._metrics.record_concurrent_start()
        
        await self._maybe_resize()
        
        logger.debug(
            "concurrency_acquired",
            investigation_id=investigation_id,
            current_limit=self._current_limit,
            concurrent=await self._metrics.get_current_concurrent()
        )
    
    def release(self):
        """Release semaphore slot."""
        if self._semaphore:
            self._semaphore.release()
        asyncio.create_task(self._metrics.record_concurrent_end())
    
    async def _maybe_resize(self):
        """Resize with hysteresis and rate limiting."""
        current_time = time.time()
        
        # Rate limit changes
        if current_time - self._last_change_time < self._config.min_change_interval:
            return
        
        # Get metrics
        avg_response = await self._metrics.get_avg_response_time()
        success_rate = await self._metrics.get_success_rate()
        current_concurrent = await self._metrics.get_current_concurrent()
        
        # Decision logic with hysteresis
        should_increase = (
            avg_response < 60 and
            success_rate > 0.7 and
            current_concurrent >= self._current_limit - 1
        )
        
        should_decrease = (
            avg_response > 180 or
            success_rate < 0.5
        )
        
        if should_increase:
            self._stabilization_counter += 1
            if self._stabilization_counter >= self._config.stabilization_required:
                new_limit = min(self._current_limit + 1, self._config.concurrency_max)
                if new_limit != self._current_limit:
                    self._current_limit = new_limit
                    self._semaphore = asyncio.Semaphore(self._current_limit)
                    self._last_change_time = current_time
                    logger.info("concurrency_increased", new_limit=new_limit)
                self._stabilization_counter = 0
                
        elif should_decrease:
            self._stabilization_counter += 1
            if self._stabilization_counter >= self._config.stabilization_required:
                new_limit = max(self._current_limit - 1, self._config.concurrency_min)
                if new_limit != self._current_limit:
                    self._current_limit = new_limit
                    self._semaphore = asyncio.Semaphore(self._current_limit)
                    self._last_change_time = current_time
                    logger.info("concurrency_decreased", new_limit=new_limit)
                self._stabilization_counter = 0
        else:
            self._stabilization_counter = 0
    
    async def get_current_limit(self) -> int:
        return self._current_limit
    
    @property
    def semaphore(self) -> asyncio.Semaphore:
        return self._semaphore


class AdaptiveSystem:
    """Main entry point for adaptive system."""
    
    _instance: Optional['AdaptiveSystem'] = None
    _lock = asyncio.Lock()
    
    def __init__(self, config: Optional[AdaptiveConfig] = None):
        self._config = config or AdaptiveConfig()
        self._metrics = MetricsCollector(self._config)
        self._timeout = AdaptiveTimeout(self._config, self._metrics)
        self._retry = AdaptiveRetryRate(self._config, self._metrics)
        self._concurrency = AdaptiveConcurrency(self._config, self._metrics)
        
        logger.info(
            "adaptive_system_initialized",
            timeout_range=f"{self._config.timeout_min}-{self._config.timeout_max}",
            retry_range=f"{self._config.retry_min_interval}-{self._config.retry_max_interval}",
            concurrency_range=f"{self._config.concurrency_min}-{self._config.concurrency_max}"
        )
    
    @property
    def timeout(self) -> AdaptiveTimeout:
        return self._timeout
    
    @property
    def retry(self) -> AdaptiveRetryRate:
        return self._retry
    
    @property
    def concurrency(self) -> AdaptiveConcurrency:
        return self._concurrency
    
    @property
    def metrics(self) -> MetricsCollector:
        return self._metrics
    
    async def get_status(self) -> Dict[str, Any]:
        metrics_status = await self._metrics.get_status()
        
        return {
            "timeout": {
                "current": await self._timeout.get_current_timeout(),
                "avg_response": metrics_status["avg_response_time"]
            },
            "retry": {
                "current_interval": await self._retry.get_current_interval(),
                "error_counts": metrics_status["error_counts"]
            },
            "concurrency": {
                "current_limit": await self._concurrency.get_current_limit(),
                "current_concurrent": metrics_status["current_concurrent"],
                "peak_concurrent": metrics_status["peak_concurrent"]
            },
            "metrics": {
                "investigations_completed": metrics_status["investigations_completed"],
                "investigations_failed": metrics_status["investigations_failed"],
                "success_rate": metrics_status["success_rate"],
                "queue_depth": metrics_status["queue_depth"]
            }
        }


async def get_adaptive_system() -> AdaptiveSystem:
    """Get or create global adaptive system instance."""
    if AdaptiveSystem._instance is None:
        async with AdaptiveSystem._lock:
            if AdaptiveSystem._instance is None:
                AdaptiveSystem._instance = AdaptiveSystem()
    return AdaptiveSystem._instance


# Fallback functions for safe usage
async def get_timeout_safe(prompt_length: int, model: str = "qwen3:8b") -> int:
    try:
        adaptive = await get_adaptive_system()
        return await adaptive.timeout.calculate_timeout(prompt_length, model)
    except Exception as e:
        logger.warning("adaptive_timeout_fallback", error=str(e))
        return 180


async def get_retry_decision_safe(inv_id: str, error: Optional[str]) -> tuple[bool, int]:
    try:
        adaptive = await get_adaptive_system()
        return await adaptive.retry.should_retry(inv_id, error)
    except Exception as e:
        logger.warning("adaptive_retry_fallback", error=str(e))
        return True, 30


async def record_response_safe(duration: float, success: bool):
    try:
        adaptive = await get_adaptive_system()
        await adaptive.metrics.record_ollama_response(duration, success)
    except Exception:
        pass


async def record_error_safe(error_type: str):
    try:
        adaptive = await get_adaptive_system()
        await adaptive.metrics.record_error(error_type)
    except Exception:
        pass