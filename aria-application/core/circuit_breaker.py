"""
Circuit Breaker Pattern.

Prevents cascade failures when external services (Elasticsearch, OpenSOAR) are unavailable.
Circuit states: closed → open → half-open → closed

Part of the Performance Monitoring System Best Practices.
"""

import asyncio
import time
import structlog
from typing import Callable, Any, Optional
from enum import Enum

logger = structlog.get_logger()


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpen(Exception):
    """Raised when circuit is open and calls are not allowed."""
    pass


class CircuitBreaker:
    """
    Circuit breaker to prevent cascade failures.
    
    Usage:
        cb = CircuitBreaker(failure_threshold=5, timeout_seconds=60)
        
        result = await cb.call(
            lambda: some_async_function(),
            fallback=default_value
        )
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        timeout_seconds: int = 60,
        half_open_max_calls: int = 3,
        name: Optional[str] = None
    ):
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self.half_open_max_calls = half_open_max_calls
        self.name = name
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0
    
    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        if self._state == CircuitState.OPEN:
            # Check if timeout has passed to transition to half-open
            if self._last_failure_time:
                if time.time() - self._last_failure_time > self.timeout_seconds:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
                    logger.info("circuit_breaker_half_open")
        return self._state
    
    def _on_success(self):
        """Handle successful call."""
        if self._state == CircuitState.HALF_OPEN:
            self._half_open_calls += 1
            if self._half_open_calls >= self.half_open_max_calls:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                logger.info("circuit_breaker_closed", name=self.name)
        elif self._state == CircuitState.CLOSED:
            # Reset failure count on success
            self._failure_count = 0
    
    def record_success(self):
        """Public method to record a successful call."""
        self._on_success()
    
    def record_failure(self):
        """Public method to record a failed call."""
        self._on_failure()
    
    def _on_failure(self):
        """Handle failed call."""
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._state == CircuitState.HALF_OPEN:
            # Any failure in half-open goes back to open
            self._state = CircuitState.OPEN
            logger.warning("circuit_breaker_reopened", failures=self._failure_count, name=self.name)
        elif self._state == CircuitState.CLOSED:
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(
                    "circuit_breaker_opened",
                    failures=self._failure_count,
                    threshold=self.failure_threshold,
                    name=self.name
                )
    
    async def call(
        self,
        func: Callable,
        fallback: Any = None,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Async function to call
            fallback: Value to return if circuit is open
            *args, **kwargs: Arguments to pass to func
            
        Returns:
            Result of func, or fallback if circuit is open
        """
        # Check if circuit is open
        if self.state == CircuitState.OPEN:
            if fallback is not None:
                logger.debug("circuit_breaker_open_using_fallback")
                return fallback
            raise CircuitBreakerOpen(
                f"Circuit breaker is open. Failures: {self._failure_count}"
            )
        
        # Try to execute
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            self._on_success()
            return result
            
        except Exception as e:
            self._on_failure()
            logger.warning(
                "circuit_breaker_call_failed",
                state=self.state,
                error=str(e),
                name=self.name
            )
            
            if fallback is not None:
                return fallback
            raise
    
    def reset(self):
        """Manually reset the circuit breaker."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = None
        self._half_open_calls = 0
        logger.info("circuit_breaker_reset", name=self.name)
    
    def get_status(self) -> dict:
        """Get current circuit breaker status."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "last_failure_age_seconds": (
                time.time() - self._last_failure_time 
                if self._last_failure_time else None
            )
        }


# Circuit breakers for different services
elasticsearch_circuit = CircuitBreaker(
    failure_threshold=5,
    timeout_seconds=60,
    name="elasticsearch"
)

opensoar_circuit = CircuitBreaker(
    failure_threshold=3,
    timeout_seconds=30,
    name="opensoar"
)

redis_circuit = CircuitBreaker(
    failure_threshold=3,
    timeout_seconds=30,
    name="redis"
)