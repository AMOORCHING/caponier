"""
Circuit Breaker Pattern Implementation for External Service Resilience

This module provides robust circuit breaker implementations that protect against
cascading failures when external services (GitHub API, NVD API) become unavailable
or degraded. The circuit breaker pattern prevents continuous failures by:

- Monitoring failure rates and response times
- Opening the circuit when failure thresholds are exceeded
- Allowing limited probes to test service recovery
- Automatically recovering when services become healthy

Features:
- Configurable failure thresholds and timeouts
- Automatic recovery detection
- Detailed metrics and monitoring
- Integration with existing retry and rate limiting
- Graceful degradation strategies
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional, Callable, Awaitable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
from collections import deque

from ..utils.exceptions import ExternalServiceError, CircuitBreakerError

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states"""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"           # Circuit open, failing fast
    HALF_OPEN = "half_open" # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior"""
    
    # Failure thresholds
    failure_threshold: int = 5           # Failures to open circuit
    failure_rate_threshold: float = 0.5  # Failure rate (0.0-1.0) to open
    
    # Timing configuration
    timeout_duration: float = 60.0       # Seconds to keep circuit open
    recovery_timeout: float = 30.0       # Timeout for half-open state
    
    # Window configuration
    sliding_window_size: int = 10        # Number of recent calls to track
    minimum_requests: int = 3            # Minimum requests before considering failure rate
    
    # Performance thresholds
    slow_call_duration: float = 5.0      # Seconds to consider a call "slow"
    slow_call_threshold: float = 0.8     # Rate of slow calls to open circuit
    
    # Recovery configuration
    half_open_max_calls: int = 3         # Max calls in half-open state
    success_threshold: int = 2           # Successes needed to close circuit
    
    # Service identification
    service_name: str = "external_service"
    
    def __post_init__(self):
        """Validate configuration parameters"""
        if not 0.0 <= self.failure_rate_threshold <= 1.0:
            raise ValueError("failure_rate_threshold must be between 0.0 and 1.0")
        if not 0.0 <= self.slow_call_threshold <= 1.0:
            raise ValueError("slow_call_threshold must be between 0.0 and 1.0")
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if self.sliding_window_size < self.minimum_requests:
            raise ValueError("sliding_window_size must be >= minimum_requests")


@dataclass
class CallResult:
    """Result of a circuit breaker call"""
    success: bool
    duration: float
    timestamp: datetime
    error: Optional[Exception] = None
    
    @property
    def is_slow(self) -> bool:
        """Check if call was slow based on duration"""
        # This will be set by the circuit breaker based on its config
        return hasattr(self, '_slow_threshold') and self.duration > self._slow_threshold


@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker monitoring"""
    
    # State tracking
    current_state: CircuitState = CircuitState.CLOSED
    state_duration: float = 0.0
    last_state_change: Optional[datetime] = None
    
    # Call statistics
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0  # Calls rejected due to open circuit
    
    # Performance metrics
    average_response_time: float = 0.0
    slow_calls: int = 0
    
    # Window statistics
    recent_calls: deque = field(default_factory=lambda: deque(maxlen=100))
    failure_rate: float = 0.0
    slow_call_rate: float = 0.0
    
    # Error tracking
    last_error: Optional[str] = None
    error_types: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization"""
        return {
            "current_state": self.current_state.value,
            "state_duration_seconds": self.state_duration,
            "last_state_change": self.last_state_change.isoformat() if self.last_state_change else None,
            "total_calls": self.total_calls,
            "successful_calls": self.successful_calls,
            "failed_calls": self.failed_calls,
            "rejected_calls": self.rejected_calls,
            "success_rate": self.successful_calls / max(self.total_calls, 1),
            "failure_rate": self.failure_rate,
            "average_response_time": self.average_response_time,
            "slow_calls": self.slow_calls,
            "slow_call_rate": self.slow_call_rate,
            "recent_calls_count": len(self.recent_calls),
            "last_error": self.last_error,
            "error_types": dict(self.error_types)
        }


class CircuitBreaker:
    """
    Implementation of the Circuit Breaker pattern for external service resilience
    
    The circuit breaker monitors calls to external services and automatically
    opens the circuit when failure thresholds are exceeded, preventing cascade
    failures and allowing services time to recover.
    """
    
    def __init__(self, config: CircuitBreakerConfig):
        """
        Initialize circuit breaker with configuration
        
        Args:
            config: Circuit breaker configuration
        """
        self.config = config
        self.metrics = CircuitBreakerMetrics()
        self._lock = asyncio.Lock()
        self._half_open_calls = 0
        self._last_failure_time: Optional[float] = None
        
        logger.info(f"Initialized circuit breaker for {config.service_name}")
    
    async def call(self, func: Callable[..., Awaitable[Any]], *args, **kwargs) -> Any:
        """
        Execute a function call through the circuit breaker
        
        Args:
            func: Async function to call
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function
            
        Returns:
            Result of function call
            
        Raises:
            CircuitBreakerError: When circuit is open or half-open limit exceeded
            Original exception: When function fails and circuit allows it
        """
        async with self._lock:
            # Check if we should reject the call
            if await self._should_reject_call():
                self.metrics.rejected_calls += 1
                raise CircuitBreakerError(
                    f"Circuit breaker is {self.metrics.current_state.value} for {self.config.service_name}",
                    service=self.config.service_name,
                    circuit_state=self.metrics.current_state.value
                )
            
            # Update state if needed
            await self._update_state()
        
        # Execute the call
        start_time = time.time()
        call_result = None
        
        try:
            result = await func(*args, **kwargs)
            
            # Record successful call
            duration = time.time() - start_time
            call_result = CallResult(
                success=True,
                duration=duration,
                timestamp=datetime.now()
            )
            call_result._slow_threshold = self.config.slow_call_duration
            
            async with self._lock:
                await self._record_call(call_result)
            
            return result
            
        except Exception as e:
            # Record failed call
            duration = time.time() - start_time
            call_result = CallResult(
                success=False,
                duration=duration,
                timestamp=datetime.now(),
                error=e
            )
            call_result._slow_threshold = self.config.slow_call_duration
            
            async with self._lock:
                await self._record_call(call_result)
            
            # Re-raise the original exception
            raise
    
    async def _should_reject_call(self) -> bool:
        """Check if call should be rejected based on current state"""
        if self.metrics.current_state == CircuitState.CLOSED:
            return False
        
        elif self.metrics.current_state == CircuitState.OPEN:
            return True
        
        elif self.metrics.current_state == CircuitState.HALF_OPEN:
            # Allow limited calls in half-open state
            return self._half_open_calls >= self.config.half_open_max_calls
        
        return False
    
    async def _update_state(self):
        """Update circuit breaker state based on current conditions"""
        now = time.time()
        
        if self.metrics.current_state == CircuitState.OPEN:
            # Check if timeout has expired
            if (self._last_failure_time and 
                now - self._last_failure_time >= self.config.timeout_duration):
                await self._transition_to_half_open()
        
        elif self.metrics.current_state == CircuitState.HALF_OPEN:
            # Check if recovery timeout exceeded
            if (self.metrics.last_state_change and
                datetime.now() - self.metrics.last_state_change >= 
                timedelta(seconds=self.config.recovery_timeout)):
                await self._transition_to_open()
    
    async def _record_call(self, call_result: CallResult):
        """Record call result and update metrics"""
        # Add to recent calls window
        self.metrics.recent_calls.append(call_result)
        
        # Update counters
        self.metrics.total_calls += 1
        if call_result.success:
            self.metrics.successful_calls += 1
        else:
            self.metrics.failed_calls += 1
            self._last_failure_time = time.time()
            
            # Track error types
            if call_result.error:
                error_type = type(call_result.error).__name__
                self.metrics.error_types[error_type] = self.metrics.error_types.get(error_type, 0) + 1
                self.metrics.last_error = str(call_result.error)[:200]  # Truncate long errors
        
        # Update performance metrics
        if call_result.is_slow:
            self.metrics.slow_calls += 1
        
        # Calculate response time
        total_duration = sum(call.duration for call in self.metrics.recent_calls)
        self.metrics.average_response_time = total_duration / len(self.metrics.recent_calls)
        
        # Update rates based on sliding window
        await self._update_rates()
        
        # Check state transitions
        await self._check_state_transitions(call_result)
    
    async def _update_rates(self):
        """Update failure and slow call rates based on sliding window"""
        window_calls = list(self.metrics.recent_calls)[-self.config.sliding_window_size:]
        
        if len(window_calls) >= self.config.minimum_requests:
            failed_calls = sum(1 for call in window_calls if not call.success)
            slow_calls = sum(1 for call in window_calls if call.is_slow)
            
            self.metrics.failure_rate = failed_calls / len(window_calls)
            self.metrics.slow_call_rate = slow_calls / len(window_calls)
        else:
            self.metrics.failure_rate = 0.0
            self.metrics.slow_call_rate = 0.0
    
    async def _check_state_transitions(self, call_result: CallResult):
        """Check if state transition is needed based on call result"""
        if self.metrics.current_state == CircuitState.CLOSED:
            # Check if we should open the circuit
            should_open = False
            
            # Check failure count threshold
            recent_failures = sum(1 for call in list(self.metrics.recent_calls)[-self.config.failure_threshold:] 
                                 if not call.success)
            if recent_failures >= self.config.failure_threshold:
                should_open = True
                logger.warning(f"Opening circuit for {self.config.service_name}: {recent_failures} consecutive failures")
            
            # Check failure rate threshold
            elif (len(self.metrics.recent_calls) >= self.config.minimum_requests and
                  self.metrics.failure_rate >= self.config.failure_rate_threshold):
                should_open = True
                logger.warning(f"Opening circuit for {self.config.service_name}: failure rate {self.metrics.failure_rate:.2%}")
            
            # Check slow call rate threshold
            elif (len(self.metrics.recent_calls) >= self.config.minimum_requests and
                  self.metrics.slow_call_rate >= self.config.slow_call_threshold):
                should_open = True
                logger.warning(f"Opening circuit for {self.config.service_name}: slow call rate {self.metrics.slow_call_rate:.2%}")
            
            if should_open:
                await self._transition_to_open()
        
        elif self.metrics.current_state == CircuitState.HALF_OPEN:
            self._half_open_calls += 1
            
            if call_result.success:
                # Count successful calls in half-open state
                recent_successes = sum(1 for call in list(self.metrics.recent_calls)[-self.config.success_threshold:]
                                     if call.success)
                if recent_successes >= self.config.success_threshold:
                    await self._transition_to_closed()
            else:
                # Any failure in half-open state opens the circuit
                await self._transition_to_open()
    
    async def _transition_to_open(self):
        """Transition circuit to open state"""
        old_state = self.metrics.current_state
        self.metrics.current_state = CircuitState.OPEN
        self.metrics.last_state_change = datetime.now()
        self._half_open_calls = 0
        
        logger.warning(f"Circuit breaker OPENED for {self.config.service_name} (was {old_state.value})")
    
    async def _transition_to_half_open(self):
        """Transition circuit to half-open state"""
        old_state = self.metrics.current_state
        self.metrics.current_state = CircuitState.HALF_OPEN
        self.metrics.last_state_change = datetime.now()
        self._half_open_calls = 0
        
        logger.info(f"Circuit breaker HALF-OPEN for {self.config.service_name} (was {old_state.value})")
    
    async def _transition_to_closed(self):
        """Transition circuit to closed state"""
        old_state = self.metrics.current_state
        self.metrics.current_state = CircuitState.CLOSED
        self.metrics.last_state_change = datetime.now()
        self._half_open_calls = 0
        
        logger.info(f"Circuit breaker CLOSED for {self.config.service_name} (was {old_state.value})")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current circuit breaker metrics"""
        # Update state duration
        if self.metrics.last_state_change:
            self.metrics.state_duration = (datetime.now() - self.metrics.last_state_change).total_seconds()
        
        return self.metrics.to_dict()
    
    async def force_open(self):
        """Manually open the circuit (for testing/maintenance)"""
        async with self._lock:
            await self._transition_to_open()
            logger.warning(f"Circuit breaker MANUALLY OPENED for {self.config.service_name}")
    
    async def force_close(self):
        """Manually close the circuit (for testing/recovery)"""
        async with self._lock:
            await self._transition_to_closed()
            logger.info(f"Circuit breaker MANUALLY CLOSED for {self.config.service_name}")
    
    async def reset_metrics(self):
        """Reset circuit breaker metrics (keep current state)"""
        async with self._lock:
            current_state = self.metrics.current_state
            last_state_change = self.metrics.last_state_change
            
            self.metrics = CircuitBreakerMetrics()
            self.metrics.current_state = current_state
            self.metrics.last_state_change = last_state_change
            self._half_open_calls = 0
            
            logger.info(f"Reset metrics for circuit breaker {self.config.service_name}")


class CircuitBreakerRegistry:
    """
    Registry for managing multiple circuit breakers
    
    Provides centralized management of circuit breakers for different services
    with shared configuration and monitoring capabilities.
    """
    
    def __init__(self):
        """Initialize empty circuit breaker registry"""
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = asyncio.Lock()
    
    async def get_breaker(self, service_name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """
        Get or create circuit breaker for service
        
        Args:
            service_name: Name of the service
            config: Optional configuration (uses default if not provided)
            
        Returns:
            Circuit breaker instance
        """
        async with self._lock:
            if service_name not in self._breakers:
                if config is None:
                    config = CircuitBreakerConfig(service_name=service_name)
                
                self._breakers[service_name] = CircuitBreaker(config)
                logger.info(f"Created circuit breaker for service: {service_name}")
            
            return self._breakers[service_name]
    
    async def call_with_breaker(
        self, 
        service_name: str, 
        func: Callable[..., Awaitable[Any]], 
        *args, 
        config: Optional[CircuitBreakerConfig] = None,
        **kwargs
    ) -> Any:
        """
        Execute function call with circuit breaker protection
        
        Args:
            service_name: Name of the service
            func: Function to call
            *args: Function arguments
            config: Optional circuit breaker configuration
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
        """
        breaker = await self.get_breaker(service_name, config)
        return await breaker.call(func, *args, **kwargs)
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all circuit breakers"""
        return {name: breaker.get_metrics() for name, breaker in self._breakers.items()}
    
    async def force_open_all(self):
        """Open all circuit breakers (emergency use)"""
        async with self._lock:
            for breaker in self._breakers.values():
                await breaker.force_open()
    
    async def reset_all_metrics(self):
        """Reset metrics for all circuit breakers"""
        async with self._lock:
            for breaker in self._breakers.values():
                await breaker.reset_metrics()


# Global circuit breaker registry
_global_registry = CircuitBreakerRegistry()


async def get_circuit_breaker(service_name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
    """Get circuit breaker from global registry"""
    return await _global_registry.get_breaker(service_name, config)


async def call_with_circuit_breaker(
    service_name: str,
    func: Callable[..., Awaitable[Any]], 
    *args,
    config: Optional[CircuitBreakerConfig] = None,
    **kwargs
) -> Any:
    """Convenience function to call function with circuit breaker protection"""
    return await _global_registry.call_with_breaker(service_name, func, *args, config=config, **kwargs)


def get_all_circuit_breaker_metrics() -> Dict[str, Dict[str, Any]]:
    """Get metrics for all circuit breakers in global registry"""
    return _global_registry.get_all_metrics()
