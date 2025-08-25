"""
Advanced retry management for analysis tasks

Provides sophisticated retry logic with exponential backoff, failure classification,
and comprehensive error tracking for robust task processing.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Type
from enum import Enum
from dataclasses import dataclass
import traceback
import time

from celery.exceptions import Retry, WorkerLostError
from ..utils.exceptions import AnalysisError, JobNotFoundError
from ..config import RedisManager

logger = logging.getLogger(__name__)


class FailureCategory(str, Enum):
    """Categories of task failures for different retry strategies"""
    TRANSIENT = "transient"          # Network issues, temporary service unavailable
    RATE_LIMITED = "rate_limited"    # API rate limiting
    RECOVERABLE = "recoverable"      # Partial failures that can be retried
    PERMANENT = "permanent"          # Invalid input, authentication failures
    RESOURCE = "resource"            # Memory/disk/CPU resource issues
    TIMEOUT = "timeout"              # Task timeout
    UNKNOWN = "unknown"              # Unclassified errors


class RetryStrategy(str, Enum):
    """Retry strategy types"""
    EXPONENTIAL = "exponential"      # Exponential backoff
    LINEAR = "linear"                # Linear increase in delays
    FIXED = "fixed"                  # Fixed delay between retries
    IMMEDIATE = "immediate"          # No delay (for transient issues)
    NO_RETRY = "no_retry"           # Don't retry


@dataclass
class RetryConfig:
    """Configuration for retry behavior"""
    max_retries: int = 3
    base_delay: int = 60  # seconds
    max_delay: int = 3600  # 1 hour max
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    jitter: bool = True  # Add randomization to prevent thundering herd
    
    # Category-specific overrides
    category_configs: Dict[FailureCategory, Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.category_configs is None:
            self.category_configs = {
                FailureCategory.TRANSIENT: {"max_retries": 5, "base_delay": 30},
                FailureCategory.RATE_LIMITED: {"max_retries": 3, "base_delay": 300, "strategy": RetryStrategy.EXPONENTIAL},
                FailureCategory.RECOVERABLE: {"max_retries": 3, "base_delay": 120},
                FailureCategory.PERMANENT: {"max_retries": 0, "strategy": RetryStrategy.NO_RETRY},
                FailureCategory.RESOURCE: {"max_retries": 2, "base_delay": 600},
                FailureCategory.TIMEOUT: {"max_retries": 1, "base_delay": 300},
                FailureCategory.UNKNOWN: {"max_retries": 2, "base_delay": 180}
            }


@dataclass
class FailureRecord:
    """Record of a task failure"""
    job_id: str
    task_name: str
    attempt: int
    category: FailureCategory
    error_type: str
    error_message: str
    traceback: str
    timestamp: datetime
    worker_id: Optional[str] = None
    stage: Optional[str] = None
    next_retry_at: Optional[datetime] = None


class ErrorClassifier:
    """Classifies errors into failure categories for appropriate retry logic"""
    
    # Error patterns and their categories
    ERROR_PATTERNS = {
        FailureCategory.TRANSIENT: [
            "Connection refused", "Connection timeout", "Temporary failure",
            "Service unavailable", "502 Bad Gateway", "503 Service Unavailable",
            "504 Gateway Timeout", "TimeoutError", "ConnectTimeout", "ReadTimeout"
        ],
        FailureCategory.RATE_LIMITED: [
            "Rate limit exceeded", "Too many requests", "429", "API limit",
            "Quota exceeded", "Request throttled"
        ],
        FailureCategory.RECOVERABLE: [
            "Partial failure", "Some dependencies failed", "Network error",
            "Database connection lost", "Redis connection failed"
        ],
        FailureCategory.PERMANENT: [
            "Authentication failed", "Invalid token", "Unauthorized", "403 Forbidden",
            "Invalid repository", "Repository not found", "404 Not Found",
            "Invalid URL", "Permission denied", "Access denied"
        ],
        FailureCategory.RESOURCE: [
            "Out of memory", "Disk space", "CPU limit", "Resource exhausted",
            "MemoryError", "DiskQuotaExceeded"
        ],
        FailureCategory.TIMEOUT: [
            "Task timeout", "Execution timeout", "Worker timeout",
            "Analysis timeout", "Processing timeout"
        ]
    }
    
    @classmethod
    def classify_error(cls, error: Exception, error_message: str = None) -> FailureCategory:
        """
        Classify an error into a failure category
        
        Args:
            error: The exception object
            error_message: Optional custom error message
            
        Returns:
            Failure category for the error
        """
        # Use provided message or extract from exception
        message = error_message or str(error)
        error_type = type(error).__name__
        
        # Check error type first
        if isinstance(error, (JobNotFoundError, ValueError)):
            return FailureCategory.PERMANENT
        elif isinstance(error, JobStorageError):
            return FailureCategory.RECOVERABLE
        elif isinstance(error, WorkerLostError):
            return FailureCategory.RESOURCE
        
        # Check message patterns
        message_lower = message.lower()
        for category, patterns in cls.ERROR_PATTERNS.items():
            if any(pattern.lower() in message_lower for pattern in patterns):
                return category
        
        # Check error type patterns
        error_type_lower = error_type.lower()
        for category, patterns in cls.ERROR_PATTERNS.items():
            if any(pattern.lower() in error_type_lower for pattern in patterns):
                return category
        
        # Default to unknown
        return FailureCategory.UNKNOWN


class RetryManager:
    """
    Advanced retry manager for analysis tasks
    
    Provides intelligent retry logic with error classification,
    exponential backoff, and comprehensive failure tracking.
    """
    
    def __init__(self, redis_manager: RedisManager, config: RetryConfig = None):
        self.redis_manager = redis_manager
        self.redis_client = redis_manager.get_job_queue_client()
        self.config = config or RetryConfig()
        
        # Redis keys for tracking
        self.failure_key_prefix = "retry:failures:"
        self.stats_key = "retry:stats"
        self.backoff_key_prefix = "retry:backoff:"
        
        logger.info("RetryManager initialized")
    
    def should_retry(self, job_id: str, error: Exception, attempt: int, 
                    task_name: str = "unknown", stage: str = None) -> Tuple[bool, int]:
        """
        Determine if a task should be retried and calculate delay
        
        Args:
            job_id: Job identifier
            error: The exception that occurred
            attempt: Current attempt number (0-based)
            task_name: Name of the task
            stage: Analysis stage where error occurred
            
        Returns:
            Tuple of (should_retry, delay_seconds)
        """
        try:
            # Classify the error
            category = ErrorClassifier.classify_error(error)
            
            # Get category-specific config
            category_config = self.config.category_configs.get(category, {})
            max_retries = category_config.get("max_retries", self.config.max_retries)
            
            # Check if we should retry
            if attempt >= max_retries:
                logger.info(f"Job {job_id} exceeded max retries ({max_retries}) for category {category.value}")
                self._record_failure(job_id, error, attempt, task_name, category, stage, final=True)
                return False, 0
            
            # Calculate delay
            delay = self._calculate_delay(category, attempt, category_config)
            
            # Record failure
            next_retry_at = datetime.utcnow() + timedelta(seconds=delay)
            self._record_failure(job_id, error, attempt, task_name, category, stage, next_retry_at=next_retry_at)
            
            logger.info(f"Job {job_id} will retry in {delay}s (attempt {attempt + 1}/{max_retries}, category: {category.value})")
            return True, delay
            
        except Exception as e:
            logger.error(f"Error in retry decision for job {job_id}: {e}")
            # Conservative fallback - retry with default config
            if attempt < self.config.max_retries:
                return True, self.config.base_delay
            return False, 0
    
    def get_failure_history(self, job_id: str) -> List[FailureRecord]:
        """
        Get failure history for a job
        
        Args:
            job_id: Job identifier
            
        Returns:
            List of failure records
        """
        try:
            failure_key = f"{self.failure_key_prefix}{job_id}"
            failure_data = self.redis_client.lrange(failure_key, 0, -1)
            
            failures = []
            for data in failure_data:
                try:
                    import json
                    failure_dict = json.loads(data)
                    
                    failure = FailureRecord(
                        job_id=failure_dict["job_id"],
                        task_name=failure_dict["task_name"],
                        attempt=failure_dict["attempt"],
                        category=FailureCategory(failure_dict["category"]),
                        error_type=failure_dict["error_type"],
                        error_message=failure_dict["error_message"],
                        traceback=failure_dict["traceback"],
                        timestamp=datetime.fromisoformat(failure_dict["timestamp"]),
                        worker_id=failure_dict.get("worker_id"),
                        stage=failure_dict.get("stage"),
                        next_retry_at=datetime.fromisoformat(failure_dict["next_retry_at"]) if failure_dict.get("next_retry_at") else None
                    )
                    failures.append(failure)
                except Exception as e:
                    logger.warning(f"Failed to parse failure record: {e}")
                    continue
            
            return failures
            
        except Exception as e:
            logger.error(f"Failed to get failure history for job {job_id}: {e}")
            return []
    
    def get_retry_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive retry statistics
        
        Returns:
            Dictionary with retry statistics
        """
        try:
            stats = self.redis_client.hgetall(self.stats_key)
            
            # Convert byte strings to appropriate types
            cleaned_stats = {}
            for key, value in stats.items():
                key_str = key.decode('utf-8') if isinstance(key, bytes) else key
                value_str = value.decode('utf-8') if isinstance(value, bytes) else value
                
                try:
                    cleaned_stats[key_str] = int(value_str)
                except ValueError:
                    cleaned_stats[key_str] = value_str
            
            # Calculate additional metrics
            total_failures = cleaned_stats.get("total_failures", 0)
            total_retries = cleaned_stats.get("total_retries", 0)
            successful_retries = cleaned_stats.get("successful_retries", 0)
            
            retry_success_rate = (successful_retries / total_retries * 100) if total_retries > 0 else 0
            
            return {
                "total_failures": total_failures,
                "total_retries": total_retries,
                "successful_retries": successful_retries,
                "failed_final": cleaned_stats.get("failed_final", 0),
                "retry_success_rate": round(retry_success_rate, 2),
                "category_breakdown": {
                    category.value: cleaned_stats.get(f"category_{category.value}", 0)
                    for category in FailureCategory
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get retry statistics: {e}")
            return {"error": str(e)}
    
    def clear_failure_history(self, job_id: str) -> bool:
        """
        Clear failure history for a job (called on success)
        
        Args:
            job_id: Job identifier
            
        Returns:
            True if cleared successfully
        """
        try:
            failure_key = f"{self.failure_key_prefix}{job_id}"
            self.redis_client.delete(failure_key)
            logger.debug(f"Cleared failure history for job {job_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to clear failure history for job {job_id}: {e}")
            return False
    
    def _calculate_delay(self, category: FailureCategory, attempt: int, 
                        category_config: Dict[str, Any]) -> int:
        """Calculate retry delay based on strategy and attempt"""
        base_delay = category_config.get("base_delay", self.config.base_delay)
        strategy = RetryStrategy(category_config.get("strategy", self.config.strategy.value))
        max_delay = category_config.get("max_delay", self.config.max_delay)
        
        if strategy == RetryStrategy.IMMEDIATE:
            delay = 0
        elif strategy == RetryStrategy.FIXED:
            delay = base_delay
        elif strategy == RetryStrategy.LINEAR:
            delay = base_delay * (attempt + 1)
        elif strategy == RetryStrategy.EXPONENTIAL:
            delay = base_delay * (2 ** attempt)
        else:  # NO_RETRY
            return 0
        
        # Apply jitter if enabled
        if self.config.jitter and delay > 0:
            import random
            jitter_amount = delay * 0.1  # 10% jitter
            delay += random.uniform(-jitter_amount, jitter_amount)
        
        # Cap at max delay
        delay = min(int(delay), max_delay)
        
        return delay
    
    def _record_failure(self, job_id: str, error: Exception, attempt: int,
                       task_name: str, category: FailureCategory, stage: str = None,
                       next_retry_at: datetime = None, final: bool = False) -> None:
        """Record a failure in Redis for tracking and analytics"""
        try:
            import json
            
            failure_record = FailureRecord(
                job_id=job_id,
                task_name=task_name,
                attempt=attempt,
                category=category,
                error_type=type(error).__name__,
                error_message=str(error),
                traceback=traceback.format_exc(),
                timestamp=datetime.utcnow(),
                stage=stage,
                next_retry_at=next_retry_at
            )
            
            # Store failure record
            failure_key = f"{self.failure_key_prefix}{job_id}"
            self.redis_client.lpush(failure_key, json.dumps({
                "job_id": failure_record.job_id,
                "task_name": failure_record.task_name,
                "attempt": failure_record.attempt,
                "category": failure_record.category.value,
                "error_type": failure_record.error_type,
                "error_message": failure_record.error_message,
                "traceback": failure_record.traceback,
                "timestamp": failure_record.timestamp.isoformat(),
                "stage": failure_record.stage,
                "next_retry_at": failure_record.next_retry_at.isoformat() if failure_record.next_retry_at else None
            }))
            
            # Keep only last 10 failures per job
            self.redis_client.ltrim(failure_key, 0, 9)
            self.redis_client.expire(failure_key, 86400 * 7)  # 7 days
            
            # Update statistics
            pipe = self.redis_client.pipeline()
            pipe.hincrby(self.stats_key, "total_failures", 1)
            pipe.hincrby(self.stats_key, f"category_{category.value}", 1)
            
            if not final:
                pipe.hincrby(self.stats_key, "total_retries", 1)
            else:
                pipe.hincrby(self.stats_key, "failed_final", 1)
            
            pipe.execute()
            
        except Exception as e:
            logger.error(f"Failed to record failure for job {job_id}: {e}")


# Global instance
_retry_manager = None

def get_retry_manager() -> RetryManager:
    """Get global retry manager instance"""
    global _retry_manager
    if _retry_manager is None:
        from ..config import redis_manager
        _retry_manager = RetryManager(redis_manager)
    return _retry_manager
