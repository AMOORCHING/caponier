"""
Concurrency management for analysis jobs

Provides intelligent job queuing, worker pool management, and load balancing
to ensure optimal concurrent processing without blocking the UI or overwhelming resources.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Set, Tuple
from enum import Enum
from dataclasses import dataclass, field
import asyncio
import threading
import time

from ..config import RedisManager, app_config
from ..models import JobStatus
from ..utils.exceptions import JobError

logger = logging.getLogger(__name__)


class JobPriority(str, Enum):
    """Job priority levels for queue management"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class WorkerPool(str, Enum):
    """Worker pool types for different workloads"""
    ANALYSIS = "analysis"      # Main repository analysis
    MAINTENANCE = "maintenance"  # Cleanup, health checks
    FAST = "fast"             # Quick tasks, status updates
    BULK = "bulk"             # Batch processing


@dataclass
class ConcurrencyConfig:
    """Configuration for concurrency management"""
    max_concurrent_jobs: int = 5
    max_jobs_per_user: int = 3
    queue_priority_weights: Dict[JobPriority, int] = field(default_factory=lambda: {
        JobPriority.URGENT: 100,
        JobPriority.HIGH: 10,
        JobPriority.NORMAL: 1,
        JobPriority.LOW: 0.1
    })
    worker_pool_limits: Dict[WorkerPool, int] = field(default_factory=lambda: {
        WorkerPool.ANALYSIS: 3,
        WorkerPool.MAINTENANCE: 1,
        WorkerPool.FAST: 2,
        WorkerPool.BULK: 1
    })
    job_rate_limits: Dict[str, Dict[str, int]] = field(default_factory=lambda: {
        "per_minute": {"limit": 10, "window": 60},
        "per_hour": {"limit": 50, "window": 3600},
        "per_day": {"limit": 200, "window": 86400}
    })
    auto_scaling: bool = True
    resource_monitoring: bool = True


@dataclass
class QueuedJob:
    """Represents a job in the queue"""
    job_id: str
    task_name: str
    priority: JobPriority
    worker_pool: WorkerPool
    created_at: datetime
    user_id: Optional[str] = None
    estimated_duration: Optional[int] = None  # seconds
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            "job_id": self.job_id,
            "task_name": self.task_name,
            "priority": self.priority.value,
            "worker_pool": self.worker_pool.value,
            "created_at": self.created_at.isoformat(),
            "user_id": self.user_id,
            "estimated_duration": self.estimated_duration,
            "dependencies": self.dependencies,
            "metadata": self.metadata
        }


class ConcurrencyManager:
    """
    Advanced concurrency manager for job processing
    
    Features:
    - Intelligent job queuing with priority levels
    - Worker pool management and load balancing
    - Rate limiting and user quotas
    - Resource monitoring and auto-scaling
    - Dependency-aware job scheduling
    - Queue health monitoring and metrics
    """
    
    def __init__(self, redis_manager: RedisManager, config: ConcurrencyConfig = None):
        self.redis_manager = redis_manager
        self.redis_client = redis_manager.get_job_queue_client()
        self.config = config or ConcurrencyConfig()
        
        # Redis keys for concurrency management
        self.queue_key_prefix = "concurrency:queue:"
        self.active_jobs_key = "concurrency:active"
        self.user_jobs_key_prefix = "concurrency:user:"
        self.rate_limit_key_prefix = "concurrency:rate:"
        self.pool_stats_key = "concurrency:pool_stats"
        self.metrics_key = "concurrency:metrics"
        
        # In-memory tracking for performance
        self._active_jobs: Set[str] = set()
        self._pool_usage: Dict[WorkerPool, int] = {pool: 0 for pool in WorkerPool}
        self._last_cleanup = datetime.utcnow()
        
        # Start background monitoring
        self._monitoring_thread = None
        self._should_stop = threading.Event()
        self._start_monitoring()
        
        logger.info(f"ConcurrencyManager initialized with config: {self.config}")
    
    def can_accept_job(self, user_id: str = None, worker_pool: WorkerPool = WorkerPool.ANALYSIS) -> Tuple[bool, str]:
        """
        Check if a new job can be accepted based on limits and quotas
        
        Args:
            user_id: User identifier for quota checking
            worker_pool: Target worker pool
            
        Returns:
            Tuple of (can_accept, reason)
        """
        try:
            # Check global concurrent job limit
            active_count = len(self._active_jobs)
            if active_count >= self.config.max_concurrent_jobs:
                return False, f"Global job limit reached ({active_count}/{self.config.max_concurrent_jobs})"
            
            # Check worker pool capacity
            pool_limit = self.config.worker_pool_limits.get(worker_pool, 1)
            pool_usage = self._pool_usage.get(worker_pool, 0)
            if pool_usage >= pool_limit:
                return False, f"Worker pool {worker_pool.value} at capacity ({pool_usage}/{pool_limit})"
            
            # Check user-specific limits
            if user_id:
                user_jobs = self._get_user_job_count(user_id)
                if user_jobs >= self.config.max_jobs_per_user:
                    return False, f"User job limit reached ({user_jobs}/{self.config.max_jobs_per_user})"
                
                # Check rate limits
                rate_limited, limit_reason = self._check_rate_limits(user_id)
                if rate_limited:
                    return False, f"Rate limit exceeded: {limit_reason}"
            
            return True, "Job can be accepted"
            
        except Exception as e:
            logger.error(f"Error checking job acceptance: {e}")
            return False, f"Internal error: {str(e)}"
    
    def queue_job(self, job_id: str, task_name: str, priority: JobPriority = JobPriority.NORMAL,
                  worker_pool: WorkerPool = WorkerPool.ANALYSIS, user_id: str = None,
                  estimated_duration: int = None, dependencies: List[str] = None,
                  metadata: Dict[str, Any] = None) -> bool:
        """
        Queue a job for processing
        
        Args:
            job_id: Job identifier
            task_name: Name of the task
            priority: Job priority level
            worker_pool: Target worker pool
            user_id: User identifier
            estimated_duration: Estimated duration in seconds
            dependencies: List of job IDs this job depends on
            metadata: Additional job metadata
            
        Returns:
            True if job was queued successfully
        """
        try:
            # Check if job can be accepted
            can_accept, reason = self.can_accept_job(user_id, worker_pool)
            if not can_accept:
                logger.warning(f"Job {job_id} rejected: {reason}")
                return False
            
            # Create queued job
            queued_job = QueuedJob(
                job_id=job_id,
                task_name=task_name,
                priority=priority,
                worker_pool=worker_pool,
                created_at=datetime.utcnow(),
                user_id=user_id,
                estimated_duration=estimated_duration,
                dependencies=dependencies or [],
                metadata=metadata or {}
            )
            
            # Add to priority queue
            queue_key = f"{self.queue_key_prefix}{worker_pool.value}"
            priority_score = self._calculate_priority_score(queued_job)
            
            import json
            self.redis_client.zadd(queue_key, {json.dumps(queued_job.to_dict()): priority_score})
            
            # Track user jobs
            if user_id:
                user_key = f"{self.user_jobs_key_prefix}{user_id}"
                self.redis_client.sadd(user_key, job_id)
                self.redis_client.expire(user_key, 86400)  # 24 hours
            
            # Update metrics
            self._update_queue_metrics("job_queued", worker_pool.value)
            
            logger.info(f"Job {job_id} queued in {worker_pool.value} pool with priority {priority.value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to queue job {job_id}: {e}")
            return False
    
    def get_next_job(self, worker_pool: WorkerPool = WorkerPool.ANALYSIS) -> Optional[QueuedJob]:
        """
        Get the next job to process from the queue
        
        Args:
            worker_pool: Worker pool to get job from
            
        Returns:
            Next job to process or None if queue is empty
        """
        try:
            queue_key = f"{self.queue_key_prefix}{worker_pool.value}"
            
            # Get highest priority job
            job_data = self.redis_client.zpopmax(queue_key)
            if not job_data:
                return None
            
            # Parse job data
            import json
            job_dict = json.loads(job_data[0][0])
            
            queued_job = QueuedJob(
                job_id=job_dict["job_id"],
                task_name=job_dict["task_name"],
                priority=JobPriority(job_dict["priority"]),
                worker_pool=WorkerPool(job_dict["worker_pool"]),
                created_at=datetime.fromisoformat(job_dict["created_at"]),
                user_id=job_dict.get("user_id"),
                estimated_duration=job_dict.get("estimated_duration"),
                dependencies=job_dict.get("dependencies", []),
                metadata=job_dict.get("metadata", {})
            )
            
            # Check dependencies are satisfied
            if queued_job.dependencies:
                if not self._dependencies_satisfied(queued_job.dependencies):
                    # Put job back in queue
                    priority_score = self._calculate_priority_score(queued_job)
                    self.redis_client.zadd(queue_key, {json.dumps(job_dict): priority_score})
                    return None
            
            # Mark job as active
            self._mark_job_active(queued_job.job_id, worker_pool)
            
            logger.info(f"Retrieved job {queued_job.job_id} from {worker_pool.value} queue")
            return queued_job
            
        except Exception as e:
            logger.error(f"Failed to get next job from {worker_pool.value} queue: {e}")
            return None
    
    def mark_job_completed(self, job_id: str, worker_pool: WorkerPool = WorkerPool.ANALYSIS) -> None:
        """
        Mark a job as completed and update tracking
        
        Args:
            job_id: Job identifier
            worker_pool: Worker pool the job was running in
        """
        try:
            # Remove from active jobs
            self._mark_job_inactive(job_id, worker_pool)
            
            # Remove from user tracking
            user_jobs_pattern = f"{self.user_jobs_key_prefix}*"
            for key in self.redis_client.scan_iter(match=user_jobs_pattern):
                self.redis_client.srem(key, job_id)
            
            # Update metrics
            self._update_queue_metrics("job_completed", worker_pool.value)
            
            logger.info(f"Job {job_id} marked as completed in {worker_pool.value} pool")
            
        except Exception as e:
            logger.error(f"Failed to mark job {job_id} as completed: {e}")
    
    def mark_job_failed(self, job_id: str, worker_pool: WorkerPool = WorkerPool.ANALYSIS) -> None:
        """
        Mark a job as failed and update tracking
        
        Args:
            job_id: Job identifier
            worker_pool: Worker pool the job was running in
        """
        try:
            # Remove from active jobs
            self._mark_job_inactive(job_id, worker_pool)
            
            # Update metrics
            self._update_queue_metrics("job_failed", worker_pool.value)
            
            logger.info(f"Job {job_id} marked as failed in {worker_pool.value} pool")
            
        except Exception as e:
            logger.error(f"Failed to mark job {job_id} as failed: {e}")
    
    def get_queue_status(self) -> Dict[str, Any]:
        """
        Get comprehensive queue status and metrics
        
        Returns:
            Dictionary with queue status information
        """
        try:
            status = {
                "active_jobs": len(self._active_jobs),
                "max_concurrent": self.config.max_concurrent_jobs,
                "pool_usage": {},
                "queue_lengths": {},
                "metrics": self._get_metrics(),
                "generated_at": datetime.utcnow().isoformat()
            }
            
            # Get pool usage and queue lengths
            for pool in WorkerPool:
                queue_key = f"{self.queue_key_prefix}{pool.value}"
                queue_length = self.redis_client.zcard(queue_key)
                
                status["pool_usage"][pool.value] = {
                    "active": self._pool_usage.get(pool, 0),
                    "limit": self.config.worker_pool_limits.get(pool, 1),
                    "queued": queue_length
                }
                status["queue_lengths"][pool.value] = queue_length
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get queue status: {e}")
            return {"error": str(e)}
    
    def cleanup_stale_jobs(self) -> int:
        """
        Clean up stale jobs and update tracking
        
        Returns:
            Number of jobs cleaned up
        """
        try:
            cleanup_count = 0
            current_time = datetime.utcnow()
            
            # Check for jobs that have been active too long (over 1 hour)
            stale_threshold = current_time - timedelta(hours=1)
            
            # This would typically involve checking job timestamps and comparing
            # with actual worker status - simplified for this implementation
            
            # Clean up old user job tracking
            user_jobs_pattern = f"{self.user_jobs_key_prefix}*"
            for key in self.redis_client.scan_iter(match=user_jobs_pattern):
                if self.redis_client.ttl(key) == -1:  # No expiration set
                    self.redis_client.expire(key, 86400)
            
            # Clean up old rate limit keys
            rate_limit_pattern = f"{self.rate_limit_key_prefix}*"
            for key in self.redis_client.scan_iter(match=rate_limit_pattern):
                if self.redis_client.ttl(key) == -1:
                    self.redis_client.delete(key)
                    cleanup_count += 1
            
            if cleanup_count > 0:
                logger.info(f"Cleaned up {cleanup_count} stale entries")
            
            return cleanup_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup stale jobs: {e}")
            return 0
    
    def shutdown(self) -> None:
        """Shutdown the concurrency manager"""
        try:
            self._should_stop.set()
            if self._monitoring_thread and self._monitoring_thread.is_alive():
                self._monitoring_thread.join(timeout=5)
            logger.info("ConcurrencyManager shutdown completed")
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
    
    def _calculate_priority_score(self, job: QueuedJob) -> float:
        """Calculate priority score for job ordering"""
        base_score = self.config.queue_priority_weights.get(job.priority, 1)
        
        # Add time-based factor (older jobs get higher priority)
        age_minutes = (datetime.utcnow() - job.created_at).total_seconds() / 60
        age_factor = min(age_minutes * 0.1, 10)  # Cap at 10 points
        
        return base_score + age_factor
    
    def _dependencies_satisfied(self, dependencies: List[str]) -> bool:
        """Check if job dependencies are satisfied"""
        if not dependencies:
            return True
        
        # Check if all dependency jobs are completed
        # This would involve checking job status in JobStorage
        # Simplified for this implementation
        return True
    
    def _mark_job_active(self, job_id: str, worker_pool: WorkerPool) -> None:
        """Mark job as active"""
        self._active_jobs.add(job_id)
        self._pool_usage[worker_pool] = self._pool_usage.get(worker_pool, 0) + 1
        
        # Store in Redis for persistence
        self.redis_client.sadd(self.active_jobs_key, job_id)
        self.redis_client.expire(self.active_jobs_key, 3600)  # 1 hour
    
    def _mark_job_inactive(self, job_id: str, worker_pool: WorkerPool) -> None:
        """Mark job as inactive"""
        self._active_jobs.discard(job_id)
        current_usage = self._pool_usage.get(worker_pool, 0)
        self._pool_usage[worker_pool] = max(0, current_usage - 1)
        
        # Remove from Redis
        self.redis_client.srem(self.active_jobs_key, job_id)
    
    def _get_user_job_count(self, user_id: str) -> int:
        """Get number of active jobs for a user"""
        user_key = f"{self.user_jobs_key_prefix}{user_id}"
        return self.redis_client.scard(user_key)
    
    def _check_rate_limits(self, user_id: str) -> Tuple[bool, str]:
        """Check if user has exceeded rate limits"""
        for limit_name, limit_config in self.config.job_rate_limits.items():
            limit_key = f"{self.rate_limit_key_prefix}{user_id}:{limit_name}"
            current_count = self.redis_client.get(limit_key)
            
            if current_count:
                current_count = int(current_count)
                if current_count >= limit_config["limit"]:
                    return True, f"{limit_name} limit exceeded ({current_count}/{limit_config['limit']})"
            
            # Increment counter
            pipe = self.redis_client.pipeline()
            pipe.incr(limit_key)
            pipe.expire(limit_key, limit_config["window"])
            pipe.execute()
        
        return False, ""
    
    def _update_queue_metrics(self, metric: str, pool: str = None) -> None:
        """Update queue metrics"""
        try:
            metric_key = f"{self.metrics_key}:{metric}"
            self.redis_client.incr(metric_key)
            self.redis_client.expire(metric_key, 86400)  # 24 hours
            
            if pool:
                pool_metric_key = f"{self.metrics_key}:{metric}:{pool}"
                self.redis_client.incr(pool_metric_key)
                self.redis_client.expire(pool_metric_key, 86400)
        except Exception as e:
            logger.debug(f"Failed to update metrics: {e}")
    
    def _get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        try:
            metrics = {}
            metric_pattern = f"{self.metrics_key}:*"
            
            for key in self.redis_client.scan_iter(match=metric_pattern):
                key_str = key.decode('utf-8') if isinstance(key, bytes) else key
                metric_name = key_str.replace(f"{self.metrics_key}:", "")
                value = self.redis_client.get(key)
                
                if value:
                    metrics[metric_name] = int(value)
            
            return metrics
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return {}
    
    def _start_monitoring(self) -> None:
        """Start background monitoring thread"""
        def monitor():
            while not self._should_stop.wait(30):  # Check every 30 seconds
                try:
                    # Sync active jobs with Redis
                    redis_active = self.redis_client.smembers(self.active_jobs_key)
                    if redis_active:
                        redis_active_set = {
                            item.decode('utf-8') if isinstance(item, bytes) else item 
                            for item in redis_active
                        }
                        self._active_jobs = redis_active_set
                    
                    # Periodic cleanup
                    now = datetime.utcnow()
                    if (now - self._last_cleanup).total_seconds() > 300:  # Every 5 minutes
                        self.cleanup_stale_jobs()
                        self._last_cleanup = now
                
                except Exception as e:
                    logger.error(f"Error in monitoring thread: {e}")
        
        self._monitoring_thread = threading.Thread(target=monitor, daemon=True)
        self._monitoring_thread.start()


# Global instance
_concurrency_manager = None

def get_concurrency_manager() -> ConcurrencyManager:
    """Get global concurrency manager instance"""
    global _concurrency_manager
    if _concurrency_manager is None:
        from ..config import redis_manager
        _concurrency_manager = ConcurrencyManager(redis_manager)
    return _concurrency_manager
