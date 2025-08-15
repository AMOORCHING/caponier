"""
Comprehensive timeout management for analysis jobs

Provides multiple layers of timeout protection including task-level timeouts,
worker-level monitoring, and system-wide timeout enforcement.
"""

import logging
import asyncio
import signal
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable
from enum import Enum
from dataclasses import dataclass
import threading
import time

from ..models import JobStatus
from ..config import RedisManager, app_config
from ..utils.exceptions import JobTimeoutError, JobError
from .job_storage import JobStorage

logger = logging.getLogger(__name__)


class TimeoutType(str, Enum):
    """Types of timeouts that can occur"""
    TASK_EXECUTION = "task_execution"  # Individual task timeout
    STAGE_TIMEOUT = "stage_timeout"    # Specific analysis stage timeout
    TOTAL_ANALYSIS = "total_analysis"  # Overall analysis timeout
    WORKER_HEARTBEAT = "worker_heartbeat"  # Worker not responding
    QUEUE_WAIT = "queue_wait"          # Job stuck in queue too long


@dataclass
class TimeoutConfig:
    """Configuration for different timeout scenarios"""
    
    # Core analysis timeouts (in seconds)
    total_analysis_timeout: int = 300  # 5 minutes total
    stage_timeout: int = 120  # 2 minutes per stage
    task_soft_timeout: int = 240  # 4 minutes soft limit
    task_hard_timeout: int = 300  # 5 minutes hard limit
    
    # Worker and queue timeouts
    worker_heartbeat_timeout: int = 60  # 1 minute
    queue_wait_timeout: int = 600  # 10 minutes max in queue
    
    # Monitoring intervals
    timeout_check_interval: int = 30  # Check every 30 seconds
    cleanup_interval: int = 300  # Cleanup every 5 minutes
    
    # Grace periods
    graceful_shutdown_grace: int = 30  # 30 seconds to finish gracefully
    force_kill_delay: int = 10  # 10 seconds before force kill


class TimeoutManager:
    """
    Comprehensive timeout management system
    
    Provides multiple layers of timeout protection:
    - Task-level timeouts with graceful shutdown
    - Stage-specific timeouts for analysis phases
    - Worker heartbeat monitoring
    - Queue wait time limits
    - Automatic cleanup of stuck jobs
    """
    
    def __init__(self, redis_manager: RedisManager, config: Optional[TimeoutConfig] = None):
        self.redis_manager = redis_manager
        self.job_storage = JobStorage(redis_manager)
        self.config = config or TimeoutConfig()
        
        # Active timeout monitors
        self.active_monitors: Dict[str, Dict[str, Any]] = {}
        self.monitor_thread: Optional[threading.Thread] = None
        self.should_stop = threading.Event()
        
        # Timeout statistics
        self.timeout_stats = {
            "total_timeouts": 0,
            "timeouts_by_type": {timeout_type.value: 0 for timeout_type in TimeoutType},
            "average_execution_time": 0.0,
            "last_cleanup": datetime.utcnow()
        }
        
        logger.info("TimeoutManager initialized with 5-minute maximum analysis timeout")
    
    def start_monitoring(self) -> None:
        """Start the timeout monitoring thread"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            logger.warning("Timeout monitoring is already running")
            return
        
        self.should_stop.clear()
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Timeout monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop the timeout monitoring thread"""
        self.should_stop.set()
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        logger.info("Timeout monitoring stopped")
    
    def register_job_timeout(self, job_id: str, worker_id: str) -> None:
        """
        Register a job for timeout monitoring
        
        Args:
            job_id: Job identifier
            worker_id: Worker processing the job
        """
        start_time = datetime.utcnow()
        timeout_deadline = start_time + timedelta(seconds=self.config.total_analysis_timeout)
        
        self.active_monitors[job_id] = {
            "worker_id": worker_id,
            "start_time": start_time,
            "timeout_deadline": timeout_deadline,
            "last_heartbeat": start_time,
            "current_stage": "initialization",
            "stage_start_time": start_time,
            "timeout_warnings_sent": 0
        }
        
        logger.info(f"Registered timeout monitoring for job {job_id} (deadline: {timeout_deadline})")
    
    def update_job_heartbeat(self, job_id: str, current_stage: Optional[str] = None) -> None:
        """
        Update job heartbeat to indicate it's still processing
        
        Args:
            job_id: Job identifier
            current_stage: Current processing stage
        """
        if job_id in self.active_monitors:
            now = datetime.utcnow()
            monitor = self.active_monitors[job_id]
            monitor["last_heartbeat"] = now
            
            # Update stage information
            if current_stage and current_stage != monitor["current_stage"]:
                monitor["current_stage"] = current_stage
                monitor["stage_start_time"] = now
                logger.debug(f"Job {job_id} entered stage: {current_stage}")
    
    def unregister_job_timeout(self, job_id: str, reason: str = "completed") -> None:
        """
        Remove job from timeout monitoring
        
        Args:
            job_id: Job identifier
            reason: Reason for unregistering
        """
        if job_id in self.active_monitors:
            monitor = self.active_monitors.pop(job_id)
            execution_time = (datetime.utcnow() - monitor["start_time"]).total_seconds()
            
            # Update statistics
            self._update_execution_stats(execution_time)
            
            logger.info(f"Unregistered timeout monitoring for job {job_id} ({reason}) - execution time: {execution_time:.1f}s")
    
    def check_job_timeout(self, job_id: str) -> Optional[TimeoutType]:
        """
        Check if a specific job has timed out
        
        Args:
            job_id: Job identifier
            
        Returns:
            Type of timeout if occurred, None otherwise
        """
        if job_id not in self.active_monitors:
            return None
        
        monitor = self.active_monitors[job_id]
        now = datetime.utcnow()
        
        # Check total analysis timeout
        if now > monitor["timeout_deadline"]:
            return TimeoutType.TOTAL_ANALYSIS
        
        # Check stage timeout
        stage_elapsed = (now - monitor["stage_start_time"]).total_seconds()
        if stage_elapsed > self.config.stage_timeout:
            return TimeoutType.STAGE_TIMEOUT
        
        # Check worker heartbeat
        heartbeat_elapsed = (now - monitor["last_heartbeat"]).total_seconds()
        if heartbeat_elapsed > self.config.worker_heartbeat_timeout:
            return TimeoutType.WORKER_HEARTBEAT
        
        return None
    
    def handle_job_timeout(self, job_id: str, timeout_type: TimeoutType) -> None:
        """
        Handle a job timeout by taking appropriate action
        
        Args:
            job_id: Job identifier
            timeout_type: Type of timeout that occurred
        """
        try:
            monitor = self.active_monitors.get(job_id, {})
            worker_id = monitor.get("worker_id", "unknown")
            execution_time = (datetime.utcnow() - monitor.get("start_time", datetime.utcnow())).total_seconds()
            
            # Create timeout details
            timeout_details = {
                "timeout_type": timeout_type.value,
                "execution_time_seconds": execution_time,
                "worker_id": worker_id,
                "current_stage": monitor.get("current_stage", "unknown"),
                "timeout_limit_seconds": self.config.total_analysis_timeout
            }
            
            # Update job status to failed
            error_message = self._get_timeout_error_message(timeout_type, execution_time)
            self.job_storage.update_job_status(
                job_id=job_id,
                status=JobStatus.FAILED,
                error_message=error_message,
                error_details=timeout_details
            )
            
            # Record timeout statistics
            self.timeout_stats["total_timeouts"] += 1
            self.timeout_stats["timeouts_by_type"][timeout_type.value] += 1
            
            # Remove from monitoring
            self.unregister_job_timeout(job_id, f"timeout-{timeout_type.value}")
            
            # Try to send termination signal to worker (if applicable)
            self._notify_worker_termination(worker_id, job_id, timeout_type)
            
            logger.error(f"Job {job_id} timed out ({timeout_type.value}) after {execution_time:.1f}s")
            
        except Exception as e:
            logger.error(f"Error handling timeout for job {job_id}: {e}")
    
    def get_timeout_statistics(self) -> Dict[str, Any]:
        """
        Get timeout statistics and monitoring information
        
        Returns:
            Dictionary with timeout statistics
        """
        active_jobs = len(self.active_monitors)
        
        # Calculate average time for active jobs
        current_time = datetime.utcnow()
        active_execution_times = []
        for monitor in self.active_monitors.values():
            execution_time = (current_time - monitor["start_time"]).total_seconds()
            active_execution_times.append(execution_time)
        
        avg_current_execution = sum(active_execution_times) / len(active_execution_times) if active_execution_times else 0
        
        return {
            "active_jobs": active_jobs,
            "timeout_config": {
                "total_analysis_timeout": self.config.total_analysis_timeout,
                "stage_timeout": self.config.stage_timeout,
                "worker_heartbeat_timeout": self.config.worker_heartbeat_timeout
            },
            "statistics": self.timeout_stats.copy(),
            "active_job_average_execution": avg_current_execution,
            "monitoring_status": "active" if self.monitor_thread and self.monitor_thread.is_alive() else "inactive"
        }
    
    def force_timeout_job(self, job_id: str, reason: str = "manual") -> bool:
        """
        Manually force timeout a job
        
        Args:
            job_id: Job identifier
            reason: Reason for manual timeout
            
        Returns:
            True if job was timed out, False if not found
        """
        if job_id not in self.active_monitors:
            return False
        
        try:
            self.handle_job_timeout(job_id, TimeoutType.TASK_EXECUTION)
            logger.info(f"Manually timed out job {job_id}: {reason}")
            return True
        except Exception as e:
            logger.error(f"Error manually timing out job {job_id}: {e}")
            return False
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop that runs in a separate thread"""
        logger.info("Timeout monitoring loop started")
        
        while not self.should_stop.is_set():
            try:
                self._check_all_jobs()
                self._cleanup_orphaned_jobs()
                
                # Wait for next check interval
                self.should_stop.wait(self.config.timeout_check_interval)
                
            except Exception as e:
                logger.error(f"Error in timeout monitoring loop: {e}")
                # Continue monitoring even if there's an error
                time.sleep(10)
        
        logger.info("Timeout monitoring loop stopped")
    
    def _check_all_jobs(self) -> None:
        """Check all monitored jobs for timeouts"""
        jobs_to_timeout = []
        
        for job_id in list(self.active_monitors.keys()):
            timeout_type = self.check_job_timeout(job_id)
            if timeout_type:
                jobs_to_timeout.append((job_id, timeout_type))
        
        # Handle timeouts
        for job_id, timeout_type in jobs_to_timeout:
            self.handle_job_timeout(job_id, timeout_type)
    
    def _cleanup_orphaned_jobs(self) -> None:
        """Clean up jobs that are no longer in the system but still being monitored"""
        try:
            current_time = datetime.utcnow()
            
            # Only run cleanup periodically
            if (current_time - self.timeout_stats["last_cleanup"]).total_seconds() < self.config.cleanup_interval:
                return
            
            orphaned_jobs = []
            
            for job_id in list(self.active_monitors.keys()):
                try:
                    # Check if job still exists and is in progress
                    metadata = self.job_storage.get_job_metadata(job_id)
                    if metadata.status not in [JobStatus.IN_PROGRESS]:
                        orphaned_jobs.append(job_id)
                except Exception:
                    # Job doesn't exist anymore
                    orphaned_jobs.append(job_id)
            
            # Clean up orphaned jobs
            for job_id in orphaned_jobs:
                self.unregister_job_timeout(job_id, "orphaned")
            
            self.timeout_stats["last_cleanup"] = current_time
            
            if orphaned_jobs:
                logger.info(f"Cleaned up {len(orphaned_jobs)} orphaned job monitors")
                
        except Exception as e:
            logger.error(f"Error during orphaned job cleanup: {e}")
    
    def _get_timeout_error_message(self, timeout_type: TimeoutType, execution_time: float) -> str:
        """Generate appropriate error message for timeout type"""
        messages = {
            TimeoutType.TOTAL_ANALYSIS: f"Analysis exceeded maximum time limit of {self.config.total_analysis_timeout} seconds",
            TimeoutType.STAGE_TIMEOUT: f"Analysis stage exceeded {self.config.stage_timeout} second limit",
            TimeoutType.WORKER_HEARTBEAT: f"Worker stopped responding (no heartbeat for {self.config.worker_heartbeat_timeout} seconds)",
            TimeoutType.TASK_EXECUTION: f"Task execution timed out after {execution_time:.1f} seconds",
            TimeoutType.QUEUE_WAIT: f"Job exceeded queue wait time limit of {self.config.queue_wait_timeout} seconds"
        }
        return messages.get(timeout_type, f"Unknown timeout type: {timeout_type.value}")
    
    def _notify_worker_termination(self, worker_id: str, job_id: str, timeout_type: TimeoutType) -> None:
        """Notify worker about job termination (placeholder for future implementation)"""
        # This would implement worker notification/termination logic
        # For now, just log the notification
        logger.info(f"Would notify worker {worker_id} to terminate job {job_id} due to {timeout_type.value}")
    
    def _update_execution_stats(self, execution_time: float) -> None:
        """Update execution time statistics"""
        # Simple moving average calculation
        current_avg = self.timeout_stats["average_execution_time"]
        total_completed = sum(self.timeout_stats["timeouts_by_type"].values()) + 1
        
        if current_avg == 0:
            self.timeout_stats["average_execution_time"] = execution_time
        else:
            # Weighted average
            self.timeout_stats["average_execution_time"] = (
                (current_avg * (total_completed - 1) + execution_time) / total_completed
            )


# Global timeout manager instance
_timeout_manager: Optional[TimeoutManager] = None


def get_timeout_manager(redis_manager: Optional[RedisManager] = None) -> TimeoutManager:
    """Get or create the global timeout manager instance"""
    global _timeout_manager
    
    if _timeout_manager is None:
        if redis_manager is None:
            from ..config import redis_manager as default_redis_manager
            redis_manager = default_redis_manager
        
        _timeout_manager = TimeoutManager(redis_manager)
        _timeout_manager.start_monitoring()
    
    return _timeout_manager


def cleanup_timeout_manager() -> None:
    """Clean up the global timeout manager"""
    global _timeout_manager
    
    if _timeout_manager:
        _timeout_manager.stop_monitoring()
        _timeout_manager = None
