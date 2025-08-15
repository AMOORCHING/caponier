"""
Enhanced job status tracking and analytics

Provides advanced status tracking capabilities including status history,
transition validation, and analytics for job processing patterns.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass, field

from ..models import JobStatus
from ..config import RedisManager, redis_config
from .job_storage import JobStorageKeys

logger = logging.getLogger(__name__)


class StatusTransition(str, Enum):
    """Valid job status transitions"""
    PENDING_TO_IN_PROGRESS = "pending->in_progress"
    IN_PROGRESS_TO_COMPLETED = "in_progress->completed"
    IN_PROGRESS_TO_FAILED = "in_progress->failed"
    PENDING_TO_FAILED = "pending->failed"  # For validation failures
    FAILED_TO_PENDING = "failed->pending"  # For retries


@dataclass
class StatusHistoryEntry:
    """Individual status change record"""
    job_id: str
    old_status: JobStatus
    new_status: JobStatus
    timestamp: datetime
    worker_id: Optional[str] = None
    reason: Optional[str] = None
    duration_in_previous_status: Optional[int] = None  # seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            "job_id": self.job_id,
            "old_status": self.old_status.value,
            "new_status": self.new_status.value,
            "timestamp": self.timestamp.isoformat(),
            "worker_id": self.worker_id,
            "reason": self.reason,
            "duration_in_previous_status": self.duration_in_previous_status
        }


@dataclass
class JobStatusAnalytics:
    """Job status analytics and metrics"""
    total_jobs: int = 0
    status_counts: Dict[str, int] = field(default_factory=dict)
    average_processing_time: Optional[float] = None
    success_rate: Optional[float] = None
    failure_rate: Optional[float] = None
    pending_queue_depth: int = 0
    worker_utilization: Dict[str, int] = field(default_factory=dict)
    status_transitions: Dict[str, int] = field(default_factory=dict)
    hourly_completion_rate: Dict[str, int] = field(default_factory=dict)


class EnhancedStatusTracker:
    """
    Enhanced status tracking with history and analytics
    
    Provides comprehensive status tracking including:
    - Status transition validation
    - Status change history
    - Processing time analytics
    - Worker performance metrics
    """
    
    def __init__(self, redis_manager: RedisManager):
        self.redis_manager = redis_manager
        self.redis_client = redis_manager.get_job_queue_client()
        
        # Redis keys for enhanced tracking
        self.status_history_key = "jobs:status_history"
        self.analytics_key = "jobs:analytics"
        self.transitions_key = "jobs:transitions"
        
        # TTL for history data (7 days)
        self.history_ttl = 7 * 24 * 3600
        
        # Valid status transitions
        self.valid_transitions = {
            JobStatus.PENDING: [JobStatus.IN_PROGRESS, JobStatus.FAILED],
            JobStatus.IN_PROGRESS: [JobStatus.COMPLETED, JobStatus.FAILED],
            JobStatus.FAILED: [JobStatus.PENDING],  # Allow retry
            JobStatus.COMPLETED: []  # Terminal state
        }
        
        logger.info("EnhancedStatusTracker initialized")
    
    def validate_status_transition(self, job_id: str, old_status: JobStatus, 
                                 new_status: JobStatus) -> bool:
        """
        Validate if a status transition is allowed
        
        Args:
            job_id: Job identifier
            old_status: Current status
            new_status: Desired status
            
        Returns:
            True if transition is valid
        """
        if new_status in self.valid_transitions.get(old_status, []):
            return True
        
        logger.warning(f"Invalid status transition for job {job_id}: {old_status.value} -> {new_status.value}")
        return False
    
    def record_status_change(self, job_id: str, old_status: JobStatus, 
                           new_status: JobStatus, worker_id: Optional[str] = None,
                           reason: Optional[str] = None) -> None:
        """
        Record a status change in the history
        
        Args:
            job_id: Job identifier
            old_status: Previous status
            new_status: New status
            worker_id: Worker making the change
            reason: Reason for the change
        """
        try:
            # Calculate duration in previous status
            duration = self._calculate_status_duration(job_id, old_status)
            
            # Create history entry
            entry = StatusHistoryEntry(
                job_id=job_id,
                old_status=old_status,
                new_status=new_status,
                timestamp=datetime.utcnow(),
                worker_id=worker_id,
                reason=reason,
                duration_in_previous_status=duration
            )
            
            # Store in Redis
            self._store_history_entry(entry)
            
            # Update transition counters
            self._update_transition_counter(old_status, new_status)
            
            logger.debug(f"Recorded status change for job {job_id}: {old_status.value} -> {new_status.value}")
            
        except Exception as e:
            logger.error(f"Failed to record status change for job {job_id}: {e}")
    
    def get_job_status_history(self, job_id: str, limit: int = 50) -> List[StatusHistoryEntry]:
        """
        Get status history for a specific job
        
        Args:
            job_id: Job identifier
            limit: Maximum number of entries to return
            
        Returns:
            List of status history entries
        """
        try:
            # Get history entries for this job
            entries = []
            history_data = self.redis_client.lrange(f"{self.status_history_key}:{job_id}", 0, limit - 1)
            
            for entry_json in history_data:
                try:
                    import json
                    entry_dict = json.loads(entry_json)
                    entry = StatusHistoryEntry(
                        job_id=entry_dict["job_id"],
                        old_status=JobStatus(entry_dict["old_status"]),
                        new_status=JobStatus(entry_dict["new_status"]),
                        timestamp=datetime.fromisoformat(entry_dict["timestamp"]),
                        worker_id=entry_dict.get("worker_id"),
                        reason=entry_dict.get("reason"),
                        duration_in_previous_status=entry_dict.get("duration_in_previous_status")
                    )
                    entries.append(entry)
                except Exception as e:
                    logger.warning(f"Failed to parse history entry: {e}")
            
            return entries
            
        except Exception as e:
            logger.error(f"Failed to get status history for job {job_id}: {e}")
            return []
    
    def get_status_analytics(self, time_window_hours: int = 24) -> JobStatusAnalytics:
        """
        Get status analytics for the specified time window
        
        Args:
            time_window_hours: Hours to look back for analytics
            
        Returns:
            Analytics data
        """
        try:
            analytics = JobStatusAnalytics()
            
            # Get job counts by status
            analytics.status_counts = {
                JobStatus.PENDING.value: self._get_status_count(JobStatus.PENDING),
                JobStatus.IN_PROGRESS.value: self._get_status_count(JobStatus.IN_PROGRESS),
                JobStatus.COMPLETED.value: self._get_status_count(JobStatus.COMPLETED),
                JobStatus.FAILED.value: self._get_status_count(JobStatus.FAILED)
            }
            
            analytics.total_jobs = sum(analytics.status_counts.values())
            analytics.pending_queue_depth = analytics.status_counts[JobStatus.PENDING.value]
            
            # Calculate success/failure rates
            completed = analytics.status_counts[JobStatus.COMPLETED.value]
            failed = analytics.status_counts[JobStatus.FAILED.value]
            total_finished = completed + failed
            
            if total_finished > 0:
                analytics.success_rate = completed / total_finished
                analytics.failure_rate = failed / total_finished
            
            # Get transition statistics
            analytics.status_transitions = self._get_transition_stats()
            
            # Get worker utilization
            analytics.worker_utilization = self._get_worker_utilization()
            
            # Calculate average processing time
            analytics.average_processing_time = self._calculate_average_processing_time(time_window_hours)
            
            # Get hourly completion rates
            analytics.hourly_completion_rate = self._get_hourly_completion_rates(time_window_hours)
            
            return analytics
            
        except Exception as e:
            logger.error(f"Failed to get status analytics: {e}")
            return JobStatusAnalytics()
    
    def get_stuck_jobs(self, timeout_minutes: int = 10) -> List[Dict[str, Any]]:
        """
        Find jobs that appear to be stuck in processing
        
        Args:
            timeout_minutes: Minutes to consider a job stuck
            
        Returns:
            List of potentially stuck jobs
        """
        try:
            stuck_jobs = []
            cutoff_time = datetime.utcnow() - timedelta(minutes=timeout_minutes)
            
            # Get all in-progress jobs
            in_progress_jobs = self.redis_client.lrange(JobStorageKeys.JOBS_IN_PROGRESS, 0, -1)
            
            for job_id in in_progress_jobs:
                if isinstance(job_id, bytes):
                    job_id = job_id.decode('utf-8')
                
                # Get job metadata
                try:
                    job_data = self.redis_client.get(JobStorageKeys.job_meta(job_id))
                    if job_data:
                        import json
                        job_meta = json.loads(job_data)
                        started_at = datetime.fromisoformat(job_meta.get("started_at", datetime.utcnow().isoformat()))
                        
                        if started_at < cutoff_time:
                            stuck_jobs.append({
                                "job_id": job_id,
                                "started_at": started_at.isoformat(),
                                "worker_id": job_meta.get("worker_id"),
                                "repository_url": job_meta.get("repository_url"),
                                "stuck_duration_minutes": int((datetime.utcnow() - started_at).total_seconds() / 60)
                            })
                except Exception as e:
                    logger.warning(f"Failed to check job {job_id} for stuck status: {e}")
            
            return stuck_jobs
            
        except Exception as e:
            logger.error(f"Failed to get stuck jobs: {e}")
            return []
    
    def cleanup_old_history(self, days: int = 7) -> int:
        """
        Clean up old status history entries
        
        Args:
            days: Days of history to keep
            
        Returns:
            Number of entries cleaned up
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(days=days)
            cleaned_count = 0
            
            # This is a simplified cleanup - in production you might want more sophisticated logic
            logger.info(f"Status history cleanup completed (TTL-based)")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup old history: {e}")
            return 0
    
    def _calculate_status_duration(self, job_id: str, old_status: JobStatus) -> Optional[int]:
        """Calculate how long the job was in the previous status"""
        try:
            # Get the last status change time from history
            history = self.get_job_status_history(job_id, limit=1)
            if history:
                last_change = history[0].timestamp
                duration = (datetime.utcnow() - last_change).total_seconds()
                return int(duration)
        except Exception as e:
            logger.debug(f"Could not calculate status duration for job {job_id}: {e}")
        return None
    
    def _store_history_entry(self, entry: StatusHistoryEntry) -> None:
        """Store a history entry in Redis"""
        import json
        
        # Store in job-specific history list
        job_history_key = f"{self.status_history_key}:{entry.job_id}"
        self.redis_client.lpush(job_history_key, json.dumps(entry.to_dict()))
        self.redis_client.expire(job_history_key, self.history_ttl)
        
        # Store in global history (for analytics)
        self.redis_client.lpush(self.status_history_key, json.dumps(entry.to_dict()))
        self.redis_client.expire(self.status_history_key, self.history_ttl)
    
    def _update_transition_counter(self, old_status: JobStatus, new_status: JobStatus) -> None:
        """Update transition counters"""
        transition_key = f"{old_status.value}->{new_status.value}"
        counter_key = f"{self.transitions_key}:{transition_key}"
        self.redis_client.incr(counter_key)
        self.redis_client.expire(counter_key, self.history_ttl)
    
    def _get_status_count(self, status: JobStatus) -> int:
        """Get count of jobs in a specific status"""
        try:
            if status == JobStatus.PENDING:
                return self.redis_client.llen(JobStorageKeys.JOBS_PENDING)
            elif status == JobStatus.IN_PROGRESS:
                return self.redis_client.llen(JobStorageKeys.JOBS_IN_PROGRESS)
            elif status == JobStatus.COMPLETED:
                return self.redis_client.llen(JobStorageKeys.JOBS_COMPLETED)
            elif status == JobStatus.FAILED:
                return self.redis_client.llen(JobStorageKeys.JOBS_FAILED)
        except Exception as e:
            logger.error(f"Failed to get status count for {status.value}: {e}")
        return 0
    
    def _get_transition_stats(self) -> Dict[str, int]:
        """Get transition statistics"""
        try:
            stats = {}
            for transition in StatusTransition:
                counter_key = f"{self.transitions_key}:{transition.value}"
                count = self.redis_client.get(counter_key)
                stats[transition.value] = int(count) if count else 0
            return stats
        except Exception as e:
            logger.error(f"Failed to get transition stats: {e}")
            return {}
    
    def _get_worker_utilization(self) -> Dict[str, int]:
        """Get worker utilization statistics"""
        try:
            utilization = {}
            # This would typically be calculated from active job assignments
            # For now, return a placeholder
            return utilization
        except Exception as e:
            logger.error(f"Failed to get worker utilization: {e}")
            return {}
    
    def _calculate_average_processing_time(self, hours: int) -> Optional[float]:
        """Calculate average processing time for completed jobs"""
        try:
            # This would analyze completed jobs in the time window
            # For now, return a placeholder
            return None
        except Exception as e:
            logger.error(f"Failed to calculate average processing time: {e}")
            return None
    
    def _get_hourly_completion_rates(self, hours: int) -> Dict[str, int]:
        """Get hourly completion rates"""
        try:
            # This would analyze completion patterns by hour
            # For now, return a placeholder
            return {}
        except Exception as e:
            logger.error(f"Failed to get hourly completion rates: {e}")
            return {}
