"""
Job storage management using Redis

Handles job metadata, progress tracking, and result storage with proper TTL management.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from enum import Enum
import uuid

import redis
from pydantic import BaseModel

from ..models import JobStatus, AnalysisResult, AnalysisProgress
from ..config import RedisManager, redis_config
from ..utils.exceptions import JobNotFoundError, JobStorageError

logger = logging.getLogger(__name__)


class JobStorageKeys:
    """Redis key patterns for job storage"""
    
    # Job metadata and status
    JOB_META = "job:meta:{job_id}"
    JOB_STATUS = "job:status:{job_id}"
    JOB_PROGRESS = "job:progress:{job_id}"
    JOB_RESULT = "job:result:{job_id}"
    JOB_LOCK = "job:lock:{job_id}"
    
    # Job lists and indexes
    JOBS_PENDING = "jobs:pending"
    JOBS_IN_PROGRESS = "jobs:in_progress"
    JOBS_COMPLETED = "jobs:completed"
    JOBS_FAILED = "jobs:failed"
    JOBS_BY_REPOSITORY = "jobs:repo:{owner}:{repo}"
    
    # Cleanup and maintenance
    JOBS_CLEANUP_QUEUE = "jobs:cleanup"
    
    @classmethod
    def job_meta(cls, job_id: str) -> str:
        return cls.JOB_META.format(job_id=job_id)
    
    @classmethod
    def job_status(cls, job_id: str) -> str:
        return cls.JOB_STATUS.format(job_id=job_id)
    
    @classmethod
    def job_progress(cls, job_id: str) -> str:
        return cls.JOB_PROGRESS.format(job_id=job_id)
    
    @classmethod
    def job_result(cls, job_id: str) -> str:
        return cls.JOB_RESULT.format(job_id=job_id)
    
    @classmethod
    def job_lock(cls, job_id: str) -> str:
        return cls.JOB_LOCK.format(job_id=job_id)
    
    @classmethod
    def jobs_by_repository(cls, owner: str, repo: str) -> str:
        return cls.JOBS_BY_REPOSITORY.format(owner=owner, repo=repo)


class JobMetadata(BaseModel):
    """Job metadata model for storage"""
    
    job_id: str
    repository_url: str
    owner: str
    repository: str
    original_url: str
    status: JobStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    worker_id: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    error_message: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None


class JobProgressData(BaseModel):
    """Job progress model for storage"""
    
    job_id: str
    progress_percentage: int = 0
    current_stage: str = "initializing"
    stage_message: str = ""
    stages_completed: List[str] = []
    stages_total: List[str] = []
    updated_at: datetime
    estimated_completion: Optional[datetime] = None


class JobStorage:
    """
    Redis-based job storage manager
    
    Handles all job-related data storage with proper TTL management,
    atomic operations, and error handling.
    """
    
    def __init__(self, redis_manager: RedisManager):
        self.redis_manager = redis_manager
        self.job_client = redis_manager.get_job_queue_client()
        self.result_client = redis_manager.get_result_client()
        self.progress_client = redis_manager.get_progress_client()
        
        # Default TTL values
        self.job_meta_ttl = redis_config.job_result_ttl  # 24 hours
        self.job_progress_ttl = redis_config.job_progress_ttl  # 1 hour
        self.job_lock_ttl = redis_config.job_lock_ttl  # 5 minutes
        
        logger.info("JobStorage initialized with Redis backend")
    
    def create_job(self, repository_url: str, owner: str, repo: str, original_url: str) -> str:
        """
        Create a new job and store its metadata
        
        Args:
            repository_url: Normalized repository URL
            owner: Repository owner
            repo: Repository name
            original_url: Original URL provided by user
            
        Returns:
            Generated job ID
            
        Raises:
            JobStorageError: If job creation fails
        """
        try:
            job_id = str(uuid.uuid4())
            now = datetime.utcnow()
            
            # Create job metadata
            job_meta = JobMetadata(
                job_id=job_id,
                repository_url=repository_url,
                owner=owner,
                repository=repo,
                original_url=original_url,
                status=JobStatus.PENDING,
                created_at=now
            )
            
            # Create initial progress
            progress_data = JobProgressData(
                job_id=job_id,
                progress_percentage=0,
                current_stage="created",
                stage_message=f"Repository {owner}/{repo} queued for analysis",
                stages_total=[
                    "repository_validation",
                    "dependency_scanning", 
                    "vulnerability_lookup",
                    "scoring_calculation",
                    "report_generation"
                ],
                updated_at=now
            )
            
            # Store in Redis with pipeline for atomicity
            pipe = self.job_client.pipeline()
            
            # Store job metadata
            pipe.setex(
                JobStorageKeys.job_meta(job_id),
                self.job_meta_ttl,
                job_meta.json()
            )
            
            # Store job status
            pipe.setex(
                JobStorageKeys.job_status(job_id),
                self.job_meta_ttl,
                JobStatus.PENDING.value
            )
            
            # Add to pending jobs list
            pipe.lpush(JobStorageKeys.JOBS_PENDING, job_id)
            
            # Add to repository-specific job list
            repo_key = JobStorageKeys.jobs_by_repository(owner, repo)
            pipe.lpush(repo_key, job_id)
            pipe.expire(repo_key, self.job_meta_ttl)
            
            # Execute pipeline
            pipe.execute()
            
            # Store progress in separate database
            self.progress_client.setex(
                JobStorageKeys.job_progress(job_id),
                self.job_progress_ttl,
                progress_data.json()
            )
            
            logger.info(f"Created job {job_id} for repository {owner}/{repo}")
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to create job for {owner}/{repo}: {e}")
            raise JobStorageError(f"Failed to create job: {str(e)}")
    
    def get_job_metadata(self, job_id: str) -> JobMetadata:
        """
        Retrieve job metadata
        
        Args:
            job_id: Job identifier
            
        Returns:
            Job metadata
            
        Raises:
            JobNotFoundError: If job doesn't exist
            JobStorageError: If retrieval fails
        """
        try:
            job_data = self.job_client.get(JobStorageKeys.job_meta(job_id))
            if not job_data:
                raise JobNotFoundError(job_id)
            
            return JobMetadata.parse_raw(job_data)
            
        except JobNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to retrieve job metadata for {job_id}: {e}")
            raise JobStorageError(f"Failed to retrieve job metadata: {str(e)}")
    
    def update_job_status(self, job_id: str, status: JobStatus, 
                         worker_id: Optional[str] = None,
                         error_message: Optional[str] = None,
                         error_details: Optional[Dict[str, Any]] = None) -> None:
        """
        Update job status and metadata
        
        Args:
            job_id: Job identifier
            status: New job status
            worker_id: Worker processing the job
            error_message: Error message if status is FAILED
            error_details: Additional error details
            
        Raises:
            JobNotFoundError: If job doesn't exist
            JobStorageError: If update fails
        """
        try:
            # Get current metadata
            job_meta = self.get_job_metadata(job_id)
            
            # Update metadata
            now = datetime.utcnow()
            job_meta.status = status
            
            if status == JobStatus.IN_PROGRESS and not job_meta.started_at:
                job_meta.started_at = now
                job_meta.worker_id = worker_id
            elif status in [JobStatus.COMPLETED, JobStatus.FAILED]:
                job_meta.completed_at = now
                if error_message:
                    job_meta.error_message = error_message
                if error_details:
                    job_meta.error_details = error_details
            
            # Use pipeline for atomic updates
            pipe = self.job_client.pipeline()
            
            # Update metadata
            pipe.setex(
                JobStorageKeys.job_meta(job_id),
                self.job_meta_ttl,
                job_meta.json()
            )
            
            # Update status
            pipe.setex(
                JobStorageKeys.job_status(job_id),
                self.job_meta_ttl,
                status.value
            )
            
            # Move job between status lists
            old_status_key = self._get_status_list_key(job_meta.status)
            new_status_key = self._get_status_list_key(status)
            
            if old_status_key != new_status_key:
                pipe.lrem(old_status_key, 1, job_id)
                pipe.lpush(new_status_key, job_id)
            
            # Execute pipeline
            pipe.execute()
            
            # Record status change in enhanced tracker (if available)
            try:
                from .status_tracker import EnhancedStatusTracker
                tracker = EnhancedStatusTracker(self.redis_manager)
                tracker.record_status_change(
                    job_id=job_id,
                    old_status=job_meta.status,
                    new_status=status,
                    worker_id=worker_id,
                    reason=error_message if status == JobStatus.FAILED else None
                )
            except Exception as e:
                logger.debug(f"Failed to record status change in enhanced tracker: {e}")
            
            logger.info(f"Updated job {job_id} status to {status.value}")
            
        except JobNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to update job status for {job_id}: {e}")
            raise JobStorageError(f"Failed to update job status: {str(e)}")
    
    def update_job_progress(self, job_id: str, progress_percentage: int,
                           current_stage: str, stage_message: str,
                           estimated_completion: Optional[datetime] = None) -> None:
        """
        Update job progress information
        
        Args:
            job_id: Job identifier
            progress_percentage: Completion percentage (0-100)
            current_stage: Current processing stage
            stage_message: Detailed stage message
            estimated_completion: Estimated completion time
            
        Raises:
            JobNotFoundError: If job doesn't exist
            JobStorageError: If update fails
        """
        try:
            # Get current progress or create new
            progress_key = JobStorageKeys.job_progress(job_id)
            current_data = self.progress_client.get(progress_key)
            
            if current_data:
                progress_data = JobProgressData.parse_raw(current_data)
            else:
                # Check if job exists
                self.get_job_metadata(job_id)  # Will raise JobNotFoundError if not found
                
                progress_data = JobProgressData(
                    job_id=job_id,
                    updated_at=datetime.utcnow()
                )
            
            # Update progress data
            progress_data.progress_percentage = max(0, min(100, progress_percentage))
            progress_data.current_stage = current_stage
            progress_data.stage_message = stage_message
            progress_data.updated_at = datetime.utcnow()
            
            if estimated_completion:
                progress_data.estimated_completion = estimated_completion
            
            # Add to completed stages if not already there
            if current_stage not in progress_data.stages_completed:
                # Find previous stage and mark it completed
                if progress_data.stages_total:
                    try:
                        current_index = progress_data.stages_total.index(current_stage)
                        for i in range(current_index):
                            stage = progress_data.stages_total[i]
                            if stage not in progress_data.stages_completed:
                                progress_data.stages_completed.append(stage)
                    except ValueError:
                        pass  # Stage not in predefined list
            
            # Store updated progress
            self.progress_client.setex(
                progress_key,
                self.job_progress_ttl,
                progress_data.json()
            )
            
            logger.debug(f"Updated job {job_id} progress: {progress_percentage}% - {current_stage}")
            
        except JobNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to update job progress for {job_id}: {e}")
            raise JobStorageError(f"Failed to update job progress: {str(e)}")
    
    def get_job_progress(self, job_id: str) -> AnalysisProgress:
        """
        Get job progress information
        
        Args:
            job_id: Job identifier
            
        Returns:
            Analysis progress data
            
        Raises:
            JobNotFoundError: If job doesn't exist
            JobStorageError: If retrieval fails
        """
        try:
            # Get job metadata to verify existence
            job_meta = self.get_job_metadata(job_id)
            
            # Get progress data
            progress_data = self.progress_client.get(JobStorageKeys.job_progress(job_id))
            
            if progress_data:
                progress = JobProgressData.parse_raw(progress_data)
                return AnalysisProgress(
                    job_id=job_id,
                    status=job_meta.status,
                    progress_percentage=progress.progress_percentage,
                    current_stage=progress.current_stage,
                    stage_message=progress.stage_message,
                    started_at=job_meta.started_at or job_meta.created_at,
                    estimated_completion=progress.estimated_completion
                )
            else:
                # Return basic progress from job metadata
                return AnalysisProgress(
                    job_id=job_id,
                    status=job_meta.status,
                    progress_percentage=0 if job_meta.status == JobStatus.PENDING else 100,
                    current_stage="unknown",
                    stage_message="No progress information available",
                    started_at=job_meta.started_at or job_meta.created_at,
                    estimated_completion=None
                )
                
        except JobNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to get job progress for {job_id}: {e}")
            raise JobStorageError(f"Failed to get job progress: {str(e)}")
    
    def store_job_result(self, job_id: str, result: AnalysisResult) -> None:
        """
        Store analysis result
        
        Args:
            job_id: Job identifier
            result: Analysis result data
            
        Raises:
            JobNotFoundError: If job doesn't exist
            JobStorageError: If storage fails
        """
        try:
            # Verify job exists
            self.get_job_metadata(job_id)
            
            # Store result
            self.result_client.setex(
                JobStorageKeys.job_result(job_id),
                self.job_meta_ttl,
                result.json()
            )
            
            logger.info(f"Stored analysis result for job {job_id}")
            
        except JobNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to store job result for {job_id}: {e}")
            raise JobStorageError(f"Failed to store job result: {str(e)}")
    
    def get_job_result(self, job_id: str) -> AnalysisResult:
        """
        Retrieve analysis result
        
        Args:
            job_id: Job identifier
            
        Returns:
            Analysis result
            
        Raises:
            JobNotFoundError: If job or result doesn't exist
            JobStorageError: If retrieval fails
        """
        try:
            # Verify job exists and is completed
            job_meta = self.get_job_metadata(job_id)
            
            if job_meta.status != JobStatus.COMPLETED:
                raise JobStorageError(f"Job {job_id} is not completed (status: {job_meta.status.value})")
            
            # Get result
            result_data = self.result_client.get(JobStorageKeys.job_result(job_id))
            if not result_data:
                raise JobNotFoundError(f"Result not found for job {job_id}")
            
            return AnalysisResult.parse_raw(result_data)
            
        except (JobNotFoundError, JobStorageError):
            raise
        except Exception as e:
            logger.error(f"Failed to get job result for {job_id}: {e}")
            raise JobStorageError(f"Failed to get job result: {str(e)}")
    
    def acquire_job_lock(self, job_id: str, worker_id: str) -> bool:
        """
        Acquire an exclusive lock on a job
        
        Args:
            job_id: Job identifier
            worker_id: Worker identifier
            
        Returns:
            True if lock acquired, False otherwise
        """
        try:
            lock_key = JobStorageKeys.job_lock(job_id)
            result = self.job_client.set(
                lock_key, 
                worker_id, 
                nx=True,  # Only set if key doesn't exist
                ex=self.job_lock_ttl  # Set expiration
            )
            
            if result:
                logger.debug(f"Acquired lock for job {job_id} by worker {worker_id}")
                return True
            else:
                logger.debug(f"Failed to acquire lock for job {job_id} by worker {worker_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error acquiring lock for job {job_id}: {e}")
            return False
    
    def release_job_lock(self, job_id: str, worker_id: str) -> bool:
        """
        Release job lock if owned by worker
        
        Args:
            job_id: Job identifier
            worker_id: Worker identifier
            
        Returns:
            True if lock released, False otherwise
        """
        try:
            lock_key = JobStorageKeys.job_lock(job_id)
            
            # Lua script for atomic check-and-delete
            lua_script = """
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            else
                return 0
            end
            """
            
            result = self.job_client.eval(lua_script, 1, lock_key, worker_id)
            
            if result:
                logger.debug(f"Released lock for job {job_id} by worker {worker_id}")
                return True
            else:
                logger.debug(f"Lock not owned by worker {worker_id} for job {job_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error releasing lock for job {job_id}: {e}")
            return False
    
    def get_jobs_by_status(self, status: JobStatus, limit: int = 100) -> List[str]:
        """
        Get jobs by status
        
        Args:
            status: Job status to filter by
            limit: Maximum number of jobs to return
            
        Returns:
            List of job IDs
        """
        try:
            status_key = self._get_status_list_key(status)
            return self.job_client.lrange(status_key, 0, limit - 1)
        except Exception as e:
            logger.error(f"Error getting jobs by status {status.value}: {e}")
            return []
    
    def cleanup_expired_jobs(self) -> int:
        """
        Clean up expired job data
        
        Returns:
            Number of jobs cleaned up
        """
        cleaned_count = 0
        try:
            # This is a simple cleanup - in production you might want more sophisticated logic
            # For now, we rely on Redis TTL for automatic cleanup
            logger.info("Job cleanup completed (TTL-based)")
            return cleaned_count
        except Exception as e:
            logger.error(f"Error during job cleanup: {e}")
            return cleaned_count
    
    def _get_status_list_key(self, status: JobStatus) -> str:
        """Get Redis key for status-based job list"""
        status_keys = {
            JobStatus.PENDING: JobStorageKeys.JOBS_PENDING,
            JobStatus.IN_PROGRESS: JobStorageKeys.JOBS_IN_PROGRESS,
            JobStatus.COMPLETED: JobStorageKeys.JOBS_COMPLETED,
            JobStatus.FAILED: JobStorageKeys.JOBS_FAILED
        }
        return status_keys.get(status, JobStorageKeys.JOBS_PENDING)
