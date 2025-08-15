"""
Job management and coordination

Handles job lifecycle, status tracking, and coordination between API and workers.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import uuid

from ..models import JobStatus, AnalysisResult, AnalysisProgress, AnalysisRequest, AnalysisResponse
from ..config import RedisManager, app_config
from ..utils.exceptions import JobNotFoundError, JobStorageError, JobError
from .job_storage import JobStorage, JobMetadata

logger = logging.getLogger(__name__)


class JobManager:
    """
    High-level job management coordinator
    
    Provides a unified interface for job creation, status tracking,
    and result retrieval. Coordinates between the API layer and
    the underlying storage and worker systems.
    """
    
    def __init__(self, redis_manager: RedisManager):
        self.redis_manager = redis_manager
        self.job_storage = JobStorage(redis_manager)
        
        # Configuration
        self.max_concurrent_jobs = app_config.max_concurrent_jobs
        self.job_timeout = timedelta(minutes=5)  # 5-minute timeout
        
        logger.info("JobManager initialized")
    
    def create_analysis_job(self, request: AnalysisRequest, 
                          normalized_url: str, owner: str, repo: str) -> AnalysisResponse:
        """
        Create a new analysis job
        
        Args:
            request: Analysis request from API
            normalized_url: Validated and normalized repository URL
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Analysis response with job information
            
        Raises:
            JobError: If job creation fails
            JobStorageError: If storage operation fails
        """
        try:
            # Check if we're at concurrent job limit
            if not self._can_accept_new_job():
                raise JobError(
                    "Server is at capacity, please try again later",
                    error_code="SERVER_CAPACITY_EXCEEDED"
                )
            
            # Create the job
            job_id = self.job_storage.create_job(
                repository_url=normalized_url,
                owner=owner,
                repo=repo,
                original_url=request.repository_url
            )
            
            # Calculate estimated duration
            estimated_duration = self._estimate_analysis_duration(owner, repo)
            
            logger.info(f"Created analysis job {job_id} for {owner}/{repo}")
            
            return AnalysisResponse(
                job_id=job_id,
                status=JobStatus.PENDING,
                repository_url=normalized_url,
                estimated_duration=estimated_duration,
                progress_url=f"/analysis/{job_id}/progress",
                result_url=f"/analysis/{job_id}"
            )
            
        except (JobError, JobStorageError):
            raise
        except Exception as e:
            logger.error(f"Unexpected error creating analysis job: {e}")
            raise JobError(f"Failed to create analysis job: {str(e)}")
    
    def get_job_status(self, job_id: str) -> JobStatus:
        """
        Get current job status
        
        Args:
            job_id: Job identifier
            
        Returns:
            Current job status
            
        Raises:
            JobNotFoundError: If job doesn't exist
        """
        try:
            metadata = self.job_storage.get_job_metadata(job_id)
            return metadata.status
        except JobNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Error getting job status for {job_id}: {e}")
            raise JobError(f"Failed to get job status: {str(e)}")
    
    def get_job_progress(self, job_id: str) -> AnalysisProgress:
        """
        Get detailed job progress
        
        Args:
            job_id: Job identifier
            
        Returns:
            Analysis progress information
            
        Raises:
            JobNotFoundError: If job doesn't exist
        """
        try:
            return self.job_storage.get_job_progress(job_id)
        except JobNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Error getting job progress for {job_id}: {e}")
            raise JobError(f"Failed to get job progress: {str(e)}")
    
    def get_job_result(self, job_id: str) -> AnalysisResult:
        """
        Get completed analysis result
        
        Args:
            job_id: Job identifier
            
        Returns:
            Analysis result
            
        Raises:
            JobNotFoundError: If job doesn't exist
            JobError: If job is not completed or result unavailable
        """
        try:
            # Check job status first
            metadata = self.job_storage.get_job_metadata(job_id)
            
            if metadata.status == JobStatus.FAILED:
                error_msg = metadata.error_message or "Analysis failed"
                raise JobError(
                    f"Analysis failed: {error_msg}",
                    job_id=job_id,
                    error_code="ANALYSIS_FAILED"
                )
            elif metadata.status != JobStatus.COMPLETED:
                raise JobError(
                    f"Analysis is still {metadata.status.value}",
                    job_id=job_id,
                    error_code="ANALYSIS_NOT_COMPLETED"
                )
            
            # Get the result
            return self.job_storage.get_job_result(job_id)
            
        except (JobNotFoundError, JobError):
            raise
        except Exception as e:
            logger.error(f"Error getting job result for {job_id}: {e}")
            raise JobError(f"Failed to get job result: {str(e)}")
    
    def update_job_progress(self, job_id: str, progress_percentage: int,
                           current_stage: str, stage_message: str,
                           estimated_completion: Optional[datetime] = None) -> None:
        """
        Update job progress (called by workers)
        
        Args:
            job_id: Job identifier
            progress_percentage: Completion percentage (0-100)
            current_stage: Current processing stage
            stage_message: Detailed stage message
            estimated_completion: Estimated completion time
        """
        try:
            self.job_storage.update_job_progress(
                job_id=job_id,
                progress_percentage=progress_percentage,
                current_stage=current_stage,
                stage_message=stage_message,
                estimated_completion=estimated_completion
            )
        except Exception as e:
            logger.error(f"Error updating job progress for {job_id}: {e}")
            # Don't raise here - progress updates shouldn't fail the job
    
    def start_job_processing(self, job_id: str, worker_id: str) -> bool:
        """
        Mark job as started and assign to worker
        
        Args:
            job_id: Job identifier
            worker_id: Worker identifier
            
        Returns:
            True if job was successfully started, False otherwise
        """
        try:
            # Try to acquire job lock
            if not self.job_storage.acquire_job_lock(job_id, worker_id):
                logger.info(f"Job {job_id} is already locked by another worker")
                return False
            
            # Update job status to in progress
            self.job_storage.update_job_status(
                job_id=job_id,
                status=JobStatus.IN_PROGRESS,
                worker_id=worker_id
            )
            
            # Update progress
            self.update_job_progress(
                job_id=job_id,
                progress_percentage=5,
                current_stage="repository_validation",
                stage_message="Starting repository analysis..."
            )
            
            logger.info(f"Started job {job_id} processing by worker {worker_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error starting job {job_id} processing: {e}")
            # Release lock if we acquired it
            self.job_storage.release_job_lock(job_id, worker_id)
            return False
    
    def complete_job(self, job_id: str, worker_id: str, result: AnalysisResult) -> None:
        """
        Mark job as completed and store result
        
        Args:
            job_id: Job identifier
            worker_id: Worker identifier
            result: Analysis result
        """
        try:
            # Store the result
            self.job_storage.store_job_result(job_id, result)
            
            # Update job status
            self.job_storage.update_job_status(
                job_id=job_id,
                status=JobStatus.COMPLETED
            )
            
            # Final progress update
            self.update_job_progress(
                job_id=job_id,
                progress_percentage=100,
                current_stage="completed",
                stage_message="Analysis completed successfully"
            )
            
            # Release job lock
            self.job_storage.release_job_lock(job_id, worker_id)
            
            logger.info(f"Completed job {job_id} by worker {worker_id}")
            
        except Exception as e:
            logger.error(f"Error completing job {job_id}: {e}")
            # Try to mark as failed
            self.fail_job(job_id, worker_id, f"Error completing job: {str(e)}")
    
    def fail_job(self, job_id: str, worker_id: str, error_message: str,
                error_details: Optional[Dict[str, Any]] = None) -> None:
        """
        Mark job as failed
        
        Args:
            job_id: Job identifier
            worker_id: Worker identifier
            error_message: Error description
            error_details: Additional error details
        """
        try:
            # Update job status
            self.job_storage.update_job_status(
                job_id=job_id,
                status=JobStatus.FAILED,
                error_message=error_message,
                error_details=error_details
            )
            
            # Update progress
            self.update_job_progress(
                job_id=job_id,
                progress_percentage=0,  # Reset progress on failure
                current_stage="failed",
                stage_message=f"Analysis failed: {error_message}"
            )
            
            # Release job lock
            self.job_storage.release_job_lock(job_id, worker_id)
            
            logger.error(f"Failed job {job_id} by worker {worker_id}: {error_message}")
            
        except Exception as e:
            logger.error(f"Error failing job {job_id}: {e}")
    
    def get_pending_jobs(self, limit: int = 10) -> List[str]:
        """
        Get list of pending jobs for worker processing
        
        Args:
            limit: Maximum number of jobs to return
            
        Returns:
            List of job IDs
        """
        try:
            return self.job_storage.get_jobs_by_status(JobStatus.PENDING, limit)
        except Exception as e:
            logger.error(f"Error getting pending jobs: {e}")
            return []
    
    def get_job_metadata(self, job_id: str) -> JobMetadata:
        """
        Get job metadata
        
        Args:
            job_id: Job identifier
            
        Returns:
            Job metadata
        """
        return self.job_storage.get_job_metadata(job_id)
    
    def cleanup_expired_jobs(self) -> int:
        """
        Clean up expired jobs and handle timeouts
        
        Returns:
            Number of jobs cleaned up
        """
        try:
            cleaned_count = 0
            
            # Get jobs that might be stuck in progress
            in_progress_jobs = self.job_storage.get_jobs_by_status(JobStatus.IN_PROGRESS)
            
            for job_id in in_progress_jobs:
                try:
                    metadata = self.job_storage.get_job_metadata(job_id)
                    
                    # Check if job has timed out
                    if metadata.started_at:
                        elapsed = datetime.utcnow() - metadata.started_at
                        if elapsed > self.job_timeout:
                            self.job_storage.update_job_status(
                                job_id=job_id,
                                status=JobStatus.FAILED,
                                error_message="Job timed out",
                                error_details={"timeout_minutes": self.job_timeout.total_seconds() / 60}
                            )
                            cleaned_count += 1
                            logger.info(f"Marked timed-out job {job_id} as failed")
                            
                except Exception as e:
                    logger.error(f"Error checking job {job_id} for timeout: {e}")
            
            # Delegate to storage for additional cleanup
            storage_cleaned = self.job_storage.cleanup_expired_jobs()
            cleaned_count += storage_cleaned
            
            logger.info(f"Cleanup completed: {cleaned_count} jobs processed")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Error during job cleanup: {e}")
            return 0
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get system status information
        
        Returns:
            Dictionary with system status
        """
        try:
            # Get job counts by status
            pending_jobs = len(self.get_pending_jobs(1000))  # Get more for accurate count
            in_progress_jobs = len(self.job_storage.get_jobs_by_status(JobStatus.IN_PROGRESS, 1000))
            
            # Calculate system load
            system_load = (in_progress_jobs / self.max_concurrent_jobs) * 100
            
            return {
                "jobs": {
                    "pending": pending_jobs,
                    "in_progress": in_progress_jobs,
                    "max_concurrent": self.max_concurrent_jobs,
                    "system_load_percent": round(system_load, 1)
                },
                "capacity": {
                    "can_accept_jobs": pending_jobs < self.max_concurrent_jobs * 2,  # Allow some queuing
                    "estimated_wait_time": self._estimate_queue_wait_time(pending_jobs)
                },
                "health": {
                    "redis_connected": True,  # Will be updated with actual health check
                    "workers_active": in_progress_jobs > 0
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {
                "jobs": {"pending": 0, "in_progress": 0, "max_concurrent": self.max_concurrent_jobs},
                "capacity": {"can_accept_jobs": False, "estimated_wait_time": 0},
                "health": {"redis_connected": False, "workers_active": False},
                "error": str(e)
            }
    
    def _can_accept_new_job(self) -> bool:
        """Check if system can accept a new job"""
        try:
            in_progress_count = len(self.job_storage.get_jobs_by_status(JobStatus.IN_PROGRESS, 1000))
            pending_count = len(self.get_pending_jobs(1000))
            
            # Allow some queuing but not unlimited
            total_jobs = in_progress_count + pending_count
            return total_jobs < self.max_concurrent_jobs * 3
            
        except Exception as e:
            logger.error(f"Error checking job capacity: {e}")
            return False
    
    def _estimate_analysis_duration(self, owner: str, repo: str) -> int:
        """
        Estimate analysis duration based on repository characteristics
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Estimated duration in seconds
        """
        # Simple estimation - in production this could be more sophisticated
        # based on repository size, dependency count, etc.
        base_duration = 90  # 1.5 minutes base
        
        # Add some variation based on repo name length (proxy for complexity)
        complexity_factor = min(len(repo) / 10, 2.0)
        
        return int(base_duration * (1 + complexity_factor))
    
    def _estimate_queue_wait_time(self, pending_jobs: int) -> int:
        """
        Estimate wait time for new jobs based on queue length
        
        Args:
            pending_jobs: Number of pending jobs
            
        Returns:
            Estimated wait time in seconds
        """
        if pending_jobs == 0:
            return 0
        
        # Assume average job takes 2 minutes and we can process max_concurrent jobs in parallel
        avg_job_duration = 120  # 2 minutes
        jobs_per_minute = self.max_concurrent_jobs / 2  # Conservative estimate
        
        if jobs_per_minute > 0:
            wait_minutes = pending_jobs / jobs_per_minute
            return int(wait_minutes * 60)
        else:
            return pending_jobs * avg_job_duration
