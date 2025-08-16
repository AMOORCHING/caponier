from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import uuid
import logging
import os
from typing import Dict, Any, List

from .models import (
    AnalysisRequest, 
    AnalysisResponse, 
    AnalysisResult, 
    AnalysisProgress,
    ErrorResponse,
    HealthCheckResponse,
    JobStatus
)
from .utils.validators import validate_repository_url, GitHubURLValidator
from .utils.exceptions import (
    CaponierException, 
    ValidationError, 
    RepositoryError, 
    JobError, 
    AnalysisError, 
    ExternalServiceError,
    get_http_status_code
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Caponier Security Analysis API",
    description="GitHub Repository Security Analysis Platform",
    version="1.0.0"
)

# CORS Configuration for Frontend Integration
def configure_cors():
    """
    Configure CORS middleware for frontend integration
    
    Supports different configurations for development and production environments.
    """
    # Get environment-specific configuration
    environment = os.getenv("ENVIRONMENT", "development")
    
    if environment == "production":
        # Production CORS configuration - restrictive
        allowed_origins = [
            "https://caponier.io",
            "https://www.caponier.io",
            "https://app.caponier.io"
        ]
        # Add any additional production domains from environment variable
        additional_origins = os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
        allowed_origins.extend([origin.strip() for origin in additional_origins if origin.strip()])
        
        cors_config = {
            "allow_origins": allowed_origins,
            "allow_credentials": True,
            "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": [
                "Accept",
                "Accept-Language", 
                "Content-Language",
                "Content-Type",
                "Authorization",
                "X-Requested-With",
                "X-API-Key"
            ],
            "expose_headers": [
                "X-Total-Count",
                "X-Rate-Limit-Remaining", 
                "X-Rate-Limit-Reset"
            ],
            "max_age": 3600  # 1 hour
        }
    else:
        # Development CORS configuration - permissive
        cors_config = {
            "allow_origins": [
                "http://localhost:3000",    # Next.js development server
                "http://localhost:3001",    # Alternative development port
                "http://127.0.0.1:3000",
                "http://127.0.0.1:3001",
                "http://localhost:8080",    # Alternative frontend port
                "http://localhost:8000",    # FastAPI development server
            ],
            "allow_credentials": True,
            "allow_methods": ["*"],  # Allow all methods in development
            "allow_headers": ["*"],  # Allow all headers in development
            "max_age": 600  # 10 minutes for faster development iteration
        }
    
    return cors_config

# Apply CORS middleware
cors_settings = configure_cors()
app.add_middleware(
    CORSMiddleware,
    **cors_settings
)

# Log CORS configuration for debugging
logger.info("CORS Configuration Applied:")
logger.info(f"  Environment: {os.getenv('ENVIRONMENT', 'development')}")
logger.info(f"  Allowed Origins: {cors_settings.get('allow_origins', 'Not specified')}")
logger.info(f"  Allow Credentials: {cors_settings.get('allow_credentials', False)}")
logger.info(f"  Allowed Methods: {cors_settings.get('allow_methods', 'Not specified')}")

# Global exception handler for custom exceptions
@app.exception_handler(CaponierException)
async def caponier_exception_handler(request: Request, exc: CaponierException):
    """
    Global exception handler for all Caponier custom exceptions
    
    Converts structured exceptions to properly formatted HTTP responses
    """
    logger.error(f"Caponier exception: {exc.error_code} - {exc.message}")
    logger.error(f"Exception details: {exc.details}")
    
    return JSONResponse(
        status_code=exc.http_status_code,
        content=exc.to_dict()
    )

# Fallback exception handler for unhandled exceptions
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Fallback handler for unexpected exceptions
    
    Ensures all errors return structured responses
    """
    logger.error(f"Unhandled exception: {type(exc).__name__} - {str(exc)}")
    
    error_response = ErrorResponse(
        error_code="INTERNAL_SERVER_ERROR",
        message="An unexpected error occurred",
        details={"exception_type": type(exc).__name__}
    )
    
    return JSONResponse(
        status_code=500,
        content=error_response.dict()
    )

# Redis and job management configuration
from .config import redis_manager, app_config
from .jobs.job_manager import JobManager

# Initialize job manager with Redis backend
job_manager = JobManager(redis_manager)

@app.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Health check endpoint for monitoring and Kubernetes probes"""
    try:
        # Check Redis health
        redis_health = await redis_manager.health_check()
        redis_status = "healthy" if all(status == "healthy" for status in redis_health.values()) else "unhealthy"
        
        # Get system status
        system_status = job_manager.get_system_status()
        
        dependencies = {
            "redis": redis_status,
            "redis_details": redis_health,
            "nvd_api": "pending",  # Will be updated when NVD integration is added
            "github_api": "pending",  # Will be updated when GitHub client is added
            "cors": "enabled",
            "job_system": "enabled",
            "system_load": f"{system_status.get('jobs', {}).get('system_load_percent', 0)}%"
        }
        
        overall_status = "ok" if redis_status == "healthy" else "degraded"
        
        return HealthCheckResponse(
            status=overall_status,
            service="caponier-api",
            dependencies=dependencies
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthCheckResponse(
            status="error",
            service="caponier-api", 
            dependencies={
                "redis": "error",
                "error": str(e)
        }
    )

@app.options("/{full_path:path}")
async def options_handler(request: Request, full_path: str):
    """
    Handle preflight OPTIONS requests for CORS
    
    This endpoint ensures that all preflight requests are handled properly,
    particularly useful for complex requests from the frontend.
    """
    return JSONResponse(
        status_code=200,
        content={"message": "CORS preflight handled"},
        headers={
            "Access-Control-Allow-Origin": request.headers.get("Origin", "*"),
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, X-API-Key",
            "Access-Control-Max-Age": "3600"
        }
    )

@app.get("/cors-test")
async def cors_test(request: Request):
    """
    Simple endpoint to test CORS configuration from frontend
    
    Returns current CORS settings and request origin for debugging purposes.
    """
    origin = request.headers.get("Origin", "No origin header")
    user_agent = request.headers.get("User-Agent", "No user agent")
    
    return {
        "message": "CORS test successful",
        "timestamp": datetime.utcnow().isoformat(),
        "request_origin": origin,
        "user_agent": user_agent,
        "cors_enabled": True,
        "environment": os.getenv("ENVIRONMENT", "development"),
        "server": "caponier-api"
    }

@app.post("/analyze", response_model=AnalysisResponse)
async def initiate_analysis(
    request: AnalysisRequest, 
    background_tasks: BackgroundTasks
):
    """
    Initiate security analysis for a GitHub repository
    
    This endpoint validates the repository URL and starts an asynchronous
    analysis job that will scan for vulnerabilities and calculate security scores.
    Uses intelligent job queuing to prevent UI blocking and manage concurrency.
    
    The repository URL is automatically validated and normalized through dependency injection.
    """
    try:
        # Import concurrency manager
        from .jobs.concurrency_manager import get_concurrency_manager, JobPriority, WorkerPool
        concurrency_manager = get_concurrency_manager()
        
        # Validate and normalize the repository URL
        normalized_url = await validate_repository_url(request.repository_url)
        owner, repo = GitHubURLValidator.extract_owner_repo(normalized_url)
        
        # Extract user ID if available (for rate limiting)
        user_id = getattr(request, 'user_id', None)
        
        # Check if we can accept the job
        can_accept, reason = concurrency_manager.can_accept_job(user_id, WorkerPool.ANALYSIS)
        
        if not can_accept:
            logger.warning(f"Job rejected for {normalized_url}: {reason}")
            from .utils.exceptions import ResourceLimitError
            raise ResourceLimitError(f"Cannot process analysis request: {reason}. Please try again later.")
        
        logger.info(f"Creating analysis job for repository: {normalized_url}")
        
        # Create job using job manager
        response = job_manager.create_analysis_job(
            request=request,
            normalized_url=normalized_url,
            owner=owner,
            repo=repo
        )
        
        # Queue the job for intelligent processing
        job_queued = concurrency_manager.queue_job(
            job_id=response.job_id,
            task_name="analyze_repository",
            priority=JobPriority.NORMAL,
            worker_pool=WorkerPool.ANALYSIS,
            user_id=user_id,
            estimated_duration=300,  # 5 minutes estimate
            metadata={
                "repository_url": normalized_url,
                "owner": owner,
                "repo": repo
            }
        )
        
        # Schedule background analysis task (non-blocking)
        from .jobs.tasks import schedule_repository_analysis
        schedule_repository_analysis(
            job_id=response.job_id,
            repository_url=normalized_url,
            owner=owner,
            repo=repo
        )
        
        logger.info(f"Analysis job {response.job_id} created and queued for repository: {normalized_url}")
        
        # Enhance response with queue information if job was successfully queued
        if job_queued:
            queue_status = concurrency_manager.get_queue_status()
            queue_position = queue_status["queue_lengths"].get("analysis", 0)
            
            # Add queue info to response (if the model supports it)
            response_dict = response.dict()
            response_dict["queue_info"] = {
                "queued": True,
                "position": queue_position,
                "estimated_start_time": (datetime.utcnow() + timedelta(minutes=queue_position * 2)).isoformat(),
                "concurrent_jobs": queue_status["active_jobs"]
            }
            return response_dict
        
        return response
        
    except CaponierException:
        # Re-raise custom exceptions - they will be handled by the global exception handler
        raise
    except Exception as e:
        logger.error(f"Unexpected error initiating analysis: {str(e)}")
        from .utils.exceptions import AnalysisError
        raise AnalysisError("Failed to initiate repository analysis", stage="initialization", original_error=e)

@app.get("/analysis/{job_id}", response_model=AnalysisResult)
async def get_analysis_result(job_id: str):
    """
    Retrieve completed analysis results for a job
    
    Returns the full analysis report including vulnerabilities, security score,
    and recommendations. Only available for completed jobs.
    """
    try:
        return job_manager.get_job_result(job_id)
            
    except CaponierException:
        # Re-raise custom exceptions - they will be handled by the global exception handler
        raise
    except Exception as e:
        logger.error(f"Error retrieving analysis result for job {job_id}: {str(e)}")
        from .utils.exceptions import JobError
        raise JobError(f"Failed to retrieve analysis results: {str(e)}", job_id=job_id)

@app.get("/analysis/{job_id}/progress", response_model=AnalysisProgress)
async def get_analysis_progress(job_id: str):
    """
    Get real-time progress updates for an analysis job
    
    Returns current status, progress percentage, and detailed stage information.
    This endpoint is polled by the frontend and also complemented by WebSocket updates.
    """
    try:
        return job_manager.get_job_progress(job_id)
        
    except CaponierException:
        # Re-raise custom exceptions - they will be handled by the global exception handler
        raise
    except Exception as e:
        logger.error(f"Error retrieving progress for job {job_id}: {str(e)}")
        from .utils.exceptions import JobError
        raise JobError(f"Failed to retrieve analysis progress: {str(e)}", job_id=job_id)

@app.get("/system/status")
async def get_system_status():
    """
    Get system status and metrics
    
    Returns information about job queue, system load, and capacity.
    Useful for monitoring and load balancing decisions.
    """
    try:
        return job_manager.get_system_status()
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return {
            "error": "Failed to get system status",
            "details": str(e)
        }

@app.post("/system/test-worker")
async def test_worker():
    """
    Test background worker functionality
    
    Schedules a simple test task to verify Celery workers are functioning.
    """
    try:
        from .jobs.tasks import simple_test_task
        
        # Schedule test task
        task_result = simple_test_task.delay("API test request")
        
        return {
            "message": "Test task scheduled successfully",
            "task_id": task_result.id,
            "status": "pending",
            "check_url": f"/system/task-status/{task_result.id}"
        }
    except Exception as e:
        logger.error(f"Error scheduling test task: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to schedule test task: {str(e)}"
        )

@app.get("/system/task-status/{task_id}")
async def get_task_status(task_id: str):
    """
    Get status of a specific Celery task
    
    Args:
        task_id: Celery task identifier
        
    Returns:
        Task status information
    """
    try:
        from .jobs.tasks import get_task_status
        return get_task_status(task_id)
    except Exception as e:
        logger.error(f"Error getting task status for {task_id}: {e}")
        return {
            "task_id": task_id,
            "status": "error",
            "error": str(e)
        }

@app.post("/system/worker-health-check")
async def schedule_worker_health_check():
    """
    Schedule a health check task on workers
    
    Useful for monitoring worker availability and performance.
    """
    try:
        from .jobs.tasks import health_check_task
        
        # Schedule health check task
        task_result = health_check_task.delay()
        
        return {
            "message": "Health check task scheduled",
            "task_id": task_result.id,
            "status": "pending",
            "check_url": f"/system/task-status/{task_result.id}"
        }
    except Exception as e:
        logger.error(f"Error scheduling health check: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to schedule health check: {str(e)}"
        )

@app.get("/system/status-analytics")
async def get_status_analytics(time_window_hours: int = 24):
    """
    Get comprehensive job status analytics
    
    Args:
        time_window_hours: Hours to look back for analytics (default: 24)
        
    Returns:
        Detailed analytics including status counts, success rates, and trends
    """
    try:
        from .jobs.status_tracker import EnhancedStatusTracker
        
        tracker = EnhancedStatusTracker(redis_manager)
        analytics = tracker.get_status_analytics(time_window_hours)
        
        return {
            "analytics": {
                "total_jobs": analytics.total_jobs,
                "status_counts": analytics.status_counts,
                "success_rate": analytics.success_rate,
                "failure_rate": analytics.failure_rate,
                "pending_queue_depth": analytics.pending_queue_depth,
                "worker_utilization": analytics.worker_utilization,
                "status_transitions": analytics.status_transitions,
                "hourly_completion_rate": analytics.hourly_completion_rate,
                "average_processing_time": analytics.average_processing_time
            },
            "time_window_hours": time_window_hours,
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting status analytics: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get status analytics: {str(e)}"
        )

@app.get("/analysis/{job_id}/status-history")
async def get_job_status_history(job_id: str, limit: int = 20):
    """
    Get detailed status history for a specific job
    
    Args:
        job_id: Job identifier
        limit: Maximum number of history entries to return
        
    Returns:
        Status change history with timestamps and details
    """
    try:
        from .jobs.status_tracker import EnhancedStatusTracker
        
        tracker = EnhancedStatusTracker(redis_manager)
        history = tracker.get_job_status_history(job_id, limit)
        
        return {
            "job_id": job_id,
            "status_history": [
                {
                    "old_status": entry.old_status.value,
                    "new_status": entry.new_status.value,
                    "timestamp": entry.timestamp.isoformat(),
                    "worker_id": entry.worker_id,
                    "reason": entry.reason,
                    "duration_in_previous_status": entry.duration_in_previous_status
                }
                for entry in history
            ],
            "total_entries": len(history)
        }
    except Exception as e:
        logger.error(f"Error getting status history for job {job_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get status history: {str(e)}"
        )

@app.get("/system/stuck-jobs")
async def get_stuck_jobs(timeout_minutes: int = 10):
    """
    Find jobs that appear to be stuck in processing
    
    Args:
        timeout_minutes: Minutes to consider a job stuck (default: 10)
        
    Returns:
        List of potentially stuck jobs with details
    """
    try:
        from .jobs.status_tracker import EnhancedStatusTracker
        
        tracker = EnhancedStatusTracker(redis_manager)
        stuck_jobs = tracker.get_stuck_jobs(timeout_minutes)
        
        return {
            "stuck_jobs": stuck_jobs,
            "timeout_minutes": timeout_minutes,
            "total_stuck": len(stuck_jobs),
            "checked_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting stuck jobs: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get stuck jobs: {str(e)}"
        )

@app.get("/system/timeout-statistics")
async def get_timeout_statistics():
    """
    Get comprehensive timeout monitoring statistics
    
    Returns:
        Timeout statistics including active jobs, configuration, and metrics
    """
    try:
        from .jobs.timeout_manager import get_timeout_manager
        
        timeout_manager = get_timeout_manager()
        stats = timeout_manager.get_timeout_statistics()
        
        return {
            "timeout_statistics": stats,
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting timeout statistics: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get timeout statistics: {str(e)}"
        )

@app.post("/system/force-timeout/{job_id}")
async def force_timeout_job(job_id: str, reason: str = "manual"):
    """
    Manually force timeout a specific job
    
    Args:
        job_id: Job identifier to timeout
        reason: Reason for manual timeout
        
    Returns:
        Success status and details
    """
    try:
        from .jobs.timeout_manager import get_timeout_manager
        
        timeout_manager = get_timeout_manager()
        success = timeout_manager.force_timeout_job(job_id, reason)
        
        if success:
            return {
                "message": f"Job {job_id} was successfully timed out",
                "job_id": job_id,
                "reason": reason,
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Job {job_id} not found or not eligible for timeout"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error forcing timeout for job {job_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to force timeout job: {str(e)}"
        )

@app.post("/analysis/{job_id}/share")
async def create_result_share_token(job_id: str):
    """
    Create a share token for analysis results
    
    Args:
        job_id: Job identifier
        
    Returns:
        Share token and sharing information
    """
    try:
        from .jobs.result_storage import EnhancedResultStorage
        
        enhanced_storage = EnhancedResultStorage(redis_manager)
        share_token = enhanced_storage.create_share_token(job_id)
        
        return {
            "job_id": job_id,
            "share_token": share_token,
            "share_url": f"/shared/{share_token}",
            "created_at": datetime.utcnow().isoformat(),
            "expires_in_hours": 24
        }
    except Exception as e:
        logger.error(f"Error creating share token for job {job_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create share token: {str(e)}"
        )

@app.get("/shared/{share_token}")
async def get_shared_result(share_token: str):
    """
    Get analysis result using share token
    
    Args:
        share_token: Share token for the result
        
    Returns:
        Analysis result
    """
    try:
        from .jobs.result_storage import EnhancedResultStorage
        
        enhanced_storage = EnhancedResultStorage(redis_manager)
        result = enhanced_storage.get_result(share_token)
        
        return result
    except Exception as e:
        logger.error(f"Error getting shared result for token {share_token}: {e}")
        raise HTTPException(
            status_code=404,
            detail="Shared result not found or expired"
        )

@app.get("/analysis/{job_id}/result-info")
async def get_result_metadata(job_id: str):
    """
    Get metadata about stored analysis result
    
    Args:
        job_id: Job identifier
        
    Returns:
        Result metadata including storage details
    """
    try:
        from .jobs.result_storage import EnhancedResultStorage
        
        enhanced_storage = EnhancedResultStorage(redis_manager)
        metadata = enhanced_storage.get_result_metadata(job_id)
        
        return {
            "job_id": job_id,
            "storage_format": metadata.storage_format.value,
            "compressed_size": metadata.compressed_size,
            "uncompressed_size": metadata.uncompressed_size,
            "compression_ratio": metadata.compressed_size / metadata.uncompressed_size if metadata.uncompressed_size > 0 else 1.0,
            "stored_at": metadata.stored_at.isoformat(),
            "expires_at": metadata.expires_at.isoformat(),
            "access_level": metadata.access_level.value,
            "share_token": metadata.share_token,
            "access_count": metadata.access_count,
            "last_accessed": metadata.last_accessed.isoformat() if metadata.last_accessed else None,
            "has_checksum": metadata.checksum is not None
        }
    except Exception as e:
        logger.error(f"Error getting result metadata for job {job_id}: {e}")
        raise HTTPException(
            status_code=404,
            detail="Result metadata not found"
        )

@app.get("/system/storage-statistics")
async def get_storage_statistics():
    """
    Get comprehensive storage statistics
    
    Returns:
        Storage statistics including usage and performance metrics
    """
    try:
        from .jobs.result_storage import EnhancedResultStorage
        
        enhanced_storage = EnhancedResultStorage(redis_manager)
        stats = enhanced_storage.get_storage_statistics()
        
        return {
            "storage_statistics": stats,
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting storage statistics: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get storage statistics: {str(e)}"
        )

@app.delete("/analysis/{job_id}/result")
async def delete_result(job_id: str):
    """
    Delete stored analysis result
    
    Args:
        job_id: Job identifier
        
    Returns:
        Deletion status
    """
    try:
        from .jobs.result_storage import EnhancedResultStorage
        
        enhanced_storage = EnhancedResultStorage(redis_manager)
        deleted = enhanced_storage.delete_result(job_id)
        
        if deleted:
            return {
                "message": f"Result for job {job_id} was deleted",
                "job_id": job_id,
                "deleted_at": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Result for job {job_id} not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting result for job {job_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete result: {str(e)}"
        )

@app.get("/system/retry-statistics")
async def get_retry_statistics():
    """
    Get comprehensive retry statistics and analytics
    
    Returns:
        Retry statistics including success rates and failure categories
    """
    try:
        from .jobs.retry_manager import get_retry_manager
        
        retry_manager = get_retry_manager()
        stats = retry_manager.get_retry_statistics()
        
        return {
            "retry_statistics": stats,
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting retry statistics: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get retry statistics: {str(e)}"
        )

@app.get("/analysis/{job_id}/failure-history")
async def get_failure_history(job_id: str):
    """
    Get failure history for a specific job
    
    Args:
        job_id: Job identifier
        
    Returns:
        List of failure records with detailed information
    """
    try:
        from .jobs.retry_manager import get_retry_manager
        
        retry_manager = get_retry_manager()
        failure_history = retry_manager.get_failure_history(job_id)
        
        # Convert failure records to API format
        history_data = []
        for failure in failure_history:
            history_data.append({
                "attempt": failure.attempt,
                "category": failure.category.value,
                "error_type": failure.error_type,
                "error_message": failure.error_message,
                "timestamp": failure.timestamp.isoformat(),
                "stage": failure.stage,
                "worker_id": failure.worker_id,
                "next_retry_at": failure.next_retry_at.isoformat() if failure.next_retry_at else None
            })
        
        return {
            "job_id": job_id,
            "failure_count": len(history_data),
            "failure_history": history_data,
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting failure history for job {job_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get failure history: {str(e)}"
        )

@app.post("/analysis/{job_id}/clear-failures")
async def clear_failure_history(job_id: str):
    """
    Clear failure history for a job (useful for debugging/testing)
    
    Args:
        job_id: Job identifier
        
    Returns:
        Confirmation of cleared history
    """
    try:
        from .jobs.retry_manager import get_retry_manager
        
        retry_manager = get_retry_manager()
        cleared = retry_manager.clear_failure_history(job_id)
        
        if cleared:
            return {
                "message": f"Failure history cleared for job {job_id}",
                "job_id": job_id,
                "cleared_at": datetime.utcnow().isoformat()
            }
        else:
            return {
                "message": f"No failure history found for job {job_id}",
                "job_id": job_id
            }
    except Exception as e:
        logger.error(f"Error clearing failure history for job {job_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to clear failure history: {str(e)}"
        )

@app.get("/system/queue-status")
async def get_queue_status():
    """
    Get comprehensive queue status and concurrency metrics
    
    Returns:
        Queue status including active jobs, pool usage, and queue lengths
    """
    try:
        from .jobs.concurrency_manager import get_concurrency_manager
        
        concurrency_manager = get_concurrency_manager()
        status = concurrency_manager.get_queue_status()
        
        return {
            "queue_status": status,
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting queue status: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get queue status: {str(e)}"
        )

@app.post("/system/queue-cleanup")
async def cleanup_queue():
    """
    Manually trigger queue cleanup for stale jobs
    
    Returns:
        Number of items cleaned up
    """
    try:
        from .jobs.concurrency_manager import get_concurrency_manager
        
        concurrency_manager = get_concurrency_manager()
        cleanup_count = concurrency_manager.cleanup_stale_jobs()
        
        return {
            "message": f"Queue cleanup completed",
            "items_cleaned": cleanup_count,
            "cleaned_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error during queue cleanup: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to cleanup queue: {str(e)}"
        )

@app.get("/system/worker-pools")
async def get_worker_pool_status():
    """
    Get detailed worker pool status and metrics
    
    Returns:
        Worker pool utilization and performance metrics
    """
    try:
        from .jobs.concurrency_manager import get_concurrency_manager
        
        concurrency_manager = get_concurrency_manager()
        queue_status = concurrency_manager.get_queue_status()
        
        return {
            "worker_pools": queue_status["pool_usage"],
            "total_active_jobs": queue_status["active_jobs"],
            "total_queued_jobs": sum(queue_status["queue_lengths"].values()),
            "system_capacity": {
                "max_concurrent": queue_status["max_concurrent"],
                "current_utilization": round(queue_status["active_jobs"] / queue_status["max_concurrent"] * 100, 2)
            },
            "generated_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting worker pool status: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get worker pool status: {str(e)}"
        )

# TODO: Add WebSocket endpoint for real-time progress updates (task 6.0)
# TODO: Add result sharing endpoints (task 8.0)
# TODO: Add security badge generation endpoints (task 8.0)