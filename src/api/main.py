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
    
    The repository URL is automatically validated and normalized through dependency injection.
    """
    try:
        # Validate and normalize the repository URL
        normalized_url = await validate_repository_url(request.repository_url)
        owner, repo = GitHubURLValidator.extract_owner_repo(normalized_url)
        
        logger.info(f"Creating analysis job for repository: {normalized_url}")
        
        # Create job using job manager
        response = job_manager.create_analysis_job(
            request=request,
            normalized_url=normalized_url,
            owner=owner,
            repo=repo
        )
        
        # Schedule background analysis task
        from .jobs.tasks import schedule_repository_analysis
        schedule_repository_analysis(
            job_id=response.job_id,
            repository_url=normalized_url,
            owner=owner,
            repo=repo
        )
        
        logger.info(f"Analysis job {response.job_id} created for repository: {normalized_url}")
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

# TODO: Add WebSocket endpoint for real-time progress updates (task 6.0)
# TODO: Add result sharing endpoints (task 8.0)
# TODO: Add security badge generation endpoints (task 8.0)