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

# In-memory storage for demo purposes (will be replaced with Redis in task 5.0)
analysis_jobs: Dict[str, Dict[str, Any]] = {}
analysis_results: Dict[str, AnalysisResult] = {}

@app.get("/health", response_model=HealthCheckResponse)
def health_check():
    """Health check endpoint for monitoring and Kubernetes probes"""
    return HealthCheckResponse(
        status="ok", 
        service="caponier-api",
        dependencies={
            "redis": "pending",  # Will be updated when Redis is integrated
            "nvd_api": "pending",  # Will be updated when NVD integration is added
            "github_api": "pending",  # Will be updated when GitHub client is added
            "cors": "enabled"  # CORS is now configured
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
        
        # Generate unique job ID
        job_id = str(uuid.uuid4())
        
        # Create initial job record with validated URL
        job_data = {
            "job_id": job_id,
            "repository_url": normalized_url,
            "owner": owner,
            "repository": repo,
            "original_url": request.repository_url,
            "status": JobStatus.PENDING,
            "created_at": datetime.utcnow(),
            "progress_percentage": 0,
            "current_stage": "Repository validated",
            "stage_message": f"Repository {owner}/{repo} validated and queued for analysis"
        }
        
        # Store job in temporary storage
        analysis_jobs[job_id] = job_data
        
        logger.info(f"Analysis job {job_id} created for repository: {normalized_url}")
        
        # TODO: Add background task when job processing is implemented (task 5.0)
        # background_tasks.add_task(process_repository_analysis, job_id, normalized_url)
        
        # Calculate estimated duration based on typical repository analysis
        estimated_duration = 90  # seconds, will be refined based on repository size
        
        return AnalysisResponse(
            job_id=job_id,
            status=JobStatus.PENDING,
            repository_url=normalized_url,
            estimated_duration=estimated_duration,
            progress_url=f"/analysis/{job_id}/progress",
            result_url=f"/analysis/{job_id}"
        )
        
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
        # Check if job exists
        if job_id not in analysis_jobs:
            from .utils.exceptions import JobNotFoundError
            raise JobNotFoundError(job_id)
        
        job_data = analysis_jobs[job_id]
        
        # Check if analysis is completed
        if job_data["status"] != JobStatus.COMPLETED:
            current_status = job_data["status"]
            if current_status == JobStatus.FAILED:
                error_message = job_data.get("error_message", "Analysis failed")
                from .utils.exceptions import JobProcessingError
                raise JobProcessingError(job_id, "analysis_execution", error_message)
            else:
                from .utils.exceptions import JobError
                raise JobError(
                    f"Analysis is still {current_status.value}",
                    job_id,
                    current_status.value
                )
        
        # Return completed analysis result
        if job_id in analysis_results:
            return analysis_results[job_id]
        else:
            # This shouldn't happen if our system is working correctly
            from .utils.exceptions import AnalysisError
            raise AnalysisError("Analysis completed but results not found", job_id=job_id, stage="result_retrieval")
            
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Error retrieving analysis result for job {job_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=ErrorResponse(
                error_code="RESULT_RETRIEVAL_FAILED",
                message="Failed to retrieve analysis results",
                details={"job_id": job_id, "error": str(e)}
            ).dict()
        )

@app.get("/analysis/{job_id}/progress", response_model=AnalysisProgress)
async def get_analysis_progress(job_id: str):
    """
    Get real-time progress updates for an analysis job
    
    Returns current status, progress percentage, and detailed stage information.
    This endpoint is polled by the frontend and also complemented by WebSocket updates.
    """
    try:
        # Check if job exists
        if job_id not in analysis_jobs:
            from .utils.exceptions import JobNotFoundError
            raise JobNotFoundError(job_id)
        
        job_data = analysis_jobs[job_id]
        
        # Calculate estimated completion time
        estimated_completion = None
        if job_data["status"] == JobStatus.IN_PROGRESS:
            progress = job_data.get("progress_percentage", 0)
            if progress > 0:
                # Rough estimation based on current progress
                elapsed = datetime.utcnow() - job_data["created_at"]
                estimated_total = elapsed.total_seconds() * (100 / progress)
                estimated_completion = job_data["created_at"] + timedelta(seconds=estimated_total)
        
        return AnalysisProgress(
            job_id=job_id,
            status=job_data["status"],
            progress_percentage=job_data.get("progress_percentage", 0),
            current_stage=job_data.get("current_stage", "Unknown"),
            stage_message=job_data.get("stage_message", "No status message available"),
            started_at=job_data["created_at"],
            estimated_completion=estimated_completion
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Error retrieving progress for job {job_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=ErrorResponse(
                error_code="PROGRESS_RETRIEVAL_FAILED",
                message="Failed to retrieve analysis progress",
                details={"job_id": job_id, "error": str(e)}
            ).dict()
        )

# TODO: Add WebSocket endpoint for real-time progress updates (task 6.0)
# TODO: Add result sharing endpoints (task 8.0)
# TODO: Add security badge generation endpoints (task 8.0)