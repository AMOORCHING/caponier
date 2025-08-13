"""
Custom exception classes for Caponier security analysis API

This module defines structured exceptions that provide detailed error information
for different types of analysis failures and API errors.
"""

from typing import Optional, Dict, Any
from datetime import datetime


class CaponierException(Exception):
    """
    Base exception class for all Caponier-specific errors
    
    Provides structured error information that can be easily converted
    to API error responses.
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: str = "CAPONIER_ERROR",
        details: Optional[Dict[str, Any]] = None,
        http_status_code: int = 500
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.http_status_code = http_status_code
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API response"""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }


class ValidationError(CaponierException):
    """
    Raised when input validation fails
    
    Used for repository URL validation, job ID validation, 
    and other input parameter validation errors.
    """
    
    def __init__(self, message: str, field_name: str = None, field_value: Any = None):
        details = {}
        if field_name:
            details["field"] = field_name
        if field_value is not None:
            details["value"] = str(field_value)
        
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            details=details,
            http_status_code=422
        )


class RepositoryError(CaponierException):
    """
    Raised when repository-related operations fail
    
    Includes repository not found, access denied, invalid format,
    and other repository-specific errors.
    """
    
    def __init__(self, message: str, repository_url: str = None, github_response: Dict[str, Any] = None):
        details = {}
        if repository_url:
            details["repository_url"] = repository_url
        if github_response:
            details["github_response"] = github_response
        
        super().__init__(
            message=message,
            error_code="REPOSITORY_ERROR",
            details=details,
            http_status_code=422
        )


class RepositoryNotFoundError(RepositoryError):
    """Repository does not exist or is not accessible"""
    
    def __init__(self, repository_url: str, suggestion: Optional[str] = None):
        message = f"Repository not found: {repository_url}"
        if suggestion:
            message += f". {suggestion}"
        
        super().__init__(
            message=message,
            repository_url=repository_url
        )
        self.error_code = "REPOSITORY_NOT_FOUND"
        self.http_status_code = 404
        if suggestion:
            self.details["suggestion"] = suggestion


class RepositoryAccessDeniedError(RepositoryError):
    """Access to repository is denied (rate limited or private)"""
    
    def __init__(self, repository_url: str, reason: str = "Access denied", access_type: str = "unknown"):
        super().__init__(
            message=f"Repository access denied: {reason}",
            repository_url=repository_url
        )
        self.error_code = "REPOSITORY_ACCESS_DENIED"
        self.http_status_code = 403
        self.details["access_type"] = access_type


class RepositoryPrivateError(RepositoryError):
    """Repository is private and requires authentication or permissions"""
    
    def __init__(self, repository_url: str, has_token: bool = False):
        if has_token:
            message = f"Repository is private and your token does not have access: {repository_url}"
            suggestion = "Ensure your GitHub token has access to this private repository"
        else:
            message = f"Repository is private and requires authentication: {repository_url}"
            suggestion = "Provide a GitHub token with access to private repositories"
        
        super().__init__(
            message=message,
            repository_url=repository_url
        )
        self.error_code = "REPOSITORY_PRIVATE"
        self.http_status_code = 403
        self.details["has_token"] = has_token
        self.details["suggestion"] = suggestion


class InvalidRepositoryURLError(CaponierException):
    """Repository URL is malformed or invalid"""
    
    def __init__(self, repository_url: str, reason: str, suggestion: Optional[str] = None):
        message = f"Invalid repository URL: {reason}"
        if suggestion:
            message += f". {suggestion}"
        
        details = {
            "repository_url": repository_url,
            "field": "repository_url"
        }
        if suggestion:
            details["suggestion"] = suggestion
        
        super().__init__(
            message=message,
            error_code="INVALID_REPOSITORY_URL",
            details=details,
            http_status_code=400
        )


class AnalysisError(CaponierException):
    """
    Raised when security analysis operations fail
    
    Covers dependency parsing failures, vulnerability scanning errors,
    and scoring calculation problems.
    """
    
    def __init__(self, message: str, job_id: str = None, stage: str = None, original_error: Exception = None):
        details = {}
        if job_id:
            details["job_id"] = job_id
        if stage:
            details["analysis_stage"] = stage
        if original_error:
            details["original_error"] = str(original_error)
            details["error_type"] = type(original_error).__name__
        
        super().__init__(
            message=message,
            error_code="ANALYSIS_ERROR",
            details=details,
            http_status_code=500
        )


class DependencyParsingError(AnalysisError):
    """Failed to parse dependency files from repository"""
    
    def __init__(self, file_path: str, parsing_error: str, ecosystem: str = None):
        details = {
            "file_path": file_path,
            "parsing_error": parsing_error
        }
        if ecosystem:
            details["ecosystem"] = ecosystem
        
        super().__init__(
            message=f"Failed to parse dependency file: {file_path}",
            stage="dependency_parsing"
        )
        self.error_code = "DEPENDENCY_PARSING_ERROR"
        self.details.update(details)


class VulnerabilityLookupError(AnalysisError):
    """Failed to look up vulnerabilities from external sources"""
    
    def __init__(self, package_name: str, package_version: str = None, nvd_error: str = None):
        details = {
            "package_name": package_name,
        }
        if package_version:
            details["package_version"] = package_version
        if nvd_error:
            details["nvd_error"] = nvd_error
        
        super().__init__(
            message=f"Failed to lookup vulnerabilities for package: {package_name}",
            stage="vulnerability_scanning"
        )
        self.error_code = "VULNERABILITY_LOOKUP_ERROR"
        self.details.update(details)


class ScoringError(AnalysisError):
    """Failed to calculate security scores"""
    
    def __init__(self, calculation_type: str, calculation_error: str):
        details = {
            "calculation_type": calculation_type,
            "calculation_error": calculation_error
        }
        
        super().__init__(
            message=f"Failed to calculate security score: {calculation_type}",
            stage="security_scoring"
        )
        self.error_code = "SCORING_ERROR"
        self.details.update(details)


class JobError(CaponierException):
    """
    Raised when job management operations fail
    
    Includes job not found, job timeout, job processing errors,
    and job state management issues.
    """
    
    def __init__(self, message: str, job_id: str, job_status: str = None):
        details = {"job_id": job_id}
        if job_status:
            details["job_status"] = job_status
        
        super().__init__(
            message=message,
            error_code="JOB_ERROR",
            details=details,
            http_status_code=422
        )


class JobNotFoundError(JobError):
    """Analysis job does not exist"""
    
    def __init__(self, job_id: str):
        super().__init__(
            message=f"Analysis job not found: {job_id}",
            job_id=job_id
        )
        self.error_code = "JOB_NOT_FOUND"
        self.http_status_code = 404


class JobTimeoutError(JobError):
    """Analysis job exceeded maximum processing time"""
    
    def __init__(self, job_id: str, timeout_seconds: int):
        super().__init__(
            message=f"Analysis job timed out after {timeout_seconds} seconds",
            job_id=job_id
        )
        self.error_code = "JOB_TIMEOUT"
        self.details["timeout_seconds"] = timeout_seconds


class JobProcessingError(JobError):
    """Analysis job failed during processing"""
    
    def __init__(self, job_id: str, processing_stage: str, error_details: str):
        super().__init__(
            message=f"Analysis job failed during {processing_stage}",
            job_id=job_id
        )
        self.error_code = "JOB_PROCESSING_ERROR"
        self.details.update({
            "processing_stage": processing_stage,
            "error_details": error_details
        })


class ExternalServiceError(CaponierException):
    """
    Raised when external service calls fail
    
    Covers GitHub API errors, NVD API failures, rate limiting,
    and other external service integration issues.
    """
    
    def __init__(self, message: str, service_name: str, response_code: int = None, response_body: str = None):
        details = {"service_name": service_name}
        if response_code:
            details["response_code"] = response_code
        if response_body:
            details["response_body"] = response_body
        
        super().__init__(
            message=message,
            error_code="EXTERNAL_SERVICE_ERROR",
            details=details,
            http_status_code=503
        )


class VulnerabilityServiceError(ExternalServiceError):
    """
    Raised when vulnerability scanning services fail
    
    Specialized error for vulnerability databases like NVD, security scanners, etc.
    """
    
    def __init__(self, message: str, service: str = "Vulnerability Service", status_code: Optional[int] = None):
        super().__init__(message, service)
        self.error_code = "VULNERABILITY_SERVICE_ERROR"
        if status_code:
            self.details["status_code"] = status_code
            # Set appropriate HTTP status based on the service error
            if status_code == 403:
                self.http_status_code = 403
            elif status_code == 404:
                self.http_status_code = 404
            elif status_code >= 500:
                self.http_status_code = 502  # Bad Gateway
            else:
                self.http_status_code = 503  # Service Unavailable


class GitHubAPIError(ExternalServiceError):
    """GitHub API request failed"""
    
    def __init__(self, message: str, response_code: int = None, rate_limit_exceeded: bool = False):
        super().__init__(
            message=message,
            service_name="GitHub API",
            response_code=response_code
        )
        self.error_code = "GITHUB_API_ERROR"
        if rate_limit_exceeded:
            self.details["rate_limit_exceeded"] = True
            self.http_status_code = 429


class NVDAPIError(ExternalServiceError):
    """National Vulnerability Database API request failed"""
    
    def __init__(self, message: str, response_code: int = None, package_name: str = None):
        super().__init__(
            message=message,
            service_name="NVD API",
            response_code=response_code
        )
        self.error_code = "NVD_API_ERROR"
        if package_name:
            self.details["package_name"] = package_name


class ConfigurationError(CaponierException):
    """
    Raised when configuration or setup issues are detected
    
    Includes missing API keys, invalid configuration values,
    and environment setup problems.
    """
    
    def __init__(self, message: str, config_key: str = None, config_value: Any = None):
        details = {}
        if config_key:
            details["config_key"] = config_key
        if config_value is not None:
            details["config_value"] = str(config_value)
        
        super().__init__(
            message=message,
            error_code="CONFIGURATION_ERROR",
            details=details,
            http_status_code=500
        )


class RateLimitError(CaponierException):
    """
    Raised when rate limits are exceeded
    
    Can apply to internal rate limiting or external service rate limits.
    """
    
    def __init__(self, message: str, service: str = "internal", retry_after: int = None):
        details = {"service": service}
        if retry_after:
            details["retry_after_seconds"] = retry_after
        
        super().__init__(
            message=message,
            error_code="RATE_LIMIT_EXCEEDED",
            details=details,
            http_status_code=429
        )


# Exception mapping for HTTP status codes
EXCEPTION_STATUS_MAP = {
    ValidationError: 422,
    RepositoryNotFoundError: 404,
    RepositoryAccessDeniedError: 403,
    RepositoryError: 422,
    JobNotFoundError: 404,
    JobTimeoutError: 408,
    JobError: 422,
    AnalysisError: 500,
    ExternalServiceError: 503,
    GitHubAPIError: 503,
    NVDAPIError: 503,
    ConfigurationError: 500,
    RateLimitError: 429,
    CaponierException: 500
}


def get_http_status_code(exception: Exception) -> int:
    """
    Get appropriate HTTP status code for an exception
    
    Args:
        exception: Exception instance
        
    Returns:
        HTTP status code
    """
    if isinstance(exception, CaponierException):
        return exception.http_status_code
    
    # Check exception type mapping
    for exc_type, status_code in EXCEPTION_STATUS_MAP.items():
        if isinstance(exception, exc_type):
            return status_code
    
    # Default to 500 for unknown exceptions
    return 500
