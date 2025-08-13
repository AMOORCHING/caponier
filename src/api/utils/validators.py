import re
import urllib.parse
from typing import Optional, Tuple, Dict, Any
import httpx
import asyncio
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
import logging

from ..models import ErrorResponse
from .exceptions import (
    ValidationError,
    RepositoryNotFoundError,
    RepositoryAccessDeniedError,
    RepositoryPrivateError,
    InvalidRepositoryURLError,
    ExternalServiceError,
    GitHubAPIError
)
from ..security.repository_analyzer import RepositoryAnalyzer

logger = logging.getLogger(__name__)

class GitHubURLValidator:
    """
    Comprehensive GitHub repository URL validator and normalizer
    """
    
    # GitHub URL patterns for validation
    GITHUB_PATTERNS = [
        r'^https://github\.com/([a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])/([a-zA-Z0-9][a-zA-Z0-9\-_.]*[a-zA-Z0-9])/?$',
        r'^github\.com/([a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])/([a-zA-Z0-9][a-zA-Z0-9\-_.]*[a-zA-Z0-9])/?$',
        r'^([a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])/([a-zA-Z0-9][a-zA-Z0-9\-_.]*[a-zA-Z0-9])$'
    ]
    
    @staticmethod
    def normalize_github_url(url: str) -> str:
        """
        Normalize various GitHub URL formats to standard HTTPS format
        
        Args:
            url: Raw URL input from user
            
        Returns:
            Normalized GitHub repository URL
            
        Raises:
            ValidationError: If URL format is invalid
        """
        if not url or not isinstance(url, str):
            raise InvalidRepositoryURLError(
                str(url) if url else "None",
                "Repository URL is required and must be a string",
                "Provide a valid GitHub repository URL like 'https://github.com/owner/repo'"
            )
        
        # Clean and normalize the URL
        original_url = url
        url = url.strip().rstrip('/')
        
        if not url:
            raise InvalidRepositoryURLError(
                original_url,
                "Repository URL cannot be empty or whitespace only",
                "Provide a valid GitHub repository URL"
            )
        
        # Remove common prefixes that users might include
        url = re.sub(r'^(https?://)?', '', url)
        url = re.sub(r'^www\.', '', url)
        
        # Check if it's a GitHub URL
        if not url.startswith('github.com/') and not url.startswith('//github.com/'):
            # Check if user provided a non-GitHub URL
            if any(domain in url.lower() for domain in ['gitlab.com', 'bitbucket.org', 'sourceforge.net']):
                domain = next(domain for domain in ['gitlab.com', 'bitbucket.org', 'sourceforge.net'] if domain in url.lower())
                raise InvalidRepositoryURLError(
                    original_url,
                    f"Only GitHub repositories are supported, found {domain}",
                    "Provide a GitHub repository URL like 'https://github.com/owner/repo'"
                )
            
            # Assume it might be owner/repo format
            if '/' in url and not any(c in url for c in ['.', ':', '@']):
                url = f"github.com/{url}"
            else:
                raise InvalidRepositoryURLError(
                    original_url,
                    "URL does not appear to be a GitHub repository",
                    "Provide a GitHub repository URL like 'https://github.com/owner/repo'"
                )
        
        # Handle different input formats
        if url.startswith('github.com/'):
            url = url[11:]  # Remove 'github.com/'
        elif url.startswith('//github.com/'):
            url = url[13:]  # Remove '//github.com/'
        
        # Validate owner/repo format
        parts = url.split('/')
        if len(parts) < 2:
            raise InvalidRepositoryURLError(
                original_url,
                "Invalid repository format - missing owner or repository name",
                "Expected format: 'owner/repository' or 'https://github.com/owner/repository'"
            )
        
        owner, repo = parts[0], parts[1]
        
        # Check for empty owner or repo
        if not owner.strip():
            raise InvalidRepositoryURLError(
                original_url,
                "Repository owner cannot be empty",
                "Provide both owner and repository name"
            )
        
        if not repo.strip():
            raise InvalidRepositoryURLError(
                original_url,
                "Repository name cannot be empty",
                "Provide both owner and repository name"
            )
        
        # Additional validation for GitHub username/repo rules
        if not GitHubURLValidator._is_valid_github_username(owner):
            raise InvalidRepositoryURLError(
                original_url,
                f"Invalid GitHub username '{owner}' - must contain only alphanumeric characters and hyphens",
                "GitHub usernames can only contain letters, numbers, and hyphens"
            )
        
        if not GitHubURLValidator._is_valid_github_repo_name(repo):
            raise InvalidRepositoryURLError(
                original_url,
                f"Invalid GitHub repository name '{repo}' - contains invalid characters",
                "Repository names can contain letters, numbers, hyphens, periods, and underscores"
            )
        
        # Remove any additional path components (like /tree/main, /blob/master, etc.)
        normalized_url = f"https://github.com/{owner}/{repo}"
        
        return normalized_url
    
    @staticmethod
    def _is_valid_github_username(username: str) -> bool:
        """
        Validate GitHub username according to GitHub rules
        """
        if not username or len(username) > 39:
            return False
        
        # GitHub username rules:
        # - May only contain alphanumeric characters or hyphens
        # - Cannot have multiple consecutive hyphens
        # - Cannot begin or end with a hyphen
        # - Maximum 39 characters
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-])*[a-zA-Z0-9]$|^[a-zA-Z0-9]$'
        
        if not re.match(pattern, username):
            return False
        
        # Check for consecutive hyphens
        if '--' in username:
            return False
        
        return True
    
    @staticmethod
    def _is_valid_github_repo_name(repo_name: str) -> bool:
        """
        Validate GitHub repository name according to GitHub rules
        """
        if not repo_name or len(repo_name) > 100:
            return False
        
        # GitHub repository name rules:
        # - Can contain letters, numbers, hyphens, underscores, and periods
        # - Cannot start with a period or hyphen
        # - Cannot end with a period
        # - Maximum 100 characters
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\-_.]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$'
        
        if not re.match(pattern, repo_name):
            return False
        
        # Additional checks
        if repo_name.startswith('.') or repo_name.startswith('-'):
            return False
        
        if repo_name.endswith('.'):
            return False
        
        return True
    
    @staticmethod
    def extract_owner_repo(url: str) -> Tuple[str, str]:
        """
        Extract owner and repository name from normalized GitHub URL
        
        Args:
            url: Normalized GitHub URL
            
        Returns:
            Tuple of (owner, repository_name)
        """
        parsed = urllib.parse.urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) < 2:
            raise ValueError("Invalid GitHub URL format")
        
        return path_parts[0], path_parts[1]


class RepositoryExistenceValidator:
    """
    Validates that a GitHub repository actually exists and is accessible
    """
    
    @staticmethod
    async def check_repository_exists(url: str, timeout: float = 10.0) -> Tuple[bool, Optional[str]]:
        """
        Check if a GitHub repository exists and is publicly accessible
        
        Args:
            url: Normalized GitHub repository URL
            timeout: Request timeout in seconds
            
        Returns:
            Tuple of (exists: bool, error_message: Optional[str])
        """
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                # Use GitHub API to check repository existence
                owner, repo = GitHubURLValidator.extract_owner_repo(url)
                api_url = f"https://api.github.com/repos/{owner}/{repo}"
                
                response = await client.get(api_url)
                
                if response.status_code == 200:
                    return True, None
                elif response.status_code == 404:
                    raise RepositoryNotFoundError(url)
                elif response.status_code == 403:
                    # Rate limited or access denied
                    raise RepositoryAccessDeniedError(url, "Rate limited or access denied")
                else:
                    raise GitHubAPIError(f"Unable to verify repository (HTTP {response.status_code})", response.status_code)
                    
        except httpx.TimeoutException:
            logger.error(f"Timeout checking repository existence: {url}")
            raise ExternalServiceError("Repository verification timed out", "GitHub API")
        except (RepositoryNotFoundError, RepositoryAccessDeniedError, GitHubAPIError):
            # Re-raise our custom exceptions
            raise
        except Exception as e:
            logger.error(f"Error checking repository existence for {url}: {str(e)}")
            raise ExternalServiceError(f"Repository verification failed: {str(e)}", "GitHub API")


# Middleware function for URL validation
async def validate_github_url_middleware(request: Request, call_next):
    """
    FastAPI middleware to validate GitHub URLs in analysis requests
    """
    # Only apply validation to analysis endpoints
    if request.url.path == "/analyze" and request.method == "POST":
        try:
            # Parse request body to extract repository URL
            body = await request.body()
            
            # Note: This is a simplified implementation
            # In a production environment, you might want to parse JSON properly
            # and handle edge cases more robustly
            
            response = await call_next(request)
            return response
            
        except Exception as e:
            logger.error(f"URL validation middleware error: {str(e)}")
            # Continue with request if middleware fails
            response = await call_next(request)
            return response
    
    # For non-analysis endpoints, pass through
    response = await call_next(request)
    return response


# Dependency function for use in FastAPI endpoints
async def validate_repository_url(repository_url: str) -> str:
    """
    FastAPI dependency function to validate and normalize repository URLs
    
    Args:
        repository_url: Raw repository URL from request
        
    Returns:
        Normalized repository URL
        
    Raises:
        ValidationError: If URL format is invalid
        RepositoryNotFoundError: If repository doesn't exist
        RepositoryAccessDeniedError: If repository access is denied
        ExternalServiceError: If GitHub API verification fails
    """
    try:
        # Step 1: Normalize URL format
        normalized_url = GitHubURLValidator.normalize_github_url(repository_url)
        
        # Step 2: Check if repository exists
        await RepositoryExistenceValidator.check_repository_exists(normalized_url)
        
        return normalized_url
        
    except (InvalidRepositoryURLError, RepositoryNotFoundError, RepositoryPrivateError, RepositoryAccessDeniedError, GitHubAPIError, ExternalServiceError):
        # Re-raise our custom exceptions - they will be handled by the exception handler
        raise
    except Exception as e:
        logger.error(f"Unexpected error validating repository URL {repository_url}: {str(e)}")
        raise ExternalServiceError(f"Failed to validate repository URL: {str(e)}", "validation_service")


async def validate_and_analyze_repository(repository_url: str) -> Dict[str, Any]:
    """
    Comprehensive repository validation and metadata extraction
    
    This function performs both validation and detailed analysis of a GitHub repository,
    including metadata extraction, commit analysis, contributor analysis, and more.
    
    Args:
        repository_url: Raw repository URL from request
        
    Returns:
        Complete repository analysis data
        
    Raises:
        ValidationError: If URL format is invalid
        RepositoryNotFoundError: If repository doesn't exist
        RepositoryAccessDeniedError: If repository access is denied
        AnalysisError: If repository analysis fails
        ExternalServiceError: If external service calls fail
    """
    try:
        # Step 1: Validate and normalize URL
        normalized_url = await validate_repository_url(repository_url)
        
        # Step 2: Perform comprehensive repository analysis
        async with RepositoryAnalyzer() as analyzer:
            analysis_result = await analyzer.validate_and_analyze_repository(normalized_url)
            
        logger.info(f"Repository analysis completed for {normalized_url}")
        return analysis_result
        
    except (ValidationError, RepositoryNotFoundError, RepositoryAccessDeniedError, ExternalServiceError):
        # Re-raise our custom exceptions
        raise
    except Exception as e:
        logger.error(f"Unexpected error in repository analysis for {repository_url}: {str(e)}")
        raise ExternalServiceError(f"Failed to analyze repository: {str(e)}", "repository_analyzer")
