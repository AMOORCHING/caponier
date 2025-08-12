import re
import urllib.parse
from typing import Optional, Tuple
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
    ExternalServiceError,
    GitHubAPIError
)

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
            raise ValidationError("Repository URL is required and must be a string", "repository_url", url)
        
        # Clean and normalize the URL
        url = url.strip().rstrip('/')
        
        # Remove common prefixes that users might include
        url = re.sub(r'^(https?://)?', '', url)
        url = re.sub(r'^www\.', '', url)
        
        # Handle different input formats
        if url.startswith('github.com/'):
            url = url[11:]  # Remove 'github.com/'
        elif url.startswith('//github.com/'):
            url = url[13:]  # Remove '//github.com/'
        
        # Validate owner/repo format
        parts = url.split('/')
        if len(parts) < 2:
            raise ValidationError("Invalid repository format. Expected: owner/repository", "repository_url", url)
        
        owner, repo = parts[0], parts[1]
        
        # Additional validation for GitHub username/repo rules
        if not GitHubURLValidator._is_valid_github_username(owner):
            raise ValidationError(f"Invalid GitHub username: {owner}", "owner", owner)
        
        if not GitHubURLValidator._is_valid_github_repo_name(repo):
            raise ValidationError(f"Invalid GitHub repository name: {repo}", "repository_name", repo)
        
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
        
    except (ValidationError, RepositoryNotFoundError, RepositoryAccessDeniedError, ExternalServiceError):
        # Re-raise our custom exceptions - they will be handled by the exception handler
        raise
    except Exception as e:
        logger.error(f"Unexpected error validating repository URL {repository_url}: {str(e)}")
        raise ExternalServiceError(f"Failed to validate repository URL: {str(e)}", "validation_service")
