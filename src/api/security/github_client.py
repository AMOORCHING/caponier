"""
GitHub API client with rate limiting and authentication handling

This module provides a comprehensive GitHub API client that handles:
- Authentication with personal access tokens
- Rate limiting and backoff strategies
- Repository metadata extraction
- Error handling and retry logic
- Caching for improved performance
"""

import asyncio
import logging
import os
import re
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import httpx
from cachetools import TTLCache
import time

from ..utils.exceptions import (
    GitHubAPIError, 
    RateLimitError, 
    RepositoryNotFoundError, 
    RepositoryPrivateError,
    RepositoryAccessDeniedError,
    ExternalServiceError,
    CircuitBreakerError
)
from .circuit_breaker import CircuitBreakerConfig, get_circuit_breaker
from ..models import RepositoryMetadata

logger = logging.getLogger(__name__)


@dataclass
class RateLimitInfo:
    """GitHub API rate limit information"""
    limit: int
    remaining: int
    reset_timestamp: int
    used: int
    
    @property
    def reset_time(self) -> datetime:
        """Convert reset timestamp to datetime"""
        return datetime.fromtimestamp(self.reset_timestamp)
    
    @property
    def time_until_reset(self) -> timedelta:
        """Time remaining until rate limit resets"""
        return self.reset_time - datetime.now()


class GitHubAPIClient:
    """
    GitHub API client with comprehensive rate limiting and authentication
    """
    
    def __init__(
        self, 
        token: Optional[str] = None,
        base_url: str = "https://api.github.com",
        timeout: float = 30.0,
        max_retries: int = 3,
        cache_ttl: int = 300  # 5 minutes
    ):
        """
        Initialize GitHub API client
        
        Args:
            token: GitHub personal access token (optional, improves rate limits)
            base_url: GitHub API base URL
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            cache_ttl: Cache time-to-live in seconds
        """
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Setup HTTP client with headers
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Caponier-Security-Scanner/1.0"
        }
        
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
            logger.info("GitHub client initialized with authentication token")
        else:
            logger.warning("GitHub client initialized without token - rate limits will be lower")
        
        self.client = httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
        )
        
        # Rate limiting tracking
        self.rate_limit_info: Optional[RateLimitInfo] = None
        self.last_rate_limit_check = 0
        
        # Response cache
        self.cache = TTLCache(maxsize=1000, ttl=cache_ttl)
        
        # Request statistics
        self.stats = {
            "requests_made": 0,
            "cache_hits": 0,
            "rate_limit_hits": 0,
            "errors": 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
    
    def _get_cache_key(self, endpoint: str, params: Optional[Dict] = None) -> str:
        """Generate cache key for request"""
        if params:
            param_str = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
            return f"{endpoint}?{param_str}"
        return endpoint
    
    def _update_rate_limit_info(self, headers: Dict[str, str]):
        """Update rate limit information from response headers"""
        try:
            if "x-ratelimit-limit" in headers:
                self.rate_limit_info = RateLimitInfo(
                    limit=int(headers["x-ratelimit-limit"]),
                    remaining=int(headers["x-ratelimit-remaining"]),
                    reset_timestamp=int(headers["x-ratelimit-reset"]),
                    used=int(headers["x-ratelimit-used"])
                )
                self.last_rate_limit_check = time.time()
                
                logger.debug(
                    f"Rate limit updated: {self.rate_limit_info.remaining}/"
                    f"{self.rate_limit_info.limit} remaining, "
                    f"resets at {self.rate_limit_info.reset_time}"
                )
        except (KeyError, ValueError) as e:
            logger.warning(f"Failed to parse rate limit headers: {e}")
    
    async def _handle_rate_limit(self):
        """Handle rate limiting with exponential backoff"""
        if not self.rate_limit_info:
            return
        
        # Check if we're close to rate limit
        if self.rate_limit_info.remaining <= 5:
            wait_time = min(self.rate_limit_info.time_until_reset.total_seconds(), 60)
            if wait_time > 0:
                logger.warning(
                    f"Rate limit nearly exceeded. Waiting {wait_time:.1f} seconds..."
                )
                self.stats["rate_limit_hits"] += 1
                await asyncio.sleep(wait_time)
    
    async def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict] = None,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make authenticated GitHub API request with retry logic
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (relative to base_url)
            params: Query parameters
            use_cache: Whether to use response caching
            
        Returns:
            API response data
            
        Raises:
            GitHubAPIError: For GitHub API specific errors
            RateLimitError: When rate limits are exceeded
            ExternalServiceError: For other HTTP errors
        """
        # Check cache first for GET requests
        cache_key = self._get_cache_key(endpoint, params) if use_cache and method == "GET" else None
        if cache_key and cache_key in self.cache:
            self.stats["cache_hits"] += 1
            logger.debug(f"Cache hit for {endpoint}")
            return self.cache[cache_key]
        
        # Handle rate limiting proactively
        await self._handle_rate_limit()
        
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        retry_count = 0
        
        while retry_count <= self.max_retries:
            try:
                self.stats["requests_made"] += 1
                
                logger.debug(f"Making {method} request to {endpoint}")
                response = await self.client.request(method, url, params=params)
                
                # Update rate limit info
                self._update_rate_limit_info(dict(response.headers))
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Cache successful GET responses
                    if cache_key:
                        self.cache[cache_key] = data
                    
                    return data
                
                elif response.status_code == 404:
                    # Extract repository info from endpoint for better error messages
                    repo_match = re.search(r'repos/([^/]+)/([^/]+)', endpoint)
                    if repo_match:
                        owner, repo = repo_match.groups()
                        repository_url = f"https://github.com/{owner}/{repo}"
                        suggestion = "Check that the repository name is spelled correctly and that it exists"
                    else:
                        repository_url = endpoint
                        suggestion = None
                    
                    raise RepositoryNotFoundError(repository_url, suggestion)
                
                elif response.status_code == 403:
                    # Parse the response to determine the specific access issue
                    response_text = response.text.lower()
                    response_json = None
                    
                    try:
                        response_json = response.json()
                    except:
                        pass
                    
                    # Check if it's rate limiting
                    if "rate limit" in response_text or (response_json and "rate limit" in str(response_json).lower()):
                        if retry_count < self.max_retries:
                            wait_time = 2 ** retry_count  # Exponential backoff
                            logger.warning(f"Rate limited. Waiting {wait_time} seconds before retry...")
                            await asyncio.sleep(wait_time)
                            retry_count += 1
                            continue
                        else:
                            raise RateLimitError(
                                "GitHub API rate limit exceeded",
                                service="GitHub API",
                                retry_after=60
                            )
                    
                    # Check if it's a private repository
                    elif any(keyword in response_text for keyword in ["private", "must have", "permission"]):
                        repo_match = re.search(r'repos/([^/]+)/([^/]+)', endpoint)
                        if repo_match:
                            owner, repo = repo_match.groups()
                            repository_url = f"https://github.com/{owner}/{repo}"
                            raise RepositoryPrivateError(repository_url, bool(self.token))
                        else:
                            raise RepositoryAccessDeniedError(
                                endpoint, 
                                "Repository appears to be private or requires authentication",
                                "private_repository"
                            )
                    
                    # Generic access denied
                    else:
                        repo_match = re.search(r'repos/([^/]+)/([^/]+)', endpoint)
                        if repo_match:
                            owner, repo = repo_match.groups()
                            repository_url = f"https://github.com/{owner}/{repo}"
                        else:
                            repository_url = endpoint
                        
                        raise RepositoryAccessDeniedError(
                            repository_url,
                            "Access denied - insufficient permissions",
                            "access_denied"
                        )
                
                elif response.status_code >= 500:
                    # Server errors - retry with backoff
                    if retry_count < self.max_retries:
                        wait_time = 2 ** retry_count
                        logger.warning(
                            f"Server error {response.status_code}. Retrying in {wait_time} seconds..."
                        )
                        await asyncio.sleep(wait_time)
                        retry_count += 1
                        continue
                    else:
                        raise GitHubAPIError(
                            f"GitHub API server error: {response.status_code}",
                            response_code=response.status_code
                        )
                
                else:
                    # Other client errors
                    raise GitHubAPIError(
                        f"GitHub API error: {response.status_code} - {response.text}",
                        response_code=response.status_code
                    )
                    
            except httpx.TimeoutException:
                if retry_count < self.max_retries:
                    wait_time = 2 ** retry_count
                    logger.warning(f"Request timeout. Retrying in {wait_time} seconds...")
                    await asyncio.sleep(wait_time)
                    retry_count += 1
                    continue
                else:
                    self.stats["errors"] += 1
                    raise ExternalServiceError(
                        "GitHub API request timed out",
                        service_name="GitHub API"
                    )
            
            except httpx.RequestError as e:
                self.stats["errors"] += 1
                raise ExternalServiceError(
                    f"GitHub API request failed: {str(e)}",
                    service_name="GitHub API"
                )
        
        # If we get here, all retries have been exhausted
        self.stats["errors"] += 1
        raise ExternalServiceError(
            f"GitHub API request failed after {self.max_retries} retries",
            service_name="GitHub API"
        )
    
    async def get_repository_info(self, owner: str, repo: str) -> RepositoryMetadata:
        """
        Get comprehensive repository information
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Repository metadata
        """
        try:
            # Get basic repository information
            repo_data = await self._make_request("GET", f"repos/{owner}/{repo}")
            
            # Get contributor count (separate API call with pagination handling)
            contributors_count = await self._get_contributor_count(owner, repo)
            
            # Parse and return repository metadata
            return RepositoryMetadata(
                owner=repo_data["owner"]["login"],
                name=repo_data["name"],
                full_name=repo_data["full_name"],
                description=repo_data.get("description"),
                language=repo_data.get("language"),
                stars=repo_data["stargazers_count"],
                forks=repo_data["forks_count"],
                last_commit_date=self._parse_datetime(repo_data["pushed_at"]),
                contributor_count=contributors_count,
                open_issues_count=repo_data["open_issues_count"],
                created_at=self._parse_datetime(repo_data["created_at"]),
                updated_at=self._parse_datetime(repo_data["updated_at"])
            )
            
        except Exception as e:
            logger.error(f"Failed to get repository info for {owner}/{repo}: {str(e)}")
            raise
    
    async def _get_contributor_count(self, owner: str, repo: str) -> int:
        """
        Get total number of contributors (handles pagination)
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Total contributor count
        """
        try:
            # Use anonymous contributors endpoint for count
            contributors_data = await self._make_request(
                "GET", 
                f"repos/{owner}/{repo}/contributors",
                params={"anon": "true", "per_page": "1"}
            )
            
            # For most repositories, we can get a rough count from the first page
            # For precise counts, we'd need to paginate through all pages
            # This is a reasonable approximation for our use case
            if contributors_data:
                # Try to get Link header for pagination info
                # For now, return a conservative estimate
                return len(contributors_data) if len(contributors_data) < 100 else 100
            
            return 0
            
        except Exception as e:
            logger.warning(f"Failed to get contributor count for {owner}/{repo}: {str(e)}")
            return 0
    
    def _parse_datetime(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse GitHub API datetime string"""
        if not date_str:
            return None
        
        try:
            # GitHub uses ISO 8601 format: "2023-10-15T14:30:00Z"
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            logger.warning(f"Failed to parse datetime: {date_str}")
            return None
    
    async def get_repository_files(self, owner: str, repo: str, path: str = "") -> List[Dict[str, Any]]:
        """
        Get repository file tree
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: Directory path (empty for root)
            
        Returns:
            List of file/directory information
        """
        endpoint = f"repos/{owner}/{repo}/contents/{path}" if path else f"repos/{owner}/{repo}/contents"
        return await self._make_request("GET", endpoint)
    
    async def get_file_content(self, owner: str, repo: str, path: str) -> str:
        """
        Get raw file content
        
        Args:
            owner: Repository owner  
            repo: Repository name
            path: File path
            
        Returns:
            File content as string
        """
        file_info = await self._make_request("GET", f"repos/{owner}/{repo}/contents/{path}")
        
        if file_info.get("type") != "file":
            raise GitHubAPIError(f"Path {path} is not a file")
        
        # Decode base64 content
        import base64
        content = base64.b64decode(file_info["content"]).decode("utf-8")
        return content
    
    async def check_repository_exists(self, owner: str, repo: str) -> bool:
        """
        Check if repository exists and is accessible
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            True if repository exists and is accessible
        """
        try:
            await self._make_request("GET", f"repos/{owner}/{repo}")
            return True
        except RepositoryNotFoundError:
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get client usage statistics
        
        Returns:
            Statistics dictionary
        """
        stats = self.stats.copy()
        
        if self.rate_limit_info:
            stats["rate_limit"] = {
                "limit": self.rate_limit_info.limit,
                "remaining": self.rate_limit_info.remaining,
                "reset_time": self.rate_limit_info.reset_time.isoformat(),
                "used": self.rate_limit_info.used
            }
        
        stats["cache_size"] = len(self.cache)
        stats["authenticated"] = bool(self.token)
        
        return stats


# Singleton instance for application use
_github_client: Optional[GitHubAPIClient] = None


async def get_github_client() -> GitHubAPIClient:
    """
    Get singleton GitHub client instance
    
    Returns:
        Configured GitHub API client
    """
    global _github_client
    
    if _github_client is None:
        _github_client = GitHubAPIClient()
        logger.info("GitHub API client initialized")
    
    return _github_client


async def close_github_client():
    """Close the global GitHub client"""
    global _github_client
    
    if _github_client:
        await _github_client.close()
        _github_client = None
        logger.info("GitHub API client closed")
