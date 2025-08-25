"""
Synchronous GitHub API client for Celery tasks

This module provides a synchronous version of the GitHub API client specifically
designed for use in Celery tasks to avoid asyncio.run() performance issues.
"""

import logging
import os
import re
import time
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import requests
from cachetools import TTLCache

from ..utils.exceptions import (
    GitHubAPIError, 
    RateLimitError, 
    RepositoryNotFoundError, 
    RepositoryPrivateError,
    RepositoryAccessDeniedError,
    ExternalServiceError
)
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
        """Time until rate limit resets"""
        return self.reset_time - datetime.now()


class SyncGitHubClient:
    """
    Synchronous GitHub API client for Celery tasks
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
        Initialize synchronous GitHub API client
        
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
        
        # Setup session with headers
        self.session = requests.Session()
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Caponier-Security-Scanner/1.0"
        }
        
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
            logger.info("Sync GitHub client initialized with authentication token")
        else:
            logger.warning("Sync GitHub client initialized without token - rate limits will be lower")
        
        self.session.headers.update(headers)
        
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
    
    def close(self):
        """Close the session"""
        if self.session:
            self.session.close()
    
    def _update_rate_limit_info(self, headers: Dict[str, str]):
        """Update rate limit information from response headers"""
        try:
            self.rate_limit_info = RateLimitInfo(
                limit=int(headers.get('x-ratelimit-limit', 0)),
                remaining=int(headers.get('x-ratelimit-remaining', 0)),
                reset_timestamp=int(headers.get('x-ratelimit-reset', 0)),
                used=int(headers.get('x-ratelimit-used', 0))
            )
            
            logger.debug(
                f"Rate limit updated: {self.rate_limit_info.remaining}/"
                f"{self.rate_limit_info.limit} remaining"
            )
            
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse rate limit headers: {e}")
    
    def _handle_rate_limit(self):
        """Handle rate limiting with backoff"""
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
                time.sleep(wait_time)
    
    def _get_cache_key(self, endpoint: str, params: Optional[Dict] = None) -> str:
        """Generate cache key for request"""
        if params:
            sorted_params = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
            return f"{endpoint}?{sorted_params}"
        return endpoint
    
    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Make authenticated GitHub API request with retry logic
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (relative to base_url)
            params: Query parameters
            json_data: JSON data for POST requests
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
        self._handle_rate_limit()
        
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        retry_count = 0
        
        while retry_count <= self.max_retries:
            try:
                self.stats["requests_made"] += 1
                
                # Make the request
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_data,
                    timeout=self.timeout
                )
                
                # Update rate limit info
                self._update_rate_limit_info(response.headers)
                
                # Handle response status codes
                if response.status_code == 200:
                    data = response.json()
                    
                    # Cache successful GET responses
                    if cache_key and method == "GET":
                        self.cache[cache_key] = data
                    
                    return data
                
                elif response.status_code == 404:
                    error_data = response.json() if response.content else {}
                    raise RepositoryNotFoundError(
                        f"Repository not found: {endpoint}",
                        details=error_data
                    )
                
                elif response.status_code == 403:
                    error_data = response.json() if response.content else {}
                    
                    if "rate limit exceeded" in response.text.lower():
                        reset_time = int(response.headers.get('x-ratelimit-reset', 0))
                        wait_time = max(reset_time - int(time.time()), 0)
                        raise RateLimitError(
                            f"GitHub API rate limit exceeded. Reset in {wait_time}s",
                            reset_time=reset_time
                        )
                    
                    if error_data.get('message', '').lower().find('private') != -1:
                        raise RepositoryPrivateError(
                            f"Repository is private: {endpoint}",
                            details=error_data
                        )
                    
                    raise RepositoryAccessDeniedError(
                        f"Access denied to repository: {endpoint}",
                        details=error_data
                    )
                
                elif response.status_code == 422:
                    error_data = response.json() if response.content else {}
                    raise GitHubAPIError(
                        f"Invalid request to GitHub API: {endpoint}",
                        status_code=response.status_code,
                        details=error_data
                    )
                
                elif response.status_code >= 500:
                    # Server error - retry
                    if retry_count < self.max_retries:
                        wait_time = 2 ** retry_count
                        logger.warning(
                            f"GitHub API server error (attempt {retry_count + 1}). "
                            f"Retrying in {wait_time}s..."
                        )
                        time.sleep(wait_time)
                        retry_count += 1
                        continue
                    
                    raise ExternalServiceError(
                        f"GitHub API server error: {response.status_code}",
                        "github_api"
                    )
                
                else:
                    error_data = response.json() if response.content else {}
                    raise GitHubAPIError(
                        f"GitHub API error: {response.status_code}",
                        status_code=response.status_code,
                        details=error_data
                    )
                    
            except requests.exceptions.RequestException as e:
                if retry_count < self.max_retries:
                    wait_time = 2 ** retry_count
                    logger.warning(
                        f"Network error (attempt {retry_count + 1}): {e}. "
                        f"Retrying in {wait_time}s..."
                    )
                    time.sleep(wait_time)
                    retry_count += 1
                    continue
                
                self.stats["errors"] += 1
                raise ExternalServiceError(f"Network error: {str(e)}", "github_api")
        
        # If we get here, all retries were exhausted
        self.stats["errors"] += 1
        raise ExternalServiceError("Max retries exceeded", "github_api")
    
    def get_repository(self, owner: str, repo: str) -> Dict[str, Any]:
        """
        Get repository information
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            Repository data
        """
        return self._make_request("GET", f"repos/{owner}/{repo}")
    
    def get_file_content(self, owner: str, repo: str, file_path: str) -> Dict[str, Any]:
        """
        Get file content from repository
        
        Args:
            owner: Repository owner
            repo: Repository name
            file_path: Path to file in repository
            
        Returns:
            File content data
        """
        return self._make_request("GET", f"repos/{owner}/{repo}/contents/{file_path}")
    
    def get_repository_files(self, owner: str, repo: str, path: str = "") -> List[Dict[str, Any]]:
        """
        Get list of files in repository path
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: Path in repository (empty for root)
            
        Returns:
            List of file/directory information
        """
        endpoint = f"repos/{owner}/{repo}/contents"
        if path:
            endpoint += f"/{path}"
        
        result = self._make_request("GET", endpoint)
        
        # Ensure we return a list
        if isinstance(result, dict):
            return [result]
        return result
    
    def get_commits(self, owner: str, repo: str, per_page: int = 30) -> List[Dict[str, Any]]:
        """
        Get repository commits
        
        Args:
            owner: Repository owner
            repo: Repository name
            per_page: Number of commits per page
            
        Returns:
            List of commit data
        """
        return self._make_request("GET", f"repos/{owner}/{repo}/commits", 
                                  params={"per_page": per_page})
    
    def get_contributors(self, owner: str, repo: str, per_page: int = 30) -> List[Dict[str, Any]]:
        """
        Get repository contributors
        
        Args:
            owner: Repository owner
            repo: Repository name
            per_page: Number of contributors per page
            
        Returns:
            List of contributor data
        """
        return self._make_request("GET", f"repos/{owner}/{repo}/contributors", 
                                  params={"per_page": per_page})
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get client statistics
        
        Returns:
            Dictionary with client statistics
        """
        stats = self.stats.copy()
        
        if self.rate_limit_info:
            stats["rate_limit"] = {
                "limit": self.rate_limit_info.limit,
                "remaining": self.rate_limit_info.remaining,
                "reset_time": self.rate_limit_info.reset_time.isoformat()
            }
        
        stats["cache_size"] = len(self.cache)
        stats["authenticated"] = bool(self.token)
        
        return stats


# Singleton instance for Celery tasks
_sync_github_client: Optional[SyncGitHubClient] = None


def get_sync_github_client() -> SyncGitHubClient:
    """
    Get singleton synchronous GitHub client instance
    
    Returns:
        Configured synchronous GitHub API client
    """
    global _sync_github_client
    
    if _sync_github_client is None:
        _sync_github_client = SyncGitHubClient()
        logger.info("Synchronous GitHub API client initialized")
    
    return _sync_github_client


def close_sync_github_client():
    """Close the global synchronous GitHub client"""
    global _sync_github_client
    
    if _sync_github_client:
        _sync_github_client.close()
        _sync_github_client = None
        logger.info("Synchronous GitHub API client closed")
