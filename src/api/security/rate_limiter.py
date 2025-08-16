"""
Rate limiting implementation for API endpoints

This module provides comprehensive rate limiting capabilities:
- IP-based rate limiting for anonymous users
- User-based rate limiting for authenticated users
- Global rate limiting to prevent resource exhaustion
- Configurable limits and time windows
- Proper HTTP 429 responses with Retry-After headers
"""

import logging
import time
from typing import Dict, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict
import threading

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    # IP-based limits (anonymous users)
    ip_requests_per_minute: int = 10
    ip_requests_per_hour: int = 100
    
    # User-based limits (authenticated users)
    user_requests_per_minute: int = 50
    user_requests_per_hour: int = 500
    
    # Global limits
    global_concurrent_jobs: int = 100
    global_requests_per_minute: int = 200
    
    # Time windows
    window_minutes: int = 1
    window_hours: int = 60


class RateLimitManager:
    """
    Manages rate limiting across the application
    
    Provides both IP-based and user-based rate limiting with configurable limits.
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        """
        Initialize rate limit manager
        
        Args:
            config: Rate limiting configuration
        """
        self.config = config or RateLimitConfig()
        
        # Initialize slowapi limiter
        self.limiter = Limiter(key_func=get_remote_address)
        
        # In-memory storage for rate limiting data
        self.ip_requests: Dict[str, list] = defaultdict(list)
        self.user_requests: Dict[str, list] = defaultdict(list)
        self.global_requests: list = []
        self.active_jobs: int = 0
        
        # Thread lock for thread safety
        self.lock = threading.Lock()
        
        # Cleanup thread for expired entries
        self._start_cleanup_thread()
    
    def _start_cleanup_thread(self):
        """Start background thread to clean up expired rate limit entries"""
        def cleanup_worker():
            while True:
                try:
                    time.sleep(60)  # Clean up every minute
                    self._cleanup_expired_entries()
                except Exception as e:
                    logger.error(f"Rate limit cleanup error: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_expired_entries(self):
        """Remove expired rate limit entries"""
        current_time = time.time()
        
        with self.lock:
            # Clean up IP requests
            for ip in list(self.ip_requests.keys()):
                self.ip_requests[ip] = [
                    req_time for req_time in self.ip_requests[ip]
                    if current_time - req_time < 3600  # Keep last hour
                ]
                if not self.ip_requests[ip]:
                    del self.ip_requests[ip]
            
            # Clean up user requests
            for user_id in list(self.user_requests.keys()):
                self.user_requests[user_id] = [
                    req_time for req_time in self.user_requests[user_id]
                    if current_time - req_time < 3600  # Keep last hour
                ]
                if not self.user_requests[user_id]:
                    del self.user_requests[user_id]
            
            # Clean up global requests
            self.global_requests = [
                req_time for req_time in self.global_requests
                if current_time - req_time < 60  # Keep last minute
            ]
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Get client IP address from request
        
        Args:
            request: FastAPI request object
            
        Returns:
            Client IP address
        """
        # Check for forwarded headers (for proxy/load balancer setups)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct IP
        return request.client.host if request.client else "unknown"
    
    def _get_user_id(self, request: Request) -> Optional[str]:
        """
        Extract user ID from request for authenticated rate limiting
        
        Args:
            request: FastAPI request object
            
        Returns:
            User ID if authenticated, None otherwise
        """
        # Check for API key in headers
        api_key = request.headers.get("X-API-Key")
        if api_key:
            # In a real implementation, you would validate the API key
            # and return the associated user ID
            return f"api_key_{api_key[:8]}"
        
        # Check for Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            # In a real implementation, you would validate the JWT token
            # and extract the user ID
            return f"jwt_{token[:8]}"
        
        return None
    
    def check_rate_limit(self, request: Request) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Check if request is within rate limits
        
        Args:
            request: FastAPI request object
            
        Returns:
            Tuple of (allowed: bool, reason: Optional[str], retry_after: Optional[int])
        """
        current_time = time.time()
        client_ip = self._get_client_ip(request)
        user_id = self._get_user_id(request)
        
        with self.lock:
            # Check global rate limit
            if not self._check_global_limit(current_time):
                retry_after = self._calculate_retry_after_global(current_time)
                return False, "Global rate limit exceeded", retry_after
            
            # Check user-based rate limit (if authenticated)
            if user_id:
                if not self._check_user_limit(user_id, current_time):
                    retry_after = self._calculate_retry_after_user(user_id, current_time)
                    return False, "User rate limit exceeded", retry_after
            else:
                # Check IP-based rate limit (for anonymous users)
                if not self._check_ip_limit(client_ip, current_time):
                    retry_after = self._calculate_retry_after_ip(client_ip, current_time)
                    return False, "IP rate limit exceeded", retry_after
            
            # Record the request
            self._record_request(client_ip, user_id, current_time)
            return True, None, None
    
    def _check_global_limit(self, current_time: float) -> bool:
        """Check global rate limit"""
        # Remove requests older than 1 minute
        self.global_requests = [
            req_time for req_time in self.global_requests
            if current_time - req_time < 60
        ]
        
        return len(self.global_requests) < self.config.global_requests_per_minute
    
    def _check_user_limit(self, user_id: str, current_time: float) -> bool:
        """Check user-based rate limit"""
        user_requests = self.user_requests[user_id]
        
        # Remove requests older than 1 minute
        recent_requests = [
            req_time for req_time in user_requests
            if current_time - req_time < 60
        ]
        
        return len(recent_requests) < self.config.user_requests_per_minute
    
    def _check_ip_limit(self, client_ip: str, current_time: float) -> bool:
        """Check IP-based rate limit"""
        ip_requests = self.ip_requests[client_ip]
        
        # Remove requests older than 1 minute
        recent_requests = [
            req_time for req_time in ip_requests
            if current_time - req_time < 60
        ]
        
        return len(recent_requests) < self.config.ip_requests_per_minute
    
    def _calculate_retry_after_global(self, current_time: float) -> int:
        """Calculate retry-after time for global limit"""
        if not self.global_requests:
            return 60
        
        oldest_request = min(self.global_requests)
        return max(1, int(60 - (current_time - oldest_request)))
    
    def _calculate_retry_after_user(self, user_id: str, current_time: float) -> int:
        """Calculate retry-after time for user limit"""
        user_requests = self.user_requests[user_id]
        if not user_requests:
            return 60
        
        oldest_request = min(user_requests)
        return max(1, int(60 - (current_time - oldest_request)))
    
    def _calculate_retry_after_ip(self, client_ip: str, current_time: float) -> int:
        """Calculate retry-after time for IP limit"""
        ip_requests = self.ip_requests[client_ip]
        if not ip_requests:
            return 60
        
        oldest_request = min(ip_requests)
        return max(1, int(60 - (current_time - oldest_request)))
    
    def _record_request(self, client_ip: str, user_id: Optional[str], current_time: float):
        """Record a request for rate limiting"""
        self.global_requests.append(current_time)
        
        if user_id:
            self.user_requests[user_id].append(current_time)
        else:
            self.ip_requests[client_ip].append(current_time)
    
    def check_concurrent_jobs(self) -> Tuple[bool, Optional[str]]:
        """
        Check if we can accept more concurrent jobs
        
        Returns:
            Tuple of (can_accept: bool, reason: Optional[str])
        """
        with self.lock:
            if self.active_jobs >= self.config.global_concurrent_jobs:
                return False, f"Maximum concurrent jobs ({self.config.global_concurrent_jobs}) reached"
            return True, None
    
    def increment_active_jobs(self):
        """Increment active jobs counter"""
        with self.lock:
            self.active_jobs += 1
    
    def decrement_active_jobs(self):
        """Decrement active jobs counter"""
        with self.lock:
            self.active_jobs = max(0, self.active_jobs - 1)
    
    def get_rate_limit_headers(self, request: Request) -> Dict[str, str]:
        """
        Get rate limit headers for response
        
        Args:
            request: FastAPI request object
            
        Returns:
            Dictionary of rate limit headers
        """
        current_time = time.time()
        client_ip = self._get_client_ip(request)
        user_id = self._get_user_id(request)
        
        with self.lock:
            if user_id:
                # User-based limits
                user_requests = self.user_requests[user_id]
                recent_requests = [
                    req_time for req_time in user_requests
                    if current_time - req_time < 60
                ]
                remaining = max(0, self.config.user_requests_per_minute - len(recent_requests))
                limit = self.config.user_requests_per_minute
            else:
                # IP-based limits
                ip_requests = self.ip_requests[client_ip]
                recent_requests = [
                    req_time for req_time in ip_requests
                    if current_time - req_time < 60
                ]
                remaining = max(0, self.config.ip_requests_per_minute - len(recent_requests))
                limit = self.config.ip_requests_per_minute
            
            # Calculate reset time
            if recent_requests:
                reset_time = int(min(recent_requests) + 60)
            else:
                reset_time = int(current_time + 60)
            
            return {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset_time)
            }


# Global rate limit manager instance
_rate_limit_manager: Optional[RateLimitManager] = None


def get_rate_limit_manager() -> RateLimitManager:
    """
    Get global rate limit manager instance
    
    Returns:
        Rate limit manager instance
    """
    global _rate_limit_manager
    
    if _rate_limit_manager is None:
        _rate_limit_manager = RateLimitManager()
    
    return _rate_limit_manager


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """
    Custom handler for rate limit exceeded exceptions
    
    Args:
        request: FastAPI request object
        exc: Rate limit exceeded exception
        
    Returns:
        HTTP 429 response with proper headers
    """
    rate_limit_manager = get_rate_limit_manager()
    client_ip = rate_limit_manager._get_client_ip(request)
    user_id = rate_limit_manager._get_user_id(request)
    
    # Calculate retry-after time
    current_time = time.time()
    if user_id:
        retry_after = rate_limit_manager._calculate_retry_after_user(user_id, current_time)
    else:
        retry_after = rate_limit_manager._calculate_retry_after_ip(client_ip, current_time)
    
    # Get rate limit headers
    headers = rate_limit_manager.get_rate_limit_headers(request)
    headers["Retry-After"] = str(retry_after)
    
    # Create error response
    error_response = {
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please try again later.",
        "retry_after": retry_after,
        "limit_type": "user" if user_id else "ip"
    }
    
    logger.warning(f"Rate limit exceeded for {user_id or client_ip}")
    
    return JSONResponse(
        status_code=429,
        content=error_response,
        headers=headers
    )
