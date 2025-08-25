"""
WebSocket authentication and authorization module

Handles job ID validation, access control, and authentication for WebSocket connections.
"""

import re
import hashlib
import hmac
import time
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from fastapi import WebSocket, HTTPException
import logging

logger = logging.getLogger(__name__)


class WebSocketAuthManager:
    """
    Manages WebSocket authentication and authorization.
    
    Handles:
    - Job ID validation and format checking
    - Access control and authorization
    - Rate limiting for WebSocket connections
    - Security token validation
    """
    
    def __init__(self):
        """Initialize the authentication manager."""
        # Job ID validation patterns
        self.job_id_pattern = re.compile(r'^[a-f0-9]{32,64}$')  # UUID or hash-like format
        self.max_connections_per_job = 10  # Maximum connections per job
        self.connection_rate_limit = 5  # Connections per minute per IP
        self.token_expiry_hours = 24  # Token expiry time
        
        # Track connections for rate limiting
        self.job_connections: Dict[str, int] = {}
        self.ip_connections: Dict[str, list] = {}
        
        # Security configuration
        self.require_authentication = True
        self.allowed_origins = [
            "http://localhost:3000",
            "http://localhost:3001",
            "https://caponier.io",
            "https://www.caponier.io"
        ]
    
    def validate_job_id(self, job_id: str) -> Tuple[bool, str]:
        """
        Validate job ID format and structure.
        
        Args:
            job_id: The job ID to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not job_id:
            return False, "Job ID is required"
        
        if len(job_id) < 32:
            return False, "Job ID must be at least 32 characters long"
        
        if len(job_id) > 64:
            return False, "Job ID must be no more than 64 characters long"
        
        if not self.job_id_pattern.match(job_id):
            return False, "Job ID must contain only hexadecimal characters (a-f, 0-9)"
        
        # Check for suspicious patterns
        if self._contains_suspicious_patterns(job_id):
            return False, "Job ID contains suspicious patterns"
        
        return True, ""
    
    def _contains_suspicious_patterns(self, job_id: str) -> bool:
        """
        Check for suspicious patterns in job ID.
        
        Args:
            job_id: The job ID to check
            
        Returns:
            bool: True if suspicious patterns found
        """
        suspicious_patterns = [
            r'\.\.',  # Directory traversal
            r'[<>"\']',  # HTML/script injection
            r'javascript:',  # JavaScript injection
            r'data:',  # Data URL injection
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, job_id, re.IGNORECASE):
                return True
        
        return False
    
    async def validate_job_access(self, job_id: str, client_ip: str) -> Tuple[bool, str]:
        """
        Validate access to a specific job.
        
        Args:
            job_id: The job ID
            client_ip: Client IP address
            
        Returns:
            Tuple of (has_access, error_message)
        """
        # Check rate limiting
        if not self._check_rate_limit(client_ip):
            return False, "Rate limit exceeded for WebSocket connections"
        
        # Check job connection limit
        if not self._check_job_connection_limit(job_id):
            return False, "Maximum connections reached for this job"
        
        # Validate job exists and is accessible
        try:
            from ..jobs.job_manager import job_manager
            job_status = await job_manager.get_job_status(job_id)
            
            if not job_status:
                return False, "Job not found or access denied"
            
            # Check if job is still active (not completed for too long)
            if self._is_job_expired(job_status):
                return False, "Job has expired or is no longer accessible"
            
            return True, ""
            
        except Exception as e:
            logger.error(f"Error validating job access for {job_id}: {e}")
            return False, "Error validating job access"
    
    def _check_rate_limit(self, client_ip: str) -> bool:
        """
        Check rate limiting for client IP.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            bool: True if within rate limit
        """
        now = datetime.utcnow()
        cutoff_time = now - timedelta(minutes=1)
        
        # Clean old entries
        if client_ip in self.ip_connections:
            self.ip_connections[client_ip] = [
                timestamp for timestamp in self.ip_connections[client_ip]
                if timestamp > cutoff_time
            ]
        
        # Check current connections
        current_connections = len(self.ip_connections.get(client_ip, []))
        if current_connections >= self.connection_rate_limit:
            return False
        
        # Add current connection
        if client_ip not in self.ip_connections:
            self.ip_connections[client_ip] = []
        self.ip_connections[client_ip].append(now)
        
        return True
    
    def _check_job_connection_limit(self, job_id: str) -> bool:
        """
        Check connection limit for a specific job.
        
        Args:
            job_id: The job ID
            
        Returns:
            bool: True if within connection limit
        """
        current_connections = self.job_connections.get(job_id, 0)
        if current_connections >= self.max_connections_per_job:
            return False
        
        self.job_connections[job_id] = current_connections + 1
        return True
    
    def _is_job_expired(self, job_status: Dict[str, Any]) -> bool:
        """
        Check if a job has expired.
        
        Args:
            job_status: Job status information
            
        Returns:
            bool: True if job has expired
        """
        # Jobs are considered expired after 24 hours
        max_age_hours = 24
        
        if "created_at" in job_status:
            try:
                created_at = datetime.fromisoformat(job_status["created_at"].replace("Z", "+00:00"))
                age = datetime.utcnow() - created_at.replace(tzinfo=None)
                return age.total_seconds() > (max_age_hours * 3600)
            except (ValueError, TypeError):
                pass
        
        return False
    
    def validate_origin(self, origin: str) -> bool:
        """
        Validate WebSocket origin.
        
        Args:
            origin: Origin header value
            
        Returns:
            bool: True if origin is allowed
        """
        if not origin:
            return False
        
        # Remove protocol if present
        origin = origin.replace("https://", "").replace("http://", "")
        
        for allowed_origin in self.allowed_origins:
            allowed = allowed_origin.replace("https://", "").replace("http://", "")
            if origin == allowed or origin.endswith("." + allowed):
                return True
        
        return False
    
    def generate_access_token(self, job_id: str, client_ip: str) -> str:
        """
        Generate a secure access token for WebSocket connection.
        
        Args:
            job_id: The job ID
            client_ip: Client IP address
            
        Returns:
            str: Access token
        """
        # Create token payload
        payload = {
            "job_id": job_id,
            "client_ip": client_ip,
            "timestamp": int(time.time()),
            "expires": int(time.time()) + (self.token_expiry_hours * 3600)
        }
        
        # Create signature
        secret = self._get_secret_key()
        message = f"{job_id}:{client_ip}:{payload['timestamp']}"
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        
        return f"{payload['timestamp']}.{signature}"
    
    def validate_access_token(self, token: str, job_id: str, client_ip: str) -> bool:
        """
        Validate an access token.
        
        Args:
            token: The access token
            job_id: The job ID
            client_ip: Client IP address
            
        Returns:
            bool: True if token is valid
        """
        try:
            if not token or "." not in token:
                return False
            
            timestamp_str, signature = token.split(".", 1)
            timestamp = int(timestamp_str)
            
            # Check if token has expired
            if timestamp + (self.token_expiry_hours * 3600) < int(time.time()):
                return False
            
            # Verify signature
            secret = self._get_secret_key()
            message = f"{job_id}:{client_ip}:{timestamp}"
            expected_signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except (ValueError, TypeError):
            return False
    
    def _get_secret_key(self) -> str:
        """
        Get secret key for token signing.
        
        Returns:
            str: Secret key
        """
        # In production, this should come from environment variables
        import os
        return os.getenv("WEBSOCKET_SECRET_KEY", "default-secret-key-change-in-production")
    
    def record_connection(self, job_id: str, client_ip: str) -> None:
        """
        Record a new WebSocket connection.
        
        Args:
            job_id: The job ID
            client_ip: Client IP address
        """
        logger.info(f"WebSocket connection established for job {job_id} from {client_ip}")
    
    def record_disconnection(self, job_id: str, client_ip: str) -> None:
        """
        Record a WebSocket disconnection.
        
        Args:
            job_id: The job ID
            client_ip: Client IP address
        """
        # Decrease connection count
        if job_id in self.job_connections:
            self.job_connections[job_id] = max(0, self.job_connections[job_id] - 1)
        
        logger.info(f"WebSocket connection closed for job {job_id} from {client_ip}")


# Global authentication manager instance
auth_manager = WebSocketAuthManager()


async def authenticate_websocket_connection(
    websocket: WebSocket, 
    job_id: str,
    token: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Authenticate a WebSocket connection.
    
    Args:
        websocket: The WebSocket connection
        job_id: The job ID
        token: Optional access token
        
    Returns:
        Tuple of (is_authenticated, error_message)
    """
    try:
        # Get client information
        client_ip = websocket.client.host if websocket.client else "unknown"
        origin = websocket.headers.get("origin", "")
        
        # Validate origin
        if not auth_manager.validate_origin(origin):
            return False, "Invalid origin"
        
        # Validate job ID format
        is_valid, error_msg = auth_manager.validate_job_id(job_id)
        if not is_valid:
            return False, error_msg
        
        # Validate access token if provided
        if token and not auth_manager.validate_access_token(token, job_id, client_ip):
            return False, "Invalid or expired access token"
        
        # Validate job access
        has_access, error_msg = await auth_manager.validate_job_access(job_id, client_ip)
        if not has_access:
            return False, error_msg
        
        # Record successful connection
        auth_manager.record_connection(job_id, client_ip)
        
        return True, ""
        
    except Exception as e:
        logger.error(f"Authentication error for job {job_id}: {e}")
        return False, "Authentication failed"
