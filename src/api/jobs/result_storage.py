"""
Enhanced job result storage with 24-hour expiration and advanced features

Provides comprehensive result storage capabilities including compression,
archival, sharing, and efficient retrieval with proper TTL management.
"""

import json
import gzip
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from enum import Enum
from dataclasses import dataclass, field
import hashlib
import base64

from ..models import AnalysisResult, JobStatus
from ..config import RedisManager, redis_config
from ..utils.exceptions import JobNotFoundError
from .job_storage import JobStorageKeys

logger = logging.getLogger(__name__)


class StorageFormat(str, Enum):
    """Storage format options for results"""
    JSON = "json"
    COMPRESSED_JSON = "compressed_json"
    BINARY = "binary"


class ResultAccessLevel(str, Enum):
    """Access levels for result sharing"""
    PRIVATE = "private"      # Only accessible by job creator
    SHARED = "shared"        # Accessible via share token
    PUBLIC = "public"        # Publicly accessible (for badges, etc.)
    ARCHIVED = "archived"    # Moved to long-term storage


@dataclass
class ResultMetadata:
    """Metadata about stored results"""
    job_id: str
    storage_format: StorageFormat
    compressed_size: int
    uncompressed_size: int
    stored_at: datetime
    expires_at: datetime
    access_level: ResultAccessLevel
    share_token: Optional[str] = None
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    checksum: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            "job_id": self.job_id,
            "storage_format": self.storage_format.value,
            "compressed_size": self.compressed_size,
            "uncompressed_size": self.uncompressed_size,
            "stored_at": self.stored_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "access_level": self.access_level.value,
            "share_token": self.share_token,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed.isoformat() if self.last_accessed else None,
            "checksum": self.checksum
        }


class EnhancedResultStorage:
    """
    Enhanced result storage with 24-hour expiration and advanced features
    
    Features:
    - Automatic compression for large results
    - Share tokens for result sharing
    - Result archival and cleanup
    - Access tracking and analytics
    - Integrity verification with checksums
    - Multiple storage formats
    """
    
    def __init__(self, redis_manager: RedisManager):
        self.redis_manager = redis_manager
        self.result_client = redis_manager.get_result_client()
        
        # Configuration
        self.result_ttl = redis_config.job_result_ttl  # 24 hours
        self.compression_threshold = 1024 * 50  # 50KB - compress if larger
        self.max_result_size = 1024 * 1024 * 10  # 10MB max result size
        
        # Redis keys
        self.result_key_prefix = "result:data:"
        self.metadata_key_prefix = "result:meta:"
        self.share_key_prefix = "result:share:"
        self.access_log_prefix = "result:access:"
        self.stats_key = "result:stats"
        
        logger.info(f"EnhancedResultStorage initialized with {self.result_ttl}s TTL (24 hours)")
    
    def store_result(self, job_id: str, result: AnalysisResult, 
                    access_level: ResultAccessLevel = ResultAccessLevel.PRIVATE,
                    enable_sharing: bool = False) -> str:
        """
        Store analysis result with compression and metadata
        
        Args:
            job_id: Job identifier
            result: Analysis result to store
            access_level: Access level for the result
            enable_sharing: Whether to generate a share token
            
        Returns:
            Storage key or share token
            
        Raises:
            JobStorageError: If storage fails
        """
        try:
            # Serialize result
            result_json = result.json()
            result_data = result_json.encode('utf-8')
            uncompressed_size = len(result_data)
            
            # Check size limits
            if uncompressed_size > self.max_result_size:
                raise JobStorageError(f"Result size ({uncompressed_size} bytes) exceeds maximum ({self.max_result_size} bytes)")
            
            # Determine storage format and compress if needed
            if uncompressed_size > self.compression_threshold:
                compressed_data = gzip.compress(result_data)
                storage_format = StorageFormat.COMPRESSED_JSON
                final_data = compressed_data
                compressed_size = len(compressed_data)
            else:
                storage_format = StorageFormat.JSON
                final_data = result_data
                compressed_size = uncompressed_size
            
            # Generate checksum
            checksum = hashlib.sha256(final_data).hexdigest()
            
            # Generate share token if requested
            share_token = None
            if enable_sharing or access_level in [ResultAccessLevel.SHARED, ResultAccessLevel.PUBLIC]:
                share_token = self._generate_share_token(job_id)
            
            # Create metadata
            now = datetime.utcnow()
            expires_at = now + timedelta(seconds=self.result_ttl)
            
            metadata = ResultMetadata(
                job_id=job_id,
                storage_format=storage_format,
                compressed_size=compressed_size,
                uncompressed_size=uncompressed_size,
                stored_at=now,
                expires_at=expires_at,
                access_level=access_level,
                share_token=share_token,
                checksum=checksum
            )
            
            # Store result data and metadata atomically
            pipe = self.result_client.pipeline()
            
            # Store result data
            result_key = f"{self.result_key_prefix}{job_id}"
            pipe.setex(result_key, self.result_ttl, final_data)
            
            # Store metadata
            metadata_key = f"{self.metadata_key_prefix}{job_id}"
            pipe.setex(metadata_key, self.result_ttl, json.dumps(metadata.to_dict()))
            
            # Store share token mapping if applicable
            if share_token:
                share_key = f"{self.share_key_prefix}{share_token}"
                pipe.setex(share_key, self.result_ttl, job_id)
            
            # Update storage statistics
            pipe.hincrby(self.stats_key, "total_results_stored", 1)
            pipe.hincrby(self.stats_key, "total_bytes_stored", compressed_size)
            
            # Execute pipeline
            pipe.execute()
            
            # Log storage
            compression_ratio = compressed_size / uncompressed_size if uncompressed_size > 0 else 1.0
            logger.info(f"Stored result for job {job_id}: {compressed_size} bytes ({compression_ratio:.2f} compression ratio)")
            
            return share_token if share_token else job_id
            
        except Exception as e:
            logger.error(f"Failed to store result for job {job_id}: {e}")
            raise JobStorageError(f"Failed to store result: {str(e)}")
    
    def get_result(self, identifier: str, track_access: bool = True) -> AnalysisResult:
        """
        Retrieve analysis result by job ID or share token
        
        Args:
            identifier: Job ID or share token
            track_access: Whether to track this access
            
        Returns:
            Analysis result
            
        Raises:
            JobNotFoundError: If result not found
            JobStorageError: If retrieval fails
        """
        try:
            # Resolve identifier to job_id
            job_id = self._resolve_identifier(identifier)
            
            # Get metadata
            metadata = self._get_result_metadata(job_id)
            
            # Get result data
            result_key = f"{self.result_key_prefix}{job_id}"
            result_data = self.result_client.get(result_key)
            
            if not result_data:
                raise JobNotFoundError(f"Result data not found for job {job_id}")
            
            # Verify checksum if available
            if metadata.checksum:
                actual_checksum = hashlib.sha256(result_data).hexdigest()
                if actual_checksum != metadata.checksum:
                    logger.error(f"Checksum mismatch for job {job_id}: expected {metadata.checksum}, got {actual_checksum}")
                    raise JobStorageError("Result data integrity check failed")
            
            # Decompress if needed
            if metadata.storage_format == StorageFormat.COMPRESSED_JSON:
                try:
                    decompressed_data = gzip.decompress(result_data)
                    result_json = decompressed_data.decode('utf-8')
                except Exception as e:
                    raise JobStorageError(f"Failed to decompress result data: {str(e)}")
            else:
                result_json = result_data.decode('utf-8')
            
            # Parse result
            try:
                result = AnalysisResult.parse_raw(result_json)
            except Exception as e:
                raise JobStorageError(f"Failed to parse result data: {str(e)}")
            
            # Track access
            if track_access:
                self._track_access(job_id, identifier)
            
            return result
            
        except (JobNotFoundError, JobStorageError):
            raise
        except Exception as e:
            logger.error(f"Failed to get result for identifier {identifier}: {e}")
            raise JobStorageError(f"Failed to retrieve result: {str(e)}")
    
    def get_result_metadata(self, identifier: str) -> ResultMetadata:
        """
        Get result metadata by job ID or share token
        
        Args:
            identifier: Job ID or share token
            
        Returns:
            Result metadata
        """
        job_id = self._resolve_identifier(identifier)
        return self._get_result_metadata(job_id)
    
    def delete_result(self, job_id: str) -> bool:
        """
        Delete a stored result
        
        Args:
            job_id: Job identifier
            
        Returns:
            True if deleted, False if not found
        """
        try:
            # Get metadata to check for share token
            try:
                metadata = self._get_result_metadata(job_id)
                share_token = metadata.share_token
            except JobNotFoundError:
                share_token = None
            
            # Delete all associated keys
            pipe = self.result_client.pipeline()
            
            result_key = f"{self.result_key_prefix}{job_id}"
            metadata_key = f"{self.metadata_key_prefix}{job_id}"
            access_log_key = f"{self.access_log_prefix}{job_id}"
            
            pipe.delete(result_key)
            pipe.delete(metadata_key)
            pipe.delete(access_log_key)
            
            if share_token:
                share_key = f"{self.share_key_prefix}{share_token}"
                pipe.delete(share_key)
            
            # Update statistics
            pipe.hincrby(self.stats_key, "total_results_deleted", 1)
            
            results = pipe.execute()
            
            # Check if anything was actually deleted
            deleted = any(result > 0 for result in results[:3])  # First 3 deletes
            
            if deleted:
                logger.info(f"Deleted result for job {job_id}")
            
            return deleted
            
        except Exception as e:
            logger.error(f"Failed to delete result for job {job_id}: {e}")
            return False
    
    def create_share_token(self, job_id: str) -> str:
        """
        Create a share token for an existing result
        
        Args:
            job_id: Job identifier
            
        Returns:
            Share token
        """
        try:
            # Verify result exists
            metadata = self._get_result_metadata(job_id)
            
            # Generate new share token if one doesn't exist
            if not metadata.share_token:
                share_token = self._generate_share_token(job_id)
                
                # Update metadata
                metadata.share_token = share_token
                metadata.access_level = ResultAccessLevel.SHARED
                
                # Store updated metadata and share mapping
                pipe = self.result_client.pipeline()
                
                metadata_key = f"{self.metadata_key_prefix}{job_id}"
                pipe.setex(metadata_key, self.result_ttl, json.dumps(metadata.to_dict()))
                
                share_key = f"{self.share_key_prefix}{share_token}"
                pipe.setex(share_key, self.result_ttl, job_id)
                
                pipe.execute()
                
                logger.info(f"Created share token for job {job_id}")
                return share_token
            else:
                return metadata.share_token
                
        except Exception as e:
            logger.error(f"Failed to create share token for job {job_id}: {e}")
            raise JobStorageError(f"Failed to create share token: {str(e)}")
    
    def get_storage_statistics(self) -> Dict[str, Any]:
        """
        Get storage statistics and metrics
        
        Returns:
            Dictionary with storage statistics
        """
        try:
            stats = self.result_client.hgetall(self.stats_key)
            
            # Convert byte strings to appropriate types
            cleaned_stats = {}
            for key, value in stats.items():
                key_str = key.decode('utf-8') if isinstance(key, bytes) else key
                value_str = value.decode('utf-8') if isinstance(value, bytes) else value
                
                try:
                    cleaned_stats[key_str] = int(value_str)
                except ValueError:
                    cleaned_stats[key_str] = value_str
            
            # Calculate additional metrics
            total_stored = cleaned_stats.get("total_results_stored", 0)
            total_bytes = cleaned_stats.get("total_bytes_stored", 0)
            
            if total_stored > 0:
                avg_size = total_bytes / total_stored
            else:
                avg_size = 0
            
            return {
                "total_results_stored": total_stored,
                "total_results_deleted": cleaned_stats.get("total_results_deleted", 0),
                "total_bytes_stored": total_bytes,
                "average_result_size": avg_size,
                "storage_efficiency": {
                    "compression_threshold": self.compression_threshold,
                    "max_result_size": self.max_result_size,
                    "default_ttl_hours": self.result_ttl / 3600
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get storage statistics: {e}")
            return {"error": str(e)}
    
    def cleanup_expired_results(self) -> int:
        """
        Clean up expired results (Redis TTL handles most of this)
        
        Returns:
            Number of results cleaned up
        """
        # Redis automatically handles TTL cleanup, but we can do additional maintenance
        try:
            cleanup_count = 0
            
            # This could be enhanced with more sophisticated cleanup logic
            # For now, rely on Redis TTL
            
            logger.info(f"Result cleanup completed: {cleanup_count} additional items cleaned")
            return cleanup_count
            
        except Exception as e:
            logger.error(f"Error during result cleanup: {e}")
            return 0
    
    def _resolve_identifier(self, identifier: str) -> str:
        """Resolve identifier to job_id (handle both job_id and share tokens)"""
        # Check if it's a share token
        share_key = f"{self.share_key_prefix}{identifier}"
        job_id = self.result_client.get(share_key)
        
        if job_id:
            return job_id.decode('utf-8') if isinstance(job_id, bytes) else job_id
        else:
            # Assume it's a job_id
            return identifier
    
    def _get_result_metadata(self, job_id: str) -> ResultMetadata:
        """Get result metadata from Redis"""
        metadata_key = f"{self.metadata_key_prefix}{job_id}"
        metadata_data = self.result_client.get(metadata_key)
        
        if not metadata_data:
            raise JobNotFoundError(f"Result metadata not found for job {job_id}")
        
        try:
            metadata_dict = json.loads(metadata_data)
            
            # Parse dates
            stored_at = datetime.fromisoformat(metadata_dict["stored_at"])
            expires_at = datetime.fromisoformat(metadata_dict["expires_at"])
            last_accessed = None
            if metadata_dict.get("last_accessed"):
                last_accessed = datetime.fromisoformat(metadata_dict["last_accessed"])
            
            return ResultMetadata(
                job_id=metadata_dict["job_id"],
                storage_format=StorageFormat(metadata_dict["storage_format"]),
                compressed_size=metadata_dict["compressed_size"],
                uncompressed_size=metadata_dict["uncompressed_size"],
                stored_at=stored_at,
                expires_at=expires_at,
                access_level=ResultAccessLevel(metadata_dict["access_level"]),
                share_token=metadata_dict.get("share_token"),
                access_count=metadata_dict.get("access_count", 0),
                last_accessed=last_accessed,
                checksum=metadata_dict.get("checksum")
            )
            
        except Exception as e:
            raise JobStorageError(f"Failed to parse result metadata: {str(e)}")
    
    def _generate_share_token(self, job_id: str) -> str:
        """Generate a unique share token"""
        # Create a hash of job_id + timestamp + random component
        import secrets
        timestamp = str(int(datetime.utcnow().timestamp()))
        random_part = secrets.token_hex(8)
        token_source = f"{job_id}:{timestamp}:{random_part}"
        
        # Generate token
        token_hash = hashlib.sha256(token_source.encode()).hexdigest()[:16]
        return f"share_{token_hash}"
    
    def _track_access(self, job_id: str, identifier: str) -> None:
        """Track result access for analytics"""
        try:
            now = datetime.utcnow()
            
            # Update metadata access count and timestamp
            metadata = self._get_result_metadata(job_id)
            metadata.access_count += 1
            metadata.last_accessed = now
            
            # Store updated metadata
            metadata_key = f"{self.metadata_key_prefix}{job_id}"
            self.result_client.setex(metadata_key, self.result_ttl, json.dumps(metadata.to_dict()))
            
            # Log access
            access_log_key = f"{self.access_log_prefix}{job_id}"
            access_entry = {
                "timestamp": now.isoformat(),
                "identifier": identifier,
                "access_count": metadata.access_count
            }
            
            # Keep last 10 access entries
            self.result_client.lpush(access_log_key, json.dumps(access_entry))
            self.result_client.ltrim(access_log_key, 0, 9)
            self.result_client.expire(access_log_key, self.result_ttl)
            
        except Exception as e:
            logger.debug(f"Failed to track access for job {job_id}: {e}")
            # Don't raise - access tracking shouldn't break result retrieval
