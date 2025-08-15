"""
Configuration management for Caponier API

Handles Redis connection, Celery configuration, and environment settings
for job queue management and asynchronous processing.
"""

import os
from typing import Optional
from pydantic import BaseSettings, Field, validator
import redis
from celery import Celery
import logging

logger = logging.getLogger(__name__)


class RedisConfig(BaseSettings):
    """Redis connection configuration"""
    
    # Redis connection settings
    redis_host: str = Field(default="localhost", description="Redis server hostname")
    redis_port: int = Field(default=6379, description="Redis server port")
    redis_db: int = Field(default=0, description="Redis database number")
    redis_password: Optional[str] = Field(default=None, description="Redis password")
    redis_ssl: bool = Field(default=False, description="Use SSL for Redis connection")
    redis_ssl_cert_reqs: Optional[str] = Field(default=None, description="SSL certificate requirements")
    
    # Connection pool settings
    redis_max_connections: int = Field(default=20, description="Maximum Redis connections in pool")
    redis_socket_timeout: int = Field(default=5, description="Redis socket timeout in seconds")
    redis_socket_connect_timeout: int = Field(default=5, description="Redis connection timeout in seconds")
    redis_retry_on_timeout: bool = Field(default=True, description="Retry on timeout")
    
    # Job queue settings
    redis_job_queue_db: int = Field(default=1, description="Redis database for job queue")
    redis_result_db: int = Field(default=2, description="Redis database for results")
    redis_progress_db: int = Field(default=3, description="Redis database for progress tracking")
    
    # TTL settings (in seconds)
    job_result_ttl: int = Field(default=86400, description="Job result TTL (24 hours)")
    job_progress_ttl: int = Field(default=3600, description="Job progress TTL (1 hour)")
    job_lock_ttl: int = Field(default=300, description="Job lock TTL (5 minutes)")
    
    class Config:
        env_prefix = "REDIS_"
        case_sensitive = False
    
    @validator("redis_port")
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError("Redis port must be between 1 and 65535")
        return v
    
    @validator("redis_db", "redis_job_queue_db", "redis_result_db", "redis_progress_db")
    def validate_db_number(cls, v):
        if not 0 <= v <= 15:
            raise ValueError("Redis database number must be between 0 and 15")
        return v
    
    def get_redis_url(self, db: Optional[int] = None) -> str:
        """
        Generate Redis URL for connection
        
        Args:
            db: Database number to use (defaults to redis_db)
            
        Returns:
            Redis connection URL
        """
        db = db if db is not None else self.redis_db
        
        # Build the base URL
        if self.redis_password:
            auth = f":{self.redis_password}@"
        else:
            auth = ""
        
        protocol = "rediss" if self.redis_ssl else "redis"
        
        return f"{protocol}://{auth}{self.redis_host}:{self.redis_port}/{db}"
    
    def get_connection_kwargs(self, db: Optional[int] = None) -> dict:
        """
        Get Redis connection parameters as dictionary
        
        Args:
            db: Database number to use (defaults to redis_db)
            
        Returns:
            Dictionary of connection parameters
        """
        db = db if db is not None else self.redis_db
        
        kwargs = {
            "host": self.redis_host,
            "port": self.redis_port,
            "db": db,
            "socket_timeout": self.redis_socket_timeout,
            "socket_connect_timeout": self.redis_socket_connect_timeout,
            "retry_on_timeout": self.redis_retry_on_timeout,
            "max_connections": self.redis_max_connections,
        }
        
        if self.redis_password:
            kwargs["password"] = self.redis_password
        
        if self.redis_ssl:
            kwargs["ssl"] = True
            if self.redis_ssl_cert_reqs:
                kwargs["ssl_cert_reqs"] = self.redis_ssl_cert_reqs
        
        return kwargs


class CeleryConfig(BaseSettings):
    """Celery configuration for background job processing"""
    
    # Celery basic settings
    celery_broker_url: Optional[str] = Field(default=None, description="Celery broker URL")
    celery_result_backend: Optional[str] = Field(default=None, description="Celery result backend URL")
    celery_task_serializer: str = Field(default="json", description="Task serialization format")
    celery_result_serializer: str = Field(default="json", description="Result serialization format")
    celery_accept_content: list = Field(default=["json"], description="Accepted content types")
    celery_timezone: str = Field(default="UTC", description="Celery timezone")
    celery_enable_utc: bool = Field(default=True, description="Enable UTC timezone")
    
    # Task routing and execution
    celery_task_routes: dict = Field(default_factory=dict, description="Task routing configuration")
    celery_worker_prefetch_multiplier: int = Field(default=1, description="Worker prefetch multiplier")
    celery_task_acks_late: bool = Field(default=True, description="Late task acknowledgment")
    celery_worker_disable_rate_limits: bool = Field(default=False, description="Disable rate limits")
    
    # Retry and timeout settings
    celery_task_default_retry_delay: int = Field(default=60, description="Default retry delay in seconds")
    celery_task_max_retries: int = Field(default=3, description="Maximum number of retries")
    celery_task_soft_time_limit: int = Field(default=300, description="Soft time limit in seconds (5 minutes)")
    celery_task_time_limit: int = Field(default=360, description="Hard time limit in seconds (6 minutes)")
    
    # Result backend settings
    celery_result_expires: int = Field(default=86400, description="Result expiration time (24 hours)")
    celery_result_persistent: bool = Field(default=True, description="Persist results")
    
    class Config:
        env_prefix = "CELERY_"
        case_sensitive = False


class ApplicationConfig(BaseSettings):
    """Main application configuration"""
    
    # Environment
    environment: str = Field(default="development", description="Application environment")
    debug: bool = Field(default=False, description="Debug mode")
    
    # API settings
    api_host: str = Field(default="0.0.0.0", description="API host")
    api_port: int = Field(default=8000, description="API port")
    api_workers: int = Field(default=1, description="Number of API workers")
    
    # Security
    secret_key: str = Field(default="dev-secret-key-change-in-production", description="Application secret key")
    
    # External services
    github_token: Optional[str] = Field(default=None, description="GitHub API token")
    nvd_api_key: Optional[str] = Field(default=None, description="NVD API key")
    
    # Job processing
    max_concurrent_jobs: int = Field(default=10, description="Maximum concurrent analysis jobs")
    job_cleanup_interval: int = Field(default=3600, description="Job cleanup interval in seconds")
    
    class Config:
        env_prefix = "APP_"
        case_sensitive = False
    
    @validator("environment")
    def validate_environment(cls, v):
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"Environment must be one of {allowed}")
        return v


# Global configuration instances
redis_config = RedisConfig()
celery_config = CeleryConfig()
app_config = ApplicationConfig()


class RedisManager:
    """Redis connection manager with connection pooling and error handling"""
    
    def __init__(self, config: RedisConfig):
        self.config = config
        self._connections = {}
        self._connection_pools = {}
    
    def get_connection_pool(self, db: Optional[int] = None) -> redis.ConnectionPool:
        """
        Get or create a Redis connection pool for specific database
        
        Args:
            db: Database number
            
        Returns:
            Redis connection pool
        """
        db = db if db is not None else self.config.redis_db
        
        if db not in self._connection_pools:
            kwargs = self.config.get_connection_kwargs(db)
            self._connection_pools[db] = redis.ConnectionPool(**kwargs)
            logger.info(f"Created Redis connection pool for database {db}")
        
        return self._connection_pools[db]
    
    def get_redis_client(self, db: Optional[int] = None) -> redis.Redis:
        """
        Get Redis client for specific database
        
        Args:
            db: Database number
            
        Returns:
            Redis client instance
        """
        db = db if db is not None else self.config.redis_db
        
        if db not in self._connections:
            pool = self.get_connection_pool(db)
            self._connections[db] = redis.Redis(connection_pool=pool)
            logger.info(f"Created Redis client for database {db}")
        
        return self._connections[db]
    
    def get_job_queue_client(self) -> redis.Redis:
        """Get Redis client for job queue operations"""
        return self.get_redis_client(self.config.redis_job_queue_db)
    
    def get_result_client(self) -> redis.Redis:
        """Get Redis client for result storage"""
        return self.get_redis_client(self.config.redis_result_db)
    
    def get_progress_client(self) -> redis.Redis:
        """Get Redis client for progress tracking"""
        return self.get_redis_client(self.config.redis_progress_db)
    
    async def health_check(self) -> dict:
        """
        Perform health check on Redis connections
        
        Returns:
            Dictionary with health status for each database
        """
        health_status = {}
        
        # Check each configured database
        databases = {
            "main": self.config.redis_db,
            "job_queue": self.config.redis_job_queue_db,
            "results": self.config.redis_result_db,
            "progress": self.config.redis_progress_db
        }
        
        for db_name, db_num in databases.items():
            try:
                client = self.get_redis_client(db_num)
                await client.ping()
                health_status[db_name] = "healthy"
                logger.debug(f"Redis {db_name} database ({db_num}) is healthy")
            except Exception as e:
                health_status[db_name] = f"unhealthy: {str(e)}"
                logger.error(f"Redis {db_name} database ({db_num}) health check failed: {e}")
        
        return health_status
    
    def close_connections(self):
        """Close all Redis connections and pools"""
        for db, client in self._connections.items():
            try:
                client.close()
                logger.info(f"Closed Redis client for database {db}")
            except Exception as e:
                logger.error(f"Error closing Redis client for database {db}: {e}")
        
        for db, pool in self._connection_pools.items():
            try:
                pool.disconnect()
                logger.info(f"Disconnected Redis pool for database {db}")
            except Exception as e:
                logger.error(f"Error disconnecting Redis pool for database {db}: {e}")
        
        self._connections.clear()
        self._connection_pools.clear()


def create_celery_app() -> Celery:
    """
    Create and configure Celery application
    
    Returns:
        Configured Celery application instance
    """
    # Set broker and backend URLs if not explicitly configured
    if not celery_config.celery_broker_url:
        celery_config.celery_broker_url = redis_config.get_redis_url(redis_config.redis_job_queue_db)
    
    if not celery_config.celery_result_backend:
        celery_config.celery_result_backend = redis_config.get_redis_url(redis_config.redis_result_db)
    
    # Create Celery app
    celery_app = Celery("caponier")
    
    # Configure Celery
    celery_app.conf.update(
        broker_url=celery_config.celery_broker_url,
        result_backend=celery_config.celery_result_backend,
        task_serializer=celery_config.celery_task_serializer,
        result_serializer=celery_config.celery_result_serializer,
        accept_content=celery_config.celery_accept_content,
        timezone=celery_config.celery_timezone,
        enable_utc=celery_config.celery_enable_utc,
        task_routes=celery_config.celery_task_routes,
        worker_prefetch_multiplier=celery_config.celery_worker_prefetch_multiplier,
        task_acks_late=celery_config.celery_task_acks_late,
        worker_disable_rate_limits=celery_config.celery_worker_disable_rate_limits,
        task_default_retry_delay=celery_config.celery_task_default_retry_delay,
        task_max_retries=celery_config.celery_task_max_retries,
        task_soft_time_limit=celery_config.celery_task_soft_time_limit,
        task_time_limit=celery_config.celery_task_time_limit,
        result_expires=celery_config.celery_result_expires,
        result_persistent=celery_config.celery_result_persistent,
    )
    
    logger.info("Celery application configured successfully")
    logger.info(f"Broker URL: {celery_config.celery_broker_url}")
    logger.info(f"Result Backend: {celery_config.celery_result_backend}")
    
    return celery_app


# Global instances
redis_manager = RedisManager(redis_config)
celery_app = create_celery_app()


def get_redis_manager() -> RedisManager:
    """Dependency injection for Redis manager"""
    return redis_manager


def get_celery_app() -> Celery:
    """Dependency injection for Celery app"""
    return celery_app
