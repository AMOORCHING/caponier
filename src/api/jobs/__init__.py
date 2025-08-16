"""
Background job processing package for Caponier

Handles asynchronous repository analysis tasks using Celery and Redis.
"""

from .job_manager import JobManager
from .job_storage import JobStorage
from .worker import WorkerManager, get_worker_manager
from .status_tracker import EnhancedStatusTracker, JobStatusAnalytics
from .timeout_manager import TimeoutManager, TimeoutConfig, get_timeout_manager
from .result_storage import EnhancedResultStorage, ResultMetadata, StorageFormat, ResultAccessLevel
from .retry_manager import RetryManager, RetryConfig, FailureCategory, ErrorClassifier, get_retry_manager
from .concurrency_manager import ConcurrencyManager, ConcurrencyConfig, JobPriority, WorkerPool, get_concurrency_manager
from .tasks import (
    analyze_repository_task,
    scan_dependencies_task,
    check_vulnerabilities_task,
    cleanup_jobs_task,
    health_check_task,
    simple_test_task,
    schedule_repository_analysis,
    schedule_maintenance_tasks,
    get_task_status,
    revoke_task
)

__all__ = [
    "JobManager", 
    "JobStorage",
    "WorkerManager",
    "get_worker_manager",
    "EnhancedStatusTracker",
    "JobStatusAnalytics",
    "TimeoutManager",
    "TimeoutConfig", 
    "get_timeout_manager",
    "EnhancedResultStorage",
    "ResultMetadata",
    "StorageFormat",
    "ResultAccessLevel",
    "RetryManager",
    "RetryConfig",
    "FailureCategory",
    "ErrorClassifier",
    "get_retry_manager",
    "ConcurrencyManager",
    "ConcurrencyConfig",
    "JobPriority",
    "WorkerPool",
    "get_concurrency_manager",
    "analyze_repository_task",
    "scan_dependencies_task", 
    "check_vulnerabilities_task",
    "cleanup_jobs_task",
    "health_check_task",
    "simple_test_task",
    "schedule_repository_analysis",
    "schedule_maintenance_tasks",
    "get_task_status",
    "revoke_task"
]
