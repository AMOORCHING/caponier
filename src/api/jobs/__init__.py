"""
Background job processing package for Caponier

Handles asynchronous repository analysis tasks using Celery and Redis.
"""

from .job_manager import JobManager
from .job_storage import JobStorage
from .worker import WorkerManager, get_worker_manager
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
