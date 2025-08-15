"""
Celery worker configuration and setup

Configures Celery workers for background repository analysis tasks with
proper task routing, error handling, and monitoring.
"""

import logging
import os
import signal
import sys
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from celery import Celery, Task
from celery.signals import (
    worker_ready, worker_shutdown, task_prerun, task_postrun, 
    task_failure, task_retry, task_success
)
from celery.exceptions import Retry, WorkerLostError

from ..config import celery_app, redis_manager, app_config
from ..jobs.job_manager import JobManager
from ..utils.exceptions import JobError, AnalysisError

logger = logging.getLogger(__name__)


class CaponierTask(Task):
    """
    Custom Celery task base class with enhanced error handling and retry logic
    
    Provides intelligent retry logic with error classification, automatic job 
    status updates, and comprehensive error tracking for all analysis tasks.
    """
    
    # Disable automatic retries - we'll handle them manually with RetryManager
    autoretry_for = ()
    retry_kwargs = {}
    
    def __init__(self):
        super().__init__()
        self.job_manager: Optional[JobManager] = None
        self.worker_id: Optional[str] = None
        self.retry_manager = None
    
    def get_retry_manager(self):
        """Get retry manager instance"""
        if self.retry_manager is None:
            from .retry_manager import get_retry_manager
            self.retry_manager = get_retry_manager()
        return self.retry_manager
    
    def handle_task_error(self, exc, job_id: str, stage: str = None):
        """
        Handle task errors with intelligent retry logic
        
        Args:
            exc: Exception that occurred
            job_id: Job identifier
            stage: Current analysis stage
            
        Raises:
            Retry: If task should be retried
            Exception: If task should fail permanently
        """
        try:
            retry_manager = self.get_retry_manager()
            attempt = self.request.retries
            
            should_retry, delay = retry_manager.should_retry(
                job_id=job_id,
                error=exc,
                attempt=attempt,
                task_name=self.name,
                stage=stage
            )
            
            if should_retry:
                # Update job progress to show retry
                if self.job_manager:
                    try:
                        self.job_manager.update_job_progress(
                            job_id=job_id,
                            progress_percentage=0,
                            current_stage="retrying",
                            stage_message=f"Retrying analysis (attempt {attempt + 1}): {str(exc)[:100]}"
                        )
                    except Exception as e:
                        logger.error(f"Failed to update progress on retry for job {job_id}: {e}")
                
                # Raise Retry exception with calculated delay
                raise Retry(str(exc), countdown=delay)
            else:
                # Don't retry - let it fail permanently
                raise exc
                
        except Retry:
            raise  # Re-raise Retry exception
        except Exception as e:
            logger.error(f"Error in retry logic for job {job_id}: {e}")
            # Fallback to permanent failure
            raise exc
    
    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Called when task is retried"""
        job_id = kwargs.get('job_id') or (args[0] if args else None)
        retry_count = self.request.retries
        
        logger.warning(f"Task {task_id} retry {retry_count} for job {job_id}: {exc}")
        
        # Update retry statistics
        try:
            retry_manager = self.get_retry_manager()
            retry_manager.redis_client.hincrby("retry:stats", "successful_retries", 1)
        except Exception as e:
            logger.debug(f"Failed to update retry statistics: {e}")
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when task fails permanently (no more retries)"""
        job_id = kwargs.get('job_id') or (args[0] if args else None)
        worker_id = self.worker_id or "unknown"
        
        logger.error(f"Task {task_id} failed permanently for job {job_id}: {exc}")
        logger.error(f"Task failure details: {einfo}")
        
        if self.job_manager and job_id:
            try:
                # Get failure history for enhanced context
                failure_context = {"retry_count": self.request.retries}
                try:
                    retry_manager = self.get_retry_manager()
                    failure_history = retry_manager.get_failure_history(job_id)
                    if failure_history:
                        failure_context.update({
                            "total_attempts": len(failure_history) + 1,
                            "failure_categories": list(set(f.category.value for f in failure_history)),
                            "last_stage": failure_history[0].stage if failure_history else None,
                            "first_failure": failure_history[-1].timestamp.isoformat() if failure_history else None
                        })
                except Exception as e:
                    logger.debug(f"Failed to get failure context: {e}")
                
                error_details = {
                    "task_id": task_id,
                    "worker_id": worker_id,
                    "exception_type": type(exc).__name__,
                    "traceback": str(einfo),
                    "failure_context": failure_context
                }
                
                self.job_manager.fail_job(
                    job_id=job_id,
                    worker_id=worker_id,
                    error_message=str(exc),
                    error_details=error_details
                )
            except Exception as e:
                logger.error(f"Failed to mark job {job_id} as failed: {e}")
    
    def on_success(self, retval, task_id, args, kwargs):
        """Called when task succeeds"""
        job_id = kwargs.get('job_id') or (args[0] if args else None)
        logger.info(f"Task {task_id} completed successfully for job {job_id}")
        
        # Clear failure history on success
        if job_id:
            try:
                retry_manager = self.get_retry_manager()
                retry_manager.clear_failure_history(job_id)
            except Exception as e:
                logger.debug(f"Failed to clear failure history for job {job_id}: {e}")


class WorkerManager:
    """
    Celery worker manager with configuration and lifecycle management
    
    Handles worker startup, shutdown, and configuration with proper
    signal handling and resource management.
    """
    
    def __init__(self):
        self.celery_app = celery_app
        self.job_manager = JobManager(redis_manager)
        self.worker_id = self._generate_worker_id()
        self.is_shutting_down = False
        
        # Configure task routing
        self._configure_task_routing()
        
        # Set up signal handlers
        self._setup_signal_handlers()
        
        logger.info(f"WorkerManager initialized with worker_id: {self.worker_id}")
    
    def _generate_worker_id(self) -> str:
        """Generate unique worker identifier"""
        hostname = os.uname().nodename
        pid = os.getpid()
        timestamp = int(datetime.utcnow().timestamp())
        return f"caponier-worker-{hostname}-{pid}-{timestamp}"
    
    def _configure_task_routing(self):
        """Configure Celery task routing"""
        # Task routing configuration
        task_routes = {
            'caponier.analysis.analyze_repository': {
                'queue': 'analysis',
                'routing_key': 'analysis.repository'
            },
            'caponier.analysis.scan_dependencies': {
                'queue': 'analysis', 
                'routing_key': 'analysis.dependencies'
            },
            'caponier.analysis.check_vulnerabilities': {
                'queue': 'analysis',
                'routing_key': 'analysis.vulnerabilities'
            },
            'caponier.maintenance.cleanup_jobs': {
                'queue': 'maintenance',
                'routing_key': 'maintenance.cleanup'
            }
        }
        
        # Update Celery configuration
        self.celery_app.conf.update(
            task_routes=task_routes,
            worker_hijack_root_logger=False,
            worker_log_format='[%(asctime)s: %(levelname)s/%(name)s] %(message)s',
            worker_task_log_format='[%(asctime)s: %(levelname)s/%(name)s][%(task_name)s(%(task_id)s)] %(message)s',
            worker_prefetch_multiplier=1,  # Only take one task at a time for fair distribution
            task_acks_late=True,  # Acknowledge task only after completion
            task_reject_on_worker_lost=True,  # Reject tasks if worker is lost
            worker_disable_rate_limits=False,
            task_compression='gzip',  # Compress task messages
            result_compression='gzip',  # Compress results
        )
        
        logger.info("Task routing configured successfully")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def shutdown_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown...")
            self.is_shutting_down = True
            
            # Give workers time to finish current tasks
            try:
                # Send warm shutdown signal to Celery
                self.celery_app.control.broadcast('shutdown', destination=[self.worker_id])
            except Exception as e:
                logger.error(f"Error during shutdown broadcast: {e}")
        
        # Register signal handlers
        signal.signal(signal.SIGTERM, shutdown_handler)
        signal.signal(signal.SIGINT, shutdown_handler)
        
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, shutdown_handler)
    
    def start_worker(self, concurrency: int = 1, loglevel: str = 'INFO', 
                    queues: Optional[str] = None) -> None:
        """
        Start Celery worker with specified configuration
        
        Args:
            concurrency: Number of concurrent processes
            loglevel: Logging level
            queues: Comma-separated queue names to consume from
        """
        try:
            if queues is None:
                queues = "analysis,maintenance"
            
            logger.info(f"Starting Celery worker {self.worker_id}")
            logger.info(f"Configuration: concurrency={concurrency}, loglevel={loglevel}, queues={queues}")
            
            # Start the worker
            self.celery_app.worker_main([
                'worker',
                f'--hostname={self.worker_id}',
                f'--concurrency={concurrency}',
                f'--loglevel={loglevel}',
                f'--queues={queues}',
                '--without-gossip',  # Disable gossip for performance
                '--without-mingle',  # Disable mingle for faster startup
                '--without-heartbeat',  # Disable heartbeat for simpler setup
                '--pool=prefork',  # Use prefork pool for better isolation
            ])
            
        except KeyboardInterrupt:
            logger.info("Worker interrupted by user")
        except Exception as e:
            logger.error(f"Worker startup failed: {e}")
            raise
        finally:
            self._cleanup()
    
    def _cleanup(self):
        """Cleanup resources on shutdown"""
        try:
            logger.info("Cleaning up worker resources...")
            
            # Close Redis connections
            redis_manager.close_connections()
            
            logger.info("Worker cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during worker cleanup: {e}")


# Global worker manager instance
worker_manager = WorkerManager()


# Celery signal handlers
@worker_ready.connect
def worker_ready_handler(sender=None, **kwargs):
    """Called when worker is ready to receive tasks"""
    logger.info(f"Worker {worker_manager.worker_id} is ready")


@worker_shutdown.connect  
def worker_shutdown_handler(sender=None, **kwargs):
    """Called when worker is shutting down"""
    logger.info(f"Worker {worker_manager.worker_id} is shutting down")


@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **kwds):
    """Called before task execution"""
    logger.info(f"Starting task {task_id}: {task.name}")
    
    # Set job manager and worker ID on task instance
    if hasattr(task, 'job_manager'):
        task.job_manager = worker_manager.job_manager
        task.worker_id = worker_manager.worker_id


@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, 
                        kwargs=None, retval=None, state=None, **kwds):
    """Called after task execution"""
    logger.info(f"Completed task {task_id}: {task.name} with state {state}")


@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, 
                        traceback=None, einfo=None, **kwargs):
    """Called when task fails"""
    logger.error(f"Task {task_id} failed: {exception}")


@task_retry.connect
def task_retry_handler(sender=None, task_id=None, reason=None, einfo=None, **kwargs):
    """Called when task is retried"""
    logger.warning(f"Task {task_id} retrying: {reason}")


@task_success.connect
def task_success_handler(sender=None, task_id=None, result=None, **kwargs):
    """Called when task succeeds"""
    logger.info(f"Task {task_id} succeeded")


def get_worker_manager() -> WorkerManager:
    """Get the global worker manager instance"""
    return worker_manager


def create_worker_app() -> Celery:
    """Create and configure Celery app for worker"""
    return celery_app


if __name__ == '__main__':
    """
    Entry point for running worker directly
    
    Usage:
        python -m src.api.jobs.worker
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Caponier Celery Worker')
    parser.add_argument('--concurrency', type=int, default=1, 
                       help='Number of concurrent processes')
    parser.add_argument('--loglevel', default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Logging level')
    parser.add_argument('--queues', default='analysis,maintenance',
                       help='Comma-separated queue names')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.loglevel),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Start worker
    worker_manager.start_worker(
        concurrency=args.concurrency,
        loglevel=args.loglevel,
        queues=args.queues
    )
