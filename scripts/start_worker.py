#!/usr/bin/env python3
"""
Caponier Celery Worker Startup Script

Starts a Celery worker with proper configuration for repository analysis tasks.
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.api.jobs.worker import WorkerManager


def setup_logging(level: str = 'INFO'):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('/tmp/caponier-worker.log', mode='a')
        ]
    )


def main():
    """Main entry point for worker startup"""
    parser = argparse.ArgumentParser(description='Caponier Celery Worker')
    
    parser.add_argument(
        '--concurrency', 
        type=int, 
        default=1,
        help='Number of concurrent worker processes (default: 1)'
    )
    
    parser.add_argument(
        '--loglevel',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--queues',
        default='analysis,maintenance',
        help='Comma-separated queue names to consume from (default: analysis,maintenance)'
    )
    
    parser.add_argument(
        '--worker-type',
        choices=['analysis', 'maintenance', 'all'],
        default='all',
        help='Type of worker to start (default: all)'
    )
    
    parser.add_argument(
        '--max-tasks-per-child',
        type=int,
        default=100,
        help='Maximum tasks per worker child process (default: 100)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.loglevel)
    logger = logging.getLogger(__name__)
    
    # Determine queues based on worker type
    if args.worker_type == 'analysis':
        queues = 'analysis'
    elif args.worker_type == 'maintenance':
        queues = 'maintenance'
    else:
        queues = args.queues
    
    logger.info("Starting Caponier Celery Worker")
    logger.info(f"Configuration:")
    logger.info(f"  Concurrency: {args.concurrency}")
    logger.info(f"  Log Level: {args.loglevel}")
    logger.info(f"  Queues: {queues}")
    logger.info(f"  Worker Type: {args.worker_type}")
    logger.info(f"  Max Tasks Per Child: {args.max_tasks_per_child}")
    
    try:
        # Set environment variables for Celery
        os.environ.setdefault('CELERY_MAX_TASKS_PER_CHILD', str(args.max_tasks_per_child))
        
        # Create and start worker
        worker_manager = WorkerManager()
        worker_manager.start_worker(
            concurrency=args.concurrency,
            loglevel=args.loglevel,
            queues=queues
        )
        
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    except Exception as e:
        logger.error(f"Worker failed to start: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
