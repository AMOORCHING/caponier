#!/usr/bin/env python3
"""
Celery Management Script

Provides utilities for managing Celery workers, monitoring queues,
and performing maintenance tasks.
"""

import os
import sys
import argparse
import json
import time
from pathlib import Path
from typing import Dict, Any, List

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.api.config import celery_app, redis_manager
from src.api.jobs.job_manager import JobManager


def setup_logging():
    """Setup basic logging"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def get_worker_stats() -> Dict[str, Any]:
    """Get statistics about active workers"""
    try:
        inspect = celery_app.control.inspect()
        
        # Get active workers
        active_workers = inspect.active()
        registered_tasks = inspect.registered()
        worker_stats = inspect.stats()
        
        stats = {
            "active_workers": list(active_workers.keys()) if active_workers else [],
            "worker_count": len(active_workers) if active_workers else 0,
            "tasks_by_worker": active_workers or {},
            "registered_tasks": registered_tasks or {},
            "worker_stats": worker_stats or {}
        }
        
        return stats
        
    except Exception as e:
        return {"error": str(e), "worker_count": 0, "active_workers": []}


def get_queue_stats() -> Dict[str, Any]:
    """Get statistics about job queues"""
    try:
        job_manager = JobManager(redis_manager)
        system_status = job_manager.get_system_status()
        
        # Get Redis queue lengths
        redis_client = redis_manager.get_job_queue_client()
        queue_lengths = {}
        
        for queue in ['analysis', 'maintenance', 'monitoring', 'default']:
            try:
                length = redis_client.llen(f"celery:{queue}")
                queue_lengths[queue] = length
            except:
                queue_lengths[queue] = 0
        
        return {
            "queue_lengths": queue_lengths,
            "system_status": system_status,
            "total_queued": sum(queue_lengths.values())
        }
        
    except Exception as e:
        return {"error": str(e), "queue_lengths": {}, "total_queued": 0}


def purge_queues(queues: List[str] = None) -> Dict[str, int]:
    """Purge specified queues"""
    if queues is None:
        queues = ['analysis', 'maintenance', 'monitoring', 'default']
    
    purged = {}
    for queue in queues:
        try:
            result = celery_app.control.purge()
            purged[queue] = result.get('ok', 0) if result else 0
        except Exception as e:
            purged[queue] = f"error: {e}"
    
    return purged


def revoke_tasks(task_ids: List[str], terminate: bool = False) -> Dict[str, str]:
    """Revoke specified tasks"""
    results = {}
    
    for task_id in task_ids:
        try:
            celery_app.control.revoke(task_id, terminate=terminate)
            results[task_id] = "revoked"
        except Exception as e:
            results[task_id] = f"error: {e}"
    
    return results


def cleanup_jobs() -> Dict[str, Any]:
    """Run job cleanup manually"""
    try:
        job_manager = JobManager(redis_manager)
        cleaned_count = job_manager.cleanup_expired_jobs()
        
        return {
            "status": "completed",
            "jobs_cleaned": cleaned_count,
            "timestamp": time.time()
        }
        
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def monitor_workers(duration: int = 60) -> None:
    """Monitor workers for specified duration"""
    print(f"Monitoring workers for {duration} seconds...")
    print("Press Ctrl+C to stop monitoring")
    
    try:
        start_time = time.time()
        while time.time() - start_time < duration:
            stats = get_worker_stats()
            queue_stats = get_queue_stats()
            
            print(f"\n--- Worker Status ({time.strftime('%H:%M:%S')}) ---")
            print(f"Active Workers: {stats['worker_count']}")
            
            if stats['active_workers']:
                for worker in stats['active_workers']:
                    active_tasks = len(stats['tasks_by_worker'].get(worker, []))
                    print(f"  {worker}: {active_tasks} active tasks")
            
            print(f"\n--- Queue Status ---")
            for queue, length in queue_stats['queue_lengths'].items():
                print(f"  {queue}: {length} tasks")
            
            print(f"Total Queued: {queue_stats['total_queued']}")
            
            time.sleep(5)  # Update every 5 seconds
            
    except KeyboardInterrupt:
        print("\nMonitoring stopped")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Celery Management Utilities')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Worker stats command
    stats_parser = subparsers.add_parser('stats', help='Show worker and queue statistics')
    stats_parser.add_argument('--format', choices=['json', 'text'], default='text',
                             help='Output format')
    
    # Purge queues command
    purge_parser = subparsers.add_parser('purge', help='Purge job queues')
    purge_parser.add_argument('--queues', nargs='+', 
                             default=['analysis', 'maintenance', 'monitoring'],
                             help='Queues to purge')
    purge_parser.add_argument('--confirm', action='store_true',
                             help='Confirm purge operation')
    
    # Revoke tasks command
    revoke_parser = subparsers.add_parser('revoke', help='Revoke running tasks')
    revoke_parser.add_argument('task_ids', nargs='+', help='Task IDs to revoke')
    revoke_parser.add_argument('--terminate', action='store_true',
                              help='Terminate running tasks')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Run job cleanup')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor workers')
    monitor_parser.add_argument('--duration', type=int, default=60,
                               help='Monitoring duration in seconds')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    setup_logging()
    
    if args.command == 'stats':
        worker_stats = get_worker_stats()
        queue_stats = get_queue_stats()
        
        if args.format == 'json':
            result = {
                "workers": worker_stats,
                "queues": queue_stats,
                "timestamp": time.time()
            }
            print(json.dumps(result, indent=2))
        else:
            print("=== Worker Statistics ===")
            print(f"Active Workers: {worker_stats['worker_count']}")
            
            if worker_stats['active_workers']:
                print("Workers:")
                for worker in worker_stats['active_workers']:
                    active_tasks = len(worker_stats['tasks_by_worker'].get(worker, []))
                    print(f"  - {worker}: {active_tasks} active tasks")
            
            print("\n=== Queue Statistics ===")
            for queue, length in queue_stats['queue_lengths'].items():
                print(f"{queue}: {length} tasks")
            
            print(f"\nTotal Queued: {queue_stats['total_queued']}")
    
    elif args.command == 'purge':
        if not args.confirm:
            print("WARNING: This will delete all tasks in the specified queues!")
            print(f"Queues to purge: {', '.join(args.queues)}")
            confirm = input("Are you sure? (y/N): ")
            if confirm.lower() != 'y':
                print("Purge cancelled")
                return
        
        print(f"Purging queues: {', '.join(args.queues)}...")
        results = purge_queues(args.queues)
        
        for queue, count in results.items():
            print(f"{queue}: {count} tasks purged")
    
    elif args.command == 'revoke':
        print(f"Revoking tasks: {', '.join(args.task_ids)}")
        results = revoke_tasks(args.task_ids, args.terminate)
        
        for task_id, status in results.items():
            print(f"{task_id}: {status}")
    
    elif args.command == 'cleanup':
        print("Running job cleanup...")
        result = cleanup_jobs()
        
        if result['status'] == 'completed':
            print(f"Cleanup completed: {result['jobs_cleaned']} jobs processed")
        else:
            print(f"Cleanup failed: {result['error']}")
    
    elif args.command == 'monitor':
        monitor_workers(args.duration)


if __name__ == '__main__':
    main()
