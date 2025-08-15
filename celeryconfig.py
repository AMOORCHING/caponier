"""
Celery configuration file

This file provides default Celery configuration that can be overridden
by environment variables. Used by the celery command-line tool.
"""

import os
from kombu import Queue

# Broker settings
broker_url = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')
result_backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')

# Task serialization
task_serializer = 'json'
result_serializer = 'json'
accept_content = ['json']
timezone = 'UTC'
enable_utc = True

# Task routing
task_routes = {
    'caponier.analysis.analyze_repository': {'queue': 'analysis'},
    'caponier.analysis.scan_dependencies': {'queue': 'analysis'},
    'caponier.analysis.check_vulnerabilities': {'queue': 'analysis'},
    'caponier.maintenance.cleanup_jobs': {'queue': 'maintenance'},
    'caponier.monitoring.health_check': {'queue': 'monitoring'}
}

# Queue configuration
task_default_queue = 'default'
task_queues = (
    Queue('analysis', routing_key='analysis'),
    Queue('maintenance', routing_key='maintenance'),
    Queue('monitoring', routing_key='monitoring'),
    Queue('default', routing_key='default'),
)

# Worker settings
worker_prefetch_multiplier = 1
task_acks_late = True
task_reject_on_worker_lost = True
worker_disable_rate_limits = False

# Task execution settings
task_soft_time_limit = 300  # 5 minutes
task_time_limit = 360       # 6 minutes
task_max_retries = 3
task_default_retry_delay = 60

# Result backend settings
result_expires = 86400  # 24 hours
result_persistent = True

# Compression
task_compression = 'gzip'
result_compression = 'gzip'

# Beat schedule for periodic tasks
beat_schedule = {
    'cleanup-expired-jobs': {
        'task': 'caponier.maintenance.cleanup_jobs',
        'schedule': 3600.0,  # Every hour
        'options': {'queue': 'maintenance'}
    },
    'worker-health-check': {
        'task': 'caponier.monitoring.health_check',
        'schedule': 300.0,   # Every 5 minutes
        'options': {'queue': 'monitoring'}
    },
}

# Security
worker_hijack_root_logger = False
worker_log_format = '[%(asctime)s: %(levelname)s/%(processName)s] %(message)s'
worker_task_log_format = '[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s'

# Monitoring
worker_send_task_events = True
task_send_sent_event = True

# Performance
worker_pool_restarts = True
