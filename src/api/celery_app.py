"""
Celery application entry point

Provides the main Celery application instance for use by workers and beat scheduler.
This file is used by the celery command-line tool.
"""

import os
import sys

# Add the project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.api.config import celery_app

# Import all task modules to register them with Celery
from src.api.jobs import tasks

# Export the Celery app for the celery command-line tool
app = celery_app

if __name__ == '__main__':
    app.start()
