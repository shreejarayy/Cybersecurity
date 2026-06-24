"""
Argus ASM — Celery application

Defines the Celery app instance used by both the worker process
and the task definitions in scan_tasks.py.

Run the worker with:
    celery -A tasks.celery_app worker --loglevel=info --pool=solo

(--pool=solo is required on Windows; omit it on Linux/Mac.)
"""

from celery import Celery
from config.settings import settings

# Redis is used as both the message broker and the result backend.
# Format: redis://[:password]@host:port/db_number
REDIS_URL = getattr(settings, "REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "argus",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["tasks.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # Don't let a hung scan block the worker forever
    task_time_limit=600,        # hard kill after 10 minutes
    task_soft_time_limit=540,   # warn at 9 minutes
)
