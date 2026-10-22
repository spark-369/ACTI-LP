"""Celery application (Redis broker).

The API image is reused for the worker:
    celery -A app.workers worker --loglevel=info --concurrency=1
"""
from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery("actilp", broker=settings.REDIS_URL, backend=settings.REDIS_URL)

celery_app.conf.update(
    task_default_queue="actilp",
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    # Local ChromaDB is embedded and single-host: keep writes serialised.
    worker_concurrency=1,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "consume-redis-streams": {
            "task": "app.workers.tasks.consume_stream",
            "schedule": 5.0,
        },
        "expire-stale-alerts": {
            "task": "app.workers.tasks.expire_stale_alerts",
            "schedule": crontab(minute=0),
        },
    },
)

celery_app.autodiscover_tasks(["app.workers"])

# Ensure tasks module is imported for `celery -A app.workers`.
from app.workers import tasks  # noqa: E402,F401
