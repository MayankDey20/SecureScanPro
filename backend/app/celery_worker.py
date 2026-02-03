import os
from celery import Celery
from app.core.config import Settings

settings = Settings()

celery_app = Celery(
    "securescan",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.tasks.scan_tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "app.tasks.scan_tasks.*": {"queue": "scans"},
    },
)

if __name__ == "__main__":
    celery_app.start()
