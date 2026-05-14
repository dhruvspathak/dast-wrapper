from celery import Celery
from kombu import Exchange, Queue
from app.core.config import settings

celery_app = Celery(
    "dast_wrapper",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_default_exchange="dast",
    task_default_exchange_type="direct",
    task_default_queue=settings.celery_scan_queue,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    task_queues=(
        Queue(settings.celery_scan_queue, Exchange("dast"), routing_key="scan.#"),
        Queue(settings.celery_replay_queue, Exchange("dast"), routing_key="replay.#"),
        Queue(settings.celery_validation_queue, Exchange("dast"), routing_key="validation.#"),
        Queue(settings.celery_report_queue, Exchange("dast"), routing_key="report.#"),
    ),
    task_routes={
        "run_zap_scan": {"queue": settings.celery_scan_queue, "routing_key": "scan.zap"},
        "app.workers.tasks.replay_finding": {
            "queue": settings.celery_replay_queue,
            "routing_key": "replay.finding",
        },
        "app.workers.tasks.validate_idor": {
            "queue": settings.celery_validation_queue,
            "routing_key": "validation.idor",
        },
        "app.workers.tasks.generate_report": {
            "queue": settings.celery_report_queue,
            "routing_key": "report.generate",
        },
    },
)
