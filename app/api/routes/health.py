from fastapi import APIRouter, Response, status
import os
import socket
try:
    import resource
except ImportError:  # pragma: no cover - Windows developer fallback
    resource = None

import httpx
import redis.asyncio as redis

from app.core.config import settings
from app.db.base import check_database
from app.workers.celery_app import celery_app

router = APIRouter()


@router.get("/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(response: Response) -> dict[str, object]:
    checks: dict[str, object] = {"api": "ok"}

    try:
        await check_database()
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc.__class__.__name__}"

    try:
        with celery_app.connection_for_read() as connection:
            connection.ensure_connection(max_retries=1)
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {exc.__class__.__name__}"

    healthy = all(value == "ok" for value in checks.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {"status": "ready" if healthy else "not_ready", "checks": checks}


@router.get("/deep")
async def deep(response: Response) -> dict[str, object]:
    checks: dict[str, object] = {}

    try:
        await check_database()
        checks["postgres"] = "ok"
    except Exception as exc:
        checks["postgres"] = f"error: {exc.__class__.__name__}"

    try:
        client = redis.from_url(settings.redis_url)
        queue_depths = {
            queue: await client.llen(queue)
            for queue in [
                settings.celery_scan_queue,
                settings.celery_replay_queue,
                settings.celery_validation_queue,
                settings.celery_report_queue,
            ]
        }
        await client.aclose()
        checks["redis"] = {"status": "ok", "queue_depths": queue_depths}
    except Exception as exc:
        checks["redis"] = f"error: {exc.__class__.__name__}"

    try:
        async with httpx.AsyncClient(timeout=3) as client:
            zap_response = await client.get(f"{settings.zap_api_url}/JSON/core/view/version/")
        checks["zap"] = "ok" if zap_response.status_code < 500 else f"http_{zap_response.status_code}"
    except Exception as exc:
        checks["zap"] = f"error: {exc.__class__.__name__}"

    checks["playwright"] = _tcp_check("playwright", 9333)
    checks["memory"] = _memory_report()

    healthy = (
        checks.get("postgres") == "ok"
        and isinstance(checks.get("redis"), dict)
        and checks.get("playwright") == "ok"
    )
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {"status": "ready" if healthy else "not_ready", "checks": checks}


def _tcp_check(host: str, port: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=3):
            return "ok"
    except Exception as exc:
        return f"error: {exc.__class__.__name__}"


def _memory_report() -> dict[str, object]:
    if resource is None:
        return {"pid": os.getpid(), "max_rss_kb": None}
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "pid": os.getpid(),
        "max_rss_kb": usage.ru_maxrss,
    }
