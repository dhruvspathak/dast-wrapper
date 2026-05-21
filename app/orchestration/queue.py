from __future__ import annotations

import json
from typing import Any

from redis.asyncio import Redis

from app.core.config import settings


class RedisWorkflowQueue:
    def __init__(self, redis: Redis | None = None):
        self.redis = redis or Redis.from_url(settings.redis_url, decode_responses=True)
        self.queue_name = "authorization_workflows"

    async def enqueue(self, workflow_name: str, payload: dict[str, Any], idempotency_key: str) -> None:
        exists = await self.redis.set(f"workflow:idempotency:{idempotency_key}", "1", nx=True, ex=86400)
        if not exists:
            return
        await self.redis.rpush(
            self.queue_name,
            json.dumps(
                {
                    "workflow_name": workflow_name,
                    "payload": payload,
                    "idempotency_key": idempotency_key,
                }
            ),
        )

    async def dequeue(self, timeout_seconds: int = 5) -> dict[str, Any] | None:
        item = await self.redis.blpop(self.queue_name, timeout=timeout_seconds)
        if not item:
            return None
        _, raw = item
        return json.loads(raw)
