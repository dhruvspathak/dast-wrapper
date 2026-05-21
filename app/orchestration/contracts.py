from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    backoff_seconds: int = 30
    retryable_errors: tuple[str, ...] = ("TimeoutError", "ConnectionError", "RuntimeError")


@dataclass(frozen=True)
class ActivityDefinition:
    name: str
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    timeout_seconds: int = 3600


@dataclass(frozen=True)
class WorkflowDefinition:
    name: str
    activities: tuple[ActivityDefinition, ...]
    durable: bool = True
    resumable: bool = True


class WorkflowExecutor(Protocol):
    async def start(self, workflow: WorkflowDefinition, payload: dict[str, Any], idempotency_key: str) -> str:
        ...

    async def resume(self, workflow_id: str) -> None:
        ...

    async def mark_activity_complete(self, workflow_id: str, activity_name: str, result: dict[str, Any]) -> None:
        ...

    async def mark_activity_failed(self, workflow_id: str, activity_name: str, error: str) -> None:
        ...


AUTHORIZATION_SCAN_WORKFLOW = WorkflowDefinition(
    name="authorization_scan",
    activities=(
        ActivityDefinition("authenticate_identities", timeout_seconds=1800),
        ActivityDefinition("crawl_authenticated_surface", timeout_seconds=7200),
        ActivityDefinition("discover_objects", timeout_seconds=1800),
        ActivityDefinition("discover_workflows", timeout_seconds=1800),
        ActivityDefinition("inject_scanner_context", timeout_seconds=600),
        ActivityDefinition("execute_authorization_attacks", timeout_seconds=7200),
        ActivityDefinition("build_authorization_graph", timeout_seconds=1800),
    ),
)
