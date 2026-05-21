from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import ObjectReference, Session, TrafficLog
from app.validation.engine import ValidationEngine


@dataclass(slots=True)
class AttackTarget:
    baseline: TrafficLog
    target_session: Session
    object_reference: ObjectReference | None = None
    mutation: dict[str, Any] | None = None


@dataclass(slots=True)
class AttackExecutionResult:
    target: AttackTarget
    replay_request: dict[str, Any]
    replay_response: dict[str, Any]
    validation: dict[str, Any]


class AuthorizationAttack(ABC):
    attack_type: str

    def __init__(
        self,
        db: AsyncSession,
        validation_engine: ValidationEngine,
        http_client: httpx.AsyncClient,
    ):
        self.db = db
        self.validation_engine = validation_engine
        self.http_client = http_client

    @abstractmethod
    async def discover_targets(
        self,
        *,
        traffic: list[TrafficLog],
        sessions: dict[str, Session],
        references: list[ObjectReference],
    ) -> list[AttackTarget]:
        raise NotImplementedError

    async def mutate(self, target: AttackTarget) -> dict[str, Any]:
        headers = self._headers_for_replay(target.baseline.request_headers, target.target_session)
        return {
            "method": target.baseline.request_method,
            "url": target.baseline.request_url,
            "headers": headers,
            "body": target.baseline.request_body,
            "cookies": target.target_session.cookies,
        }

    async def execute(self, target: AttackTarget) -> AttackExecutionResult:
        replay_request = await self.mutate(target)
        response = await self.http_client.request(
            replay_request["method"],
            replay_request["url"],
            headers=replay_request["headers"],
            content=replay_request["body"],
            cookies=replay_request["cookies"],
        )
        replay_response = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "size": len(response.content),
        }
        validation = await self.validate(target, replay_response)
        replay_request.pop("cookies", None)
        return AttackExecutionResult(target, replay_request, replay_response, validation)

    async def validate(self, target: AttackTarget, replay_response: dict[str, Any]) -> dict[str, Any]:
        return self.validation_engine.validate(
            baseline_response={
                "status_code": target.baseline.response_status,
                "headers": target.baseline.response_headers,
                "body": target.baseline.response_body,
            },
            replay_response=replay_response,
            attack_type=self.attack_type,
        )

    def _headers_for_replay(self, original_headers: dict[str, Any], target_session: Session) -> dict[str, str]:
        blocked = {"cookie", "host", "content-length"}
        headers = {
            key: str(value)
            for key, value in (original_headers or {}).items()
            if key.lower() not in blocked
        }
        headers.update({key: str(value) for key, value in (target_session.auth_headers or {}).items()})
        return headers

    def _successful(self, log: TrafficLog) -> bool:
        return bool(log.identity_id and log.response_status in {200, 201, 202, 204, 206})

    def _reference_for_request(
        self,
        traffic: TrafficLog,
        references: list[ObjectReference],
    ) -> ObjectReference | None:
        for reference in references:
            if reference.value in traffic.request_url or (
                traffic.request_body and reference.value in traffic.request_body
            ):
                return reference
        return None
