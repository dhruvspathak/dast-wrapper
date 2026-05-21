from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import (
    AttackAttempt,
    Identity,
    ObjectReference,
    Session,
    TrafficLog,
    ValidationResult,
)
from app.validation.engine import ValidationEngine


class AuthorizationAttackEngine:
    def __init__(self, db: AsyncSession, validation_engine: ValidationEngine | None = None):
        self.db = db
        self.validation_engine = validation_engine or ValidationEngine()

    async def run_attacks(self, scan_job_id: str, application_id: str) -> list[AttackAttempt]:
        traffic = await self._traffic(scan_job_id)
        sessions = await self._sessions(application_id)
        references = await self._references(application_id)
        attempts: list[AttackAttempt] = []
        async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
            for baseline in traffic:
                if not baseline.identity_id or baseline.response_status not in {200, 201, 202, 204, 206}:
                    continue
                source_session = sessions.get(baseline.identity_id)
                if not source_session:
                    continue
                related_refs = [ref for ref in references if ref.identity_id == baseline.identity_id]
                for target_identity_id, target_session in sessions.items():
                    if target_identity_id == baseline.identity_id:
                        continue
                    attempts.append(
                        await self._replay_cross_identity(
                            client,
                            baseline,
                            target_session,
                            related_refs,
                        )
                    )
        return attempts

    async def _replay_cross_identity(
        self,
        client: httpx.AsyncClient,
        baseline: TrafficLog,
        target_session: Session,
        references: list[ObjectReference],
    ) -> AttackAttempt:
        headers = self._headers_for_replay(baseline.request_headers, target_session)
        response = await client.request(
            baseline.request_method,
            baseline.request_url,
            headers=headers,
            content=baseline.request_body,
            cookies=target_session.cookies,
        )
        ref = self._reference_for_request(baseline, references)
        attack_type = self._attack_type(baseline, ref, target_session)
        replay_response = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "size": len(response.content),
        }
        attempt = AttackAttempt(
            workspace_id=baseline.workspace_id,
            application_id=baseline.application_id,
            scan_job_id=baseline.scan_job_id or "",
            attack_type=attack_type,
            source_identity_id=baseline.identity_id,
            target_identity_id=target_session.identity_id,
            object_reference_id=ref.id if ref else None,
            baseline_traffic_log_id=baseline.id,
            replay_request={
                "method": baseline.request_method,
                "url": baseline.request_url,
                "headers": headers,
                "body": baseline.request_body,
            },
            replay_response=replay_response,
            status="replayed",
            evidence={"strategy": "cross_identity_replay"},
        )
        self.db.add(attempt)
        await self.db.flush()
        validation = self.validation_engine.validate(
            baseline_response={
                "status_code": baseline.response_status,
                "headers": baseline.response_headers,
                "body": baseline.response_body,
            },
            replay_response=replay_response,
            attack_type=attack_type,
        )
        result = ValidationResult(
            workspace_id=baseline.workspace_id,
            attack_attempt_id=attempt.id,
            verdict=validation["verdict"],
            confidence=validation["confidence"],
            status_code_delta=validation["status_code_delta"],
            body_delta=validation["body_delta"],
            sensitive_fields=validation["sensitive_fields"],
            semantic_indicators=validation["semantic_indicators"],
            evidence=validation["evidence"],
        )
        self.db.add(result)
        await self.db.flush()
        await self.db.refresh(attempt)
        return attempt

    async def _traffic(self, scan_job_id: str) -> list[TrafficLog]:
        result = await self.db.execute(select(TrafficLog).where(TrafficLog.scan_job_id == scan_job_id))
        return list(result.scalars().all())

    async def _sessions(self, application_id: str) -> dict[str, Session]:
        result = await self.db.execute(
            select(Session).where(Session.application_id == application_id, Session.status == "active")
        )
        return {session.identity_id: session for session in result.scalars().all()}

    async def _references(self, application_id: str) -> list[ObjectReference]:
        result = await self.db.execute(select(ObjectReference).where(ObjectReference.application_id == application_id))
        return list(result.scalars().all())

    def _headers_for_replay(self, original_headers: dict[str, Any], target_session: Session) -> dict[str, str]:
        blocked = {"cookie", "host", "content-length"}
        headers = {
            key: str(value)
            for key, value in (original_headers or {}).items()
            if key.lower() not in blocked
        }
        headers.update({key: str(value) for key, value in (target_session.auth_headers or {}).items()})
        return headers

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
        return references[0] if references else None

    def _attack_type(
        self,
        traffic: TrafficLog,
        reference: ObjectReference | None,
        target_session: Session,
    ) -> str:
        if reference and reference.reference_type in {"numeric_id", "uuid", "object"}:
            return "BOLA"
        if traffic.request_method in {"POST", "PUT", "PATCH", "DELETE"}:
            return "horizontal_privilege_escalation"
        return "broken_access_control"
