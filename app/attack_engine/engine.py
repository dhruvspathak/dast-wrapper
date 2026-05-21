from __future__ import annotations

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.attack_engine.attacks import (
    BOLAAttack,
    HorizontalEscalationAttack,
    TenantBoundaryAttack,
    VerticalEscalationAttack,
    WorkflowTransitionAttack,
)
from app.attack_engine.base import AttackExecutionResult, AuthorizationAttack
from app.models.authorization import (
    AttackAttempt,
    EvidenceRecord,
    ObjectReference,
    Session,
    TrafficLog,
    ValidationResult,
)
from app.replay.lineage import LineageEngine
from app.storage.traffic_store import TrafficStore
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
            for attack in self._attacks(client):
                targets = await attack.discover_targets(
                    traffic=traffic,
                    sessions=sessions,
                    references=references,
                )
                for target in targets:
                    result = await attack.execute(target)
                    attempts.append(await self._persist_result(scan_job_id, attack.attack_type, result))
        return attempts

    def _attacks(self, client: httpx.AsyncClient) -> list[AuthorizationAttack]:
        return [
            BOLAAttack(self.db, self.validation_engine, client),
            HorizontalEscalationAttack(self.db, self.validation_engine, client),
            VerticalEscalationAttack(self.db, self.validation_engine, client),
            TenantBoundaryAttack(self.db, self.validation_engine, client),
            WorkflowTransitionAttack(self.db, self.validation_engine, client),
        ]

    async def _persist_result(
        self,
        scan_job_id: str,
        attack_type: str,
        result: AttackExecutionResult,
    ) -> AttackAttempt:
        baseline = result.target.baseline
        chain = await LineageEngine(self.db).create_attack_chain(
            workspace_id=baseline.workspace_id,
            application_id=baseline.application_id,
            scan_job_id=scan_job_id,
            chain_type=attack_type,
            root_traffic_log_id=baseline.id,
            summary={"target_identity_id": result.target.target_session.identity_id},
        )
        replay_log = await TrafficStore(self.db).record(
            {
                "workspace_id": baseline.workspace_id,
                "application_id": baseline.application_id,
                "scan_job_id": scan_job_id,
                "identity_id": result.target.target_session.identity_id,
                "session_id": result.target.target_session.id,
                "parent_traffic_log_id": baseline.id,
                "request_url": result.replay_request["url"],
                "request_method": result.replay_request["method"],
                "request_headers": result.replay_request["headers"],
                "request_body": result.replay_request.get("body"),
                "response_status": result.replay_response["status_code"],
                "response_headers": result.replay_response["headers"],
                "response_body": result.replay_response["body"],
                "response_size": result.replay_response["size"],
                "source": "attack_engine",
                "source_type": "replay",
                "attack_chain_id": chain.id,
                "replay_depth": baseline.replay_depth + 1,
                "discovered_by": attack_type,
            }
        )
        attempt = AttackAttempt(
            workspace_id=baseline.workspace_id,
            application_id=baseline.application_id,
            scan_job_id=scan_job_id,
            attack_type=attack_type,
            source_identity_id=baseline.identity_id,
            target_identity_id=result.target.target_session.identity_id,
            object_reference_id=result.target.object_reference.id if result.target.object_reference else None,
            baseline_traffic_log_id=baseline.id,
            replay_traffic_log_id=replay_log.id,
            attack_chain_id=chain.id,
            replay_request=result.replay_request,
            replay_response=result.replay_response,
            status="replayed",
            evidence={"strategy": attack_type, "mutation": result.target.mutation or {}},
        )
        self.db.add(attempt)
        await self.db.flush()
        validation = result.validation
        validation_result = ValidationResult(
            workspace_id=baseline.workspace_id,
            attack_attempt_id=attempt.id,
            verdict=validation["verdict"],
            confidence=validation["confidence"],
            status_code_delta=validation["status_code_delta"],
            body_delta=validation["body_delta"],
            normalized_diff=validation["normalized_diff"],
            sensitive_fields=validation["sensitive_fields"],
            semantic_indicators=validation["semantic_indicators"],
            validation_reasons=validation["validation_reasons"],
            evidence=validation["evidence"],
        )
        self.db.add(validation_result)
        self.db.add(
            EvidenceRecord(
                workspace_id=baseline.workspace_id,
                application_id=baseline.application_id,
                scan_job_id=scan_job_id,
                attack_attempt_id=attempt.id,
                attack_chain_id=chain.id,
                evidence_type=attack_type,
                baseline_request={
                    "method": baseline.request_method,
                    "url": baseline.request_url,
                    "headers": baseline.request_headers,
                    "body": baseline.request_body,
                },
                baseline_response={
                    "status_code": baseline.response_status,
                    "headers": baseline.response_headers,
                    "body": baseline.response_body,
                },
                replay_request=result.replay_request,
                replay_response=result.replay_response,
                normalized_diffs=validation["normalized_diff"],
                validation_evidence=validation["evidence"],
                confidence=validation["confidence"],
            )
        )
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
