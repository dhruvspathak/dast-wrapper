from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import (
    AttackAttempt,
    AuthorizationExpectation,
    ObjectRelationship,
    ReasoningFinding,
    ValidationResult,
    WorkflowTransition,
)


class AuthorizationReasoner:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def reason(self, application_id: str, scan_job_id: str | None = None) -> list[ReasoningFinding]:
        findings: list[ReasoningFinding] = []
        findings.extend(await self._reason_about_validated_attacks(application_id, scan_job_id))
        findings.extend(await self._reason_about_workflow_anomalies(application_id, scan_job_id))
        findings.extend(await self._reason_about_relationship_pivots(application_id, scan_job_id))
        for finding in findings:
            self.db.add(finding)
        await self.db.flush()
        return findings

    async def _reason_about_validated_attacks(self, application_id: str, scan_job_id: str | None) -> list[ReasoningFinding]:
        query = (
            select(AttackAttempt, ValidationResult)
            .join(ValidationResult, ValidationResult.attack_attempt_id == AttackAttempt.id)
            .where(AttackAttempt.application_id == application_id)
        )
        if scan_job_id:
            query = query.where(AttackAttempt.scan_job_id == scan_job_id)
        result = await self.db.execute(query)
        findings = []
        for attempt, validation in result.all():
            if validation.verdict not in {"confirmed", "likely"}:
                continue
            findings.append(
                ReasoningFinding(
                    workspace_id=attempt.workspace_id,
                    application_id=application_id,
                    scan_job_id=attempt.scan_job_id,
                    finding_type="broken_authorization_boundary",
                    severity="high" if validation.confidence >= 0.8 else "medium",
                    confidence=validation.confidence,
                    explanation=(
                        f"{attempt.attack_type} succeeded for target identity "
                        f"{attempt.target_identity_id} against source identity {attempt.source_identity_id}."
                    ),
                    evidence={
                        "attack_attempt_id": attempt.id,
                        "validation_reasons": validation.validation_reasons,
                        "normalized_diff": validation.normalized_diff,
                    },
                )
            )
        return findings

    async def _reason_about_workflow_anomalies(self, application_id: str, scan_job_id: str | None) -> list[ReasoningFinding]:
        query = select(WorkflowTransition).where(WorkflowTransition.application_id == application_id)
        if scan_job_id:
            query = query.where(WorkflowTransition.scan_job_id == scan_job_id)
        transitions = list((await self.db.execute(query)).scalars().all())
        findings = []
        for transition in transitions:
            if transition.confidence < 0.8:
                continue
            findings.append(
                ReasoningFinding(
                    workspace_id=transition.workspace_id,
                    application_id=application_id,
                    scan_job_id=transition.scan_job_id,
                    finding_type="suspicious_workflow_transition",
                    severity="medium",
                    confidence=transition.confidence,
                    explanation=f"Suspicious workflow transition {transition.from_state}->{transition.to_state} was observed.",
                    evidence={"workflow_transition_id": transition.id, **transition.evidence},
                )
            )
        return findings

    async def _reason_about_relationship_pivots(self, application_id: str, scan_job_id: str | None) -> list[ReasoningFinding]:
        query = select(ObjectRelationship).where(ObjectRelationship.application_id == application_id)
        if scan_job_id:
            query = query.where(ObjectRelationship.scan_job_id == scan_job_id)
        relationships = list((await self.db.execute(query)).scalars().all())
        findings = []
        for relationship in relationships:
            if relationship.confidence < 0.8:
                continue
            findings.append(
                ReasoningFinding(
                    workspace_id=relationship.workspace_id,
                    application_id=application_id,
                    scan_job_id=relationship.scan_job_id,
                    finding_type="indirect_object_access_path",
                    severity="info",
                    confidence=relationship.confidence,
                    explanation="Nested object relationship can be used for indirect authorization pivot testing.",
                    evidence={
                        "object_relationship_id": relationship.id,
                        "source_object_reference_id": relationship.source_object_reference_id,
                        "target_object_reference_id": relationship.target_object_reference_id,
                        **relationship.evidence,
                    },
                )
            )
        return findings
