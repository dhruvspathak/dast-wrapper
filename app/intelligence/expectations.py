from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.application_mapper import ApplicationMap
from app.models.authorization import AuthorizationExpectation


@dataclass(slots=True)
class ExpectedAccess:
    subject_type: str
    subject: str
    resource_type: str
    resource: str
    expected_access: str
    confidence: float
    rationale: list[str]


class AuthorizationExpectationEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate(
        self,
        *,
        application_id: str,
        workspace_id: str,
        app_map: ApplicationMap,
        scan_job_id: str | None = None,
    ) -> list[ExpectedAccess]:
        expectations: list[ExpectedAccess] = []
        roles = sorted({pattern["role"] for pattern in app_map.identity_patterns.values()})
        for role in roles:
            for workflow_name, steps in app_map.workflows.items():
                for step in steps:
                    crud = step.get("crud") or step.get("action")
                    if crud in {"approve", "refund", "archive", "publish"} and role not in {"admin", "manager", "owner"}:
                        expectations.append(
                            ExpectedAccess(
                                "role",
                                role,
                                "workflow",
                                workflow_name,
                                "deny",
                                0.82,
                                [f"role:{role}:should_not_execute_privileged_workflow:{crud}"],
                            )
                        )
                    elif crud in {"create", "read", "pay"}:
                        expectations.append(
                            ExpectedAccess("role", role, "workflow", workflow_name, "allow", 0.55, ["observed_normal_user_action"])
                        )

        for tenant, object_ids in app_map.tenant_boundaries.items():
            expectations.append(
                ExpectedAccess(
                    "tenant",
                    tenant,
                    "object_group",
                    ",".join(object_ids[:20]),
                    "deny_cross_tenant",
                    0.9,
                    ["tenant_boundary_inferred_from_object_references"],
                )
            )

        for expectation in expectations:
            self.db.add(
                AuthorizationExpectation(
                    workspace_id=workspace_id,
                    application_id=application_id,
                    scan_job_id=scan_job_id,
                    subject_type=expectation.subject_type,
                    subject=expectation.subject,
                    resource_type=expectation.resource_type,
                    resource=expectation.resource,
                    expected_access=expectation.expected_access,
                    confidence=expectation.confidence,
                    rationale=expectation.rationale,
                )
            )
        await self.db.flush()
        return expectations
