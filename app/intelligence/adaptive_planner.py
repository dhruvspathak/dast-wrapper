from __future__ import annotations

from dataclasses import dataclass, field

from app.intelligence.application_mapper import ApplicationMap
from app.intelligence.expectations import ExpectedAccess
from app.intelligence.relationships import ObjectRelationshipGraph


@dataclass(slots=True)
class AdaptiveAttackStep:
    action: str
    target: str
    attack_type: str
    priority: float
    rationale: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AdaptiveAttackPlan:
    steps: list[AdaptiveAttackStep]

    def prioritized(self) -> list[AdaptiveAttackStep]:
        return sorted(self.steps, key=lambda step: step.priority, reverse=True)


class AdaptiveAttackPlanner:
    def plan(
        self,
        *,
        app_map: ApplicationMap,
        expectations: list[ExpectedAccess],
        relationships: ObjectRelationshipGraph | None = None,
    ) -> AdaptiveAttackPlan:
        steps: list[AdaptiveAttackStep] = []
        for expectation in expectations:
            if expectation.expected_access in {"deny", "deny_cross_tenant"}:
                steps.append(
                    AdaptiveAttackStep(
                        action="replay_expected_denied_access",
                        target=f"{expectation.resource_type}:{expectation.resource}",
                        attack_type="tenant_boundary_violation"
                        if expectation.expected_access == "deny_cross_tenant"
                        else "vertical_privilege_escalation",
                        priority=expectation.confidence + 0.1,
                        rationale=expectation.rationale,
                    )
                )

        for workflow, workflow_steps in app_map.workflows.items():
            actions = {str(step.get("crud") or step.get("action")) for step in workflow_steps}
            if {"create", "approve"} <= actions:
                steps.append(
                    AdaptiveAttackStep(
                        action="chain_create_to_approve",
                        target=f"workflow:{workflow}",
                        attack_type="workflow_transition_abuse",
                        priority=0.88,
                        rationale=["workflow_supports_create_and_approve"],
                        prerequisites=["create_object", "switch_identity", "approve_object"],
                    )
                )
            if {"pay", "refund"} & actions:
                steps.append(
                    AdaptiveAttackStep(
                        action="test_payment_or_refund_state_skip",
                        target=f"workflow:{workflow}",
                        attack_type="workflow_transition_abuse",
                        priority=0.8,
                        rationale=["payment_or_refund_workflow_detected"],
                    )
                )

        if relationships:
            for chain in relationships.ownership_chains():
                steps.append(
                    AdaptiveAttackStep(
                        action="pivot_nested_object_relationship",
                        target="->".join(chain),
                        attack_type="BOLA",
                        priority=0.75 + min(len(chain) * 0.03, 0.15),
                        rationale=["nested_ownership_chain_detected"],
                    )
                )

        return AdaptiveAttackPlan(steps=steps)
