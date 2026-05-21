from __future__ import annotations

from app.attack_engine.base import AttackTarget, AuthorizationAttack
from app.models.authorization import ObjectReference, Session, TrafficLog


class BOLAAttack(AuthorizationAttack):
    attack_type = "BOLA"

    async def discover_targets(
        self,
        *,
        traffic: list[TrafficLog],
        sessions: dict[str, Session],
        references: list[ObjectReference],
    ) -> list[AttackTarget]:
        targets = []
        for baseline in traffic:
            if not self._successful(baseline):
                continue
            ref = self._reference_for_request(
                baseline,
                [item for item in references if item.identity_id == baseline.identity_id],
            )
            if not ref or ref.reference_type not in {"numeric_id", "uuid", "object"}:
                continue
            for identity_id, session in sessions.items():
                if identity_id != baseline.identity_id:
                    targets.append(AttackTarget(baseline, session, ref))
        return targets


class HorizontalEscalationAttack(AuthorizationAttack):
    attack_type = "horizontal_privilege_escalation"

    async def discover_targets(
        self,
        *,
        traffic: list[TrafficLog],
        sessions: dict[str, Session],
        references: list[ObjectReference],
    ) -> list[AttackTarget]:
        targets = []
        for baseline in traffic:
            if not self._successful(baseline):
                continue
            for identity_id, session in sessions.items():
                if identity_id != baseline.identity_id:
                    targets.append(AttackTarget(baseline, session, self._reference_for_request(baseline, references)))
        return targets


class VerticalEscalationAttack(AuthorizationAttack):
    attack_type = "vertical_privilege_escalation"

    async def discover_targets(
        self,
        *,
        traffic: list[TrafficLog],
        sessions: dict[str, Session],
        references: list[ObjectReference],
    ) -> list[AttackTarget]:
        targets = []
        role_by_identity = {session.identity_id: session for session in sessions.values()}
        for baseline in traffic:
            if not self._successful(baseline) or baseline.request_method not in {"POST", "PUT", "PATCH", "DELETE"}:
                continue
            for identity_id, session in role_by_identity.items():
                if identity_id != baseline.identity_id:
                    targets.append(AttackTarget(baseline, session, self._reference_for_request(baseline, references)))
        return targets


class TenantBoundaryAttack(AuthorizationAttack):
    attack_type = "tenant_boundary_violation"

    async def discover_targets(
        self,
        *,
        traffic: list[TrafficLog],
        sessions: dict[str, Session],
        references: list[ObjectReference],
    ) -> list[AttackTarget]:
        tenant_refs = [ref for ref in references if ref.reference_type == "tenant" or ref.tenant_hint]
        targets = []
        for baseline in traffic:
            if not self._successful(baseline):
                continue
            ref = self._reference_for_request(baseline, tenant_refs)
            if not ref:
                continue
            for identity_id, session in sessions.items():
                if identity_id != baseline.identity_id:
                    targets.append(AttackTarget(baseline, session, ref))
        return targets


class WorkflowTransitionAttack(AuthorizationAttack):
    attack_type = "workflow_transition_abuse"

    async def discover_targets(
        self,
        *,
        traffic: list[TrafficLog],
        sessions: dict[str, Session],
        references: list[ObjectReference],
    ) -> list[AttackTarget]:
        targets = []
        for baseline in traffic:
            if not self._successful(baseline):
                continue
            body = (baseline.request_body or "") + " " + (baseline.response_body or "")
            if not any(token in body.lower() for token in ("approve", "approved", "paid", "archive", "archived", "status", "state")):
                continue
            for identity_id, session in sessions.items():
                if identity_id != baseline.identity_id:
                    targets.append(
                        AttackTarget(
                            baseline,
                            session,
                            self._reference_for_request(baseline, references),
                            mutation={"reason": "workflow_state_token_detected"},
                        )
                    )
        return targets
