from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import (
    AttackAttempt,
    AttackChain,
    AuthorizationGraphSnapshot,
    Endpoint,
    EvidenceRecord,
    Identity,
    ObjectReference,
    TrafficLog,
    ValidationResult,
    WorkflowTransition,
)


class GraphEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def build_graph(self, application_id: str, scan_job_id: str | None = None) -> dict:
        graph = AuthorizationGraphBuilder()
        identities = await self._all(Identity, Identity.application_id == application_id)
        endpoints = await self._all(Endpoint, Endpoint.application_id == application_id)
        objects = await self._all(ObjectReference, ObjectReference.application_id == application_id)
        transitions = await self._all(WorkflowTransition, WorkflowTransition.application_id == application_id)
        chains = await self._all(AttackChain, AttackChain.application_id == application_id)
        traffic_query = select(TrafficLog).where(TrafficLog.application_id == application_id)
        if scan_job_id:
            traffic_query = traffic_query.where(TrafficLog.scan_job_id == scan_job_id)
        traffic = list((await self.db.execute(traffic_query)).scalars().all())
        attempts = list(
            (
                await self.db.execute(
                    select(AttackAttempt).where(
                        AttackAttempt.application_id == application_id,
                        *((AttackAttempt.scan_job_id == scan_job_id,) if scan_job_id else ()),
                    )
                )
            )
            .scalars()
            .all()
        )

        for identity in identities:
            graph.add_node(f"user:{identity.id}", kind="user", label=identity.label, role=identity.role)
            graph.add_node(f"role:{identity.role}", kind="role", label=identity.role)
            graph.add_edge(f"user:{identity.id}", f"role:{identity.role}", relationship="has_role")

        for endpoint in endpoints:
            graph.add_node(
                f"endpoint:{endpoint.id}",
                kind="endpoint",
                method=endpoint.method,
                path=endpoint.normalized_path,
            )

        for obj in objects:
            graph.add_node(
                f"object:{obj.id}",
                kind="object",
                reference_type=obj.reference_type,
                value=obj.value,
                tenant_hint=obj.tenant_hint,
                ownership_confidence=obj.ownership_confidence_score,
            )
            if obj.identity_id:
                graph.add_edge(f"user:{obj.identity_id}", f"object:{obj.id}", relationship="owns")
            if obj.endpoint_id:
                graph.add_edge(f"endpoint:{obj.endpoint_id}", f"object:{obj.id}", relationship="references")

        for log in traffic:
            if log.identity_id and log.endpoint_id:
                graph.add_edge(
                    f"user:{log.identity_id}",
                    f"endpoint:{log.endpoint_id}",
                    relationship=self._permission_for_method(log.request_method),
                    status=log.response_status,
                )

        for attempt in attempts:
            validation = await self._validation(attempt.id)
            attack_node = f"attack:{attempt.id}"
            graph.add_node(
                attack_node,
                kind="attack",
                attack_type=attempt.attack_type,
                status=attempt.status,
                verdict=validation.verdict if validation else None,
                confidence=validation.confidence if validation else None,
            )
            if attempt.baseline_traffic_log_id:
                graph.add_edge(f"traffic:{attempt.baseline_traffic_log_id}", attack_node, relationship="baseline_for")
            if attempt.replay_traffic_log_id:
                graph.add_edge(attack_node, f"traffic:{attempt.replay_traffic_log_id}", relationship="replayed_as")
            if attempt.target_identity_id and attempt.object_reference_id:
                graph.add_edge(
                    f"user:{attempt.target_identity_id}",
                    f"object:{attempt.object_reference_id}",
                    relationship=attempt.attack_type,
                    status=validation.verdict if validation else None,
                )
            if validation:
                validation_node = f"validation:{validation.id}"
                graph.add_node(
                    validation_node,
                    kind="validation",
                    verdict=validation.verdict,
                    confidence=validation.confidence,
                    reasons=validation.validation_reasons,
                )
                graph.add_edge(attack_node, validation_node, relationship="validated_by")

        for log in traffic:
            graph.add_node(
                f"traffic:{log.id}",
                kind="traffic",
                source_type=log.source_type,
                replay_depth=log.replay_depth,
                normalized_response_hash=log.normalized_response_hash,
            )
            if log.parent_traffic_log_id:
                graph.add_edge(f"traffic:{log.parent_traffic_log_id}", f"traffic:{log.id}", relationship="lineage_parent")

        for chain in chains:
            chain_node = f"chain:{chain.id}"
            graph.add_node(chain_node, kind="attack_chain", chain_type=chain.chain_type, status=chain.status)
            if chain.root_traffic_log_id:
                graph.add_edge(chain_node, f"traffic:{chain.root_traffic_log_id}", relationship="starts_from")

        for transition in transitions:
            node = f"workflow:{transition.id}"
            graph.add_node(
                node,
                kind="workflow_transition",
                from_state=transition.from_state,
                to_state=transition.to_state,
                confidence=transition.confidence,
            )
            if transition.object_reference_id:
                graph.add_edge(f"object:{transition.object_reference_id}", node, relationship="has_transition")
            if transition.endpoint_id:
                graph.add_edge(f"endpoint:{transition.endpoint_id}", node, relationship="caused_transition")

        payload = graph.to_node_link_data()
        snapshot = AuthorizationGraphSnapshot(
            workspace_id=identities[0].workspace_id if identities else "default",
            application_id=application_id,
            scan_job_id=scan_job_id,
            graph=payload,
        )
        self.db.add(snapshot)
        await self.db.flush()
        return payload

    async def _validation(self, attack_attempt_id: str) -> ValidationResult | None:
        result = await self.db.execute(
            select(ValidationResult).where(ValidationResult.attack_attempt_id == attack_attempt_id)
        )
        return result.scalar_one_or_none()

    async def objects_owned_by_user(self, identity_id: str) -> list[ObjectReference]:
        return await self._all(ObjectReference, ObjectReference.identity_id == identity_id)

    async def endpoints_accessed_by_role(self, application_id: str, role: str) -> list[Endpoint]:
        result = await self.db.execute(
            select(Endpoint)
            .join(TrafficLog, TrafficLog.endpoint_id == Endpoint.id)
            .join(Identity, Identity.id == TrafficLog.identity_id)
            .where(Endpoint.application_id == application_id, Identity.role == role)
        )
        return list(result.scalars().unique().all())

    async def attack_paths(self, scan_job_id: str) -> list[dict]:
        result = await self.db.execute(
            select(AttackAttempt, ValidationResult)
            .join(ValidationResult, ValidationResult.attack_attempt_id == AttackAttempt.id)
            .where(AttackAttempt.scan_job_id == scan_job_id)
        )
        return [
            {
                "attack_attempt_id": attempt.id,
                "attack_chain_id": attempt.attack_chain_id,
                "source_identity_id": attempt.source_identity_id,
                "target_identity_id": attempt.target_identity_id,
                "object_reference_id": attempt.object_reference_id,
                "verdict": validation.verdict,
                "confidence": validation.confidence,
            }
            for attempt, validation in result.all()
        ]

    async def _all(self, model, *criteria) -> list:
        result = await self.db.execute(select(model).where(*criteria))
        return list(result.scalars().all())

    def _permission_for_method(self, method: str) -> str:
        method = method.upper()
        if method == "DELETE":
            return "deletes"
        if method in {"POST", "PUT", "PATCH"}:
            return "edits"
        return "views"


class AuthorizationGraphBuilder:
    def __init__(self):
        try:
            import networkx as nx

            self._nx = nx
            self._graph = nx.MultiDiGraph()
        except ModuleNotFoundError:
            self._nx = None
            self._nodes: dict[str, dict] = {}
            self._edges: list[dict] = []

    def add_node(self, node_id: str, **attrs) -> None:
        if self._nx:
            self._graph.add_node(node_id, **attrs)
            return
        self._nodes[node_id] = {"id": node_id, **attrs}

    def add_edge(self, source: str, target: str, **attrs) -> None:
        if self._nx:
            self._graph.add_edge(source, target, **attrs)
            return
        self._edges.append({"source": source, "target": target, **attrs})

    def to_node_link_data(self) -> dict:
        if self._nx:
            from networkx.readwrite import json_graph

            return json_graph.node_link_data(self._graph, edges="edges")
        return {"directed": True, "multigraph": True, "nodes": list(self._nodes.values()), "edges": self._edges}
