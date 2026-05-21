from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import (
    AttackAttempt,
    AuthorizationGraphSnapshot,
    Endpoint,
    Identity,
    ObjectReference,
    TrafficLog,
    ValidationResult,
)


class GraphEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def build_graph(self, application_id: str, scan_job_id: str | None = None) -> dict:
        graph = AuthorizationGraphBuilder()
        identities = await self._all(Identity, Identity.application_id == application_id)
        endpoints = await self._all(Endpoint, Endpoint.application_id == application_id)
        objects = await self._all(ObjectReference, ObjectReference.application_id == application_id)
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
            verdict = await self._validation_verdict(attempt.id)
            if attempt.target_identity_id and attempt.object_reference_id:
                graph.add_edge(
                    f"user:{attempt.target_identity_id}",
                    f"object:{attempt.object_reference_id}",
                    relationship=attempt.attack_type,
                    status=verdict,
                )

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

    async def _validation_verdict(self, attack_attempt_id: str) -> str | None:
        result = await self.db.execute(
            select(ValidationResult.verdict).where(ValidationResult.attack_attempt_id == attack_attempt_id)
        )
        return result.scalar_one_or_none()

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
