from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import (
    ApplicationMapSnapshot,
    Endpoint,
    Identity,
    ObjectReference,
    TrafficLog,
    WorkflowTransition,
)


@dataclass(slots=True)
class ApplicationMap:
    entities: dict[str, dict] = field(default_factory=dict)
    workflows: dict[str, list[dict]] = field(default_factory=dict)
    transitions: list[dict] = field(default_factory=list)
    endpoint_clusters: dict[str, list[dict]] = field(default_factory=dict)
    object_groups: dict[str, list[dict]] = field(default_factory=dict)
    identity_patterns: dict[str, dict] = field(default_factory=dict)
    tenant_boundaries: dict[str, list[str]] = field(default_factory=dict)
    privilege_boundaries: dict[str, list[str]] = field(default_factory=dict)


class ApplicationMapper:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def build(self, application_id: str, scan_job_id: str | None = None) -> ApplicationMap:
        endpoints = await self._all(Endpoint, Endpoint.application_id == application_id)
        objects = await self._all(ObjectReference, ObjectReference.application_id == application_id)
        identities = await self._all(Identity, Identity.application_id == application_id)
        transitions = await self._all(WorkflowTransition, WorkflowTransition.application_id == application_id)
        traffic_query = select(TrafficLog).where(TrafficLog.application_id == application_id)
        if scan_job_id:
            traffic_query = traffic_query.where(TrafficLog.scan_job_id == scan_job_id)
        traffic = list((await self.db.execute(traffic_query)).scalars().all())

        app_map = ApplicationMap()
        app_map.endpoint_clusters = self._cluster_endpoints(endpoints)
        app_map.object_groups = self._group_objects(objects)
        app_map.entities = self._infer_entities(app_map.endpoint_clusters, app_map.object_groups)
        app_map.transitions = [
            {
                "from": item.from_state,
                "to": item.to_state,
                "action": item.transition_action,
                "confidence": item.confidence,
                "object_reference_id": item.object_reference_id,
            }
            for item in transitions
        ]
        app_map.workflows = self._infer_workflows(app_map.endpoint_clusters, app_map.transitions)
        app_map.identity_patterns = self._identity_patterns(identities, traffic)
        app_map.tenant_boundaries = self._tenant_boundaries(objects)
        app_map.privilege_boundaries = self._privilege_boundaries(identities, traffic)

        snapshot = ApplicationMapSnapshot(
            workspace_id=identities[0].workspace_id if identities else "default",
            application_id=application_id,
            scan_job_id=scan_job_id,
            map_data=asdict(app_map),
        )
        self.db.add(snapshot)
        await self.db.flush()
        return app_map

    def _cluster_endpoints(self, endpoints: list[Endpoint]) -> dict[str, list[dict]]:
        clusters: dict[str, list[dict]] = defaultdict(list)
        for endpoint in endpoints:
            parts = [part for part in endpoint.normalized_path.split("/") if part]
            root = parts[0] if parts else "root"
            clusters[root].append(
                {
                    "id": endpoint.id,
                    "method": endpoint.method,
                    "path": endpoint.normalized_path,
                    "crud": self._crud_action(endpoint),
                }
            )
        return dict(clusters)

    def _group_objects(self, objects: list[ObjectReference]) -> dict[str, list[dict]]:
        groups: dict[str, list[dict]] = defaultdict(list)
        for obj in objects:
            groups[obj.reference_type].append(
                {
                    "id": obj.id,
                    "value": obj.value,
                    "identity_id": obj.identity_id,
                    "tenant_hint": obj.tenant_hint,
                    "ownership_confidence": obj.ownership_confidence_score,
                }
            )
        return dict(groups)

    def _infer_entities(self, endpoint_clusters: dict[str, list[dict]], object_groups: dict[str, list[dict]]) -> dict[str, dict]:
        entities = {}
        for root, endpoints in endpoint_clusters.items():
            entities[root] = {
                "name": root.rstrip("s").title(),
                "endpoint_count": len(endpoints),
                "actions": sorted({endpoint["crud"] for endpoint in endpoints}),
                "object_types": sorted(object_groups.keys()),
            }
        return entities

    def _infer_workflows(self, endpoint_clusters: dict[str, list[dict]], transitions: list[dict]) -> dict[str, list[dict]]:
        workflows = {}
        for root, endpoints in endpoint_clusters.items():
            action_endpoints = [
                endpoint for endpoint in endpoints if endpoint["crud"] in {"approve", "refund", "archive", "publish", "pay", "delete", "edit"}
            ]
            related_transitions = [
                transition for transition in transitions if any(token in str(transition).lower() for token in [root.rstrip("s"), root])
            ]
            if action_endpoints or related_transitions:
                workflows[root] = action_endpoints + related_transitions
        return workflows

    def _identity_patterns(self, identities: list[Identity], traffic: list[TrafficLog]) -> dict[str, dict]:
        patterns = {}
        by_identity: dict[str, list[TrafficLog]] = defaultdict(list)
        for log in traffic:
            if log.identity_id:
                by_identity[log.identity_id].append(log)
        for identity in identities:
            logs = by_identity.get(identity.id, [])
            patterns[identity.id] = {
                "role": identity.role,
                "request_count": len(logs),
                "methods": sorted({log.request_method for log in logs}),
                "state_changing_count": sum(1 for log in logs if log.request_method in {"POST", "PUT", "PATCH", "DELETE"}),
            }
        return patterns

    def _tenant_boundaries(self, objects: list[ObjectReference]) -> dict[str, list[str]]:
        boundaries: dict[str, list[str]] = defaultdict(list)
        for obj in objects:
            if obj.tenant_hint:
                boundaries[obj.tenant_hint].append(obj.id)
        return dict(boundaries)

    def _privilege_boundaries(self, identities: list[Identity], traffic: list[TrafficLog]) -> dict[str, list[str]]:
        role_by_identity = {identity.id: identity.role for identity in identities}
        boundaries: dict[str, set[str]] = defaultdict(set)
        for log in traffic:
            role = role_by_identity.get(log.identity_id or "")
            if role:
                boundaries[role].add(log.request_method)
        return {role: sorted(methods) for role, methods in boundaries.items()}

    def _crud_action(self, endpoint: Endpoint) -> str:
        path = endpoint.normalized_path.lower()
        for action in ("approve", "refund", "archive", "publish", "pay"):
            if action in path:
                return action
        if endpoint.method == "POST":
            return "create"
        if endpoint.method in {"PUT", "PATCH"}:
            return "edit"
        if endpoint.method == "DELETE":
            return "delete"
        return "read"

    async def _all(self, model, *criteria) -> list:
        result = await self.db.execute(select(model).where(*criteria))
        return list(result.scalars().all())
