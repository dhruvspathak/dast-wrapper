from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import ObjectReference, ObjectRelationship


@dataclass(slots=True)
class ObjectRelationshipGraph:
    edges: list[dict] = field(default_factory=list)

    def ownership_chains(self) -> list[list[str]]:
        parent_by_child = {edge["source"]: edge["target"] for edge in self.edges if edge["relationship_type"] == "belongs_to"}
        chains = []
        for child in parent_by_child:
            chain = [child]
            current = child
            seen = {child}
            while current in parent_by_child and parent_by_child[current] not in seen:
                current = parent_by_child[current]
                chain.append(current)
                seen.add(current)
            if len(chain) > 1:
                chains.append(chain)
        return chains


class ObjectRelationshipInferenceEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def infer(
        self,
        *,
        application_id: str,
        workspace_id: str,
        objects: list[ObjectReference],
        scan_job_id: str | None = None,
    ) -> ObjectRelationshipGraph:
        graph = ObjectRelationshipGraph()
        by_endpoint: dict[str, list[ObjectReference]] = defaultdict(list)
        for obj in objects:
            if obj.endpoint_id:
                by_endpoint[obj.endpoint_id].append(obj)

        for endpoint_id, refs in by_endpoint.items():
            tenant_refs = [ref for ref in refs if ref.reference_type == "tenant" or ref.tenant_hint]
            object_refs = [ref for ref in refs if ref not in tenant_refs]
            for obj in object_refs:
                for tenant in tenant_refs:
                    await self._add_edge(
                        graph,
                        workspace_id,
                        application_id,
                        scan_job_id,
                        obj,
                        tenant,
                        "belongs_to",
                        0.84,
                        {"endpoint_id": endpoint_id, "reason": "object_and_tenant_seen_in_same_endpoint"},
                    )
            for parent in refs:
                key = str(parent.evidence.get("key") or "").lower()
                if key in {"account_id", "project_id", "org_id", "tenant_id"}:
                    for child in refs:
                        if child.id != parent.id and child.ownership_confidence_score <= parent.ownership_confidence_score:
                            await self._add_edge(
                                graph,
                                workspace_id,
                                application_id,
                                scan_job_id,
                                child,
                                parent,
                                "belongs_to",
                                0.65,
                                {"endpoint_id": endpoint_id, "reason": f"parent_key:{key}"},
                            )
        return graph

    async def _add_edge(
        self,
        graph: ObjectRelationshipGraph,
        workspace_id: str,
        application_id: str,
        scan_job_id: str | None,
        source: ObjectReference,
        target: ObjectReference,
        relationship_type: str,
        confidence: float,
        evidence: dict,
    ) -> None:
        graph.edges.append(
            {
                "source": source.id,
                "target": target.id,
                "relationship_type": relationship_type,
                "confidence": confidence,
                "evidence": evidence,
            }
        )
        self.db.add(
            ObjectRelationship(
                workspace_id=workspace_id,
                application_id=application_id,
                scan_job_id=scan_job_id,
                source_object_reference_id=source.id,
                target_object_reference_id=target.id,
                relationship_type=relationship_type,
                confidence=confidence,
                evidence=evidence,
            )
        )
        await self.db.flush()
