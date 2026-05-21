from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import Endpoint, ObjectReference, TrafficLog
from app.crawling.ownership import OwnershipInferenceEngine


NUMERIC_ID = re.compile(r"(?<![A-Za-z0-9])\d{2,}(?![A-Za-z0-9])")
UUID = re.compile(
    r"[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[1-5][0-9a-fA-F]{3}-?[89abAB][0-9a-fA-F]{3}-?[0-9a-fA-F]{12}"
)
OBJECT_KEYS = {"id", "user_id", "account_id", "order_id", "resource_id", "tenant_id", "org_id", "owner_id"}
TENANT_KEYS = {"tenant", "tenant_id", "org", "org_id", "workspace", "workspace_id"}


class ObjectDiscoveryEngine:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.ownership = OwnershipInferenceEngine()

    async def discover_for_scan(self, scan_job_id: str) -> list[ObjectReference]:
        result = await self.db.execute(select(TrafficLog).where(TrafficLog.scan_job_id == scan_job_id))
        references: list[ObjectReference] = []
        for traffic in result.scalars().all():
            references.extend(await self.discover_from_traffic(traffic))
        return references

    async def discover_from_traffic(self, traffic: TrafficLog) -> list[ObjectReference]:
        endpoint = None
        if traffic.endpoint_id:
            endpoint = await self.db.get(Endpoint, traffic.endpoint_id)
        references = []
        for ref in self._references_from_url(traffic.request_url):
            references.append(await self._store_reference(traffic, endpoint, ref))
        for ref in self._references_from_body(traffic.request_body, "request_body"):
            references.append(await self._store_reference(traffic, endpoint, ref))
        for ref in self._references_from_body(traffic.response_body, "response_body"):
            references.append(await self._store_reference(traffic, endpoint, ref))
        return references

    def _references_from_url(self, url: str) -> list[dict]:
        parsed = urlparse(url)
        refs = []
        for segment in parsed.path.split("/"):
            refs.extend(self._classify_value(segment, "path"))
        for key, value in parse_qsl(parsed.query, keep_blank_values=False):
            refs.extend(self._classify_value(value, f"query:{key}", key=key))
        return refs

    def _references_from_body(self, body: str | None, location: str) -> list[dict]:
        if not body:
            return []
        refs: list[dict] = []
        try:
            decoded = json.loads(body)
        except Exception:
            for match in UUID.findall(body):
                refs.append({"type": "uuid", "value": match, "location": location})
            for match in NUMERIC_ID.findall(body):
                refs.append({"type": "numeric_id", "value": match, "location": location})
            return refs
        refs.extend(self._walk_json(decoded, location))
        return refs

    def _walk_json(self, value, location: str, key: str | None = None) -> list[dict]:
        refs = []
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                refs.extend(self._walk_json(child_value, f"{location}.{child_key}", child_key))
        elif isinstance(value, list):
            for index, child in enumerate(value[:100]):
                refs.extend(self._walk_json(child, f"{location}[{index}]", key))
        elif isinstance(value, (str, int)):
            refs.extend(self._classify_value(str(value), location, key=key))
        return refs

    def _classify_value(self, value: str, location: str, key: str | None = None) -> list[dict]:
        refs = []
        lowered = (key or "").lower()
        reference_type = "tenant" if lowered in TENANT_KEYS else "object"
        if lowered in OBJECT_KEYS or UUID.fullmatch(value) or NUMERIC_ID.fullmatch(value):
            if UUID.fullmatch(value):
                type_name = "uuid"
            elif NUMERIC_ID.fullmatch(value):
                type_name = "numeric_id"
            else:
                type_name = reference_type
            refs.append({"type": type_name, "value": value, "location": location, "key": key})
        return refs

    async def _store_reference(
        self,
        traffic: TrafficLog,
        endpoint: Endpoint | None,
        ref: dict,
    ) -> ObjectReference:
        existing = await self.db.execute(
            select(ObjectReference).where(
                ObjectReference.application_id == traffic.application_id,
                ObjectReference.identity_id == traffic.identity_id,
                ObjectReference.value == ref["value"],
                ObjectReference.location == ref["location"],
            )
        )
        current = existing.scalar_one_or_none()
        if current:
            return current
        ownership_signal = self.ownership.score(
            key=ref.get("key"),
            location=ref["location"],
            endpoint_path=endpoint.path if endpoint else None,
            identity_id=traffic.identity_id,
            reference_type=ref["type"],
        )
        evidence = {
            "traffic_log_id": traffic.id,
            "key": ref.get("key"),
            "ownership_reasons": ownership_signal.reasons,
        }
        reference = ObjectReference(
            workspace_id=traffic.workspace_id,
            application_id=traffic.application_id,
            endpoint_id=endpoint.id if endpoint else None,
            identity_id=traffic.identity_id,
            reference_type=ref["type"],
            value=ref["value"],
            location=ref["location"],
            ownership_confidence=ownership_signal.score,
            ownership_confidence_score=ownership_signal.score,
            tenant_hint=ref["value"] if ref["type"] == "tenant" else None,
            evidence=evidence,
        )
        self.db.add(reference)
        await self.db.flush()
        await self.db.refresh(reference)
        return reference
