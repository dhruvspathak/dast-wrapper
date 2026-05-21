from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import Endpoint, TrafficLog
from app.validation.normalization import ResponseNormalizer


class TrafficStore:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.normalizer = ResponseNormalizer()

    async def record(self, payload: dict) -> TrafficLog:
        endpoint = await self._upsert_endpoint(payload)
        request_hash = self.normalizer.normalize_body(payload.get("request_body")).body_hash
        response_hash = self.normalizer.normalize_body(payload.get("response_body")).body_hash
        traffic = TrafficLog(
            workspace_id=payload["workspace_id"],
            application_id=payload["application_id"],
            scan_job_id=payload.get("scan_job_id"),
            identity_id=payload.get("identity_id"),
            session_id=payload.get("session_id"),
            endpoint_id=endpoint.id if endpoint else None,
            parent_traffic_log_id=payload.get("parent_traffic_log_id"),
            request_url=payload["request_url"],
            request_method=payload["request_method"],
            request_headers=payload.get("request_headers") or {},
            request_body=payload.get("request_body"),
            response_status=payload.get("response_status"),
            response_headers=payload.get("response_headers") or {},
            response_body=payload.get("response_body"),
            response_size=payload.get("response_size"),
            elapsed_ms=payload.get("elapsed_ms"),
            source=payload.get("source", "crawler"),
            source_type=payload.get("source_type", payload.get("source", "crawl")),
            attack_chain_id=payload.get("attack_chain_id"),
            replay_depth=payload.get("replay_depth", 0),
            discovered_by=payload.get("discovered_by"),
            normalized_request_hash=request_hash,
            normalized_response_hash=response_hash,
        )
        self.db.add(traffic)
        await self.db.flush()
        await self.db.refresh(traffic)
        return traffic

    async def _upsert_endpoint(self, payload: dict) -> Endpoint | None:
        parsed = urlparse(payload["request_url"])
        path = parsed.path or "/"
        normalized = normalize_path(path)
        result = await self.db.execute(
            select(Endpoint).where(
                Endpoint.application_id == payload["application_id"],
                Endpoint.method == payload["request_method"],
                Endpoint.normalized_path == normalized,
            )
        )
        endpoint = result.scalar_one_or_none()
        if endpoint:
            return endpoint
        endpoint = Endpoint(
            workspace_id=payload["workspace_id"],
            application_id=payload["application_id"],
            method=payload["request_method"],
            url=payload["request_url"],
            path=path,
            normalized_path=normalized,
            first_seen_scan_id=payload.get("scan_job_id"),
            risk_tags=risk_tags_for_method(payload["request_method"]),
        )
        self.db.add(endpoint)
        await self.db.flush()
        await self.db.refresh(endpoint)
        return endpoint


def normalize_path(path: str) -> str:
    parts = []
    for part in path.split("/"):
        if part.isdigit():
            parts.append("{int}")
        elif is_uuid_like(part):
            parts.append("{uuid}")
        else:
            parts.append(part)
    return "/".join(parts)


def is_uuid_like(value: str) -> bool:
    return len(value) in {32, 36} and sum(char == "-" for char in value) in {0, 4}


def risk_tags_for_method(method: str) -> list[str]:
    method = method.upper()
    if method in {"POST", "PUT", "PATCH"}:
        return ["writes_object"]
    if method == "DELETE":
        return ["deletes_object"]
    return ["views_object"]
