from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.authorization import ObjectReference, TrafficLog, WorkflowTransition


STATE_KEYS = {"state", "status", "stage", "lifecycle", "approval_status", "payment_status"}
SUSPICIOUS_TRANSITIONS = {
    ("created", "approved"),
    ("draft", "published"),
    ("pending", "paid"),
    ("active", "archived"),
    ("archived", "active"),
}


@dataclass
class WorkflowStateMachine:
    transitions: dict[str, set[str]] = field(default_factory=dict)

    def add_transition(self, from_state: str | None, to_state: str) -> None:
        self.transitions.setdefault(from_state or "<unknown>", set()).add(to_state)

    def is_suspicious(self, from_state: str | None, to_state: str) -> bool:
        return (from_state or "", to_state) in SUSPICIOUS_TRANSITIONS

    def as_dict(self) -> dict[str, list[str]]:
        return {state: sorted(targets) for state, targets in self.transitions.items()}


class WorkflowDiscoveryEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def discover_from_traffic(
        self,
        traffic: list[TrafficLog],
        objects: list[ObjectReference],
    ) -> WorkflowStateMachine:
        machine = WorkflowStateMachine()
        last_state_by_object: dict[str, str] = {}
        object_by_value = {obj.value: obj for obj in objects}
        for log in traffic:
            states = self._extract_states(log.response_body)
            if not states:
                continue
            obj = self._object_for_log(log, object_by_value)
            for state in states:
                previous = last_state_by_object.get(obj.id if obj else log.request_url)
                machine.add_transition(previous, state)
                await self._persist_transition(log, obj, previous, state, machine.is_suspicious(previous, state))
                last_state_by_object[obj.id if obj else log.request_url] = state
        return machine

    def _extract_states(self, body: str | None) -> list[str]:
        if not body:
            return []
        try:
            payload = json.loads(body)
        except Exception:
            return []
        states: list[str] = []
        self._walk(payload, states)
        return states

    def _walk(self, value: Any, states: list[str]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in STATE_KEYS and isinstance(child, str):
                    states.append(child.lower())
                self._walk(child, states)
        elif isinstance(value, list):
            for item in value[:50]:
                self._walk(item, states)

    def _object_for_log(
        self,
        log: TrafficLog,
        object_by_value: dict[str, ObjectReference],
    ) -> ObjectReference | None:
        haystack = f"{log.request_url} {log.request_body or ''} {log.response_body or ''}"
        for value, obj in object_by_value.items():
            if value in haystack:
                return obj
        return None

    async def _persist_transition(
        self,
        log: TrafficLog,
        obj: ObjectReference | None,
        from_state: str | None,
        to_state: str,
        suspicious: bool,
    ) -> None:
        transition = WorkflowTransition(
            workspace_id=log.workspace_id,
            application_id=log.application_id,
            scan_job_id=log.scan_job_id,
            object_reference_id=obj.id if obj else None,
            identity_id=log.identity_id,
            endpoint_id=log.endpoint_id,
            from_state=from_state,
            to_state=to_state,
            transition_action=log.request_method,
            confidence=0.85 if suspicious else 0.55,
            evidence={"traffic_log_id": log.id, "suspicious": suspicious},
        )
        self.db.add(transition)
        await self.db.flush()
