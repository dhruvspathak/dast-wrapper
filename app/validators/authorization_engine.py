from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.replay.replay_engine import ReplayEngine
from app.schemas.canonical import AuthContext, RequestData, ValidationResult, ValidationStatus

IDENTIFIER_NAMES = [
    "user_id",
    "userId",
    "plan_id",
    "planId",
    "report_id",
    "reportId",
    "org_id",
    "orgId",
    "activity_id",
    "activityId",
    "tenant_id",
    "tenantId",
    "workspace_id",
    "workspaceId",
]


@dataclass(slots=True)
class AuthorizationMutation:
    kind: str
    identifier: str
    original_value: str
    mutated_value: str

    def as_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "original_value": self.original_value,
            "mutated_value": self.mutated_value,
        }


class AuthorizationValidationEngine:
    def __init__(self, replay_engine: ReplayEngine):
        self.replay_engine = replay_engine

    async def validate(
        self,
        request: RequestData | dict[str, Any],
        auth_contexts: list[AuthContext],
        baseline_role: str | None = None,
    ) -> ValidationResult:
        canonical_request = request if isinstance(request, RequestData) else RequestData(**request)
        if len(auth_contexts) < 2:
            return ValidationResult(
                validator="authorization",
                status=ValidationStatus.needs_manual_review,
                confidence=0.2,
                evidence={"reason": "At least two role-isolated auth contexts are required"},
            )

        baseline_context = self._choose_baseline(auth_contexts, baseline_role)
        baseline_replay = await self.replay_engine.replay_canonical(
            canonical_request,
            auth_context=baseline_context,
        )

        mutations = self.generate_identifier_mutations(canonical_request, auth_contexts)
        evidence: dict[str, Any] = {
            "baseline_role": baseline_context.role,
            "baseline": baseline_replay.replay_response.model_dump(mode="json"),
            "mutations": [mutation.as_dict() for mutation in mutations],
            "role_results": [],
        }

        suspicious = 0
        total = 0

        for context in auth_contexts:
            if context.id == baseline_context.id:
                continue

            role_replay = await self.replay_engine.replay_canonical(
                canonical_request,
                auth_context=context,
                baseline_response=baseline_replay.replay_response,
            )
            role_signal = self._score_role_replay(role_replay.diff)
            suspicious += role_signal
            total += 1
            evidence["role_results"].append(
                {
                    "role": context.role,
                    "kind": "token_swap",
                    "score": role_signal,
                    "diff": role_replay.diff,
                }
            )

            for mutation in mutations:
                mutated_request = self.apply_mutation(canonical_request, mutation)
                replay = await self.replay_engine.replay_canonical(
                    mutated_request,
                    auth_context=context,
                    baseline_response=baseline_replay.replay_response,
                )
                mutation_signal = self._score_role_replay(replay.diff)
                suspicious += mutation_signal
                total += 1
                evidence["role_results"].append(
                    {
                        "role": context.role,
                        "kind": mutation.kind,
                        "mutation": mutation.as_dict(),
                        "score": mutation_signal,
                        "diff": replay.diff,
                    }
                )

        confidence = round(min(1.0, suspicious / max(total, 1)), 2)
        exploitable = confidence >= 0.6
        if exploitable:
            status = ValidationStatus.confirmed if confidence >= 0.8 else ValidationStatus.likely
        else:
            status = ValidationStatus.needs_manual_review if total else ValidationStatus.false_positive

        return ValidationResult(
            validator="authorization",
            status=status,
            confidence=confidence,
            exploitable=exploitable,
            evidence=evidence,
            remediation=[
                "Enforce object-level authorization on every server-side resource access.",
                "Bind resource ownership checks to authenticated subject, role, tenant, and workspace.",
                "Add negative authorization tests for cross-user and cross-role object access.",
            ],
        )

    def generate_identifier_mutations(
        self,
        request: RequestData,
        auth_contexts: list[AuthContext],
    ) -> list[AuthorizationMutation]:
        identifiers = self.extract_identifiers(request)
        candidate_values = self._candidate_values_from_contexts(auth_contexts)
        mutations: list[AuthorizationMutation] = []
        for name, value in identifiers.items():
            replacements = [item for item in candidate_values if item != value]
            replacements.append("999999")
            for replacement in replacements[:3]:
                mutations.append(
                    AuthorizationMutation(
                        kind="identifier_swap",
                        identifier=name,
                        original_value=value,
                        mutated_value=replacement,
                    )
                )
        return mutations

    def extract_identifiers(self, request: RequestData) -> dict[str, str]:
        found: dict[str, str] = {}
        url_parts = urlsplit(request.url)
        for key, value in parse_qsl(url_parts.query, keep_blank_values=True):
            if key in IDENTIFIER_NAMES:
                found[key] = value
        for name in IDENTIFIER_NAMES:
            pattern = re.compile(rf"(?P<key>{re.escape(name)})[\"'=:\s/]+(?P<value>[A-Za-z0-9_-]+)")
            for source in [url_parts.path, str(request.body or "")]:
                match = pattern.search(source)
                if match:
                    found[match.group("key")] = match.group("value")
        return found

    def apply_mutation(self, request: RequestData, mutation: AuthorizationMutation) -> RequestData:
        data = copy.deepcopy(request.model_dump())
        data["url"] = self._replace_in_url(data["url"], mutation)
        if data.get("body") is not None:
            data["body"] = str(data["body"]).replace(mutation.original_value, mutation.mutated_value)
        if mutation.identifier in data.get("query_params", {}):
            data["query_params"][mutation.identifier] = mutation.mutated_value
        return RequestData(**data)

    def _replace_in_url(self, url: str, mutation: AuthorizationMutation) -> str:
        parts = urlsplit(url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        new_params = [
            (key, mutation.mutated_value if key == mutation.identifier and value == mutation.original_value else value)
            for key, value in params
        ]
        path = parts.path.replace(mutation.original_value, mutation.mutated_value)
        return urlunsplit((parts.scheme, parts.netloc, path, urlencode(new_params), parts.fragment))

    def _choose_baseline(self, contexts: list[AuthContext], role: str | None) -> AuthContext:
        if role:
            for context in contexts:
                if context.role == role:
                    return context
        return contexts[0]

    def _candidate_values_from_contexts(self, contexts: list[AuthContext]) -> list[str]:
        values: list[str] = []
        for context in contexts:
            for source in [context.local_storage, context.session_storage, context.metadata]:
                for key, value in source.items():
                    if key in IDENTIFIER_NAMES and value is not None:
                        values.append(str(value))
        return values

    def _score_role_replay(self, diff: dict[str, Any]) -> int:
        if not diff.get("access_granted"):
            return 0
        if diff.get("baseline_denied"):
            return 1
        if diff.get("body_similarity", 0) >= 0.85:
            return 1
        semantic = diff.get("semantic", {})
        ownership_delta = semantic.get("ownership_delta", {})
        if ownership_delta.get("changed_count", 0) > 0 and diff.get("replay_status", 0) < 400:
            return 1
        return 0
