from __future__ import annotations

import json
from typing import Any


SENSITIVE_FIELD_NAMES = {
    "email",
    "phone",
    "address",
    "ssn",
    "token",
    "secret",
    "api_key",
    "balance",
    "amount",
    "salary",
    "role",
    "permissions",
}


class ValidationEngine:
    def validate(
        self,
        *,
        baseline_response: dict[str, Any],
        replay_response: dict[str, Any],
        attack_type: str,
    ) -> dict[str, Any]:
        baseline_status = int(baseline_response.get("status_code") or baseline_response.get("status") or 0)
        replay_status = int(replay_response.get("status_code") or replay_response.get("status") or 0)
        baseline_body = str(baseline_response.get("body") or "")
        replay_body = str(replay_response.get("body") or "")
        baseline_json = self._json_or_none(baseline_body)
        replay_json = self._json_or_none(replay_body)

        status_allows_access = replay_status in {200, 201, 202, 204, 206}
        denied = replay_status in {401, 403, 404}
        size_similarity = self._size_similarity(len(baseline_body), len(replay_body))
        schema_similarity = self._schema_similarity(baseline_json, replay_json)
        sensitive_fields = sorted(self._sensitive_fields(replay_json))
        semantic_indicators = self._semantic_indicators(replay_body)

        confidence = 0.0
        verdict = "not_exploitable"
        if status_allows_access:
            confidence += 0.35
            confidence += 0.25 * size_similarity
            confidence += 0.25 * schema_similarity
            if sensitive_fields:
                confidence += 0.1
            if semantic_indicators:
                confidence += 0.05
            verdict = "confirmed" if confidence >= 0.75 else "likely" if confidence >= 0.5 else "needs_review"
        elif denied:
            verdict = "blocked"
            confidence = 0.9
        else:
            verdict = "needs_review"
            confidence = 0.25

        return {
            "verdict": verdict,
            "confidence": round(min(confidence, 1.0), 3),
            "status_code_delta": {"baseline": baseline_status, "replay": replay_status},
            "body_delta": {
                "baseline_size": len(baseline_body),
                "replay_size": len(replay_body),
                "size_similarity": round(size_similarity, 3),
                "schema_similarity": round(schema_similarity, 3),
            },
            "sensitive_fields": sensitive_fields,
            "semantic_indicators": semantic_indicators,
            "evidence": {"attack_type": attack_type},
        }

    def _json_or_none(self, body: str) -> Any | None:
        try:
            return json.loads(body)
        except Exception:
            return None

    def _size_similarity(self, baseline: int, replay: int) -> float:
        if baseline == 0 and replay == 0:
            return 1.0
        if baseline == 0 or replay == 0:
            return 0.0
        return min(baseline, replay) / max(baseline, replay)

    def _schema_similarity(self, baseline: Any, replay: Any) -> float:
        if baseline is None or replay is None:
            return 0.4
        baseline_keys = self._schema_keys(baseline)
        replay_keys = self._schema_keys(replay)
        if not baseline_keys and not replay_keys:
            return 1.0
        return len(baseline_keys & replay_keys) / max(len(baseline_keys | replay_keys), 1)

    def _schema_keys(self, value: Any, prefix: str = "") -> set[str]:
        keys = set()
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                keys.add(path)
                keys |= self._schema_keys(child, path)
        elif isinstance(value, list) and value:
            keys |= self._schema_keys(value[0], f"{prefix}[]")
        return keys

    def _sensitive_fields(self, value: Any, prefix: str = "") -> set[str]:
        fields = set()
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if key.lower() in SENSITIVE_FIELD_NAMES:
                    fields.add(path)
                fields |= self._sensitive_fields(child, path)
        elif isinstance(value, list):
            for child in value[:20]:
                fields |= self._sensitive_fields(child, prefix)
        return fields

    def _semantic_indicators(self, body: str) -> list[str]:
        lowered = body.lower()
        indicators = []
        for token in ["owner", "approved", "admin", "permission", "tenant", "account", "invoice"]:
            if token in lowered:
                indicators.append(token)
        return indicators
