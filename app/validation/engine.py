from __future__ import annotations

import json
from typing import Any

from app.validation.normalization import ResponseNormalizer


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
    def __init__(self, normalizer: ResponseNormalizer | None = None):
        self.normalizer = normalizer or ResponseNormalizer()

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
        normalized_diff = self.normalizer.semantic_diff(baseline_body, replay_body)
        baseline_json = self._json_or_none(baseline_body)
        replay_json = self._json_or_none(replay_body)

        status_allows_access = replay_status in {200, 201, 202, 204, 206}
        denied = replay_status in {401, 403, 404}
        size_similarity = self._size_similarity(len(baseline_body), len(replay_body))
        schema_similarity = self._schema_similarity(baseline_json, replay_json)
        sensitive_fields = sorted(self._sensitive_fields(replay_json))
        semantic_indicators = self._semantic_indicators(replay_body)
        leakage_indicators = self._leakage_indicators(baseline_json, replay_json, replay_body)
        access_anomalies = self._access_anomalies(baseline_json, replay_json)
        reasons: list[str] = []

        confidence = 0.0
        verdict = "not_exploitable"
        if status_allows_access:
            reasons.append("replay_identity_received_success_status")
            confidence += 0.35
            confidence += 0.25 * size_similarity
            confidence += 0.25 * schema_similarity
            if normalized_diff["structure_equal"]:
                confidence += 0.1
                reasons.append("normalized_response_structure_matches_baseline")
            if sensitive_fields:
                confidence += 0.1
                reasons.append("sensitive_fields_present_in_replay")
            if semantic_indicators:
                confidence += 0.05
                reasons.append("authorization_semantic_indicators_present")
            if leakage_indicators:
                confidence += 0.1
                reasons.append("leakage_indicators_present")
            if access_anomalies:
                confidence += 0.08
                reasons.append("access_pattern_anomalies_present")
            if replay_status == 204:
                reasons.append("state_changing_request_succeeded_without_body")
            verdict = "confirmed" if confidence >= 0.75 else "likely" if confidence >= 0.5 else "needs_review"
        elif denied:
            verdict = "blocked"
            confidence = 0.9
            reasons.append("replay_identity_was_denied")
        else:
            verdict = "needs_review"
            confidence = 0.25
            reasons.append("ambiguous_replay_status")

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
            "normalized_diff": normalized_diff,
            "sensitive_fields": sensitive_fields,
            "semantic_indicators": semantic_indicators,
            "leakage_indicators": leakage_indicators,
            "access_anomalies": access_anomalies,
            "validation_reasons": reasons,
            "evidence": {"attack_type": attack_type, "reasons": reasons},
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

    def _leakage_indicators(self, baseline: Any, replay: Any, replay_body: str) -> list[str]:
        indicators = []
        replay_paths = self._schema_keys(replay)
        for field in ["total", "count", "page", "next", "previous", "cursor", "has_more"]:
            if any(path.lower().endswith(field) for path in replay_paths):
                indicators.append(f"pagination_or_row_count:{field}")
        for field in ["created_by", "updated_by", "owner", "internal_id", "tenant_id", "deleted_at"]:
            if any(field in path.lower() for path in replay_paths):
                indicators.append(f"metadata_exposure:{field}")
        if 'type="hidden"' in replay_body.lower() or '"hidden"' in replay_body.lower():
            indicators.append("hidden_field_exposure")
        if baseline is not None and replay is not None:
            removed = self._schema_keys(baseline) - replay_paths
            added = replay_paths - self._schema_keys(baseline)
            if added and len(added) > len(removed):
                indicators.append("partial_data_leakage_schema_expansion")
        return sorted(set(indicators))

    def _access_anomalies(self, baseline: Any, replay: Any) -> list[str]:
        anomalies = []
        if isinstance(baseline, list) and isinstance(replay, list) and len(replay) > len(baseline) * 2 and len(replay) > 10:
            anomalies.append("row_count_expansion")
        if isinstance(baseline, dict) and isinstance(replay, dict):
            for key in ("items", "results", "data"):
                if isinstance(baseline.get(key), list) and isinstance(replay.get(key), list):
                    if len(replay[key]) > len(baseline[key]) * 2 and len(replay[key]) > 10:
                        anomalies.append(f"row_count_expansion:{key}")
        return anomalies
