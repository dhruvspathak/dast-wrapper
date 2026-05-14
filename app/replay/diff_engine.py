from __future__ import annotations

import hashlib
import json
import re
from difflib import SequenceMatcher, unified_diff
from typing import Any

from app.schemas.canonical import ResponseData

OWNERSHIP_KEYS = {
    "user_id",
    "userid",
    "owner_id",
    "ownerid",
    "account_id",
    "org_id",
    "organization_id",
    "tenant_id",
    "workspace_id",
    "report_id",
    "plan_id",
    "activity_id",
}

VOLATILE_PATTERNS = [
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
    re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"),
    re.compile(r"\b\d{10,13}\b"),
]


class ReplayDiffEngine:
    def fingerprint(self, response: ResponseData) -> str:
        normalized = {
            "status_code": response.status_code,
            "body": self._normalize_body(response.body or ""),
            "content_type": response.headers.get("content-type", ""),
        }
        encoded = json.dumps(normalized, sort_keys=True, default=str).encode()
        return hashlib.sha256(encoded).hexdigest()

    def compare(self, baseline: ResponseData | None, replay: ResponseData) -> dict[str, Any]:
        if baseline is None:
            replay.fingerprint = replay.fingerprint or self.fingerprint(replay)
            return {
                "comparable": False,
                "reason": "baseline_response_missing",
                "replay_fingerprint": replay.fingerprint,
                "semantic": self.semantic_summary(replay),
            }

        baseline_body = baseline.body or ""
        replay_body = replay.body or ""
        body_similarity = self.body_similarity(baseline_body, replay_body)
        timing_delta_ms = None
        if baseline.elapsed_ms is not None and replay.elapsed_ms is not None:
            timing_delta_ms = abs(replay.elapsed_ms - baseline.elapsed_ms)

        baseline.fingerprint = baseline.fingerprint or self.fingerprint(baseline)
        replay.fingerprint = replay.fingerprint or self.fingerprint(replay)

        semantic = {
            "baseline": self.semantic_summary(baseline),
            "replay": self.semantic_summary(replay),
            "ownership_delta": self.ownership_delta(baseline_body, replay_body),
        }

        diff_lines = list(
            unified_diff(
                self._normalize_body(baseline_body).splitlines(),
                self._normalize_body(replay_body).splitlines(),
                fromfile="baseline",
                tofile="replay",
                lineterm="",
            )
        )

        access_granted = replay.status_code is not None and replay.status_code < 400
        baseline_denied = baseline.status_code in {401, 403, 404}

        return {
            "comparable": True,
            "status_changed": baseline.status_code != replay.status_code,
            "baseline_status": baseline.status_code,
            "replay_status": replay.status_code,
            "body_similarity": body_similarity,
            "timing_delta_ms": timing_delta_ms,
            "baseline_fingerprint": baseline.fingerprint,
            "replay_fingerprint": replay.fingerprint,
            "fingerprint_changed": baseline.fingerprint != replay.fingerprint,
            "access_granted": access_granted,
            "baseline_denied": baseline_denied,
            "semantic": semantic,
            "diff_excerpt": diff_lines[:80],
        }

    def body_similarity(self, left: str, right: str) -> float:
        return round(SequenceMatcher(None, self._normalize_body(left), self._normalize_body(right)).ratio(), 4)

    def semantic_summary(self, response: ResponseData) -> dict[str, Any]:
        body = response.body or ""
        parsed = self._parse_json(body)
        ownership = self._extract_ownership(parsed if parsed is not None else body)
        return {
            "content_length": response.content_length if response.content_length is not None else len(body),
            "ownership": ownership,
            "has_error_terms": bool(re.search(r"\b(error|unauthorized|forbidden|denied|not found)\b", body, re.I)),
            "json_shape": self._json_shape(parsed) if parsed is not None else None,
        }

    def ownership_delta(self, baseline_body: str, replay_body: str) -> dict[str, Any]:
        baseline = self._extract_ownership(self._parse_json(baseline_body) or baseline_body)
        replay = self._extract_ownership(self._parse_json(replay_body) or replay_body)
        changed = {
            key: {"baseline": baseline.get(key), "replay": replay.get(key)}
            for key in set(baseline) | set(replay)
            if baseline.get(key) != replay.get(key)
        }
        return {"changed": changed, "changed_count": len(changed)}

    def _normalize_body(self, body: str) -> str:
        normalized = body.strip()
        for pattern in VOLATILE_PATTERNS:
            normalized = pattern.sub("<volatile>", normalized)
        return normalized

    def _parse_json(self, body: str) -> Any | None:
        try:
            return json.loads(body)
        except Exception:
            return None

    def _extract_ownership(self, value: Any) -> dict[str, Any]:
        found: dict[str, Any] = {}
        if isinstance(value, dict):
            for key, item in value.items():
                normalized_key = str(key).lower()
                if normalized_key in OWNERSHIP_KEYS:
                    found[normalized_key] = item
                if isinstance(item, (dict, list)):
                    found.update(self._extract_ownership(item))
        elif isinstance(value, list):
            for item in value:
                found.update(self._extract_ownership(item))
        elif isinstance(value, str):
            for key in OWNERSHIP_KEYS:
                match = re.search(rf"{re.escape(key)}[\"'=:\s]+([A-Za-z0-9_-]+)", value, re.I)
                if match:
                    found[key] = match.group(1)
        return found

    def _json_shape(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self._json_shape(item) for key, item in sorted(value.items())}
        if isinstance(value, list):
            return [self._json_shape(value[0])] if value else []
        return type(value).__name__
