from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[1-5][0-9a-fA-F]{3}-?[89abAB][0-9a-fA-F]{3}-?[0-9a-fA-F]{12}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
EPOCH_RE = re.compile(r"\b1[6-9]\d{8,12}\b")
TOKEN_KEY_RE = re.compile(r"(csrf|token|session|nonce|trace|request[_-]?id|tracking|cursor|page)", re.I)


@dataclass(frozen=True)
class NormalizedResponse:
    raw_body: str
    normalized_body: str
    body_hash: str
    structure_hash: str
    json_body: Any | None
    schema_paths: set[str]


class ResponseNormalizer:
    def normalize_body(self, body: str | bytes | None) -> NormalizedResponse:
        raw = body.decode(errors="replace") if isinstance(body, bytes) else str(body or "")
        json_body = self._json_or_none(raw)
        if json_body is not None:
            normalized_json = self._normalize_json(json_body)
            normalized = json.dumps(normalized_json, sort_keys=True, separators=(",", ":"))
            schema_paths = self.schema_paths(normalized_json)
            structure = json.dumps(sorted(schema_paths), separators=(",", ":"))
        else:
            normalized = self._normalize_text(raw)
            schema_paths = set()
            structure = normalized
        return NormalizedResponse(
            raw_body=raw,
            normalized_body=normalized,
            body_hash=self.hash_text(normalized),
            structure_hash=self.hash_text(structure),
            json_body=json_body,
            schema_paths=schema_paths,
        )

    def semantic_diff(self, baseline: str | bytes | None, replay: str | bytes | None) -> dict[str, Any]:
        left = self.normalize_body(baseline)
        right = self.normalize_body(replay)
        common = left.schema_paths & right.schema_paths
        added = right.schema_paths - left.schema_paths
        removed = left.schema_paths - right.schema_paths
        return {
            "baseline_hash": left.body_hash,
            "replay_hash": right.body_hash,
            "baseline_structure_hash": left.structure_hash,
            "replay_structure_hash": right.structure_hash,
            "body_equal": left.body_hash == right.body_hash,
            "structure_equal": left.structure_hash == right.structure_hash,
            "schema_added": sorted(added),
            "schema_removed": sorted(removed),
            "schema_common_count": len(common),
        }

    def hash_text(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def schema_paths(self, value: Any, prefix: str = "") -> set[str]:
        paths: set[str] = set()
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                paths.add(path)
                paths |= self.schema_paths(child, path)
        elif isinstance(value, list):
            paths.add(f"{prefix}[]" if prefix else "[]")
            if value:
                paths |= self.schema_paths(value[0], f"{prefix}[]" if prefix else "[]")
        return paths

    def _json_or_none(self, raw: str) -> Any | None:
        try:
            return json.loads(raw)
        except Exception:
            return None

    def _normalize_json(self, value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {k: self._normalize_json(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self._normalize_json(item, key) for item in value]
        if isinstance(value, str):
            if key and TOKEN_KEY_RE.search(key):
                return "<dynamic-token>"
            return self._normalize_text(value)
        if isinstance(value, int) and key and TOKEN_KEY_RE.search(key):
            return "<dynamic-number>"
        return value

    def _normalize_text(self, value: str) -> str:
        normalized = JWT_RE.sub("<jwt>", value)
        normalized = UUID_RE.sub("<uuid>", normalized)
        normalized = ISO_TS_RE.sub("<timestamp>", normalized)
        normalized = EPOCH_RE.sub("<epoch>", normalized)
        return normalized
