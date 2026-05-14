from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import hashlib
import json
from typing import Any

from app.schemas.canonical import Finding, RequestData, ResponseData, Severity


@dataclass(slots=True)
class ScanTarget:
    url: str
    auth_headers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScannerFinding:
    title: str
    severity: str
    description: str | None = None
    url: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    request: dict[str, Any] | str | None = None
    response: dict[str, Any] | str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


class ScannerPlugin(ABC):
    name: str

    @abstractmethod
    def start_scan(self, target: ScanTarget) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_status(self, scanner_scan_id: str) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_findings(self, scanner_scan_id: str) -> list[ScannerFinding]:
        raise NotImplementedError

    def normalize_finding(self, scan_id: str, finding: ScannerFinding, workspace_id: str = "default") -> Finding:
        request = normalize_request(finding.request, finding.url)
        response = normalize_response(finding.response)
        fingerprint_source = {
            "scanner": self.name,
            "title": finding.title,
            "severity": finding.severity,
            "url": finding.url,
            "cwe": finding.cwe,
            "method": request.method if request else None,
        }
        fingerprint = hashlib.sha256(
            json.dumps(fingerprint_source, sort_keys=True, default=str).encode()
        ).hexdigest()
        return Finding(
            scan_id=scan_id,
            workspace_id=workspace_id,
            scanner=self.name,
            scanner_finding_id=str(finding.raw.get("pluginId") or finding.raw.get("id") or "") or None,
            title=finding.title,
            description=finding.description,
            severity=normalize_severity(finding.severity),
            url=finding.url,
            cwe=finding.cwe,
            owasp=finding.owasp,
            request=request,
            response=response,
            evidence={"scanner_confidence": finding.raw.get("confidence")},
            raw=finding.raw,
            fingerprint=fingerprint,
        )


def normalize_severity(value: str | None) -> Severity:
    normalized = (value or "info").lower()
    if normalized in {"informational", "info"}:
        return Severity.info
    if normalized in {"low", "medium", "high", "critical"}:
        return Severity(normalized)
    return Severity.info


def normalize_request(value: dict[str, Any] | str | None, fallback_url: str | None = None) -> RequestData | None:
    if value is None and not fallback_url:
        return None
    if isinstance(value, dict):
        data = dict(value)
        data.setdefault("url", fallback_url)
        return RequestData(**data)
    if isinstance(value, str):
        return RequestData(method=_extract_method(value), url=_extract_url(value) or fallback_url or "", body=value)
    return RequestData(url=fallback_url or "")


def normalize_response(value: dict[str, Any] | str | None) -> ResponseData | None:
    if value is None:
        return None
    if isinstance(value, dict):
        data = dict(value)
        if "content" in data and "body" not in data:
            data["body"] = data.pop("content")
        if "response_time" in data and "elapsed_ms" not in data:
            data["elapsed_ms"] = float(data.pop("response_time")) * 1000
        return ResponseData(**data)
    return ResponseData(body=value, content_length=len(value))


def _extract_method(raw_request: str) -> str:
    first_line = raw_request.splitlines()[0] if raw_request else ""
    token = first_line.split(" ", 1)[0]
    return token if token else "GET"


def _extract_url(raw_request: str) -> str | None:
    for line in raw_request.splitlines():
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            first_line = raw_request.splitlines()[0]
            path = first_line.split(" ")[1] if " " in first_line else "/"
            return f"http://{host}{path}"
    return None
