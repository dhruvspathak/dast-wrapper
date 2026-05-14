from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "access_token",
    "refresh_token",
    "jwt",
    "token",
    "password",
    "secret",
}


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ValidationStatus(StrEnum):
    pending = "pending"
    confirmed = "confirmed"
    likely = "likely"
    false_positive = "false_positive"
    informational = "informational"
    needs_manual_review = "needs_manual_review"
    failed = "failed"


class ScanStatus(StrEnum):
    pending = "pending"
    running = "running"
    cancelling = "cancelling"
    cancelled = "cancelled"
    completed = "completed"
    failed = "failed"
    timed_out = "timed_out"


def utc_now() -> datetime:
    return datetime.utcnow()


def redact_secret_data(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = redact_secret_data(item)
        return redacted
    if isinstance(value, list):
        return [redact_secret_data(item) for item in value]
    return value


class CanonicalModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    def redacted(self) -> dict[str, Any]:
        return redact_secret_data(self.model_dump(mode="json"))


class RequestData(CanonicalModel):
    method: str = Field(default="GET", max_length=16)
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, Any] = Field(default_factory=dict)
    body: str | bytes | dict[str, Any] | list[Any] | None = None
    content_type: str | None = None
    timeout_seconds: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()


class ResponseData(CanonicalModel):
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    elapsed_ms: float | None = None
    content_length: int | None = None
    fingerprint: str | None = None
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuthContext(CanonicalModel):
    id: str | None = None
    application_id: str
    workspace_id: str = "default"
    role: str
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    local_storage: dict[str, str] = Field(default_factory=dict)
    session_storage: dict[str, str] = Field(default_factory=dict)
    refresh_token: str | None = None
    browser_storage_state_path: str | None = None
    expires_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return bool(self.expires_at and self.expires_at <= utc_now())


class Finding(CanonicalModel):
    id: str | None = None
    scan_id: str
    workspace_id: str = "default"
    scanner: str
    scanner_finding_id: str | None = None
    title: str
    description: str | None = None
    severity: Severity = Severity.info
    cwe: str | None = None
    owasp: str | None = None
    url: str | None = None
    request: RequestData | None = None
    response: ResponseData | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class ReplayResult(CanonicalModel):
    finding_id: str | None = None
    request: RequestData
    baseline_response: ResponseData | None = None
    replay_response: ResponseData
    auth_context_id: str | None = None
    role: str | None = None
    success: bool
    diff: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class ValidationResult(CanonicalModel):
    finding_id: str | None = None
    validator: Literal["replay", "authorization", "ai_triage", "scope"] | str
    status: ValidationStatus
    confidence: float = Field(ge=0.0, le=1.0)
    exploitable: bool = False
    role: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class ScanExecution(CanonicalModel):
    id: str | None = None
    application_id: str
    workspace_id: str = "default"
    scanner: str
    status: ScanStatus = ScanStatus.pending
    config: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = None
    celery_task_id: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    timeout_seconds: int | None = None
    cancellation_requested_at: datetime | None = None


class ReportArtifact(CanonicalModel):
    id: str | None = None
    scan_id: str
    workspace_id: str = "default"
    artifact_type: Literal["json", "html", "pdf", "sarif", "markdown"] | str
    path: str | None = None
    content: dict[str, Any] = Field(default_factory=dict)
    checksum: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
