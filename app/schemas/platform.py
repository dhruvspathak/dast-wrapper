from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class ApplicationCreate(BaseModel):
    name: str
    base_url: HttpUrl
    workspace_id: str = "default"
    config: dict[str, Any] = Field(default_factory=dict)


class ApplicationRead(BaseModel):
    id: str
    workspace_id: str
    name: str
    base_url: str
    config: dict[str, Any]


class LoginConfig(BaseModel):
    login_url: str | None = None
    username_selector: str | None = None
    password_selector: str | None = None
    submit_selector: str | None = None
    success_url_pattern: str | None = None
    extra_steps: list[dict[str, Any]] = Field(default_factory=list)


class IdentityCreate(BaseModel):
    label: str
    role: str
    username: str | None = None
    password: str | None = None
    auth_headers: dict[str, str] = Field(default_factory=dict)
    login_config: LoginConfig = Field(default_factory=LoginConfig)


class IdentityRead(BaseModel):
    id: str
    application_id: str
    label: str
    role: str
    username: str | None = None
    is_active: bool


class StartScanRequest(BaseModel):
    application_id: str
    workspace_id: str = "default"
    scanner_backend: str = "zap"
    identity_ids: list[str] | None = None
    config: dict[str, Any] = Field(default_factory=dict)


class ScanJobRead(BaseModel):
    id: str
    application_id: str
    status: str
    scanner_backend: str
    current_stage: str | None = None
    results: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class FindingRead(BaseModel):
    id: str
    title: str
    severity: str
    validation_status: str | None = None
    exploitability_score: float | None = None
    evidence: dict[str, Any] | None = None


class GraphRead(BaseModel):
    application_id: str
    scan_job_id: str | None = None
    graph: dict[str, Any]
