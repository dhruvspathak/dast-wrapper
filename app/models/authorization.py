from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def uuid_string() -> str:
    return str(uuid.uuid4())


class Identity(Base):
    __tablename__ = "identities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_credentials: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    login_config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    auth_headers: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, onupdate=datetime.utcnow)

    application = relationship("Application")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    identity_id: Mapped[str] = mapped_column(String(36), ForeignKey("identities.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="pending", index=True)
    cookies: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    local_storage: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    session_storage: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    auth_headers: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    tokens: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    traffic_history: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    storage_state_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_refreshed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, onupdate=datetime.utcnow)

    application = relationship("Application")
    identity = relationship("Identity")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    normalized_path: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    first_seen_scan_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True)
    risk_tags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    application = relationship("Application")


class ObjectReference(Base):
    __tablename__ = "object_references"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    endpoint_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("endpoints.id"), nullable=True)
    identity_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("identities.id"), nullable=True, index=True)
    reference_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    location: Mapped[str] = mapped_column(String(50), nullable=False)
    ownership_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    ownership_confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    tenant_hint: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    application = relationship("Application")
    endpoint = relationship("Endpoint")
    identity = relationship("Identity")


class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    identity_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("identities.id"), nullable=True, index=True)
    session_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("sessions.id"), nullable=True)
    endpoint_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("endpoints.id"), nullable=True)
    parent_traffic_log_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("traffic_logs.id"), nullable=True, index=True)
    request_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    request_method: Mapped[str] = mapped_column(String(12), nullable=False)
    request_headers: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_headers: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    elapsed_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    source: Mapped[str] = mapped_column(String(50), default="crawler", index=True)
    source_type: Mapped[str] = mapped_column(String(50), default="crawl", index=True)
    attack_chain_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("attack_chains.id"), nullable=True, index=True)
    replay_depth: Mapped[int] = mapped_column(Integer, default=0)
    discovered_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    normalized_request_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    normalized_response_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class AttackAttempt(Base):
    __tablename__ = "attack_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=False, index=True)
    attack_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    source_identity_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("identities.id"), nullable=True)
    target_identity_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("identities.id"), nullable=True)
    object_reference_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("object_references.id"), nullable=True)
    baseline_traffic_log_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("traffic_logs.id"), nullable=True)
    replay_traffic_log_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("traffic_logs.id"), nullable=True)
    attack_chain_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("attack_chains.id"), nullable=True, index=True)
    replay_request: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    replay_response: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(50), default="pending", index=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class ValidationResult(Base):
    __tablename__ = "validation_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    attack_attempt_id: Mapped[str] = mapped_column(String(36), ForeignKey("attack_attempts.id"), nullable=False, index=True)
    verdict: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status_code_delta: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    body_delta: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    normalized_diff: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    sensitive_fields: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    semantic_indicators: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    validation_reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="queued", index=True)
    scanner_backend: Mapped[str] = mapped_column(String(50), default="zap")
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    current_stage: Mapped[str | None] = mapped_column(String(100), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    results: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, onupdate=datetime.utcnow)

    application = relationship("Application")


class WorkflowState(Base):
    __tablename__ = "workflow_states"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=False, index=True)
    workflow_name: Mapped[str] = mapped_column(String(100), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="pending", index=True)
    stage: Mapped[str] = mapped_column(String(100), nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, onupdate=datetime.utcnow)


class AttackChain(Base):
    __tablename__ = "attack_chains"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=False, index=True)
    chain_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    root_traffic_log_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("traffic_logs.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="running", index=True)
    summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, onupdate=datetime.utcnow)


class WorkflowTransition(Base):
    __tablename__ = "workflow_transitions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    object_reference_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("object_references.id"), nullable=True)
    identity_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("identities.id"), nullable=True)
    endpoint_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("endpoints.id"), nullable=True)
    from_state: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    to_state: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    transition_action: Mapped[str | None] = mapped_column(String(100), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    attack_attempt_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("attack_attempts.id"), nullable=True, index=True)
    attack_chain_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("attack_chains.id"), nullable=True, index=True)
    evidence_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    baseline_request: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    baseline_response: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    replay_request: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    replay_response: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    normalized_diffs: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    validation_evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class ApplicationMapSnapshot(Base):
    __tablename__ = "application_map_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    map_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class AuthorizationExpectation(Base):
    __tablename__ = "authorization_expectations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    subject_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    resource: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    expected_access: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    rationale: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class ObjectRelationship(Base):
    __tablename__ = "object_relationships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    source_object_reference_id: Mapped[str] = mapped_column(String(36), ForeignKey("object_references.id"), nullable=False, index=True)
    target_object_reference_id: Mapped[str] = mapped_column(String(36), ForeignKey("object_references.id"), nullable=False, index=True)
    relationship_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class ReasoningFinding(Base):
    __tablename__ = "reasoning_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class ScanStrategy(Base):
    __tablename__ = "scan_strategies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    plan: Mapped[dict] = mapped_column(JSON, nullable=False)
    priority_score: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class AuthorizationGraphSnapshot(Base):
    __tablename__ = "authorization_graph_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_string)
    workspace_id: Mapped[str] = mapped_column(String(36), default="default", index=True)
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    scan_job_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scan_jobs.id"), nullable=True)
    graph: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
