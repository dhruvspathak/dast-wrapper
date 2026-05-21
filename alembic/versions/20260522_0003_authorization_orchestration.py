"""authorization orchestration schema

Revision ID: 20260522_0003
Revises: 20260514_0002
Create Date: 2026-05-22
"""

from alembic import op
import sqlalchemy as sa


revision = "20260522_0003"
down_revision = "20260514_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "identities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("role", sa.String(100), nullable=False),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("encrypted_credentials", sa.JSON(), nullable=False),
        sa.Column("login_config", sa.JSON(), nullable=False),
        sa.Column("auth_headers", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_identities_application_id", "identities", ["application_id"])
    op.create_index("ix_identities_role", "identities", ["role"])
    op.create_index("ix_identities_workspace_id", "identities", ["workspace_id"])

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("scanner_backend", sa.String(50), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("current_stage", sa.String(100), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("results", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_scan_jobs_application_id", "scan_jobs", ["application_id"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_workspace_id", "scan_jobs", ["workspace_id"])

    op.create_table(
        "sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("identity_id", sa.String(36), sa.ForeignKey("identities.id"), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("cookies", sa.JSON(), nullable=False),
        sa.Column("local_storage", sa.JSON(), nullable=False),
        sa.Column("session_storage", sa.JSON(), nullable=False),
        sa.Column("auth_headers", sa.JSON(), nullable=False),
        sa.Column("tokens", sa.JSON(), nullable=False),
        sa.Column("traffic_history", sa.JSON(), nullable=False),
        sa.Column("storage_state_path", sa.String(1024), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("last_refreshed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_sessions_application_id", "sessions", ["application_id"])
    op.create_index("ix_sessions_identity_id", "sessions", ["identity_id"])
    op.create_index("ix_sessions_status", "sessions", ["status"])
    op.create_index("ix_sessions_workspace_id", "sessions", ["workspace_id"])

    op.create_table(
        "endpoints",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("method", sa.String(12), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("normalized_path", sa.String(1024), nullable=False),
        sa.Column("first_seen_scan_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("risk_tags", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_endpoints_application_id", "endpoints", ["application_id"])
    op.create_index("ix_endpoints_method", "endpoints", ["method"])
    op.create_index("ix_endpoints_normalized_path", "endpoints", ["normalized_path"])
    op.create_index("ix_endpoints_path", "endpoints", ["path"])
    op.create_index("ix_endpoints_workspace_id", "endpoints", ["workspace_id"])

    op.create_table(
        "object_references",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("endpoint_id", sa.String(36), sa.ForeignKey("endpoints.id"), nullable=True),
        sa.Column("identity_id", sa.String(36), sa.ForeignKey("identities.id"), nullable=True),
        sa.Column("reference_type", sa.String(50), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("location", sa.String(50), nullable=False),
        sa.Column("ownership_confidence", sa.Float(), nullable=False),
        sa.Column("tenant_hint", sa.String(255), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_object_references_application_id", "object_references", ["application_id"])
    op.create_index("ix_object_references_identity_id", "object_references", ["identity_id"])
    op.create_index("ix_object_references_reference_type", "object_references", ["reference_type"])
    op.create_index("ix_object_references_tenant_hint", "object_references", ["tenant_hint"])
    op.create_index("ix_object_references_value", "object_references", ["value"])
    op.create_index("ix_object_references_workspace_id", "object_references", ["workspace_id"])

    op.create_table(
        "traffic_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("identity_id", sa.String(36), sa.ForeignKey("identities.id"), nullable=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("sessions.id"), nullable=True),
        sa.Column("endpoint_id", sa.String(36), sa.ForeignKey("endpoints.id"), nullable=True),
        sa.Column("request_url", sa.String(2048), nullable=False),
        sa.Column("request_method", sa.String(12), nullable=False),
        sa.Column("request_headers", sa.JSON(), nullable=False),
        sa.Column("request_body", sa.Text(), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("response_headers", sa.JSON(), nullable=False),
        sa.Column("response_body", sa.Text(), nullable=True),
        sa.Column("response_size", sa.Integer(), nullable=True),
        sa.Column("elapsed_ms", sa.Float(), nullable=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_traffic_logs_application_id", "traffic_logs", ["application_id"])
    op.create_index("ix_traffic_logs_identity_id", "traffic_logs", ["identity_id"])
    op.create_index("ix_traffic_logs_scan_job_id", "traffic_logs", ["scan_job_id"])
    op.create_index("ix_traffic_logs_workspace_id", "traffic_logs", ["workspace_id"])

    op.create_table(
        "attack_attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("attack_type", sa.String(80), nullable=False),
        sa.Column("source_identity_id", sa.String(36), sa.ForeignKey("identities.id"), nullable=True),
        sa.Column("target_identity_id", sa.String(36), sa.ForeignKey("identities.id"), nullable=True),
        sa.Column("object_reference_id", sa.String(36), sa.ForeignKey("object_references.id"), nullable=True),
        sa.Column("baseline_traffic_log_id", sa.String(36), sa.ForeignKey("traffic_logs.id"), nullable=True),
        sa.Column("replay_request", sa.JSON(), nullable=False),
        sa.Column("replay_response", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_attack_attempts_application_id", "attack_attempts", ["application_id"])
    op.create_index("ix_attack_attempts_attack_type", "attack_attempts", ["attack_type"])
    op.create_index("ix_attack_attempts_scan_job_id", "attack_attempts", ["scan_job_id"])
    op.create_index("ix_attack_attempts_status", "attack_attempts", ["status"])
    op.create_index("ix_attack_attempts_workspace_id", "attack_attempts", ["workspace_id"])

    op.create_table(
        "validation_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("attack_attempt_id", sa.String(36), sa.ForeignKey("attack_attempts.id"), nullable=False),
        sa.Column("verdict", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("status_code_delta", sa.JSON(), nullable=False),
        sa.Column("body_delta", sa.JSON(), nullable=False),
        sa.Column("sensitive_fields", sa.JSON(), nullable=False),
        sa.Column("semantic_indicators", sa.JSON(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_validation_results_attack_attempt_id", "validation_results", ["attack_attempt_id"])
    op.create_index("ix_validation_results_verdict", "validation_results", ["verdict"])
    op.create_index("ix_validation_results_workspace_id", "validation_results", ["workspace_id"])

    op.create_table(
        "workflow_states",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("workflow_name", sa.String(100), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("stage", sa.String(100), nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_workflow_states_idempotency_key", "workflow_states", ["idempotency_key"])
    op.create_index("ix_workflow_states_scan_job_id", "workflow_states", ["scan_job_id"])
    op.create_index("ix_workflow_states_status", "workflow_states", ["status"])
    op.create_index("ix_workflow_states_workspace_id", "workflow_states", ["workspace_id"])

    op.create_table(
        "authorization_graph_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("graph", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_authorization_graph_snapshots_application_id", "authorization_graph_snapshots", ["application_id"])
    op.create_index("ix_authorization_graph_snapshots_workspace_id", "authorization_graph_snapshots", ["workspace_id"])


def downgrade() -> None:
    op.drop_table("authorization_graph_snapshots")
    op.drop_table("workflow_states")
    op.drop_table("validation_results")
    op.drop_table("attack_attempts")
    op.drop_table("traffic_logs")
    op.drop_table("object_references")
    op.drop_table("endpoints")
    op.drop_table("sessions")
    op.drop_table("scan_jobs")
    op.drop_table("identities")
