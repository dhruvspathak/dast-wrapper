"""platform hardening fields

Revision ID: 20260514_0002
Revises: 20260514_0001
Create Date: 2026-05-14
"""

from alembic import op
import sqlalchemy as sa


revision = "20260514_0002"
down_revision = "20260514_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("applications", sa.Column("workspace_id", sa.String(length=36), nullable=False, server_default="default"))
    op.create_index("ix_applications_workspace_id", "applications", ["workspace_id"])

    op.add_column("auth_sessions", sa.Column("workspace_id", sa.String(length=36), nullable=False, server_default="default"))
    op.add_column("auth_sessions", sa.Column("headers", sa.JSON(), nullable=True))
    op.add_column("auth_sessions", sa.Column("cookies", sa.JSON(), nullable=True))
    op.add_column("auth_sessions", sa.Column("local_storage", sa.JSON(), nullable=True))
    op.add_column("auth_sessions", sa.Column("session_storage", sa.JSON(), nullable=True))
    op.add_column("auth_sessions", sa.Column("refresh_token", sa.String(length=2048), nullable=True))
    op.add_column("auth_sessions", sa.Column("browser_storage_state_path", sa.String(length=1024), nullable=True))
    op.add_column("auth_sessions", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.create_index("ix_auth_sessions_workspace_id", "auth_sessions", ["workspace_id"])

    op.add_column("scans", sa.Column("workspace_id", sa.String(length=36), nullable=False, server_default="default"))
    op.add_column("scans", sa.Column("correlation_id", sa.String(length=64), nullable=True))
    op.add_column("scans", sa.Column("celery_task_id", sa.String(length=255), nullable=True))
    op.add_column("scans", sa.Column("scanner_scan_id", sa.String(length=255), nullable=True))
    op.add_column("scans", sa.Column("started_at", sa.DateTime(), nullable=True))
    op.add_column("scans", sa.Column("completed_at", sa.DateTime(), nullable=True))
    op.add_column("scans", sa.Column("timeout_seconds", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("cancellation_requested_at", sa.DateTime(), nullable=True))
    op.create_index("ix_scans_workspace_id", "scans", ["workspace_id"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_correlation_id", "scans", ["correlation_id"])

    op.add_column("findings", sa.Column("workspace_id", sa.String(length=36), nullable=False, server_default="default"))
    op.add_column("findings", sa.Column("scanner", sa.String(length=50), nullable=False, server_default="unknown"))
    op.add_column("findings", sa.Column("scanner_finding_id", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column("fingerprint", sa.String(length=128), nullable=True))
    op.add_column("findings", sa.Column("evidence", sa.JSON(), nullable=True))
    op.add_column("findings", sa.Column("raw", sa.JSON(), nullable=True))
    op.add_column("findings", sa.Column("validation_status", sa.String(length=50), nullable=False, server_default="pending"))
    op.create_index("ix_findings_workspace_id", "findings", ["workspace_id"])
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])

    op.add_column("replay_validations", sa.Column("workspace_id", sa.String(length=36), nullable=False, server_default="default"))
    op.add_column("replay_validations", sa.Column("auth_session_id", sa.String(length=36), nullable=True))
    op.add_column("replay_validations", sa.Column("role", sa.String(length=50), nullable=True))
    op.add_column("replay_validations", sa.Column("diff", sa.JSON(), nullable=True))
    op.add_column("replay_validations", sa.Column("confidence", sa.Float(), nullable=True))
    op.create_foreign_key("fk_replay_validations_auth_session_id", "replay_validations", "auth_sessions", ["auth_session_id"], ["id"])
    op.create_index("ix_replay_validations_workspace_id", "replay_validations", ["workspace_id"])

    op.add_column("reports", sa.Column("workspace_id", sa.String(length=36), nullable=False, server_default="default"))
    op.add_column("reports", sa.Column("artifact_type", sa.String(length=50), nullable=False, server_default="json"))
    op.add_column("reports", sa.Column("path", sa.String(length=1024), nullable=True))
    op.add_column("reports", sa.Column("checksum", sa.String(length=128), nullable=True))
    op.create_index("ix_reports_workspace_id", "reports", ["workspace_id"])


def downgrade() -> None:
    op.drop_index("ix_reports_workspace_id", table_name="reports")
    op.drop_column("reports", "checksum")
    op.drop_column("reports", "path")
    op.drop_column("reports", "artifact_type")
    op.drop_column("reports", "workspace_id")

    op.drop_index("ix_replay_validations_workspace_id", table_name="replay_validations")
    op.drop_constraint("fk_replay_validations_auth_session_id", "replay_validations", type_="foreignkey")
    op.drop_column("replay_validations", "confidence")
    op.drop_column("replay_validations", "diff")
    op.drop_column("replay_validations", "role")
    op.drop_column("replay_validations", "auth_session_id")
    op.drop_column("replay_validations", "workspace_id")

    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_index("ix_findings_workspace_id", table_name="findings")
    op.drop_column("findings", "validation_status")
    op.drop_column("findings", "raw")
    op.drop_column("findings", "evidence")
    op.drop_column("findings", "fingerprint")
    op.drop_column("findings", "scanner_finding_id")
    op.drop_column("findings", "scanner")
    op.drop_column("findings", "workspace_id")

    op.drop_index("ix_scans_correlation_id", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_workspace_id", table_name="scans")
    op.drop_column("scans", "cancellation_requested_at")
    op.drop_column("scans", "timeout_seconds")
    op.drop_column("scans", "completed_at")
    op.drop_column("scans", "started_at")
    op.drop_column("scans", "scanner_scan_id")
    op.drop_column("scans", "celery_task_id")
    op.drop_column("scans", "correlation_id")
    op.drop_column("scans", "workspace_id")

    op.drop_index("ix_auth_sessions_workspace_id", table_name="auth_sessions")
    op.drop_column("auth_sessions", "is_active")
    op.drop_column("auth_sessions", "browser_storage_state_path")
    op.drop_column("auth_sessions", "refresh_token")
    op.drop_column("auth_sessions", "session_storage")
    op.drop_column("auth_sessions", "local_storage")
    op.drop_column("auth_sessions", "cookies")
    op.drop_column("auth_sessions", "headers")
    op.drop_column("auth_sessions", "workspace_id")

    op.drop_index("ix_applications_workspace_id", table_name="applications")
    op.drop_column("applications", "workspace_id")
