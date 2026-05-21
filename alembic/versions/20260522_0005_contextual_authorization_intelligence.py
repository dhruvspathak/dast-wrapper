"""contextual authorization intelligence schema

Revision ID: 20260522_0005
Revises: 20260522_0004
Create Date: 2026-05-22
"""

from alembic import op
import sqlalchemy as sa


revision = "20260522_0005"
down_revision = "20260522_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "application_map_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("map_data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_application_map_snapshots_workspace_id", "application_map_snapshots", ["workspace_id"])
    op.create_index("ix_application_map_snapshots_application_id", "application_map_snapshots", ["application_id"])
    op.create_index("ix_application_map_snapshots_scan_job_id", "application_map_snapshots", ["scan_job_id"])

    op.create_table(
        "authorization_expectations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("subject_type", sa.String(50), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("resource_type", sa.String(80), nullable=False),
        sa.Column("resource", sa.String(512), nullable=False),
        sa.Column("expected_access", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("rationale", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_authorization_expectations_workspace_id", "authorization_expectations", ["workspace_id"])
    op.create_index("ix_authorization_expectations_application_id", "authorization_expectations", ["application_id"])
    op.create_index("ix_authorization_expectations_scan_job_id", "authorization_expectations", ["scan_job_id"])
    op.create_index("ix_authorization_expectations_subject_type", "authorization_expectations", ["subject_type"])
    op.create_index("ix_authorization_expectations_subject", "authorization_expectations", ["subject"])
    op.create_index("ix_authorization_expectations_resource_type", "authorization_expectations", ["resource_type"])
    op.create_index("ix_authorization_expectations_resource", "authorization_expectations", ["resource"])
    op.create_index("ix_authorization_expectations_expected_access", "authorization_expectations", ["expected_access"])

    op.create_table(
        "object_relationships",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("source_object_reference_id", sa.String(36), sa.ForeignKey("object_references.id"), nullable=False),
        sa.Column("target_object_reference_id", sa.String(36), sa.ForeignKey("object_references.id"), nullable=False),
        sa.Column("relationship_type", sa.String(80), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_object_relationships_workspace_id", "object_relationships", ["workspace_id"])
    op.create_index("ix_object_relationships_application_id", "object_relationships", ["application_id"])
    op.create_index("ix_object_relationships_scan_job_id", "object_relationships", ["scan_job_id"])
    op.create_index("ix_object_relationships_source_object_reference_id", "object_relationships", ["source_object_reference_id"])
    op.create_index("ix_object_relationships_target_object_reference_id", "object_relationships", ["target_object_reference_id"])
    op.create_index("ix_object_relationships_relationship_type", "object_relationships", ["relationship_type"])

    op.create_table(
        "reasoning_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("finding_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_reasoning_findings_workspace_id", "reasoning_findings", ["workspace_id"])
    op.create_index("ix_reasoning_findings_application_id", "reasoning_findings", ["application_id"])
    op.create_index("ix_reasoning_findings_scan_job_id", "reasoning_findings", ["scan_job_id"])
    op.create_index("ix_reasoning_findings_finding_type", "reasoning_findings", ["finding_type"])
    op.create_index("ix_reasoning_findings_severity", "reasoning_findings", ["severity"])

    op.create_table(
        "scan_strategies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("plan", sa.JSON(), nullable=False),
        sa.Column("priority_score", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_scan_strategies_workspace_id", "scan_strategies", ["workspace_id"])
    op.create_index("ix_scan_strategies_application_id", "scan_strategies", ["application_id"])
    op.create_index("ix_scan_strategies_scan_job_id", "scan_strategies", ["scan_job_id"])


def downgrade() -> None:
    op.drop_table("scan_strategies")
    op.drop_table("reasoning_findings")
    op.drop_table("object_relationships")
    op.drop_table("authorization_expectations")
    op.drop_table("application_map_snapshots")
