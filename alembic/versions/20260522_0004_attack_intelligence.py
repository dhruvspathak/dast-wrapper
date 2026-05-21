"""attack intelligence lineage evidence workflow schema

Revision ID: 20260522_0004
Revises: 20260522_0003
Create Date: 2026-05-22
"""

from alembic import op
import sqlalchemy as sa


revision = "20260522_0004"
down_revision = "20260522_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "attack_chains",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("chain_type", sa.String(80), nullable=False),
        sa.Column("root_traffic_log_id", sa.String(36), sa.ForeignKey("traffic_logs.id"), nullable=True),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_attack_chains_workspace_id", "attack_chains", ["workspace_id"])
    op.create_index("ix_attack_chains_application_id", "attack_chains", ["application_id"])
    op.create_index("ix_attack_chains_scan_job_id", "attack_chains", ["scan_job_id"])
    op.create_index("ix_attack_chains_chain_type", "attack_chains", ["chain_type"])
    op.create_index("ix_attack_chains_status", "attack_chains", ["status"])

    op.add_column("object_references", sa.Column("ownership_confidence_score", sa.Float(), nullable=False, server_default="0"))
    op.add_column("traffic_logs", sa.Column("parent_traffic_log_id", sa.String(36), nullable=True))
    op.add_column("traffic_logs", sa.Column("source_type", sa.String(50), nullable=False, server_default="crawl"))
    op.add_column("traffic_logs", sa.Column("attack_chain_id", sa.String(36), nullable=True))
    op.add_column("traffic_logs", sa.Column("replay_depth", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("traffic_logs", sa.Column("discovered_by", sa.String(100), nullable=True))
    op.add_column("traffic_logs", sa.Column("normalized_request_hash", sa.String(128), nullable=True))
    op.add_column("traffic_logs", sa.Column("normalized_response_hash", sa.String(128), nullable=True))
    op.create_foreign_key("fk_traffic_parent", "traffic_logs", "traffic_logs", ["parent_traffic_log_id"], ["id"])
    op.create_foreign_key("fk_traffic_attack_chain", "traffic_logs", "attack_chains", ["attack_chain_id"], ["id"])
    op.create_index("ix_traffic_logs_parent_traffic_log_id", "traffic_logs", ["parent_traffic_log_id"])
    op.create_index("ix_traffic_logs_source_type", "traffic_logs", ["source_type"])
    op.create_index("ix_traffic_logs_attack_chain_id", "traffic_logs", ["attack_chain_id"])
    op.create_index("ix_traffic_logs_normalized_request_hash", "traffic_logs", ["normalized_request_hash"])
    op.create_index("ix_traffic_logs_normalized_response_hash", "traffic_logs", ["normalized_response_hash"])

    op.add_column("attack_attempts", sa.Column("replay_traffic_log_id", sa.String(36), nullable=True))
    op.add_column("attack_attempts", sa.Column("attack_chain_id", sa.String(36), nullable=True))
    op.create_foreign_key("fk_attack_replay_traffic", "attack_attempts", "traffic_logs", ["replay_traffic_log_id"], ["id"])
    op.create_foreign_key("fk_attack_chain", "attack_attempts", "attack_chains", ["attack_chain_id"], ["id"])
    op.create_index("ix_attack_attempts_attack_chain_id", "attack_attempts", ["attack_chain_id"])

    op.add_column("validation_results", sa.Column("normalized_diff", sa.JSON(), nullable=False, server_default="{}"))
    op.add_column("validation_results", sa.Column("validation_reasons", sa.JSON(), nullable=False, server_default="[]"))

    op.create_table(
        "workflow_transitions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("object_reference_id", sa.String(36), sa.ForeignKey("object_references.id"), nullable=True),
        sa.Column("identity_id", sa.String(36), sa.ForeignKey("identities.id"), nullable=True),
        sa.Column("endpoint_id", sa.String(36), sa.ForeignKey("endpoints.id"), nullable=True),
        sa.Column("from_state", sa.String(100), nullable=True),
        sa.Column("to_state", sa.String(100), nullable=False),
        sa.Column("transition_action", sa.String(100), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_workflow_transitions_workspace_id", "workflow_transitions", ["workspace_id"])
    op.create_index("ix_workflow_transitions_scan_job_id", "workflow_transitions", ["scan_job_id"])
    op.create_index("ix_workflow_transitions_from_state", "workflow_transitions", ["from_state"])
    op.create_index("ix_workflow_transitions_to_state", "workflow_transitions", ["to_state"])

    op.create_table(
        "evidence_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(36), sa.ForeignKey("applications.id"), nullable=False),
        sa.Column("scan_job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=True),
        sa.Column("attack_attempt_id", sa.String(36), sa.ForeignKey("attack_attempts.id"), nullable=True),
        sa.Column("attack_chain_id", sa.String(36), sa.ForeignKey("attack_chains.id"), nullable=True),
        sa.Column("evidence_type", sa.String(80), nullable=False),
        sa.Column("baseline_request", sa.JSON(), nullable=False),
        sa.Column("baseline_response", sa.JSON(), nullable=False),
        sa.Column("replay_request", sa.JSON(), nullable=False),
        sa.Column("replay_response", sa.JSON(), nullable=False),
        sa.Column("normalized_diffs", sa.JSON(), nullable=False),
        sa.Column("validation_evidence", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_evidence_records_workspace_id", "evidence_records", ["workspace_id"])
    op.create_index("ix_evidence_records_application_id", "evidence_records", ["application_id"])
    op.create_index("ix_evidence_records_scan_job_id", "evidence_records", ["scan_job_id"])
    op.create_index("ix_evidence_records_attack_attempt_id", "evidence_records", ["attack_attempt_id"])
    op.create_index("ix_evidence_records_attack_chain_id", "evidence_records", ["attack_chain_id"])
    op.create_index("ix_evidence_records_evidence_type", "evidence_records", ["evidence_type"])


def downgrade() -> None:
    op.drop_table("evidence_records")
    op.drop_table("workflow_transitions")
    op.drop_column("validation_results", "validation_reasons")
    op.drop_column("validation_results", "normalized_diff")
    op.drop_index("ix_attack_attempts_attack_chain_id", table_name="attack_attempts")
    op.drop_constraint("fk_attack_chain", "attack_attempts", type_="foreignkey")
    op.drop_constraint("fk_attack_replay_traffic", "attack_attempts", type_="foreignkey")
    op.drop_column("attack_attempts", "attack_chain_id")
    op.drop_column("attack_attempts", "replay_traffic_log_id")
    op.drop_index("ix_traffic_logs_normalized_response_hash", table_name="traffic_logs")
    op.drop_index("ix_traffic_logs_normalized_request_hash", table_name="traffic_logs")
    op.drop_index("ix_traffic_logs_attack_chain_id", table_name="traffic_logs")
    op.drop_index("ix_traffic_logs_source_type", table_name="traffic_logs")
    op.drop_index("ix_traffic_logs_parent_traffic_log_id", table_name="traffic_logs")
    op.drop_constraint("fk_traffic_attack_chain", "traffic_logs", type_="foreignkey")
    op.drop_constraint("fk_traffic_parent", "traffic_logs", type_="foreignkey")
    op.drop_column("traffic_logs", "normalized_response_hash")
    op.drop_column("traffic_logs", "normalized_request_hash")
    op.drop_column("traffic_logs", "discovered_by")
    op.drop_column("traffic_logs", "replay_depth")
    op.drop_column("traffic_logs", "attack_chain_id")
    op.drop_column("traffic_logs", "source_type")
    op.drop_column("traffic_logs", "parent_traffic_log_id")
    op.drop_column("object_references", "ownership_confidence_score")
    op.drop_table("attack_chains")
