"""Create portable tables: pr_runs, audits, findings, suppressions, memory_entries.

Revision ID: 0001_initial_tables
Revises:
Create Date: 2026-11-11
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001_initial_tables"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pr_runs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("repo", sa.String(length=256), nullable=False),
        sa.Column("branch", sa.String(length=128), nullable=False),
        sa.Column("pr_number", sa.String(length=32), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Float(), nullable=False),
        sa.Column("duration_sec", sa.Float(), nullable=False),
        sa.Column("judge_log_json", sa.Text(), nullable=False),
        sa.Column("ot_checks_json", sa.Text(), nullable=False),
        sa.Column("summary_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "audits",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("repo", sa.String(length=256), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("unverified_count", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Float(), nullable=False),
        sa.Column("report_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audits_run_id", "audits", ["run_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("audit_id", sa.String(length=64), nullable=True),
        sa.Column("check_id", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("file", sa.String(length=512), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("rule", sa.String(length=128), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("blast_radius_json", sa.Text(), nullable=False),
        sa.Column("standards_json", sa.Text(), nullable=False),
        sa.Column("fix", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("tool", sa.String(length=64), server_default="LineTrack", nullable=False),
        sa.Column("verified_deterministically", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_findings_run_id", "findings", ["run_id"])
    op.create_index("ix_findings_audit_id", "findings", ["audit_id"])
    op.create_index("ix_findings_check_id", "findings", ["check_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])

    op.create_table(
        "suppressions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("owner", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_suppressions_finding_id", "suppressions", ["finding_id"])
    op.create_index("ix_suppressions_active", "suppressions", ["active"])

    op.create_table(
        "memory_entries",
        sa.Column("id", sa.String(length=128), primary_key=True),
        sa.Column("memory_type", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_memory_entries_memory_type", "memory_entries", ["memory_type"])


def downgrade() -> None:
    op.drop_table("memory_entries")
    op.drop_table("suppressions")
    op.drop_table("findings")
    op.drop_table("audits")
    op.drop_table("pr_runs")
