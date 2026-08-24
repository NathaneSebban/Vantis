"""add schedules table (recurring scans)

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-08-24 18:45:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c2d3e4f5a6b7"
down_revision: Union[str, Sequence[str], None] = "b1c2d3e4f5a6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "schedules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("modules", sa.Text(), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("authorized", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_id", sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("schedules", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_schedules_enabled"), ["enabled"], unique=False)
        batch_op.create_index(batch_op.f("ix_schedules_next_run_at"), ["next_run_at"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("schedules", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_schedules_next_run_at"))
        batch_op.drop_index(batch_op.f("ix_schedules_enabled"))
    op.drop_table("schedules")
