"""add findings.status for triage (false-positive management)

Revision ID: b1c2d3e4f5a6
Revises: a3a496357a02
Create Date: 2026-08-24 18:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b1c2d3e4f5a6"
down_revision: Union[str, Sequence[str], None] = "a3a496357a02"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("status", sa.String(length=20), nullable=False, server_default="open"))
        batch_op.create_index(batch_op.f("ix_findings_status"), ["status"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_findings_status"))
        batch_op.drop_column("status")
