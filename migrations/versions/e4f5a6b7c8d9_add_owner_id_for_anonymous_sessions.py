"""add owner_id to scans/schedules for anonymous per-visitor isolation

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-09-02 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e4f5a6b7c8d9"
down_revision: Union[str, Sequence[str], None] = "d3e4f5a6b7c8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Nullable, no default: existing rows (created before per-visitor scoping
    # existed) get owner_id = NULL and become invisible to every visitor going
    # forward — they stay in the database, just filtered out, since there's no
    # visitor cookie to retroactively attribute them to.
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.add_column(sa.Column("owner_id", sa.String(length=64), nullable=True))
        batch_op.create_index("ix_scans_owner_id", ["owner_id"])

    with op.batch_alter_table("schedules", schema=None) as batch_op:
        batch_op.add_column(sa.Column("owner_id", sa.String(length=64), nullable=True))
        batch_op.create_index("ix_schedules_owner_id", ["owner_id"])


def downgrade() -> None:
    with op.batch_alter_table("schedules", schema=None) as batch_op:
        batch_op.drop_index("ix_schedules_owner_id")
        batch_op.drop_column("owner_id")

    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_index("ix_scans_owner_id")
        batch_op.drop_column("owner_id")
