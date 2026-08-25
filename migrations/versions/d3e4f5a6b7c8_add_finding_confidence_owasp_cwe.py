"""add findings.confidence/owasp/cwe (classification mapping)

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-08-25 15:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "d3e4f5a6b7c8"
down_revision: Union[str, Sequence[str], None] = "c2d3e4f5a6b7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("confidence", sa.String(length=20), nullable=False, server_default="medium"))
        batch_op.add_column(sa.Column("owasp", sa.String(length=20), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("cwe", sa.String(length=20), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_column("cwe")
        batch_op.drop_column("owasp")
        batch_op.drop_column("confidence")
