"""persist scan analysis metadata

Revision ID: 64f1bc2e916a
Revises: c20b5191b4fd
Create Date: 2026-11-08 18:05:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "64f1bc2e916a"
down_revision: Union[str, Sequence[str], None] = "c20b5191b4fd"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("semgrep_findings", sa.Integer(), nullable=True),
    )
    op.add_column(
        "scans",
        sa.Column("limitations", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "limitations")
    op.drop_column("scans", "semgrep_findings")
