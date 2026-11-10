"""persist pull request changed-file counts

Revision ID: 98d5a223cb61
Revises: 64f1bc2e916a
Create Date: 2026-11-09 10:56:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "98d5a223cb61"
down_revision: Union[str, Sequence[str], None] = "64f1bc2e916a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("changed_files", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "changed_files")
