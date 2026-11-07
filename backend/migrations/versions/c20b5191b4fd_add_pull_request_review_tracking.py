"""add pull request review tracking

Revision ID: c20b5191b4fd
Revises: eb71eac01562
Create Date: 2026-11-07 16:38:16.191629
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c20b5191b4fd"
down_revision: Union[str, Sequence[str], None] = "eb71eac01562"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("pull_request_number", sa.Integer(), nullable=True)
    )

    op.add_column(
        "scans",
        sa.Column("files_analyzed", sa.Integer(), nullable=True)
    )

    op.create_index(
        "uq_scans_active_pr_review",
        "scans",
        ["repository_id", "pull_request_number", "commit_sha"],
        unique=True,
        postgresql_where=sa.text(
            "scan_type = 'pull_request' "
            "AND status IN ('running', 'completed') "
            "AND pull_request_number IS NOT NULL "
            "AND commit_sha IS NOT NULL"
        )
    )


def downgrade() -> None:
    op.drop_index(
        "uq_scans_active_pr_review",
        table_name="scans"
    )

    op.drop_column("scans", "files_analyzed")
    op.drop_column("scans", "pull_request_number")