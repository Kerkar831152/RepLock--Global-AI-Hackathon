"""version pull request review cache entries

Revision ID: 2ab6d1c9f704
Revises: 98d5a223cb61
Create Date: 2026-11-09 11:10:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "2ab6d1c9f704"
down_revision: Union[str, Sequence[str], None] = "98d5a223cb61"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index("uq_scans_active_pr_review", table_name="scans")
    op.add_column(
        "scans",
        sa.Column("review_version", sa.Integer(), nullable=True),
    )
    op.create_index(
        "uq_scans_active_pr_review",
        "scans",
        [
            "repository_id",
            "pull_request_number",
            "commit_sha",
            "review_version",
        ],
        unique=True,
        postgresql_where=sa.text(
            "scan_type = 'pull_request' "
            "AND status IN ('running', 'completed') "
            "AND pull_request_number IS NOT NULL "
            "AND commit_sha IS NOT NULL "
            "AND review_version IS NOT NULL"
        ),
    )


def downgrade() -> None:
    duplicates = op.get_bind().execute(
        sa.text(
            "SELECT repository_id, pull_request_number, commit_sha "
            "FROM scans "
            "WHERE scan_type = 'pull_request' "
            "AND status IN ('running', 'completed') "
            "AND pull_request_number IS NOT NULL "
            "AND commit_sha IS NOT NULL "
            "GROUP BY repository_id, pull_request_number, commit_sha "
            "HAVING COUNT(*) > 1 LIMIT 1"
        )
    ).first()
    if duplicates:
        raise RuntimeError(
            "Cannot downgrade PR review-cache versioning while multiple "
            "review versions exist for the same commit."
        )

    op.drop_index("uq_scans_active_pr_review", table_name="scans")
    op.drop_column("scans", "review_version")
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
        ),
    )
