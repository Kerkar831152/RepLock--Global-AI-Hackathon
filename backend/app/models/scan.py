import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import String, DateTime, ForeignKey, Text, Index, Integer, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.repository import Repository
    from app.models.finding import Finding


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("repositories.id", ondelete="CASCADE"),
        nullable=False
    )
    commit_sha: Mapped[str | None] = mapped_column(String(100), nullable=True)
    pull_request_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    changed_files: Mapped[int | None] = mapped_column(Integer, nullable=True)
    review_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    files_analyzed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    semgrep_findings: Mapped[int | None] = mapped_column(Integer, nullable=True)
    limitations: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), default="full", nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    repository: Mapped["Repository"] = relationship(
        "Repository",
        back_populates="scans"
    )

    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_scans_repository_id", "repository_id"),
    )