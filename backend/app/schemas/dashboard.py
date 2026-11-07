
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class RecentScanResponse(BaseModel):
    scan_id: uuid.UUID
    repository_id: uuid.UUID
    repository_name: str
    status: str
    scan_type: str
    commit_sha: str | None
    created_at: datetime
    completed_at: datetime | None
    findings_count: int


class AffectedFileResponse(BaseModel):
    file_path: str
    finding_count: int
    repository_count: int


class DashboardOverviewResponse(BaseModel):
    total_repositories: int
    total_scans: int
    scan_status_counts: dict[str, int]

    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_status: dict[str, int]

    security_score: int
    risk_level: Literal["low", "moderate", "high", "critical"]
    risk_points: int

    latest_scan: RecentScanResponse | None
    recent_scans: list[RecentScanResponse]
    most_affected_files: list[AffectedFileResponse]
