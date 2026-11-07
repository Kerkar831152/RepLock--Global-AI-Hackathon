from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class RepositorySecurityInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    full_name: str
    description: str | None
    default_branch: str
    is_private: bool
    created_at: datetime


class RepositoryScanHistoryItem(BaseModel):
    scan_id: UUID
    commit_sha: str | None
    status: str
    scan_type: str
    summary: str | None
    created_at: datetime
    completed_at: datetime | None
    findings_count: int


class AffectedFileItem(BaseModel):
    file_path: str
    finding_count: int


class RepositorySecurityResponse(BaseModel):
    repository: RepositorySecurityInfo
    total_scans: int
    total_findings: int
    severity_counts: dict[str, int]
    status_counts: dict[str, int]
    latest_scan: RepositoryScanHistoryItem | None
    scan_history: list[RepositoryScanHistoryItem]
    most_affected_files: list[AffectedFileItem]