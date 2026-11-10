import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.schemas.finding import FindingSeverity, FindingStatus


class ReportRepository(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    github_repo_id: str
    name: str
    full_name: str
    description: str | None
    default_branch: str
    is_private: bool


class ReportScan(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: str
    scan_type: str
    commit_sha: str | None
    pull_request_number: int | None
    changed_files: int | None
    files_analyzed: int | None
    semgrep_findings: int | None
    summary: str | None
    limitations: list[str] | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ReportFinding(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    description: str
    severity: FindingSeverity
    vulnerability_type: str
    status: FindingStatus
    file_path: str | None
    line_number: int | None
    evidence: str | None
    remediation: str | None


class SecurityReportResponse(BaseModel):
    repository: ReportRepository
    scan: ReportScan
    total_findings: int
    findings_by_severity: dict[str, int]
    findings: list[ReportFinding]
