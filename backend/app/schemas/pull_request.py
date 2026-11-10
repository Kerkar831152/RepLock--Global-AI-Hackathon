
import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.finding import FindingResponse


class PullRequestResponse(BaseModel):
    number: int
    title: str
    state: str
    html_url: str
    author: str | None
    head_sha: str
    base_branch: str
    changed_files: int
    additions: int
    deletions: int

    model_config = ConfigDict(extra="forbid")


class PullRequestReviewResponse(BaseModel):
    scan_id: uuid.UUID
    pull_request_number: int
    pull_request_url: str
    head_sha: str
    status: str
    summary: str
    changed_files: int
    files_analyzed: int
    findings: list[FindingResponse]
    limitations: list[str] = Field(default_factory=list)
