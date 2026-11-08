from pydantic import BaseModel, Field
from app.schemas.security_analysis import SecurityFinding


class MergeIntelligenceRequest(BaseModel):
    branch_a: str = Field(min_length=1, max_length=255)
    branch_b: str = Field(min_length=1, max_length=255)


class MergeIntelligenceResponse(BaseModel):
    repository: str
    branch_a: str
    branch_b: str
    comparison_status: str
    ahead_by: int
    behind_by: int
    changed_files: int
    files_analyzed: int
    summary: str
    findings: list[SecurityFinding]
    limitations: list[str]