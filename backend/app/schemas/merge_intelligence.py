from typing import Literal

from pydantic import BaseModel, Field, field_validator
from app.schemas.security_analysis import SecurityFinding


class MergeConflictEvidence(BaseModel):
    branch: str
    file_path: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    code: str = Field(min_length=1, max_length=2000)


class LogicalMergeConflict(BaseModel):
    status: Literal["confirmed", "potential"]
    conflict_type: str = Field(min_length=1, max_length=100)
    confidence: float = Field(ge=0, le=1)
    explanation: str = Field(min_length=1, max_length=3000)
    affected_files: list[str] = Field(min_length=1, max_length=10)
    related_symbols: list[str] = Field(default_factory=list, max_length=10)
    dependency_description: str | None = Field(default=None, max_length=1000)
    evidence: list[MergeConflictEvidence] = Field(min_length=2, max_length=10)


class MergeIntelligenceRequest(BaseModel):
    branch_a: str = Field(min_length=1, max_length=255)
    branch_b: str = Field(min_length=1, max_length=255)

    @field_validator("branch_a", "branch_b")
    @classmethod
    def validate_branch_ref(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(character) < 32 for character in value):
            raise ValueError("A valid branch reference is required")
        return value


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
    conflicts: list[LogicalMergeConflict] = Field(default_factory=list)
    limitations: list[str]