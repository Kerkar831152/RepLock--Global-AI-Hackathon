
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


Severity = Literal["critical", "high", "medium", "low", "info"]


class CodeFileInput(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    content: str = Field(min_length=1, max_length=4000)
    start_line: int = Field(default=1, ge=1)


class ScannerSignalInput(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=1000)
    severity: Severity | None = None
    file_path: str | None = Field(default=None, max_length=300)


class ResearchSourceInput(BaseModel):
    title: str = Field(max_length=200)
    url: str = Field(max_length=1000)
    content: str = Field(max_length=1000)


class SecurityAnalysisRequest(BaseModel):
    files: list[CodeFileInput] = Field(min_length=1, max_length=3)
    scanner_findings: list[ScannerSignalInput] = Field(
        default_factory=list,
        max_length=5
    )
    research_sources: list[ResearchSourceInput] = Field(
        default_factory=list,
        max_length=3
    )
    research_query: str | None = Field(
        default=None,
        min_length=3,
        max_length=300
    )

    @model_validator(mode="after")
    def validate_total_code_size(self):
        total_size = sum(len(item.content) for item in self.files)

        if total_size > 8000:
            raise ValueError(
                "Combined source code cannot exceed 8000 characters"
            )

        return self


class SecurityReference(BaseModel):
    title: str = Field(max_length=200)
    url: str = Field(max_length=1000)


class SecurityFinding(BaseModel):
    title: str
    vulnerability_type: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    file_path: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    evidence: str
    description: str
    remediation: str
    references: list[SecurityReference] = Field(default_factory=list)


class SecurityAnalysisResponse(BaseModel):
    summary: str
    findings: list[SecurityFinding]
    limitations: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
