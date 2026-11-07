
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Severity = Literal["critical", "high", "medium", "low", "info"]


def validate_relative_path(value: str) -> str:
    value = value.strip()

    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in {".", ".."} for part in value.split("/"))
        or ":" in value.split("/")[0]
    ):
        raise ValueError("A valid relative repository path is required")

    return value


def validate_http_url(value: str) -> str:
    value = value.strip()
    parsed = urlsplit(value)

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Only valid HTTP or HTTPS URLs are allowed")

    return value


class CodeFileInput(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    content: str = Field(min_length=1, max_length=4000)
    start_line: int = Field(default=1, ge=1)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return validate_relative_path(value)

    model_config = ConfigDict(extra="forbid")


class ScannerSignalInput(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=1000)
    severity: Severity | None = None
    file_path: str | None = Field(default=None, max_length=300)

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_relative_path(value)

    model_config = ConfigDict(extra="forbid")


class ResearchSourceInput(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=1000)
    content: str = Field(max_length=1000)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return validate_http_url(value)

    model_config = ConfigDict(extra="forbid")


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
    def validate_request(self):
        paths = [item.path for item in self.files]

        if len(paths) != len(set(paths)):
            raise ValueError("Duplicate file paths are not allowed")

        total_size = sum(len(item.content) for item in self.files)

        if total_size > 8000:
            raise ValueError(
                "Combined source code cannot exceed 8000 characters"
            )

        return self

    model_config = ConfigDict(extra="forbid")


class SecurityReference(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=1000)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return validate_http_url(value)

    model_config = ConfigDict(extra="forbid")


class SecurityFinding(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    vulnerability_type: str = Field(min_length=1, max_length=100)
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    file_path: str = Field(min_length=1, max_length=500)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    evidence: str = Field(min_length=1, max_length=4000)
    description: str = Field(min_length=1, max_length=5000)
    remediation: str = Field(min_length=1, max_length=5000)
    references: list[SecurityReference] = Field(
        default_factory=list,
        max_length=3
    )

    @field_validator("file_path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return validate_relative_path(value)

    @model_validator(mode="after")
    def validate_line_range(self):
        if self.line_end < self.line_start:
            raise ValueError("line_end cannot be before line_start")
        return self

    model_config = ConfigDict(extra="forbid")


class SecurityAnalysisResponse(BaseModel):
    summary: str = Field(min_length=1, max_length=2000)
    findings: list[SecurityFinding] = Field(max_length=50)
    limitations: list[str] = Field(default_factory=list, max_length=30)

    model_config = ConfigDict(extra="forbid")
