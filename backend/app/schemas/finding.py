
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

FindingSeverity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal[
    "open",
    "in_progress",
    "resolved",
    "ignored",
    "false_positive",
]


class FindingCreate(BaseModel):
    scan_id: uuid.UUID
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    severity: FindingSeverity
    vulnerability_type: str = Field(min_length=1, max_length=100)
    file_path: str | None = Field(default=None, max_length=500)
    line_number: int | None = Field(default=None, ge=1)
    evidence: str | None = None
    remediation: str | None = None


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class FindingResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    description: str
    severity: FindingSeverity
    vulnerability_type: str
    file_path: str | None
    line_number: int | None
    evidence: str | None
    remediation: str | None
    status: FindingStatus
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    limit: int
    offset: int


class FindingSummaryResponse(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
