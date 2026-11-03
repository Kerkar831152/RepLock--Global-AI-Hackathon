import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict

class FindingCreate(BaseModel):
    scan_id: uuid.UUID
    title: str
    description: str
    severity: str
    vulnerability_type: str
    file_path: str | None = None
    line_number: int | None = None
    evidence: str | None = None
    remediation: str | None = None

class FindingResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    description: str
    severity: str
    vulnerability_type: str
    file_path: str | None
    line_number: int | None
    evidence: str | None
    remediation: str | None
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)