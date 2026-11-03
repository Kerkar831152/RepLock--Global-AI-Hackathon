import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict

class ScanCreate(BaseModel):
    repository_id: uuid.UUID
    commit_sha: str | None = None
    scan_type: str = "full"

class ScanResponse(BaseModel):
    id: uuid.UUID
    repository_id: uuid.UUID
    commit_sha: str | None
    status: str
    scan_type: str
    summary: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)