
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RepositoryCreate(BaseModel):
    github_repo_id: str
    name: str
    full_name: str
    description: str | None = None
    default_branch: str = "main"
    is_private: bool = False


class RepositoryResponse(BaseModel):
    id: uuid.UUID
    github_repo_id: str
    name: str
    full_name: str
    description: str | None
    default_branch: str
    is_private: bool
    owner_id: uuid.UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
