import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr

class UserCreate(BaseModel):
    github_id: str
    username: str
    email: EmailStr | None = None

class UserResponse(BaseModel):
    id: uuid.UUID
    github_id: str
    username: str
    email: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)