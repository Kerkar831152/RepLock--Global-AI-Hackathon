
from pydantic import BaseModel, Field


class ResearchSearchRequest(BaseModel):
    query: str = Field(min_length=3, max_length=500)
    max_results: int = Field(default=5, ge=1, le=5)


class ResearchSource(BaseModel):
    title: str
    url: str
    content: str
    score: float | None = None
    published_date: str | None = None


class ResearchSearchResponse(BaseModel):
    query: str
    results: list[ResearchSource]
    cached: bool
