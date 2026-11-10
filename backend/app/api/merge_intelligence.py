import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.security import decrypt_token
from app.models import User, Repository
from app.schemas.merge_intelligence import (
    MergeIntelligenceRequest,
    MergeIntelligenceResponse,
)
from app.services.merge_intelligence_service import (
    merge_intelligence_service,
    MergeIntelligenceError,
)


router = APIRouter(
    prefix="/repositories",
    tags=["Merge Intelligence"],
)


@router.post(
    "/{repo_id}/merge-intelligence/analyze",
    response_model=MergeIntelligenceResponse,
    summary="Analyze branch security and logical merge conflicts",
    description=(
        "Compares both branches against their common ancestor and uses "
        "Bifrost to assess semantic incompatibilities. Conflict evidence is "
        "validated against added lines from each branch."
    ),
)
async def analyze_merge(
    repo_id: uuid.UUID,
    request: MergeIntelligenceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    repository = db.scalar(
        select(Repository).where(
            Repository.id == repo_id,
            Repository.owner_id == current_user.id,
        )
    )

    if not repository:
        raise HTTPException(
            status_code=404,
            detail="Repository not found",
        )

    if not current_user.github_access_token_encrypted:
        raise HTTPException(
            status_code=401,
            detail="GitHub account is not connected",
        )

    try:
        token = decrypt_token(
            current_user.github_access_token_encrypted
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to decrypt GitHub access token",
        ) from exc

    try:
        return await merge_intelligence_service.analyze(
            full_name=repository.full_name,
            token=token,
            branch_a=request.branch_a,
            branch_b=request.branch_b,
        )
    except MergeIntelligenceError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc