
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import User, Repository
from app.schemas.repository import RepositoryCreate, RepositoryResponse

router = APIRouter(prefix="/repositories", tags=["Repositories"])


@router.post("/", response_model=RepositoryResponse, status_code=status.HTTP_201_CREATED)
def create_repository(
    repo_data: RepositoryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    existing_repo = db.scalar(
        select(Repository).where(
            Repository.github_repo_id == repo_data.github_repo_id
        )
    )

    if existing_repo:
        raise HTTPException(status_code=409, detail="Repository already exists")

    repo_fields = repo_data.model_dump(exclude={"owner_id"})

    new_repo = Repository(
        **repo_fields,
        owner_id=current_user.id
    )

    db.add(new_repo)

    try:
        db.commit()
        db.refresh(new_repo)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Repository already exists")

    return new_repo


@router.get("/", response_model=list[RepositoryResponse])
def get_repositories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.scalars(
        select(Repository)
        .where(Repository.owner_id == current_user.id)
        .order_by(Repository.created_at.desc())
    ).all()


@router.get("/{repo_id}", response_model=RepositoryResponse)
def get_repository(
    repo_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    repository = db.scalar(
        select(Repository).where(
            Repository.id == repo_id,
            Repository.owner_id == current_user.id
        )
    )

    if not repository:
        raise HTTPException(status_code=404, detail="Repository not found")

    return repository
