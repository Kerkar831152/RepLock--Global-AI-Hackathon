import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import User, Repository
from app.schemas.repository import RepositoryCreate, RepositoryResponse

router = APIRouter(prefix="/repositories", tags=["Repositories"])

@router.post("/", response_model=RepositoryResponse, status_code=status.HTTP_201_CREATED)
def create_repository(repo_data: RepositoryCreate, db: Session = Depends(get_db)):
    owner = db.get(User, repo_data.owner_id)

    if not owner:
        raise HTTPException(status_code=404, detail="Owner not found")

    existing_repo = db.scalar(
        select(Repository).where(Repository.github_repo_id == repo_data.github_repo_id)
    )

    if existing_repo:
        raise HTTPException(status_code=409, detail="Repository already exists")

    new_repo = Repository(**repo_data.model_dump())
    db.add(new_repo)

    try:
        db.commit()
        db.refresh(new_repo)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Repository already exists")

    return new_repo


@router.get("/", response_model=list[RepositoryResponse])
def get_repositories(db: Session = Depends(get_db)):
    return db.scalars(select(Repository).order_by(Repository.created_at.desc())).all()


@router.get("/{repo_id}", response_model=RepositoryResponse)
def get_repository(repo_id: uuid.UUID, db: Session = Depends(get_db)):
    repository = db.get(Repository, repo_id)

    if not repository:
        raise HTTPException(status_code=404, detail="Repository not found")

    return repository