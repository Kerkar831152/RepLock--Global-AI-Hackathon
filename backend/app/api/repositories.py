
import uuid

import httpx

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.security import decrypt_token
from app.models import User, Repository
from app.schemas.repository import RepositoryCreate, RepositoryResponse


router = APIRouter(prefix="/repositories", tags=["Repositories"])

GITHUB_API_URL = "https://api.github.com"


def get_github_headers(user: User):
    if not user.github_access_token_encrypted:
        raise HTTPException(
            status_code=401,
            detail="GitHub account is not connected"
        )

    try:
        token = decrypt_token(user.github_access_token_encrypted)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to decrypt GitHub access token"
        )

    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }


def github_request(url: str, headers: dict, params: dict | None = None):
    try:
        response = httpx.get(
            url,
            headers=headers,
            params=params,
            timeout=20
        )

        if response.status_code == 401:
            raise HTTPException(
                status_code=401,
                detail="GitHub authorization expired or was revoked. Please reconnect GitHub."
            )

        if response.status_code == 403:
            raise HTTPException(
                status_code=403,
                detail="GitHub denied the request. Check repository permissions or API rate limits."
            )

        if response.status_code == 404:
            raise HTTPException(
                status_code=404,
                detail="GitHub repository not found or inaccessible"
            )

        response.raise_for_status()
        return response.json()

    except HTTPException:
        raise

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="GitHub API request timed out"
        )

    except httpx.HTTPError:
        raise HTTPException(
            status_code=502,
            detail="Unable to communicate with GitHub"
        )


@router.get("/github")
def get_github_repositories(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=30, ge=1, le=100),
    current_user: User = Depends(get_current_user)
):
    headers = get_github_headers(current_user)

    repositories = github_request(
        f"{GITHUB_API_URL}/user/repos",
        headers,
        params={
            "visibility": "public",
            "affiliation": "owner",
            "sort": "updated",
            "direction": "desc",
            "per_page": per_page,
            "page": page
        }
    )

    return [
        {
            "github_repo_id": str(repo["id"]),
            "name": repo["name"],
            "full_name": repo["full_name"],
            "description": repo["description"],
            "default_branch": repo["default_branch"],
            "is_private": repo["private"],
            "html_url": repo["html_url"],
            "language": repo["language"],
            "updated_at": repo["updated_at"]
        }
        for repo in repositories
        if str(repo["owner"]["id"]) == current_user.github_id
    ]


@router.post(
    "/",
    response_model=RepositoryResponse,
    status_code=status.HTTP_201_CREATED
)
def create_repository(
    repo_data: RepositoryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    headers = get_github_headers(current_user)

    github_repo = github_request(
        f"{GITHUB_API_URL}/repositories/{repo_data.github_repo_id}",
        headers
    )

    if str(github_repo["owner"]["id"]) != current_user.github_id:
        raise HTTPException(
            status_code=403,
            detail="You can only add repositories owned by your GitHub account"
        )

    existing_repo = db.scalar(
        select(Repository).where(
            Repository.github_repo_id == str(github_repo["id"])
        )
    )

    if existing_repo:
        if existing_repo.owner_id == current_user.id:
            return existing_repo

        raise HTTPException(
            status_code=409,
            detail="Repository is already connected to another account"
        )

    new_repo = Repository(
        github_repo_id=str(github_repo["id"]),
        name=github_repo["name"],
        full_name=github_repo["full_name"],
        description=github_repo["description"],
        default_branch=github_repo["default_branch"],
        is_private=github_repo["private"],
        owner_id=current_user.id
    )

    db.add(new_repo)

    try:
        db.commit()
        db.refresh(new_repo)

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Repository already exists"
        )

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
        raise HTTPException(
            status_code=404,
            detail="Repository not found"
        )

    return repository
