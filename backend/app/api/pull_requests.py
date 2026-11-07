
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.security import decrypt_token
from app.models import User, Repository, Scan, Finding
from app.schemas.pull_request import (
    PullRequestResponse,
    PullRequestReviewResponse
)
from app.schemas.finding import FindingResponse
from app.services.pull_request_service import (
    pull_request_service,
    PullRequestError
)


router = APIRouter(
    prefix="/repositories",
    tags=["Pull Requests"]
)


def get_owned_repository(
    repo_id: uuid.UUID,
    db: Session,
    current_user: User
) -> Repository:

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


def get_github_token(user: User) -> str:

    if not user.github_access_token_encrypted:
        raise HTTPException(
            status_code=401,
            detail="GitHub account is not connected"
        )

    try:
        return decrypt_token(user.github_access_token_encrypted)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to decrypt GitHub access token"
        )


def mark_scan_failed(db: Session, scan_id: uuid.UUID):
    try:
        db.rollback()

        scan = db.get(Scan, scan_id)

        if scan:
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()

    except SQLAlchemyError:
        db.rollback()


@router.get(
    "/{repo_id}/pull-requests",
    response_model=list[PullRequestResponse]
)
async def list_repository_pull_requests(
    repo_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    repository = get_owned_repository(
        repo_id,
        db,
        current_user
    )

    token = get_github_token(current_user)

    try:
        return await pull_request_service.list_pull_requests(
            repository.full_name,
            token
        )
    except PullRequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc)
        )


@router.post(
    "/{repo_id}/pull-requests/{number}/review",
    response_model=PullRequestReviewResponse
)
async def review_pull_request(
    repo_id: uuid.UUID,
    number: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    if number < 1:
        raise HTTPException(
            status_code=400,
            detail="Invalid pull request number"
        )

    repository = get_owned_repository(
        repo_id,
        db,
        current_user
    )

    token = get_github_token(current_user)

    scan = Scan(
        repository_id=repository.id,
        commit_sha=None,
        status="running",
        scan_type="pull_request",
        summary="Pull request security review in progress",
        started_at=datetime.now(timezone.utc)
    )

    db.add(scan)

    try:
        db.commit()
        db.refresh(scan)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to create pull request review"
        )

    try:
        review = await pull_request_service.review_pull_request(
            repository.full_name,
            number,
            token
        )

        analysis = review["analysis"]

        scan.commit_sha = review["head_sha"]
        scan.summary = analysis.summary
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)

        saved_findings = []

        for item in analysis.findings:
            finding = Finding(
                scan_id=scan.id,
                title=item.title,
                description=item.description,
                severity=item.severity,
                vulnerability_type=item.vulnerability_type,
                file_path=item.file_path,
                line_number=item.line_start,
                evidence=item.evidence,
                remediation=item.remediation,
                status="open"
            )

            db.add(finding)
            saved_findings.append(finding)

        db.commit()

        for finding in saved_findings:
            db.refresh(finding)

        db.refresh(scan)

        return PullRequestReviewResponse(
            scan_id=scan.id,
            pull_request_number=number,
            pull_request_url=review["html_url"],
            head_sha=review["head_sha"],
            status=scan.status,
            summary=analysis.summary,
            files_analyzed=review["files_analyzed"],
            findings=[
                FindingResponse.model_validate(item)
                for item in saved_findings
            ],
            limitations=review["limitations"]
        )

    except PullRequestError as exc:
        mark_scan_failed(db, scan.id)

        raise HTTPException(
            status_code=502,
            detail=str(exc)
        )

    except SQLAlchemyError as exc:
        mark_scan_failed(db, scan.id)

        raise HTTPException(
            status_code=500,
            detail="Unable to save pull request review results"
        ) from exc

    except Exception as exc:
        mark_scan_failed(db, scan.id)

        raise HTTPException(
            status_code=500,
            detail="Pull request review failed"
        ) from exc
