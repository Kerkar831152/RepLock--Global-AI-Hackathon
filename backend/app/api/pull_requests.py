import asyncio
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
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
logger = logging.getLogger(__name__)
# Bump this when review analysis or attribution semantics change.
PR_REVIEW_VERSION = 1


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


def get_existing_review(
    db: Session,
    repository_id: uuid.UUID,
    number: int,
    head_sha: str
) -> Scan | None:

    return db.scalar(
        select(Scan)
        .where(
            Scan.repository_id == repository_id,
            Scan.pull_request_number == number,
            Scan.commit_sha == head_sha,
            Scan.scan_type == "pull_request",
            Scan.review_version == PR_REVIEW_VERSION,
            Scan.status.in_(["running", "completed"])
        )
        .limit(1)
    )


def build_existing_review_response(
    db: Session,
    scan: Scan,
    number: int,
    pull_request_url: str
) -> PullRequestReviewResponse:

    findings = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.created_at.asc(), Finding.id.asc())
    ).all()

    return PullRequestReviewResponse(
        scan_id=scan.id,
        pull_request_number=number,
        pull_request_url=pull_request_url,
        head_sha=scan.commit_sha,
        status=scan.status,
        summary=scan.summary or "",
        changed_files=scan.changed_files or 0,
        files_analyzed=scan.files_analyzed or 0,
        findings=[
            FindingResponse.model_validate(item)
            for item in findings
        ],
        limitations=list(scan.limitations or []) + [
            "This pull request commit has already been reviewed. "
            "The previously saved review is being returned."
        ],
    )


def mark_scan_failed(
    db: Session,
    scan_id: uuid.UUID,
    failure_summary: str = "Pull request security review failed",
):
    try:
        db.rollback()

        scan = db.get(Scan, scan_id)

        if scan:
            scan.status = "failed"
            scan.summary = failure_summary
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()

    except SQLAlchemyError:
        db.rollback()
        logger.exception("Unable to persist failed PR review %s", scan_id)


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
    response_model=PullRequestReviewResponse,
    summary="Review the current pull request head",
    description=(
        "Reviews added code in the current PR head. A completed review is "
        "reused only for the same repository, PR number, head SHA, and review "
        "version; a changed head or review version triggers fresh analysis."
    ),
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

    try:
        metadata = await pull_request_service.get_pull_request_metadata(
            repository.full_name,
            number,
            token
        )
    except PullRequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc)
        )

    existing = get_existing_review(
        db,
        repository.id,
        number,
        metadata["head_sha"]
    )

    if existing:
        if existing.status == "completed":
            return build_existing_review_response(
                db,
                existing,
                number,
                metadata["html_url"]
            )

        raise HTTPException(
            status_code=409,
            detail="A review for this pull request commit is already running."
        )

    scan = Scan(
        repository_id=repository.id,
        commit_sha=metadata["head_sha"],
        pull_request_number=number,
        changed_files=metadata["changed_files"],
        review_version=PR_REVIEW_VERSION,
        files_analyzed=0,
        status="running",
        scan_type="pull_request",
        summary="Pull request security review in progress",
        started_at=datetime.now(timezone.utc)
    )

    db.add(scan)

    try:
        db.commit()
        db.refresh(scan)

    except IntegrityError:
        db.rollback()

        existing = get_existing_review(
            db,
            repository.id,
            number,
            metadata["head_sha"]
        )

        if existing and existing.status == "completed":
            return build_existing_review_response(
                db,
                existing,
                number,
                metadata["html_url"]
            )

        raise HTTPException(
            status_code=409,
            detail="A review for this pull request commit is already running."
        )

    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to create pull request review"
        ) from exc

    try:
        review = await pull_request_service.review_pull_request(
            repository.full_name,
            number,
            token,
            metadata=metadata
        )

        analysis = review["analysis"]

        scan.commit_sha = review["head_sha"]
        scan.changed_files = review["changed_files"]
        scan.files_analyzed = review["files_analyzed"]
        scan.summary = analysis.summary
        scan.limitations = review["limitations"]
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
            changed_files=review["changed_files"],
            files_analyzed=review["files_analyzed"],
            findings=[
                FindingResponse.model_validate(item)
                for item in saved_findings
            ],
            limitations=review["limitations"]
        )

    except asyncio.CancelledError:
        mark_scan_failed(
            db,
            scan.id,
            "Pull request security review was cancelled",
        )
        raise

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