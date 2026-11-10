
import asyncio
import logging
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, get_db
from app.core.dependencies import get_current_user
from app.core.security import decrypt_token
from app.models import User, Repository, Scan, Finding
from app.schemas.scan import ScanCreate, ScanResponse
from app.schemas.finding import FindingResponse
from app.services.scan_orchestrator import (
    scan_orchestrator,
    ScanOrchestrationError,
)

router = APIRouter(prefix="/scans", tags=["Scans"])
logger = logging.getLogger(__name__)


class ScanStatusUpdate(BaseModel):
    status: Literal["pending", "running", "completed", "failed"]


class ScanRunResponse(BaseModel):
    scan: ScanResponse
    findings: list[FindingResponse]
    semgrep_findings: int
    files_analyzed: int
    limitations: list[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


def _get_owned_repository(
    repository_id: uuid.UUID,
    db: Session,
    current_user: User,
    *,
    for_update: bool = False,
):
    query = select(Repository).where(
        Repository.id == repository_id,
        Repository.owner_id == current_user.id,
    )
    if for_update:
        query = query.with_for_update()
    repository = db.scalar(query)

    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found",
        )

    return repository


def _get_owned_scan(
    scan_id: uuid.UUID,
    db: Session,
    current_user: User,
):
    scan = db.scalar(
        select(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(
            Scan.id == scan_id,
            Repository.owner_id == current_user.id,
        )
    )

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return scan


def mark_scan_failed(
    db: Session,
    scan_id: uuid.UUID,
    failure_summary: str = "Security scan failed",
):
    try:
        scan = db.get(Scan, scan_id)

        if scan:
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.summary = failure_summary[:5000]
            db.commit()

    except SQLAlchemyError:
        db.rollback()
        logger.exception("Unable to persist failed status for scan %s", scan_id)


def _apply_scan_result(db: Session, scan: Scan, result: dict) -> list[Finding]:
    scan.commit_sha = result["commit_sha"]
    scan.files_analyzed = result["files_analyzed"]
    scan.semgrep_findings = result["semgrep_findings"]
    scan.limitations = result["limitations"]
    scan.summary = result["summary"]
    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)

    saved_findings = []
    for item in result["findings"]:
        finding = Finding(
            scan_id=scan.id,
            title=item.title[:255],
            description=item.description,
            severity=item.severity,
            vulnerability_type=(item.vulnerability_type or "unknown")[:100],
            file_path=item.file_path[:500] if item.file_path else None,
            line_number=item.line_start,
            evidence=item.evidence,
            remediation=item.remediation,
        )
        db.add(finding)
        saved_findings.append(finding)

    return saved_findings


async def execute_background_scan(
    scan_id: uuid.UUID,
    repository: SimpleNamespace,
    access_token: str,
) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan or scan.status != "pending":
            logger.warning(
                "Background scan %s was missing or no longer pending",
                scan_id,
            )
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        scan.summary = "Security scan in progress"
        db.commit()

        result = await scan_orchestrator.run(repository, access_token)
        _apply_scan_result(db, scan, result)
        db.commit()
    except asyncio.CancelledError:
        db.rollback()
        mark_scan_failed(
            db,
            scan_id,
            "Repository security scan was cancelled",
        )
        raise
    except Exception as exc:
        db.rollback()
        failure_summary = (
            str(exc)
            if isinstance(exc, ScanOrchestrationError)
            else "Repository security scan failed. Check backend logs."
        )
        mark_scan_failed(db, scan_id, failure_summary)
        logger.exception("Background scan %s failed", scan_id)
    finally:
        db.close()


@router.post(
    "/run",
    response_model=ScanRunResponse,
    status_code=status.HTTP_201_CREATED,
)
async def run_repository_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if scan_data.scan_type == "dynamic":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Dynamic scanning is not available yet",
        )

    repository = _get_owned_repository(
        scan_data.repository_id,
        db,
        current_user,
        for_update=True,
    )

    active_scan = db.scalar(
        select(Scan.id).where(
            Scan.repository_id == repository.id,
            Scan.status.in_(["pending", "running"]),
        )
    )
    if active_scan:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A security scan is already running for this repository.",
        )

    if not current_user.github_access_token_encrypted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GitHub account is not connected",
        )

    try:
        access_token = decrypt_token(
            current_user.github_access_token_encrypted
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to access GitHub credentials",
        ) from exc

    new_scan = Scan(
        repository_id=repository.id,
        commit_sha=scan_data.commit_sha,
        scan_type=scan_data.scan_type,
        status="running",
        started_at=datetime.now(timezone.utc),
    )

    db.add(new_scan)

    try:
        db.commit()
        db.refresh(new_scan)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create scan",
        ) from exc

    try:
        result = await scan_orchestrator.run(
            repository,
            access_token,
        )

        saved_findings = _apply_scan_result(db, new_scan, result)
        db.flush()
        response = ScanRunResponse(
            scan=new_scan,
            findings=saved_findings,
            semgrep_findings=result["semgrep_findings"],
            files_analyzed=result["files_analyzed"],
            limitations=result["limitations"],
        )
        db.commit()
        return response

    except asyncio.CancelledError:
        db.rollback()
        mark_scan_failed(
            db,
            new_scan.id,
            "Repository security scan was cancelled",
        )
        raise

    except Exception as exc:
        db.rollback()
        failure_summary = (
            str(exc)
            if isinstance(exc, ScanOrchestrationError)
            else "Repository security scan failed. Check backend logs."
        )
        mark_scan_failed(db, new_scan.id, failure_summary)
        logger.exception("Scan %s failed unexpectedly", new_scan.id)

        if isinstance(exc, ScanOrchestrationError):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Repository security scan failed",
        ) from exc


@router.post(
    "/background",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a repository security scan in the background",
    description=(
        "Creates a pending scan and returns immediately. Poll GET /scans/{scan_id} "
        "for status and query GET /findings?scan_id={scan_id} for results. "
        "The task runs in this API process and is not durable across restarts."
    ),
)
async def start_background_repository_scan(
    background_tasks: BackgroundTasks,
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if scan_data.scan_type == "dynamic":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Dynamic scanning is not available yet",
        )

    repository = _get_owned_repository(
        scan_data.repository_id,
        db,
        current_user,
        for_update=True,
    )
    active_scan = db.scalar(
        select(Scan.id).where(
            Scan.repository_id == repository.id,
            Scan.status.in_(["pending", "running"]),
        )
    )
    if active_scan:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A security scan is already running for this repository.",
        )

    if not current_user.github_access_token_encrypted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GitHub account is not connected",
        )
    try:
        access_token = decrypt_token(
            current_user.github_access_token_encrypted
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to access GitHub credentials",
        ) from exc

    scan = Scan(
        repository_id=repository.id,
        commit_sha=scan_data.commit_sha,
        scan_type=scan_data.scan_type,
        status="pending",
        summary="Security scan queued",
    )
    db.add(scan)
    try:
        db.commit()
        db.refresh(scan)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create scan",
        ) from exc

    target = SimpleNamespace(
        full_name=repository.full_name,
        default_branch=repository.default_branch,
    )
    background_tasks.add_task(
        execute_background_scan,
        scan.id,
        target,
        access_token,
    )
    return scan


@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if scan_data.scan_type == "dynamic":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Dynamic scanning is not available yet",
        )

    repository = _get_owned_repository(
        scan_data.repository_id,
        db,
        current_user,
    )

    new_scan = Scan(
        repository_id=repository.id,
        commit_sha=scan_data.commit_sha,
        scan_type=scan_data.scan_type,
    )

    db.add(new_scan)

    try:
        db.commit()
        db.refresh(new_scan)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create scan",
        ) from exc

    return new_scan


@router.get("/", response_model=list[ScanResponse])
def get_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return db.scalars(
        select(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(Repository.owner_id == current_user.id)
        .order_by(Scan.created_at.desc())
    ).all()


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return _get_owned_scan(scan_id, db, current_user)


@router.patch(
    "/{scan_id}/status",
    response_model=ScanResponse,
)
def update_scan_status(
    scan_id: uuid.UUID,
    update_data: ScanStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = _get_owned_scan(scan_id, db, current_user)
    new_status = update_data.status

    allowed_transitions = {
        "pending": {"running", "failed"},
        "running": {"failed"},
        "completed": set(),
        "failed": set(),
    }

    if new_status == scan.status:
        return scan

    if new_status not in allowed_transitions[scan.status]:
        if new_status == "completed":
            detail = "A scan can only be completed by a successful scan execution."
        else:
            detail = (
                f"Cannot change scan status from '{scan.status}' to '{new_status}'"
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        )

    now = datetime.now(timezone.utc)
    scan.status = new_status

    if new_status == "running":
        scan.started_at = now

    if new_status in {"completed", "failed"}:
        scan.completed_at = now

    try:
        db.commit()
        db.refresh(scan)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to update scan status",
        ) from exc

    return scan
