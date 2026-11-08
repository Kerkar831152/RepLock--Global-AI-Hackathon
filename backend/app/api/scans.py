
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import get_db
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
):
    repository = db.scalar(
        select(Repository).where(
            Repository.id == repository_id,
            Repository.owner_id == current_user.id,
        )
    )

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


def mark_scan_failed(db: Session, scan_id: uuid.UUID):
    try:
        scan = db.get(Scan, scan_id)

        if scan:
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.summary = "Security scan failed"
            db.commit()

    except SQLAlchemyError:
        db.rollback()


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

        new_scan.commit_sha = result["commit_sha"]
        new_scan.summary = result["summary"]
        new_scan.status = "completed"
        new_scan.completed_at = datetime.now(timezone.utc)

        for item in result["findings"]:
            db.add(
                Finding(
                    scan_id=new_scan.id,
                    title=item.title[:255],
                    description=item.description,
                    severity=item.severity,
                    vulnerability_type=(
                        item.vulnerability_type or "unknown"
                    )[:100],
                    file_path=(
                        item.file_path[:500]
                        if item.file_path
                        else None
                    ),
                    line_number=item.line_start,
                    evidence=item.evidence,
                    remediation=item.remediation,
                )
            )

        db.commit()
        db.refresh(new_scan)

        findings = db.scalars(
            select(Finding)
            .where(Finding.scan_id == new_scan.id)
            .order_by(
                Finding.created_at.asc(),
                Finding.id.asc(),
            )
        ).all()

        return ScanRunResponse(
            scan=new_scan,
            findings=findings,
            semgrep_findings=result["semgrep_findings"],
            files_analyzed=result["files_analyzed"],
            limitations=result["limitations"],
        )

    except Exception as exc:
        db.rollback()
        mark_scan_failed(db, new_scan.id)

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
        "running": {"completed", "failed"},
        "completed": set(),
        "failed": set(),
    }

    if new_status == scan.status:
        return scan

    if new_status not in allowed_transitions[scan.status]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot change scan status from '{scan.status}' to '{new_status}'",
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
