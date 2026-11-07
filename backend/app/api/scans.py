import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.security import decrypt_token
from app.models import User, Repository, Scan, Finding
from app.schemas.scan import ScanCreate, ScanResponse
from app.schemas.finding import FindingResponse
from app.services.scan_orchestrator import (
    scan_orchestrator,
    ScanOrchestrationError
)


router = APIRouter(prefix="/scans", tags=["Scans"])


class ScanStatusUpdate(BaseModel):
    status: Literal["pending", "running", "completed", "failed"]


class ScanRunResponse(BaseModel):
    scan: ScanResponse
    findings: list[FindingResponse]
    semgrep_findings: int
    files_analyzed: int
    limitations: list[str] = []

    model_config = ConfigDict(from_attributes=True)


@router.post(
    "/run",
    response_model=ScanRunResponse,
    status_code=status.HTTP_201_CREATED
)
async def run_repository_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if scan_data.scan_type == "dynamic":
        raise HTTPException(
            status_code=400,
            detail="Dynamic scanning is not available yet"
        )

    repository = db.scalar(
        select(Repository).where(
            Repository.id == scan_data.repository_id,
            Repository.owner_id == current_user.id
        )
    )

    if not repository:
        raise HTTPException(
            status_code=404,
            detail="Repository not found"
        )

    if not current_user.github_access_token_encrypted:
        raise HTTPException(
            status_code=401,
            detail="GitHub account is not connected"
        )

    try:
        access_token = decrypt_token(
            current_user.github_access_token_encrypted
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to access GitHub credentials"
        )

    new_scan = Scan(
        repository_id=repository.id,
        commit_sha=scan_data.commit_sha,
        scan_type=scan_data.scan_type,
        status="running",
        started_at=datetime.now(timezone.utc)
    )

    db.add(new_scan)

    try:
        db.commit()
        db.refresh(new_scan)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Unable to create scan"
        )

    try:
        result = await scan_orchestrator.run(
            repository,
            access_token
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
                    vulnerability_type=item.vulnerability_type[:100],
                    file_path=item.file_path[:500],
                    line_number=item.line_start,
                    evidence=item.evidence,
                    remediation=item.remediation
                )
            )

        db.commit()
        db.refresh(new_scan)

        findings = db.scalars(
            select(Finding)
            .where(Finding.scan_id == new_scan.id)
            .order_by(Finding.created_at.asc())
        ).all()

        return ScanRunResponse(
            scan=new_scan,
            findings=findings,
            semgrep_findings=result["semgrep_findings"],
            files_analyzed=result["files_analyzed"],
            limitations=result["limitations"]
        )

    except Exception as exc:
        db.rollback()

        failed_scan = db.get(Scan, new_scan.id)

        if failed_scan:
            failed_scan.status = "failed"
            failed_scan.completed_at = datetime.now(timezone.utc)
            failed_scan.summary = "Security scan failed"
            db.commit()

        if isinstance(exc, ScanOrchestrationError):
            raise HTTPException(
                status_code=502,
                detail=str(exc)
            )

        raise HTTPException(
            status_code=502,
            detail="Repository security scan failed"
        )


@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED
)
def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    repository = db.scalar(
        select(Repository).where(
            Repository.id == scan_data.repository_id,
            Repository.owner_id == current_user.id
        )
    )

    if not repository:
        raise HTTPException(status_code=404, detail="Repository not found")

    new_scan = Scan(**scan_data.model_dump())
    db.add(new_scan)

    try:
        db.commit()
        db.refresh(new_scan)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Unable to create scan")

    return new_scan


@router.get("/", response_model=list[ScanResponse])
def get_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.scalars(
        select(Scan)
        .join(Repository)
        .where(Repository.owner_id == current_user.id)
        .order_by(Scan.created_at.desc())
    ).all()


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.scalar(
        select(Scan)
        .join(Repository)
        .where(
            Scan.id == scan_id,
            Repository.owner_id == current_user.id
        )
    )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@router.patch("/{scan_id}/status", response_model=ScanResponse)
def update_scan_status(
    scan_id: uuid.UUID,
    update_data: ScanStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.scalar(
        select(Scan)
        .join(Repository)
        .where(
            Scan.id == scan_id,
            Repository.owner_id == current_user.id
        )
    )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    new_status = update_data.status
    scan.status = new_status

    if new_status == "running" and scan.started_at is None:
        scan.started_at = datetime.now(timezone.utc)

    if new_status in {"completed", "failed"}:
        scan.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)

    return scan