
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import User, Repository, Scan
from app.schemas.scan import ScanCreate, ScanResponse

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
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
    db.commit()
    db.refresh(new_scan)

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
    new_status: str,
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

    allowed_statuses = {"pending", "running", "completed", "failed"}

    if new_status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="Invalid scan status")

    scan.status = new_status

    if new_status == "running" and scan.started_at is None:
        scan.started_at = datetime.now(timezone.utc)

    if new_status in {"completed", "failed"}:
        scan.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)

    return scan
