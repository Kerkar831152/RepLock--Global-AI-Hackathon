import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import User, Repository, Scan, Finding
from app.schemas.finding import FindingCreate, FindingResponse

router = APIRouter(prefix="/findings", tags=["Findings"])


class FindingStatusUpdate(BaseModel):
    status: Literal["open", "in_progress", "resolved", "false_positive"]


@router.post("/", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
def create_finding(
    finding_data: FindingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.scalar(
        select(Scan)
        .join(Repository)
        .where(
            Scan.id == finding_data.scan_id,
            Repository.owner_id == current_user.id
        )
    )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    new_finding = Finding(**finding_data.model_dump())
    db.add(new_finding)

    try:
        db.commit()
        db.refresh(new_finding)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Unable to create finding")

    return new_finding


@router.get("/", response_model=list[FindingResponse])
def get_findings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.scalars(
        select(Finding)
        .join(Scan)
        .join(Repository)
        .where(Repository.owner_id == current_user.id)
        .order_by(Finding.created_at.desc())
    ).all()


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    finding = db.scalar(
        select(Finding)
        .join(Scan)
        .join(Repository)
        .where(
            Finding.id == finding_id,
            Repository.owner_id == current_user.id
        )
    )

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    finding_id: uuid.UUID,
    status_data: FindingStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    finding = db.scalar(
        select(Finding)
        .join(Scan)
        .join(Repository)
        .where(
            Finding.id == finding_id,
            Repository.owner_id == current_user.id
        )
    )

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = status_data.status

    try:
        db.commit()
        db.refresh(finding)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Unable to update finding")

    return finding