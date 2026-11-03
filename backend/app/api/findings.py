import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import Scan, Finding
from app.schemas.finding import FindingCreate, FindingResponse

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.post("/", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
def create_finding(finding_data: FindingCreate, db: Session = Depends(get_db)):
    scan = db.get(Scan, finding_data.scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    new_finding = Finding(**finding_data.model_dump())
    db.add(new_finding)
    db.commit()
    db.refresh(new_finding)

    return new_finding


@router.get("/", response_model=list[FindingResponse])
def get_findings(db: Session = Depends(get_db)):
    return db.scalars(select(Finding).order_by(Finding.created_at.desc())).all()


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: uuid.UUID, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(finding_id: uuid.UUID, new_status: str, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    allowed_statuses = {"open", "in_progress", "resolved", "false_positive"}

    if new_status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="Invalid finding status")

    finding.status = new_status
    db.commit()
    db.refresh(finding)

    return finding