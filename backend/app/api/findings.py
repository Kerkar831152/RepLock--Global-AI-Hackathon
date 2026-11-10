
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import User, Repository, Scan, Finding
from app.schemas.finding import (
    FindingCreate,
    FindingResponse,
    FindingStatusUpdate,
    FindingListResponse,
    FindingSummaryResponse,
)

router = APIRouter(prefix="/findings", tags=["Findings"])

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = (
    "open",
    "in_progress",
    "resolved",
    "ignored",
    "false_positive",
)


def _finding_query(current_user: User):
    return (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(Repository.owner_id == current_user.id)
    )


def _get_owned_finding(
    finding_id: uuid.UUID,
    db: Session,
    current_user: User,
):
    finding = db.scalar(
        _finding_query(current_user).where(Finding.id == finding_id)
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return finding


def _apply_filters(
    query,
    severity,
    finding_status,
    scan_id,
    repository_id,
    vulnerability_type,
    search,
    date_from,
    date_to,
):
    if severity:
        query = query.where(Finding.severity == severity)

    if finding_status:
        query = query.where(Finding.status == finding_status)

    if scan_id:
        query = query.where(Finding.scan_id == scan_id)

    if repository_id:
        query = query.where(Scan.repository_id == repository_id)

    if vulnerability_type:
        value = vulnerability_type.strip()
        if value:
            query = query.where(
                Finding.vulnerability_type.ilike(f"%{value}%")
            )

    if search:
        value = search.strip()
        if value:
            term = f"%{value}%"
            query = query.where(
                Finding.title.ilike(term)
                | Finding.description.ilike(term)
                | Finding.file_path.ilike(term)
                | Finding.vulnerability_type.ilike(term)
                | Finding.evidence.ilike(term)
            )

    if date_from:
        query = query.where(Finding.created_at >= date_from)

    if date_to:
        query = query.where(Finding.created_at <= date_to)

    return query


@router.post(
    "/",
    response_model=FindingResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_finding(
    finding_data: FindingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = db.scalar(
        select(Scan)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(
            Scan.id == finding_data.scan_id,
            Repository.owner_id == current_user.id,
        )
    )

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    new_finding = Finding(**finding_data.model_dump())
    db.add(new_finding)

    try:
        db.commit()
        db.refresh(new_finding)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to create finding",
        )

    return new_finding


@router.get(
    "/summary",
    response_model=FindingSummaryResponse,
)
def get_finding_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    base_query = _finding_query(current_user)

    total = db.scalar(
        select(func.count()).select_from(base_query.subquery())
    ) or 0

    grouped_rows = db.execute(
        select(
            Finding.severity,
            Finding.status,
            func.count(Finding.id),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(Repository.owner_id == current_user.id)
        .group_by(Finding.severity, Finding.status)
    ).all()

    by_severity = {key: 0 for key in SEVERITIES}
    by_status = {key: 0 for key in STATUSES}

    for severity, finding_status, count in grouped_rows:
        if severity in by_severity:
            by_severity[severity] += count

        if finding_status in by_status:
            by_status[finding_status] += count

    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
    }


@router.get(
    "/",
    response_model=FindingListResponse,
)
def get_findings(
    severity: str | None = Query(
        default=None,
        pattern="^(critical|high|medium|low|info)$",
    ),
    finding_status: str | None = Query(
        default=None,
        alias="status",
        pattern="^(open|in_progress|resolved|ignored|false_positive)$",
    ),
    scan_id: uuid.UUID | None = None,
    repository_id: uuid.UUID | None = None,
    vulnerability_type: str | None = Query(
        default=None,
        max_length=100,
    ),
    search: str | None = Query(
        default=None,
        max_length=100,
    ),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if date_from and date_to and date_from > date_to:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="date_from cannot be later than date_to",
        )

    query = _apply_filters(
        _finding_query(current_user),
        severity,
        finding_status,
        scan_id,
        repository_id,
        vulnerability_type,
        search,
        date_from,
        date_to,
    )

    total = db.scalar(
        select(func.count()).select_from(
            query.order_by(None).subquery()
        )
    ) or 0

    findings = db.scalars(
        query
        .order_by(
            Finding.created_at.desc(),
            Finding.id.desc(),
        )
        .limit(limit)
        .offset(offset)
    ).all()

    return {
        "items": findings,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
)
def get_finding(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return _get_owned_finding(finding_id, db, current_user)


@router.patch(
    "/{finding_id}/status",
    response_model=FindingResponse,
)
def update_finding_status(
    finding_id: uuid.UUID,
    status_data: FindingStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = _get_owned_finding(
        finding_id,
        db,
        current_user,
    )

    finding.status = status_data.status

    try:
        db.commit()
        db.refresh(finding)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to update finding",
        )

    return finding


findings_router = router
