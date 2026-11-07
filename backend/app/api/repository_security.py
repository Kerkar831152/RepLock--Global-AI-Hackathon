from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import User, Repository, Scan, Finding
from app.schemas.repository_security import (
    RepositorySecurityResponse,
    RepositorySecurityInfo,
    RepositoryScanHistoryItem,
    AffectedFileItem,
)

router = APIRouter(
    prefix="/repositories",
    tags=["Repository Security"]
)


@router.get(
    "/{repository_id}/security",
    response_model=RepositorySecurityResponse
)
def get_repository_security(
    repository_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    repository = db.scalar(
        select(Repository).where(
            Repository.id == repository_id,
            Repository.owner_id == current_user.id
        )
    )

    if not repository:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found"
        )

    total_scans = db.scalar(
        select(func.count(Scan.id)).where(
            Scan.repository_id == repository_id
        )
    ) or 0

    total_findings = db.scalar(
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.repository_id == repository_id)
    ) or 0

    severity_rows = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.repository_id == repository_id)
        .group_by(Finding.severity)
    ).all()

    status_rows = db.execute(
        select(Finding.status, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.repository_id == repository_id)
        .group_by(Finding.status)
    ).all()

    severity_counts = {
        severity: count for severity, count in severity_rows
    }

    status_counts = {
        finding_status: count for finding_status, count in status_rows
    }

    scan_rows = db.scalars(
        select(Scan)
        .where(Scan.repository_id == repository_id)
        .order_by(Scan.created_at.desc())
        .limit(10)
    ).all()

    scan_ids = [scan.id for scan in scan_rows]

    findings_by_scan = {}

    if scan_ids:
        finding_rows = db.execute(
            select(Finding.scan_id, func.count(Finding.id))
            .where(Finding.scan_id.in_(scan_ids))
            .group_by(Finding.scan_id)
        ).all()

        findings_by_scan = {
            scan_id: count for scan_id, count in finding_rows
        }

    scan_history = [
        RepositoryScanHistoryItem(
            scan_id=scan.id,
            commit_sha=scan.commit_sha,
            status=scan.status,
            scan_type=scan.scan_type,
            summary=scan.summary,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            findings_count=findings_by_scan.get(scan.id, 0)
        )
        for scan in scan_rows
    ]

    affected_file_rows = db.execute(
        select(
            Finding.file_path,
            func.count(Finding.id).label("finding_count")
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .where(
            Scan.repository_id == repository_id,
            Finding.file_path.is_not(None)
        )
        .group_by(Finding.file_path)
        .order_by(func.count(Finding.id).desc())
        .limit(5)
    ).all()

    most_affected_files = [
        AffectedFileItem(
            file_path=file_path,
            finding_count=count
        )
        for file_path, count in affected_file_rows
    ]

    return RepositorySecurityResponse(
        repository=RepositorySecurityInfo.model_validate(repository),
        total_scans=total_scans,
        total_findings=total_findings,
        severity_counts=severity_counts,
        status_counts=status_counts,
        latest_scan=scan_history[0] if scan_history else None,
        scan_history=scan_history,
        most_affected_files=most_affected_files
    )