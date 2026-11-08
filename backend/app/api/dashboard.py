
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import User, Repository, Scan, Finding
from app.schemas.dashboard import DashboardOverviewResponse


router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("open", "in_progress", "resolved", "false_positive")
SCAN_STATUSES = ("pending", "running", "completed", "failed")
UNRESOLVED_STATUSES = ("open", "in_progress")

SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0
}


def get_risk_level(risk_points: int) -> str:
    if risk_points >= 80:
        return "critical"
    if risk_points >= 50:
        return "high"
    if risk_points >= 20:
        return "moderate"
    return "low"


@router.get(
    "/overview",
    response_model=DashboardOverviewResponse
)
def get_dashboard_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    owner_filter = Repository.owner_id == current_user.id

    total_repositories = db.scalar(
        select(func.count(Repository.id))
        .where(owner_filter)
    ) or 0

    total_scans = db.scalar(
        select(func.count(Scan.id))
        .join(Repository, Scan.repository_id == Repository.id)
        .where(owner_filter)
    ) or 0

    scan_rows = db.execute(
        select(Scan.status, func.count(Scan.id))
        .join(Repository, Scan.repository_id == Repository.id)
        .where(owner_filter)
        .group_by(Scan.status)
    ).all()

    scan_status_counts = {key: 0 for key in SCAN_STATUSES}

    for scan_status, count in scan_rows:
        if scan_status in scan_status_counts:
            scan_status_counts[scan_status] = count

    finding_rows = db.execute(
        select(
            Finding.severity,
            Finding.status,
            func.count(Finding.id)
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(owner_filter)
        .group_by(Finding.severity, Finding.status)
    ).all()

    findings_by_severity = {key: 0 for key in SEVERITIES}
    findings_by_status = {key: 0 for key in STATUSES}
    unresolved_by_severity = {key: 0 for key in SEVERITIES}

    for severity, finding_status, count in finding_rows:
        if severity in findings_by_severity:
            findings_by_severity[severity] += count

        if finding_status in findings_by_status:
            findings_by_status[finding_status] += count

        if (
            severity in unresolved_by_severity
            and finding_status in UNRESOLVED_STATUSES
        ):
            unresolved_by_severity[severity] += count

    total_findings = sum(findings_by_severity.values())

    risk_points = sum(
        unresolved_by_severity[severity] * weight
        for severity, weight in SEVERITY_WEIGHTS.items()
    )

    security_score = max(0, 100 - min(100, risk_points))
    risk_level = get_risk_level(risk_points)

    recent_scan_rows = db.execute(
        select(
            Scan.id,
            Scan.repository_id,
            Repository.full_name,
            Scan.status,
            Scan.scan_type,
            Scan.commit_sha,
            Scan.created_at,
            Scan.completed_at,
            func.count(Finding.id).label("findings_count")
        )
        .join(Repository, Scan.repository_id == Repository.id)
        .outerjoin(Finding, Finding.scan_id == Scan.id)
        .where(owner_filter)
        .group_by(
            Scan.id,
            Scan.repository_id,
            Repository.full_name,
            Scan.status,
            Scan.scan_type,
            Scan.commit_sha,
            Scan.created_at,
            Scan.completed_at
        )
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(5)
    ).all()

    recent_scans = [
        {
            "scan_id": row.id,
            "repository_id": row.repository_id,
            "repository_name": row.full_name,
            "status": row.status,
            "scan_type": row.scan_type,
            "commit_sha": row.commit_sha,
            "created_at": row.created_at,
            "completed_at": row.completed_at,
            "findings_count": row.findings_count
        }
        for row in recent_scan_rows
    ]

    affected_file_rows = db.execute(
        select(
            Finding.file_path,
            func.count(Finding.id).label("finding_count"),
            func.count(func.distinct(Scan.repository_id)).label(
                "repository_count"
            )
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Repository, Scan.repository_id == Repository.id)
        .where(
            owner_filter,
            Finding.file_path.is_not(None),
            Finding.file_path != ""
        )
        .group_by(Finding.file_path)
        .order_by(
            func.count(Finding.id).desc(),
            Finding.file_path.asc()
        )
        .limit(5)
    ).all()

    most_affected_files = [
        {
            "file_path": row.file_path,
            "finding_count": row.finding_count,
            "repository_count": row.repository_count
        }
        for row in affected_file_rows
    ]

    return {
        "total_repositories": total_repositories,
        "total_scans": total_scans,
        "scan_status_counts": scan_status_counts,
        "total_findings": total_findings,
        "findings_by_severity": findings_by_severity,
        "findings_by_status": findings_by_status,
        "security_score": security_score,
        "risk_level": risk_level,
        "risk_points": risk_points,
        "latest_scan": recent_scans[0] if recent_scans else None,
        "recent_scans": recent_scans,
        "most_affected_files": most_affected_files
    }
