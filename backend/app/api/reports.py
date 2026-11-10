import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import Finding, Repository, Scan, User
from app.schemas.report import (
    ReportFinding,
    ReportRepository,
    ReportScan,
    SecurityReportResponse,
)


router = APIRouter(prefix="/reports", tags=["Reports"])

SEVERITIES = ("critical", "high", "medium", "low", "info")


@router.get(
    "/repositories/{repository_id}",
    response_model=SecurityReportResponse,
    summary="Generate a repository security report",
    description=(
        "Returns repository details, a selected scan, findings with evidence "
        "and remediation, and scan limitations. If scan_id is omitted, the "
        "most recent scan is used."
    ),
)
def get_repository_report(
    repository_id: uuid.UUID,
    scan_id: uuid.UUID | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
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

    scan_query = select(Scan).where(Scan.repository_id == repository_id)
    if scan_id is not None:
        scan_query = scan_query.where(Scan.id == scan_id)
    else:
        scan_query = scan_query.order_by(
            Scan.created_at.desc(),
            Scan.id.desc(),
        )
    scan = db.scalar(scan_query.limit(1))

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    findings = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.created_at.asc(), Finding.id.asc())
    ).all()

    findings_by_severity = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        if finding.severity in findings_by_severity:
            findings_by_severity[finding.severity] += 1

    return SecurityReportResponse(
        repository=ReportRepository.model_validate(repository),
        scan=ReportScan.model_validate(scan),
        total_findings=len(findings),
        findings_by_severity=findings_by_severity,
        findings=[
            ReportFinding.model_validate(finding)
            for finding in findings
        ],
    )
