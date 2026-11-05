from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from scanner.database.session import get_db
from scanner.services.report_service import (
    ReportService,
    PaginatedFindingsResponse,
    ScanReportResponse,
)

router = APIRouter(prefix="/api/v1/scans", tags=["Reports"])


@router.get("/{scan_id}/findings", response_model=PaginatedFindingsResponse)
def get_scan_findings(
    scan_id: str,
    severity: str | None = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    category: str | None = Query(None, description="Filter by category"),
    rule_id: str | None = Query(None, description="Filter by rule ID (e.g. SEC-001)"),
    status: str | None = Query(None, description="Filter by status (confirmed, potential, needs_verification)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Retrieve filtered and paginated findings for a scan."""
    # Unpack default Query objects if function is called directly in Python
    severity_val = severity.default if hasattr(severity, "default") else severity
    category_val = category.default if hasattr(category, "default") else category
    rule_id_val = rule_id.default if hasattr(rule_id, "default") else rule_id
    status_val = status.default if hasattr(status, "default") else status
    page_val = page.default if hasattr(page, "default") else page
    page_size_val = page_size.default if hasattr(page_size, "default") else page_size

    service = ReportService(db)
    # Check if scan exists
    if not service.job_repo.get_job(scan_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{scan_id}' not found",
        )

    return service.get_findings_paginated(
        scan_id=scan_id,
        severity=severity_val,
        category=category_val,
        rule_id=rule_id_val,
        status=status_val,
        page=page_val,
        page_size=page_size_val,
    )


@router.get("/{scan_id}/report", response_model=ScanReportResponse)
def get_scan_report(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve the full structured security report for a scan."""
    service = ReportService(db)
    report = service.get_complete_report(scan_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{scan_id}' not found",
        )

    return report
