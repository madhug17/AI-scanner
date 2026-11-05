import json
from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from sqlalchemy.orm import Session

from scanner.database.session import get_db
from scanner.services.report_service import (
    ReportService,
    PaginatedFindingsResponse,
    ScanReportResponse,
)
from scanner.database.repositories import FindingRepository
from scanner.services.pdf_report import generate_pdf_report

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
    severity_val = severity.default if hasattr(severity, "default") else severity
    category_val = category.default if hasattr(category, "default") else category
    rule_id_val = rule_id.default if hasattr(rule_id, "default") else rule_id
    status_val = status.default if hasattr(status, "default") else status
    page_val = page.default if hasattr(page, "default") else page
    page_size_val = page_size.default if hasattr(page_size, "default") else page_size

    service = ReportService(db)
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
@router.get("/{scan_id}/results", response_model=ScanReportResponse)
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
            detail=f"Scan report for '{scan_id}' not found",
        )
    return report


@router.get("/{scan_id}/report/json")
def download_scan_report_json(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Download full scan report as a JSON file attachment."""
    service = ReportService(db)
    report = service.get_complete_report(scan_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    content = report.model_dump_json(indent=2)
    filename = f"scan-report-{scan_id[:8]}.json"
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/report/pdf")
def download_scan_report_pdf(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Download publication-ready PDF security report."""
    service = ReportService(db)
    report = service.get_complete_report(scan_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    pdf_bytes = generate_pdf_report(report)
    filename = f"scan-report-{scan_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/compare/{target_scan_id}")
def compare_two_scans(
    scan_id: str,
    target_scan_id: str,
    db: Session = Depends(get_db),
):
    """Compare baseline scan against target scan to compute new, resolved, and persistent vulnerabilities."""
    service = ReportService(db)
    rep_a = service.job_repo.get_job(scan_id)
    rep_b = service.job_repo.get_job(target_scan_id)
    if not rep_a or not rep_b:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both scans not found")

    finding_repo = FindingRepository(db)
    diff = finding_repo.compare_scans(scan_id, target_scan_id)

    # Format findings in diff
    def format_list(f_list):
        return [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "status": f.status,
            }
            for f in f_list
        ]

    score_a = rep_a.summary.risk_score if rep_a.summary else 0.0
    score_b = rep_b.summary.risk_score if rep_b.summary else 0.0

    return {
        "baseline_scan_id": scan_id,
        "target_scan_id": target_scan_id,
        "risk_score_delta": round(score_b - score_a, 1),
        "new_count": diff["new_count"],
        "resolved_count": diff["resolved_count"],
        "persistent_count": diff["persistent_count"],
        "new_findings": format_list(diff["new_findings"]),
        "resolved_findings": format_list(diff["resolved_findings"]),
        "persistent_findings": format_list(diff["persistent_findings"]),
    }
