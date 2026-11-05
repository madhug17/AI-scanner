from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from scanner.database.session import get_db
from scanner.database.repositories import FindingRepository
from scanner.database.models import FindingModel, EvidenceModel

router = APIRouter(prefix="/findings", tags=["Findings"])


class EvidenceResponse(BaseModel):
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    rule_id: str
    title: str
    category: str
    severity: str
    status: str
    confidence: str
    detection_source: str
    description: str
    impact: str
    recommendation: str
    evidence: list[EvidenceResponse] = []


class FindingStatusUpdateRequest(BaseModel):
    status: str  # open, confirmed, false_positive, resolved


class PaginatedAllFindingsResponse(BaseModel):
    page: int
    page_size: int
    total_findings: int
    items: list[FindingResponse]


@router.get("", response_model=PaginatedAllFindingsResponse)
def list_all_findings(
    severity: str | None = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    category: str | None = Query(None, description="Filter by category"),
    status_filter: str | None = Query(None, alias="status", description="Filter by status (open, confirmed, false_positive, resolved)"),
    search: str | None = Query(None, description="Search keyword in title or description"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    severity_val = severity.default if hasattr(severity, "default") else severity
    category_val = category.default if hasattr(category, "default") else category
    status_val = status_filter.default if hasattr(status_filter, "default") else status_filter
    search_val = search.default if hasattr(search, "default") else search
    page_val = page.default if hasattr(page, "default") else page
    page_size_val = page_size.default if hasattr(page_size, "default") else page_size

    repo = FindingRepository(db)
    items, total = repo.list_all_findings(
        severity=severity_val,
        category=category_val,
        status=status_val,
        search=search_val,
        page=page_val,
        page_size=page_size_val,
    )

    results = []
    for f in items:
        evidence_list = [
            EvidenceResponse(
                file_path=ev.file_path,
                line_start=ev.line_start,
                line_end=ev.line_end,
                code_snippet=ev.code_snippet,
            )
            for ev in f.evidence
        ]
        results.append(
            FindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                rule_id=f.rule_id,
                title=f.title,
                category=f.category,
                severity=f.severity,
                status=f.status,
                confidence=f.confidence or "high",
                detection_source=f.detection_source or "built-in",
                description=f.description,
                impact=f.impact,
                recommendation=f.recommendation,
                evidence=evidence_list,
            )
        )

    return PaginatedAllFindingsResponse(
        page=page_val,
        page_size=page_size_val,
        total_findings=total,
        items=results,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    repo = FindingRepository(db)
    f = repo.get_finding_by_id(finding_id)
    if not f:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    evidence_list = [
        EvidenceResponse(
            file_path=ev.file_path,
            line_start=ev.line_start,
            line_end=ev.line_end,
            code_snippet=ev.code_snippet,
        )
        for ev in f.evidence
    ]

    return FindingResponse(
        id=f.id,
        scan_id=f.scan_id,
        rule_id=f.rule_id,
        title=f.title,
        category=f.category,
        severity=f.severity,
        status=f.status,
        confidence=f.confidence or "high",
        detection_source=f.detection_source or "built-in",
        description=f.description,
        impact=f.impact,
        recommendation=f.recommendation,
        evidence=evidence_list,
    )


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding_status(
    finding_id: str,
    update_req: FindingStatusUpdateRequest,
    db: Session = Depends(get_db),
):
    repo = FindingRepository(db)
    valid_statuses = {"open", "confirmed", "false_positive", "resolved"}
    if update_req.status.lower() not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Status must be one of: {', '.join(valid_statuses)}",
        )

    updated = repo.update_finding_status(finding_id, update_req.status.lower())
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    evidence_list = [
        EvidenceResponse(
            file_path=ev.file_path,
            line_start=ev.line_start,
            line_end=ev.line_end,
            code_snippet=ev.code_snippet,
        )
        for ev in updated.evidence
    ]

    return FindingResponse(
        id=updated.id,
        scan_id=updated.scan_id,
        rule_id=updated.rule_id,
        title=updated.title,
        category=updated.category,
        severity=updated.severity,
        status=updated.status,
        confidence=updated.confidence or "high",
        detection_source=updated.detection_source or "built-in",
        description=updated.description,
        impact=updated.impact,
        recommendation=updated.recommendation,
        evidence=evidence_list,
    )
