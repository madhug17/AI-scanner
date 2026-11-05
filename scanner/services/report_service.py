from typing import Any
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from scanner.database.repositories import ScanJobRepository, FindingRepository, ScanSummaryRepository
from scanner.core.finding import Finding, Evidence, Severity, FindingStatus
from scanner.core.scoring import RiskSummary
from scanner.cache.redis_client import redis_client, RedisClient
from scanner.core.config import settings


class PaginatedFindingsResponse(BaseModel):
    scan_id: str
    page: int
    page_size: int
    total_findings: int
    items: list[Finding]


class ScanReportResponse(BaseModel):
    scan_id: str
    repository_url: str
    repository_owner: str
    repository_name: str
    status: str
    created_at: str | None
    started_at: str | None
    completed_at: str | None
    error_message: str | None
    scan_version: str
    summary: RiskSummary | None
    findings: list[Finding]


class ReportService:
    def __init__(self, db: Session):
        self.db = db
        self.job_repo = ScanJobRepository(db)
        self.finding_repo = FindingRepository(db)
        self.summary_repo = ScanSummaryRepository(db)

    def get_findings_paginated(
        self,
        scan_id: str,
        severity: str | None = None,
        category: str | None = None,
        rule_id: str | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PaginatedFindingsResponse:
        models, total = self.finding_repo.get_findings_for_scan(
            scan_id=scan_id,
            severity=severity,
            category=category,
            rule_id=rule_id,
            status=status,
            page=page,
            page_size=page_size,
        )

        pydantic_findings: list[Finding] = []
        for m in models:
            evidences = [
                Evidence(
                    file_path=ev.file_path,
                    line_start=ev.line_start,
                    line_end=ev.line_end,
                    code_snippet=ev.code_snippet,
                )
                for ev in m.evidence
            ]
            pydantic_findings.append(
                Finding(
                    rule_id=m.rule_id,
                    title=m.title,
                    category=m.category,
                    severity=Severity(m.severity),
                    status=FindingStatus(m.status),
                    description=m.description,
                    impact=m.impact,
                    recommendation=m.recommendation,
                    evidence=evidences,
                )
            )

        return PaginatedFindingsResponse(
            scan_id=scan_id,
            page=page,
            page_size=page_size,
            total_findings=total,
            items=pydantic_findings,
        )

    def get_complete_report(self, scan_id: str, bypass_cache: bool = False) -> ScanReportResponse | None:
        cache_key = f"scan:{scan_id}:report"
        if not bypass_cache:
            cached_json = redis_client.get(cache_key)
            if cached_json:
                try:
                    return ScanReportResponse.model_validate_json(cached_json)
                except Exception:
                    pass

        job = self.job_repo.get_job(scan_id)
        if not job:
            return None

        # Fetch all findings
        models, _ = self.finding_repo.get_findings_for_scan(
            scan_id=scan_id,
            page=1,
            page_size=10000,
        )
        findings: list[Finding] = []
        for m in models:
            evidences = [
                Evidence(
                    file_path=ev.file_path,
                    line_start=ev.line_start,
                    line_end=ev.line_end,
                    code_snippet=ev.code_snippet,
                )
                for ev in m.evidence
            ]
            findings.append(
                Finding(
                    rule_id=m.rule_id,
                    title=m.title,
                    category=m.category,
                    severity=Severity(m.severity),
                    status=FindingStatus(m.status),
                    description=m.description,
                    impact=m.impact,
                    recommendation=m.recommendation,
                    evidence=evidences,
                )
            )

        summary_model = self.summary_repo.get_summary(scan_id)
        summary = None
        if summary_model:
            summary = RiskSummary(
                risk_score=summary_model.risk_score,
                risk_category=summary_model.risk_category,
                critical_count=summary_model.critical_count,
                high_count=summary_model.high_count,
                medium_count=summary_model.medium_count,
                low_count=summary_model.low_count,
                info_count=summary_model.info_count,
                scan_complete=summary_model.scan_complete,
            )

        report = ScanReportResponse(
            scan_id=job.id,
            repository_url=job.repository_url,
            repository_owner=job.repository_owner,
            repository_name=job.repository_name,
            status=job.status,
            created_at=job.created_at.isoformat() if job.created_at else None,
            started_at=job.started_at.isoformat() if job.started_at else None,
            completed_at=job.completed_at.isoformat() if job.completed_at else None,
            error_message=job.error_message,
            scan_version=job.scan_version,
            summary=summary,
            findings=findings,
        )

        if not bypass_cache and job.status in {"completed", "failed", "cancelled"}:
            redis_client.set(cache_key, report.model_dump_json(), ttl_seconds=settings.redis_scan_cache_ttl)

        return report

