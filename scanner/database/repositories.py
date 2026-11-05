from datetime import datetime, timezone
from typing import Sequence
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc

from scanner.database.models import ScanJobModel, FindingModel, EvidenceModel, ScanSummaryModel
from scanner.core.finding import Finding
from scanner.core.scoring import RiskSummary


class ScanJobRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_job(
        self,
        repository_url: str,
        repository_owner: str,
        repository_name: str,
        scan_version: str = "1.0.0",
    ) -> ScanJobModel:
        job = ScanJobModel(
            repository_url=repository_url,
            repository_owner=repository_owner,
            repository_name=repository_name,
            status="queued",
            created_at=datetime.now(timezone.utc),
            scan_version=scan_version,
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)
        return job

    def get_job(self, scan_id: str) -> ScanJobModel | None:
        stmt = select(ScanJobModel).where(ScanJobModel.id == scan_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def update_status(
        self,
        scan_id: str,
        status: str,
        error_message: str | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> ScanJobModel | None:
        job = self.get_job(scan_id)
        if not job:
            return None
        job.status = status
        if error_message is not None:
            job.error_message = error_message
        if started_at is not None:
            job.started_at = started_at
        if completed_at is not None:
            job.completed_at = completed_at
        self.db.commit()
        self.db.refresh(job)
        return job

    def cancel_job(self, scan_id: str) -> bool:
        job = self.get_job(scan_id)
        if not job:
            return False
        if job.status in {"completed", "failed", "cancelled"}:
            return False
        job.status = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
        self.db.commit()
        return True

    def list_jobs(
        self,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[Sequence[ScanJobModel], int]:
        total_stmt = select(func.count(ScanJobModel.id))
        total = self.db.execute(total_stmt).scalar_one()

        offset = max(0, (page - 1) * page_size)
        stmt = (
            select(ScanJobModel)
            .order_by(desc(ScanJobModel.created_at))
            .offset(offset)
            .limit(page_size)
        )
        items = self.db.execute(stmt).scalars().all()
        return items, total


class FindingRepository:
    def __init__(self, db: Session):
        self.db = db

    def save_findings_for_scan(
        self,
        scan_id: str,
        findings: list[Finding],
    ) -> list[FindingModel]:
        # Delete existing findings if any (idempotency support)
        existing = self.db.execute(
            select(FindingModel).where(FindingModel.scan_id == scan_id)
        ).scalars().all()
        for f in existing:
            self.db.delete(f)

        saved_models: list[FindingModel] = []
        for finding in findings:
            f_model = FindingModel(
                scan_id=scan_id,
                rule_id=finding.rule_id,
                title=finding.title,
                category=finding.category,
                severity=finding.severity.value,
                status=finding.status.value,
                description=finding.description,
                impact=finding.impact,
                recommendation=finding.recommendation,
            )
            self.db.add(f_model)
            self.db.flush()  # assign f_model.id

            for ev in finding.evidence:
                ev_model = EvidenceModel(
                    finding_id=f_model.id,
                    file_path=ev.file_path,
                    line_start=ev.line_start,
                    line_end=ev.line_end,
                    code_snippet=ev.code_snippet,
                )
                self.db.add(ev_model)

            saved_models.append(f_model)

        self.db.commit()
        return saved_models

    def get_findings_for_scan(
        self,
        scan_id: str,
        severity: str | None = None,
        category: str | None = None,
        rule_id: str | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[Sequence[FindingModel], int]:
        query = select(FindingModel).where(FindingModel.scan_id == scan_id)

        if severity and isinstance(severity, str):
            query = query.where(FindingModel.severity == severity.lower())
        if category and isinstance(category, str):
            query = query.where(FindingModel.category == category)
        if rule_id and isinstance(rule_id, str):
            query = query.where(FindingModel.rule_id == rule_id.upper())
        if status and isinstance(status, str):
            query = query.where(FindingModel.status == status.lower())

        count_stmt = select(func.count()).select_from(query.subquery())
        total = self.db.execute(count_stmt).scalar_one()

        offset = max(0, (page - 1) * page_size)
        paginated_query = query.order_by(FindingModel.id).offset(offset).limit(page_size)
        items = self.db.execute(paginated_query).scalars().all()
        return items, total


class ScanSummaryRepository:
    def __init__(self, db: Session):
        self.db = db

    def save_summary(
        self,
        scan_id: str,
        summary: RiskSummary,
    ) -> ScanSummaryModel:
        # Check existing summary
        existing = self.db.execute(
            select(ScanSummaryModel).where(ScanSummaryModel.scan_id == scan_id)
        ).scalar_one_or_none()

        if existing:
            self.db.delete(existing)
            self.db.flush()

        model = ScanSummaryModel(
            scan_id=scan_id,
            risk_score=summary.risk_score,
            risk_category=summary.risk_category,
            critical_count=summary.critical_count,
            high_count=summary.high_count,
            medium_count=summary.medium_count,
            low_count=summary.low_count,
            info_count=summary.info_count,
            scan_complete=summary.scan_complete,
        )
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        return model

    def get_summary(self, scan_id: str) -> ScanSummaryModel | None:
        stmt = select(ScanSummaryModel).where(ScanSummaryModel.scan_id == scan_id)
        return self.db.execute(stmt).scalar_one_or_none()
