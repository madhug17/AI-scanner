import json
from datetime import datetime, timezone
from typing import Sequence
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc

from scanner.database.models import (
    UserModel,
    RepositoryModel,
    ScanJobModel,
    FindingModel,
    EvidenceModel,
    ScanSummaryModel,
    ScanEventModel,
)
from scanner.core.finding import Finding
from scanner.core.scoring import RiskSummary


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_user(
        self,
        email: str,
        hashed_password: str,
        full_name: str | None = None,
        is_admin: bool = False,
    ) -> UserModel:
        user = UserModel(
            email=email.lower().strip(),
            hashed_password=hashed_password,
            full_name=full_name,
            is_admin=is_admin,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def get_by_email(self, email: str) -> UserModel | None:
        stmt = select(UserModel).where(UserModel.email == email.lower().strip())
        return self.db.execute(stmt).scalar_one_or_none()

    def get_by_id(self, user_id: str) -> UserModel | None:
        stmt = select(UserModel).where(UserModel.id == user_id)
        return self.db.execute(stmt).scalar_one_or_none()


class RepositoryRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_repository(
        self,
        url: str,
        owner: str,
        name: str,
        user_id: str | None = None,
        default_branch: str = "main",
        is_private: bool = False,
    ) -> RepositoryModel:
        existing = self.get_by_url(url)
        if existing:
            return existing

        repo = RepositoryModel(
            url=url,
            owner=owner,
            name=name,
            user_id=user_id,
            default_branch=default_branch,
            is_private=is_private,
            detected_languages="[]",
            detected_frameworks="[]",
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(repo)
        self.db.commit()
        self.db.refresh(repo)
        return repo

    def get_by_id(self, repo_id: str) -> RepositoryModel | None:
        stmt = select(RepositoryModel).where(RepositoryModel.id == repo_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def get_by_url(self, url: str) -> RepositoryModel | None:
        clean_url = url.strip().rstrip("/")
        stmt = select(RepositoryModel).where(RepositoryModel.url == clean_url)
        return self.db.execute(stmt).scalar_one_or_none()

    def list_repositories(
        self,
        user_id: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[Sequence[RepositoryModel], int]:
        query = select(RepositoryModel)
        if user_id:
            query = query.where(RepositoryModel.user_id == user_id)
        
        count_stmt = select(func.count()).select_from(query.subquery())
        total = self.db.execute(count_stmt).scalar_one()

        offset = max(0, (page - 1) * page_size)
        paginated_query = query.order_by(desc(RepositoryModel.created_at)).offset(offset).limit(page_size)
        items = self.db.execute(paginated_query).scalars().all()
        return items, total

    def update_metadata(
        self,
        repo_id: str,
        languages: list[str] | None = None,
        frameworks: list[str] | None = None,
    ) -> RepositoryModel | None:
        repo = self.get_by_id(repo_id)
        if not repo:
            return None
        if languages is not None:
            repo.detected_languages = json.dumps(languages)
        if frameworks is not None:
            repo.detected_frameworks = json.dumps(frameworks)
        self.db.commit()
        self.db.refresh(repo)
        return repo


class ScanJobRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_job(
        self,
        repository_url: str,
        repository_owner: str,
        repository_name: str,
        scan_version: str = "1.0.0",
        repository_id: str | None = None,
    ) -> ScanJobModel:
        job = ScanJobModel(
            repository_url=repository_url,
            repository_owner=repository_owner,
            repository_name=repository_name,
            repository_id=repository_id,
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
        repository_id: str | None = None,
    ) -> tuple[Sequence[ScanJobModel], int]:
        query = select(ScanJobModel)
        if repository_id:
            query = query.where(ScanJobModel.repository_id == repository_id)

        count_stmt = select(func.count()).select_from(query.subquery())
        total = self.db.execute(count_stmt).scalar_one()

        offset = max(0, (page - 1) * page_size)
        paginated_query = query.order_by(desc(ScanJobModel.created_at)).offset(offset).limit(page_size)
        items = self.db.execute(paginated_query).scalars().all()
        return items, total


class ScanEventRepository:
    def __init__(self, db: Session):
        self.db = db

    def record_event(
        self,
        scan_id: str,
        stage: str,
        status: str = "in_progress",
        message: str | None = None,
    ) -> ScanEventModel:
        event = ScanEventModel(
            scan_id=scan_id,
            stage=stage,
            status=status,
            message=message,
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event

    def get_events_for_scan(self, scan_id: str) -> list[ScanEventModel]:
        stmt = select(ScanEventModel).where(ScanEventModel.scan_id == scan_id).order_by(ScanEventModel.timestamp)
        return list(self.db.execute(stmt).scalars().all())


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
                confidence="high",
                detection_source="built-in",
                description=finding.description,
                impact=finding.impact,
                recommendation=finding.recommendation,
            )
            self.db.add(f_model)
            self.db.flush()

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

    def get_finding_by_id(self, finding_id: str) -> FindingModel | None:
        stmt = select(FindingModel).where(FindingModel.id == finding_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def update_finding_status(self, finding_id: str, status: str) -> FindingModel | None:
        finding = self.get_finding_by_id(finding_id)
        if not finding:
            return None
        finding.status = status
        self.db.commit()
        self.db.refresh(finding)
        return finding

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

    def list_all_findings(
        self,
        severity: str | None = None,
        category: str | None = None,
        status: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[Sequence[FindingModel], int]:
        query = select(FindingModel)

        if severity and isinstance(severity, str):
            query = query.where(FindingModel.severity == severity.lower())
        if category and isinstance(category, str):
            query = query.where(FindingModel.category == category)
        if status and isinstance(status, str):
            query = query.where(FindingModel.status == status.lower())
        if search and isinstance(search, str):
            term = f"%{search}%"
            query = query.where((FindingModel.title.ilike(term)) | (FindingModel.description.ilike(term)))

        count_stmt = select(func.count()).select_from(query.subquery())
        total = self.db.execute(count_stmt).scalar_one()

        offset = max(0, (page - 1) * page_size)
        paginated_query = query.order_by(desc(FindingModel.id)).offset(offset).limit(page_size)
        items = self.db.execute(paginated_query).scalars().all()
        return items, total

    def compare_scans(self, scan_id_a: str, scan_id_b: str) -> dict:
        """Compare two scans (scan A as baseline, scan B as target/recent)."""
        findings_a = list(self.db.execute(
            select(FindingModel).where(FindingModel.scan_id == scan_id_a)
        ).scalars().all())

        findings_b = list(self.db.execute(
            select(FindingModel).where(FindingModel.scan_id == scan_id_b)
        ).scalars().all())

        def finding_fingerprint(f: FindingModel) -> str:
            # Match by rule_id and title (and first evidence path if available)
            ev_path = f.evidence[0].file_path if f.evidence else ""
            return f"{f.rule_id}::{f.title}::{ev_path}"

        map_a = {finding_fingerprint(f): f for f in findings_a}
        map_b = {finding_fingerprint(f): f for f in findings_b}

        keys_a = set(map_a.keys())
        keys_b = set(map_b.keys())

        new_keys = keys_b - keys_a
        resolved_keys = keys_a - keys_b
        persistent_keys = keys_a & keys_b

        return {
            "baseline_scan_id": scan_id_a,
            "target_scan_id": scan_id_b,
            "new_count": len(new_keys),
            "resolved_count": len(resolved_keys),
            "persistent_count": len(persistent_keys),
            "new_findings": [map_b[k] for k in new_keys],
            "resolved_findings": [map_a[k] for k in resolved_keys],
            "persistent_findings": [map_b[k] for k in persistent_keys],
        }


class ScanSummaryRepository:
    def __init__(self, db: Session):
        self.db = db

    def save_summary(
        self,
        scan_id: str,
        summary: RiskSummary,
    ) -> ScanSummaryModel:
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
