import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scanner.database.models import Base, ScanJobModel, FindingModel
from scanner.database.repositories import ScanJobRepository, FindingRepository, ScanSummaryRepository
from scanner.core.finding import Finding, Evidence, Severity, FindingStatus
from scanner.core.scoring import RiskSummary


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        yield db
    finally:
        db.close()


def test_scan_job_crud_and_status(test_db):
    repo = ScanJobRepository(test_db)
    job = repo.create_job(
        repository_url="https://github.com/fastapi/fastapi",
        repository_owner="fastapi",
        repository_name="fastapi",
    )
    assert job.id is not None
    assert job.status == "queued"

    # Update status
    updated = repo.update_status(job.id, status="scanning")
    assert updated.status == "scanning"

    # Cancellation
    assert repo.cancel_job(job.id) is True
    assert repo.get_job(job.id).status == "cancelled"

    # Attempting to cancel already cancelled job returns False
    assert repo.cancel_job(job.id) is False


def test_findings_persistence_and_filtering(test_db):
    job_repo = ScanJobRepository(test_db)
    finding_repo = FindingRepository(test_db)

    job = job_repo.create_job("https://github.com/org/repo", "org", "repo")

    findings = [
        Finding(
            rule_id="SEC-008",
            title="SQLi",
            category="Injection",
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            description="desc",
            impact="impact",
            recommendation="fix",
            evidence=[Evidence(file_path="db.py", line_start=1, line_end=2, code_snippet="SELECT *")],
        ),
        Finding(
            rule_id="SEC-001",
            title="No Auth",
            category="Authentication",
            severity=Severity.MEDIUM,
            status=FindingStatus.NEEDS_VERIFICATION,
            description="desc",
            impact="impact",
            recommendation="fix",
            evidence=[Evidence(file_path="api.py", line_start=10, line_end=10, code_snippet="@app.get")],
        ),
    ]

    finding_repo.save_findings_for_scan(job.id, findings)

    # Filter by severity
    crit_items, crit_total = finding_repo.get_findings_for_scan(job.id, severity="critical")
    assert crit_total == 1
    assert crit_items[0].rule_id == "SEC-008"

    # Filter by category
    auth_items, auth_total = finding_repo.get_findings_for_scan(job.id, category="Authentication")
    assert auth_total == 1
    assert auth_items[0].rule_id == "SEC-001"


def test_scan_summary_persistence(test_db):
    job_repo = ScanJobRepository(test_db)
    summary_repo = ScanSummaryRepository(test_db)

    job = job_repo.create_job("https://github.com/org/repo", "org", "repo")
    summary = RiskSummary(
        risk_score=75.5,
        risk_category="High",
        critical_count=2,
        high_count=3,
        scan_complete=True,
    )

    summary_repo.save_summary(job.id, summary)
    fetched = summary_repo.get_summary(job.id)
    assert fetched is not None
    assert fetched.risk_score == 75.5
    assert fetched.critical_count == 2

