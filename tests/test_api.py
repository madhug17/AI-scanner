import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scanner.database.models import Base
from scanner.database.repositories import ScanJobRepository, FindingRepository, ScanSummaryRepository
from scanner.core.finding import Finding, Evidence, Severity, FindingStatus
from scanner.core.scoring import RiskSummary

from scanner.api.routes.health import get_health
from scanner.api.routes.scans import (
    create_scan,
    get_scan_status,
    cancel_scan,
    list_scans,
    ScanRequest,
)
from scanner.api.routes.reports import get_scan_findings, get_scan_report


@pytest.fixture
def api_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        yield db
    finally:
        db.close()


def test_health_endpoint(api_db):
    result = get_health(db=api_db)
    assert result["status"] == "healthy"
    assert result["version"] == "1.0.0"
    assert result["components"]["database"] == "connected"
    assert result["components"]["scanner_engine"]["rules_loaded"] == 52


def test_create_scan_valid_and_invalid(api_db):
    # Valid submission
    req = ScanRequest(repository_url="https://github.com/fastapi/fastapi")
    resp = create_scan(request=req, db=api_db)
    assert resp.status == "queued"
    assert resp.message == "Scan job accepted"
    assert resp.scan_id is not None

    # Invalid URL scheme
    bad_req = ScanRequest(repository_url="http://insecure.com/repo")
    with pytest.raises(HTTPException) as exc_info:
        create_scan(request=bad_req, db=api_db)
    assert exc_info.value.status_code == 400

    # Non-github host
    non_gh_req = ScanRequest(repository_url="https://gitlab.com/owner/repo")
    with pytest.raises(HTTPException) as exc_info2:
        create_scan(request=non_gh_req, db=api_db)
    assert exc_info2.value.status_code == 400


def test_get_scan_status_and_cancel(api_db):
    req = ScanRequest(repository_url="https://github.com/owner/sample-repo")
    create_resp = create_scan(request=req, db=api_db)
    scan_id = create_resp.scan_id

    # Fetch status
    status_resp = get_scan_status(scan_id=scan_id, db=api_db)
    assert status_resp.scan_id == scan_id
    assert status_resp.status == "queued"
    assert status_resp.repository_owner == "owner"

    # Cancel scan
    cancel_res = cancel_scan(scan_id=scan_id, db=api_db)
    assert cancel_res["status"] == "cancelled"

    # Cancel already cancelled scan raises 400
    with pytest.raises(HTTPException) as exc_info:
        cancel_scan(scan_id=scan_id, db=api_db)
    assert exc_info.value.status_code == 400


def test_get_scan_findings_and_report(api_db):
    # Seed a completed scan with findings and summary
    job_repo = ScanJobRepository(api_db)
    job = job_repo.create_job("https://github.com/owner/report-test", "owner", "report-test")
    job_repo.update_status(job.id, status="completed")

    findings = [
        Finding(
            rule_id="SEC-008",
            title="SQL Injection",
            category="Injection",
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            description="SQL Injection detected",
            impact="Data exposure",
            recommendation="Use parameterized queries",
            evidence=[Evidence(file_path="main.py", line_start=5, line_end=5, code_snippet="cursor.execute(f'...')")],
        )
    ]
    FindingRepository(api_db).save_findings_for_scan(job.id, findings)
    ScanSummaryRepository(api_db).save_summary(
        job.id,
        RiskSummary(risk_score=20.0, risk_category="Low", critical_count=1, scan_complete=True),
    )

    # Fetch findings with severity filter
    f_res = get_scan_findings(scan_id=job.id, severity="critical", db=api_db)
    assert f_res.total_findings == 1
    assert f_res.items[0].rule_id == "SEC-008"

    # Fetch full report
    rep = get_scan_report(scan_id=job.id, db=api_db)
    assert rep.scan_id == job.id
    assert rep.status == "completed"
    assert rep.summary.risk_score == 20.0
    assert len(rep.findings) == 1


def test_list_scans_history(api_db):
    req1 = ScanRequest(repository_url="https://github.com/owner/repo1")
    req2 = ScanRequest(repository_url="https://github.com/owner/repo2")
    create_scan(request=req1, db=api_db)
    create_scan(request=req2, db=api_db)

    history = list_scans(page=1, page_size=10, db=api_db)
    assert history.total_scans >= 2
    assert len(history.items) >= 2
