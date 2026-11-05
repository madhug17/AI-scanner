import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi import HTTPException

from scanner.database.models import Base
from scanner.database.repositories import ScanJobRepository, FindingRepository, ScanSummaryRepository
from scanner.core.finding import Finding, Evidence, Severity, FindingStatus
from scanner.core.scoring import RiskSummary

from scanner.api.routes.auth import register_user, login_user, get_user_profile, RegisterRequest, LoginRequest
from scanner.api.routes.repositories import create_repository, list_repositories, get_repository_details, RepositoryCreateRequest
from scanner.api.routes.findings import list_all_findings, get_finding, update_finding_status, FindingStatusUpdateRequest
from scanner.api.routes.health import get_readiness, get_prometheus_metrics, get_all_rules, get_dashboard_stats
from scanner.api.routes.reports import download_scan_report_pdf, compare_two_scans


@pytest.fixture
def ext_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        yield db
    finally:
        db.close()


def test_auth_workflow(ext_db):
    # Register
    reg_req = RegisterRequest(email="tester@example.com", password="SecretPassword123!", full_name="Test Dev")
    res = register_user(request=reg_req, db=ext_db)
    assert res.access_token is not None
    assert res.user["email"] == "tester@example.com"

    # Login
    login_req = LoginRequest(email="tester@example.com", password="SecretPassword123!")
    login_res = login_user(request=login_req, db=ext_db)
    assert login_res.access_token is not None

    # Invalid login
    with pytest.raises(HTTPException):
        login_user(request=LoginRequest(email="tester@example.com", password="WrongPassword"), db=ext_db)


def test_repositories_endpoints(ext_db):
    req = RepositoryCreateRequest(repository_url="https://github.com/pallets/flask", default_branch="main")
    repo = create_repository(request=req, current_user=None, db=ext_db)
    assert repo.owner == "pallets"
    assert repo.name == "flask"

    # List
    listing = list_repositories(page=1, page_size=10, current_user=None, db=ext_db)
    assert listing.total_repositories >= 1
    assert any(r.name == "flask" for r in listing.items)

    # Details
    details = get_repository_details(id=repo.id, db=ext_db)
    assert details.id == repo.id


def test_findings_and_patch(ext_db):
    # Seed job & finding
    job_repo = ScanJobRepository(ext_db)
    job = job_repo.create_job("https://github.com/test/repo", "test", "repo")

    finding_repo = FindingRepository(ext_db)
    f = Finding(
        rule_id="SEC-008",
        title="SQL Injection in auth handler",
        category="Injection",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        description="F-string SQL",
        impact="DB breach",
        recommendation="Use parameterized queries",
        evidence=[Evidence(file_path="app.py", line_start=10, line_end=12, code_snippet="SELECT *")]
    )
    saved = finding_repo.save_findings_for_scan(job.id, [f])
    finding_id = saved[0].id

    # List all findings
    all_f = list_all_findings(db=ext_db)
    assert all_f.total_findings >= 1

    # Get single finding
    retrieved = get_finding(finding_id=finding_id, db=ext_db)
    assert retrieved.rule_id == "SEC-008"

    # Patch finding status
    patch_req = FindingStatusUpdateRequest(status="false_positive")
    patched = update_finding_status(finding_id=finding_id, update_req=patch_req, db=ext_db)
    assert patched.status == "false_positive"


def test_system_and_stats_endpoints(ext_db):
    # Readiness probe
    ready = get_readiness(db=ext_db)
    assert ready["ready"] is True

    # Prometheus metrics
    metrics_resp = get_prometheus_metrics()
    assert metrics_resp.status_code == 200
    assert len(metrics_resp.body) > 0

    # Rules catalog
    rules_resp = get_all_rules()
    assert rules_resp["total_rules"] == 52
    assert any(r["id"] == "SEC-008" for r in rules_resp["rules"])

    # Dashboard stats
    stats_resp = get_dashboard_stats(db=ext_db)
    assert "total_repositories" in stats_resp
    assert "total_scans" in stats_resp
    assert "severity_distribution" in stats_resp


def test_pdf_report_and_scan_comparison(ext_db):
    job_repo = ScanJobRepository(ext_db)
    job_a = job_repo.create_job("https://github.com/test/scan-a", "test", "scan-a")
    job_b = job_repo.create_job("https://github.com/test/scan-b", "test", "scan-b")

    summary_repo = ScanSummaryRepository(ext_db)
    summary_repo.save_summary(job_a.id, RiskSummary(
        risk_score=40.0,
        risk_category="Medium",
        critical_count=0,
        high_count=2,
        medium_count=4,
        low_count=0,
        info_count=0,
        scan_complete=True,
    ))
    summary_repo.save_summary(job_b.id, RiskSummary(
        risk_score=75.0,
        risk_category="Critical",
        critical_count=2,
        high_count=3,
        medium_count=4,
        low_count=0,
        info_count=0,
        scan_complete=True,
    ))

    # PDF Download
    pdf_resp = download_scan_report_pdf(scan_id=job_a.id, db=ext_db)
    assert pdf_resp.status_code == 200
    assert pdf_resp.media_type == "application/pdf"
    assert len(pdf_resp.body) > 1000

    # Comparison
    diff = compare_two_scans(scan_id=job_a.id, target_scan_id=job_b.id, db=ext_db)
    assert diff["baseline_scan_id"] == job_a.id
    assert diff["target_scan_id"] == job_b.id
    assert diff["risk_score_delta"] == 35.0
