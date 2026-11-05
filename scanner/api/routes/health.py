from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import text, select, func
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, Counter, Histogram

from scanner.database.session import get_db
from scanner.database.models import ScanJobModel, FindingModel, RepositoryModel
from scanner.cache.redis_client import redis_client
from scanner.messaging.kafka_producer import kafka_producer
from scanner.core.config import settings
from scanner.core.registry import default_registry

router = APIRouter(tags=["System & Metrics"])

# Prometheus Metrics
SCAN_REQUESTS_TOTAL = Counter("scanner_scans_total", "Total scan requests created", ["status"])
FINDINGS_TOTAL = Counter("scanner_findings_total", "Total findings discovered", ["severity", "category"])
SCAN_DURATION_SECONDS = Histogram("scanner_scan_duration_seconds", "Scan duration in seconds")


@router.get("/health")
def get_health(db: Session = Depends(get_db)):
    """Health check for backend API, Database, Redis, Kafka, and Scanner Engine."""
    db_healthy = False
    try:
        db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception:
        db_healthy = False

    redis_healthy = redis_client.is_healthy()
    kafka_healthy = kafka_producer.is_healthy()

    overall_status = "healthy" if db_healthy else "degraded"

    return {
        "status": overall_status,
        "app_name": settings.app_name,
        "version": settings.scan_version,
        "components": {
            "database": "connected" if db_healthy else "unavailable",
            "redis": "connected" if redis_healthy else "in-memory fallback",
            "kafka": "connected" if kafka_healthy else "in-memory fallback",
            "scanner_engine": {
                "status": "ready",
                "rules_loaded": default_registry.count(),
            },
        },
    }


@router.get("/ready")
def get_readiness(db: Session = Depends(get_db)):
    """Kubernetes readiness probe."""
    try:
        db.execute(text("SELECT 1"))
        return {"ready": True}
    except Exception as e:
        return Response(content=f'{{"ready": false, "error": "{str(e)}"}}', media_type="application/json", status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


@router.get("/metrics")
def get_prometheus_metrics():
    """Prometheus exposition endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@router.get("/rules")
@router.get("/api/v1/rules")
def get_all_rules():
    """Return catalog of all supported security and quality rules."""
    rules = default_registry.get_all_rules()
    rule_list = []
    for r in rules:
        rule_list.append({
            "id": r.rule_id,
            "title": r.title,
            "category": r.category,
            "severity": r.severity.value,
            "description": r.description,
            "recommendation": r.recommendation,
            "enabled": True,
        })
    return {"total_rules": len(rule_list), "rules": rule_list}


@router.get("/api/v1/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Return live dashboard statistics computed from real PostgreSQL data."""
    total_scans = db.execute(select(func.count(ScanJobModel.id))).scalar_one()
    total_repos = db.execute(select(func.count(func.distinct(ScanJobModel.repository_url)))).scalar_one()
    
    # Completed / Failed stats
    completed_scans = db.execute(
        select(func.count(ScanJobModel.id)).where(ScanJobModel.status == "completed")
    ).scalar_one()
    failed_scans = db.execute(
        select(func.count(ScanJobModel.id)).where(ScanJobModel.status == "failed")
    ).scalar_one()

    # Total findings
    total_findings = db.execute(select(func.count(FindingModel.id))).scalar_one()

    # Severity distribution
    severity_rows = db.execute(
        select(FindingModel.severity, func.count(FindingModel.id)).group_by(FindingModel.severity)
    ).all()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in severity_rows:
        if sev in severity_counts:
            severity_counts[sev] = cnt

    # Category distribution
    cat_rows = db.execute(
        select(FindingModel.category, func.count(FindingModel.id)).group_by(FindingModel.category)
    ).all()
    category_counts = {cat: cnt for cat, cnt in cat_rows}

    # Recent scans
    recent_jobs = db.execute(
        select(ScanJobModel).order_by(ScanJobModel.created_at.desc()).limit(10)
    ).scalars().all()

    recent_activity = []
    for j in recent_jobs:
        score = j.summary.risk_score if j.summary else 0.0
        cat = j.summary.risk_category if j.summary else "Unknown"
        recent_activity.append({
            "scan_id": j.id,
            "repository_url": j.repository_url,
            "repository_name": j.repository_name,
            "status": j.status,
            "risk_score": score,
            "risk_category": cat,
            "findings_count": len(j.findings),
            "created_at": j.created_at.isoformat(),
        })

    return {
        "total_repositories": total_repos,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "success_rate_pct": round((completed_scans / total_scans * 100.0), 1) if total_scans > 0 else 100.0,
        "total_vulnerabilities": total_findings,
        "severity_distribution": severity_counts,
        "category_distribution": category_counts,
        "recent_scans": recent_activity,
    }
