from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from scanner.database.session import get_db
from scanner.cache.redis_client import redis_client
from scanner.messaging.kafka_producer import kafka_producer
from scanner.core.config import settings
from scanner.core.registry import default_registry

router = APIRouter(tags=["Health"])


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

