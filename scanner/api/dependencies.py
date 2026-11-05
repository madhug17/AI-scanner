from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from scanner.database.session import get_db
from scanner.cache.redis_client import redis_client, RedisClient
from scanner.messaging.kafka_producer import kafka_producer, ScanKafkaProducer
from scanner.core.config import settings


def get_redis() -> RedisClient:
    return redis_client


def get_kafka() -> ScanKafkaProducer:
    return kafka_producer


def rate_limit_dependency(
    request: Request,
    redis: RedisClient = Depends(get_redis),
):
    """Enforce per-client IP rate limits using Redis sliding window."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    is_allowed, remaining = redis.check_rate_limit(
        identifier=f"ip:{client_ip}",
        max_requests=settings.redis_rate_limit_per_minute,
        window_seconds=60,
    )
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="API rate limit exceeded. Please try again later.",
            headers={"Retry-After": "60"},
        )

