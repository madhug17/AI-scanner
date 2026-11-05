from sqlalchemy.orm import Session
from scanner.database.models import ScanJobModel
from scanner.database.repositories import ScanJobRepository
from scanner.repository.github import validate_and_parse_github_url
from scanner.messaging.kafka_producer import kafka_producer, ScanKafkaProducer
from scanner.cache.redis_client import redis_client, RedisClient
from scanner.core.config import settings


class ScanService:
    def __init__(
        self,
        db: Session,
        producer: ScanKafkaProducer = kafka_producer,
        cache: RedisClient = redis_client,
    ):
        self.db = db
        self.job_repo = ScanJobRepository(db)
        self.producer = producer
        self.cache = cache

    def create_scan(self, repository_url: str) -> ScanJobModel:
        """Validate URL, create database job, and publish scan request to Kafka."""
        parsed = validate_and_parse_github_url(repository_url)
        
        job = self.job_repo.create_job(
            repository_url=parsed.url,
            repository_owner=parsed.owner,
            repository_name=parsed.name,
            scan_version=settings.scan_version,
        )

        # Publish event to Kafka
        self.producer.publish_scan_requested(
            scan_id=job.id,
            repository_url=parsed.url,
        )

        # Cache initial status
        self.cache.set(f"scan:{job.id}:status", "queued", ttl_seconds=settings.redis_scan_cache_ttl)

        return job

    def get_scan(self, scan_id: str) -> ScanJobModel | None:
        """Fetch scan job by ID."""
        return self.job_repo.get_job(scan_id)

    def cancel_scan(self, scan_id: str) -> bool:
        """Safely cancel a queued or running scan."""
        success = self.job_repo.cancel_job(scan_id)
        if success:
            self.cache.set(f"scan:{scan_id}:status", "cancelled", ttl_seconds=settings.redis_scan_cache_ttl)
        return success

    def list_scans(self, page: int = 1, page_size: int = 20) -> tuple[list[ScanJobModel], int]:
        items, total = self.job_repo.list_jobs(page=page, page_size=page_size)
        return list(items), total

