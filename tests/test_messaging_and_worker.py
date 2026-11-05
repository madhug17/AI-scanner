import tempfile
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scanner.database.models import Base
from scanner.database.repositories import ScanJobRepository, FindingRepository
from scanner.messaging.kafka_producer import ScanKafkaProducer
from scanner.workers.scan_worker import ScanWorker
from scanner.workers.kafka_consumer import ScanKafkaConsumer
from scanner.core.engine import SecurityEngine


@pytest.fixture
def memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session


def test_kafka_producer_event_generation():
    producer = ScanKafkaProducer(bootstrap_servers="localhost:9092")
    published = producer.publish_scan_requested(
        scan_id="test-scan-uuid",
        repository_url="https://github.com/owner/repo",
    )
    assert published is True
    assert len(producer.published_events) == 1
    event = producer.published_events[0]
    assert event["event_type"] == "scan.requested"
    assert event["scan_id"] == "test-scan-uuid"


def test_scan_worker_execution_and_idempotency(memory_db):
    db = memory_db()
    job_repo = ScanJobRepository(db)
    job = job_repo.create_job(
        repository_url="https://github.com/fastapi/fastapi",
        repository_owner="fastapi",
        repository_name="fastapi",
    )
    db.close()

    worker = ScanWorker(engine=SecurityEngine(rules=[]), db_factory=memory_db)

    with tempfile.TemporaryDirectory() as tmp_dir:
        repo_dir = Path(tmp_dir)
        (repo_dir / "app.py").write_text("print('test')", encoding="utf-8")

        # 1. First run processes and completes
        success = worker.process_scan_job(
            scan_id=job.id,
            repository_url=job.repository_url,
            local_repo_override=repo_dir,
        )
        assert success is True

        db2 = memory_db()
        updated_job = ScanJobRepository(db2).get_job(job.id)
        assert updated_job.status == "completed"
        db2.close()

        # 2. Duplicate event received (Idempotency test):
        # Should return True without re-running or raising errors
        duplicate_success = worker.process_scan_job(
            scan_id=job.id,
            repository_url=job.repository_url,
            local_repo_override=repo_dir,
        )
        assert duplicate_success is True


def test_kafka_consumer_retry_and_deadletter(memory_db):
    consumer = ScanKafkaConsumer(max_retries=2)
    # Message with non-existent job ID will fail
    msg = {"scan_id": "nonexistent-job", "repository_url": "https://github.com/owner/repo"}

    # Attempt 1 -> fails
    res1 = consumer.process_message(msg)
    assert res1 is False

    # Attempt 2 -> hits max_retries and goes to deadletter
    res2 = consumer.process_message(msg)
    assert res2 is False
    assert len(consumer.deadletter_events) == 1

