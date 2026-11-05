import time
import tempfile
from pathlib import Path
from typing import Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scanner.database.models import Base
from scanner.database.repositories import ScanJobRepository, FindingRepository, ScanSummaryRepository
from scanner.services.scan_service import ScanService
from scanner.workers.scan_worker import ScanWorker
from scanner.workers.kafka_consumer import ScanKafkaConsumer
from scanner.messaging.kafka_producer import ScanKafkaProducer
from scanner.core.engine import SecurityEngine
from scanner.benchmarks.metrics import calculate_latency_stats, calculate_reduction_pct, ResourceMonitor


class KafkaBenchmark:
    """Benchmark comparing synchronous request handling against asynchronous Kafka job processing."""

    def __init__(self, iterations: int = 15):
        self.iterations = iterations
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.sample_repo_path: Path | None = None
        self._setup_sample_repo()

    def _setup_sample_repo(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sample_repo_path = Path(self.temp_dir.name)
        # Create a sample multi-file codebase
        (self.sample_repo_path / "app.py").write_text(
            "import os\nos.system('echo hi')\ncursor.execute(f'SELECT * FROM users WHERE id={uid}')\n",
            encoding="utf-8"
        )
        (self.sample_repo_path / "auth.py").write_text(
            "token = jwt.decode(t, options={'verify_signature': False})\napi_key = 'sk-live_1234567890123456'\n",
            encoding="utf-8"
        )
        (self.sample_repo_path / "routes.py").write_text(
            "@app.get('/unauth')\ndef route(): return {'ok': True}\n",
            encoding="utf-8"
        )

    def run_all(self) -> dict[str, Any]:
        monitor = ResourceMonitor()
        monitor.start()

        sync_results = self.benchmark_synchronous_flow()
        async_results = self.benchmark_asynchronous_flow()

        submission_reduction = calculate_reduction_pct(
            sync_results["api_submission_latency"]["avg_ms"],
            async_results["api_submission_latency"]["avg_ms"],
        )

        return {
            "synchronous_baseline": sync_results,
            "asynchronous_kafka": async_results,
            "comparison": {
                "sync_api_response_avg_ms": sync_results["api_submission_latency"]["avg_ms"],
                "async_api_response_avg_ms": async_results["api_submission_latency"]["avg_ms"],
                "api_latency_reduction_pct": submission_reduction,
                "sync_total_completion_avg_ms": sync_results["total_scan_duration"]["avg_ms"],
                "async_total_completion_avg_ms": async_results["total_scan_duration"]["avg_ms"],
                "queue_waiting_time_avg_ms": async_results["queue_waiting_time"]["avg_ms"],
                "worker_processing_time_avg_ms": async_results["worker_processing_time"]["avg_ms"],
                "resource_usage": monitor.sample().model_dump(),
            },
        }

    def benchmark_synchronous_flow(self) -> dict[str, Any]:
        """Measure synchronous flow where the API request directly blocks on scanning."""
        latencies_submission = []
        scan_durations = []
        db_persist_durations = []

        scanner = SecurityEngine()

        for _ in range(self.iterations):
            t_total_start = time.perf_counter()

            # 1. Job created in DB
            db = self.SessionLocal()
            job_repo = ScanJobRepository(db)
            finding_repo = FindingRepository(db)
            summary_repo = ScanSummaryRepository(db)
            job = job_repo.create_job("https://github.com/sync/repo", "sync", "repo")

            # 2. Synchronous engine scan
            t_scan_start = time.perf_counter()
            scan_res = scanner.execute_scan(self.sample_repo_path, run_external_tools=False)
            scan_ms = (time.perf_counter() - t_scan_start) * 1000.0
            scan_durations.append(scan_ms)

            # 3. Synchronous persistence
            t_persist_start = time.perf_counter()
            finding_repo.save_findings_for_scan(job.id, scan_res.findings)
            if scan_res.summary:
                summary_repo.save_summary(job.id, scan_res.summary)
            job_repo.update_status(job.id, status="completed")
            db_persist_ms = (time.perf_counter() - t_persist_start) * 1000.0
            db_persist_durations.append(db_persist_ms)

            # 4. Total API block time
            total_ms = (time.perf_counter() - t_total_start) * 1000.0
            latencies_submission.append(total_ms)
            db.close()

        return {
            "flow_type": "Synchronous (API blocks for scan & persistence)",
            "iterations": self.iterations,
            "api_submission_latency": calculate_latency_stats(latencies_submission),
            "scan_execution_duration": calculate_latency_stats(scan_durations),
            "persistence_duration": calculate_latency_stats(db_persist_durations),
            "total_scan_duration": calculate_latency_stats(latencies_submission),
        }

    def benchmark_asynchronous_flow(self) -> dict[str, Any]:
        """Measure asynchronous Kafka architecture: API returns immediately, worker scans in background."""
        api_latencies = []
        publish_latencies = []
        queue_wait_latencies = []
        worker_processing_latencies = []
        total_completion_latencies = []

        producer = ScanKafkaProducer()
        worker = ScanWorker(engine=SecurityEngine(), db_factory=self.SessionLocal)
        consumer = ScanKafkaConsumer(worker=worker)

        for _ in range(self.iterations):
            t_submit_start = time.perf_counter()

            # 1. API: create job & publish event
            db = self.SessionLocal()
            job_repo = ScanJobRepository(db)
            job = job_repo.create_job("https://github.com/async/repo", "async", "repo")

            t_pub_start = time.perf_counter()
            producer.publish_scan_requested(job.id, job.repository_url)
            pub_ms = (time.perf_counter() - t_pub_start) * 1000.0
            publish_latencies.append(pub_ms)

            # API response is returned immediately to client!
            api_ms = (time.perf_counter() - t_submit_start) * 1000.0
            api_latencies.append(api_ms)
            db.close()

            # 2. Event queue waiting & pickup (simulate Kafka consumer poll)
            t_pickup_start = time.perf_counter()
            # Dequeue event from producer buffer
            event = producer.published_events[-1]
            queue_wait_ms = (time.perf_counter() - t_pickup_start) * 1000.0
            queue_wait_latencies.append(queue_wait_ms)

            # 3. Worker execution
            t_work_start = time.perf_counter()
            worker.process_scan_job(
                scan_id=event["scan_id"],
                repository_url=event["repository_url"],
                local_repo_override=self.sample_repo_path,
            )
            work_ms = (time.perf_counter() - t_work_start) * 1000.0
            worker_processing_latencies.append(work_ms)

            # Total lifecycle duration (from client submission to completion in DB)
            total_ms = (time.perf_counter() - t_submit_start) * 1000.0
            total_completion_latencies.append(total_ms)

        return {
            "flow_type": "Asynchronous (Kafka event + background worker)",
            "iterations": self.iterations,
            "api_submission_latency": calculate_latency_stats(api_latencies),
            "kafka_publish_latency": calculate_latency_stats(publish_latencies),
            "queue_waiting_time": calculate_latency_stats(queue_wait_latencies),
            "worker_processing_time": calculate_latency_stats(worker_processing_latencies),
            "total_scan_duration": calculate_latency_stats(total_completion_latencies),
        }
