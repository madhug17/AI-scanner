import time
import concurrent.futures
from typing import Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from scanner.database.models import Base
from scanner.database.repositories import ScanJobRepository, FindingRepository, ScanSummaryRepository
from scanner.services.report_service import ReportService
from scanner.cache.redis_client import RedisClient
from scanner.core.finding import Finding, Evidence, Severity, FindingStatus
from scanner.core.scoring import RiskSummary
from scanner.benchmarks.metrics import calculate_latency_stats, ResourceMonitor


class ConcurrencyBenchmark:
    """Benchmark evaluating system scalability, throughput (RPS), and latency percentiles
    across varying concurrency levels (1, 5, 10, 25, 50).
    """

    def __init__(self, requests_per_level: int = 100):
        self.requests_per_level = requests_per_level
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.scan_id = "conc-bench-scan-001"
        self._seed_data()

    def _seed_data(self):
        db = self.SessionLocal()
        job_repo = ScanJobRepository(db)
        job = job_repo.create_job("https://github.com/conc/repo", "conc", "repo")
        self.scan_id = job.id
        job_repo.update_status(job.id, status="completed")

        findings = [
            Finding(
                rule_id=f"SEC-{i:03d}",
                title=f"Finding {i}",
                category="Injection",
                severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                description="Sample finding",
                impact="Sample impact",
                recommendation="Fix",
                evidence=[Evidence(file_path="main.py", line_start=1, line_end=2, code_snippet="cursor.execute()")],
            )
            for i in range(1, 15)
        ]
        FindingRepository(db).save_findings_for_scan(job.id, findings)
        ScanSummaryRepository(db).save_summary(
            job.id,
            RiskSummary(risk_score=50.0, risk_category="Medium", critical_count=0, high_count=14, scan_complete=True),
        )
        db.close()

    def _execute_workload(self, concurrency: int, use_cache: bool) -> dict[str, Any]:
        monitor = ResourceMonitor()
        monitor.start()

        latencies = []
        errors = 0

        # Pre-warm if using cache
        if use_cache:
            db_warm = self.SessionLocal()
            ReportService(db_warm).get_complete_report(self.scan_id, bypass_cache=False)
            db_warm.close()

        def request_task():
            db = self.SessionLocal()
            service = ReportService(db)
            t0 = time.perf_counter()
            try:
                rep = service.get_complete_report(self.scan_id, bypass_cache=not use_cache)
                dur = (time.perf_counter() - t0) * 1000.0
                if not rep:
                    raise ValueError("Report not found")
                return dur, False
            except Exception:
                return (time.perf_counter() - t0) * 1000.0, True
            finally:
                db.close()

        t_start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(request_task) for _ in range(self.requests_per_level)]
            for f in concurrent.futures.as_completed(futures):
                duration, is_err = f.result()
                latencies.append(duration)
                if is_err:
                    errors += 1

        total_elapsed_sec = time.perf_counter() - t_start
        rps = round(len(latencies) / max(0.001, total_elapsed_sec), 2)
        err_pct = round((errors / len(latencies)) * 100.0, 2) if latencies else 0.0

        sys_sample = monitor.sample()
        stats = calculate_latency_stats(latencies)

        return {
            "concurrency_level": concurrency,
            "requests_completed": len(latencies),
            "total_duration_sec": round(total_elapsed_sec, 3),
            "throughput_rps": rps,
            "error_percentage": err_pct,
            "latency": stats,
            "cpu_percent": sys_sample.cpu_percent,
            "memory_used_mb": sys_sample.memory_used_mb,
        }

    def run_all(self, concurrency_levels: list[int] | None = None) -> dict[str, Any]:
        levels = concurrency_levels or [1, 5, 10, 25, 50]

        baseline_results = {}
        optimized_results = {}

        for c in levels:
            baseline_results[f"concurrency_{c}"] = self._execute_workload(c, use_cache=False)
            optimized_results[f"concurrency_{c}"] = self._execute_workload(c, use_cache=True)

        return {
            "concurrency_levels_tested": levels,
            "baseline_postgresql_only": baseline_results,
            "optimized_redis_cached": optimized_results,
        }
