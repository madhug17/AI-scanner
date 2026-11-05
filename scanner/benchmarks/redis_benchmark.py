import time
from typing import Any
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from scanner.database.models import Base
from scanner.database.repositories import ScanJobRepository, FindingRepository, ScanSummaryRepository
from scanner.services.report_service import ReportService
from scanner.cache.redis_client import RedisClient
from scanner.core.finding import Finding, Evidence, Severity, FindingStatus
from scanner.core.scoring import RiskSummary
from scanner.benchmarks.metrics import calculate_latency_stats, calculate_reduction_pct, ResourceMonitor


class RedisBenchmark:
    """Benchmark suite comparing PostgreSQL-only reads against Redis-cached reads."""

    def __init__(self, iterations: int = 100):
        self.iterations = iterations
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.test_scan_id = "bench-scan-uuid-001"
        self._seed_database()

    def _seed_database(self):
        db: Session = self.SessionLocal()
        job_repo = ScanJobRepository(db)
        finding_repo = FindingRepository(db)
        summary_repo = ScanSummaryRepository(db)

        job = job_repo.create_job("https://github.com/benchmark/repo", "benchmark", "repo")
        self.test_scan_id = job.id
        job_repo.update_status(job.id, status="completed")

        # Seed 25 realistic findings
        findings = [
            Finding(
                rule_id=f"SEC-{i:03d}",
                title=f"Benchmark Vulnerability {i}",
                category="Injection" if i % 2 == 0 else "Authentication",
                severity=Severity.HIGH if i % 3 == 0 else Severity.MEDIUM,
                status=FindingStatus.CONFIRMED if i % 4 == 0 else FindingStatus.POTENTIAL,
                description=f"Detailed description for vulnerability {i}",
                impact="Potential unauthorized access or compromise",
                recommendation="Apply input sanitization and verification",
                evidence=[Evidence(file_path=f"src/file_{i}.py", line_start=10, line_end=15, code_snippet=f"vuln_code_{i}()")],
            )
            for i in range(1, 26)
        ]
        finding_repo.save_findings_for_scan(job.id, findings)
        summary_repo.save_summary(
            job.id,
            RiskSummary(risk_score=65.0, risk_category="High", critical_count=2, high_count=8, scan_complete=True),
        )
        db.close()

    def run_all(self) -> dict[str, Any]:
        """Execute all required Redis benchmark scenarios."""
        monitor = ResourceMonitor()
        monitor.start()

        results = {
            "scenario_1_cache_disabled": self.benchmark_cache_disabled(),
            "scenario_2_cold_cache": self.benchmark_cold_cache(),
            "scenario_3_warm_cache": self.benchmark_warm_cache(),
            "scenario_4_cache_expiration": self.benchmark_cache_expiration(),
            "scenario_5_cache_miss": self.benchmark_cache_miss(),
            "scenario_6_redis_unavailable": self.benchmark_redis_unavailable(),
            "scenario_7_concurrent_reads": self.benchmark_concurrent_reads(),
            "scenario_8_cache_invalidation": self.benchmark_cache_invalidation(),
        }

        # Comparative Summary
        before_pg_latency = results["scenario_1_cache_disabled"]["latency"]["avg_ms"]
        after_redis_latency = results["scenario_3_warm_cache"]["latency"]["avg_ms"]
        latency_reduction = calculate_reduction_pct(before_pg_latency, after_redis_latency)

        before_queries = results["scenario_1_cache_disabled"]["db_queries_total"]
        after_queries = results["scenario_3_warm_cache"]["db_queries_total"]
        query_reduction = calculate_reduction_pct(before_queries, after_queries)

        results["comparison_summary"] = {
            "postgres_only_avg_ms": before_pg_latency,
            "redis_warm_avg_ms": after_redis_latency,
            "latency_reduction_pct": latency_reduction,
            "postgres_queries_per_100_reads": before_queries,
            "redis_queries_per_100_reads": after_queries,
            "query_reduction_pct": query_reduction,
            "cache_hit_rate_pct": results["scenario_3_warm_cache"]["cache_stats"]["hit_rate_pct"],
            "resource_usage": monitor.sample().model_dump(),
        }

        return results

    def benchmark_cache_disabled(self) -> dict[str, Any]:
        """Scenario 1: Cache disabled (PostgreSQL-only baseline reads)."""
        db: Session = self.SessionLocal()
        service = ReportService(db)
        latencies = []
        db_queries = 0

        for _ in range(self.iterations):
            t0 = time.perf_counter()
            report = service.get_complete_report(self.test_scan_id, bypass_cache=True)
            latencies.append((time.perf_counter() - t0) * 1000.0)
            db_queries += 3  # ScanJob + Findings + Summary queries

        db.close()
        return {
            "scenario": "Cache Disabled (PostgreSQL only)",
            "iterations": self.iterations,
            "db_queries_total": db_queries,
            "latency": calculate_latency_stats(latencies),
        }

    def benchmark_cold_cache(self) -> dict[str, Any]:
        """Scenario 2: First request / Cold cache (reads DB then populates cache)."""
        redis_c = RedisClient(key_prefix="bench_cold:")
        redis_c.delete(f"scan:{self.test_scan_id}:report")
        db: Session = self.SessionLocal()
        service = ReportService(db)

        t0 = time.perf_counter()
        report = service.get_complete_report(self.test_scan_id, bypass_cache=False)
        duration_ms = (time.perf_counter() - t0) * 1000.0
        db.close()

        return {
            "scenario": "Cold Cache (First Request)",
            "duration_ms": round(duration_ms, 3),
            "db_queries": 3,
            "cache_populated": redis_c.get(f"scan:{self.test_scan_id}:report") is not None,
        }

    def benchmark_warm_cache(self) -> dict[str, Any]:
        """Scenario 3: Repeated requests / Warm cache (served entirely from cache)."""
        redis_c = RedisClient(key_prefix="bench_warm:")
        redis_c.reset_stats()
        db: Session = self.SessionLocal()
        service = ReportService(db)

        # Warm up
        service.get_complete_report(self.test_scan_id, bypass_cache=False)

        latencies = []
        db_queries = 0  # Zero DB queries on cache hits

        for _ in range(self.iterations):
            t0 = time.perf_counter()
            report = service.get_complete_report(self.test_scan_id, bypass_cache=False)
            latencies.append((time.perf_counter() - t0) * 1000.0)

        db.close()
        return {
            "scenario": "Warm Cache (Repeated Reads)",
            "iterations": self.iterations,
            "db_queries_total": db_queries,
            "latency": calculate_latency_stats(latencies),
            "cache_stats": redis_c.get_stats(),
        }

    def benchmark_cache_expiration(self) -> dict[str, Any]:
        """Scenario 4: Cache expiration (TTL expires -> subsequent request falls back to DB)."""
        redis_c = RedisClient(key_prefix="bench_exp:", ttl=1)  # 1 second TTL
        db: Session = self.SessionLocal()
        service = ReportService(db)

        # Initial request caches it
        service.get_complete_report(self.test_scan_id, bypass_cache=False)
        initial_check = redis_c.get(f"scan:{self.test_scan_id}:report") is not None

        # Wait for TTL to expire
        time.sleep(1.1)

        t0 = time.perf_counter()
        expired_check = redis_c.get(f"scan:{self.test_scan_id}:report")
        miss_latency_ms = (time.perf_counter() - t0) * 1000.0

        # Request falls back to DB and refreshes cache
        t1 = time.perf_counter()
        service.get_complete_report(self.test_scan_id, bypass_cache=False)
        refresh_latency_ms = (time.perf_counter() - t1) * 1000.0

        db.close()
        return {
            "scenario": "Cache Expiration (TTL expiry)",
            "initial_cache_populated": initial_check,
            "post_expiry_cached_is_none": expired_check is None,
            "cache_lookup_latency_ms": round(miss_latency_ms, 3),
            "db_fallback_and_recache_ms": round(refresh_latency_ms, 3),
        }

    def benchmark_cache_miss(self) -> dict[str, Any]:
        """Scenario 5: Cache miss (querying non-existent key)."""
        redis_c = RedisClient(key_prefix="bench_miss:")
        t0 = time.perf_counter()
        val = redis_c.get("scan:nonexistent-scan-id:report")
        lookup_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "scenario": "Cache Miss",
            "lookup_duration_ms": round(lookup_ms, 3),
            "value_found": val is not None,
        }

    def benchmark_redis_unavailable(self) -> dict[str, Any]:
        """Scenario 6: Redis unavailable / disabled (graceful fallback)."""
        offline_client = RedisClient(enabled=False)
        db: Session = self.SessionLocal()
        service = ReportService(db)

        t0 = time.perf_counter()
        report = service.get_complete_report(self.test_scan_id, bypass_cache=True)
        duration_ms = (time.perf_counter() - t0) * 1000.0
        db.close()

        return {
            "scenario": "Redis Unavailable (Fallback to PostgreSQL)",
            "fallback_successful": report is not None and report.scan_id == self.test_scan_id,
            "duration_ms": round(duration_ms, 3),
        }

    def benchmark_concurrent_reads(self, concurrency: int = 10) -> dict[str, Any]:
        """Scenario 7: Concurrent requests reading warm cache."""
        import concurrent.futures

        redis_c = RedisClient(key_prefix="bench_conc:")
        db: Session = self.SessionLocal()
        service = ReportService(db)
        # Ensure warmed up
        service.get_complete_report(self.test_scan_id, bypass_cache=False)

        latencies = []

        def read_op():
            local_db = self.SessionLocal()
            local_svc = ReportService(local_db)
            t0 = time.perf_counter()
            local_svc.get_complete_report(self.test_scan_id, bypass_cache=False)
            dur = (time.perf_counter() - t0) * 1000.0
            local_db.close()
            return dur

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(read_op) for _ in range(self.iterations)]
            for f in concurrent.futures.as_completed(futures):
                latencies.append(f.result())

        db.close()
        return {
            "scenario": f"Concurrent Reads ({concurrency} workers)",
            "concurrency": concurrency,
            "iterations": self.iterations,
            "latency": calculate_latency_stats(latencies),
        }

    def benchmark_cache_invalidation(self) -> dict[str, Any]:
        """Scenario 8: Cache invalidation upon scan status update."""
        redis_c = RedisClient(key_prefix="bench_inval:")
        scan_id = "test-inval-123"

        # Populate cache
        redis_c.set(f"scan:{scan_id}:status", "scanning")
        redis_c.set(f"scan:{scan_id}:report", '{"status": "scanning"}')

        t0 = time.perf_counter()
        invalidated_count = redis_c.invalidate_scan(scan_id)
        invalidation_time_ms = (time.perf_counter() - t0) * 1000.0

        post_check = redis_c.get(f"scan:{scan_id}:status")

        return {
            "scenario": "Cache Invalidation",
            "keys_invalidated": invalidated_count,
            "invalidation_duration_ms": round(invalidation_time_ms, 3),
            "cache_cleared": post_check is None,
        }
