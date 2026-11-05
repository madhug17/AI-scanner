import time
from typing import Any
from sqlalchemy import create_engine, select, text, func
from sqlalchemy.orm import sessionmaker, Session

from scanner.database.models import Base, ScanJobModel, FindingModel, EvidenceModel
from scanner.benchmarks.metrics import calculate_latency_stats, calculate_reduction_pct


class DatabaseBenchmark:
    """Benchmark evaluating database query execution, index performance, and pagination."""

    def __init__(self, record_count: int = 500):
        self.record_count = record_count
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self._seed_data()

    def _seed_data(self):
        db: Session = self.SessionLocal()
        jobs = []
        for i in range(1, 51):
            job = ScanJobModel(
                id=f"job-{i:04d}",
                repository_url=f"https://github.com/org/repo-{i}",
                repository_owner="org",
                repository_name=f"repo-{i}",
                status="completed" if i % 2 == 0 else "queued",
                scan_version="1.0.0",
            )
            jobs.append(job)
            db.add(job)
        db.commit()

        # Seed findings
        severities = ["critical", "high", "medium", "low", "info"]
        categories = ["Injection", "Authentication", "Authorization", "Secrets", "Configuration"]
        rules = ["SEC-001", "SEC-002", "SEC-006", "SEC-008", "SEC-018", "SEC-043"]

        for i in range(1, self.record_count + 1):
            f = FindingModel(
                id=f"find-{i:04d}",
                scan_id=f"job-{(i % 50) + 1:04d}",
                rule_id=rules[i % len(rules)],
                title=f"Vulnerability {i}",
                category=categories[i % len(categories)],
                severity=severities[i % len(severities)],
                status="confirmed" if i % 2 == 0 else "potential",
                description="Benchmark finding description",
                impact="Benchmark impact",
                recommendation="Fix recommendation",
            )
            db.add(f)
        db.commit()
        db.close()

    def run_all(self) -> dict[str, Any]:
        return {
            "lookup_by_indexed_fields": self.benchmark_indexed_lookups(),
            "pagination_performance": self.benchmark_pagination(),
            "transaction_duration": self.benchmark_transactions(),
            "query_cost_summary": {
                "total_records_seeded": self.record_count,
                "scan_jobs_count": 50,
            },
        }

    def benchmark_indexed_lookups(self, iterations: int = 50) -> dict[str, Any]:
        """Measure query execution latency for indexed lookup fields."""
        db: Session = self.SessionLocal()

        scan_id_latencies = []
        status_latencies = []
        severity_latencies = []
        category_latencies = []

        for i in range(iterations):
            # 1. Lookup by scan_id (Indexed FK)
            target_scan = f"job-{(i % 50) + 1:04d}"
            t0 = time.perf_counter()
            stmt1 = select(FindingModel).where(FindingModel.scan_id == target_scan)
            db.execute(stmt1).scalars().all()
            scan_id_latencies.append((time.perf_counter() - t0) * 1000.0)

            # 2. Lookup by status (Indexed)
            t1 = time.perf_counter()
            stmt2 = select(ScanJobModel).where(ScanJobModel.status == "completed")
            db.execute(stmt2).scalars().all()
            status_latencies.append((time.perf_counter() - t1) * 1000.0)

            # 3. Lookup by severity (Indexed)
            t2 = time.perf_counter()
            stmt3 = select(FindingModel).where(FindingModel.severity == "critical")
            db.execute(stmt3).scalars().all()
            severity_latencies.append((time.perf_counter() - t2) * 1000.0)

            # 4. Lookup by category (Indexed)
            t3 = time.perf_counter()
            stmt4 = select(FindingModel).where(FindingModel.category == "Injection")
            db.execute(stmt4).scalars().all()
            category_latencies.append((time.perf_counter() - t3) * 1000.0)

        db.close()
        return {
            "scan_id_lookup_latency": calculate_latency_stats(scan_id_latencies),
            "status_lookup_latency": calculate_latency_stats(status_latencies),
            "severity_lookup_latency": calculate_latency_stats(severity_latencies),
            "category_lookup_latency": calculate_latency_stats(category_latencies),
        }

    def benchmark_pagination(self, iterations: int = 50) -> dict[str, Any]:
        """Compare Page 1 (offset 0) vs Deep Pagination (offset 200)."""
        db: Session = self.SessionLocal()
        page1_latencies = []
        deep_page_latencies = []

        for _ in range(iterations):
            # Page 1 (limit 20, offset 0)
            t0 = time.perf_counter()
            stmt1 = select(FindingModel).order_by(FindingModel.id).offset(0).limit(20)
            db.execute(stmt1).scalars().all()
            page1_latencies.append((time.perf_counter() - t0) * 1000.0)

            # Deep Page 11 (limit 20, offset 200)
            t1 = time.perf_counter()
            stmt2 = select(FindingModel).order_by(FindingModel.id).offset(200).limit(20)
            db.execute(stmt2).scalars().all()
            deep_page_latencies.append((time.perf_counter() - t1) * 1000.0)

        db.close()
        return {
            "page_1_offset_0": calculate_latency_stats(page1_latencies),
            "page_11_offset_200": calculate_latency_stats(deep_page_latencies),
        }

    def benchmark_transactions(self, iterations: int = 30) -> dict[str, Any]:
        """Measure atomic write transaction duration."""
        db: Session = self.SessionLocal()
        tx_durations = []

        for i in range(iterations):
            t0 = time.perf_counter()
            job = ScanJobModel(
                id=f"tx-job-{i}",
                repository_url=f"https://github.com/tx/repo-{i}",
                repository_owner="tx",
                repository_name=f"repo-{i}",
                status="queued",
            )
            db.add(job)
            db.commit()
            tx_durations.append((time.perf_counter() - t0) * 1000.0)

        db.close()
        return {
            "insert_transaction_latency": calculate_latency_stats(tx_durations),
        }
