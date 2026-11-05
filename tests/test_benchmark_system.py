import tempfile
from pathlib import Path
import pytest

from scanner.benchmarks.metrics import (
    calculate_latency_stats,
    calculate_reduction_pct,
    calculate_improvement_pct,
    ResourceMonitor,
)
from scanner.benchmarks.redis_benchmark import RedisBenchmark
from scanner.benchmarks.kafka_benchmark import KafkaBenchmark
from scanner.benchmarks.database_benchmark import DatabaseBenchmark
from scanner.benchmarks.scanner_benchmark import ScannerBenchmark
from scanner.benchmarks.concurrency_benchmark import ConcurrencyBenchmark
from scanner.benchmarks.report_generator import BenchmarkReportGenerator


def test_metric_calculations():
    latencies = [10.0, 20.0, 30.0, 40.0, 50.0]
    stats = calculate_latency_stats(latencies)
    assert stats["avg_ms"] == 30.0
    assert stats["p50_ms"] == 30.0
    assert stats["min_ms"] == 10.0
    assert stats["max_ms"] == 50.0

    # Reductions & improvements
    red = calculate_reduction_pct(100.0, 20.0)
    assert red == 80.0

    imp = calculate_improvement_pct(50.0, 150.0)
    assert imp == 200.0


def test_redis_benchmark_scenarios():
    bench = RedisBenchmark(iterations=10)
    results = bench.run_all()
    assert "scenario_1_cache_disabled" in results
    assert "scenario_2_cold_cache" in results
    assert "scenario_3_warm_cache" in results
    assert "comparison_summary" in results
    assert results["comparison_summary"]["latency_reduction_pct"] >= 0.0


def test_kafka_benchmark_execution():
    bench = KafkaBenchmark(iterations=3)
    results = bench.run_all()
    assert "synchronous_baseline" in results
    assert "asynchronous_kafka" in results
    assert "comparison" in results
    assert results["comparison"]["api_latency_reduction_pct"] > 0.0


def test_database_benchmark_execution():
    bench = DatabaseBenchmark(record_count=50)
    results = bench.run_all()
    assert "lookup_by_indexed_fields" in results
    assert "pagination_performance" in results
    assert "transaction_duration" in results


def test_scanner_tiered_benchmark():
    bench = ScannerBenchmark()
    small_res = bench.benchmark_repository("SmallTest", num_files=3, lines_per_file=20)
    assert small_res["files_scanned"] == 3
    assert small_res["total_scan_duration_sec"] > 0.0
    assert small_res["scan_complete"] is True


def test_concurrency_benchmark_execution():
    bench = ConcurrencyBenchmark(requests_per_level=10)
    results = bench.run_all(concurrency_levels=[1, 2])
    assert "concurrency_levels_tested" in results
    assert "baseline_postgresql_only" in results
    assert "optimized_redis_cached" in results


def test_report_generator():
    with tempfile.TemporaryDirectory() as tmp_dir:
        json_path = Path(tmp_dir) / "bench.json"
        csv_path = Path(tmp_dir) / "bench.csv"

        sample_data = {
            "before_after_summary": {
                "avg_latency": {"before": "100 ms", "after": "10 ms", "improvement": "90% reduction"}
            }
        }
        BenchmarkReportGenerator.save_json(sample_data, json_path)
        BenchmarkReportGenerator.save_csv(sample_data, csv_path)

        assert json_path.exists()
        assert csv_path.exists()

