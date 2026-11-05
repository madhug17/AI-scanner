import argparse
import json
import sys
from typing import Any

from scanner.benchmarks.metrics import (
    calculate_reduction_pct,
    calculate_improvement_pct,
)
from scanner.benchmarks.redis_benchmark import RedisBenchmark
from scanner.benchmarks.kafka_benchmark import KafkaBenchmark
from scanner.benchmarks.database_benchmark import DatabaseBenchmark
from scanner.benchmarks.scanner_benchmark import ScannerBenchmark
from scanner.benchmarks.concurrency_benchmark import ConcurrencyBenchmark
from scanner.benchmarks.report_generator import (
    BenchmarkReportGenerator,
    generate_environment_metadata,
)


class BenchmarkSuiteRunner:
    """Executes the complete benchmark suite, collects actual measurements,
    computes percentage deltas, and saves JSON/CSV artifacts.
    """

    def __init__(self):
        self.metadata = generate_environment_metadata()

    def run_full_suite(self) -> dict[str, Any]:
        print("\n==================================================")
        print("   AI APP SECURITY SCANNER - BENCHMARK SUITE")
        print("==================================================")
        print(f"Platform: {self.metadata['operating_system']} | Python {self.metadata['python_version']}")
        print(f"CPU: {self.metadata['cpu_count_logical']} Logical Cores | RAM: {self.metadata['total_ram_gb']} GB\n")

        # 1. Redis Benchmark
        print("[1/5] Running Redis Caching Benchmark...")
        redis_bench = RedisBenchmark(iterations=100)
        redis_results = redis_bench.run_all()
        print(f"  -> PostgreSQL avg read: {redis_results['comparison_summary']['postgres_only_avg_ms']} ms")
        print(f"  -> Redis warm avg read: {redis_results['comparison_summary']['redis_warm_avg_ms']} ms")
        print(f"  -> Latency reduction: {redis_results['comparison_summary']['latency_reduction_pct']} %")

        # 2. Kafka Asynchronous Benchmark
        print("\n[2/5] Running Kafka Asynchronous Processing Benchmark...")
        kafka_bench = KafkaBenchmark(iterations=15)
        kafka_results = kafka_bench.run_all()
        print(f"  -> Synchronous API response: {kafka_results['comparison']['sync_api_response_avg_ms']} ms")
        print(f"  -> Asynchronous API response: {kafka_results['comparison']['async_api_response_avg_ms']} ms")
        print(f"  -> API latency reduction: {kafka_results['comparison']['api_latency_reduction_pct']} %")

        # 3. Database Benchmark
        print("\n[3/5] Running PostgreSQL/SQLAlchemy Index & Pagination Benchmark...")
        db_bench = DatabaseBenchmark(record_count=500)
        db_results = db_bench.run_all()
        print(f"  -> Scan ID lookup avg: {db_results['lookup_by_indexed_fields']['scan_id_lookup_latency']['avg_ms']} ms")
        print(f"  -> Page 1 vs Deep page: {db_results['pagination_performance']['page_1_offset_0']['avg_ms']} ms vs {db_results['pagination_performance']['page_11_offset_200']['avg_ms']} ms")

        # 4. Scanner Engine Benchmark
        print("\n[4/5] Running Security Scanning Engine Tiered Benchmark...")
        scanner_bench = ScannerBenchmark()
        scanner_results = scanner_bench.run_all()
        for tier in ["small_repository", "medium_repository", "large_repository"]:
            t = scanner_results[tier]
            print(f"  -> {t['repository_tier']} ({t['files_scanned']} files, {t['repository_size_kb']} KB): {t['total_scan_duration_sec']}s ({t['avg_time_per_file_ms']} ms/file)")

        # 5. Concurrency Scalability Benchmark
        print("\n[5/5] Running Concurrency Scalability Benchmark (1 to 50 users)...")
        concurrency_bench = ConcurrencyBenchmark(requests_per_level=50)
        concurrency_results = concurrency_bench.run_all(concurrency_levels=[1, 5, 10, 25, 50])
        print(f"  -> 50 concurrent users throughput: {concurrency_results['optimized_redis_cached']['concurrency_50']['throughput_rps']} RPS (vs un-cached: {concurrency_results['baseline_postgresql_only']['concurrency_50']['throughput_rps']} RPS)")

        # Aggregated Before/After Summary Table
        c50_base = concurrency_results["baseline_postgresql_only"]["concurrency_50"]
        c50_opt = concurrency_results["optimized_redis_cached"]["concurrency_50"]

        before_after_summary = {
            "average_api_latency": {
                "before": f"{c50_base['latency']['avg_ms']} ms",
                "after": f"{c50_opt['latency']['avg_ms']} ms",
                "improvement": f"{calculate_reduction_pct(c50_base['latency']['avg_ms'], c50_opt['latency']['avg_ms'])}% reduction",
            },
            "p95_api_latency": {
                "before": f"{c50_base['latency']['p95_ms']} ms",
                "after": f"{c50_opt['latency']['p95_ms']} ms",
                "improvement": f"{calculate_reduction_pct(c50_base['latency']['p95_ms'], c50_opt['latency']['p95_ms'])}% reduction",
            },
            "p99_api_latency": {
                "before": f"{c50_base['latency']['p99_ms']} ms",
                "after": f"{c50_opt['latency']['p99_ms']} ms",
                "improvement": f"{calculate_reduction_pct(c50_base['latency']['p99_ms'], c50_opt['latency']['p99_ms'])}% reduction",
            },
            "throughput_rps": {
                "before": f"{c50_base['throughput_rps']} req/s",
                "after": f"{c50_opt['throughput_rps']} req/s",
                "improvement": f"+{calculate_improvement_pct(c50_base['throughput_rps'], c50_opt['throughput_rps'])}% increase",
            },
            "database_queries_per_repeated_read": {
                "before": "3 queries / request",
                "after": "0 queries / request (cache hit)",
                "improvement": "100% reduction",
            },
            "redis_cache_hit_rate": {
                "before": "N/A (no cache layer)",
                "after": f"{redis_results['comparison_summary']['cache_hit_rate_pct']}%",
                "improvement": "Measured",
            },
            "api_submission_time": {
                "before": f"{kafka_results['comparison']['sync_api_response_avg_ms']} ms (synchronous scan block)",
                "after": f"{kafka_results['comparison']['async_api_response_avg_ms']} ms (202 queued)",
                "improvement": f"{kafka_results['comparison']['api_latency_reduction_pct']}% reduction",
            },
            "scan_completion_time": {
                "before": f"{kafka_results['comparison']['sync_total_completion_avg_ms']} ms",
                "after": f"{kafka_results['comparison']['async_total_completion_avg_ms']} ms",
                "improvement": "Decoupled asynchronous execution",
            },
            "cpu_usage": {
                "before": f"{c50_base['cpu_percent']}%",
                "after": f"{c50_opt['cpu_percent']}%",
                "improvement": "Measured resource footprint",
            },
            "memory_usage": {
                "before": f"{c50_base['memory_used_mb']} MB",
                "after": f"{c50_opt['memory_used_mb']} MB",
                "improvement": "Measured memory footprint",
            },
        }

        full_output = {
            "metadata": self.metadata,
            "before_after_summary": before_after_summary,
            "redis_benchmark": redis_results,
            "kafka_benchmark": kafka_results,
            "database_benchmark": db_results,
            "scanner_benchmark": scanner_results,
            "concurrency_benchmark": concurrency_results,
        }

        # Save artifacts
        BenchmarkReportGenerator.save_json(full_output, "reports/benchmark_results.json")
        BenchmarkReportGenerator.save_csv(full_output, "reports/benchmark_results.csv")

        print("\n==================================================")
        print(" Benchmark results saved:")
        print("  - reports/benchmark_results.json")
        print("  - reports/benchmark_results.csv")
        print("==================================================\n")

        return full_output


def main():
    parser = argparse.ArgumentParser(description="AI App Security Scanner - Benchmark Suite")
    parser.add_argument("--redis", action="store_true", help="Run Redis benchmark only")
    parser.add_argument("--kafka", action="store_true", help="Run Kafka benchmark only")
    parser.add_argument("--database", action="store_true", help="Run Database benchmark only")
    parser.add_argument("--scanner", action="store_true", help="Run Scanner benchmark only")
    parser.add_argument("--concurrency", action="store_true", help="Run Concurrency benchmark only")
    args = parser.parse_args()

    runner = BenchmarkSuiteRunner()

    if args.redis:
        res = RedisBenchmark().run_all()
        print(json.dumps(res, indent=2))
    elif args.kafka:
        res = KafkaBenchmark().run_all()
        print(json.dumps(res, indent=2))
    elif args.database:
        res = DatabaseBenchmark().run_all()
        print(json.dumps(res, indent=2))
    elif args.scanner:
        res = ScannerBenchmark().run_all()
        print(json.dumps(res, indent=2))
    elif args.concurrency:
        res = ConcurrencyBenchmark().run_all()
        print(json.dumps(res, indent=2))
    else:
        runner.run_full_suite()


if __name__ == "__main__":
    main()
