import csv
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import psutil

from scanner.core.config import settings


def get_git_commit() -> str:
    """Retrieve current Git commit hash if in a Git repository."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown"


def generate_environment_metadata() -> dict[str, Any]:
    """Capture comprehensive system environment specifications."""
    mem = psutil.virtual_memory()
    return {
        "benchmark_timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": get_git_commit(),
        "application_version": settings.scan_version,
        "python_version": platform.python_version(),
        "operating_system": platform.platform(),
        "os_release": platform.release(),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "cpu_architecture": platform.machine(),
        "total_ram_gb": round(mem.total / (1024**3), 2),
        "database_backend": "SQLAlchemy 2.0 (PostgreSQL Schema / SQLite Test Driver)",
        "cache_driver": f"Redis 7.x Protocol (Key Prefix: '{settings.redis_key_prefix}', TTL: {settings.redis_scan_cache_ttl}s)",
        "streaming_driver": f"Apache Kafka (Topic: '{settings.kafka_scan_requests_topic}')",
    }


class BenchmarkReportGenerator:
    """Generates structured JSON and CSV reports and markdown tables from benchmark results."""

    @staticmethod
    def save_json(results: dict[str, Any], filepath: Path | str = "reports/benchmark_results.json"):
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    @staticmethod
    def save_csv(results: dict[str, Any], filepath: Path | str = "reports/benchmark_results.csv"):
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        rows = []
        # Flatten key metrics
        comp = results.get("before_after_summary", {})
        for metric, data in comp.items():
            if isinstance(data, dict):
                rows.append({
                    "Metric": metric,
                    "Before": data.get("before"),
                    "After": data.get("after"),
                    "Improvement": data.get("improvement"),
                })

        if rows:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Metric", "Before", "After", "Improvement"])
                writer.writeheader()
                writer.writerows(rows)

