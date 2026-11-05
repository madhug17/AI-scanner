import time
import numpy as np
import psutil
from typing import Any
from pydantic import BaseModel, Field


def calculate_latency_stats(latencies_ms: list[float]) -> dict[str, float]:
    """Calculate statistical distribution of latencies in milliseconds."""
    if not latencies_ms:
        return {
            "avg_ms": 0.0,
            "min_ms": 0.0,
            "p50_ms": 0.0,
            "p90_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "max_ms": 0.0,
            "sample_count": 0,
        }

    arr = np.array(latencies_ms)
    return {
        "avg_ms": round(float(np.mean(arr)), 3),
        "min_ms": round(float(np.min(arr)), 3),
        "p50_ms": round(float(np.percentile(arr, 50)), 3),
        "p90_ms": round(float(np.percentile(arr, 90)), 3),
        "p95_ms": round(float(np.percentile(arr, 95)), 3),
        "p99_ms": round(float(np.percentile(arr, 99)), 3),
        "max_ms": round(float(np.max(arr)), 3),
        "sample_count": len(latencies_ms),
    }


def calculate_reduction_pct(before: float, after: float) -> float:
    """Calculate percentage reduction: ((before - after) / before) * 100."""
    if before <= 0:
        return 0.0
    return round(((before - after) / before) * 100.0, 2)


def calculate_improvement_pct(before: float, after: float) -> float:
    """Calculate percentage throughput improvement: ((after - before) / before) * 100."""
    if before <= 0:
        return 0.0
    return round(((after - before) / before) * 100.0, 2)


class SystemSnapshot(BaseModel):
    cpu_percent: float
    memory_used_mb: float
    memory_percent: float


class ResourceMonitor:
    """Samples CPU and memory metrics over a test execution interval."""

    def __init__(self):
        self.process = psutil.Process()
        self._initial_cpu = 0.0
        self._initial_mem = 0.0

    def start(self):
        self.process.cpu_percent(interval=None)
        self._initial_mem = self.process.memory_info().rss / (1024 * 1024)

    def sample(self) -> SystemSnapshot:
        cpu = self.process.cpu_percent(interval=None)
        mem_info = self.process.memory_info()
        mem_mb = mem_info.rss / (1024 * 1024)
        sys_mem = psutil.virtual_memory().percent
        return SystemSnapshot(
            cpu_percent=round(cpu, 2),
            memory_used_mb=round(mem_mb, 2),
            memory_percent=round(sys_mem, 2),
        )

