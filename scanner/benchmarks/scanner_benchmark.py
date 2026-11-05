import time
import tempfile
from pathlib import Path
from typing import Any
from scanner.core.engine import SecurityEngine
from scanner.benchmarks.metrics import ResourceMonitor


class ScannerBenchmark:
    """Benchmark evaluating the deterministic security scanning engine across repository sizes."""

    def __init__(self):
        self.engine = SecurityEngine()

    def _create_sample_repo(self, dir_path: Path, num_files: int, lines_per_file: int) -> int:
        """Populate a synthetic repository with realistic vulnerable and clean code patterns."""
        total_bytes = 0
        vuln_templates = [
            "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n",
            "import os\nos.system('echo ' + user_arg)\n",
            "jwt.decode(t, options={'verify_signature': False})\n",
            "eval(response.choices[0].message.content)\n",
            "@app.get('/unauth')\ndef route(): return {'ok': True}\n",
            "api_key = 'sk-live_9876543210abcdef'\n",
            "response.set_cookie('sid', '123', httponly=False)\n",
            "db.users.find({'$where': 'this.x == 1'})\n",
        ]
        clean_templates = [
            "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))\n",
            "subprocess.run(['ls', '-la'], shell=False)\n",
            "api_key = os.getenv('API_KEY')\n",
            "@app.get('/auth')\ndef route(u=Depends(get_current_user)): return {'user': u}\n",
            "response.set_cookie('sid', '123', httponly=True, secure=True)\n",
            "hash_val = bcrypt.hashpw(p.encode(), bcrypt.gensalt())\n",
        ]

        for i in range(1, num_files + 1):
            file_path = dir_path / f"module_{i:03d}.py"
            lines = []
            for j in range(lines_per_file):
                if (i + j) % 7 == 0:
                    lines.append(vuln_templates[(i + j) % len(vuln_templates)])
                else:
                    lines.append(clean_templates[(i + j) % len(clean_templates)])

            content = "".join(lines)
            file_path.write_text(content, encoding="utf-8")
            total_bytes += len(content.encode("utf-8"))

        return total_bytes

    def benchmark_repository(self, label: str, num_files: int, lines_per_file: int) -> dict[str, Any]:
        """Run full scan on a repository of specified dimension and measure performance."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo_path = Path(tmp_dir)
            size_bytes = self._create_sample_repo(repo_path, num_files, lines_per_file)

            monitor = ResourceMonitor()
            monitor.start()

            t0 = time.perf_counter()
            result = self.engine.execute_scan(repo_path, run_external_tools=False)
            duration_sec = time.perf_counter() - t0
            duration_ms = duration_sec * 1000.0

            sys_sample = monitor.sample()

            files_scanned = result.scanned_files_count
            rules_executed = len(result.rules_executed)

            avg_time_per_file_ms = round(duration_ms / max(1, files_scanned), 3)
            avg_time_per_rule_ms = round(duration_ms / max(1, rules_executed), 3)

            return {
                "repository_tier": label,
                "repository_size_kb": round(size_bytes / 1024.0, 2),
                "files_discovered": files_scanned + result.skipped_files_count,
                "files_scanned": files_scanned,
                "files_skipped": result.skipped_files_count,
                "rules_executed_count": rules_executed,
                "analyzer_tools_executed": 3,
                "total_scan_duration_sec": round(duration_sec, 4),
                "total_scan_duration_ms": round(duration_ms, 2),
                "avg_time_per_file_ms": avg_time_per_file_ms,
                "avg_time_per_rule_ms": avg_time_per_rule_ms,
                "findings_generated": len(result.findings),
                "rule_execution_errors": len(result.rules_failed),
                "external_analyzer_failures": len(result.tool_errors),
                "scan_complete": result.scan_complete,
                "cpu_percent": sys_sample.cpu_percent,
                "memory_used_mb": sys_sample.memory_used_mb,
            }

    def run_all(self) -> dict[str, Any]:
        return {
            "small_repository": self.benchmark_repository("Small", num_files=10, lines_per_file=50),
            "medium_repository": self.benchmark_repository("Medium", num_files=40, lines_per_file=100),
            "large_repository": self.benchmark_repository("Large", num_files=100, lines_per_file=150),
        }

