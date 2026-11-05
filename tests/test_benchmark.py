import tempfile
from pathlib import Path
import pytest

from scanner.core.engine import SecurityEngine
from scanner.benchmark.evaluator import BenchmarkEvaluator


def test_benchmark_evaluation_runner():
    with tempfile.TemporaryDirectory() as tmp_dir:
        base = Path(tmp_dir)
        vuln_dir = base / "benchmark_vuln"
        clean_dir = base / "benchmark_clean"
        vuln_dir.mkdir()
        clean_dir.mkdir()

        # 1. Populate vulnerable benchmark repository
        (vuln_dir / "sqli.py").write_text("cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n", encoding="utf-8")
        (vuln_dir / "cmd.py").write_text("import os\nos.system('rm -rf ' + path)\n", encoding="utf-8")
        (vuln_dir / "secret.py").write_text("api_key = 'sk-live_998877665544332211'\n", encoding="utf-8")
        (vuln_dir / "jwt.py").write_text("jwt.decode(tok, options={'verify_signature': False})\n", encoding="utf-8")
        (vuln_dir / "llm.py").write_text("eval(response.choices[0].message.content)\n", encoding="utf-8")

        expected_rules = {"SEC-008", "SEC-018", "SEC-006", "SEC-007", "SEC-044"}

        # 2. Populate clean benchmark repository
        (clean_dir / "clean_db.py").write_text("cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n", encoding="utf-8")
        (clean_dir / "clean_sys.py").write_text("subprocess.run(['ls', '-la'], shell=False)\n", encoding="utf-8")
        (clean_dir / "clean_auth.py").write_text("api_key = os.getenv('API_KEY')\n", encoding="utf-8")

        evaluator = BenchmarkEvaluator()
        metrics = evaluator.evaluate_benchmark(
            vulnerable_dir=vuln_dir,
            clean_dir=clean_dir,
            expected_vulnerable_rules=expected_rules,
        )

        # Assert measured real metrics
        assert metrics.files_scanned == 8
        assert metrics.scan_duration_sec > 0.0
        assert metrics.recall >= 0.8  # High recall on expected vulnerabilities
        assert metrics.precision > 0.0
        assert metrics.false_positive_rate <= 0.2  # Clean files have low false positives
        assert metrics.rule_execution_failures == 0
        assert metrics.analyzer_failures == 0

