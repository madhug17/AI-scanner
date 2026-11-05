import tempfile
from pathlib import Path
import pytest

from scanner.core.engine import SecurityEngine
from scanner.rules.base import SecurityRule
from scanner.core.finding import Finding, Severity, FindingStatus
from scanner.repository.file_discovery import discover_files


class FailingRule(SecurityRule):
    rule_id = "SEC-FAIL"
    def scan(self, file_path: str, content: str) -> list[Finding]:
        raise RuntimeError("Simulated crash in custom rule")


def test_engine_discovery_and_skips():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        # Create valid python file
        (root / "app.py").write_text("print('hello')", encoding="utf-8")
        
        # Create directory that should be ignored
        git_dir = root / ".git"
        git_dir.mkdir()
        (git_dir / "config.py").write_text("print('git')", encoding="utf-8")

        venv_dir = root / "venv"
        venv_dir.mkdir()
        (venv_dir / "lib.py").write_text("print('venv')", encoding="utf-8")

        # Create oversized file (> 1MB)
        large_file = root / "large.py"
        large_file.write_text("x = 1\n" * 200_000, encoding="utf-8")

        discovered, skipped = discover_files(root, max_file_size=100_000)
        rel_paths = [d.relative_path for d in discovered]

        assert "app.py" in rel_paths
        assert not any(".git" in p for p in rel_paths)
        assert not any("venv" in p for p in rel_paths)
        assert not any("large.py" in p for p in rel_paths)


def test_engine_incomplete_scan_on_rule_failure():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / "main.py").write_text("a = 1", encoding="utf-8")

        engine = SecurityEngine(rules=[FailingRule()])
        result = engine.execute_scan(root, run_external_tools=False)

        # Scanner must record rule errors and mark scan_complete as False!
        assert result.scan_complete is False
        assert "SEC-FAIL" in result.rules_failed
        assert len(result.tool_errors) > 0


def test_engine_clean_scan():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / "main.py").write_text("# Clean benign file\ndef hello():\n    return 'world'\n", encoding="utf-8")

        engine = SecurityEngine(rules=[])
        result = engine.execute_scan(root, run_external_tools=False)

        assert result.scan_complete is True
        assert len(result.findings) == 0
        assert result.summary.risk_score == 0.0
        assert result.summary.risk_category == "Clean"

