import tempfile
from pathlib import Path
import pytest

from scanner.analyzers.semgrep import SemgrepAnalyzer
from scanner.analyzers.gitleaks import GitleaksAnalyzer
from scanner.analyzers.dependency_audit import DependencyAuditAnalyzer
from scanner.analyzers.result_normalizer import (
    normalize_semgrep_finding,
    normalize_gitleaks_finding,
    normalize_dependency_finding,
)
from scanner.core.finding import Severity, FindingStatus


def test_semgrep_missing_executable():
    analyzer = SemgrepAnalyzer(binary_path="nonexistent_semgrep_tool_xyz")
    res = analyzer.run(Path("."))
    assert res.success is False
    assert "not found" in res.error_message
    assert res.findings == []


def test_gitleaks_missing_executable():
    analyzer = GitleaksAnalyzer(binary_path="nonexistent_gitleaks_tool_xyz")
    res = analyzer.run(Path("."))
    assert res.success is False
    assert "not found" in res.error_message
    assert res.findings == []


def test_semgrep_normalization():
    raw_issue = {
        "check_id": "rules.python.security.sql_injection",
        "path": "app/db.py",
        "start": {"line": 15},
        "end": {"line": 15},
        "extra": {
            "message": "Unescaped SQL query",
            "severity": "ERROR",
            "lines": "cursor.execute(f'SELECT * FROM {tbl}')",
        },
    }
    finding = normalize_semgrep_finding(raw_issue)
    assert finding.rule_id == "SEMGREP-SQL_INJECTION"
    assert finding.severity == Severity.HIGH
    assert finding.evidence[0].line_start == 15


def test_gitleaks_normalization_and_redaction():
    raw_issue = {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "secrets.env",
        "StartLine": 5,
        "EndLine": 5,
        "Match": "api_key = 'sk-live_abcdef1234567890'",
    }
    finding = normalize_gitleaks_finding(raw_issue)
    assert finding.rule_id == "SEC-006"
    assert finding.severity == Severity.HIGH
    # Evidence must be redacted
    assert "sk-live_abcdef1234567890" not in finding.evidence[0].code_snippet
    assert "*" in finding.evidence[0].code_snippet


def test_dependency_audit_built_in_catalog():
    analyzer = DependencyAuditAnalyzer()
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        req_file = root / "requirements.txt"
        req_file.write_text("requests==2.19.0\nurllib3==1.24.1\ncleanpkg==1.0.0", encoding="utf-8")

        res = analyzer.run(root)
        assert res.success is True
        assert len(res.findings) == 2
        advisories = [f.title for f in res.findings]
        assert any("CVE-2018-18074" in a for a in advisories)
        assert any("CVE-2019-11324" in a for a in advisories)

