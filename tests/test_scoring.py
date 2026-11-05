import pytest
from scanner.core.finding import Finding, Evidence, Severity, FindingStatus
from scanner.core.scoring import ScoringService


def test_scoring_weights_and_confidence():
    findings = [
        Finding(
            rule_id="SEC-008",
            title="SQLi",
            category="Injection",
            severity=Severity.CRITICAL,   # weight 10
            status=FindingStatus.CONFIRMED, # mult 1.0 -> 10.0
            description="desc",
            impact="impact",
            recommendation="fix",
        ),
        Finding(
            rule_id="SEC-001",
            title="No Auth",
            category="Authentication",
            severity=Severity.HIGH,       # weight 7
            status=FindingStatus.POTENTIAL, # mult 0.6 -> 4.2
            description="desc",
            impact="impact",
            recommendation="fix",
        ),
    ]

    # raw_score = 10.0 + 4.2 = 14.2; normalized = min(100.0, round(14.2 * 2.0, 1)) = 28.4
    summary = ScoringService.calculate_score(findings, rules_executed=["SEC-001", "SEC-008"])
    assert summary.risk_score == 28.4
    assert summary.risk_category == "Medium"
    assert summary.critical_count == 1
    assert summary.high_count == 1
    assert summary.confirmed_count == 1
    assert summary.potential_count == 1
    assert summary.scan_complete is True


def test_scoring_marks_incomplete_when_rules_failed():
    findings = []
    summary = ScoringService.calculate_score(
        findings=findings,
        rules_executed=["SEC-001"],
        rules_failed=["SEC-008"],
    )
    assert summary.scan_complete is False
    assert "SEC-008" in summary.rules_failed

