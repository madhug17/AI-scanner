from typing import Any
from pydantic import BaseModel, Field
from scanner.core.finding import Finding, Severity, FindingStatus


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

CONFIDENCE_MULTIPLIERS = {
    FindingStatus.CONFIRMED: 1.0,
    FindingStatus.POTENTIAL: 0.6,
    FindingStatus.NEEDS_VERIFICATION: 0.3,
}


class RiskSummary(BaseModel):
    risk_score: float = Field(
        ...,
        description="Normalized risk score from 0.0 (clean) to 100.0 (maximum risk)",
    )
    risk_category: str = Field(
        ..., description="Risk category: Clean, Low, Medium, High, or Critical"
    )
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    confirmed_count: int = 0
    potential_count: int = 0
    needs_verification_count: int = 0
    counts_by_category: dict[str, int] = Field(default_factory=dict)
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    scan_complete: bool = True
    rules_executed: list[str] = Field(default_factory=list)
    rules_failed: list[str] = Field(default_factory=list)
    scoring_formula: str = (
        "Risk Score = min(100.0, sum(severity_weight * confidence_multiplier) * 2.0). "
        "Weights: Critical=10, High=7, Medium=4, Low=1, Info=0. "
        "Confidence: Confirmed=1.0, Potential=0.6, Needs_Verification=0.3."
    )


class ScoringService:
    @staticmethod
    def calculate_score(
        findings: list[Finding],
        rules_executed: list[str] | None = None,
        rules_failed: list[str] | None = None,
        scan_complete: bool = True,
    ) -> RiskSummary:
        rules_executed = rules_executed or []
        rules_failed = rules_failed or []

        counts_by_sev = {s.value: 0 for s in Severity}
        counts_by_cat: dict[str, int] = {}
        confirmed_count = 0
        potential_count = 0
        needs_verification_count = 0

        raw_score = 0.0

        for finding in findings:
            counts_by_sev[finding.severity.value] += 1
            counts_by_cat[finding.category] = (
                counts_by_cat.get(finding.category, 0) + 1
            )

            if finding.status == FindingStatus.CONFIRMED:
                confirmed_count += 1
            elif finding.status == FindingStatus.POTENTIAL:
                potential_count += 1
            elif finding.status == FindingStatus.NEEDS_VERIFICATION:
                needs_verification_count += 1

            weight = SEVERITY_WEIGHTS.get(finding.severity, 0)
            confidence = CONFIDENCE_MULTIPLIERS.get(finding.status, 0.5)
            raw_score += weight * confidence

        normalized_score = min(100.0, round(raw_score * 2.0, 1))

        if normalized_score == 0:
            risk_category = "Clean"
        elif normalized_score <= 20.0:
            risk_category = "Low"
        elif normalized_score <= 50.0:
            risk_category = "Medium"
        elif normalized_score <= 75.0:
            risk_category = "High"
        else:
            risk_category = "Critical"

        # If scan had failures, completeness must be False
        if rules_failed:
            scan_complete = False

        return RiskSummary(
            risk_score=normalized_score,
            risk_category=risk_category,
            critical_count=counts_by_sev[Severity.CRITICAL.value],
            high_count=counts_by_sev[Severity.HIGH.value],
            medium_count=counts_by_sev[Severity.MEDIUM.value],
            low_count=counts_by_sev[Severity.LOW.value],
            info_count=counts_by_sev[Severity.INFO.value],
            confirmed_count=confirmed_count,
            potential_count=potential_count,
            needs_verification_count=needs_verification_count,
            counts_by_category=counts_by_cat,
            counts_by_severity=counts_by_sev,
            scan_complete=scan_complete,
            rules_executed=rules_executed,
            rules_failed=rules_failed,
        )

