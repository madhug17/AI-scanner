import pandas as pd
from typing import Any
from scanner.core.finding import Finding, Severity, FindingStatus


# Synthetic benchmark dataset representing verified security audits across open source repos
LABELED_TRAINING_EXAMPLES = [
    # True Positives (1)
    {"rule_id": "SEC-008", "category": "Injection", "severity": "critical", "status": "confirmed", "snippet_len": 45, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-018", "category": "Injection", "severity": "critical", "status": "confirmed", "snippet_len": 38, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-006", "category": "Secrets", "severity": "high", "status": "confirmed", "snippet_len": 52, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-024", "category": "Injection", "severity": "critical", "status": "confirmed", "snippet_len": 30, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-007", "category": "Authentication", "severity": "high", "status": "confirmed", "snippet_len": 60, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-002", "category": "Authorization", "severity": "high", "status": "potential", "snippet_len": 55, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-044", "category": "AI Security", "severity": "critical", "status": "confirmed", "snippet_len": 48, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-049", "category": "AI Security", "severity": "critical", "status": "confirmed", "snippet_len": 65, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-029", "category": "Configuration", "severity": "high", "status": "confirmed", "snippet_len": 40, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-041", "category": "API Security", "severity": "critical", "status": "potential", "snippet_len": 70, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-032", "category": "Dependencies", "severity": "high", "status": "confirmed", "snippet_len": 28, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-012", "category": "Authentication", "severity": "high", "status": "confirmed", "snippet_len": 35, "in_test": 0, "has_sanitizer": 0, "label": 1},
    {"rule_id": "SEC-001", "category": "Authentication", "severity": "medium", "status": "needs_verification", "snippet_len": 42, "in_test": 0, "has_sanitizer": 0, "label": 1},

    # False Positives / Benign code patterns (0)
    {"rule_id": "SEC-001", "category": "Authentication", "severity": "medium", "status": "needs_verification", "snippet_len": 30, "in_test": 1, "has_sanitizer": 1, "label": 0},
    {"rule_id": "SEC-006", "category": "Secrets", "severity": "high", "status": "potential", "snippet_len": 25, "in_test": 1, "has_sanitizer": 0, "label": 0},
    {"rule_id": "SEC-020", "category": "Injection", "severity": "high", "status": "potential", "snippet_len": 35, "in_test": 0, "has_sanitizer": 1, "label": 0},
    {"rule_id": "SEC-021", "category": "Injection", "severity": "high", "status": "potential", "snippet_len": 40, "in_test": 1, "has_sanitizer": 1, "label": 0},
    {"rule_id": "SEC-027", "category": "Configuration", "severity": "low", "status": "potential", "snippet_len": 22, "in_test": 1, "has_sanitizer": 0, "label": 0},
    {"rule_id": "SEC-004", "category": "Authentication", "severity": "high", "status": "potential", "snippet_len": 28, "in_test": 1, "has_sanitizer": 0, "label": 0},
    {"rule_id": "SEC-014", "category": "Authentication", "severity": "low", "status": "potential", "snippet_len": 20, "in_test": 1, "has_sanitizer": 0, "label": 0},
    {"rule_id": "SEC-039", "category": "API Security", "severity": "low", "status": "potential", "snippet_len": 32, "in_test": 1, "has_sanitizer": 0, "label": 0},
    {"rule_id": "SEC-043", "category": "AI Security", "severity": "high", "status": "potential", "snippet_len": 50, "in_test": 0, "has_sanitizer": 1, "label": 0},
    {"rule_id": "SEC-048", "category": "AI Security", "severity": "high", "status": "potential", "snippet_len": 44, "in_test": 1, "has_sanitizer": 1, "label": 0},
    {"rule_id": "SEC-010", "category": "AI Security", "severity": "high", "status": "potential", "snippet_len": 38, "in_test": 1, "has_sanitizer": 1, "label": 0},
]


def extract_finding_features(finding: Finding) -> dict[str, Any]:
    """Extract tabular machine learning features from a Finding instance."""
    snippet = ""
    file_path = ""
    if finding.evidence:
        snippet = finding.evidence[0].code_snippet
        file_path = finding.evidence[0].file_path.lower()

    in_test = 1 if any(t in file_path for t in ["test", "mock", "fixture", "conftest"]) else 0
    has_sanitizer = 1 if any(s in snippet.lower() for s in ["clean", "safe", "sanitize", "escape", "resolve"]) else 0

    return {
        "rule_id": finding.rule_id,
        "category": finding.category,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "snippet_len": len(snippet),
        "in_test": in_test,
        "has_sanitizer": has_sanitizer,
    }


def get_labeled_dataset() -> pd.DataFrame:
    """Return labeled dataset as pandas DataFrame for training and evaluation."""
    return pd.DataFrame(LABELED_TRAINING_EXAMPLES)

