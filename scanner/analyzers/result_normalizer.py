from typing import Any
from pydantic import BaseModel, Field
from scanner.core.finding import Finding, Evidence, Severity, FindingStatus


class AnalyzerResult(BaseModel):
    tool_name: str
    success: bool
    error_message: str | None = None
    findings: list[Finding] = Field(default_factory=list)


def normalize_semgrep_finding(raw_issue: dict[str, Any], base_path: str = "") -> Finding:
    """Normalize a Semgrep JSON issue into the standard Finding model."""
    extra = raw_issue.get("extra", {})
    check_id = raw_issue.get("check_id", "semgrep.rule")
    message = extra.get("message", "Semgrep security issue detected.")
    severity_str = extra.get("severity", "WARNING").upper()

    sev_map = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    }
    severity = sev_map.get(severity_str, Severity.MEDIUM)

    path = raw_issue.get("path", "unknown")
    start_line = raw_issue.get("start", {}).get("line", 1)
    end_line = raw_issue.get("end", {}).get("line", 1)
    lines_code = extra.get("lines", "")

    return Finding(
        rule_id=f"SEMGREP-{check_id.split('.')[-1].upper()}",
        title=f"Semgrep: {check_id}",
        category="Static Analysis",
        severity=severity,
        status=FindingStatus.POTENTIAL,
        description=message,
        impact="Identified potential code vulnerability via static AST rule matching.",
        recommendation=extra.get("fix", "Review the flagged code and apply secure coding practices."),
        evidence=[
            Evidence(
                file_path=path,
                line_start=start_line,
                line_end=end_line,
                code_snippet=lines_code.strip() if lines_code else "semgrep flagged code",
            )
        ],
    )


def normalize_gitleaks_finding(raw_issue: dict[str, Any]) -> Finding:
    """Normalize a Gitleaks JSON issue into the standard Finding model."""
    rule_id = raw_issue.get("RuleID", "gitleaks-secret")
    desc = raw_issue.get("Description", "Exposed credential detected")
    file_path = raw_issue.get("File", "unknown")
    line_no = raw_issue.get("StartLine", 1)
    raw_snippet = raw_issue.get("Match", "credential match")

    return Finding(
        rule_id="SEC-006",
        title=f"Gitleaks: {desc}",
        category="Secrets",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        description=f"Secret detected by Gitleaks rule: {rule_id}.",
        impact="Compromised credentials can allow unauthorized access to sensitive systems or APIs.",
        recommendation="Revoke and rotate the exposed credential immediately. Remove it from Git history.",
        evidence=[
            Evidence(
                file_path=file_path,
                line_start=line_no,
                line_end=raw_issue.get("EndLine", line_no),
                code_snippet=raw_snippet,  # Will be redacted automatically by Evidence validator
            )
        ],
    )


def normalize_dependency_finding(
    package_name: str,
    installed_version: str,
    advisory_id: str,
    details: str = "",
    file_path: str = "requirements.txt",
    line_start: int = 1,
) -> Finding:
    """Normalize a pip-audit or OSV vulnerability into the standard Finding model."""
    return Finding(
        rule_id="SEC-032",
        title=f"Vulnerable Dependency: {package_name} ({advisory_id})",
        category="Dependencies",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        description=f"Package '{package_name}=={installed_version}' is affected by known advisory {advisory_id}. {details}".strip(),
        impact="Known vulnerability may allow remote exploits, denial of service, or data exposure.",
        recommendation=f"Upgrade '{package_name}' to a patched release.",
        evidence=[
            Evidence(
                file_path=file_path,
                line_start=line_start,
                line_end=line_start,
                code_snippet=f"{package_name}=={installed_version}",
            )
        ],
    )

