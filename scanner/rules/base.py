from abc import ABC, abstractmethod
from scanner.core.finding import Finding, Evidence, Severity, FindingStatus


class SecurityRule(ABC):
    rule_id: str = "SEC-000"
    title: str = "Base Security Rule"
    category: str = "General"
    severity: Severity = Severity.MEDIUM
    default_status: FindingStatus = FindingStatus.POTENTIAL
    description: str = "Base security rule description"
    impact: str = "Base security rule impact"
    recommendation: str = "Base security rule recommendation"

    @abstractmethod
    def scan(self, file_path: str, content: str) -> list[Finding]:
        """Scan file content and return a list of findings."""
        pass

    def create_finding(
        self,
        file_path: str,
        line_start: int,
        line_end: int,
        code_snippet: str,
        description: str | None = None,
        impact: str | None = None,
        recommendation: str | None = None,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
        title: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=title or self.title,
            category=self.category,
            severity=severity or self.severity,
            status=status or self.default_status,
            description=description or self.description,
            impact=impact or self.impact,
            recommendation=recommendation or self.recommendation,
            evidence=[
                Evidence(
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code_snippet,
                )
            ],
        )

