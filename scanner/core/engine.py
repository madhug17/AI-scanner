from pathlib import Path
from pydantic import BaseModel, Field

from scanner.core.finding import Finding
from scanner.core.registry import default_registry
from scanner.core.scoring import ScoringService, RiskSummary
from scanner.rules.base import SecurityRule
from scanner.repository.file_discovery import discover_files, DiscoveredFile
from scanner.analyzers.semgrep import SemgrepAnalyzer
from scanner.analyzers.gitleaks import GitleaksAnalyzer
from scanner.analyzers.dependency_audit import DependencyAuditAnalyzer


class ScanExecutionResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    scanned_files_count: int = 0
    skipped_files_count: int = 0
    rules_executed: list[str] = Field(default_factory=list)
    rules_failed: list[str] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)
    scan_complete: bool = True
    summary: RiskSummary | None = None


class SecurityEngine:
    def __init__(
        self,
        rules: list[SecurityRule] | None = None,
        semgrep_analyzer: SemgrepAnalyzer | None = None,
        gitleaks_analyzer: GitleaksAnalyzer | None = None,
        dependency_analyzer: DependencyAuditAnalyzer | None = None,
    ):
        self.rules = rules if rules is not None else default_registry.get_all_rules()
        self.semgrep = semgrep_analyzer or SemgrepAnalyzer()
        self.gitleaks = gitleaks_analyzer or GitleaksAnalyzer()
        self.dependency_audit = dependency_analyzer or DependencyAuditAnalyzer()

    def scan_repository(
        self,
        repo_path: str | Path,
        run_external_tools: bool = True,
    ) -> list[Finding]:
        """Runs scan and returns findings list (backwards-compatible interface)."""
        result = self.execute_scan(repo_path, run_external_tools=run_external_tools)
        return result.findings

    def execute_scan(
        self,
        repo_path: str | Path,
        run_external_tools: bool = True,
    ) -> ScanExecutionResult:
        """Executes full repository scan across built-in rules and external analyzers.
        
        Guarantees that errors or exceptions do not produce a false clean result.
        """
        root = Path(repo_path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Repository path does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"Expected a directory: {root}")

        discovered_files, skipped_files = discover_files(root)
        findings: list[Finding] = []
        rules_executed: set[str] = set()
        rules_failed: set[str] = set()
        tool_errors: list[str] = []

        # 1. Run Built-in Rules on Discovered Files
        for disc_file in discovered_files:
            try:
                content = disc_file.path.read_text(encoding="utf-8", errors="replace")
            except OSError as err:
                skipped_files.append(f"{disc_file.relative_path}: {err}")
                continue

            for rule in self.rules:
                try:
                    rule_findings = rule.scan(disc_file.relative_path, content)
                    if not isinstance(rule_findings, list):
                        raise TypeError(f"Rule {rule.rule_id} must return a list")
                    findings.extend(rule_findings)
                    rules_executed.add(rule.rule_id)
                except Exception as err:
                    rules_failed.add(rule.rule_id)
                    tool_errors.append(f"Rule {rule.rule_id} error on {disc_file.relative_path}: {err}")

        # 2. Run External Analyzers if requested
        if run_external_tools:
            # Semgrep
            semgrep_res = self.semgrep.run(root)
            if semgrep_res.success:
                findings.extend(semgrep_res.findings)
            else:
                if semgrep_res.error_message:
                    tool_errors.append(semgrep_res.error_message)

            # Gitleaks
            gitleaks_res = self.gitleaks.run(root)
            if gitleaks_res.success:
                findings.extend(gitleaks_res.findings)
            else:
                if gitleaks_res.error_message:
                    tool_errors.append(gitleaks_res.error_message)

            # Dependency Audit
            dep_res = self.dependency_audit.run(root)
            if dep_res.success:
                findings.extend(dep_res.findings)
            else:
                if dep_res.error_message:
                    tool_errors.append(dep_res.error_message)

        # 3. Determine scan completeness:
        # A scan with tool failures or rule exceptions MUST be marked incomplete.
        scan_complete = len(rules_failed) == 0 and len(tool_errors) == 0

        # 4. Calculate Risk Scoring
        summary = ScoringService.calculate_score(
            findings=findings,
            rules_executed=sorted(list(rules_executed)),
            rules_failed=sorted(list(rules_failed)),
            scan_complete=scan_complete,
        )

        return ScanExecutionResult(
            findings=findings,
            scanned_files_count=len(discovered_files),
            skipped_files_count=len(skipped_files),
            rules_executed=sorted(list(rules_executed)),
            rules_failed=sorted(list(rules_failed)),
            tool_errors=tool_errors,
            scan_complete=scan_complete,
            summary=summary,
        )
