import re
from scanner.rules.base import SecurityRule
from scanner.core.finding import Finding, Severity, FindingStatus


class HardcodedSecretRule(SecurityRule):
    """SEC-006: Detects hardcoded credentials, API keys, tokens."""
    rule_id = "SEC-006"
    title = "Hardcoded Secret or API Key"
    category = "Secrets"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "A variable containing a sensitive value appears to hold a hardcoded secret."
    impact = "An attacker with access to the source code can obtain sensitive credentials."
    recommendation = "Move secrets to environment variables or a secrets manager. Rotate exposed credentials."

    SECRET_PATTERN = re.compile(
        r"""(?i)\b(api[_-]?key|secret[_-]?key|password|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["']([^"']{8,})["']"""
    )
    SAFE_VALUES = {
        "your_api_key", "your_secret", "changeme", "example", "placeholder",
        "test_password", "dummy_value", "none", "secret_here"
    }

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if clean_line.startswith(("#", "//", "/*", "*")):
                continue
            match = self.SECRET_PATTERN.search(clean_line)
            if not match:
                continue
            value = match.group(2).strip()
            if value.lower() in self.SAFE_VALUES:
                continue

            findings.append(
                self.create_finding(
                    file_path=file_path,
                    line_start=line_no,
                    line_end=line_no,
                    code_snippet=clean_line,
                )
            )
        return findings


class DefaultCredentialsRule(SecurityRule):
    """SEC-016: Detects default usernames and passwords in code or config."""
    rule_id = "SEC-016"
    title = "Default Credentials Detected"
    category = "Secrets"
    severity = Severity.CRITICAL
    default_status = FindingStatus.CONFIRMED
    description = "Common default username and password combinations detected in configuration or initialization."
    impact = "Attackers can log into administrative accounts using well-known default credentials."
    recommendation = "Require passwords to be set upon installation or generated securely during deployment."

    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "admin123"),
        ("root", "root"),
        ("root", "toor"),
        ("postgres", "postgres"),
        ("user", "password"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        for u, p in self.DEFAULT_CREDS:
            single_line = re.compile(rf"""['"]{u}['"]\s*[:,=]\s*['"]{p}['"]""", re.IGNORECASE)
            multi_line = re.compile(rf"""\busername\s*[:=]\s*['"]{u}['"][\s\S]*?\bpassword\s*[:=]\s*['"]{p}['"]""", re.IGNORECASE)
            
            if multi_line.search(content):
                # Locate line number
                for line_no, line in enumerate(lines, start=1):
                    if u in line:
                        findings.append(
                            self.create_finding(
                                file_path=file_path,
                                line_start=line_no,
                                line_end=min(line_no + 3, len(lines)),
                                code_snippet=line.strip(),
                                description=f"Default credential pair '{u}:{p}' found in configuration.",
                            )
                        )
                        break
            else:
                for line_no, line in enumerate(lines, start=1):
                    if single_line.search(line):
                        findings.append(
                            self.create_finding(
                                file_path=file_path,
                                line_start=line_no,
                                line_end=line_no,
                                code_snippet=line.strip(),
                                description=f"Default credential pair '{u}:{p}' found in configuration.",
                            )
                        )
                        break
        return findings


class GitHistoryLeakRule(SecurityRule):
    """SEC-034: Inspects repository for exposed secret traces or commit artifact leaks."""
    rule_id = "SEC-034"
    title = "Exposed Secret Trace or Uncommitted Git Secret"
    category = "Secrets"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "Potential secrets, private keys, or credentials detected in repository files or gitignore omissions."
    impact = "Secrets inadvertently tracked or preserved in version control can be harvested by attackers."
    recommendation = "Add sensitive files to .gitignore, use git filter-repo or BFG to purge history, and rotate credentials."

    GIT_LEAK_PATTERNS = [
        re.compile(r"""BEGIN\s+([A-Z ]*?)PRIVATE KEY"""),
        re.compile(r"""ghp_[a-zA-Z0-9]{36}"""),
        re.compile(r"""glpat-[a-zA-Z0-9\-_]{20}"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern in self.GIT_LEAK_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description="Private key or token found in repository source.",
                            status=FindingStatus.CONFIRMED,
                        )
                    )
        return findings


class CicdSecretRule(SecurityRule):
    """SEC-035: Identifies credentials exposed in workflow and CI/CD files."""
    rule_id = "SEC-035"
    title = "Plaintext Credential in CI/CD Workflow"
    category = "Secrets"
    severity = Severity.HIGH
    default_status = FindingStatus.CONFIRMED
    description = "Hardcoded token or password found in GitHub Actions, GitLab CI, or workflow configuration."
    impact = "Anyone with read access to the repository can extract CI/CD secrets and compromise build pipelines."
    recommendation = "Use GitHub Secrets (${{ secrets.MY_SECRET }}) rather than hardcoding values."

    SECRET_KEY_PATTERN = re.compile(
        r"""(?i)(password|secret|token|api_key|auth_token)\s*:\s*['"]?([a-zA-Z0-9_\-]{8,})['"]?"""
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        norm_path = file_path.replace("\\", "/").lower()
        if not (norm_path.startswith(".github/") or ".gitlab-ci" in norm_path or "jenkins" in norm_path or "workflow" in norm_path):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if "${{" in clean_line or "$(" in clean_line or clean_line.startswith("#"):
                continue

            match = self.SECRET_KEY_PATTERN.search(clean_line)
            if match:
                val = match.group(2).lower()
                if val not in {"true", "false", "null", "none", "dummy", "test"}:
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description="Plaintext secret found in CI/CD configuration.",
                        )
                    )
        return findings


class FrontendSecretRule(SecurityRule):
    """SEC-042: Detects private credentials exposed through frontend environment variables or client bundles."""
    rule_id = "SEC-042"
    title = "Private Secret Exposed in Frontend Environment"
    category = "Secrets"
    severity = Severity.HIGH
    default_status = FindingStatus.CONFIRMED
    description = "Backend secret keys or private tokens exposed with frontend prefixes (e.g. NEXT_PUBLIC_, REACT_APP_, VITE_)."
    impact = "Frontend environment variables are bundled into client-side JavaScript, exposing private credentials to all web visitors."
    recommendation = "Never prefix private backend secrets with public frontend environment prefixes."

    FRONTEND_SECRET_PATTERN = re.compile(
        r"""(?i)(REACT_APP|NEXT_PUBLIC|VITE|GATSBY)_[A-Z0-9_]*(SECRET|PRIVATE|KEY|TOKEN|PASSWORD|DATABASE|CREDENTIAL)[A-Z0-9_]*\s*=\s*['"]?([^'"\s]+)['"]?"""
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            match = self.FRONTEND_SECRET_PATTERN.search(clean_line)
            if match:
                # Exclude explicitly public keys like publishable_key
                var_name = clean_line.split("=")[0].upper()
                if "PUBLISHABLE" in var_name or "PUBLIC_KEY" in var_name:
                    continue
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=clean_line,
                        description=f"Private credential exposed via public frontend environment variable prefix '{match.group(1)}'.",
                    )
                )
        return findings
