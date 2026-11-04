
import re

from scanner.core.finding import (
    Finding,
    Evidence,
    Severity,
    FindingStatus,
)


class HardcodedSecretRule:

    rule_id = "SEC-006"

    SECRET_PATTERN = re.compile(
        r"""(?i)\b(api[_-]?key|secret[_-]?key|password|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["']([^"']{8,})["']"""
    )

    SAFE_VALUES = {
        "your_api_key",
        "your_secret",
        "changeme",
        "example",
        "placeholder",
        "test_password",
    }

    def scan(self, file_path: str, content: str) -> list[Finding]:

        findings = []

        for line_number, line in enumerate(
            content.splitlines(), start=1
        ):

            match = self.SECRET_PATTERN.search(line)

            if not match:
                continue
            value = match.group(2).strip()
            if value.lower() in self.SAFE_VALUES:
                continue
            finding = Finding(
                rule_id=self.rule_id,
                title="Possible hardcoded secret",
                category="Secrets",
                severity=Severity.HIGH,
                status=FindingStatus.POTENTIAL,

                description=(
                    "A variable containing a sensitive value "
                    "appears to contain a hardcoded secret."
                ),

                impact=(
                    "An attacker with access to the repository "
                    "may obtain sensitive credentials."
                ),

                recommendation=(
                    "Move secrets to environment variables or "
                    "a secrets manager. Rotate exposed credentials."
                ),
                evidence=[
                    Evidence(
                        file_path=file_path,
                        line_start=line_number,
                        line_end=line_number,
                        code_snippet=line.strip(),
                    )
                ],
            )
            findings.append(finding)
        return findings
