import re
from enum import Enum
from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    NEEDS_VERIFICATION = "needs_verification"


# Redaction patterns for secrets in evidence
SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|password|token|bearer|access[_-]?key|auth[_-]?token)(\s*[:=]\s*['\"])([^'\"]{4,})(['\"])"),
    re.compile(r"(?i)(sk-[a-zA-Z0-9_-]{8,})"),
    re.compile(r"(?i)(ghp_[a-zA-Z0-9]{20,})"),
    re.compile(r"(?i)(xox[baprs]-[0-9a-zA-Z]{10,})"),
    re.compile(r"(?i)(AKIA[0-9A-Z]{16})"),
]


def redact_secret_string(value: str) -> str:
    """Redact sensitive credentials from snippet while preserving structural context."""
    redacted = value
    for pattern in SECRET_PATTERNS:
        if pattern.groups == 4:
            def repl(match):
                prefix = match.group(1) + match.group(2)
                secret = match.group(3)
                suffix = match.group(4)
                masked = secret[:3] + "*" * min(max(len(secret) - 3, 4), 16)
                return f"{prefix}{masked}{suffix}"
            redacted = pattern.sub(repl, redacted)
        elif pattern.groups == 1:
            def repl_single(match):
                secret = match.group(1)
                masked = secret[:3] + "*" * min(max(len(secret) - 3, 4), 16)
                return masked
            redacted = pattern.sub(repl_single, redacted)
    return redacted


class Evidence(BaseModel):
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str

    @field_validator("code_snippet", mode="before")
    @classmethod
    def redact_snippet(cls, v: str) -> str:
        if isinstance(v, str):
            return redact_secret_string(v)
        return v


class Finding(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: Severity
    status: FindingStatus
    description: str
    impact: str
    recommendation: str
    evidence: list[Evidence] = Field(default_factory=list)
