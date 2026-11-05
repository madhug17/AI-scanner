import ast
import re
from scanner.rules.base import SecurityRule
from scanner.core.finding import Finding, Severity, FindingStatus


class MassAssignmentRule(SecurityRule):
    """SEC-013: Inspects user-controlled updates to privileged fields (is_admin, role)."""
    rule_id = "SEC-013"
    title = "Potential Mass Assignment to Privileged Fields"
    category = "API Security"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "User request payload is mapped directly into a database model or updates privileged fields without filtering."
    impact = "Attackers can escalate privileges by setting is_admin=True or role='admin' in payload."
    recommendation = "Use separate Pydantic schemas for user input that omit privileged fields, or explicitly whitelist fields."

    PRIVILEGED_FIELDS = {"is_admin", "role", "is_superuser", "permissions", "is_staff"}
    MASS_UPDATE_PATTERNS = [
        re.compile(r"""\b(update|setattr)\([^)]*(request\.(json|data)|payload|body)"""),
        re.compile(r"""User\(\*\*(request\.|data|payload)"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        lines = content.splitlines()
        content_lower = content.lower()

        # Check if privileged fields are mentioned in the file
        has_privileged = any(f in content_lower for f in self.PRIVILEGED_FIELDS)
        if not has_privileged:
            return findings

        for line_no, line in enumerate(lines, start=1):
            for pattern in self.MASS_UPDATE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description="Direct assignment of request payload into database model where privileged fields exist.",
                        )
                    )
        return findings


class InputValidationRule(SecurityRule):
    """SEC-017: Identifies missing validation on untrusted input."""
    rule_id = "SEC-017"
    title = "Missing Input Validation Schema"
    category = "API Security"
    severity = Severity.MEDIUM
    default_status = FindingStatus.POTENTIAL
    description = "API endpoint accepts unvalidated dictionary or raw Request object without Pydantic schema or type bounds."
    impact = "Improperly formatted or malicious input can cause application exceptions or logic bypasses."
    recommendation = "Define strongly-typed Pydantic request models with field validation rules."

    RAW_REQUEST_PATTERNS = [
        re.compile(r"""def\s+[a-zA-Z0-9_]+\s*\([^)]*request\s*:\s*Request\b[^)]*\)"""),
        re.compile(r"""async\s+def\s+[a-zA-Z0-9_]+\s*\([^)]*request\s*:\s*Request\b[^)]*\)"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            if any(p.search(line) for p in self.RAW_REQUEST_PATTERNS):
                # Check if it accesses request.json() without validation
                func_context = "\n".join(lines[line_no - 1 : min(line_no + 15, len(lines))])
                if "await request.json()" in func_context or "request.json()" in func_context:
                    if "BaseModel" not in func_context and "validate" not in func_context:
                        findings.append(
                            self.create_finding(
                                file_path=file_path,
                                line_start=line_no,
                                line_end=line_no,
                                code_snippet=line.strip(),
                                description="Endpoint reads raw request JSON without validating against a Pydantic schema.",
                            )
                        )
        return findings


class ExcessiveDataExposureRule(SecurityRule):
    """SEC-036: Identifies unnecessary sensitive information returned in API responses."""
    rule_id = "SEC-036"
    title = "Excessive Data Exposure in API Response"
    category = "API Security"
    severity = Severity.HIGH
    default_status = FindingStatus.CONFIRMED
    description = "Database model containing sensitive fields (e.g. password, hash, ssn) returned directly in API response."
    impact = "Client applications and network inspectors receive sensitive credentials or personal data."
    recommendation = "Use response_model with an explicit response schema excluding sensitive fields."

    SENSITIVE_FIELDS = ["password", "password_hash", "hashed_password", "ssn", "secret_key"]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            clean_line = line.strip()
            # If returning dict containing user.password or user.hashed_password
            for field in self.SENSITIVE_FIELDS:
                pattern = rf"""['"]{field}['"]\s*:\s*(user|account|record)\.{field}"""
                if re.search(pattern, clean_line, re.IGNORECASE):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description=f"Sensitive field '{field}' explicitly returned in response dictionary.",
                        )
                    )
        return findings


class ErrorHandlingRule(SecurityRule):
    """SEC-037: Identifies stack traces and sensitive internal details exposed to clients."""
    rule_id = "SEC-037"
    title = "Detailed Stack Trace / Internal Error Exposed to Client"
    category = "API Security"
    severity = Severity.MEDIUM
    default_status = FindingStatus.CONFIRMED
    description = "Exception details (traceback.format_exc() or str(e)) returned in client HTTP response."
    impact = "Exposes internal file paths, framework versions, query structure, and environment secrets."
    recommendation = "Log detailed exceptions internally and return generic error messages to clients."

    LEAK_PATTERNS = [
        re.compile(r"""detail\s*=\s*(str\(e\)|traceback\.format_exc\(\))"""),
        re.compile(r"""return\s*\{[^}]*['"](error|detail|exception)['"]\s*:\s*(str\(e\)|traceback\.format_exc\(\))"""),
        re.compile(r"""HTTPException\([^)]*detail\s*=\s*str\(e\)"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern in self.LEAK_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description="Raw exception details or traceback returned to client in HTTP error.",
                        )
                    )
                    break
        return findings


class LoggingHygieneRule(SecurityRule):
    """SEC-038: Detects passwords, tokens and sensitive personal information in logs."""
    rule_id = "SEC-038"
    title = "Sensitive Credential Logged in Plaintext"
    category = "API Security"
    severity = Severity.MEDIUM
    default_status = FindingStatus.CONFIRMED
    description = "Logging statement outputs passwords, tokens, API keys, or credit card numbers."
    impact = "Sensitive credentials are saved to log aggregators and terminal history where multiple parties can view them."
    recommendation = "Sanitize or mask sensitive fields prior to logging."

    LOG_PATTERNS = [
        re.compile(r"""logger\.(info|debug|warn|error)\([^)]*f['"].*(\bpassword\b|\btoken\b|\bsecret\b|\bapi_key\b).*\{""", re.IGNORECASE),
        re.compile(r"""print\([^)]*f['"].*(\bpassword\b|\btoken\b|\bsecret\b).*\{""", re.IGNORECASE),
        re.compile(r"""logging\.(info|debug|warn|error)\([^)]*(\bpassword\b|\btoken\b|\bsecret\b)""", re.IGNORECASE),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if clean_line.startswith(("#", "//")):
                continue
            for pattern in self.LOG_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description="Sensitive parameter logged in plaintext.",
                        )
                    )
        return findings


class PaginationRule(SecurityRule):
    """SEC-039: Identifies unbounded database queries and list endpoints."""
    rule_id = "SEC-039"
    title = "Unbounded Database Query / Missing Pagination"
    category = "API Security"
    severity = Severity.LOW
    default_status = FindingStatus.POTENTIAL
    description = "List endpoint queries database with .all() without limit() or pagination controls."
    impact = "Querying massive tables can exhaust server memory, lock database rows, and cause Denial of Service."
    recommendation = "Enforce default pagination with limit and offset or cursor-based pagination."

    UNBOUNDED_PATTERN = re.compile(r"""\bquery\([a-zA-Z0-9_]+\)\.all\(\)""")

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            if self.UNBOUNDED_PATTERN.search(line):
                # Check if limit() is present on the same line
                if ".limit(" not in line:
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description="Unbounded .all() database query executed without limit constraint.",
                        )
                    )
        return findings


class WebhookVerificationRule(SecurityRule):
    """SEC-040: Inspects signature validation for incoming webhooks."""
    rule_id = "SEC-040"
    title = "Missing Signature Verification for Webhook"
    category = "API Security"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "Webhook receiver endpoint processes incoming webhook events without verifying HMAC signatures."
    impact = "Attackers can forge payment or third-party events, triggering unauthorized state updates."
    recommendation = "Verify HMAC signatures (e.g. stripe.Webhook.construct_event or crypto.createHmac) using a secret webhook key."

    WEBHOOK_ROUTE_PATTERN = re.compile(r"""@.*(post|api_route)\([^)]*webhook""", re.IGNORECASE)

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            if self.WEBHOOK_ROUTE_PATTERN.search(line):
                # Check next 20 lines for signature verification
                context = "\n".join(lines[line_no - 1 : min(line_no + 25, len(lines))]).lower()
                if not any(k in context for k in ["signature", "construct_event", "verify", "hmac", "secret"]):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description="Webhook route lacks recognizable signature verification check.",
                        )
                    )
        return findings


class PaymentTamperingRule(SecurityRule):
    """SEC-041: Identifies client-controlled payment amounts and prices."""
    rule_id = "SEC-041"
    title = "Client-Controlled Payment Amount / Price Tampering"
    category = "API Security"
    severity = Severity.CRITICAL
    default_status = FindingStatus.POTENTIAL
    description = "Payment processing endpoint accepts amount/price directly from client request payload."
    impact = "Malicious customers can modify the price to $0.01 and purchase items at arbitrary discounts."
    recommendation = "Lookup product prices on the server and calculate total amounts server-side."

    PAYMENT_PATTERNS = [
        re.compile(r"""stripe\.PaymentIntent\.create\([^)]*amount\s*=\s*(request\.|payload\.|data\.|body\.)"""),
        re.compile(r"""charge\([^)]*amount\s*=\s*(request\.|payload\[['"]amount['"]\])"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern in self.PAYMENT_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description="Payment charge amount taken directly from client request parameter.",
                        )
                    )
        return findings
