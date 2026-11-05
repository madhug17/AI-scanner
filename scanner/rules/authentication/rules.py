import ast
import re
from scanner.rules.base import SecurityRule
from scanner.core.finding import Finding, Severity, FindingStatus


class AuthenticationRule(SecurityRule):
    """SEC-001: Detects API endpoints lacking authentication controls."""
    rule_id = "SEC-001"
    title = "Potentially unprotected API route"
    category = "Authentication"
    severity = Severity.MEDIUM
    default_status = FindingStatus.NEEDS_VERIFICATION
    description = "API route appears to lack an authentication check or dependency."
    impact = "Unauthorized users may gain unauthenticated access to sensitive operations or data."
    recommendation = "Enforce authentication via dependency injection (e.g. Depends(get_current_user)), decorator, or middleware."

    HTTP_METHODS = {"get", "post", "put", "patch", "delete", "api_route"}
    AUTH_KEYWORDS = {
        "auth", "authenticate", "authorization", "current_user", "active_user",
        "verify_token", "verify_jwt", "jwt", "require_auth", "require_user",
        "is_authenticated", "login_required", "permission_required", "check_permissions"
    }
    EXEMPT_PATHS = {"/docs", "/openapi.json", "/redoc", "/health", "/metrics", "/public", "/login", "/register"}

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        lines = content.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_decorators = []
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr.lower() in self.HTTP_METHODS:
                        route_decorators.append(decorator)

            if not route_decorators:
                continue

            # Check if path is intentionally public/health
            path_val = ""
            for dec in route_decorators:
                if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                    path_val = dec.args[0].value
                    break

            if any(path_val.startswith(p) for p in self.EXEMPT_PATHS):
                continue

            # Inspect parameters & defaults
            has_auth = False
            for default in node.args.defaults + [v for v in node.args.kw_defaults if v is not None]:
                for child in ast.walk(default):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                        if child.func.id in {"Depends", "Security"}:
                            for arg in child.args:
                                name = getattr(arg, "id", getattr(arg, "attr", "")).lower()
                                if any(kw in name for kw in self.AUTH_KEYWORDS):
                                    has_auth = True
                                    break

            # Inspect decorator args
            for dec in route_decorators:
                for kw in dec.keywords:
                    for child in ast.walk(kw.value):
                        if isinstance(child, ast.Name) and any(k in child.id.lower() for k in self.AUTH_KEYWORDS):
                            has_auth = True

            if not has_auth:
                line_no = route_decorators[0].lineno
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else "route decorator"
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=snippet,
                        description=f"Route '{path_val or node.name}' has no recognizable authentication dependency.",
                    )
                )

        return findings


class RateLimitingRule(SecurityRule):
    """SEC-004: Detects sensitive endpoints without rate limiting."""
    rule_id = "SEC-004"
    title = "Missing rate limiting on sensitive endpoint"
    category = "Authentication"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "Sensitive authentication or payment route lacks rate limiting controls."
    impact = "Vulnerable to credential stuffing, brute force attacks, and denial of service."
    recommendation = "Apply rate limiting middleware or decorators (e.g., @limiter.limit('5/minute'))."

    SENSITIVE_NAMES = {"login", "signin", "authenticate", "token", "password_reset", "reset_password", "register", "signup"}
    RATE_LIMIT_KEYWORDS = {"limit", "ratelimit", "throttle", "rate_limiter"}

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        lines = content.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            name_lower = node.name.lower()
            if not any(k in name_lower for k in self.SENSITIVE_NAMES):
                continue

            # Check if this function is an API route
            is_route = any(
                isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr.lower() in {"post", "put", "patch"}
                for d in node.decorator_list
            )
            if not is_route:
                continue

            # Check for limiter decorator or dependency
            has_limiter = False
            for d in node.decorator_list:
                for child in ast.walk(d):
                    id_name = getattr(child, "id", getattr(child, "attr", "")).lower()
                    if any(rl in id_name for rl in self.RATE_LIMIT_KEYWORDS):
                        has_limiter = True
                        break

            if not has_limiter:
                line_no = node.lineno
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else node.name
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=snippet,
                        description=f"Endpoint '{node.name}' handles sensitive credentials or registration but lacks rate limiting.",
                    )
                )

        return findings


class JwtSecurityRule(SecurityRule):
    """SEC-007: Inspects JWT signing, verification and weak-secret configuration."""
    rule_id = "SEC-007"
    title = "Insecure JWT configuration or verification bypass"
    category = "Authentication"
    severity = Severity.HIGH
    default_status = FindingStatus.CONFIRMED
    description = "JWT verification is disabled, uses the 'none' algorithm, or utilizes hardcoded weak secrets."
    impact = "Attackers can forge arbitrary tokens and impersonate any user."
    recommendation = "Always verify JWT signatures using strong algorithms (e.g. RS256, HS256 with strong secrets) and enforce expiration."

    PATTERNS = [
        (re.compile(r"""options\s*=\s*\{[^}]*['"]verify_signature['"]\s*:\s*False"""), "JWT signature verification explicitly disabled"),
        (re.compile(r"""algorithms\s*=\s*\[\s*['"]none['"]\s*\]"""), "JWT configured to allow 'none' algorithm"),
        (re.compile(r"""jwt\.decode\([^)]*verify\s*=\s*False"""), "JWT decode called with verify=False"),
        (re.compile(r"""jwt\.encode\([^)]*['"]secret['"]\s*,\s*algorithm\s*=\s*['"]HS256['"]"""), "JWT signed with weak or static secret literal"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not (file_path.lower().endswith((".py", ".js", ".ts"))):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern, reason in self.PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description=f"{reason}.",
                        )
                    )
        return findings


class CookieSecurityRule(SecurityRule):
    """SEC-011: Inspects HttpOnly, Secure and SameSite settings."""
    rule_id = "SEC-011"
    title = "Insecure cookie configuration"
    category = "Authentication"
    severity = Severity.MEDIUM
    default_status = FindingStatus.CONFIRMED
    description = "Cookies set without HttpOnly, Secure, or proper SameSite flags."
    impact = "Cookies containing session tokens may be exposed via XSS or CSRF attacks."
    recommendation = "Always set httponly=True, secure=True, and samesite='lax' or 'strict'."

    INSECURE_PATTERNS = [
        (re.compile(r"""set_cookie\([^)]*httponly\s*=\s*False"""), "Cookie configured with httponly=False"),
        (re.compile(r"""set_cookie\([^)]*secure\s*=\s*False"""), "Cookie configured with secure=False"),
        (re.compile(r"""set_cookie\([^)]*samesite\s*=\s*['"]none['"][^)]*secure\s*=\s*False"""), "SameSite=None configured without Secure flag"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern, reason in self.INSECURE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description=f"Insecure cookie detected: {reason}.",
                        )
                    )
        return findings


class PasswordHashingRule(SecurityRule):
    """SEC-012: Identifies plaintext or weak password hashing (MD5, SHA1)."""
    rule_id = "SEC-012"
    title = "Weak password hashing algorithm"
    category = "Authentication"
    severity = Severity.HIGH
    default_status = FindingStatus.CONFIRMED
    description = "MD5 or SHA1 is used for password hashing, or passwords are stored/compared in plaintext."
    impact = "Weak hashes can be reversed or cracked via rainbow tables within seconds."
    recommendation = "Use modern password hashing schemes like bcrypt, argon2, or pbkdf2."

    PATTERNS = [
        (re.compile(r"""hashlib\.md5\([^)]*password"""), "MD5 used for password hashing"),
        (re.compile(r"""hashlib\.sha1\([^)]*password"""), "SHA1 used for password hashing"),
        (re.compile(r"""password\s*==\s*hashlib\."""), "Password compared against weak hash directly"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern, reason in self.PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description=f"{reason}.",
                        )
                    )
        return findings


class AccountEnumerationRule(SecurityRule):
    """SEC-014: Identifies login and reset response differences that leak user existence."""
    rule_id = "SEC-014"
    title = "Account enumeration via disparate response messages"
    category = "Authentication"
    severity = Severity.LOW
    default_status = FindingStatus.POTENTIAL
    description = "Authentication or reset endpoints return messages explicitly stating whether the user exists."
    impact = "Attackers can enumerate valid registered user accounts."
    recommendation = "Return uniform error messages like 'Invalid credentials' or 'If the account exists, an email has been sent'."

    PATTERNS = [
        re.compile(r"""['"]User not found['"]|['"]User does not exist['"]|['"]No user with this email['"]"""),
        re.compile(r"""['"]Username already exists['"]|['"]Email already registered['"]"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            # Only flag if in an error or exception context
            if any(p.search(line) for p in self.PATTERNS) and any(w in line for w in ["HTTPException", "raise", "return", "error"]):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=line.strip(),
                        description="Distinct error message exposes whether an account exists.",
                    )
                )
        return findings


class PasswordResetTokenRule(SecurityRule):
    """SEC-015: Inspects randomness and security of password reset tokens."""
    rule_id = "SEC-015"
    title = "Cryptographically weak password reset token generation"
    category = "Authentication"
    severity = Severity.HIGH
    default_status = FindingStatus.CONFIRMED
    description = "Password reset tokens generated using non-cryptographic random generators like random.randint."
    impact = "Predictable reset tokens allow attackers to take over user accounts."
    recommendation = "Use secrets.token_urlsafe() or secrets.token_hex() with sufficient entropy and expiry."

    PATTERNS = [
        re.compile(r"""(reset_token|token|otp)\s*=\s*(str\()?random\.(randint|random|choice)"""),
        re.compile(r"""(reset_token|token)\s*=\s*str\(time\.time\(\)\)"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description="Password reset token generated with non-cryptographic random generator.",
                        )
                    )
        return findings

