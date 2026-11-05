import ast
import re
from scanner.rules.base import SecurityRule
from scanner.core.finding import Finding, Severity, FindingStatus


class SqlInjectionRule(SecurityRule):
    """SEC-008: Identifies unsafe SQL query construction via string formatting/concatenation."""
    rule_id = "SEC-008"
    title = "Potential SQL Injection"
    category = "Injection"
    severity = Severity.CRITICAL
    default_status = FindingStatus.POTENTIAL
    description = "SQL query appears to be constructed using string interpolation, formatting, or concatenation."
    impact = "Attackers can manipulate database queries, bypass authentication, and extract or corrupt sensitive data."
    recommendation = "Use parameterized queries or ORM query builders instead of raw string formatting."

    SQL_PATTERNS = [
        re.compile(r"""f["'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\{""", re.IGNORECASE),
        re.compile(r"""["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*["']\s*%\s*\(?""", re.IGNORECASE),
        re.compile(r"""["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*["']\s*\.format\(""", re.IGNORECASE),
        re.compile(r"""execute\(\s*f["'].*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|WHERE).*\{""", re.IGNORECASE),
        re.compile(r"""cursor\.execute\([^)]*\+[^)]*\)"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        # Check with AST for Python
        if file_path.lower().endswith(".py"):
            try:
                tree = ast.parse(content)
                lines = content.splitlines()

                # Look for JoinedStr (f-strings) containing SQL keywords
                for node in ast.walk(tree):
                    if isinstance(node, ast.JoinedStr):
                        # Inspect string constants inside the JoinedStr
                        text_parts = [
                            p.value for p in node.values
                            if isinstance(p, ast.Constant) and isinstance(p.value, str)
                        ]
                        joined_text = " ".join(text_parts).upper()
                        if any(kw in joined_text for kw in ["SELECT", "INSERT INTO", "UPDATE", "DELETE FROM", "DROP TABLE", "ALTER TABLE"]):
                            line_no = node.lineno
                            findings.append(
                                self.create_finding(
                                    file_path=file_path,
                                    line_start=line_no,
                                    line_end=line_no,
                                    code_snippet=lines[line_no - 1].strip() if line_no <= len(lines) else "SQL f-string",
                                    description="SQL query dynamically constructed via f-string interpolation.",
                                    status=FindingStatus.CONFIRMED,
                                )
                            )

                if findings:
                    return findings
            except SyntaxError:
                pass

        # Regex fallback
        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if clean_line.startswith(("#", "//")):
                continue
            for pattern in self.SQL_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description="Unsafe SQL query dynamically constructed using string formatting.",
                        )
                    )
                    break
        return findings


class CommandInjectionRule(SecurityRule):
    """SEC-018: Inspects os.system, subprocess, shell=True, eval and exec."""
    rule_id = "SEC-018"
    title = "Potential Command Injection or Code Execution"
    category = "Injection"
    severity = Severity.CRITICAL
    default_status = FindingStatus.CONFIRMED
    description = "Dangerous system command execution sink called with shell=True, os.system, or eval/exec."
    impact = "Attackers can execute arbitrary operating system commands on the host machine."
    recommendation = "Use subprocess.run with a sequence of arguments and shell=False. Never pass user input to eval or os.system."

    PATTERNS = [
        (re.compile(r"""subprocess\.(run|Popen|call|check_output)\([^)]*shell\s*=\s*True"""), "subprocess invoked with shell=True"),
        (re.compile(r"""os\.system\([^)]+\)"""), "os.system called with dynamic command"),
        (re.compile(r"""os\.popen\([^)]+\)"""), "os.popen called"),
        (re.compile(r"""\beval\s*\([^)]+\)"""), "eval called"),
        (re.compile(r"""\bexec\s*\([^)]+\)"""), "exec called"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts", ".sh")):
            return findings

        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            clean_line = line.strip()
            if clean_line.startswith("#") or clean_line.startswith("//"):
                continue

            for pattern, reason in self.PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description=f"Dangerous command execution: {reason}.",
                        )
                    )
        return findings


class XssRule(SecurityRule):
    """SEC-019: Inspects dangerous HTML output and rendering sinks."""
    rule_id = "SEC-019"
    title = "Cross-Site Scripting (XSS) / Unsafe HTML Rendering"
    category = "Injection"
    severity = Severity.HIGH
    default_status = FindingStatus.CONFIRMED
    description = "Unescaped HTML or dangerous frontend rendering detected."
    impact = "Attackers can execute malicious scripts in client browsers, stealing sessions and credentials."
    recommendation = "Use auto-escaping templates and avoid Markup(), render_template_string, or dangerouslySetInnerHTML."

    PATTERNS = [
        (re.compile(r"""render_template_string\("""), "Flask render_template_string used with potentially unescaped input"),
        (re.compile(r"""Markup\([^)]*(\+|f["'])"""), "Markup() called with dynamically concatenated HTML"),
        (re.compile(r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:"""), "React dangerouslySetInnerHTML used without sanitization"),
        (re.compile(r"""\.innerHTML\s*=\s*"""), "Direct DOM innerHTML assignment"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".html")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if clean_line.startswith(("#", "//")):
                continue
            for pattern, reason in self.PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description=f"Potential XSS vulnerability: {reason}.",
                        )
                    )
        return findings


class PathTraversalRule(SecurityRule):
    """SEC-020: Detects unsafe user-controlled file paths."""
    rule_id = "SEC-020"
    title = "Potential Path Traversal"
    category = "Injection"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "File system operation called with direct user-supplied path without canonicalization or directory sandboxing."
    impact = "Attackers can access arbitrary system or application files (e.g., /etc/passwd or .env)."
    recommendation = "Validate filenames using os.path.basename and ensure resolved paths remain within an intended base directory."

    PATTERNS = [
        re.compile(r"""open\(\s*(request\.|params|filename|user_path|file_path|path)[^)]*\)"""),
        re.compile(r"""send_file\(\s*(request\.|path|filename)[^)]*\)"""),
        re.compile(r"""os\.path\.join\([^)]*,\s*(request\.|path|filename)[^)]*\)"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if clean_line.startswith(("#", "//")):
                continue
            for pattern in self.PATTERNS:
                if pattern.search(line) and "resolve()" not in line and "basename" not in line:
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description="File opened or joined directly using unvalidated path variable.",
                        )
                    )
        return findings


class SsrfRule(SecurityRule):
    """SEC-021: Identifies user-controlled server-side URL requests."""
    rule_id = "SEC-021"
    title = "Potential Server-Side Request Forgery (SSRF)"
    category = "Injection"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "Outbound HTTP request constructed directly with user-supplied URL."
    impact = "Attackers can probe internal microservices, cloud metadata APIs (e.g. 169.254.169.254), or local networks."
    recommendation = "Validate URLs against an allowlist, restrict schemes to HTTP/HTTPS, and block private IP ranges."

    PATTERNS = [
        re.compile(r"""requests\.(get|post|put|delete)\(\s*(url|target_url|req_url|user_url|request\.)"""),
        re.compile(r"""httpx\.(get|post|put|delete|AsyncClient\(\)\.(get|post))\(\s*(url|target_url|user_url|request\.)"""),
        re.compile(r"""urllib\.request\.urlopen\(\s*(url|target_url|user_url|request\.)"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if clean_line.startswith(("#", "//")):
                continue
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description="Outbound HTTP client invoked with unvalidated URL parameter.",
                        )
                    )
        return findings


class NosqlInjectionRule(SecurityRule):
    """SEC-022: Inspects unsafe NoSQL query construction."""
    rule_id = "SEC-022"
    title = "Potential NoSQL Injection"
    category = "Injection"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "NoSQL query contains direct user dictionary or $where evaluation without sanitization."
    impact = "Attackers can bypass authentication or extract documents from MongoDB/NoSQL databases."
    recommendation = "Enforce type checking on query parameters and avoid passing unvalidated dictionaries or $where expressions."

    PATTERNS = [
        re.compile(r"""\.(find|find_one|update|delete)\(\s*\{[^}]*['"]\$where['"]\s*:"""),
        re.compile(r"""\.(find|find_one)\(\s*request\.(json|get_json|data)"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description="Unsafe NoSQL query pattern detected.",
                        )
                    )
        return findings


class UnsafeDeserializationRule(SecurityRule):
    """SEC-024: Inspects pickle and unsafe YAML loading."""
    rule_id = "SEC-024"
    title = "Unsafe Object Deserialization"
    category = "Injection"
    severity = Severity.CRITICAL
    default_status = FindingStatus.CONFIRMED
    description = "Use of pickle.loads, marshal.loads, or yaml.load without SafeLoader leads to remote code execution."
    impact = "Attackers can construct malicious serialized payloads to execute arbitrary code upon deserialization."
    recommendation = "Use safe serialization formats like JSON or yaml.safe_load. Avoid pickle for untrusted data."

    PATTERNS = [
        (re.compile(r"""pickle\.(loads|load)\("""), "pickle deserialization is inherently vulnerable to code execution"),
        (re.compile(r"""yaml\.(load|load_all)\([^)]*(?<!SafeLoader)[^)]*\)"""), "yaml.load used without SafeLoader"),
        (re.compile(r"""marshal\.(load|loads)\("""), "marshal deserialization detected"),
        (re.compile(r"""shelve\.open\("""), "shelve database open detected"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith(".py"):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if clean_line.startswith("#"):
                continue

            for pattern, reason in self.PATTERNS:
                if pattern.search(line):
                    # Check if safe_load is actually used
                    if "safe_load" in line or "SafeLoader" in line:
                        continue
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description=f"Unsafe deserialization: {reason}.",
                        )
                    )
        return findings
