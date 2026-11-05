import re
from scanner.rules.base import SecurityRule
from scanner.core.finding import Finding, Severity, FindingStatus


class HttpsEnforcementRule(SecurityRule):
    """SEC-005: Identifies insecure transport configuration."""
    rule_id = "SEC-005"
    title = "Insecure Transport / HTTPS Not Enforced"
    category = "Configuration"
    severity = Severity.MEDIUM
    default_status = FindingStatus.CONFIRMED
    description = "Plaintext HTTP URL or disabled SSL verification detected."
    impact = "Unencrypted network traffic can be intercepted or modified via man-in-the-middle (MitM) attacks."
    recommendation = "Enforce HTTPS transport and never disable TLS certificate verification (verify=False)."

    PATTERNS = [
        (re.compile(r"""\bverify\s*=\s*False\b"""), "TLS certificate verification disabled (verify=False)"),
        (re.compile(r"""['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9_\-\.]+"""), "Insecure plaintext HTTP endpoint configured"),
        (re.compile(r"""NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?"""), "Node.js TLS certificate rejection disabled"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
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
                            description=f"Insecure transport configuration: {reason}.",
                        )
                    )
        return findings


class FileUploadSafetyRule(SecurityRule):
    """SEC-023: Inspects file upload validation, extension, and storage safety."""
    rule_id = "SEC-023"
    title = "Insecure File Upload Handling"
    category = "Configuration"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "File upload endpoint writes files without checking extension or content-type."
    impact = "Attackers can upload malicious executables, web shells, or oversized files causing DoS."
    recommendation = "Validate file extensions against an allowlist, check MIME types, and enforce maximum file sizes."

    UPLOAD_PATTERNS = [
        re.compile(r"""UploadFile\b"""),
        re.compile(r"""request\.files\b"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        lines = content.splitlines()
        has_upload = any(any(p.search(line) for p in self.UPLOAD_PATTERNS) for line in lines)
        if not has_upload:
            return findings

        # Check if validation exists in the file
        content_lower = content.lower()
        has_validation = any(k in content_lower for k in [
            "allowed_extensions", "content_type", "max_content_length", "max_file_size", "magic", "extension in"
        ])

        if not has_validation:
            for line_no, line in enumerate(lines, start=1):
                if any(p.search(line) for p in self.UPLOAD_PATTERNS):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description="File upload handled without recognizable file extension or size validation.",
                        )
                    )
                    break
        return findings


class CorsRule(SecurityRule):
    """SEC-025: Identifies overly permissive cross-origin configuration."""
    rule_id = "SEC-025"
    title = "Overly Permissive CORS Policy"
    category = "Configuration"
    severity = Severity.MEDIUM
    default_status = FindingStatus.CONFIRMED
    description = "CORS middleware is configured with wildcard origin ('*') together with credentials or broad access."
    impact = "Malicious websites can issue authenticated cross-origin requests and read private user data."
    recommendation = "Specify exact trusted origins instead of wildcard '*' when allow_credentials is True."

    PATTERNS = [
        (re.compile(r"""allow_origins\s*=\s*\[\s*['"]\*['"]\s*\][\s\S]*?allow_credentials\s*=\s*True"""), "Wildcard origin with credentials allowed"),
        (re.compile(r"""allow_credentials\s*=\s*True[\s\S]*?allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]"""), "Wildcard origin with credentials allowed"),
        (re.compile(r"""Access-Control-Allow-Origin\s*['"]?\s*:\s*['"]\*['"]"""), "Wildcard Access-Control-Allow-Origin header"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()
        for pattern, reason in self.PATTERNS:
            match = pattern.search(content)
            if match:
                start_pos = match.start()
                line_no = content[:start_pos].count("\n") + 1
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else "CORS config"
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=snippet,
                        description=f"Insecure CORS configuration: {reason}.",
                    )
                )
                break
        return findings


class DebugExposureRule(SecurityRule):
    """SEC-026: Inspects debug mode, stack traces and exposed documentation."""
    rule_id = "SEC-026"
    title = "Debug Mode Enabled in Configuration"
    category = "Configuration"
    severity = Severity.MEDIUM
    default_status = FindingStatus.CONFIRMED
    description = "Application is configured with debug mode explicitly turned on (e.g. DEBUG = True)."
    impact = "Debug mode leaks detailed stack traces, internal variables, source code, and interactive debuggers."
    recommendation = "Ensure debug mode is disabled (DEBUG = False) in production environments."

    DEBUG_PATTERNS = [
        (re.compile(r"""\bDEBUG\s*=\s*True\b"""), "DEBUG = True hardcoded"),
        (re.compile(r"""\bdebug\s*=\s*True\b"""), "debug=True parameter passed to application or runner"),
        (re.compile(r"""app\.run\([^)]*debug\s*=\s*True"""), "Flask/server app.run called with debug=True"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        # Exclude test files
        norm_path = file_path.replace("\\", "/").lower()
        if "test" in norm_path or "mock" in norm_path:
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if clean_line.startswith("#"):
                continue
            for pattern, reason in self.DEBUG_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description=f"Exposed debug configuration: {reason}.",
                        )
                    )
        return findings


class SecurityHeadersRule(SecurityRule):
    """SEC-027: Inspects missing or disabled CSP, HSTS, X-Frame-Options, X-Content-Type-Options."""
    rule_id = "SEC-027"
    title = "Missing or Weak Security Headers"
    category = "Configuration"
    severity = Severity.LOW
    default_status = FindingStatus.POTENTIAL
    description = "Security headers such as Content-Security-Policy or X-Frame-Options are missing or disabled."
    impact = "Leaves web application susceptible to clickjacking, MIME-sniffing, and cross-site scripting."
    recommendation = "Configure HSTS, X-Content-Type-Options: nosniff, and X-Frame-Options: DENY."

    WEAK_HEADER_PATTERNS = [
        (re.compile(r"""X-Frame-Options.*ALLOW-FROM""", re.IGNORECASE), "Weak X-Frame-Options directive"),
        (re.compile(r"""unsafe-inline|unsafe-eval"""), "Permissive CSP allowing unsafe-inline or unsafe-eval"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts", ".json", ".conf", ".yaml", ".yml")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern, reason in self.WEAK_HEADER_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description=f"Weak security header configuration: {reason}.",
                        )
                    )
        return findings


class CsrfProtectionRule(SecurityRule):
    """SEC-028: Identifies missing CSRF protection where applicable."""
    rule_id = "SEC-028"
    title = "Missing CSRF Protection on State-Changing Routes"
    category = "Configuration"
    severity = Severity.MEDIUM
    default_status = FindingStatus.POTENTIAL
    description = "Cookie-based state-changing endpoints lack CSRF token validation or middleware."
    impact = "Attackers can trick authenticated victims into submitting unwanted state-changing transactions."
    recommendation = "Use anti-CSRF tokens for session-cookie authenticated endpoints or enforce SameSite=Strict cookies."

    CSRF_EXEMPT_PATTERN = re.compile(r"""@csrf_exempt\b""")

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            if self.CSRF_EXEMPT_PATTERN.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line_start=line_no,
                        line_end=line_no,
                        code_snippet=line.strip(),
                        description="Endpoint explicitly exempts CSRF protection with @csrf_exempt.",
                        status=FindingStatus.CONFIRMED,
                    )
                )
        return findings


class DatabaseExposureRule(SecurityRule):
    """SEC-029: Inspects Supabase/Firebase access rules and public database permissions."""
    rule_id = "SEC-029"
    title = "Permissive Database or Backend Access Rules"
    category = "Configuration"
    severity = Severity.HIGH
    default_status = FindingStatus.CONFIRMED
    description = "Firebase or Supabase security rules grant unrestricted public read/write access."
    impact = "Anyone on the internet can read or overwrite the entire database without authentication."
    recommendation = "Restrict access rules based on request.auth != null and user ownership."

    PATTERNS = [
        (re.compile(r"""allow\s+read,\s*write\s*:\s*if\s+true\s*;"""), "Firebase rule allows public read and write access"),
        (re.compile(r"""allow\s+(read|write)\s*:\s*if\s+true\s*;"""), "Firebase rule allows unrestricted public access"),
        (re.compile(r"""create\s+policy\s+.*with\s+check\s*\(\s*true\s*\)"""), "Supabase RLS policy allows check (true) unconditionally"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        norm_path = file_path.lower()
        if not any(k in norm_path for k in ["rules", "supabase", "firebase", ".sql"]):
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
                            description=f"Insecure database permission: {reason}.",
                        )
                    )
        return findings


class CloudStorageRule(SecurityRule):
    """SEC-030: Inspects public buckets and overly broad IAM permissions."""
    rule_id = "SEC-030"
    title = "Public Cloud Storage Bucket or Permissive IAM Policy"
    category = "Configuration"
    severity = Severity.HIGH
    default_status = FindingStatus.CONFIRMED
    description = "S3 or cloud storage bucket configured with public read/write or wildcard Principal permissions."
    impact = "Confidential files, customer data, and backups in cloud buckets are exposed to the public."
    recommendation = "Set acl to 'private' and avoid wildcard 'Principal: *' with unrestricted Actions."

    PATTERNS = [
        (re.compile(r"""acl\s*=\s*['"]public-read(-write)?['"]"""), "Cloud bucket configured with public-read ACL"),
        (re.compile(r"""['"]Principal['"]\s*:\s*['"]\*['"]"""), "Cloud policy grants wildcard Principal access"),
        (re.compile(r"""block_public_acls\s*=\s*false"""), "S3 block public ACLs explicitly disabled"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        norm_path = file_path.lower()
        if not norm_path.endswith((".tf", ".json", ".yaml", ".yml", ".py")):
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
                            description=f"Public cloud storage misconfiguration: {reason}.",
                        )
                    )
        return findings


class ContainerInfraRule(SecurityRule):
    """SEC-031: Static inspection of Dockerfiles, Terraform and Kubernetes configurations for risky settings."""
    rule_id = "SEC-031"
    title = "Insecure Container or Infrastructure Configuration"
    category = "Configuration"
    severity = Severity.MEDIUM
    default_status = FindingStatus.CONFIRMED
    description = "Container runs as root, uses privileged mode, or exposes insecure host namespaces."
    impact = "Compromising the container allows easy host breakout and cluster takeover."
    recommendation = "Use non-root USER in Dockerfile, avoid privileged: true, and drop unnecessary capabilities."

    PATTERNS = [
        (re.compile(r"""^USER\s+root\b""", re.IGNORECASE), "Dockerfile explicitly switches to root user"),
        (re.compile(r"""\bprivileged:\s*true\b""", re.IGNORECASE), "Kubernetes or Docker Compose container runs with privileged: true"),
        (re.compile(r"""\bhostNetwork:\s*true\b""", re.IGNORECASE), "Container shares host network namespace"),
        (re.compile(r"""\bhostPID:\s*true\b""", re.IGNORECASE), "Container shares host PID namespace"),
        (re.compile(r"""^FROM\s+.*:latest\b""", re.IGNORECASE), "Dockerfile uses unpinned :latest base image tag"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        norm_path = file_path.replace("\\", "/").lower()
        is_target = "dockerfile" in norm_path or norm_path.endswith((".dockerfile", ".yaml", ".yml", ".tf"))
        if not is_target:
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if clean_line.startswith("#"):
                continue
            for pattern, reason in self.PATTERNS:
                if pattern.search(clean_line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description=f"Insecure container configuration: {reason}.",
                        )
                    )
        return findings
