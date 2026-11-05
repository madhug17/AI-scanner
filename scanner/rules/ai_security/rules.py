import re
from scanner.rules.base import SecurityRule
from scanner.core.finding import Finding, Severity, FindingStatus


class AiSecurityRule(SecurityRule):
    """SEC-010: AI/LLM Security — general unsafe user-input and model-output handling."""
    rule_id = "SEC-010"
    title = "Unsafe AI/LLM Integration Boundary"
    category = "AI Security"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "Application interfaces with an LLM without clear sanitization of prompt inputs or output validation."
    impact = "Vulnerable to prompt injection, jailbreaks, and unsafe downstream actions."
    recommendation = "Implement input guardrails and validate LLM outputs against strict schemas before consumption."

    AI_CALL_PATTERN = re.compile(
        r"""(openai\.chat\.completions|client\.chat\.completions|anthropic\.messages|genai\.GenerativeModel)"""
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            if self.AI_CALL_PATTERN.search(line):
                # Check surrounding context for raw input or string formatting
                context = "\n".join(lines[max(0, line_no - 10) : min(line_no + 10, len(lines))])
                if "f\"" in context or "f'" in context or ".format(" in context:
                    if "guardrail" not in context.lower() and "validate" not in context.lower():
                        findings.append(
                            self.create_finding(
                                file_path=file_path,
                                line_start=line_no,
                                line_end=line_no,
                                code_snippet=line.strip(),
                                description="LLM invoked with direct string formatting without input guardrails or validation.",
                            )
                        )
                        break
        return findings


class PromptInjectionRule(SecurityRule):
    """SEC-043: Detects untrusted content mixed directly into prompts without safeguards."""
    rule_id = "SEC-043"
    title = "Direct Prompt Injection Vulnerability"
    category = "AI Security"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "User input interpolated directly into system instructions or prompt templates via f-strings."
    impact = "Attackers can override developer instructions, hijack conversational state, and leak system secrets."
    recommendation = "Separate user input into distinct 'user' role messages, use parameter delimiters, and apply input sanitizers."

    PATTERNS = [
        re.compile(r"""messages\s*=\s*\[\s*\{['"]role['"]\s*:\s*['"]system['"],\s*['"]content['"]\s*:\s*f["'].*\{(user_input|prompt|request\.|query)""", re.IGNORECASE),
        re.compile(r"""PromptTemplate\([^)]*template\s*=\s*f["']"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
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
                            description="User input interpolated directly into system instructions or prompt template.",
                        )
                    )
        return findings


class InsecureOutputHandlingRule(SecurityRule):
    """SEC-044: Detects model output flowing into SQL, shell, eval or unsafe HTML."""
    rule_id = "SEC-044"
    title = "Insecure LLM Output Handling (Code/SQL/Shell Execution)"
    category = "AI Security"
    severity = Severity.CRITICAL
    default_status = FindingStatus.CONFIRMED
    description = "LLM response text passed directly into an execution sink (eval, exec, subprocess, cursor.execute)."
    impact = "Indirect prompt injection can trick the LLM into generating malicious code that the server automatically executes."
    recommendation = "Never execute unvalidated model output. Run generated code in hardened isolated sandboxes only."

    SINKS = [
        (re.compile(r"""eval\([^)]*(response|completion|llm|content|code|snippet|output)"""), "eval called with LLM output"),
        (re.compile(r"""exec\([^)]*(response|completion|llm|content|code|snippet|output)"""), "exec called with LLM output"),
        (re.compile(r"""(subprocess\.run|os\.system)\([^)]*(response|completion|llm|content|code|snippet|output)"""), "System shell called with LLM output"),
        (re.compile(r"""execute\([^)]*(response|completion|llm|content|code|snippet|output)"""), "Database query executed directly from LLM output"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            if clean_line.startswith(("#", "//")):
                continue
            for pattern, reason in self.SINKS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description=f"Dangerous output sink: {reason}.",
                        )
                    )
        return findings


class ExcessiveAgencyRule(SecurityRule):
    """SEC-045: Identifies AI agents with powerful tools and insufficient approval controls."""
    rule_id = "SEC-045"
    title = "Excessive Agency in AI Agent Tools"
    category = "AI Security"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "Agent granted destructive tool access (database drop/delete, file wipe, terminal execution) without human confirmation."
    impact = "Autonomous agents tricked by malicious context can irreversibly destroy databases or infrastructure."
    recommendation = "Enforce human-in-the-loop (HITL) approval requirements for destructive or high-impact agent tools."

    TOOL_PATTERNS = [
        re.compile(r"""tools\s*=\s*\[[^\]]*(BashProcess|ShellTool|PythonREPLTool|TerminalTool|SqlDatabaseToolkit)[^\]]*\]"""),
        re.compile(r"""allow_dangerous_tools\s*=\s*True"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern in self.TOOL_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=line.strip(),
                            description="AI Agent granted access to high-impact shell/code execution tools without approval gates.",
                        )
                    )
        return findings


class SystemPromptLeakageRule(SecurityRule):
    """SEC-046: Identifies sensitive data or internal instructions exposed through model responses."""
    rule_id = "SEC-046"
    title = "System Prompt or Instruction Leakage Risk"
    category = "AI Security"
    severity = Severity.MEDIUM
    default_status = FindingStatus.POTENTIAL
    description = "System prompt includes confidential API keys, passwords, or instructions explicitly returned in user responses."
    impact = "System prompts containing IP, private business logic, or secrets can be extracted by users."
    recommendation = "Store sensitive data in backend services, never in prompts, and filter system instructions from responses."

    PATTERNS = [
        re.compile(r"""system_prompt\s*=\s*f?["'].*(SECRET_KEY|PASSWORD|API_KEY|INTERNAL_CONFIDENTIAL).*["']""", re.IGNORECASE),
        re.compile(r"""return\s*\{[^}]*['"]system_prompt['"]\s*:"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
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
                            description="System prompt contains sensitive credential keywords or is returned in response.",
                        )
                    )
        return findings


class LlmCostAbuseRule(SecurityRule):
    """SEC-047: Identifies missing request, token or per-user spend limits."""
    rule_id = "SEC-047"
    title = "Missing LLM Token / Cost Limits"
    category = "AI Security"
    severity = Severity.MEDIUM
    default_status = FindingStatus.POTENTIAL
    description = "LLM completion call does not specify max_tokens, or iterative agent loop runs without max_iterations."
    impact = "Malicious or looped queries can drain cloud LLM API budgets rapidly (denial of wallet)."
    recommendation = "Always set max_tokens on completions and bound agent loops with max_iterations or cost quotas."

    COMPLETION_PATTERNS = [
        re.compile(r"""openai\.chat\.completions\.create\([^)]*\)"""),
        re.compile(r"""client\.chat\.completions\.create\([^)]*\)"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern in self.COMPLETION_PATTERNS:
                if pattern.search(line):
                    if "max_tokens" not in line and "max_completion_tokens" not in line:
                        findings.append(
                            self.create_finding(
                                file_path=file_path,
                                line_start=line_no,
                                line_end=line_no,
                                code_snippet=line.strip(),
                                description="LLM chat completion invoked without specifying max_tokens bound.",
                            )
                        )
        return findings


class RagDataIsolationRule(SecurityRule):
    """SEC-048: Inspects tenant filtering and document-access controls in vector searches."""
    rule_id = "SEC-048"
    title = "Missing Tenant Isolation in RAG Vector Search"
    category = "AI Security"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "Vector search query (e.g. similarity_search) called without user or tenant metadata filter."
    impact = "One tenant's vector search retrieves embeddings and confidential context belonging to another tenant."
    recommendation = "Always pass a metadata filter including tenant_id or user_id in similarity_search calls."

    VECTOR_SEARCH_PATTERNS = [
        re.compile(r"""\.(similarity_search|query|search)\(\s*(query|query_text|prompt)[^)]*\)"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern in self.VECTOR_SEARCH_PATTERNS:
                if pattern.search(line):
                    if "filter" not in line and "where" not in line and "tenant" not in line:
                        findings.append(
                            self.create_finding(
                                file_path=file_path,
                                line_start=line_no,
                                line_end=line_no,
                                code_snippet=line.strip(),
                                description="Vector database similarity search executed without metadata isolation filter.",
                            )
                        )
        return findings


class LlmApiKeyExposureRule(SecurityRule):
    """SEC-049: Detects LLM provider API keys exposed to frontend code."""
    rule_id = "SEC-049"
    title = "LLM Provider API Key Exposed to Client Frontend"
    category = "AI Security"
    severity = Severity.CRITICAL
    default_status = FindingStatus.CONFIRMED
    description = "OpenAI, Anthropic, or Gemini API key declared with public frontend prefix (e.g. NEXT_PUBLIC_OPENAI_API_KEY)."
    impact = "Anyone viewing the client source code can steal the API key and use paid LLM services at the owner's expense."
    recommendation = "Route all LLM requests through a backend API and never expose API keys to client-side bundles."

    PATTERNS = [
        re.compile(r"""(NEXT_PUBLIC|REACT_APP|VITE)_(OPENAI|ANTHROPIC|GEMINI|COHERE)_API_KEY\s*=\s*['"]?[a-zA-Z0-9_\-]+"""),
        re.compile(r"""dangerouslyAllowBrowser\s*:\s*true"""),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            for pattern in self.PATTERNS:
                if pattern.search(clean_line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description="LLM provider API key exposed via frontend configuration or dangerouslyAllowBrowser.",
                        )
                    )
        return findings


class PiiToLlmRule(SecurityRule):
    """SEC-050: Identifies possible sensitive-data or PII transmission to LLM providers without safeguards."""
    rule_id = "SEC-050"
    title = "Plaintext PII Transmitted to External LLM Provider"
    category = "AI Security"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "Customer PII (SSN, credit card, passwords) sent directly in LLM prompt payload without redaction."
    impact = "Violates privacy regulations (GDPR, HIPAA, PCI-DSS) and risks data leakage via third-party providers."
    recommendation = "Anonymize or mask sensitive PII using tools like Microsoft Presidio before sending text to external LLMs."

    PII_KEYWORDS = ["ssn", "credit_card", "card_number", "social_security", "passport_number"]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        if not file_path.lower().endswith((".py", ".js", ".ts")):
            return findings

        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            clean_line = line.strip()
            if any(k in clean_line.lower() for k in self.PII_KEYWORDS):
                # Check if it is passed into an LLM call or prompt context
                context = "\n".join(lines[max(0, line_no - 5) : min(line_no + 10, len(lines))]).lower()
                if any(llm in context for llm in ["messages", "prompt", "completions.create"]):
                    if "mask" not in context and "anonymize" not in context and "redact" not in context:
                        findings.append(
                            self.create_finding(
                                file_path=file_path,
                                line_start=line_no,
                                line_end=line_no,
                                code_snippet=clean_line,
                                description="PII variable included in LLM message construction without redaction.",
                            )
                        )
        return findings


class UnsafeModelLoadingRule(SecurityRule):
    """SEC-051: Inspects unsafe model loading: torch.load without weights_only=True or trust_remote_code=True."""
    rule_id = "SEC-051"
    title = "Unsafe Machine Learning Model File Loading"
    category = "AI Security"
    severity = Severity.CRITICAL
    default_status = FindingStatus.CONFIRMED
    description = "Loading untrusted PyTorch/HuggingFace model checkpoints with trust_remote_code=True or torch.load without weights_only."
    impact = "Pickle-based model files can execute arbitrary remote code when loaded."
    recommendation = "Use safetensors format or specify weights_only=True in torch.load. Avoid trust_remote_code=True."

    PATTERNS = [
        (re.compile(r"""trust_remote_code\s*=\s*True"""), "HuggingFace model loaded with trust_remote_code=True"),
        (re.compile(r"""torch\.load\([^)]*(?<!weights_only=True)[^)]*\)"""), "torch.load invoked without weights_only=True"),
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
                    if "weights_only=True" in line:
                        continue
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description=f"Unsafe model loading: {reason}.",
                        )
                    )
        return findings


class ToolMcpPermissionsRule(SecurityRule):
    """SEC-052: Inspects overly broad tool permissions and missing authorization controls in tool/MCP configurations."""
    rule_id = "SEC-052"
    title = "Overly Broad Tool / MCP Execution Permissions"
    category = "AI Security"
    severity = Severity.HIGH
    default_status = FindingStatus.POTENTIAL
    description = "Model Context Protocol (MCP) or tool configuration exposes wildcard permissions or missing scope constraints."
    impact = "AI agents can invoke privileged APIs beyond their intended scope."
    recommendation = "Apply principle of least privilege, specify discrete read-only scopes, and require explicit permission tokens."

    PATTERNS = [
        (re.compile(r"""['"]permissions['"]\s*:\s*\[\s*['"]\*['"]\s*\]"""), "Tool configuration grants wildcard '*' permissions"),
        (re.compile(r"""auto_approve_all_tools\s*=\s*True"""), "Automated approval enabled for all tool calls"),
    ]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            clean_line = line.strip()
            for pattern, reason in self.PATTERNS:
                if pattern.search(clean_line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            code_snippet=clean_line,
                            description=f"Insecure MCP / Tool permission setting: {reason}.",
                        )
                    )
        return findings
