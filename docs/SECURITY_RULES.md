# Security Rules Inventory

The AI App Security & Quality Scanner implements 52 static security rules covering OWASP Top 10, LLM Top 10, secrets hygiene, and cloud configurations.

---

## 1. Repository & Secrets Security
- **SEC-001**: **Committed .env File** — Flags sensitive environment files committed to version control.
- **SEC-002**: **Missing .gitignore** — Flags repositories lacking a `.gitignore` baseline.
- **SEC-003**: **.env Not Excluded** — Verifies `.env` patterns are present in `.gitignore`.
- **SEC-004 / SEC-006**: **Hardcoded API Keys & Tokens** — High-entropy regex and AST detectors for OpenAI, AWS, GitHub, Stripe, and generic bearer tokens.
- **SEC-005**: **Default Passwords** — Detects standard hardcoded passwords (`admin`, `password`, `123456`).
- **SEC-006**: **Private Key Exposure** — Identifies PEM-encoded RSA/EC private keys committed in source.
- **SEC-034**: **Git History Secrets** — Detects credentials in commit history and staging files.
- **SEC-035**: **CI/CD Secrets** — Detects plaintext tokens in GitHub Actions workflow YAML files.

---

## 2. Authentication & Authorization
- **AUTH-001 / SEC-007**: **Insecure JWT Configuration** — Flags `algorithms=['none']`, disabled verification, or weak secrets.
- **AUTH-002**: **JWT Without Expiration** — Detects tokens minted without `exp` claims.
- **AUTH-003 / SEC-001**: **Missing Authentication on Sensitive Routes** — AST inspection of route handlers lacking auth dependencies.
- **AUTH-004 / SEC-002**: **Missing Authorization on Admin Routes** — Detects administrative operations lacking role checks.
- **AUTH-005 / SEC-012**: **Plaintext Password Storage / Weak Hashing** — Flags MD5, SHA1, or unhashed passwords.
- **AUTH-006 / SEC-016**: **Default Credentials** — Identifies well-known admin/password pairs in code.
- **AUTH-007 / SEC-004**: **Missing Rate Limiting** — Identifies auth and login routes unprotected by rate limiting.

---

## 3. Backend & Injection Vulnerabilities
- **API-001 / SEC-008**: **SQL Injection** — AST parsing detects unparameterized SQL queries via f-strings and `.format()`.
- **API-002 / SEC-018**: **Command Injection** — Identifies `os.system`, `subprocess(shell=True)`, `eval`, and `exec`.
- **API-003 / SEC-024**: **Unsafe Deserialization** — Flags `pickle.loads`, `marshal`, and unsafe YAML loaders.
- **API-004 / SEC-025**: **Insecure CORS Configuration** — Identifies wildcard origins (`allow_origins=["*"]`) with credentials enabled.
- **API-005 / SEC-017**: **Missing Input Validation** — Identifies endpoints accepting raw JSON payloads without Pydantic schemas.
- **API-006 / SEC-026**: **Exposed Debug Mode** — Detects `DEBUG = True` in production configurations.
- **API-007 / SEC-039**: **Unbounded Pagination** — Flags database queries executing `.all()` without limit constraints.
- **API-008 / SEC-023**: **Unsafe File Upload Handling** — Verifies file upload handlers enforce extension and content-type validation.
- **API-009 / SEC-037**: **Exposed Stack Traces** — Detects `traceback.format_exc()` or raw exceptions returned to clients.

---

## 4. AI & LLM Application Security
- **AI-001 / SEC-043**: **Prompt Injection** — Detects untrusted user variables formatted directly into system prompt templates.
- **AI-002**: **LLM Output to SQL** — Flags database queries constructed directly from raw LLM output text.
- **AI-003 / SEC-044**: **LLM Execution Sink** — Detects LLM response text flowing into `eval`, `exec`, or system shells.
- **AI-004 / SEC-047**: **Missing LLM Cost / Usage Limits** — Flags model completion invocations missing `max_tokens`.
- **AI-005**: **Missing Per-User AI Request Limits** — Detects completion routes lacking user-scoped rate limiting.
- **AI-006 / SEC-045**: **Unrestricted AI Tool Execution** — Flags autonomous agents equipped with dangerous tools without human confirmation.
- **AI-007 / SEC-048**: **Unauthorized RAG Data Retrieval** — Detects vector store queries missing tenant/user scoping metadata filters.
- **AI-008 / SEC-049**: **Exposed LLM Provider Keys** — Detects OpenAI / Anthropic keys exposed in client-facing code.

---

## 5. Docker, Kubernetes & Infrastructure Security
- **DOCKER-001 / SEC-031**: **Container Running as Root** — Flags Dockerfiles lacking a non-root `USER` directive.
- **DOCKER-002**: **Secrets Copied into Docker Image** — Flags `COPY .env` or credentials in Dockerfiles.
- **DOCKER-003**: **Untrusted Base Image / Latest Tag** — Detects images using unpinned `:latest` tags.
- **DOCKER-004**: **Unnecessary Exposed Ports** — Identifies administrative or database ports exposed directly.
- **DOCKER-005**: **Missing HEALTHCHECK** — Identifies container images lacking health probe instructions.
- **K8S-001**: **Privileged Container** — Detects `privileged: true` in Kubernetes pod manifests.
- **K8S-002**: **Running as Root** — Detects missing `runAsNonRoot: true` in securityContext.
- **K8S-003**: **Missing CPU and Memory Limits** — Identifies pods missing resource constraints.
- **K8S-004**: **Insecure hostPath Configuration** — Flags dangerous host filesystem volume mounts.
- **TF-001 / SEC-030**: **Publicly Exposed Cloud Storage** — Identifies public S3 bucket ACLs (`public-read`).
- **TF-002**: **Excessive IAM Permissions** — Flags wildcard `*` action statements in IAM policies.
- **TF-003 / SEC-029**: **Publicly Exposed Database** — Detects databases with `publicly_accessible = true`.
- **TF-004**: **Unencrypted Storage Configuration** — Identifies storage volumes lacking KMS / server-side encryption.
