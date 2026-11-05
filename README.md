# AI App Security & Quality Scanner

A robust backend security scanning application designed to inspect source-code repositories for security vulnerabilities, configuration weaknesses, dependency risks, and AI/LLM-specific security issues. Built specifically for developers building applications with AI coding assistants who need assurance that generated code adheres to secure development practices.

---

## 1. Architecture Overview

```
                      +-----------------------------+
                      |       Client / Dev UI       |
                      +--------------+--------------+
                                     |
                          POST /api/v1/scans
                                     v
                      +-----------------------------+
                      |         FastAPI API         |
                      |   - GitHub URL Validation   |
                      |   - Redis Rate Limiting     |
                      +-------+-------------+-------+
                              |             |
           Persist Job (queued)             Publish scan.requested
                              v             v
                    +------------+       +------------+
                    | PostgreSQL |       |   Kafka    |
                    +------------+       +------+-----+
                                                |
                                                | Consume event
                                                v
                                         +--------------+
                                         | Scan Worker  |
                                         +-------+------+
                                                 |
         +---------------------------------------+---------------------------------------+
         |                                       |                                       |
         v                                       v                                       v
+------------------+                   +--------------------+                  +--------------------+
| Safe Git Clone   |                   | File Discovery     |                  | Security Engine    |
| - Shallow clone  |                   | - Ignore .git/venv |                  | - 52 Rule Engine   |
| - Temp isolation |                   | - Max file size    |                  | - AST & RegEx      |
| - Zero execution |                   | - Anti-traversal   |                  | - External Adapters|
+------------------+                   +--------------------+                  +---------+----------+
                                                                                         |
                                           +---------------------------------------------+
                                           v
                              +----------------------------+
                              | Result Normalizer          |
                              | - Common Finding Model     |
                              | - Secret Redaction         |
                              | - Risk Scoring Service     |
                              +--------------+-------------+
                                             |
                         Save findings, summary, completed
                                             v
                              +----------------------------+
                              |   PostgreSQL / Cache       |
                              +----------------------------+
```

---

## 2. Technology Stack

| Component | Technology | Responsibility |
|---|---|---|
| Programming Language | Python 3.10+ | Backend and scanning engine |
| API Framework | FastAPI / Uvicorn | REST API & OpenAPI docs |
| Data Validation | Pydantic v2 | Request/response models & Evidence redaction |
| Database | PostgreSQL & SQLite | Scan jobs, findings, evidence, summaries |
| ORM & Migrations | SQLAlchemy 2.0 / Alembic | Database persistence & migrations |
| Cache & Rate Limiting | Redis | Sliding-window API rate limiting, status cache |
| Event Streaming | Apache Kafka | Asynchronous scan-job distribution |
| Static Analysis | Semgrep Adapter | Source-code static analysis |
| Secret Detection | Gitleaks Adapter | Repository history secret scanning |
| Dependency Audit | OSV / pip-audit | Vulnerable dependency detection |
| Machine Learning | Scikit-learn / Joblib | ML-based finding prioritization & triage |
| Testing | Pytest | Comprehensive 86+ test suite |

---

## 3. The 52-Security Rule Inventory

All 52 security rules are implemented with language-aware Python AST analysis, regular expressions, and configuration parsing.

### A. Authentication and Authorization (Rules 1-10)
- **SEC-001**: **Authentication** — Detects API routes lacking authentication dependencies or decorators.
- **SEC-002**: **Authorization** — Detects database resource access without user ownership checks.
- **SEC-003**: **IDOR / BOLA** — Identifies direct object reference lookup without tenant/user scoping.
- **SEC-004**: **Rate Limiting** — Identifies sensitive authentication/registration routes missing rate limits.
- **SEC-005**: **HTTPS Enforcement** — Flags insecure HTTP URLs and `verify=False` SSL bypasses.
- **SEC-006**: **Secret Exposure** — Detects hardcoded API keys, tokens, and passwords with automatic redaction.
- **SEC-007**: **JWT Security** — Inspects JWT verification bypasses, `none` algorithms, and weak secrets.
- **SEC-008**: **SQL Injection** — Detects unsafe SQL query construction via f-strings and string formatting.
- **SEC-009**: **Admin Protection** — Detects exposed administrative routes lacking admin-role checks.
- **SEC-010**: **AI/LLM Boundary** — Identifies LLM interfaces lacking input guardrails or output validation.

### B. Application Security (Rules 11-24)
- **SEC-011**: **Session & Cookie Security** — Inspects `HttpOnly`, `Secure`, and `SameSite` settings.
- **SEC-012**: **Password Handling** — Detects weak password hashing (MD5, SHA1) and plaintext storage.
- **SEC-013**: **Mass Assignment** — Detects user payloads assigned directly to models with privileged fields.
- **SEC-014**: **Account Enumeration** — Detects disparate error messages leaking user registration status.
- **SEC-015**: **Password Reset Tokens** — Flags cryptographically weak reset tokens (`random.randint`).
- **SEC-016**: **Default Credentials** — Detects well-known default username/password pairs in config.
- **SEC-017**: **Input Validation** — Identifies endpoints accepting raw JSON without Pydantic schemas.
- **SEC-018**: **Command Injection** — Flags `os.system`, `subprocess(shell=True)`, `eval`, and `exec`.
- **SEC-019**: **Cross-Site Scripting (XSS)** — Inspects rendering sinks like `render_template_string` and `Markup`.
- **SEC-020**: **Path Traversal** — Detects unvalidated user paths passed to file open or join calls.
- **SEC-021**: **SSRF** — Detects outbound HTTP requests constructed directly from user input.
- **SEC-022**: **NoSQL Injection** — Inspects unsafe NoSQL query construction (`$where`, raw body).
- **SEC-023**: **File Upload Safety** — Verifies file uploads enforce extension and content-type checks.
- **SEC-024**: **Unsafe Deserialization** — Flags `pickle.loads`, marshal, and `yaml.load` without SafeLoader.

### C. Configuration and Infrastructure Security (Rules 25-35)
- **SEC-025**: **CORS Policy** — Identifies wildcard origins (`allow_origins=["*"]`) with credentials allowed.
- **SEC-026**: **Debug Mode Exposure** — Detects `DEBUG = True` and debug flags in application configs.
- **SEC-027**: **Security Headers** — Flags weak or disabled security headers (X-Frame-Options, CSP).
- **SEC-028**: **CSRF Protection** — Identifies state-changing routes marked with `@csrf_exempt`.
- **SEC-029**: **Database Exposure** — Inspects permissive Firebase/Supabase rules (`allow read, write: if true`).
- **SEC-030**: **Cloud Storage Permissions** — Detects public S3 bucket ACLs (`public-read`, wildcard Principal).
- **SEC-031**: **Container & Infrastructure** — Inspects Dockerfiles (`USER root`, `:latest`) and K8s privileged settings.
- **SEC-032**: **Dependency Vulnerabilities** — Identifies dependencies matching known vulnerability catalogs.
- **SEC-033**: **Hallucinated Packages** — Detects suspicious typosquatted or AI-hallucinated package names.
- **SEC-034**: **Git History Leaks** — Detects private keys (PEM) and access tokens committed in source.
- **SEC-035**: **CI/CD Secrets** — Detects plaintext passwords or tokens in GitHub Actions / CI workflow files.

### D. Data Protection and API Security (Rules 36-42)
- **SEC-036**: **Excessive Data Exposure** — Detects responses returning `hashed_password` or sensitive fields.
- **SEC-037**: **Error Handling Hygiene** — Flags raw stack traces (`traceback.format_exc()`, `str(e)`) returned to clients.
- **SEC-038**: **Logging Hygiene** — Detects plaintext passwords, tokens, or cards output to logs.
- **SEC-039**: **Pagination Enforcement** — Identifies unbounded `.all()` database queries lacking limits.
- **SEC-040**: **Webhook Verification** — Flags incoming webhook endpoints missing signature verification.
- **SEC-041**: **Payment Tampering** — Detects payment endpoints accepting client-controlled prices/amounts.
- **SEC-042**: **Frontend Secrets** — Detects private credentials prefixed with public frontend env variables (`NEXT_PUBLIC_`).

### E. AI and LLM Security (Rules 43-52)
- **SEC-043**: **Prompt Injection** — Detects untrusted user input interpolated directly into system instructions.
- **SEC-044**: **Insecure Output Handling** — Detects LLM response text flowing directly into `eval`, `exec`, or shell.
- **SEC-045**: **Excessive Agency** — Flags autonomous agents granted dangerous tools without approval gates.
- **SEC-046**: **System Prompt Leakage** — Identifies confidential keys or instructions echoed in responses.
- **SEC-047**: **LLM Cost Abuse** — Flags completion calls lacking `max_tokens` or token limits.
- **SEC-048**: **RAG Data Isolation** — Identifies vector search queries lacking tenant or user metadata filters.
- **SEC-049**: **LLM API Key Exposure** — Detects OpenAI/Anthropic keys exposed to frontend client code.
- **SEC-050**: **PII Sent to LLM Providers** — Flags unredacted PII (SSN, credit cards) passed into LLM completions.
- **SEC-051**: **Unsafe Model Loading** — Flags checkpoints loaded with `trust_remote_code=True` or unpinned torch load.
- **SEC-052**: **Tool/MCP Permissions** — Inspects Model Context Protocol (MCP) tool configurations granting wildcard `*` permissions.

---

## 4. Finding Data Model & Secret Redaction

Every scan result adheres strictly to the common Pydantic model:

```python
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

class Evidence(BaseModel):
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str  # Automatically redacts sensitive tokens (e.g. sk-proj***)

class Finding(BaseModel):
    rule_id: str
    title: str
    category: str
    severity: Severity
    status: FindingStatus
    description: str
    impact: str
    recommendation: str
    evidence: list[Evidence] = []
```

### Secret Redaction Guarantee
All evidence snippets are automatically processed through the `redact_secret_string` filter before persistence or reporting. Tokens such as OpenAI keys (`sk-***`), GitHub tokens (`ghp_***`), AWS keys (`AKIA***`), bearer tokens, and passwords are permanently masked, preserving structural context without leaking plaintext credentials.

---

## 5. Severity and Risk Scoring Formula

The scoring service computes an overall risk score from **0.0 (clean)** to **100.0 (maximum risk)**:

$$\text{Raw Score} = \sum_{f \in \text{Findings}} (\text{Weight}(f.\text{severity}) \times \text{ConfidenceMultiplier}(f.\text{status}))$$

$$\text{Risk Score} = \min(100.0, \, \text{round}(\text{Raw Score} \times 2.0, 1))$$

### Weights & Multipliers
- **Severity Weights**: Critical = 10, High = 7, Medium = 4, Low = 1, Info = 0
- **Confidence Multipliers**: Confirmed = 1.0, Potential = 0.6, Needs Verification = 0.3
- **Risk Categories**:
  - `0.0`: Clean
  - `0.1` – `20.0`: Low
  - `20.1` – `50.0`: Medium
  - `50.1` – `75.0`: High
  - `75.1` – `100.0`: Critical

### Completeness Tracking
A scan with rule failures or external analyzer execution errors is strictly marked with `scan_complete: false` and lists all `rules_failed` and `tool_errors`.

---

## 6. REST API Reference

### Health Check
`GET /health`
Returns backend connectivity and component health (PostgreSQL, Redis, Kafka, Scanner Engine).

### Submit Scan
`POST /api/v1/scans`
```json
{
  "repository_url": "https://github.com/owner/repository"
}
```
**Response (202 Accepted):**
```json
{
  "scan_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "status": "queued",
  "message": "Scan job accepted"
}
```

### Get Scan Status
`GET /api/v1/scans/{scan_id}`
Returns scan ID, repository URL, current status (`queued`, `cloning`, `scanning`, `processing`, `completed`, `failed`, `cancelled`), creation time, start time, completion time, and error details.

### Get Scan Findings (Filtered & Paginated)
`GET /api/v1/scans/{scan_id}/findings?severity=critical&page=1&page_size=20`

### Get Full Report
`GET /api/v1/scans/{scan_id}/report`
Returns risk score, summary breakdown, metadata, findings, and redacted evidence.

### Cancel Scan
`POST /api/v1/scans/{scan_id}/cancel`
Safely terminates queued or eligible running scans.

### Scan History
`GET /api/v1/scans?page=1&page_size=20`

---

## 7. Machine Learning Prioritization Component (Phase 8)

The ML prioritization component (`scanner.ml`) trains on labeled security findings to predict true-positive vs false-positive probabilities:
- **Features**: Rule ID, category, severity, status, evidence length, test-file indicators, sanitizer presence.
- **Model**: Scikit-learn Pipeline with `ColumnTransformer` (OneHotEncoder + StandardScaler) and `LogisticRegression`.
- **Metrics**: Accuracy, Precision, Recall, F1-Score logged and compared against rule-only baselines.
- **Experiment Tracking**: Compatible with MLflow experiment logging format (`ml_experiments.json`).

---

## 8. CLI Usage

Run a scan locally from the terminal:

```bash
# Scan repository and display summary
python -m scanner.main /path/to/repo --no-external

# Output full structured JSON report
python -m scanner.main /path/to/repo --json --no-external
```

---

## 9. Running Tests

Execute the Pytest test suite:

```bash
pytest -v
```

All 86 tests verify:
- Clean and vulnerable code fixtures for all 52 security rules.
- Safe cloning, timeout enforcement, and GitHub URL sanitization.
- PostgreSQL database transactions, cascade deletes, and migrations.
- Sliding-window Redis rate limiting and in-memory failover.
- Kafka asynchronous producer/consumer retries and deadletter queues.
- Machine learning finding prioritization and benchmark metrics.

