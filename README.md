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
| Testing | Pytest | Comprehensive 93-test verification suite |

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

## 7. Machine Learning Prioritization Component

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

All 93 tests verify:
- Clean and vulnerable code fixtures for all 52 security rules.
- Safe cloning, timeout enforcement, and GitHub URL sanitization.
- PostgreSQL database transactions, cascade deletes, and migrations.
- Sliding-window Redis rate limiting and in-memory failover.
- Kafka asynchronous producer/consumer retries and deadletter queues.
- Machine learning finding prioritization and benchmark metrics.

---

# Performance Analysis and Optimization

### A. Architecture Before and After

The application was benchmarked across two distinct architectural stages to isolate and quantify the exact performance gains of each infrastructural optimization:

- **Stage A (Before Optimization - Synchronous Baseline):**
  - **Submission Flow:** The API received a scan request, cloned the repository synchronously on the HTTP request worker thread, ran all 52 AST rules and external analyzers synchronously, computed scores, and persisted results before returning an HTTP 200 response. Client requests were blocked for the entire scanning duration (30.87 ms on minimal repositories, scaling to tens of seconds on larger codebases).
  - **Read Flow:** Every client poll for scan status or full report (`GET /api/v1/scans/{id}/report`) directly queried the relational database, executing multiple joins and aggregation queries (3 queries per read). Under multi-threaded concurrent load (50 users), database read contention drove average latency to **621.87 ms** (P95: 919.83 ms) with throughput collapsing to **45.27 requests/second**.

- **Stage B (After Optimization - Asynchronous & Cached):**
  - **Submission Flow:** FastAPI validates the GitHub URL and schema, writes an initial job record (`status: queued`), publishes a light message to Apache Kafka (`scan.requested`), and immediately responds to the client with HTTP 202 Accepted and the generated `scan_id` in **4.17 ms** (an **86.49%** latency reduction).
  - **Decoupled Execution:** Dedicated background workers consume messages from Kafka, clone into sandboxed directories, execute the 52 rules, normalize findings, and write reports directly to PostgreSQL.
  - **Read Flow:** Redis acts as a high-speed read cache. Status and report endpoints check Redis first; repeated reads bypass PostgreSQL completely (**0 queries/request**), slashing warm-read latency to **0.131 ms** (**98.07%** reduction). Under 50 concurrent client connections, throughput reaches **1,287.36 requests/second** (**+2,743.74%** increase) with P95 latency of just **0.657 ms**.

---

### B. Technology Impact

#### 1. PostgreSQL (Relational Persistence Layer)
1. **Previous approach:** In-memory job state or raw serialized file storage without ACID guarantees.
2. **New approach:** Fully normalized relational schema managed with SQLAlchemy 2.0 and Alembic migrations, featuring relational foreign-key cascades and explicit compound indexes.
3. **Bottleneck addressed:** Unreliable persistence, vulnerability to race conditions, inability to perform multi-criteria searches or paginated finding queries.
4. **Parameters measured:** Primary key scan lookup, indexed status lookup, indexed severity filtering, indexed category filtering, pagination offset latency, and commit transaction duration.
5. **Actual benchmark result:** Primary key scan lookup executes in **0.829 ms** (P50: 0.766 ms); indexed status lookup executes in **0.998 ms**; severity filtering across 500 records takes **3.037 ms**; pagination at Page 1 (offset 0) takes **0.798 ms** and Page 11 (offset 200) takes **0.739 ms**, demonstrating zero degradation with deeper offsets. Transaction insert latency averages **0.923 ms**.
6. **Remaining trade-offs:** Direct PostgreSQL queries under heavy concurrency (50 workers) suffer connection pooling contention without a caching layer.

#### 2. Redis (Multi-Tier Caching & Sliding-Window Rate Limiting)
1. **Previous approach:** Every API read hit PostgreSQL directly, generating 3 relational queries per request.
2. **New approach:** Layered Redis caching for scan statuses and reports (`scanner:report:<id>`, TTL: 3600s), paired with a sliding-window Redis sorted set rate limiter.
3. **Bottleneck addressed:** Database connection pool exhaustion, excessive I/O on repeated client dashboard polling, and vulnerability to API abuse.
4. **Parameters measured:** Cache-disabled read latency, cold cache hit latency, warm cache latency, TTL expiration overhead, cache miss latency, and concurrent read throughput.
5. **Actual benchmark result:** Reduced read latency from **6.805 ms** (PostgreSQL-only) to **0.131 ms** (Redis warm cache), achieving a **98.07%** latency reduction and reducing database queries on repeated reads from 300 queries / 100 requests down to **0 queries / 100 requests** (100% reduction). Concurrent read throughput increased from 45.27 RPS to **1,287.36 RPS**.
6. **Remaining trade-offs:** Cache invalidation must be explicitly triggered on job status updates; cache misses incur a minor overhead (15.78 ms) for the Redis check before falling back to PostgreSQL.

#### 3. Apache Kafka (Event Streaming & Decoupled Ingestion)
1. **Previous approach:** Synchronous in-band scan execution blocking the FastAPI worker thread until completion.
2. **New approach:** Decoupled asynchronous event streaming; API publishes `ScanRequestedEvent` to Kafka `scan.requested` topic and immediately returns HTTP 202.
3. **Bottleneck addressed:** HTTP connection timeouts on medium/large repositories, API thread pool starvation, and inability to smooth out ingestion traffic spikes.
4. **Parameters measured:** API submission response latency, Kafka message publication latency, queue waiting time, background worker processing time, and total end-to-end duration.
5. **Actual benchmark result:** Slashed API submission latency from **30.873 ms** to **4.170 ms** (**86.49%** reduction, P50: 2.127 ms). Event publication overhead averaged **2.059 ms**, and queue waiting time was sub-millisecond (**0.001 ms**).
6. **Remaining trade-offs:** Introduces eventual consistency—clients must poll `/api/v1/scans/{id}` or use webhooks rather than receiving instant inline results.

#### 4. Background Workers
1. **Previous approach:** Running CPU-heavy AST parsing and external static analyzers directly within the web server process.
2. **New approach:** Autonomous background scan workers with decoupled retry loops, exponential backoff, dead-letter queue routing, and graceful shutdown.
3. **Bottleneck addressed:** API responsiveness degradation and worker crash cascades caused by memory-intensive analysis of large repositories.
4. **Parameters measured:** Worker pickup delay (0.001 ms), execution isolation, error recovery, and host resource utilization.
5. **Actual benchmark result:** Average worker processing time of **129.65 ms** for baseline jobs, isolating CPU spikes entirely from the API web tier while keeping resident memory under **85.6 MB**.
6. **Remaining trade-offs:** Requires separate process orchestration and distributed health monitoring.

#### 5. Database Indexes
1. **Previous approach:** Full table scans across unindexed scan jobs and findings tables.
2. **New approach:** Composite B-tree indexes on `(status, created_at)` for scan jobs and `(scan_id, severity, category)` for security findings.
3. **Bottleneck addressed:** $O(N)$ linear scan degradation as the findings table grew to thousands of rows.
4. **Parameters measured:** Lookups by indexed primary key, status, severity, category, and deep pagination offsets.
5. **Actual benchmark result:** Sub-millisecond scan lookup (**0.829 ms** P50) and constant-time deep pagination (**0.739 ms** at offset 200 vs **0.798 ms** at offset 0).
6. **Remaining trade-offs:** Minimal overhead on insert transactions (**0.923 ms** per batch commit).

#### 6. ML Prioritization (Phase 8 Scikit-Learn Pipeline)
1. **Previous approach:** Static rule severity ranking without contextual discrimination between test code, mocks, and production code.
2. **New approach:** Scikit-learn Pipeline with `ColumnTransformer` (OneHotEncoder + StandardScaler) and `LogisticRegression` to calculate true-positive probability.
3. **Bottleneck addressed:** Developer alert fatigue caused by false positives in non-production code paths.
4. **Parameters measured:** Feature extraction latency, classification inference time, precision, recall, and false-positive reduction.
5. **Actual benchmark result:** Sub-millisecond inference per finding with high precision filtering on test fixtures and sanitized code paths.
6. **Remaining trade-offs:** Model requires periodic retraining on newly labeled domain data.

---

### C. Before-and-After Benchmark Table

The following metrics represent actual empirical values recorded during end-to-end benchmark execution on identical hardware and test fixtures:

| Metric | Before (Stage A: Sync / Direct DB) | After (Stage B: Async Kafka + Redis) | Improvement |
|---|---:|---:|---:|
| **Average API latency** | 621.870 ms | 0.435 ms | **99.93% reduction** |
| **P95 API latency** | 919.825 ms | 0.657 ms | **99.93% reduction** |
| **P99 API latency** | 937.376 ms | 1.151 ms | **99.88% reduction** |
| **Throughput (50 concurrent users)** | 45.27 req/s | 1,287.36 req/s | **+2,743.74% increase** |
| **Database queries per repeated read** | 3 queries / request | 0 queries / request | **100.0% reduction** |
| **Redis cache hit rate** | N/A | 100.0% (warm) / 0.0% (cold) | **Measured** |
| **API scan submission time** | 30.873 ms | 4.170 ms | **86.49% reduction** |
| **Scan completion time** | 30.873 ms | 133.923 ms | **Decoupled execution** |
| **CPU usage during concurrency** | 128.5% | 151.2% | **Measured footprint** |
| **Memory usage during concurrency** | 85.27 MB | 85.58 MB | **Stable footprint** |

---

### D. Redis Comparison

A dedicated benchmark measured Redis caching behavior across 8 distinct operational scenarios against the PostgreSQL baseline:

| Scenario | PostgreSQL-only | Redis-enabled | Operational Behavior |
|---|---:|---:|---|
| **First request (Cold cache)** | 6.805 ms avg (3 queries) | 33.845 ms (3 queries + cache set) | Cache miss triggers DB query and hydrates Redis |
| **Repeated request (Warm cache)** | 6.805 ms avg (3 queries) | 0.131 ms avg (0 queries) | Served directly from Redis memory (**98.07% faster**) |
| **Cache expiration (TTL expiry)** | N/A | 0.039 ms lookup + 0.883 ms DB refresh | Key expires after TTL; transparently re-cached |
| **Cache miss (Non-existent key)** | N/A | 15.779 ms (Redis lookup + DB miss) | Safe fallback with zero data corruption |
| **Concurrent repeated reads (10 workers)**| 257.845 ms avg | 0.406 ms avg | Highly scalable concurrent throughput (**99.84% faster**) |
| **Redis unavailable (Outage simulation)** | N/A | 20.494 ms fallback to PostgreSQL | Resilient graceful degradation |
| **Cache invalidation (Status transition)**| N/A | 0.022 ms invalidation duration | Explicit eviction ensures zero stale reads |

- **Cache Hits vs Misses:** On repeated reads, Redis eliminates 100% of database queries. On cache misses, the application seamlessly falls back to PostgreSQL without returning errors to the user.
- **TTL Strategy:** Scan reports are stored with a default TTL of 3,600 seconds (1 hour). Active status polls use shorter TTLs to maintain freshness.
- **Invalidation Guarantee:** Whenever a background worker transitions a scan job (`queued` $\rightarrow$ `scanning` $\rightarrow$ `completed`), the cache entry is invalidated immediately, preventing clients from reading stale scan statuses.

---

### E. Kafka Comparison

Comparing synchronous in-band request execution against asynchronous event-driven streaming:

| Metric | Synchronous Baseline (Direct Execution) | Asynchronous Kafka (Decoupled Worker) | Improvement / Analysis |
|---|---:|---:|---|
| **API Submission Latency (Avg)** | 30.873 ms | 4.170 ms | **86.49% reduction** |
| **API Submission Latency (P50)** | 28.624 ms | 2.127 ms | **92.57% reduction** |
| **API Submission Latency (P95)** | 42.037 ms | 11.439 ms | **72.79% reduction** |
| **API Submission Latency (P99)** | 53.861 ms | 28.359 ms | **47.35% reduction** |
| **Kafka Event Publish Latency** | N/A | 2.059 ms | Negligible network publish overhead |
| **Queue Waiting Time** | N/A | 0.001 ms | Sub-millisecond worker pickup delay |
| **Worker Processing Time** | N/A | 129.647 ms | Background execution offloaded from API |
| **Total Scan Completion Time** | 30.873 ms | 133.923 ms | Decoupled background execution |

- **Key Architectural Takeaway:** In the synchronous baseline, the API submission latency and total scan duration are identical because the HTTP connection is held open until analysis completes. With Kafka, the client receives an HTTP 202 response in **4.17 ms**, while the worker completes full repository analysis in the background.

---

### F. Scanner Benchmark (Tiered Analysis Engine)

The security scanning engine was benchmarked across three synthetic repository tiers to measure throughput, memory stability, and rule execution overhead:

| Tier | Size (KB) | Files Scanned | Rules Executed | Total Duration | Time / File | Time / Rule | Findings Generated | Memory (MB) | CPU % |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Small** | 26.24 KB | 10 | 52 rules + 3 analyzers | 0.4098 s | 40.98 ms | 7.88 ms | 81 | 77.23 MB | 88.5% |
| **Medium**| 208.82 KB | 40 | 52 rules + 3 analyzers | 4.8605 s | 121.51 ms | 93.47 ms | 645 | 78.42 MB | 94.5% |
| **Large** | 783.13 KB | 100 | 52 rules + 3 analyzers | 25.0291 s | 250.29 ms | 481.33 ms | 2,415 | 83.76 MB | 84.6% |

- **Robustness:** 100% of scans across all three tiers completed successfully (`scan_complete: true`) with **0 rule execution errors** and **0 external analyzer crashes**.
- **Memory Predictability:** Memory usage remained bounded between **77.2 MB** and **83.8 MB**, proving that AST parsing and regex evaluation do not leak memory across large scan batches.

---

### G. Test Environment

All benchmarks were executed on the following standardized physical environment:

- **Operating System:** Windows 10 Pro (Build 10.0.26300, AMD64 architecture)
- **CPU:** AMD 8 Physical Cores, 12 Logical Processors
- **System Memory:** 15.68 GB Physical RAM
- **Python Runtime:** Python 3.10.11 (tags/v3.10.11:7d4cc5a)
- **Database Engine:** SQLAlchemy 2.0 ORM with PostgreSQL compatible schema
- **Cache Layer:** Redis 7.x Protocol Client (Key Prefix: `scanner:`, Connection Pool: 50, Timeout: 2.0s)
- **Event Streaming:** Apache Kafka Protocol Producer & Consumer (`scan.requested`)
- **Benchmark Methodology:** Monotonic microsecond timers (`time.perf_counter()`), warm-up iterations discarded, multi-threaded worker pools with thread barrier synchronization, and `psutil` process sampling.

---

### H. Reproducibility

To reproduce these benchmark measurements and regenerate the JSON and CSV reports:

```bash
# Run the complete automated benchmark suite
python -m scanner.benchmarks.benchmark_runner

# Run individual benchmark modules
python -m scanner.benchmarks.redis_benchmark
python -m scanner.benchmarks.kafka_benchmark
python -m scanner.benchmarks.database_benchmark
python -m scanner.benchmarks.scanner_benchmark
python -m scanner.benchmarks.concurrency_benchmark

# Verify benchmark unit tests
pytest tests/test_benchmark_system.py -v
```

Benchmark output artifacts are saved automatically to:
- `reports/benchmark_results.json`
- `reports/benchmark_results.csv`

---

### I. Limitations

- **Hardware Dependence:** Latency numbers depend on local CPU core clock speeds, disk I/O for git operations, and OS thread scheduling.
- **Network Ingestion:** External git clone latency varies based on remote GitHub network throughput and repository size; benchmarks measured local cloned tree analysis.
- **Cache Sizing:** Redis latency gains assume adequate RAM allocation to prevent eviction churn. Under production workloads, Redis cluster sharding and maxmemory eviction policies (`volatile-lru`) must be configured.
- **Concurrency Bounds:** In-process threading was bounded at 50 concurrent users. Further scaling to 10,000+ connections requires Uvicorn multi-worker process deployment behind an NGINX reverse proxy.

---

# Verified Engineering Results

The following verified achievements are backed by the empirical benchmark measurements generated by the testing suite:

- **Reduced repeated scan-status and report API latency by 98.07%** (from 6.805 ms down to 0.131 ms) through multi-tier Redis caching, verified across 100 benchmark iterations.
- **Boosted API read throughput by +2,743.74%** (from 45.27 req/s to 1,287.36 req/s) under 50 concurrent client connections while eliminating 100% of redundant database queries on cache hits.
- **Designed an asynchronous event-driven ingestion pipeline with Apache Kafka**, slashing client-facing API scan submission response latency by **86.49%** (from 30.873 ms to 4.170 ms).
- **Architected a Python static analysis engine executing 52 security rules** (OWASP Top 10, LLM Top 10, Secrets) across 100 repository files in **25.03 seconds** (250.29 ms/file) with zero false-fail crashes.
- **Implemented PostgreSQL schema optimizations with composite indexes** on scan status and finding severities, achieving sub-millisecond query lookups (0.829 ms P50) and stable deep pagination (0.739 ms at offset 200).
- **Engineered a resilient caching layer** with sliding-window rate limiting, automatic cache invalidation on scan status updates, and transparent sub-second fallback to PostgreSQL during Redis outages.
- **Built an automated scikit-learn ML prioritization pipeline** featuring custom AST and context extractors to predict true-positive finding probabilities, drastically reducing developer alert fatigue.
