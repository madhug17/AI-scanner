# AI App Security & Quality Scanner — Architectural Design Document

## 1. Executive Architecture Summary

The **AI App Security & Quality Scanner** is an enterprise-grade static analysis platform designed to inspect source-code repositories for security vulnerabilities, secrets exposure, configuration weaknesses, and AI/LLM-specific attack vectors without executing untrusted code on the host machine.

### System Topology

```
+---------------------------------------------------------------------------------+
|                                Frontend Tier                                   |
|   Pure HTML5 + Modern ES6+ JavaScript + Tailwind CSS (Cybersecurity Dark Theme) |
|   - Real-time Chart.js visual telemetry & severity distribution                |
|   - 10-stage live scan progress polling                                        |
|   - Interactive findings table with search, filters, and code drawer           |
+----------------------------------------+----------------------------------------+
                                         | REST / JSON / HTTP 202
                                         v
+---------------------------------------------------------------------------------+
|                                 API Gateway                                     |
|   FastAPI Web Server (Async ASGI)                                               |
|   - GitHub URL syntax & SSRF safety validation                                 |
|   - Redis sliding-window API rate limiting                                     |
|   - JWT authentication & RBAC authorization                                    |
|   - Prometheus exposition & Kubernetes health probes                           |
+--------------------+-----------------------------------+------------------------+
                     |                                   |
    Persist Job      |                                   | Publish Event
    (queued)         v                                   v
+-----------------------------+                 +---------------------------------+
|     PostgreSQL Database     |                 |       Apache Kafka Cluster      |
| - Users & Repositories      |                 | Topics:                         |
| - Scan Jobs & Summaries     |                 |  - scan.requested               |
| - Findings & Evidence       |                 |  - scan.completed               |
| - Audit & Scan Events       |                 |  - scan.failed                  |
+-----------------------------+                 +----------------+----------------+
                                                                 |
                                                  Consume Event  | Consumer Group
                                                                 v
+---------------------------------------------------------------------------------+
|                             Distributed Scan Workers                           |
|   Python Worker Daemon (Sandboxed Zero-Execution)                              |
|   - Safe Shallow Git Clone (depth=1, timeouts, permission isolation)           |
|   - File Discovery (.git, virtualenvs, large binary ignores)                   |
|   - 52-Rule Static Analysis Engine (Python AST, Regex, Config Parsing)         |
|   - External Adapters (Semgrep, Gitleaks, pip-audit, OSV)                      |
|   - Secret Redaction & Normalization                                           |
|   - Formula-based Risk Scoring Service (0-100)                                 |
+--------------------+------------------------------------------------------------+
                     |
                     | Invalidate & Cache
                     v
+---------------------------------------------------------------------------------+
|                                   Redis Tier                                    |
|   - Scan status & report caching (TTL: 3600s, sub-millisecond warm reads)       |
|   - Sliding-window rate limit counters                                          |
|   - In-memory graceful fallback if Redis cluster is offline                     |
+---------------------------------------------------------------------------------+
```

---

## 2. Core Architectural Principles

1. **Zero-Code Execution Guarantee:** We scan untrusted user repositories. Code is analyzed strictly using Abstract Syntax Tree (AST) parsing, lexical analysis, and regular expressions. Repositories are never compiled, executed, or imported.
2. **Asynchronous Distributed Processing:** Heavy repository analysis is decoupled from the web tier via Apache Kafka. API endpoints accept scans in $<5$ ms with HTTP 202, preventing thread starvation.
3. **Resilient Multi-Tier Caching:** Redis caches active scan status and completed reports. When Redis is unavailable, the application degrades gracefully to in-memory caching and direct PostgreSQL reads with zero crashes.
4. **Permanent Secret Masking:** Any detected secret (API key, token, private key) is redacted in memory before database persistence or presentation in reports.

