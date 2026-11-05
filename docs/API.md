# REST API Specification

All API endpoints are documented interactively via OpenAPI / Swagger UI at `/docs` and ReDoc at `/redoc`.

---

## 1. Authentication Endpoints

### Register User
`POST /auth/register` (also `/api/v1/auth/register`)
- **Request Body:**
  ```json
  {
    "email": "dev@example.com",
    "password": "StrongPassword123!",
    "full_name": "Developer Name"
  }
  ```
- **Response (201 Created):**
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "token_type": "bearer",
    "expires_in_hours": 24,
    "user": {
      "id": "uuid",
      "email": "dev@example.com",
      "full_name": "Developer Name",
      "is_admin": false
    }
  }
  ```

### Login User
`POST /auth/login` (also `/api/v1/auth/login`)
- **Response (200 OK):** JWT Bearer Token.

### Current User Profile
`GET /auth/me` (also `/api/v1/auth/me`)
- **Headers:** `Authorization: Bearer <token>`

---

## 2. Repositories Endpoints

### Register Repository
`POST /repositories` (also `/api/v1/repositories`)
- **Request Body:**
  ```json
  {
    "repository_url": "https://github.com/owner/repo",
    "default_branch": "main",
    "is_private": false
  }
  ```

### List Repositories
`GET /repositories?page=1&page_size=20`

### Get Repository Details
`GET /repositories/{id}`

---

## 3. Scanning Endpoints

### Submit Repository for Scan
`POST /scans` (also `/api/v1/scans`)
- **Request Body:**
  ```json
  {
    "repository_url": "https://github.com/owner/repo"
  }
  ```
- **Response (202 Accepted):**
  ```json
  {
    "scan_id": "30cb69ca-51da-4f77-bf2b-97742c64e4f6",
    "status": "queued",
    "message": "Scan job accepted"
  }
  ```

### Get Scan Status
`GET /scans/{scan_id}` (also `/api/v1/scans/{scan_id}`)

### Get Full Security Report
`GET /scans/{scan_id}/report` (also `/scans/{scan_id}/results`)

### Cancel Scan Job
`POST /scans/{scan_id}/cancel`

### Compare Two Scans (Diff)
`GET /scans/{scan_id_a}/compare/{scan_id_b}`
- Compares baseline scan against target scan.
- Returns risk score delta ($\Delta$), new vulnerabilities, resolved vulnerabilities, and persistent findings.

---

## 4. Findings Endpoints

### List Findings
`GET /findings?severity=critical&category=Injection&page=1&page_size=50`

### Get Single Finding
`GET /findings/{finding_id}`

### Update Finding Status
`PATCH /findings/{finding_id}`
- **Request Body:** `{"status": "false_positive"}` (or `resolved`, `confirmed`)

---

## 5. Reports & Export Endpoints

### Download JSON Report
`GET /scans/{scan_id}/report/json` (File attachment)

### Download PDF Report
`GET /scans/{scan_id}/report/pdf` (Publication-grade PDF generated with ReportLab)

---

## 6. System & Observability

### Health Check
`GET /health`

### Readiness Probe
`GET /ready`

### Prometheus Metrics
`GET /metrics`

### Security Rules Catalog
`GET /rules` (also `/api/v1/rules`)

### Aggregate Dashboard Statistics
`GET /api/v1/stats`

