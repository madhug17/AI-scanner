import pytest
from scanner.rules.configuration.rules import (
    HttpsEnforcementRule,
    FileUploadSafetyRule,
    CorsRule,
    DebugExposureRule,
    SecurityHeadersRule,
    CsrfProtectionRule,
    DatabaseExposureRule,
    CloudStorageRule,
    ContainerInfraRule,
)
from scanner.rules.dependencies.rules import (
    DependencyVulnerabilitiesRule,
    SuspiciousPackagesRule,
)


def test_sec_005_https_enforcement_vulnerable_and_clean():
    rule = HttpsEnforcementRule()

    vuln_code = 'requests.get("https://example.com", verify=False)'
    findings = rule.scan("client.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-005"

    clean_code = 'requests.get("https://example.com", verify=True)'
    assert len(rule.scan("client.py", clean_code)) == 0


def test_sec_023_file_upload_safety_vulnerable_and_clean():
    rule = FileUploadSafetyRule()

    vuln_code = """
@app.post("/upload")
async def upload(file: UploadFile):
    contents = await file.read()
    with open("uploads/" + file.filename, "wb") as f:
        f.write(contents)
"""
    findings = rule.scan("upload.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-023"

    clean_code = """
ALLOWED_EXTENSIONS = {".png", ".jpg"}
@app.post("/upload")
async def upload(file: UploadFile):
    ext = os.path.splitext(file.filename)[1]
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400)
"""
    assert len(rule.scan("upload.py", clean_code)) == 0


def test_sec_025_cors_vulnerable_and_clean():
    rule = CorsRule()

    vuln_code = """
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)
"""
    findings = rule.scan("main.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-025"

    clean_code = """
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted.app.com"],
    allow_credentials=True,
)
"""
    assert len(rule.scan("main.py", clean_code)) == 0


def test_sec_026_debug_exposure_vulnerable_and_clean():
    rule = DebugExposureRule()

    vuln_code = "DEBUG = True\napp.run(debug=True)"
    findings = rule.scan("settings.py", vuln_code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "SEC-026"

    clean_code = "DEBUG = os.getenv('APP_DEBUG', 'False').lower() == 'true'"
    assert len(rule.scan("settings.py", clean_code)) == 0


def test_sec_027_security_headers_vulnerable_and_clean():
    rule = SecurityHeadersRule()

    vuln_code = 'headers["X-Frame-Options"] = "ALLOW-FROM https://untrusted.com"'
    findings = rule.scan("headers.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-027"

    clean_code = 'headers["X-Frame-Options"] = "DENY"'
    assert len(rule.scan("headers.py", clean_code)) == 0


def test_sec_028_csrf_vulnerable_and_clean():
    rule = CsrfProtectionRule()

    vuln_code = """
@csrf_exempt
def handle_post_payment(request):
    return process_payment(request)
"""
    findings = rule.scan("views.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-028"

    clean_code = """
def handle_post_payment(request):
    return process_payment(request)
"""
    assert len(rule.scan("views.py", clean_code)) == 0


def test_sec_029_database_exposure_vulnerable_and_clean():
    rule = DatabaseExposureRule()

    vuln_code = """
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
"""
    findings = rule.scan("firestore.rules", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-029"

    clean_code = """
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.auth != null;
    }
  }
}
"""
    assert len(rule.scan("firestore.rules", clean_code)) == 0


def test_sec_030_cloud_storage_vulnerable_and_clean():
    rule = CloudStorageRule()

    vuln_code = """
resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "public-read"
}
"""
    findings = rule.scan("s3.tf", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-030"

    clean_code = """
resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "private"
}
"""
    assert len(rule.scan("s3.tf", clean_code)) == 0


def test_sec_031_container_infra_vulnerable_and_clean():
    rule = ContainerInfraRule()

    vuln_code = """
FROM python:3.10
USER root
CMD ["python", "app.py"]
"""
    findings = rule.scan("Dockerfile", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-031"

    clean_code = """
FROM python:3.10-slim
RUN useradd -m appuser
USER appuser
CMD ["python", "app.py"]
"""
    assert len(rule.scan("Dockerfile", clean_code)) == 0


def test_sec_032_dependency_vuln_vulnerable_and_clean():
    rule = DependencyVulnerabilitiesRule()

    vuln_code = "requests==2.19.0\nurllib3==1.24.1"
    findings = rule.scan("requirements.txt", vuln_code)
    assert len(findings) == 2
    assert findings[0].rule_id == "SEC-032"

    clean_code = "requests==2.31.0\nurllib3==2.2.1"
    assert len(rule.scan("requirements.txt", clean_code)) == 0


def test_sec_033_suspicious_packages_vulnerable_and_clean():
    rule = SuspiciousPackagesRule()

    vuln_code = "colourama==0.4.6\nreqeusts==2.31.0"
    findings = rule.scan("requirements.txt", vuln_code)
    assert len(findings) == 2
    assert findings[0].rule_id == "SEC-033"

    clean_code = "colorama==0.4.6\nrequests==2.31.0"
    assert len(rule.scan("requirements.txt", clean_code)) == 0

