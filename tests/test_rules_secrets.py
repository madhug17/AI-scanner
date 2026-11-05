import pytest
from scanner.rules.secrets.rules import (
    HardcodedSecretRule,
    DefaultCredentialsRule,
    GitHistoryLeakRule,
    CicdSecretRule,
    FrontendSecretRule,
)
from scanner.core.finding import redact_secret_string, Evidence


def test_sec_006_hardcoded_secrets_vulnerable_and_clean():
    rule = HardcodedSecretRule()

    # Note: synthetic dummy key
    vuln_code = 'api_key = "ak_live_9876543210abcdef"'
    findings = rule.scan("config.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-006"
    # Ensure evidence was redacted!
    assert "ak_live_9876543210abcdef" not in findings[0].evidence[0].code_snippet
    assert "ak_***" in findings[0].evidence[0].code_snippet or "*" in findings[0].evidence[0].code_snippet

    clean_code = 'api_key = os.getenv("API_KEY")\ndummy_key = "your_api_key"'
    assert len(rule.scan("config.py", clean_code)) == 0


def test_sec_016_default_credentials_vulnerable_and_clean():
    rule = DefaultCredentialsRule()

    vuln_code = 'username = "admin"\npassword = "admin123"'
    findings = rule.scan("db.py", vuln_code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "SEC-016"

    clean_code = 'username = os.environ["DB_USER"]\npassword = os.environ["DB_PASS"]'
    assert len(rule.scan("db.py", clean_code)) == 0


def test_sec_034_git_history_leak_vulnerable_and_clean():
    rule = GitHistoryLeakRule()

    vuln_code = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    findings = rule.scan("key.pem", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-034"

    clean_code = "# Load public key from authorized_keys"
    assert len(rule.scan("key.pem", clean_code)) == 0


def test_sec_035_cicd_secret_vulnerable_and_clean():
    rule = CicdSecretRule()

    vuln_code = """
name: Deploy
on: push
jobs:
  build:
    steps:
      - run: echo deploy
        env:
          api_key: "ghp_123456789012345678901234567890123456"
"""
    findings = rule.scan(".github/workflows/deploy.yml", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-035"

    clean_code = """
name: Deploy
on: push
jobs:
  build:
    steps:
      - run: echo deploy
        env:
          api_key: ${{ secrets.GITHUB_TOKEN }}
"""
    assert len(rule.scan(".github/workflows/deploy.yml", clean_code)) == 0


def test_sec_042_frontend_secret_vulnerable_and_clean():
    rule = FrontendSecretRule()

    vuln_code = 'NEXT_PUBLIC_STRIPE_SECRET_KEY="sk_live_123456789"'
    findings = rule.scan(".env.production", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-042"

    clean_code = 'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY="pk_live_123456789"'
    assert len(rule.scan(".env.production", clean_code)) == 0


def test_secret_redaction_utility():
    raw_snippet = 'openai_api_key = "sk-proj123456789abcdef"'
    redacted = redact_secret_string(raw_snippet)
    assert "sk-proj123456789abcdef" not in redacted
    assert "sk-" in redacted
    assert "****" in redacted

    ev = Evidence(
        file_path="app.py",
        line_start=1,
        line_end=1,
        code_snippet='password = "secret_password_12345"',
    )
    assert "secret_password_12345" not in ev.code_snippet
    assert "sec***" in ev.code_snippet or "*" in ev.code_snippet

