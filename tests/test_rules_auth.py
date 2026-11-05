import pytest
from scanner.rules.authentication.rules import (
    AuthenticationRule,
    RateLimitingRule,
    JwtSecurityRule,
    CookieSecurityRule,
    PasswordHashingRule,
    AccountEnumerationRule,
    PasswordResetTokenRule,
)
from scanner.rules.authorization.rules import (
    AuthorizationRule,
    IdorBolaRule,
    AdminProtectionRule,
)


def test_sec_001_authentication_vulnerable_and_clean():
    rule = AuthenticationRule()

    # Vulnerable route: no auth parameter or dependency
    vuln_code = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/api/v1/orders")
def get_orders():
    return {"orders": []}
"""
    findings = rule.scan("api/routes.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-001"

    # Clean route: contains Depends(get_current_user)
    clean_code = """
from fastapi import FastAPI, Depends
app = FastAPI()

@app.get("/api/v1/orders")
def get_orders(user=Depends(get_current_user)):
    return {"orders": []}
"""
    clean_findings = rule.scan("api/routes.py", clean_code)
    assert len(clean_findings) == 0


def test_sec_002_authorization_vulnerable_and_clean():
    rule = AuthorizationRule()

    vuln_code = """
@app.get("/orders/{order_id}")
def get_order(order_id: int):
    return db.query(Order).filter(Order.id == order_id).first()
"""
    findings = rule.scan("orders.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-002"

    clean_code = """
@app.get("/orders/{order_id}")
def get_order(order_id: int, current_user=Depends(get_current_user)):
    return db.query(Order).filter(Order.id == order_id, Order.user_id == current_user.id).first()
"""
    clean_findings = rule.scan("orders.py", clean_code)
    assert len(clean_findings) == 0


def test_sec_003_idor_bola_vulnerable_and_clean():
    rule = IdorBolaRule()

    vuln_code = """
@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int):
    return db.query(Invoice).filter(Invoice.id == invoice_id).one()
"""
    findings = rule.scan("invoices.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-003"

    clean_code = """
@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, user=Depends(get_current_user)):
    check_object_permissions(user, invoice_id)
    return db.query(Invoice).filter_by(id=invoice_id, owner_id=user.id).first()
"""
    assert len(rule.scan("invoices.py", clean_code)) == 0


def test_sec_004_rate_limiting_vulnerable_and_clean():
    rule = RateLimitingRule()

    vuln_code = """
@app.post("/api/login")
def login(creds: Credentials):
    return authenticate_user(creds)
"""
    findings = rule.scan("auth.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-004"

    clean_code = """
@app.post("/api/login")
@limiter.limit("5/minute")
def login(creds: Credentials):
    return authenticate_user(creds)
"""
    assert len(rule.scan("auth.py", clean_code)) == 0


def test_sec_007_jwt_security_vulnerable_and_clean():
    rule = JwtSecurityRule()

    vuln_code = """
token = jwt.decode(raw_token, options={"verify_signature": False})
"""
    findings = rule.scan("auth.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-007"

    clean_code = """
token = jwt.decode(raw_token, key=PUBLIC_KEY, algorithms=["RS256"])
"""
    assert len(rule.scan("auth.py", clean_code)) == 0


def test_sec_009_admin_protection_vulnerable_and_clean():
    rule = AdminProtectionRule()

    vuln_code = """
@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int):
    return db.delete_user(user_id)
"""
    findings = rule.scan("admin.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-009"

    clean_code = """
@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, admin=Depends(require_admin)):
    return db.delete_user(user_id)
"""
    assert len(rule.scan("admin.py", clean_code)) == 0


def test_sec_011_cookie_security_vulnerable_and_clean():
    rule = CookieSecurityRule()

    vuln_code = """
response.set_cookie(key="session_id", value="xyz", httponly=False)
"""
    findings = rule.scan("session.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-011"

    clean_code = """
response.set_cookie(key="session_id", value="xyz", httponly=True, secure=True, samesite="lax")
"""
    assert len(rule.scan("session.py", clean_code)) == 0


def test_sec_012_password_hashing_vulnerable_and_clean():
    rule = PasswordHashingRule()

    vuln_code = """
hash_val = hashlib.md5(user_password.encode()).hexdigest()
"""
    findings = rule.scan("users.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-012"

    clean_code = """
hash_val = bcrypt.hashpw(user_password.encode(), bcrypt.gensalt())
"""
    assert len(rule.scan("users.py", clean_code)) == 0


def test_sec_014_account_enumeration_vulnerable_and_clean():
    rule = AccountEnumerationRule()

    vuln_code = """
if not user:
    raise HTTPException(status_code=404, detail="User does not exist")
"""
    findings = rule.scan("login.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-014"

    clean_code = """
if not user:
    raise HTTPException(status_code=401, detail="Invalid username or password")
"""
    assert len(rule.scan("login.py", clean_code)) == 0


def test_sec_015_password_reset_token_vulnerable_and_clean():
    rule = PasswordResetTokenRule()

    vuln_code = """
reset_token = str(random.randint(100000, 999999))
"""
    findings = rule.scan("reset.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-015"

    clean_code = """
reset_token = secrets.token_urlsafe(32)
"""
    assert len(rule.scan("reset.py", clean_code)) == 0

