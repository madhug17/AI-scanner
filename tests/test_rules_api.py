import pytest
from scanner.rules.api_security.rules import (
    MassAssignmentRule,
    InputValidationRule,
    ExcessiveDataExposureRule,
    ErrorHandlingRule,
    LoggingHygieneRule,
    PaginationRule,
    WebhookVerificationRule,
    PaymentTamperingRule,
)


def test_sec_013_mass_assignment_vulnerable_and_clean():
    rule = MassAssignmentRule()

    vuln_code = """
# is_admin field exists on user
user = User(**request.json)
"""
    findings = rule.scan("users.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-013"

    clean_code = """
user = User(username=schema.username, email=schema.email)
"""
    assert len(rule.scan("users.py", clean_code)) == 0


def test_sec_017_input_validation_vulnerable_and_clean():
    rule = InputValidationRule()

    vuln_code = """
async def create_item(request: Request):
    data = await request.json()
    return save_to_db(data)
"""
    findings = rule.scan("items.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-017"

    clean_code = """
class ItemCreate(BaseModel):
    name: str

async def create_item(item: ItemCreate):
    return save_to_db(item)
"""
    assert len(rule.scan("items.py", clean_code)) == 0


def test_sec_036_excessive_data_exposure_vulnerable_and_clean():
    rule = ExcessiveDataExposureRule()

    vuln_code = """
return {"id": user.id, "email": user.email, "hashed_password": user.hashed_password}
"""
    findings = rule.scan("user_api.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-036"

    clean_code = """
return {"id": user.id, "email": user.email}
"""
    assert len(rule.scan("user_api.py", clean_code)) == 0


def test_sec_037_error_handling_vulnerable_and_clean():
    rule = ErrorHandlingRule()

    vuln_code = """
try:
    process()
except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))
"""
    findings = rule.scan("handler.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-037"

    clean_code = """
try:
    process()
except Exception as e:
    logger.error("Internal processing error", exc_info=True)
    raise HTTPException(status_code=500, detail="Internal server error")
"""
    assert len(rule.scan("handler.py", clean_code)) == 0


def test_sec_038_logging_hygiene_vulnerable_and_clean():
    rule = LoggingHygieneRule()

    vuln_code = 'logger.info(f"User login attempt with password: {password}")'
    findings = rule.scan("auth_log.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-038"

    clean_code = 'logger.info(f"User {user_id} login attempt successful")'
    assert len(rule.scan("auth_log.py", clean_code)) == 0


def test_sec_039_pagination_vulnerable_and_clean():
    rule = PaginationRule()

    vuln_code = "items = db.query(Product).all()"
    findings = rule.scan("products.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-039"

    clean_code = "items = db.query(Product).offset(skip).limit(limit).all()"
    assert len(rule.scan("products.py", clean_code)) == 0


def test_sec_040_webhook_verification_vulnerable_and_clean():
    rule = WebhookVerificationRule()

    vuln_code = """
@app.post("/api/stripe/webhook")
async def stripe_webhook(payload: dict):
    event_type = payload.get("type")
    return {"status": "received"}
"""
    findings = rule.scan("webhooks.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-040"

    clean_code = """
@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request):
    sig = request.headers.get("stripe-signature")
    event = stripe.Webhook.construct_event(await request.body(), sig, WEBHOOK_SECRET)
    return {"status": "ok"}
"""
    assert len(rule.scan("webhooks.py", clean_code)) == 0


def test_sec_041_payment_tampering_vulnerable_and_clean():
    rule = PaymentTamperingRule()

    vuln_code = """
stripe.PaymentIntent.create(amount=request.data["amount"], currency="usd")
"""
    findings = rule.scan("checkout.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-041"

    clean_code = """
product = get_product(product_id)
stripe.PaymentIntent.create(amount=product.price_cents, currency="usd")
"""
    assert len(rule.scan("checkout.py", clean_code)) == 0

