import pytest
from scanner.rules.ai_security.rules import (
    AiSecurityRule,
    PromptInjectionRule,
    InsecureOutputHandlingRule,
    ExcessiveAgencyRule,
    SystemPromptLeakageRule,
    LlmCostAbuseRule,
    RagDataIsolationRule,
    LlmApiKeyExposureRule,
    PiiToLlmRule,
    UnsafeModelLoadingRule,
    ToolMcpPermissionsRule,
)


def test_sec_010_ai_security_vulnerable_and_clean():
    rule = AiSecurityRule()

    vuln_code = """
prompt = f"Summarize {raw_user_input}"
res = openai.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])
"""
    findings = rule.scan("ai.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-010"

    clean_code = """
sanitized = guardrail.sanitize(raw_user_input)
res = openai.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": sanitized}])
"""
    assert len(rule.scan("ai.py", clean_code)) == 0


def test_sec_043_prompt_injection_vulnerable_and_clean():
    rule = PromptInjectionRule()

    vuln_code = """
messages = [{"role": "system", "content": f"You are a helper. Context: {user_input}"}]
"""
    findings = rule.scan("llm.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-043"

    clean_code = """
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": user_input}
]
"""
    assert len(rule.scan("llm.py", clean_code)) == 0


def test_sec_044_insecure_output_handling_vulnerable_and_clean():
    rule = InsecureOutputHandlingRule()

    vuln_code = """
code_snippet = response.choices[0].message.content
eval(code_snippet)
"""
    findings = rule.scan("agent.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-044"

    clean_code = """
code_snippet = response.choices[0].message.content
parsed_ast = ast.parse(code_snippet)
"""
    assert len(rule.scan("agent.py", clean_code)) == 0


def test_sec_045_excessive_agency_vulnerable_and_clean():
    rule = ExcessiveAgencyRule()

    vuln_code = """
agent = initialize_agent(tools=[BashProcess(), TerminalTool()], allow_dangerous_tools=True)
"""
    findings = rule.scan("agent_tools.py", vuln_code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "SEC-045"

    clean_code = """
agent = initialize_agent(tools=[CalculatorTool(), WeatherLookupTool()])
"""
    assert len(rule.scan("agent_tools.py", clean_code)) == 0


def test_sec_046_system_prompt_leakage_vulnerable_and_clean():
    rule = SystemPromptLeakageRule()

    vuln_code = 'system_prompt = "You are a bot. SECRET_KEY=sk_internal_99999999"'
    findings = rule.scan("prompts.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-046"

    clean_code = 'system_prompt = "You are an AI customer support assistant."'
    assert len(rule.scan("prompts.py", clean_code)) == 0


def test_sec_047_llm_cost_abuse_vulnerable_and_clean():
    rule = LlmCostAbuseRule()

    vuln_code = """
client.chat.completions.create(model="gpt-4", messages=messages)
"""
    findings = rule.scan("client.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-047"

    clean_code = """
client.chat.completions.create(model="gpt-4", messages=messages, max_tokens=1000)
"""
    assert len(rule.scan("client.py", clean_code)) == 0


def test_sec_048_rag_data_isolation_vulnerable_and_clean():
    rule = RagDataIsolationRule()

    vuln_code = """
docs = vector_store.similarity_search(query)
"""
    findings = rule.scan("rag.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-048"

    clean_code = """
docs = vector_store.similarity_search(query, filter={"tenant_id": current_tenant.id})
"""
    assert len(rule.scan("rag.py", clean_code)) == 0


def test_sec_049_llm_api_key_exposure_vulnerable_and_clean():
    rule = LlmApiKeyExposureRule()

    vuln_code = 'NEXT_PUBLIC_OPENAI_API_KEY="sk-proj1234567890abcdef"'
    findings = rule.scan(".env.local", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-049"

    clean_code = 'OPENAI_API_KEY="sk-proj1234567890abcdef"'
    assert len(rule.scan(".env.local", clean_code)) == 0


def test_sec_050_pii_to_llm_vulnerable_and_clean():
    rule = PiiToLlmRule()

    vuln_code = """
messages = [{"role": "user", "content": f"Process customer ssn: {customer.ssn}"}]
client.chat.completions.create(messages=messages)
"""
    findings = rule.scan("compliance.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-050"

    clean_code = """
masked_ssn = anonymize(customer.ssn)
messages = [{"role": "user", "content": f"Customer ID: {customer.id}"}]
"""
    assert len(rule.scan("compliance.py", clean_code)) == 0


def test_sec_051_unsafe_model_loading_vulnerable_and_clean():
    rule = UnsafeModelLoadingRule()

    vuln_code = "model = AutoModel.from_pretrained('untrusted/repo', trust_remote_code=True)"
    findings = rule.scan("model.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-051"

    clean_code = "model = AutoModel.from_pretrained('bert-base-uncased', trust_remote_code=False)"
    assert len(rule.scan("model.py", clean_code)) == 0


def test_sec_052_tool_mcp_permissions_vulnerable_and_clean():
    rule = ToolMcpPermissionsRule()

    vuln_code = """
mcp_config = {"permissions": ["*"]}
"""
    findings = rule.scan("mcp.json", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-052"

    clean_code = """
mcp_config = {"permissions": ["read:calendar", "read:contacts"]}
"""
    assert len(rule.scan("mcp.json", clean_code)) == 0

