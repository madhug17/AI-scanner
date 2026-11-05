import pytest
from scanner.rules.injection.rules import (
    SqlInjectionRule,
    CommandInjectionRule,
    XssRule,
    PathTraversalRule,
    SsrfRule,
    NosqlInjectionRule,
    UnsafeDeserializationRule,
)


def test_sec_008_sql_injection_vulnerable_and_clean():
    rule = SqlInjectionRule()

    vuln_code = """
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
"""
    findings = rule.scan("repo.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-008"

    clean_code = """
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
"""
    assert len(rule.scan("repo.py", clean_code)) == 0


def test_sec_018_command_injection_vulnerable_and_clean():
    rule = CommandInjectionRule()

    vuln_code = """
import os
os.system("ping " + user_ip)
"""
    findings = rule.scan("network.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-018"

    clean_code = """
import subprocess
subprocess.run(["ping", "-c", "1", "127.0.0.1"], shell=False, check=True)
"""
    assert len(rule.scan("network.py", clean_code)) == 0


def test_sec_019_xss_vulnerable_and_clean():
    rule = XssRule()

    vuln_code = """
html = render_template_string("<h1>Welcome " + user_input + "</h1>")
"""
    findings = rule.scan("views.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-019"

    clean_code = """
html = render_template("welcome.html", user=user_input)
"""
    assert len(rule.scan("views.py", clean_code)) == 0


def test_sec_020_path_traversal_vulnerable_and_clean():
    rule = PathTraversalRule()

    vuln_code = """
with open(request.params["file"], "r") as f:
    data = f.read()
"""
    findings = rule.scan("files.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-020"

    clean_code = """
safe_name = os.path.basename(user_filename)
target = (BASE_DIR / safe_name).resolve()
"""
    assert len(rule.scan("files.py", clean_code)) == 0


def test_sec_021_ssrf_vulnerable_and_clean():
    rule = SsrfRule()

    vuln_code = """
res = requests.get(user_url)
"""
    findings = rule.scan("proxy.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-021"

    clean_code = """
res = requests.get("https://api.github.com/zen")
"""
    assert len(rule.scan("proxy.py", clean_code)) == 0


def test_sec_022_nosql_injection_vulnerable_and_clean():
    rule = NosqlInjectionRule()

    vuln_code = """
db.users.find({"$where": "this.name == '" + user + "'"})
"""
    findings = rule.scan("mongo.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-022"

    clean_code = """
db.users.find({"username": str(user_id)})
"""
    assert len(rule.scan("mongo.py", clean_code)) == 0


def test_sec_024_unsafe_deserialization_vulnerable_and_clean():
    rule = UnsafeDeserializationRule()

    vuln_code = """
obj = pickle.loads(user_payload)
"""
    findings = rule.scan("serializer.py", vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-024"

    clean_code = """
obj = json.loads(user_payload)
config = yaml.safe_load(yaml_str)
"""
    assert len(rule.scan("serializer.py", clean_code)) == 0

