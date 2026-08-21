import re
from typing import Dict, Any, List, Tuple

# Common default credentials frequently used in automated botnets (Mirai, SSH brute-forcers)
COMMON_DEFAULT_CREDS = {
    ("root", "root"), ("root", "admin"), ("root", "123456"), ("root", "toor"),
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("admin", "1234"),
    ("ubuntu", "ubuntu"), ("user", "user"), ("guest", "guest"), ("support", "support"),
    ("ubnt", "ubnt"), ("pi", "raspberry"), ("cisco", "cisco"), ("test", "test")
}

# Attack vector regex signatures
SQLI_PATTERNS = [
    r"(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER|EXEC|TRUNCATE)\b)",
    r"(\bOR\b|\bAND\b)\s+['\"0-9a-zA-Z]+\s*=\s*['\"0-9a-zA-Z]+",
    r"(--|#|/\*|\*/|;\s*$)",
    r"(\bSLEEP\s*\(|\bBENCHMARK\s*\(|\bWAITFOR\s+DELAY\b)",
    r"(\binformation_schema\b|\bpg_catalog\b|\bsys\.tables\b)"
]

TRAVERSAL_PATTERNS = [
    r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c)",
    r"(/etc/passwd|/etc/shadow|/etc/hosts|win\.ini|boot\.ini|cmd\.exe|powershell\.exe)"
]

RCE_PATTERNS = [
    r"(\b(system|exec|passthru|shell_exec|eval|popen|proc_open)\b)",
    r"(;\s*(cat|ls|id|whoami|uname|curl|wget|nc|bash|sh|python|perl)\b)",
    r"(\|\s*(cat|ls|id|whoami|uname|curl|wget|nc|bash|sh|python|perl)\b)",
    r"(`.*?`)",
    r"(\$\(.*?\))"
]

CRED_HUNTING_PATHS = [
    r"(\.env|\.git|\.svn|\.hg|\.DS_Store|wp-config\.php|config\.php|configuration\.php|settings\.py|database\.yml)",
    r"(\.aws/credentials|\.ssh/id_rsa|\.bash_history|backup\.sql|dump\.sql)"
]

EXPLOIT_PAYLOAD_PATTERNS = [
    (r"\$\{jndi:(ldap|rmi|dns|nis|iiop):", "LOG4SHELL", "CRITICAL", 95, "T1190"),
    (r"class\.module\.classLoader", "SPRING4SHELL", "CRITICAL", 95, "T1190"),
    (r"<script.*?>.*?</script>|javascript:|alert\(|onerror=", "CROSS_SITE_SCRIPTING", "MEDIUM", 50, "T1190"),
    (r"(\.php|\.asp|\.aspx|\.jsp|\.cgi)\b", "SCRIPT_PROBE", "LOW", 30, "T1595")
]

class IoCAnalyzer:
    """Analyzes captured attack traffic, extracts IoCs, and maps to MITRE ATT&CK techniques."""

    @staticmethod
    def analyze_ssh_attempt(username: str, password: str, client_banner: str = "") -> Tuple[List[str], int, str, str]:
        """
        Returns (ioc_tags, risk_score, severity, mitre_technique)
        """
        tags = ["SSH_AUTH_ATTEMPT", "BRUTE_FORCE"]
        score = 40
        severity = "MEDIUM"
        mitre = "T1110.001 (Password Guessing)"

        # Check default credential abuse
        if (username.lower(), password) in COMMON_DEFAULT_CREDS:
            tags.append("DEFAULT_CREDENTIAL_ABUSE")
            score += 20
            mitre = "T1078.001 (Default Accounts)"

        if username.lower() == "root":
            tags.append("ROOT_LOGIN_ATTEMPT")
            score += 15

        if len(password) < 4 or password.isdigit():
            tags.append("WEAK_PASSWORD_PROBE")
            score += 10

        score = min(score, 100)
        if score >= 80:
            severity = "HIGH"
        elif score >= 50:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return tags, score, severity, mitre

    @staticmethod
    def analyze_ssh_command(command: str) -> Tuple[List[str], int, str, str]:
        """
        Analyze captured interactive shell command from attacker.
        """
        tags = ["POST_EXPLOITATION_COMMAND"]
        score = 70
        severity = "HIGH"
        mitre = "T1059.004 (Unix Shell)"

        cmd_lower = command.lower().strip()

        # Reconnaissance
        if any(recon in cmd_lower for recon in ["uname", "whoami", "id", "cat /etc/issue", "hostname", "lscpu", "cat /proc/cpuinfo"]):
            tags.append("SYSTEM_RECONNAISSANCE")
            mitre = "T1082 (System Information Discovery)"
            score += 10

        # Credential / sensitive file snooping
        if any(snoop in cmd_lower for snoop in ["cat /etc/passwd", "cat /etc/shadow", "history", ".ssh"]):
            tags.append("CREDENTIAL_SNOOPING")
            mitre = "T1003 (Credential Dumping)"
            score += 15

        # Malware download / Dropper execution
        if any(dropper in cmd_lower for dropper in ["wget", "curl", "tftp", "ftp", "chmod +x", "sh -c", "bash -i", "/dev/tcp"]):
            tags.append("MALWARE_STAGER")
            tags.append("INGRESS_TOOL_TRANSFER")
            mitre = "T1105 (Ingress Tool Transfer)"
            score = 95
            severity = "CRITICAL"

        score = min(score, 100)
        return tags, score, severity, mitre

    @staticmethod
    def analyze_http_request(method: str, path: str, headers: Dict[str, str], body: str = "") -> Tuple[List[str], int, str, str]:
        """
        Analyze HTTP request method, path, headers, and body for attack patterns.
        """
        tags = ["HTTP_PROBE"]
        score = 25
        severity = "LOW"
        mitre = "T1595.002 (Vulnerability Scanning)"

        raw_target = f"{path} {body}"

        # 1. Check known exploit patterns (Log4j, Spring4Shell, XSS, etc.)
        for pattern, tag, sev, sc, m in EXPLOIT_PAYLOAD_PATTERNS:
            if re.search(pattern, raw_target, re.IGNORECASE):
                tags.append(tag)
                score = max(score, sc)
                severity = sev
                mitre = m

        # 2. Check SQL Injection
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, raw_target, re.IGNORECASE):
                tags.append("SQL_INJECTION")
                score = max(score, 85)
                severity = "HIGH"
                mitre = "T1190 (Exploit Public-Facing Application)"
                break

        # 3. Check Path Traversal
        for pattern in TRAVERSAL_PATTERNS:
            if re.search(pattern, raw_target, re.IGNORECASE):
                tags.append("PATH_TRAVERSAL")
                score = max(score, 80)
                severity = "HIGH"
                mitre = "T1083 (File and Directory Discovery)"
                break

        # 4. Check Remote Code Execution
        for pattern in RCE_PATTERNS:
            if re.search(pattern, raw_target, re.IGNORECASE):
                tags.append("COMMAND_INJECTION")
                score = max(score, 90)
                severity = "CRITICAL"
                mitre = "T1059 (Command and Scripting Interpreter)"
                break

        # 5. Check Sensitive File / Credential Probing
        for pattern in CRED_HUNTING_PATHS:
            if re.search(pattern, path, re.IGNORECASE):
                tags.append("CREDENTIAL_HUNTING")
                score = max(score, 65)
                if severity == "LOW":
                    severity = "MEDIUM"
                mitre = "T1083 (File and Directory Discovery)"
                break

        # 6. Check CMS / Admin portals
        if any(admin in path.lower() for admin in ["/wp-login.php", "/wp-admin", "/administrator", "/phpmyadmin", "/pma", "/admin"]):
            tags.append("ADMIN_PORTAL_SCAN")
            score = max(score, 50)
            if severity == "LOW":
                severity = "MEDIUM"
            mitre = "T1190 (Exploit Public-Facing Application)"

        # Check User-Agent scanner signatures
        user_agent = headers.get("user-agent", "").lower()
        if any(scanner in user_agent for scanner in ["sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "zgrab", "nuclei", "python-requests"]):
            tags.append(f"AUTOMATED_SCANNER ({user_agent.split('/')[0]})")
            score = max(score, 60)
            mitre = "T1595 (Active Scanning)"

        score = min(score, 100)
        return tags, score, severity, mitre

ioc_analyzer = IoCAnalyzer()
