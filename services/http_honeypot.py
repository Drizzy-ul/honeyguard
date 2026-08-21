import json
import threading
import uuid
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from core.config import settings
from core.logger import logger, threat_logger
from core.database import db
from core.geoip import resolve_geoip
from core.ioc_analyzer import ioc_analyzer
from core.alerting import alert_dispatcher

# Fake Decoy Templates
DECOY_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Corporate Intranet - Authentication Required</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #fff; padding: 35px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 340px; }
        h2 { margin-top: 0; color: #1a1a1a; font-size: 22px; text-align: center; }
        .subtitle { font-size: 13px; color: #666; text-align: center; margin-bottom: 25px; }
        .form-group { margin-bottom: 18px; }
        label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; color: #333; }
        input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; }
        input[type="submit"] { width: 100%; background: #0066cc; color: #fff; padding: 12px; border: none; border-radius: 4px; font-size: 15px; font-weight: 600; cursor: pointer; }
        input[type="submit"]:hover { background: #0052a3; }
        .alert { background: #ffebe8; color: #d8000c; padding: 10px; border-radius: 4px; font-size: 12px; margin-bottom: 15px; border: 1px solid #ffbaba; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Corporate Gateway</h2>
        <div class="subtitle">Internal Production Portal v4.2.1</div>
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Username / Employee ID</label>
                <input type="text" name="username" placeholder="user@corp.internal" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" required>
            </div>
            <input type="submit" value="Sign In">
        </form>
    </div>
</body>
</html>"""

DECOY_ENV_CONTENT = """# Production Environment Config - DO NOT LEAK
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:4Z4y0vK+L9F7Z1v6Jk0O2x3yP4a5b6c7d8e9f0g1h2i=
APP_URL=https://gateway.corp.internal

DB_CONNECTION=mysql
DB_HOST=10.142.0.4
DB_PORT=3306
DB_DATABASE=corp_users_prod
DB_USERNAME=db_admin_svc
DB_PASSWORD=P@ssw0rdProd_2026_Secure!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1

JWT_SECRET=super_secret_corporate_token_signing_key_99128
"""

DECOY_WP_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Log In &lsaquo; WordPress</title>
    <style>
        body { background: #f1f1f1; font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif; }
        .login { width: 320px; margin: 80px auto; padding: 26px 24px 46px; background: #fff; border: 1px solid #c3c4c7; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
        .login label { font-size: 14px; line-height: 1.5; color: #3c434a; }
        .login input[type="text"], .login input[type="password"] { font-size: 20px; line-height: 2; width: 100%; border: 1px solid #8c8f94; border-radius: 4px; padding: 3px 5px; margin-bottom: 16px; box-sizing: border-box; }
        .button-primary { background: #2271b1; border-color: #2271b1; color: #fff; padding: 8px 16px; border-radius: 3px; font-size: 13px; font-weight: 600; cursor: pointer; float: right; }
    </style>
</head>
<body class="login">
    <div class="login">
        <form name="loginform" id="loginform" action="/wp-login.php" method="post">
            <p><label for="user_login">Username or Email Address<br /><input type="text" name="log" id="user_login" class="input" size="20" autocapitalize="off" /></label></p>
            <p><label for="user_pass">Password<br /><input type="password" name="pwd" id="user_pass" class="input" size="20" /></label></p>
            <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" /></p>
        </form>
    </div>
</body>
</html>"""

DECOY_ACTUATOR_JSON = {
    "status": "UP",
    "components": {
        "db": {"status": "UP", "details": {"database": "MySQL", "validationQuery": "isValid()"}},
        "diskSpace": {"status": "UP", "details": {"total": 512110190592, "free": 320485910400}},
        "ping": {"status": "UP"}
    }
}

class HTTPHoneypotHandler(BaseHTTPRequestHandler):
    server_version = settings.HTTP_SERVER_BANNER
    sys_version = ""

    def log_message(self, format, *args):
        # Suppress default noisy stderr prints
        pass

    def _get_client_ip(self) -> str:
        # Check standard reverse-proxy headers if present
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def _process_intercept(self, method: str, body: str = ""):
        client_ip = self._get_client_ip()
        client_port = self.client_address[1]
        session_id = str(uuid.uuid4())
        geo = resolve_geoip(client_ip)

        headers_dict = dict(self.headers)
        
        # Extract credentials if sent via POST or query string
        username = None
        password = None
        
        # Check POST Form or JSON
        if body:
            # Check JSON
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    username = data.get("username") or data.get("user") or data.get("email") or data.get("login") or data.get("log")
                    password = data.get("password") or data.get("pass") or data.get("pwd")
            except Exception:
                pass
            
            # Check Form-urlencoded
            if not username and not password and "=" in body:
                parsed_form = parse_qs(body)
                for u_key in ["username", "user", "email", "login", "log", "pma_username", "name"]:
                    if u_key in parsed_form:
                        username = parsed_form[u_key][0]
                        break
                for p_key in ["password", "pass", "pwd", "pma_password"]:
                    if p_key in parsed_form:
                        password = parsed_form[p_key][0]
                        break

        # Check basic auth header
        if not username and "authorization" in headers_dict:
            import base64
            auth_val = headers_dict["authorization"]
            if auth_val.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth_val[6:]).decode("utf-8")
                    if ":" in decoded:
                        username, password = decoded.split(":", 1)
                except Exception:
                    pass

        # IoC and Threat analysis
        tags, score, severity, mitre = ioc_analyzer.analyze_http_request(method, self.path, headers_dict, body)
        if username or password:
            tags.append("WEB_CREDENTIAL_SUBMISSION")
            score = max(score, 60)
            if severity == "LOW":
                severity = "MEDIUM"

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "HTTP",
            "event_type": "HTTP_REQUEST",
            "src_ip": client_ip,
            "src_port": client_port,
            "username": username,
            "password": password,
            "http_method": method,
            "http_path": self.path,
            "http_headers": headers_dict,
            "payload": body if body else (self.path if "?" in self.path else None),
            "country": geo.get("country"),
            "country_code": geo.get("country_code"),
            "city": geo.get("city"),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "org": geo.get("org"),
            "asn": geo.get("asn"),
            "ioc_tags": tags,
            "risk_score": score,
            "severity": severity,
            "mitre_technique": mitre,
            "session_id": session_id
        }

        # Log & Alert
        db.insert_event_sync(event)
        threat_logger.log_event(event)
        alert_dispatcher.dispatch(event)

        logger.info(f"[HTTP PROBE] IP={client_ip} Method={method} Path='{self.path}' Risk={score} ({severity})")
        return event

    def _serve_response(self, status_code: int, content: str, content_type: str = "text/html"):
        self.send_response(status_code)
        self.send_header("Server", settings.HTTP_SERVER_BANNER)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Connection", "close")
        encoded = content.encode("utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        self._process_intercept("GET")
        parsed_url = urlparse(self.path)
        path = parsed_url.path.lower()

        # Route honeypot decoys
        if path in ("/", "/index.html", "/login", "/admin"):
            self._serve_response(200, DECOY_LOGIN_HTML)
        elif path in ("/.env", "/.env.backup", "/.env.production", "/.env.local"):
            self._serve_response(200, DECOY_ENV_CONTENT, "text/plain")
        elif path in ("/wp-login.php", "/wp-admin", "/wp-admin/"):
            self._serve_response(200, DECOY_WP_LOGIN_HTML)
        elif path in ("/actuator/health", "/actuator/env", "/actuator"):
            self._serve_response(200, json.dumps(DECOY_ACTUATOR_JSON, indent=2), "application/json")
        elif path in ("/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/"):
            self._serve_response(200, DECOY_LOGIN_HTML.replace("Corporate Gateway", "phpMyAdmin - Database Access"))
        elif path in ("/robots.txt",):
            self._serve_response(200, "User-agent: *\nDisallow: /admin/\nDisallow: /.env\nDisallow: /wp-admin/\nDisallow: /backup/\n", "text/plain")
        elif "/etc/passwd" in path or "win.ini" in path:
            self._serve_response(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n", "text/plain")
        else:
            self._serve_response(404, "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>Apache/2.4.41 (Ubuntu)</center></body></html>")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore") if content_length > 0 else ""
        self._process_intercept("POST", body)
        
        # Respond with realistic fake authentication failure or redirect
        if "/login" in self.path or "/wp-login" in self.path:
            # Fake invalid credentials error
            self._serve_response(401, DECOY_LOGIN_HTML.replace('<form method="POST"', '<div class="alert">[!] Invalid credentials. Incident has been logged.</div><form method="POST"'))
        else:
            self._serve_response(200, '{"status": "error", "message": "Access denied. Operation logged."}', "application/json")

    def do_PUT(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore") if content_length > 0 else ""
        self._process_intercept("PUT", body)
        self._serve_response(403, '{"error": "Forbidden: PUT method disabled by policy"}', "application/json")

    def do_HEAD(self):
        self._process_intercept("HEAD")
        self.send_response(200)
        self.send_header("Server", settings.HTTP_SERVER_BANNER)
        self.end_headers()

    def do_OPTIONS(self):
        self._process_intercept("OPTIONS")
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, HEAD")
        self.send_header("Server", settings.HTTP_SERVER_BANNER)
        self.end_headers()

class HTTPHoneypotService:
    def __init__(self, host: str = settings.HONEYPOT_HTTP_HOST, port: int = settings.HONEYPOT_HTTP_PORT):
        self.host = host
        self.port = port
        self.httpd = None
        self.thread = None

    def start(self):
        self.httpd = HTTPServer((self.host, self.port), HTTPHoneypotHandler)
        logger.info(f"[HTTP HONEYPOT] Listening on http://{self.host}:{self.port} (Server: {settings.HTTP_SERVER_BANNER})")
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="HTTPHoneypotThread")
        self.thread.start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        logger.info("[HTTP HONEYPOT] Stopped.")

http_service = HTTPHoneypotService()
