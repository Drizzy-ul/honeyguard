import os
import socket
import threading
import uuid
from datetime import datetime, timezone
import paramiko
from paramiko import RSAKey

from core.config import settings
from core.logger import logger, threat_logger
from core.database import db
from core.geoip import resolve_geoip
from core.ioc_analyzer import ioc_analyzer
from core.alerting import alert_dispatcher

# Generate host key if not present
def get_or_generate_host_key():
    key_path = settings.SSH_KEY_FILE
    if not os.path.exists(key_path):
        logger.info(f"Generating new RSA host key for SSH honeypot at {key_path}...")
        key = RSAKey.generate(2048)
        key.write_private_key_file(key_path)
    return RSAKey(filename=key_path)

FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
_apt:x:103:65534::/nonexistent:/usr/sbin/nologin
messagebus:x:104:107::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
admin:x:1001:1001:Administrator:/home/admin:/bin/bash
"""

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int):
        self.client_ip = client_ip
        self.client_port = client_port
        self.session_id = str(uuid.uuid4())
        self.authenticated_user = None
        self.event = threading.Event()
        self.client_banner = ""

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.authenticated_user = username
        geo = resolve_geoip(self.client_ip)
        tags, score, severity, mitre = ioc_analyzer.analyze_ssh_attempt(username, password, self.client_banner)

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "SSH",
            "event_type": "AUTH_ATTEMPT",
            "src_ip": self.client_ip,
            "src_port": self.client_port,
            "username": username,
            "password": password,
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
            "session_id": self.session_id
        }

        # Log & Alert
        db.insert_event_sync(event)
        threat_logger.log_event(event)
        alert_dispatcher.dispatch(event)
        
        logger.info(f"🚨 [SSH AUTH] IP={self.client_ip} User='{username}' Pass='{password}' Risk={score} ({severity})")

        if settings.SSH_ALLOW_INTERACTIVE:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        geo = resolve_geoip(self.client_ip)
        fingerprint = key.get_fingerprint().hex()
        tags = ["SSH_PUBKEY_PROBE"]
        score = 45
        severity = "MEDIUM"
        mitre = "T1110.001 (Password Guessing)"

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "SSH",
            "event_type": "PUBKEY_AUTH_ATTEMPT",
            "src_ip": self.client_ip,
            "src_port": self.client_port,
            "username": username,
            "payload": f"KeyType: {key.get_name()}, Fingerprint: {fingerprint}",
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
            "session_id": self.session_id
        }
        db.insert_event_sync(event)
        threat_logger.log_event(event)
        alert_dispatcher.dispatch(event)
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        """Handle non-interactive SSH commands (e.g. ssh user@host 'cat /etc/passwd')"""
        cmd_str = command.decode("utf-8", errors="ignore")
        self._handle_command(cmd_str, channel)
        channel.close()
        return True

    def _handle_command(self, cmd_str: str, channel):
        geo = resolve_geoip(self.client_ip)
        tags, score, severity, mitre = ioc_analyzer.analyze_ssh_command(cmd_str)

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "SSH",
            "event_type": "COMMAND_EXEC",
            "src_ip": self.client_ip,
            "src_port": self.client_port,
            "username": self.authenticated_user or "unknown",
            "payload": cmd_str,
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
            "session_id": self.session_id
        }
        db.insert_event_sync(event)
        threat_logger.log_event(event)
        alert_dispatcher.dispatch(event)
        logger.warning(f"⚠️ [SSH CMD INTERCEPT] IP={self.client_ip} Cmd='{cmd_str}' Severity={severity}")

        # Send realistic mock output back to decoy terminal
        output = self._get_fake_command_response(cmd_str)
        if output:
            channel.send(output.replace("\n", "\r\n") + "\r\n")

    def _get_fake_command_response(self, cmd: str) -> str:
        c = cmd.strip()
        if not c:
            return ""
        if c in ("whoami", "id -un"):
            return self.authenticated_user or "root"
        elif c in ("id", "id -u"):
            return "uid=0(root) gid=0(root) groups=0(root)"
        elif c.startswith("uname"):
            return "Linux ubuntu-server 5.4.0-150-generic #167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
        elif c in ("pwd",):
            return "/root"
        elif c in ("ls", "dir", "ls -l", "ls -la"):
            return "total 32\ndrwx------ 4 root root 4096 Aug 21 09:12 .\ndrwxr-xr-x 20 root root 4096 Aug 21 08:30 ..\n-rw------- 1 root root 1432 Aug 21 09:15 .bash_history\n-rw-r--r-- 1 root root 3106 Dec  5  2019 .bashrc\n-rw-r--r-- 1 root root  161 Dec  5  2019 .profile\ndrwx------ 2 root root 4096 Aug 21 08:32 .ssh\n-rw-r--r-- 1 root root  240 Aug 21 08:40 backup.sh"
        elif c == "cat /etc/passwd":
            return FAKE_PASSWD
        elif c in ("cat /etc/issue", "cat /etc/os-release"):
            return "Ubuntu 20.04.6 LTS \\n \\l"
        elif c.startswith("cat"):
            return "cat: file or directory not found"
        elif c.startswith("wget") or c.startswith("curl"):
            return "--2026-08-21 11:15:00--  Connecting... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 4892 (4.8K) [application/x-sh]\nSaving to: 'malware.sh'\n\nmalware.sh          100%[===================>]   4.78K  --.-KB/s    in 0.001s\n\n2026-08-21 11:15:00 (4.78 MB/s) - 'malware.sh' saved [4892/4892]"
        elif c.startswith("chmod") or c.startswith("mkdir") or c.startswith("rm") or c.startswith("touch"):
            return ""
        elif c in ("ps", "ps aux"):
            return "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.2 168432  9820 ?        Ss   08:30   0:01 /sbin/init\nroot       412  0.0  0.1  43120  4100 ?        Ss   08:30   0:00 /lib/systemd/systemd-journald\nroot       612  0.0  0.2  72100  8300 ?        Ss   08:30   0:00 /usr/sbin/sshd -D\nroot      1450  0.0  0.1  14200  3800 pts/0    Ss+  09:12   0:00 -bash"
        elif c in ("hostname",):
            return "ubuntu-server-prod"
        elif c in ("ifconfig", "ip a", "ip addr"):
            return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        ether 52:54:00:12:34:56  txqueuelen 1000  (Ethernet)"
        else:
            return f"bash: {c.split()[0]}: command not found"

def handle_ssh_connection(client_socket, client_addr):
    client_ip, client_port = client_addr
    try:
        transport = paramiko.Transport(client_socket)
        host_key = get_or_generate_host_key()
        transport.add_server_key(host_key)
        transport.local_version = settings.SSH_BANNER

        server = FakeSSHServer(client_ip, client_port)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return

        channel = transport.accept(20)
        if channel is None:
            return

        server.event.wait(10)
        if not server.event.is_set():
            channel.close()
            return

        # Interactive fake shell loop
        channel.send(b"\r\nWelcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n\r\nLast login: Fri Aug 21 09:12:34 2026 from 10.0.0.15\r\n")
        
        prompt = f"{server.authenticated_user or 'root'}@ubuntu-srv:~# "
        channel.send(prompt.encode("utf-8"))

        buffer = ""
        while not channel.closed:
            try:
                data = channel.recv(1024).decode("utf-8", errors="ignore")
                if not data:
                    break

                for char in data:
                    # Handle Enter / Return
                    if char in ("\r", "\n"):
                        channel.send(b"\r\n")
                        cmd = buffer.strip()
                        if cmd in ("exit", "logout", "quit"):
                            channel.send(b"logout\r\n")
                            channel.close()
                            break
                        if cmd:
                            server._handle_command(cmd, channel)
                        buffer = ""
                        channel.send(prompt.encode("utf-8"))
                    # Handle Backspace
                    elif char in ("\x08", "\x7f"):
                        if len(buffer) > 0:
                            buffer = buffer[:-1]
                            channel.send(b"\b \b")
                    # Handle Ctrl+C
                    elif char == "\x03":
                        buffer = ""
                        channel.send(b"^C\r\n" + prompt.encode("utf-8"))
                    # Handle Ctrl+D
                    elif char == "\x04":
                        channel.close()
                        break
                    else:
                        buffer += char
                        channel.send(char.encode("utf-8"))
            except Exception:
                break

        channel.close()
    except Exception as e:
        logger.debug(f"SSH connection error for {client_ip}: {e}")
    finally:
        try:
            client_socket.close()
        except Exception:
            pass

class SSHHoneypotService:
    def __init__(self, host: str = settings.HONEYPOT_SSH_HOST, port: int = settings.HONEYPOT_SSH_PORT):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.thread = None

    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        logger.info(f"🛡️  [SSH HONEYPOT] Listening on {self.host}:{self.port} (Banner: {settings.SSH_BANNER})")

        self.thread = threading.Thread(target=self._accept_loop, daemon=True, name="SSHHoneypotThread")
        self.thread.start()

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=handle_ssh_connection,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                client_thread.start()
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        logger.info("🛑 [SSH HONEYPOT] Stopped.")

ssh_service = SSHHoneypotService()
