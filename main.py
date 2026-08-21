import os
import sys
import time
import signal
import uvicorn
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from core.config import settings
from core.logger import logger
from core.database import db
from services.ssh_honeypot import ssh_service, get_or_generate_host_key
from services.http_honeypot import http_service
from dashboard.app import app

# Set UTF-8 encoding for standard output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

def print_banner():
    banner = f"""
======================================================================
  [+] HONEYGUARD - DECEPTION SENTINEL & THREAT INTEL SOC
======================================================================
  [*] Fake SSH Honeypot:     0.0.0.0:{settings.HONEYPOT_SSH_PORT} (Banner: {settings.SSH_BANNER})
  [*] Fake HTTP Honeypot:    http://0.0.0.0:{settings.HONEYPOT_HTTP_PORT}
  [*] SOC Live Dashboard:    http://127.0.0.1:{settings.DASHBOARD_PORT}
  [*] Threat JSONL Log:      {settings.JSON_LOG_PATH}
  [*] IoC Database:          {settings.DB_PATH}
======================================================================
    """
    print(banner)

def main():
    print_banner()

    # 1. Initialize DB and Keys
    logger.info("Initializing SQLite Threat Database...")
    db.init_sync_db()

    logger.info("Ensuring SSH Decoy Host Key exists...")
    get_or_generate_host_key()

    # 2. Start Honeypot Services
    ssh_service.start()
    http_service.start()

    # 3. Handle graceful shutdown
    def handle_exit(signum, frame):
        logger.info("\n[!] Shutting down HoneyGuard services...")
        ssh_service.stop()
        http_service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # 4. Start FastAPI Uvicorn Server (blocks in main thread)
    logger.info(f"🚀 Starting HoneyGuard Dashboard on http://{settings.DASHBOARD_HOST}:{settings.DASHBOARD_PORT}")
    try:
        uvicorn.run(
            app,
            host=settings.DASHBOARD_HOST,
            port=settings.DASHBOARD_PORT,
            log_level="warning"
        )
    except KeyboardInterrupt:
        handle_exit(None, None)

if __name__ == "__main__":
    main()
