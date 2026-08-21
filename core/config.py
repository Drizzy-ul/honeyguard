import os
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
KEYS_DIR = BASE_DIR / "keys"

# Ensure runtime directories exist
LOGS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
KEYS_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseSettings):
    # Ports & Hosts
    HONEYPOT_SSH_PORT: int = 2222
    HONEYPOT_SSH_HOST: str = "0.0.0.0"
    HONEYPOT_HTTP_PORT: int = 8080
    HONEYPOT_HTTP_HOST: str = "0.0.0.0"
    DASHBOARD_PORT: int = 8000
    DASHBOARD_HOST: str = "0.0.0.0"
    
    # Decoys
    SSH_BANNER: str = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    HTTP_SERVER_BANNER: str = "Apache/2.4.41 (Ubuntu)"
    SSH_ALLOW_INTERACTIVE: bool = True
    SSH_KEY_FILE: str = str(KEYS_DIR / "honeypot_rsa.key")
    
    # Storage
    DB_PATH: str = str(DATA_DIR / "honeyguard.db")
    JSON_LOG_PATH: str = str(LOGS_DIR / "honeypot_events.jsonl")
    
    # Webhooks
    DISCORD_WEBHOOK_URL: str = ""
    SLACK_WEBHOOK_URL: str = ""
    ALERT_COOLDOWN_SECONDS: int = 20
    
    # GeoIP
    GEOIP_DB_PATH: str = ""
    
    class Config:
        env_file = str(BASE_DIR / ".env")
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()
