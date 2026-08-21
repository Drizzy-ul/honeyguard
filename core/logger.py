import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from core.config import settings

# Configure standard console logger
logger = logging.getLogger("HoneyGuard")
logger.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = logging.FileHandler(Path(settings.JSON_LOG_PATH).parent / "honeypot.log", encoding="utf-8")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

class JsonThreatLogger:
    """Logs raw security events in structured JSONL for SIEM & Log Analysis."""
    
    def __init__(self, log_path: str = settings.JSON_LOG_PATH):
        self.log_path = log_path
        Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, event_data: dict):
        try:
            if "timestamp" not in event_data:
                event_data["timestamp"] = datetime.now(timezone.utc).isoformat()
            
            line = json.dumps(event_data, ensure_ascii=False)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as e:
            logger.error(f"Failed to write JSON log: {e}")

threat_logger = JsonThreatLogger()
