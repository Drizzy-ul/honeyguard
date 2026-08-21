import time
import requests
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable
from core.config import settings
from core.logger import logger

# In-memory alert cooldown tracker: {ip_or_key: last_alert_time}
_ALERT_COOLDOWN: Dict[str, float] = {}

# Listeners for real-time WebSocket broadcasting
_WS_LISTENERS: List[Callable[[Dict[str, Any]], Any]] = []

def register_ws_listener(listener: Callable[[Dict[str, Any]], Any]):
    if listener not in _WS_LISTENERS:
        _WS_LISTENERS.append(listener)

def unregister_ws_listener(listener: Callable[[Dict[str, Any]], Any]):
    if listener in _WS_LISTENERS:
        _WS_LISTENERS.remove(listener)

def broadcast_to_dashboards(event: Dict[str, Any]):
    """Send event to all active dashboard WebSocket clients."""
    for listener in list(_WS_LISTENERS):
        try:
            listener(event)
        except Exception as e:
            logger.debug(f"Failed to push to WS listener: {e}")

class AlertDispatcher:
    """Dispatches real-time alerts to Discord and Slack with rate limiting."""

    SEVERITY_COLORS = {
        "CRITICAL": 0xFF0033,  # Crimson Red
        "HIGH": 0xFF6600,      # Neon Orange
        "MEDIUM": 0xFFCC00,    # Amber Yellow
        "LOW": 0x0099FF        # Electric Blue
    }

    @classmethod
    def should_alert(cls, key: str, cooldown_seconds: int = settings.ALERT_COOLDOWN_SECONDS) -> bool:
        now = time.time()
        last_time = _ALERT_COOLDOWN.get(key, 0)
        if (now - last_time) >= cooldown_seconds:
            _ALERT_COOLDOWN[key] = now
            return True
        return False

    @classmethod
    def send_discord_alert(cls, event: Dict[str, Any]):
        if not settings.DISCORD_WEBHOOK_URL:
            return

        ip = event.get("src_ip", "Unknown")
        key = f"discord_{ip}_{event.get('service')}"
        if not cls.should_alert(key):
            return

        severity = event.get("severity", "LOW")
        color = cls.SEVERITY_COLORS.get(severity, 0x0099FF)
        service = event.get("service", "Generic")
        country = event.get("country", "Unknown")
        city = event.get("city", "Unknown")
        org = event.get("org", "Unknown")
        mitre = event.get("mitre_technique", "N/A")
        tags = ", ".join(event.get("ioc_tags", [])) or "None"

        # Build payload / credentials detail
        details = []
        if event.get("username"):
            details.append(f"**Username:** `{event['username']}`")
        if event.get("password"):
            details.append(f"**Password:** `{event['password']}`")
        if event.get("http_method") and event.get("http_path"):
            details.append(f"**HTTP:** `{event['http_method']} {event['http_path']}`")
        if event.get("payload"):
            payload_sample = event['payload'][:250] + "..." if len(event['payload']) > 250 else event['payload']
            details.append(f"**Payload/Cmd:** ```{payload_sample}```")

        embed = {
            "title": f"[HoneyGuard Alert] {severity} Threat on {service} Decoy",
            "color": color,
            "fields": [
                {"name": "Attacker IP", "value": f"`{ip}` ({country} - {city})", "inline": True},
                {"name": "ISP / ASN", "value": org, "inline": True},
                {"name": "Risk Score", "value": f"**{event.get('risk_score', 0)}/100**", "inline": True},
                {"name": "MITRE ATT&CK", "value": mitre, "inline": True},
                {"name": "IoC Tags", "value": f"`{tags}`", "inline": False},
            ],
            "footer": {"text": f"HoneyGuard SIEM | Timestamp: {event.get('timestamp')}"}
        }

        if details:
            embed["fields"].insert(2, {"name": "Captured Intercept", "value": "\n".join(details), "inline": False})

        payload = {
            "username": "HoneyGuard SOC Sentinel",
            "avatar_url": "https://raw.githubusercontent.com/feathericons/feather/master/icons/shield.png",
            "embeds": [embed]
        }

        try:
            requests.post(settings.DISCORD_WEBHOOK_URL, json=payload, timeout=3)
        except Exception as e:
            logger.error(f"Failed to dispatch Discord webhook: {e}")

    @classmethod
    def send_slack_alert(cls, event: Dict[str, Any]):
        if not settings.SLACK_WEBHOOK_URL:
            return

        ip = event.get("src_ip", "Unknown")
        key = f"slack_{ip}_{event.get('service')}"
        if not cls.should_alert(key):
            return

        severity = event.get("severity", "LOW")
        service = event.get("service", "Generic")
        country = event.get("country", "Unknown")
        org = event.get("org", "Unknown")
        mitre = event.get("mitre_technique", "N/A")

        text = f"[HoneyGuard Alert] *{severity}* Threat detected on *{service}* Honeypot from `{ip}` ({country}, {org}) - MITRE: {mitre}"
        payload = {"text": text}

        try:
            requests.post(settings.SLACK_WEBHOOK_URL, json=payload, timeout=3)
        except Exception as e:
            logger.error(f"Failed to dispatch Slack webhook: {e}")

    @classmethod
    def dispatch(cls, event: Dict[str, Any]):
        """Dispatches event to active Dashboards, Webhooks, and Threat Logs."""
        broadcast_to_dashboards(event)
        cls.send_discord_alert(event)
        cls.send_slack_alert(event)

alert_dispatcher = AlertDispatcher()
