import csv
import io
import json
import socket
import threading
import requests
from typing import Optional
from fastapi import APIRouter, Query, Response, HTTPException
from pydantic import BaseModel

from core.config import settings
from core.database import db
from core.logger import logger

router = APIRouter(prefix="/api")

class WebhookUpdateRequest(BaseModel):
    discord_webhook_url: Optional[str] = None
    slack_webhook_url: Optional[str] = None

class SimulationRequest(BaseModel):
    scenario: str  # ssh_brute, sqli, traversal, env_leak, log4shell, ssh_dropper
    attacker_ip: Optional[str] = None

@router.get("/stats")
async def get_dashboard_stats():
    """Returns aggregated attack metrics, breakdown by service, severity, top countries, etc."""
    stats = await db.get_stats()
    stats["services_status"] = {
        "ssh_port": settings.HONEYPOT_SSH_PORT,
        "http_port": settings.HONEYPOT_HTTP_PORT,
        "dashboard_port": settings.DASHBOARD_PORT,
        "ssh_banner": settings.SSH_BANNER,
        "http_banner": settings.HTTP_SERVER_BANNER
    }
    return stats

@router.get("/events")
async def get_attack_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    service: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None
):
    """Returns filtered, paginated attack events."""
    events = await db.get_recent_events(limit=limit, offset=offset, service=service, severity=severity, search=search)
    return {"events": events, "count": len(events), "limit": limit, "offset": offset}

@router.get("/iocs")
async def get_ioc_list():
    """Returns all gathered Indicators of Compromise."""
    iocs = await db.get_all_iocs()
    return {"iocs": iocs, "total": len(iocs)}

@router.get("/iocs/export")
async def export_iocs(format: str = Query("json", pattern="^(json|csv|snort)$")):
    """Export Indicators of Compromise in JSON, CSV, or Snort/Suricata signature rule formats."""
    iocs = await db.get_all_iocs()
    
    if format == "json":
        return iocs
    
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "IoC_Type", "IoC_Value", "Threat_Level", "Hit_Count", "First_Seen", "Last_Seen", "Notes"])
        for item in iocs:
            writer.writerow([
                item["id"],
                item["ioc_type"],
                item["ioc_value"],
                item["threat_level"],
                item["hit_count"],
                item["first_seen"],
                item["last_seen"],
                item["notes"]
            ])
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=honeyguard_iocs.csv"}
        )
    
    elif format == "snort":
        # Generate Snort / Suricata IDS rules from captured IP indicators and payloads
        rules = []
        rule_sid = 1000001
        for item in iocs:
            if item["ioc_type"] == "IP_ADDRESS" and item["ioc_value"] not in ("127.0.0.1", "localhost", "0.0.0.0"):
                rules.append(f'alert ip {item["ioc_value"]} any -> $HOME_NET any (msg:"[HoneyGuard] Known Malicious Attacker IP detected ({item["threat_level"]})"; classtype:trojan-activity; sid:{rule_sid}; rev:1;)')
                rule_sid += 1
            elif item["ioc_type"] == "PAYLOAD_SIGNATURE" and len(item["ioc_value"]) > 5:
                clean_payload = item["ioc_value"].replace('"', '\\"').replace("\n", " ")
                rules.append(f'alert tcp $EXTERNAL_NET any -> $HOME_NET [80,8080] (msg:"[HoneyGuard] Decoy Exploit Payload Signature detected"; content:"{clean_payload[:40]}"; nocase; classtype:web-application-attack; sid:{rule_sid}; rev:1;)')
                rule_sid += 1
        
        content = "\n".join(rules) if rules else "# No malicious remote IP / payload rules currently generated."
        return Response(
            content=content,
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=honeyguard_suricata_rules.rules"}
        )

@router.post("/settings/webhooks")
async def update_webhooks(req: WebhookUpdateRequest):
    if req.discord_webhook_url is not None:
        settings.DISCORD_WEBHOOK_URL = req.discord_webhook_url
    if req.slack_webhook_url is not None:
        settings.SLACK_WEBHOOK_URL = req.slack_webhook_url
    return {"status": "success", "message": "Webhook settings updated successfully"}

def _run_async_simulation(scenario: str, custom_ip: Optional[str] = None):
    """Executes a simulation payload in a background thread."""
    from simulator.attack_simulator import run_single_simulation
    run_single_simulation(scenario, custom_ip)

@router.post("/simulate")
async def trigger_simulation(req: SimulationRequest):
    """Triggers an attack simulation payload against the honeypot for testing."""
    thread = threading.Thread(target=_run_async_simulation, args=(req.scenario, req.attacker_ip), daemon=True)
    thread.start()
    return {
        "status": "success",
        "message": f"Simulation '{req.scenario}' launched against honeypot!",
        "scenario": req.scenario
    }
