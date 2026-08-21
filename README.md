# HoneyGuard: Intelligent Multi-Service Honeypot & SOC Telemetry Sentinel

> **A deliberate, low-interaction Python honeypot mimicking vulnerable SSH & HTTP services with GeoIP enrichment, Discord/Slack alerting, real-time SOC dashboard, and CompTIA Security+ aligned IoC threat intelligence.**

---

## Architecture Overview

```
                        [ Attacker / Botnet ]
                                  │
          ┌───────────────────────┴───────────────────────┐
          ▼                                               ▼
┌──────────────────┐                            ┌──────────────────┐
│   SSH Honeypot   │ (Port 2222)                │  HTTP Honeypot   │ (Port 8080)
│ OpenSSH Decoy +  │                            │ Decoy Web Portal │
│ Fake Bash Shell  │                            │ .env, wp-login   │
└─────────┬────────┘                            └────────┬─────────┘
          │                                              │
          └───────────────────────┬──────────────────────┘
                                  ▼
                   ┌─────────────────────────────┐
                   │     Threat Analysis Engine  │
                   │  - IoC Extractor & Tagger   │
                   │  - MITRE ATT&CK Classifier  │
                   │  - GeoIP Telemetry Cache    │
                   │  - Risk Score Calculator    │
                   └──────────────┬──────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          ▼                       ▼                       ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ Discord / Slack  │    │  FastAPI SOC &   │    │  SIEM JSON Logs  │
│  Alert Webhooks  │    │  WebSocket Feed  │    │ & SQLite DB IoCs │
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

---

## Key Features

1. **Fake SSH Honeypot (`services/ssh_honeypot.py`)**:
   - Paramiko-based low-interaction SSH server on port `2222`.
   - Authentic OpenSSH banner: `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`.
   - Intercepts username/password brute-force attempts and public keys.
   - Interactive fake shell trap (`root@ubuntu-srv:~#`) simulating `/bin/bash`, capturing attacker commands (`whoami`, `id`, `uname -a`, `cat /etc/passwd`, `wget`, `curl`, `chmod +x`).

2. **Fake HTTP Honeypot (`services/http_honeypot.py`)**:
   - Decoy corporate web portal on port `8080` (`Apache/2.4.41 (Ubuntu)`).
   - Sensitive leak traps: `/.env`, `/.git/config`, `/wp-config.php.bak`, `/actuator/env`.
   - CMS & Admin traps: `/wp-login.php`, `/admin`, `/phpmyadmin`.
   - Catches SQL Injection, Path Traversal, Log4j JNDI, and Command Injection payloads.

3. **Threat Analysis & GeoIP Enrichment (`core/`)**:
   - Evaluates risk score (0 - 100) and severity level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - Maps attacks to **MITRE ATT&CK** techniques:
     - `T1110.001`: Password Guessing / Brute Force
     - `T1078.001`: Default Accounts Abuse
     - `T1190`: Exploit Public-Facing Application (SQLi, Log4Shell)
     - `T1083`: File and Directory Discovery (.env, passwd)
     - `T1059.004`: Unix Shell Command Execution
     - `T1105`: Ingress Tool Transfer (`wget` / `curl` droppers)
   - Real-time GeoIP lookups with simulated lab IP support and MaxMind compatibility.

4. **Real-time SOC Dashboard (`dashboard/`)**:
   - Fast real-time WebSocket attack stream.
   - Interactive Leaflet.js dark attack world map with pulsating beacons.
   - Real-time audio alerts via Web Audio API.
   - Analytics charts for MITRE vectors, attacker countries, and tried passwords.
   - One-click IoC exporter for **CSV**, **JSON**, and **Snort/Suricata IDS rules**.
   - Built-in Attack Simulator launchpad to trigger test attacks with a single click.

5. **Security+ Connection & Incident Response**:
   - Covers Domain 1.0 (Deception technologies), Domain 2.0 (Threats & Vulnerabilities), and Domain 4.0 (Security Operations, SIEM log parsing, IoC blocklists).

---

## Installation & Quick Start

### 1. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 2. Configure Settings (Optional)
Copy `.env.example` to `.env` to configure ports or webhook URLs:
```bash
# Webhooks (Optional)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

### 3. Launch HoneyGuard
```bash
python main.py
```

### 4. Access the SOC Dashboard
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

---

## Testing with Attack Simulator

In a separate terminal, execute realistic attack simulations:

```bash
# Run a full red-team campaign across all services
python simulator/attack_simulator.py --scenario all

# Or run specific scenarios:
python simulator/attack_simulator.py --scenario ssh_brute
python simulator/attack_simulator.py --scenario sqli
python simulator/attack_simulator.py --scenario traversal
python simulator/attack_simulator.py --scenario env_leak
python simulator/attack_simulator.py --scenario ssh_dropper
```

---

## REST API & IoC Export Endpoints

- `GET /api/stats` - Summary KPI metrics and MITRE breakdown
- `GET /api/events` - Filterable, paginated raw attack telemetry
- `GET /api/iocs` - List of all captured Indicators of Compromise
- `GET /api/iocs/export?format=csv` - Download IoCs as CSV
- `GET /api/iocs/export?format=json` - Download IoCs as JSON
- `GET /api/iocs/export?format=snort` - Download Snort/Suricata IDS rules
- `POST /api/simulate` - Trigger attack scenarios via API
- `WS  /ws/live` - Real-time attack WebSocket stream
