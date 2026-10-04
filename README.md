<div align="center">

# ðŸ›¡ï¸ HoneyGuard: Intelligent Multi-Service Honeypot & SOC Telemetry Sentinel

### Low-Interaction SSH & HTTP Decoys with GeoIP Enrichment, MITRE ATT&CK Mapping & Real-Time SOC Dashboard

[![CI Status](https://github.com/Drizzy-ul/honeyguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Drizzy-ul/honeyguard/actions)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](https://github.com/Drizzy-ul/honeyguard)](https://opensource.org/licenses/MIT)
[![Security+](https://img.shields.io/badge/CompTIA-Security%2B%20Aligned-yellow.svg)](https://www.comptia.org/certifications/security)

<p align="center">
  A deliberate, low-interaction Python honeypot mimicking vulnerable SSH & HTTP services with GeoIP enrichment, Discord/Slack alerting, real-time SOC dashboard, and CompTIA Security+ aligned IoC threat intelligence.
</p>

</div>

---

## ðŸŽ¯ Architecture Overview

```
                        [ Attacker / Botnet ]
                                  â”‚
          â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
          â–¼                                               â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                            â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚   SSH Honeypot   â”‚ (Port 2222)                â”‚  HTTP Honeypot   â”‚ (Port 8080)
â”‚ OpenSSH Decoy +  â”‚                            â”‚ Decoy Web Portal â”‚
â”‚ Fake Bash Shell  â”‚                            â”‚ .env, wp-login   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”˜                            â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
          â”‚                                              â”‚
          â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                  â–¼
                   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                   â”‚     Threat Analysis Engine  â”‚
                   â”‚  - IoC Extractor & Tagger   â”‚
                   â”‚  - MITRE ATT&CK Classifier  â”‚
                   â”‚  - GeoIP Telemetry Cache    â”‚
                   â”‚  - Risk Score Calculator    â”‚
                   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                  â”‚
          â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
          â–¼                       â–¼                       â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ Discord / Slack  â”‚    â”‚  FastAPI SOC &   â”‚    â”‚  SIEM JSON Logs  â”‚
â”‚  Alert Webhooks  â”‚    â”‚  WebSocket Feed  â”‚    â”‚ & SQLite DB IoCs â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

---

## ðŸš€ Key Features

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

## ðŸ› ï¸ Installation & Quick Start

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

## ðŸ§ª Testing with Attack Simulator

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

## ðŸ“¡ REST API & IoC Export Endpoints

- `GET /api/stats` - Summary KPI metrics and MITRE breakdown
- `GET /api/events` - Filterable, paginated raw attack telemetry
- `GET /api/iocs` - List of all captured Indicators of Compromise
- `GET /api/iocs/export?format=csv` - Download IoCs as CSV
- `GET /api/iocs/export?format=json` - Download IoCs as JSON
- `GET /api/iocs/export?format=snort` - Download Snort/Suricata IDS rules
- `POST /api/simulate` - Trigger attack scenarios via API
- `WS  /ws/live` - Real-time attack WebSocket stream
