# 🛡️ Evil Twin Attack Detection System (Fake WiFi Hotspot Detector)

A real-time, behavior-based WiFi security system that detects Evil Twin attacks by analyzing network characteristics and behavioral patterns. Built with Python Flask and designed as a university graduation project.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Detection Algorithm](#detection-algorithm)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Legal and Ethical Use](#legal-and-ethical-use)
- [Technologies Used](#technologies-used)

---

## Overview

An **Evil Twin attack** occurs when an attacker creates a fake WiFi access point that mimics a legitimate network. Victims unknowingly connect to the rogue network, exposing their traffic to interception and credential theft.

This system provides **real-time detection** of such attacks by scanning nearby WiFi networks and analyzing multiple behavioral indicators rather than relying on static rules.

---

## Features

- **Real-Time WiFi Scanning** — Scans nearby networks using system tools (nmcli, iwlist, iw, netsh) or scapy
- **Multi-Factor Risk Analysis** — Evaluates 7+ security indicators per network
- **Behavior-Based Detection** — Detects attacks through behavioral anomalies, not just blacklists
- **Interactive Web Dashboard** — Dark-themed cybersecurity dashboard with real-time updates
- **Risk Scoring Engine** — Calculates 0-100 risk scores with LOW/MEDIUM/HIGH classification
- **Scan History & Alerts** — Persistent SQLite database for historical tracking
- **Trusted Network Whitelist** — Mark known-safe networks to reduce false positives
- **Cross-Platform** — Works on Linux, macOS, and Windows
- **Demo Mode** — Built-in realistic demo data for testing and presentation

---

## System Architecture

```
┌─────────────────────────────────────────────────┐
│                  Web Browser                     │
│            (Dashboard Interface)                 │
└──────────────────┬──────────────────────────────┘
                   │ HTTP / AJAX
┌──────────────────▼──────────────────────────────┐
│              Flask Web Server                    │
│         (app.py - Routes & API)                  │
├─────────────────────────────────────────────────┤
│                                                  │
│  ┌──────────────┐    ┌───────────────────────┐  │
│  │ WiFi Scanner │───▶│ Evil Twin Detector     │  │
│  │              │    │ (Detection Engine)     │  │
│  │ - scapy      │    │                        │  │
│  │ - nmcli      │    │ - SSID Duplication     │  │
│  │ - iwlist     │    │ - MAC Analysis         │  │
│  │ - netsh      │    │ - Encryption Check     │  │
│  │ - iw         │    │ - Signal Analysis      │  │
│  └──────────────┘    │ - Channel Analysis     │  │
│                      │ - Historical Tracking   │  │
│                      └──────────┬────────────┘  │
│                                 │                │
│                    ┌────────────▼─────────────┐  │
│                    │   SQLite Database         │  │
│                    │                           │  │
│                    │ - Scan Sessions           │  │
│                    │ - Network Observations    │  │
│                    │ - Alert History           │  │
│                    │ - Trusted Whitelist       │  │
│                    └───────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

---

## Detection Algorithm

The system uses a **weighted multi-factor scoring system** (0-100):

| Factor | Weight | Description |
|--------|--------|-------------|
| SSID Duplication | 25 | Multiple APs sharing the same network name |
| Encryption Mismatch | 20 | Same-name networks with different security (e.g., WPA2 vs Open) |
| MAC Address Anomaly | 15 | Locally administered or multicast bit set in the BSSID (the vendor name is shown for information only) |
| Signal Anomaly | 15 | Unusually strong signal compared to peers |
| Channel Discrepancy | 10 | Same-name networks on different channels |
| Open Network | 10 | No encryption detected |
| Common Spoof Target | 5 | SSID matches commonly spoofed names |

**Risk Levels:**
- **LOW (0-30):** Normal network behavior
- **MEDIUM (31-60):** Suspicious indicators, investigate further  
- **HIGH (61-100):** Strong Evil Twin indicators, avoid connecting

Two additional indicators add to the score: an encryption or large signal change for the same
BSSID between scans in the same session (+10) and a hidden network with no encryption (+15).

---

## Installation

### Prerequisites
- Python 3.8+
- pip
- A WiFi adapter (for real scanning)

### Steps

```bash
# 1. Clone or extract the project
cd evil_twin_detector

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Run the application
python app.py

# 4. Open the dashboard
# Navigate to http://127.0.0.1:5000 in your browser
```

### For Full WiFi Scanning (Linux)
```bash
# Run with sudo for hardware-level scanning
sudo python app.py
```

> **Note:** Without sudo or a WiFi adapter, the system automatically falls back to demo mode with realistic simulated data.

---

## Usage

1. **Open the Dashboard** — Navigate to `http://127.0.0.1:5000`
2. **Click "Start Scan"** — Initiates a real-time WiFi scan
3. **Review Results** — Networks appear in the table with risk scores
4. **Click "Details"** — View detailed risk factors for any network
5. **Manage Trust** — Add known networks to whitelist
6. **View History** — Check past scans in the History tab

---

## Project Structure

```
evil_twin_detector/
├── app.py                          # Main Flask application & routes
├── config.py                       # Configuration settings
├── requirements.txt                # Python dependencies
├── README.md                       # This file
│
├── scanner/                        # Core scanning & detection
│   ├── __init__.py
│   ├── wifi_scanner.py             # Multi-method WiFi scanner
│   └── detector.py                 # Evil Twin detection engine
│
├── models/                         # Data layer
│   ├── __init__.py
│   └── database.py                 # SQLite database operations
│
├── templates/                      # HTML templates (Jinja2)
│   ├── base.html                   # Base layout template
│   ├── dashboard.html              # Main dashboard page
│   ├── history.html                # Scan history page
│   ├── network_detail.html         # Network detail page
│   └── 404.html                    # Error page
│
└── static/                         # Frontend assets
    ├── css/
    │   └── style.css               # Dark cybersecurity theme
    └── js/
        └── dashboard.js            # Dashboard interactivity
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Trigger a new WiFi scan |
| GET | `/api/scan/status` | Get current scan status |
| GET | `/api/networks` | Get all detected networks |
| GET | `/api/alerts` | Get current alerts |
| GET | `/api/statistics` | Get system statistics |
| GET | `/api/network/<bssid>/history` | Get network history |
| GET/POST/DELETE | `/api/whitelist` | Manage trusted networks |

---

## Hosted Version (e.g. Render)

A website cannot scan Wi-Fi: the server runs in a data centre with no Wi-Fi radio, and browsers do
not let web pages read the list of nearby networks. When the app is hosted (detected through Render's
`RENDER` environment variable, or by setting `EVILTWIN_HOSTED=1`), it therefore offers:

- **Paste a Scan** - the visitor runs one command on their own computer and pastes the output:
  - Windows: `netsh wlan show networks mode=bssid`
  - Linux: `nmcli -t -f SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY device wifi list --rescan yes`
  The networks are analysed by the same detection engine as a live scan.
- **Check My Connection** - automatic, nothing to install: looks up who provides the visitor's
  internet connection (ip-api.com; flags mobile networks, VPNs/proxies and data centres) and measures
  delay and download speed to the server.
- **Simulate Attack** - the six attack scenarios.

Each browser gets its own anonymous id (cookie), so visitors only see their own results, history and
trusted networks. Start Scan is disabled with an explanation. For fully automatic scanning, run the
app on your own computer (`python app.py`). The server logs its network interfaces at start-up
(`[Server] ... wireless: none` on Render).

---

## Testing

The `tests/` folder holds a `unittest` suite (black-box, white-box, integration,
scenario, security and performance tests). Every test uses a temporary database,
so `evil_twin_detector.db` is never modified.

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v          # run all tests
python -m coverage run -m unittest discover -s tests
python -m coverage report                        # statement coverage
```

Two scenario tests are marked as *expected failures*: they document known
limitations of the scoring model (unique-name honeypots score LOW, and one
legitimate AP in the multi-vector scenario scores HIGH).

---

## Legal and Ethical Use

- **Passive monitoring only.** EvilTwinGuard reads the network information that access points
  broadcast publicly (name, BSSID, channel, signal, security type). It does not connect to,
  attack, decrypt or capture the traffic of any network.
- **Check the law before you deploy.** Rules on wireless monitoring differ between countries and
  organisations. Get permission from the network owner or your institution's IT/security office
  before using the tool on a campus, corporate or government site.
- **The simulator never transmits.** Attack scenarios are generated as data inside the program.
  Creating a real fake access point to impersonate someone else's network is illegal in most
  jurisdictions; do it only in an isolated lab with written authorisation.
- **Responsible disclosure.** If you find a suspected Evil Twin or a weakness in someone else's
  network, report it privately to the network operator (or venue staff) and give them time to act
  before telling anyone else. Do not try to interfere with the suspicious access point yourself.
- **Protect the scan data.** `evil_twin_detector.db` records the networks seen around you. Keep it
  on an account only you can access, delete old scans you no longer need, and do not share it
  outside the people responsible for the network you were asked to assess.

---

## Technologies Used

- **Backend:** Python 3, Flask
- **Frontend:** HTML5, CSS3, JavaScript (Vanilla)
- **Database:** SQLite3
- **WiFi Scanning:** scapy, nmcli, iwlist, iw, netsh
- **Design:** Custom dark cybersecurity theme
