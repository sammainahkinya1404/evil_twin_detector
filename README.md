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
| MAC Address Anomaly | 15 | Locally administered bit set, unknown vendor |
| Signal Anomaly | 15 | Unusually strong signal compared to peers |
| Channel Discrepancy | 10 | Same-name networks on different channels |
| Open Network | 10 | No encryption detected |
| Common Spoof Target | 5 | SSID matches commonly spoofed names |

**Risk Levels:**
- **LOW (0-30):** Normal network behavior
- **MEDIUM (31-60):** Suspicious indicators, investigate further  
- **HIGH (61-100):** Strong Evil Twin indicators, avoid connecting

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

## Technologies Used

- **Backend:** Python 3, Flask
- **Frontend:** HTML5, CSS3, JavaScript (Vanilla)
- **Database:** SQLite3
- **WiFi Scanning:** scapy, nmcli, iwlist, iw, netsh
- **Design:** Custom dark cybersecurity theme
