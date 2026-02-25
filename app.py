"""
Fake WiFi Hotspot Detector - Evil Twin Attack Detection System
Main Flask Application
"""

import os
import json
import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from scanner.wifi_scanner import WiFiScanner
from scanner.detector import EvilTwinDetector
from scanner.simulator import ThreatSimulator
from models.database import Database

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize components
db = Database()
scanner = WiFiScanner()
detector = EvilTwinDetector()
simulator = ThreatSimulator()

# Global state for scan results
scan_state = {
    'is_scanning': False,
    'last_scan': None,
    'networks': [],
    'alerts': [],
    'scan_history': []
}


# ─────────────────────────────────────────────
# Routes - Web Pages
# ─────────────────────────────────────────────

@app.route('/')
def dashboard():
    """Main dashboard page."""
    stats = db.get_statistics()
    recent_alerts = db.get_recent_alerts(limit=10)
    return render_template('dashboard.html', stats=stats, alerts=recent_alerts)


@app.route('/history')
def history():
    """Scan history page."""
    scans = db.get_scan_history(limit=50)
    return render_template('history.html', scans=scans)


@app.route('/network/<bssid>')
def network_detail(bssid):
    """Detailed view of a specific network."""
    network = db.get_network_details(bssid)
    return render_template('network_detail.html', network=network)


# ─────────────────────────────────────────────
# API Routes - Scanning & Detection
# ─────────────────────────────────────────────

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Trigger a new WiFi scan."""
    if scan_state['is_scanning']:
        return jsonify({'status': 'error', 'message': 'Scan already in progress'}), 409

    def run_scan():
        scan_state['is_scanning'] = True
        try:
            # Step 1: Scan nearby WiFi networks
            networks = scanner.scan()

            # Step 2: Analyze each network for Evil Twin indicators
            analyzed_networks = detector.analyze(networks)

            # Step 3: Store results
            scan_id = db.save_scan(analyzed_networks)

            scan_state['networks'] = analyzed_networks
            scan_state['last_scan'] = datetime.now().isoformat()
            scan_state['alerts'] = [
                n for n in analyzed_networks if n['risk_level'] in ('medium', 'high')
            ]
        except Exception as e:
            print(f"Scan error: {e}")
        finally:
            scan_state['is_scanning'] = False

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({'status': 'ok', 'message': 'Scan started'})


@app.route('/api/scan/status')
def scan_status():
    """Get current scan status and results."""
    return jsonify({
        'is_scanning': scan_state['is_scanning'],
        'last_scan': scan_state['last_scan'],
        'network_count': len(scan_state['networks']),
        'alert_count': len(scan_state['alerts']),
    })


@app.route('/api/networks')
def get_networks():
    """Get all detected networks from the last scan."""
    return jsonify({
        'networks': scan_state['networks'],
        'last_scan': scan_state['last_scan']
    })


@app.route('/api/alerts')
def get_alerts():
    """Get current alerts (medium and high risk networks)."""
    return jsonify({
        'alerts': scan_state['alerts'],
        'count': len(scan_state['alerts'])
    })


@app.route('/api/statistics')
def get_statistics():
    """Get overall system statistics."""
    stats = db.get_statistics()
    return jsonify(stats)


@app.route('/api/network/<bssid>/history')
def network_history_api(bssid):
    """Get historical data for a specific network."""
    history = db.get_network_history(bssid)
    return jsonify({'bssid': bssid, 'history': history})


@app.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
def manage_whitelist():
    """Manage trusted networks whitelist."""
    if request.method == 'GET':
        return jsonify({'whitelist': db.get_whitelist()})

    elif request.method == 'POST':
        data = request.json
        bssid = data.get('bssid')
        ssid = data.get('ssid', '')
        if bssid:
            db.add_to_whitelist(bssid, ssid)
            detector.update_whitelist(db.get_whitelist())
            return jsonify({'status': 'ok', 'message': f'{ssid} added to whitelist'})
        return jsonify({'status': 'error', 'message': 'BSSID required'}), 400

    elif request.method == 'DELETE':
        data = request.json
        bssid = data.get('bssid')
        if bssid:
            db.remove_from_whitelist(bssid)
            detector.update_whitelist(db.get_whitelist())
            return jsonify({'status': 'ok', 'message': 'Removed from whitelist'})
        return jsonify({'status': 'error', 'message': 'BSSID required'}), 400


# ─────────────────────────────────────────────
# API Routes - Simulation Mode
# ─────────────────────────────────────────────

@app.route('/api/simulate/scenarios')
def get_scenarios():
    """Get available simulation scenarios."""
    return jsonify({'scenarios': simulator.get_available_scenarios()})


@app.route('/api/simulate/<scenario_id>', methods=['POST'])
def run_simulation(scenario_id):
    """Run a specific attack simulation scenario."""
    if scan_state['is_scanning']:
        return jsonify({'status': 'error', 'message': 'Scan already in progress'}), 409

    def run_sim():
        scan_state['is_scanning'] = True
        try:
            # Step 1: Generate simulated networks for this scenario
            networks = simulator.simulate(scenario_id)

            # Step 2: Run through the real detection engine
            analyzed_networks = detector.analyze(networks)

            # Step 3: Store results (same as real scan)
            scan_id = db.save_scan(analyzed_networks)

            scan_state['networks'] = analyzed_networks
            scan_state['last_scan'] = datetime.now().isoformat()
            scan_state['alerts'] = [
                n for n in analyzed_networks if n['risk_level'] in ('medium', 'high')
            ]
        except Exception as e:
            print(f"Simulation error: {e}")
        finally:
            scan_state['is_scanning'] = False

    thread = threading.Thread(target=run_sim, daemon=True)
    thread.start()

    return jsonify({'status': 'ok', 'message': f'Simulation "{scenario_id}" started'})


# ─────────────────────────────────────────────
# Error Handlers
# ─────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


# ─────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 60)
    print("  Evil Twin Attack Detection System")
    print("  Fake WiFi Hotspot Detector")
    print("=" * 60)
    print(f"  Dashboard: http://127.0.0.1:5000")
    print(f"  Note: Run with sudo for full WiFi scanning capability")
    print("=" * 60)

    db.initialize()
    app.run(debug=True, host='0.0.0.0', port=5000)
