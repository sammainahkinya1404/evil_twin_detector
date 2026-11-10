"""
Fake WiFi Hotspot Detector - Evil Twin Attack Detection System
Main Flask Application
"""

import os
import re
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from scanner.wifi_scanner import WiFiScanner
from scanner.detector import EvilTwinDetector
from scanner.simulator import ThreatSimulator
from models.database import Database

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize components
db = Database()          # creates the schema if it does not exist yet
scanner = WiFiScanner()
detector = EvilTwinDetector()
simulator = ThreatSimulator()

# Load the saved whitelist into the detector at startup.
# Previously the detector started with an empty whitelist and only learned
# about trusted networks after the next add/remove call, so every restart
# silently "forgot" the user's trusted networks.
detector.update_whitelist(db.get_whitelist())

# Global state for scan results
scan_state = {
    'is_scanning': False,
    'last_scan': None,
    'scan_mode': None,      # 'live', 'demo' or 'simulation'
    'scan_note': None,      # why demo data was used, shown on the dashboard
    'networks': [],
    'alerts': [],
    'scan_history': []
}

# Guards scan_state['is_scanning'] so two requests arriving at the same time
# cannot both start a scan. Previously the flag was only set inside the
# worker thread, leaving a window in which a second request was accepted.
scan_lock = threading.Lock()

MAC_PATTERN = re.compile(r'^[0-9A-F]{2}(:[0-9A-F]{2}){5}$')


def start_background_job(produce_networks, source_of):
    """
    Run scan -> detect -> store in a background thread.

    Returns False if a scan is already running. The busy flag is set while
    holding the lock and *before* the thread starts, which closes the race.
    """
    with scan_lock:
        if scan_state['is_scanning']:
            return False
        scan_state['is_scanning'] = True

    def worker():
        try:
            # Step 1: get networks (real scan or simulation)
            networks = produce_networks()

            # Step 2: analyze each network for Evil Twin indicators
            analyzed_networks = detector.analyze(networks)

            # Step 3: store results
            db.save_scan(analyzed_networks)

            scan_state['networks'] = analyzed_networks
            scan_state['last_scan'] = datetime.now().isoformat()
            scan_state['scan_mode'], scan_state['scan_note'] = source_of()
            scan_state['alerts'] = [
                n for n in analyzed_networks if n['risk_level'] in ('medium', 'high')
            ]
        except Exception as e:
            print(f"Scan error: {e}")
        finally:
            scan_state['is_scanning'] = False

    threading.Thread(target=worker, daemon=True).start()
    return True


def json_body():
    """Return the request's JSON object, or None if it is missing or not an object."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


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
    if not start_background_job(scanner.scan,
                                lambda: (scanner.last_scan_mode, scanner.last_scan_note)):
        return jsonify({'status': 'error', 'message': 'Scan already in progress'}), 409
    return jsonify({'status': 'ok', 'message': 'Scan started'})


@app.route('/api/scan/status')
def scan_status():
    """Get current scan status and results."""
    return jsonify({
        'is_scanning': scan_state['is_scanning'],
        'last_scan': scan_state['last_scan'],
        'scan_mode': scan_state['scan_mode'],
        'scan_note': scan_state['scan_note'],
        'network_count': len(scan_state['networks']),
        'alert_count': len(scan_state['alerts']),
    })


@app.route('/api/networks')
def get_networks():
    """Get all detected networks from the last scan."""
    return jsonify({
        'networks': scan_state['networks'],
        'last_scan': scan_state['last_scan'],
        'scan_mode': scan_state['scan_mode'],
        'scan_note': scan_state['scan_note'],
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

    # POST / DELETE: validate the body instead of assuming it is a JSON object.
    # Previously request.json returned None for a "null" body and the
    # following .get() raised AttributeError -> HTTP 500.
    data = json_body()
    if data is None:
        return jsonify({'status': 'error', 'message': 'Request body must be a JSON object'}), 400

    bssid = str(data.get('bssid') or '').strip().upper()
    if not MAC_PATTERN.match(bssid):
        return jsonify({'status': 'error',
                        'message': 'A valid BSSID (AA:BB:CC:DD:EE:FF) is required'}), 400

    if request.method == 'POST':
        ssid = str(data.get('ssid') or '')
        db.add_to_whitelist(bssid, ssid)
        detector.update_whitelist(db.get_whitelist())
        return jsonify({'status': 'ok', 'message': f'{ssid} added to whitelist'})

    db.remove_from_whitelist(bssid)
    detector.update_whitelist(db.get_whitelist())
    return jsonify({'status': 'ok', 'message': 'Removed from whitelist'})


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
    if scenario_id not in simulator.scenarios:
        return jsonify({'status': 'error', 'message': f'Unknown scenario: {scenario_id}'}), 404
    if not start_background_job(lambda: simulator.simulate(scenario_id), lambda: ('simulation', None)):
        return jsonify({'status': 'error', 'message': 'Scan already in progress'}), 409
    return jsonify({'status': 'ok', 'message': f'Simulation "{scenario_id}" started'})


# ─────────────────────────────────────────────
# Error Handlers
# ─────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'status': 'error', 'message': 'Not found'}), 404
    return render_template('404.html'), 404


@app.errorhandler(400)
@app.errorhandler(405)
@app.errorhandler(415)
def client_error(e):
    """Return JSON (not an HTML page) for bad API requests."""
    if request.path.startswith('/api/'):
        return jsonify({'status': 'error', 'message': e.description}), e.code
    return e


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
    print(f"  Scan method: {scanner.scan_method}")
    print(f"  Note: Run with sudo for full WiFi scanning capability")
    print("=" * 60)

    app.run(debug=True, host='0.0.0.0', port=5000)
