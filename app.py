"""
Fake WiFi Hotspot Detector - Evil Twin Attack Detection System
Main Flask Application

Two ways to run it:
  * On your own computer (python app.py): one user, live Wi-Fi scans through
    the operating system's tools (netsh / nmcli / iw / airport).
  * Hosted (e.g. Render, detected through the RENDER environment variable, or
    EVILTWIN_HOSTED=1): the server is in a data centre with no Wi-Fi radio and
    browsers cannot scan Wi-Fi, so visitors paste a scan from their own
    computer, run the automatic connection check, or simulate an attack.
    Every visitor gets their own results, history and whitelist.
"""

import os
import re
import threading
import uuid
from collections import OrderedDict
from datetime import datetime
from flask import Flask, render_template, jsonify, request, g, make_response
from scanner.wifi_scanner import WiFiScanner
from scanner.detector import EvilTwinDetector
from scanner.simulator import ThreatSimulator
from scanner import network_probe
from models.database import Database, LOCAL

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

HOSTED = os.environ.get('EVILTWIN_HOSTED', '1' if os.environ.get('RENDER') else '0') == '1'
CLIENT_COOKIE = 'etg_client'
CLIENT_ID_PATTERN = re.compile(r'^[0-9a-f]{32}$')
MAX_CLIENTS_IN_MEMORY = 500

# Initialize components
db = Database()          # creates (or upgrades) the schema
scanner = WiFiScanner()
simulator = ThreatSimulator()
SERVER_INTERFACES = network_probe.describe_interfaces()
print(f"[Server] Mode: {'hosted' if HOSTED else 'local'} | interfaces: "
      f"{', '.join(SERVER_INTERFACES['interfaces']) or 'unknown'} | wireless: "
      f"{', '.join(SERVER_INTERFACES['wireless']) or 'none'}")


def new_state():
    return {
        'is_scanning': False,
        'last_scan': None,
        'scan_mode': None,      # 'live', 'demo', 'imported' or 'simulation'
        'scan_note': None,      # where the data came from, shown on the dashboard
        'networks': [],
        'alerts': [],
        'scan_history': []
    }


class Client:
    """Everything that must not be shared between visitors."""

    def __init__(self, client_id):
        self.id = client_id
        self.state = new_state()
        self.lock = threading.Lock()
        self.detector = EvilTwinDetector()
        # Load the saved whitelist at start-up. Previously the detector began
        # empty and only learned about trusted networks after the next
        # add/remove call, so every restart "forgot" them.
        self.detector.update_whitelist(db.get_whitelist(client_id))


clients = OrderedDict()
clients_lock = threading.Lock()


def get_client(client_id):
    """Return the Client for an id, keeping at most MAX_CLIENTS_IN_MEMORY (least recently used out)."""
    with clients_lock:
        client = clients.get(client_id)
        if client is None:
            client = clients[client_id] = Client(client_id)
            while len(clients) > MAX_CLIENTS_IN_MEMORY:
                oldest = next(iter(clients))
                if oldest == LOCAL:
                    clients.move_to_end(oldest)
                    continue
                clients.popitem(last=False)
        clients.move_to_end(client_id)
        return client


# The local user's state (also used by the single-user desktop mode and the tests)
local_client = get_client(LOCAL)
scan_state = local_client.state
detector = local_client.detector

MAC_PATTERN = re.compile(r'^[0-9A-F]{2}(:[0-9A-F]{2}){5}$')


@app.before_request
def identify_client():
    """Hosted: one anonymous id per browser (cookie). Local: a single user."""
    if not HOSTED:
        g.client_id, g.new_cookie = LOCAL, False
        return
    cid = request.cookies.get(CLIENT_COOKIE, '')
    g.new_cookie = not CLIENT_ID_PATTERN.match(cid)
    g.client_id = uuid.uuid4().hex if g.new_cookie else cid


@app.after_request
def set_client_cookie(response):
    if getattr(g, 'new_cookie', False):
        response.set_cookie(CLIENT_COOKIE, g.client_id, max_age=365 * 24 * 3600,
                            httponly=True, samesite='Lax', secure=request.is_secure or HOSTED)
    return response


def current():
    return get_client(g.client_id)


def finish_scan(client, analyzed_networks, mode, note):
    """Store an analysed scan and make it the client's current result."""
    db.save_scan(analyzed_networks, client.id)
    state = client.state
    state['networks'] = analyzed_networks
    state['last_scan'] = datetime.now().isoformat()
    state['scan_mode'], state['scan_note'] = mode, note
    state['alerts'] = [n for n in analyzed_networks if n['risk_level'] in ('medium', 'high')]


def start_background_job(produce_networks, source_of, client=None):
    """
    Run scan -> detect -> store in a background thread.

    Returns False if a scan is already running for this client. The busy flag
    is set while holding the lock and *before* the thread starts, which
    closes the race between two simultaneous requests.
    """
    client = client or local_client
    with client.lock:
        if client.state['is_scanning']:
            return False
        client.state['is_scanning'] = True

    def worker():
        try:
            networks = produce_networks()
            analyzed = client.detector.analyze(networks)
            finish_scan(client, analyzed, *source_of())
        except Exception as e:
            print(f"Scan error: {e}")
        finally:
            client.state['is_scanning'] = False

    threading.Thread(target=worker, daemon=True).start()
    return True


def live_scan_available():
    return scanner.scan_method != 'none'


def json_body():
    """Return the request's JSON object, or None if it is missing or not an object."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def no_store(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


# ─────────────────────────────────────────────
# Routes - Web Pages
# ─────────────────────────────────────────────

@app.route('/')
def dashboard():
    """Main dashboard page."""
    stats = db.get_statistics(g.client_id)
    recent_alerts = db.get_recent_alerts(limit=10, client_id=g.client_id)
    return render_template('dashboard.html', stats=stats, alerts=recent_alerts,
                           live_scan=live_scan_available(), hosted=HOSTED)


@app.route('/history')
def history():
    """Scan history page."""
    scans = db.get_scan_history(limit=50, client_id=g.client_id)
    return render_template('history.html', scans=scans)


@app.route('/network/<bssid>')
def network_detail(bssid):
    """Detailed view of a specific network."""
    network = db.get_network_details(bssid, g.client_id)
    return render_template('network_detail.html', network=network)


# ─────────────────────────────────────────────
# API Routes - Scanning & Detection
# ─────────────────────────────────────────────

@app.route('/api/capabilities')
def capabilities():
    """What this server can do (the dashboard adapts to it)."""
    return jsonify({
        'hosted': HOSTED,
        'live_scan': live_scan_available(),
        'scan_method': scanner.scan_method,
        'server_os': SERVER_INTERFACES['system'],
        'server_wireless_interfaces': SERVER_INTERFACES['wireless'],
    })


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Trigger a new WiFi scan."""
    if HOSTED and not live_scan_available():
        return jsonify({
            'status': 'error', 'code': 'no_wifi_on_server',
            'message': 'This website runs on a server in a data centre, which has no Wi-Fi radio, and '
                       'browsers do not let websites scan Wi-Fi. Use "Paste a scan" to analyse the '
                       'networks around you, "Check my connection", or "Simulate Attack".'}), 503
    if not start_background_job(scanner.scan,
                                lambda: (scanner.last_scan_mode, scanner.last_scan_note),
                                current()):
        return jsonify({'status': 'error', 'message': 'Scan already in progress'}), 409
    return jsonify({'status': 'ok', 'message': 'Scan started'})


@app.route('/api/scan/import', methods=['POST'])
def import_scan():
    """Analyse scan output (netsh / nmcli) pasted from the visitor's own computer."""
    data = json_body()
    if data is None or not isinstance(data.get('text'), str):
        return jsonify({'status': 'error', 'message': 'Send the pasted scan as {"text": "..."}'}), 400
    text = data['text']
    if len(text) > network_probe.MAX_PASTE_CHARS:
        return jsonify({'status': 'error', 'message': 'The pasted text is too long (limit 200,000 characters).'}), 413
    networks, fmt = network_probe.parse_pasted_scan(text, scanner, datetime.now().isoformat())
    if not networks:
        return jsonify({'status': 'error', 'message':
                        'No access points were found in the pasted text. Paste the complete output of the '
                        'command shown for your system (English-language Windows or Linux).'}), 400
    client = current()
    with client.lock:
        if client.state['is_scanning']:
            return jsonify({'status': 'error', 'message': 'Scan already in progress'}), 409
        client.state['is_scanning'] = True
    try:
        analyzed = client.detector.analyze(networks)
        finish_scan(client, analyzed, 'imported',
                    f'Pasted {fmt} output from your computer ({len(analyzed)} access points).')
    finally:
        client.state['is_scanning'] = False
    return jsonify({'status': 'ok', 'format': fmt, 'network_count': len(analyzed),
                    'alert_count': len(client.state['alerts'])})


@app.route('/api/scan/status')
def scan_status():
    """Get current scan status and results."""
    state = current().state
    return jsonify({
        'is_scanning': state['is_scanning'],
        'last_scan': state['last_scan'],
        'scan_mode': state['scan_mode'],
        'scan_note': state['scan_note'],
        'network_count': len(state['networks']),
        'alert_count': len(state['alerts']),
    })


@app.route('/api/networks')
def get_networks():
    """Get all detected networks from the last scan."""
    state = current().state
    return jsonify({
        'networks': state['networks'],
        'last_scan': state['last_scan'],
        'scan_mode': state['scan_mode'],
        'scan_note': state['scan_note'],
    })


@app.route('/api/alerts')
def get_alerts():
    """Get current alerts (medium and high risk networks)."""
    state = current().state
    return jsonify({'alerts': state['alerts'], 'count': len(state['alerts'])})


@app.route('/api/statistics')
def get_statistics():
    """Get this client's statistics."""
    return jsonify(db.get_statistics(g.client_id))


@app.route('/api/network/<bssid>/history')
def network_history_api(bssid):
    """Get historical data for a specific network."""
    return jsonify({'bssid': bssid, 'history': db.get_network_history(bssid, g.client_id)})


@app.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
def manage_whitelist():
    """Manage this client's trusted networks whitelist."""
    client = current()
    if request.method == 'GET':
        return jsonify({'whitelist': db.get_whitelist(client.id)})

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
        db.add_to_whitelist(bssid, ssid, client_id=client.id)
        client.detector.update_whitelist(db.get_whitelist(client.id))
        return jsonify({'status': 'ok', 'message': f'{ssid} added to whitelist'})

    db.remove_from_whitelist(bssid, client.id)
    client.detector.update_whitelist(db.get_whitelist(client.id))
    return jsonify({'status': 'ok', 'message': 'Removed from whitelist'})


# ─────────────────────────────────────────────
# API Routes - Connection check (runs for any visitor, nothing to install)
# ─────────────────────────────────────────────

@app.route('/api/connection/info')
def connection_info():
    """Who provides the visitor's internet connection, and any warning signs."""
    ip, source = network_probe.client_ip(request.headers, request.remote_addr)
    if network_probe.is_public(ip):
        lookup = network_probe.lookup_ip(ip)
    else:
        # Running on the user's own computer: look up this machine's public address instead
        lookup, source = network_probe.lookup_ip(None), 'this computer'
    return no_store(jsonify({
        'ip': lookup.get('query') or ip,
        'ip_source': source,
        'lookup': lookup,
        'findings': network_probe.assess_connection(lookup),
        'privacy': 'Your IP address is looked up with ip-api.com to find your provider; it is not stored.',
    }))


@app.route('/api/connection/ping')
def connection_ping():
    """Tiny response used by the browser to measure round-trip time."""
    return no_store(jsonify({'t': datetime.now().isoformat()}))


@app.route('/api/connection/payload')
def connection_payload():
    """Random (incompressible) bytes for a download-speed measurement, like fast.com."""
    try:
        kb = max(16, min(2048, int(request.args.get('kb', 512))))
    except ValueError:
        kb = 512
    response = make_response(os.urandom(kb * 1024))
    response.headers['Content-Type'] = 'application/octet-stream'
    return no_store(response)


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
    if not start_background_job(lambda: simulator.simulate(scenario_id), lambda: ('simulation', None),
                                current()):
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
@app.errorhandler(413)
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
