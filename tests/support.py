"""Shared helpers for the test suite."""
import contextlib
import io
import time
from datetime import datetime

KNOWN_MAC = '30:B5:C2:00:00:01'      # TP-Link OUI, globally administered
SPOOFED_MAC = '02:11:22:33:44:55'    # locally administered bit set
UNKNOWN_MAC = '00:11:22:33:44:55'    # unknown vendor, globally administered


def net(ssid='HomeNet', bssid=KNOWN_MAC, encryption='WPA2', signal=-50, channel=6):
    """Build a network dict in the same format WiFiScanner returns."""
    return {
        'ssid': ssid,
        'bssid': bssid,
        'signal_strength': signal,
        'channel': channel,
        'frequency': '5GHz' if channel > 14 else '2.4GHz',
        'encryption': encryption,
        'timestamp': datetime.now().isoformat(),
    }


def quiet():
    """Silence the components' console prints during a test."""
    return contextlib.redirect_stdout(io.StringIO())


def load_app():
    """Import the Flask app module quietly."""
    with quiet():
        import app as appmod
    return appmod


def reset_app(appmod):
    """Put the app's global state back to a clean starting point."""
    appmod.scan_state.update({'is_scanning': False, 'last_scan': None, 'scan_mode': None, 'scan_note': None,
                              'networks': [], 'alerts': []})
    conn = appmod.db._connect()
    conn.executescript('DELETE FROM alerts; DELETE FROM networks; DELETE FROM scans; DELETE FROM whitelist;')
    conn.commit()
    conn.close()
    appmod.detector.update_whitelist([])
    appmod.detector.network_history.clear()


def wait_for_scan(appmod, timeout=15):
    """Block until the background scan/simulation thread has finished."""
    deadline = time.time() + timeout
    time.sleep(0.05)
    while appmod.scan_state['is_scanning']:
        if time.time() > deadline:
            raise TimeoutError('scan did not finish')
        time.sleep(0.02)
