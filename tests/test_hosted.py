"""
Hosted-mode tests (e.g. Render): the server has no Wi-Fi radio, every visitor
is isolated, scans are pasted from the visitor's own computer, and the
connection check works for anyone. HM-xx IDs are used in the report.
"""
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from scanner import network_probe
from scanner.wifi_scanner import WiFiScanner
from models.database import Database
from tests.support import quiet, load_app, reset_app, wait_for_scan
from tests.test_whitebox import NETSH_SAMPLE, NMCLI_SAMPLE


class HostedApp(unittest.TestCase):
    """The Flask app as it runs on Render: hosted, no scanning tool."""

    @classmethod
    def setUpClass(cls):
        cls.app = load_app()

    def setUp(self):
        reset_app(self.app)
        with self.app.clients_lock:
            for cid in [c for c in self.app.clients if c != 'local']:
                del self.app.clients[cid]
        self.patches = [mock.patch.object(self.app, 'HOSTED', True),
                        mock.patch.object(self.app.scanner, 'scan_method', 'none')]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def visitor(self):
        c = self.app.app.test_client()
        c.environ_base['wsgi.url_scheme'] = 'https'      # the hosted cookie is Secure
        return c

    def simulate(self, client, scenario):
        client.post(f'/api/simulate/{scenario}')
        cid = client.get_cookie('etg_client').value
        wait_for_scan(type('S', (), {'scan_state': self.app.get_client(cid).state}))

    def test_hm01_capabilities_without_wifi(self):
        """HM-01 /api/capabilities reports hosted mode and no live scan on a server without Wi-Fi"""
        caps = self.visitor().get('/api/capabilities').get_json()
        self.assertTrue(caps['hosted'])
        self.assertFalse(caps['live_scan'])

    def test_hm02_live_scan_refused_with_explanation(self):
        """HM-02 POST /api/scan on the hosted server returns 503 with an explanation, not demo data"""
        r = self.visitor().post('/api/scan')
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.get_json()['code'], 'no_wifi_on_server')

    def test_hm03_visitors_are_isolated(self):
        """HM-03 Two visitors see only their own results, statistics and history"""
        a, b = self.visitor(), self.visitor()
        self.simulate(a, 'coffee_shop')
        self.simulate(b, 'airport')
        self.assertEqual(len(a.get('/api/networks').get_json()['networks']), 8)
        self.assertEqual(len(b.get('/api/networks').get_json()['networks']), 12)
        self.assertEqual(a.get('/api/statistics').get_json()['total_scans'], 1)
        self.assertEqual(b.get('/api/statistics').get_json()['unique_networks'], 12)
        self.assertNotEqual(a.get_cookie('etg_client').value, b.get_cookie('etg_client').value)

    def test_hm04_whitelist_cannot_affect_other_visitors(self):
        """HM-04 A visitor who trusts a network (e.g. an attacker trusting their clone) changes nothing for others"""
        attacker, victim = self.visitor(), self.visitor()
        attacker.post('/api/whitelist', json={'bssid': '30:B5:C2:A1:44:21', 'ssid': 'Brew & Bean WiFi'})
        self.simulate(victim, 'coffee_shop')
        real = next(n for n in victim.get('/api/networks').get_json()['networks']
                    if n['bssid'] == '30:B5:C2:A1:44:21')
        self.assertFalse(real['is_whitelisted'])
        self.assertEqual(victim.get('/api/whitelist').get_json()['whitelist'], [])

    def test_hm05_forged_client_cookie_rejected(self):
        """HM-05 A forged cookie such as 'local' gets a fresh id and cannot read the local user's data"""
        reset_app(self.app)
        self.app.db.save_scan([], 'local')
        c = self.visitor()
        c.set_cookie('etg_client', 'local', domain='localhost')
        stats = c.get('/api/statistics').get_json()
        self.assertEqual(stats['total_scans'], 0)
        self.assertRegex(c.get_cookie('etg_client').value, r'^[0-9a-f]{32}$')

    def test_hm06_import_netsh(self):
        """HM-06 Pasted netsh output is parsed, analysed and shown as an imported scan"""
        c = self.visitor()
        r = c.post('/api/scan/import', json={'text': NETSH_SAMPLE})
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.get_json()['format'], r.get_json()['network_count']), ('netsh', 3))
        data = c.get('/api/networks').get_json()
        self.assertEqual(data['scan_mode'], 'imported')
        self.assertEqual(len(data['networks']), 3)

    def test_hm07_import_nmcli(self):
        """HM-07 Pasted nmcli output is parsed and analysed"""
        r = self.visitor().post('/api/scan/import', json={'text': NMCLI_SAMPLE})
        self.assertEqual((r.status_code, r.get_json()['format']), (200, 'nmcli'))

    def test_hm08_import_rejects_bad_input(self):
        """HM-08 Unrecognised text -> 400, missing text -> 400, over 200,000 characters -> 413"""
        c = self.visitor()
        self.assertEqual(c.post('/api/scan/import', json={'text': 'hello world'}).status_code, 400)
        self.assertEqual(c.post('/api/scan/import', json={'text': 5}).status_code, 400)
        self.assertEqual(c.post('/api/scan/import', json={'text': 'x' * 200_001}).status_code, 413)

    def test_hm09_dashboard_explains_missing_scan(self):
        """HM-09 The hosted dashboard disables Start Scan and explains why"""
        html = self.visitor().get('/').get_data(as_text=True)
        self.assertIn('Live Scan Unavailable Online', html)
        self.assertIn('Why there is no live scan here', html)
        self.assertIn('Paste a Scan', html)
        self.assertNotIn('Click <strong>Start Scan</strong> to begin', html)   # no hint to use the disabled button

    def test_hm10_connection_info_uses_visitor_ip(self):
        """HM-10 /api/connection/info looks up the visitor's IP from True-Client-IP"""
        fake = {'query': '102.0.0.10', 'isp': 'Example Mobile', 'mobile': True, 'proxy': False, 'hosting': False}
        with mock.patch.object(network_probe, 'lookup_ip', return_value=fake) as lookup:
            r = self.visitor().get('/api/connection/info', headers={'True-Client-IP': '102.0.0.10'})
        lookup.assert_called_once_with('102.0.0.10')
        body = r.get_json()
        self.assertEqual(body['ip_source'], 'proxy')
        self.assertEqual(body['findings'][0]['level'], 'warning')
        self.assertEqual(r.headers['Cache-Control'], 'no-store')


class ProbeHelpers(unittest.TestCase):

    def test_hm11_client_ip_precedence(self):
        """HM-11 Visitor IP: True-Client-IP, then CF-Connecting-IP, then X-Forwarded-For (unverified), then socket"""
        ip = network_probe.client_ip
        self.assertEqual(ip({'True-Client-IP': '8.8.8.8', 'X-Forwarded-For': '1.1.1.1'}, '10.0.0.1'), ('8.8.8.8', 'proxy'))
        self.assertEqual(ip({'CF-Connecting-IP': '9.9.9.9'}, '10.0.0.1'), ('9.9.9.9', 'proxy'))
        self.assertEqual(ip({'X-Forwarded-For': '1.1.1.1, 10.0.0.2'}, '10.0.0.1'), ('1.1.1.1', 'forwarded (unverified)'))
        self.assertEqual(ip({'True-Client-IP': 'not-an-ip'}, '127.0.0.1'), ('127.0.0.1', 'direct'))

    def test_hm12_lookup_cache_limit_and_errors(self):
        """HM-12 IP lookup: cached for 10 minutes, rate-limited, and failures are reported, not raised"""
        network_probe._cache.clear()
        network_probe._calls.clear()
        calls = []
        ok = {'status': 'success', 'query': '8.8.4.4', 'isp': 'X', 'mobile': False, 'proxy': False, 'hosting': True}

        def fetch(url):
            calls.append(url)
            return ok
        t = [1000.0]
        first = network_probe.lookup_ip('8.8.4.4', fetch=fetch, now=lambda: t[0])
        again = network_probe.lookup_ip('8.8.4.4', fetch=fetch, now=lambda: t[0] + 60)
        self.assertEqual(len(calls), 1)
        self.assertEqual(first, again)
        failed = network_probe.lookup_ip('1.2.3.4', fetch=lambda u: (_ for _ in ()).throw(OSError()), now=lambda: t[0])
        self.assertIn('error', failed)
        network_probe._calls[:] = [t[0]] * network_probe.MAX_CALLS_PER_MINUTE
        limited = network_probe.lookup_ip('5.6.7.8', fetch=fetch, now=lambda: t[0] + 1)
        self.assertIn('rate-limited', limited['error'])
        network_probe._cache.clear()
        network_probe._calls.clear()

    def test_hm13_assessment(self):
        """HM-13 Findings: mobile -> warning, VPN/data centre -> warning, regular provider -> ok, lookup error -> none"""
        assess = network_probe.assess_connection
        self.assertEqual(assess({'mobile': True})[0]['level'], 'warning')
        self.assertEqual(assess({'hosting': True})[0]['level'], 'warning')
        self.assertEqual(assess({'mobile': False, 'proxy': False, 'hosting': False})[0]['level'], 'ok')
        self.assertEqual(assess({'error': 'x'}), [])

    def test_hm14_ping_and_payload(self):
        """HM-14 Speed-test payload is clamped to 16 KB - 2 MB and never cached"""
        client = load_app().app.test_client()
        self.assertEqual(len(client.get('/api/connection/payload?kb=1').data), 16 * 1024)
        self.assertEqual(len(client.get('/api/connection/payload?kb=99999').data), 2048 * 1024)
        self.assertEqual(len(client.get('/api/connection/payload?kb=abc').data), 512 * 1024)
        self.assertEqual(client.get('/api/connection/ping').headers['Cache-Control'], 'no-store')

    def test_hm15_server_interfaces(self):
        """HM-15 describe_interfaces() lists the server's interfaces and finds wireless ones"""
        root = tempfile.mkdtemp()
        for name in ('eth0', 'lo', 'wlan0'):
            os.makedirs(os.path.join(root, name))
        os.makedirs(os.path.join(root, 'wlan0', 'wireless'))
        with mock.patch('platform.system', return_value='Linux'):
            info = network_probe.describe_interfaces(root)
        self.assertEqual(info['interfaces'], ['eth0', 'lo', 'wlan0'])
        self.assertEqual(info['wireless'], ['wlan0'])

    def test_hm16_parse_pasted_scan_detection(self):
        """HM-16 Pasted text is recognised as netsh or nmcli; anything else is rejected"""
        s = WiFiScanner.__new__(WiFiScanner)
        self.assertEqual(network_probe.parse_pasted_scan(NETSH_SAMPLE, s, 't')[1], 'netsh')
        self.assertEqual(network_probe.parse_pasted_scan(NMCLI_SAMPLE, s, 't')[1], 'nmcli')
        self.assertEqual(network_probe.parse_pasted_scan('ipconfig output', s, 't'), ([], None))


class DatabaseUpgrade(unittest.TestCase):

    def test_hm17_old_database_upgraded(self):
        """HM-17 A database from before visitors existed is upgraded; old data belongs to the local user"""
        path = os.path.join(tempfile.mkdtemp(), 'old.db')
        con = sqlite3.connect(path)
        con.executescript('''
            CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                total_networks INTEGER DEFAULT 0, high_risk_count INTEGER DEFAULT 0,
                medium_risk_count INTEGER DEFAULT 0, low_risk_count INTEGER DEFAULT 0,
                threat_level TEXT DEFAULT 'safe');
            CREATE TABLE whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, bssid TEXT UNIQUE NOT NULL,
                ssid TEXT, added_date TEXT, notes TEXT);
            INSERT INTO scans (timestamp) VALUES ('2026-02-01T10:00:00');
            INSERT INTO whitelist (bssid, ssid) VALUES ('30:B5:C2:A1:44:21', 'Cafe');
        ''')
        con.commit()
        con.close()
        with quiet():
            db = Database(path)
        self.assertEqual(db.get_statistics('local')['total_scans'], 1)
        self.assertEqual(db.get_statistics('someone-else')['total_scans'], 0)
        self.assertEqual([w['bssid'] for w in db.get_whitelist('local')], ['30:B5:C2:A1:44:21'])
        db.add_to_whitelist('30:B5:C2:A1:44:21', 'Cafe', client_id='visitor')   # same BSSID, other visitor
        self.assertEqual(len(db.get_whitelist('visitor')), 1)


if __name__ == '__main__':
    unittest.main()
