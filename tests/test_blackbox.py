"""
Black-box tests: written from the requirements (FR02, FR03, FR04, FR07, FR08)
without relying on how the code is structured. Techniques used: equivalence
partitioning and boundary-value analysis on the 0-100 risk score, and
input/output checks on the public HTTP API.
"""
import unittest

from scanner.detector import EvilTwinDetector
from tests.support import (net, quiet, load_app, reset_app, wait_for_scan,
                           KNOWN_MAC, SPOOFED_MAC)


def score_with_weight(points):
    """A unique open network scores exactly `points` when the open weight is set to it."""
    d = EvilTwinDetector()
    d.weights['open_network'] = points
    return d.analyze([net('CafeNet', KNOWN_MAC, 'Open')])[0]


class DetectorBlackBox(unittest.TestCase):

    def test_bb01_legitimate_network(self):
        """BB-01 A single WPA2 AP from a known vendor scores 0 (LOW)"""
        r = EvilTwinDetector().analyze([net()])[0]
        self.assertEqual((r['risk_score'], r['risk_level']), (0, 'low'))

    def test_bb02_open_network(self):
        """BB-02 A unique open AP scores 10 (LOW) and lists the open-network factor"""
        r = EvilTwinDetector().analyze([net('CafeNet', encryption='Open')])[0]
        self.assertEqual((r['risk_score'], r['risk_level']), (10, 'low'))
        self.assertIn('Open Network (No Encryption)', [f['factor'] for f in r['risk_factors']])

    def test_bb03_boundary_30_is_low(self):
        """BB-03 Boundary value: score 30 is classified LOW"""
        r = score_with_weight(30)
        self.assertEqual((r['risk_score'], r['risk_level']), (30, 'low'))

    def test_bb04_boundary_31_is_medium(self):
        """BB-04 Boundary value: score 31 is classified MEDIUM"""
        r = score_with_weight(31)
        self.assertEqual((r['risk_score'], r['risk_level']), (31, 'medium'))

    def test_bb05_boundary_60_is_medium(self):
        """BB-05 Boundary value: score 60 is classified MEDIUM"""
        r = score_with_weight(60)
        self.assertEqual((r['risk_score'], r['risk_level']), (60, 'medium'))

    def test_bb06_boundary_61_is_high(self):
        """BB-06 Boundary value: score 61 is classified HIGH"""
        r = score_with_weight(61)
        self.assertEqual((r['risk_score'], r['risk_level']), (61, 'high'))

    def test_bb07_classic_evil_twin(self):
        """BB-07 Open clone of a WPA2 AP (spoofed MAC, +26 dBm, other channel) is HIGH"""
        real = net('Brew & Bean WiFi', KNOWN_MAC, 'WPA2', signal=-52, channel=6)
        clone = net('Brew & Bean WiFi', SPOOFED_MAC, 'Open', signal=-26, channel=11)
        results = {r['bssid']: r for r in EvilTwinDetector().analyze([real, clone])}
        self.assertEqual(results[SPOOFED_MAC]['risk_level'], 'high')
        self.assertGreaterEqual(results[SPOOFED_MAC]['risk_score'], 61)

    def test_bb08_score_capped_at_100(self):
        """BB-08 The risk score never exceeds 100"""
        r = score_with_weight(500)
        self.assertEqual(r['risk_score'], 100)

    def test_bb09_whitelisted_network(self):
        """BB-09 A whitelisted BSSID scores 0 even when it is an obvious clone"""
        d = EvilTwinDetector()
        d.update_whitelist([{'bssid': SPOOFED_MAC}])
        clone = net('Office', SPOOFED_MAC, 'Open', signal=-20)
        results = {r['bssid']: r for r in d.analyze([net('Office'), clone])}
        self.assertEqual(results[SPOOFED_MAC]['risk_score'], 0)
        self.assertTrue(results[SPOOFED_MAC]['is_whitelisted'])

    def test_bb10_empty_scan(self):
        """BB-10 An empty scan result returns an empty list (no error)"""
        self.assertEqual(EvilTwinDetector().analyze([]), [])

    def test_bb11_spoof_target_case_insensitive(self):
        """BB-11 'Free WiFi' matches the spoof-target list regardless of case"""
        r = EvilTwinDetector().analyze([net('  Free WiFi ')])[0]
        self.assertIn('Common Spoof Target', [f['factor'] for f in r['risk_factors']])
        self.assertEqual(r['risk_score'], 5)

    def test_bb12_sorted_by_risk(self):
        """BB-12 Results are returned highest risk first"""
        nets = [net('A'), net('B', SPOOFED_MAC, 'Open'), net('C', encryption='Open')]
        scores = [r['risk_score'] for r in EvilTwinDetector().analyze(nets)]
        self.assertEqual(scores, sorted(scores, reverse=True))


class ApiBlackBox(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = load_app()
        cls.client = cls.app.app.test_client()

    def setUp(self):
        reset_app(self.app)

    def test_bb13_scan_without_tool_reports_demo(self):
        """BB-13 POST /api/scan with no scanning tool returns demo data flagged scan_mode=demo"""
        original = self.app.scanner.scan_method
        self.app.scanner.scan_method = 'none'
        try:
            with quiet():
                r = self.client.post('/api/scan')
                wait_for_scan(self.app)
        finally:
            self.app.scanner.scan_method = original
        self.assertEqual(r.status_code, 200)
        status = self.client.get('/api/scan/status').get_json()
        self.assertEqual(status['scan_mode'], 'demo')
        self.assertEqual(status['network_count'], 10)

    def test_bb14_list_scenarios(self):
        """BB-14 GET /api/simulate/scenarios lists the 6 attack scenarios"""
        ids = [s['id'] for s in self.client.get('/api/simulate/scenarios').get_json()['scenarios']]
        self.assertEqual(ids, ['coffee_shop', 'corporate', 'airport', 'university', 'hotel', 'multi_attack'])

    def test_bb15_unknown_scenario(self):
        """BB-15 POST /api/simulate/<unknown> returns 404 JSON"""
        r = self.client.post('/api/simulate/does_not_exist')
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json()['status'], 'error')

    def test_bb16_whitelist_add_list_remove(self):
        """BB-16 Whitelist: add (200), list contains it, delete removes it"""
        bssid = '30:B5:C2:A1:44:21'
        self.assertEqual(self.client.post('/api/whitelist', json={'bssid': bssid, 'ssid': 'Cafe'}).status_code, 200)
        listed = [w['bssid'] for w in self.client.get('/api/whitelist').get_json()['whitelist']]
        self.assertIn(bssid, listed)
        self.assertEqual(self.client.delete('/api/whitelist', json={'bssid': bssid}).status_code, 200)
        self.assertEqual(self.client.get('/api/whitelist').get_json()['whitelist'], [])

    def test_bb17_whitelist_rejects_bad_input(self):
        """BB-17 Whitelist rejects null / missing / malformed bodies and bad BSSIDs with 400 JSON"""
        cases = [dict(data='null', content_type='application/json'),
                 dict(),
                 dict(data='{bssid:', content_type='application/json'),
                 dict(json={'bssid': 'not-a-mac'}),
                 dict(json={'ssid': 'no bssid'})]
        for kw in cases:
            r = self.client.post('/api/whitelist', **kw)
            self.assertEqual(r.status_code, 400, kw)
            self.assertEqual(r.get_json()['status'], 'error', kw)

    def test_bb18_not_found(self):
        """BB-18 Unknown page returns the 404 HTML page; unknown API path returns 404 JSON"""
        page = self.client.get('/no-such-page')
        self.assertEqual(page.status_code, 404)
        self.assertIn('text/html', page.content_type)
        api = self.client.get('/api/no-such-endpoint')
        self.assertEqual(api.status_code, 404)
        self.assertEqual(api.get_json()['status'], 'error')

    def test_bb20_demo_reason_reported(self):
        """BB-20 When demo data is used, /api/networks explains why (scan_note)"""
        original = self.app.scanner.scan_method
        self.app.scanner.scan_method = 'none'
        try:
            with quiet():
                self.client.post('/api/scan')
                wait_for_scan(self.app)
        finally:
            self.app.scanner.scan_method = original
        data = self.client.get('/api/networks').get_json()
        self.assertEqual(data['scan_mode'], 'demo')
        self.assertIn('No Wi-Fi scanning tool', data['scan_note'])

    def test_bb19_scan_while_busy(self):
        """BB-19 Starting a scan while one is running returns 409"""
        self.app.scan_state['is_scanning'] = True
        r = self.client.post('/api/scan')
        self.assertEqual(r.status_code, 409)


if __name__ == '__main__':
    unittest.main()
