"""
Integration tests: the scanner/simulator, detector, database and Flask
routes working together through the real HTTP API. IT-02, IT-03 and IT-04
are regression tests for implementation problems documented in Section 4.7.
"""
import importlib
import os
import tempfile
import threading
import unittest
from unittest import mock

from tests.support import quiet, load_app, reset_app, wait_for_scan


class EndToEnd(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = load_app()
        cls.client = cls.app.app.test_client()

    def setUp(self):
        reset_app(self.app)

    def simulate(self, scenario):
        r = self.client.post(f'/api/simulate/{scenario}')
        wait_for_scan(self.app)
        return r

    def test_it01_simulation_pipeline(self):
        """IT-01 Simulation -> detector -> database -> API: counts agree at every layer"""
        self.assertEqual(self.simulate('coffee_shop').status_code, 200)
        nets = self.client.get('/api/networks').get_json()
        stats = self.client.get('/api/statistics').get_json()
        flagged = [n for n in nets['networks'] if n['risk_level'] in ('medium', 'high')]
        self.assertEqual(len(nets['networks']), 8)
        self.assertEqual(nets['scan_mode'], 'simulation')
        self.assertEqual(stats['total_scans'], 1)
        self.assertEqual(stats['unique_networks'], 8)
        self.assertEqual(stats['total_alerts'], len(flagged))
        self.assertEqual(self.client.get('/api/alerts').get_json()['count'], len(flagged))

    def test_it02_whitelist_survives_restart(self):
        """IT-02 A trusted network stays trusted after the server restarts (Problem 3)"""
        self.simulate('coffee_shop')
        self.client.post('/api/whitelist', json={'bssid': '30:B5:C2:A1:44:21', 'ssid': 'Brew & Bean WiFi'})
        with quiet():
            restarted = importlib.reload(self.app)            # same DB file, fresh process state
        try:
            client = restarted.app.test_client()
            client.post('/api/simulate/coffee_shop')
            wait_for_scan(restarted)
            real = next(n for n in restarted.scan_state['networks'] if n['bssid'] == '30:B5:C2:A1:44:21')
            self.assertTrue(real['is_whitelisted'])
            self.assertEqual(real['risk_score'], 0)
        finally:
            type(self).app = restarted
            type(self).client = restarted.app.test_client()

    def test_it03_concurrent_requests_start_one_scan(self):
        """IT-03 Two simultaneous scan requests start exactly one scan (Problem 4)"""
        release = threading.Event()
        real_simulate = self.app.simulator.simulate

        def slow_simulate(scenario_id):
            release.wait(5)                                   # hold the first job open
            return real_simulate(scenario_id)

        codes, barrier = [], threading.Barrier(2)

        def press():
            barrier.wait()
            codes.append(self.app.app.test_client().post('/api/simulate/airport').status_code)

        with mock.patch.object(self.app.simulator, 'simulate', side_effect=slow_simulate):
            threads = [threading.Thread(target=press) for _ in range(2)]
            [t.start() for t in threads]
            [t.join() for t in threads]
            release.set()
            wait_for_scan(self.app)
        self.assertEqual(sorted(codes), [200, 409])
        self.assertEqual(self.app.db.get_statistics()['total_scans'], 1)

    def test_it04_fresh_install_serves_dashboard(self):
        """IT-04 Starting the app on a brand-new database serves the dashboard (Problem 1)"""
        fresh = os.path.join(tempfile.mkdtemp(), 'brand_new.db')
        with mock.patch.dict(os.environ, {'DATABASE_PATH': fresh}), quiet():
            new_app = importlib.reload(self.app)
        try:
            self.assertEqual(new_app.app.test_client().get('/').status_code, 200)
        finally:
            with quiet():
                type(self).app = importlib.reload(new_app)    # back to the suite's database
            type(self).client = self.app.app.test_client()

    def test_it05_pages_render_after_scan(self):
        """IT-05 Dashboard, history and network-detail pages render after a scan"""
        self.simulate('hotel')
        bssid = self.app.scan_state['networks'][0]['bssid']
        for url in ('/', '/history', f'/network/{bssid}'):
            self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_it06_network_history_accumulates(self):
        """IT-06 /api/network/<bssid>/history returns one observation per scan"""
        self.simulate('coffee_shop')
        self.simulate('coffee_shop')
        history = self.client.get('/api/network/30:B5:C2:A1:44:21/history').get_json()['history']
        self.assertEqual(len(history), 2)


if __name__ == '__main__':
    unittest.main()
