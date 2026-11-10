"""
Performance tests for the non-functional requirements:
  NFR01 - scan and analysis complete within 15 seconds
  NFR06 - 50 or more visible networks without performance degradation
"""
import time
import unittest

from scanner.detector import EvilTwinDetector
from tests.support import net, load_app, reset_app, wait_for_scan


class Performance(unittest.TestCase):

    def test_perf01_analyse_60_networks(self):
        """PERF-01 Analysing 60 networks (incl. 20 duplicated SSIDs) takes under 0.5 s"""
        nets = [net(f'Net{i % 40}', f'30:B5:C2:00:00:{i:02X}', signal=-40 - i % 30, channel=1 + i % 11)
                for i in range(60)]
        start = time.perf_counter()
        EvilTwinDetector().analyze(nets)
        self.assertLess(time.perf_counter() - start, 0.5)

    def test_perf02_simulation_end_to_end(self):
        """PERF-02 Largest scenario (15 APs) API request -> results stored in under 15 s"""
        appmod = load_app()
        reset_app(appmod)
        start = time.perf_counter()
        appmod.app.test_client().post('/api/simulate/university')
        wait_for_scan(appmod)
        self.assertLess(time.perf_counter() - start, 15)
        self.assertEqual(len(appmod.scan_state['networks']), 15)

    def test_perf03_dashboard_with_history(self):
        """PERF-03 Dashboard page loads in under 1 s with 50 stored scans"""
        appmod = load_app()
        reset_app(appmod)
        rows = [dict(net(f'N{i}', f'30:B5:C2:00:01:{i:02X}'), risk_level='medium', risk_score=40, risk_factors=[])
                for i in range(12)]
        for _ in range(50):
            appmod.db.save_scan(rows)
        start = time.perf_counter()
        r = appmod.app.test_client().get('/')
        self.assertEqual(r.status_code, 200)
        self.assertLess(time.perf_counter() - start, 1.0)


if __name__ == '__main__':
    unittest.main()
