"""
Security tests: SQL injection, cross-site scripting (XSS) and information
leakage. SEC-04 is the regression test for the stored-XSS vulnerability in
the dashboard's Trust button that this testing uncovered (Section 4.6).
"""
import os
import re
import shutil
import subprocess
import unittest

from tests.support import net, load_app, reset_app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XSS_SSID = "');alert(document.domain)//"
SCRIPT_SSID = '<script>alert(1)</script>'


class Security(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = load_app()
        cls.client = cls.app.app.test_client()

    def setUp(self):
        reset_app(self.app)

    def save(self, ssid, bssid='02:AA:BB:CC:DD:EE'):
        row = dict(net(ssid, bssid, 'Open'), risk_level='high', risk_score=90, risk_factors=[])
        self.app.db.save_scan([row])
        return bssid

    def test_sec01_sql_injection_in_url(self):
        """SEC-01 SQL injection in /api/network/<bssid>/history returns nothing and drops nothing"""
        self.save('Office')
        for payload in ("' OR '1'='1", "x'; DROP TABLE networks;--"):
            r = self.client.get(f'/api/network/{payload}/history')
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.get_json()['history'], [])
        self.assertEqual(self.app.db.get_statistics()['unique_networks'], 1)

    def test_sec02_injection_string_rejected_by_whitelist(self):
        """SEC-02 An SQL-injection string as a whitelist BSSID is rejected and not stored"""
        r = self.client.post('/api/whitelist', json={'bssid': "x' OR 1=1 --", 'ssid': 'x'})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.app.db.get_whitelist(), [])

    def test_sec03_script_ssid_escaped_in_page(self):
        """SEC-03 A <script> SSID is HTML-escaped on the server-rendered detail page"""
        bssid = self.save(SCRIPT_SSID)
        html = self.client.get(f'/network/{bssid}').get_data(as_text=True)
        self.assertNotIn(SCRIPT_SSID, html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)

    def test_sec04_no_network_data_in_inline_handlers(self):
        """SEC-04 dashboard.js never puts scanned data inside inline onclick handlers"""
        with open(os.path.join(ROOT, 'static', 'js', 'dashboard.js'), encoding='utf-8') as f:
            js = f.read()
        # Body of every onclick="..." / onclick='...' attribute in the templates
        handlers = [m.group(2) for m in re.finditer(r'onclick\s*=\s*(["\'])(.*?)\1', js)]
        leaking = [h for h in handlers if '${' in h and re.search(r'network\b|ssid|bssid', h)]
        self.assertEqual(leaking, [], leaking)

    @unittest.skipUnless(shutil.which('node'), 'Node.js not installed')
    def test_sec05_escape_html_in_browser_engine(self):
        """SEC-05 escapeHtml() (run in Node.js) neutralises < > & \" ' in an SSID"""
        with open(os.path.join(ROOT, 'static', 'js', 'dashboard.js'), encoding='utf-8') as f:
            fn = re.search(r'function escapeHtml\(text\) \{.*?\n\}', f.read(), re.S).group(0)
        out = subprocess.run(['node', '-e', fn + f'\nprocess.stdout.write(escapeHtml({SCRIPT_SSID + XSS_SSID!r}))'],
                             capture_output=True, text=True, check=True).stdout
        self.assertNotRegex(out, r'[<>"\']')

    def test_sec06_errors_do_not_leak_internals(self):
        """SEC-06 Bad API requests return a short JSON error with no stack trace"""
        r = self.client.post('/api/whitelist', data='null', content_type='application/json')
        body = r.get_data(as_text=True)
        self.assertEqual(r.status_code, 400)
        self.assertNotIn('Traceback', body)
        self.assertNotIn('.py', body)

    def test_sec07_all_sql_is_parameterised(self):
        """SEC-07 database.py builds no SQL with string formatting (only ? placeholders)"""
        with open(os.path.join(ROOT, 'models', 'database.py'), encoding='utf-8') as f:
            src = f.read()
        self.assertIsNone(re.search(r'execute\(\s*f["\']|execute\([^)]*%\s*\(|execute\([^)]*\.format\(', src))


if __name__ == '__main__':
    unittest.main()
