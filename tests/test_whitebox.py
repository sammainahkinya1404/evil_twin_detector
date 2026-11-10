"""
White-box tests: written from the source code so that every decision
(branch) in the detection engine, the scanner's method selection and the
database layer is executed at least once. Coverage is measured with
`coverage run -m unittest discover -s tests` / `coverage report`.
"""
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from scanner.detector import EvilTwinDetector
from scanner.wifi_scanner import WiFiScanner
from models.database import Database
from tests.support import net, quiet, KNOWN_MAC, SPOOFED_MAC, UNKNOWN_MAC


def factors(result):
    return [f['factor'] if isinstance(f, dict) else f for f in result['risk_factors']]


class MacAnalysisBranches(unittest.TestCase):
    """_analyze_mac() and _identify_vendor() - every return path."""

    def setUp(self):
        self.d = EvilTwinDetector()

    def test_wb01_missing_mac(self):
        """WB-01 _analyze_mac: empty BSSID -> 'Missing MAC address'"""
        self.assertEqual(self.d._analyze_mac(''), 'Missing MAC address')

    def test_wb02_locally_administered(self):
        """WB-02 _analyze_mac: locally administered bit (0x02) -> anomaly"""
        self.assertIn('locally administered', self.d._analyze_mac(SPOOFED_MAC))

    def test_wb03_multicast(self):
        """WB-03 _analyze_mac: multicast bit (0x01) -> anomaly"""
        self.assertIn('multicast', self.d._analyze_mac('01:00:5E:00:00:01'))

    def test_wb04_invalid_format(self):
        """WB-04 _analyze_mac: non-hex BSSID -> 'invalid format'"""
        self.assertIn('invalid format', self.d._analyze_mac('ZZ:11:22:33:44:55'))

    def test_wb05_normal_mac(self):
        """WB-05 _analyze_mac: normal manufacturer MAC -> no anomaly (None)"""
        self.assertIsNone(self.d._analyze_mac(KNOWN_MAC))

    def test_wb06_vendor_lookup_paths(self):
        """WB-06 _identify_vendor: known OUI / locally administered / unknown / empty"""
        self.assertEqual(self.d._identify_vendor(KNOWN_MAC), 'TP-Link')
        self.assertEqual(self.d._identify_vendor(SPOOFED_MAC), 'Locally Administered (possibly spoofed)')
        self.assertEqual(self.d._identify_vendor(UNKNOWN_MAC), 'Unknown Vendor')
        self.assertEqual(self.d._identify_vendor(''), 'Unknown')


class DuplicateSsidBranches(unittest.TestCase):
    """The 'same SSID' block in _analyze_single() and its inner conditions."""

    def analyze(self, *nets):
        return {r['bssid']: r for r in EvilTwinDetector().analyze(list(nets))}

    def test_wb07_hidden_ssids_not_duplicates(self):
        """WB-07 Two '<Hidden>' APs do not trigger SSID Duplication"""
        r = self.analyze(net('<Hidden>', KNOWN_MAC), net('<Hidden>', '30:B5:C2:00:00:02'))
        self.assertNotIn('SSID Duplication', factors(r[KNOWN_MAC]))

    def test_wb08_signal_anomaly_boundary(self):
        """WB-08 Signal anomaly: +15 dBm over peers is not flagged, +16 dBm is"""
        r15 = self.analyze(net('X', KNOWN_MAC, signal=-50), net('X', UNKNOWN_MAC, signal=-35))
        r16 = self.analyze(net('X', KNOWN_MAC, signal=-50), net('X', UNKNOWN_MAC, signal=-34))
        self.assertNotIn('Abnormal Signal Strength', factors(r15[UNKNOWN_MAC]))
        self.assertIn('Abnormal Signal Strength', factors(r16[UNKNOWN_MAC]))

    def test_wb09_channel_branch(self):
        """WB-09 Channel Discrepancy only when same-name APs use different channels"""
        same = self.analyze(net('X', KNOWN_MAC, channel=6), net('X', UNKNOWN_MAC, channel=6))
        diff = self.analyze(net('X', KNOWN_MAC, channel=6), net('X', UNKNOWN_MAC, channel=11))
        self.assertNotIn('Channel Discrepancy', factors(same[KNOWN_MAC]))
        self.assertIn('Channel Discrepancy', factors(diff[KNOWN_MAC]))

    def test_wb10_encryption_branch(self):
        """WB-10 Encryption Mismatch only when same-name APs use different security"""
        same = self.analyze(net('X', KNOWN_MAC, 'WPA2'), net('X', UNKNOWN_MAC, 'WPA2'))
        diff = self.analyze(net('X', KNOWN_MAC, 'WPA2'), net('X', UNKNOWN_MAC, 'Open'))
        self.assertEqual(same[KNOWN_MAC]['risk_score'], 25)       # duplication only
        self.assertIn('Encryption Mismatch', factors(diff[KNOWN_MAC]))

    def test_wb15_hidden_open_bonus(self):
        """WB-15 Hidden + Open AP gets the +15 'Hidden Open Network' bonus"""
        r = self.analyze(net('<Hidden>', KNOWN_MAC, 'Open'))
        self.assertIn('Hidden Open Network', factors(r[KNOWN_MAC]))
        self.assertEqual(r[KNOWN_MAC]['risk_score'], 25)          # open 10 + hidden-open 15


class HistoryBranches(unittest.TestCase):
    """_check_history() and _update_history()."""

    def run_scans(self, *observations):
        d = EvilTwinDetector()
        result = None
        for obs in observations:
            result = d.analyze([obs])[0]
        return d, result

    def test_wb11_needs_two_observations(self):
        """WB-11 History check is skipped until a BSSID has 2 earlier observations"""
        _, r = self.run_scans(net(encryption='WPA2'), net(encryption='Open'))
        self.assertNotIn('Encryption Change Detected', factors(r))

    def test_wb12_encryption_change(self):
        """WB-12 Encryption change between scans is flagged"""
        _, r = self.run_scans(net(), net(), net(encryption='Open'))
        self.assertIn('Encryption Change Detected', factors(r))

    def test_wb13_signal_fluctuation_boundary(self):
        """WB-13 Signal change of 25 dB is not flagged, 26 dB is"""
        _, r25 = self.run_scans(net(signal=-70), net(signal=-70), net(signal=-45))
        _, r26 = self.run_scans(net(signal=-70), net(signal=-70), net(signal=-44))
        self.assertNotIn('Signal Strength Fluctuation', factors(r25))
        self.assertIn('Signal Strength Fluctuation', factors(r26))

    def test_wb14_history_is_bounded(self):
        """WB-14 Only the last 50 observations per BSSID are kept"""
        d, _ = self.run_scans(*[net() for _ in range(60)])
        self.assertEqual(len(d.network_history[KNOWN_MAC]), 50)


class ScannerSelectionBranches(unittest.TestCase):
    """WiFiScanner method selection and fallbacks."""

    def make_scanner(self, method):
        s = WiFiScanner.__new__(WiFiScanner)   # skip OS detection
        s.os_type, s.scan_method, s.previous_scan, s.last_scan_mode = 'windows', method, [], None
        return s

    def test_wb16_scapy_requires_linux_root(self):
        """WB-16 Scapy is not selected on Windows or for a non-root Linux user"""
        s = self.make_scanner('netsh')
        self.assertFalse(s._scapy_usable())
        s.os_type = 'linux'
        with mock.patch('os.geteuid', create=True, return_value=1000):
            self.assertFalse(s._scapy_usable())

    def test_wb17_scapy_empty_falls_back(self):
        """WB-17 Scapy capturing nothing falls back to the OS tool (live data)"""
        s = self.make_scanner('scapy')
        with mock.patch.object(s, '_scan_scapy', return_value=[]), \
             mock.patch.object(s, '_system_scan_method', return_value='netsh'), \
             mock.patch.object(s, '_scan_netsh', return_value=[net()]), quiet():
            result = s.scan()
        self.assertEqual(len(result), 1)
        self.assertEqual(s.last_scan_mode, 'live')

    def test_wb18_no_tool_uses_demo(self):
        """WB-18 No scanning tool -> demo data and scan mode 'demo'"""
        s = self.make_scanner('none')
        with quiet():
            result = s.scan()
        self.assertEqual(len(result), 10)
        self.assertEqual(s.last_scan_mode, 'demo')

    def test_wb19_tool_error_uses_demo(self):
        """WB-19 An exception inside a scanning tool -> demo data and mode 'demo'"""
        s = self.make_scanner('netsh')
        with mock.patch.object(s, '_scan_netsh', side_effect=OSError('adapter missing')), quiet():
            s.scan()
        self.assertEqual(s.last_scan_mode, 'demo')

    def test_wb20_percent_to_dbm(self):
        """WB-20 Signal % -> dBm conversion at 0, 50 and 100 percent"""
        s = self.make_scanner('netsh')
        self.assertEqual([s._percent_to_dbm(p) for p in (0, 50, 100)], [-100, -65, -30])


NETSH_SAMPLE = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : CafeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 30:b5:c2:a1:44:21
         Signal             : 80%
         Radio type         : 802.11n
         Channel            : 6
    BSSID 2                 : 02:de:ad:be:ef:01
         Signal             : 99%
         Radio type         : 802.11n
         Channel            : 11

SSID 2 :
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 02:aa:bb:cc:dd:ee
         Signal             : 60%
         Channel            : 36
"""

# nmcli -t escapes ':' inside values as '\:'
NMCLI_SAMPLE = (r"CafeNet:30\:B5\:C2\:A1\:44\:21:6:2437 MHz:80:WPA2:Infra" "\n"
                r"Lab\:5G:30\:B5\:C2\:A1\:44\:22:36:5180 MHz:70:WPA1 WPA2:Infra" "\n"
                r":02\:AA\:BB\:CC\:DD\:EE:11:2462 MHz:60::Infra" "\n")


class ScannerParsers(unittest.TestCase):
    """Output parsers for the OS scanning tools, fed with captured sample output."""

    def setUp(self):
        self.s = WiFiScanner.__new__(WiFiScanner)

    def test_wb23_netsh_keeps_every_bssid(self):
        """WB-23 netsh parser returns every BSSID listed under an SSID, not just the last"""
        nets = self.s._parse_netsh(NETSH_SAMPLE, 'ts')
        self.assertEqual([n['bssid'] for n in nets],
                         ['30:B5:C2:A1:44:21', '02:DE:AD:BE:EF:01', '02:AA:BB:CC:DD:EE'])
        self.assertEqual([n['ssid'] for n in nets], ['CafeNet', 'CafeNet', '<Hidden>'])
        self.assertEqual([n['encryption'] for n in nets], ['WPA2', 'WPA2', 'Open'])
        self.assertEqual([n['channel'] for n in nets], [6, 11, 36])
        self.assertEqual(nets[0]['signal_strength'], -44)          # 80 % -> -44 dBm

    def test_wb24_nmcli_unescapes_colons(self):
        """WB-24 nmcli parser rebuilds escaped BSSIDs/SSIDs and normalises security"""
        nets = self.s._parse_nmcli(NMCLI_SAMPLE, 'ts')
        self.assertEqual([n['bssid'] for n in nets],
                         ['30:B5:C2:A1:44:21', '30:B5:C2:A1:44:22', '02:AA:BB:CC:DD:EE'])
        self.assertEqual([n['ssid'] for n in nets], ['CafeNet', 'Lab:5G', '<Hidden>'])
        self.assertEqual([n['encryption'] for n in nets], ['WPA2', 'WPA2', 'Open'])
        self.assertEqual([n['frequency'] for n in nets], ['2.4GHz', '5GHz', '2.4GHz'])

    def test_wb25_parsed_macs_are_valid(self):
        """WB-25 Parsed BSSIDs from a real vendor raise no MAC anomaly in the detector"""
        d = EvilTwinDetector()
        for n in self.s._parse_nmcli(NMCLI_SAMPLE, 'ts')[:2]:
            self.assertIsNone(d._analyze_mac(n['bssid']), n['bssid'])


LOCATION_BLOCKED = ('Network shell commands need location permission to access WLAN information. '
                    'Turn on Location services on the Location page in Privacy & security settings.\n')


class NetshFreshScan(unittest.TestCase):
    """_scan_netsh(): fresh-scan trigger, Location block and empty results (Problem 6)."""

    def setUp(self):
        self.s = WiFiScanner.__new__(WiFiScanner)
        self.s.os_type, self.s.scan_method, self.s.previous_scan = 'windows', 'netsh', []
        self.s.last_scan_mode, self.s.last_scan_note = 'live', None

    def netsh(self, stdout, rc=0, triggered=True):
        result = mock.Mock(stdout=stdout, stderr='', returncode=rc)
        with mock.patch.object(self.s, '_trigger_windows_scan', return_value=triggered), \
             mock.patch('scanner.wifi_scanner.subprocess.run', return_value=result) as run, \
             mock.patch('scanner.wifi_scanner.time.sleep') as sleep, quiet():
            nets = self.s._scan_netsh()
        return nets, sleep, run

    def test_wb26_fresh_scan_before_reading(self):
        """WB-26 netsh: a fresh WlanScan is requested and awaited before netsh is read"""
        nets, sleep, run = self.netsh(NETSH_SAMPLE)
        sleep.assert_called_once_with(WiFiScanner.WINDOWS_SCAN_WAIT)
        run.assert_called_once()
        self.assertEqual(len(nets), 3)
        self.assertEqual(self.s.last_scan_mode, 'live')

    def test_wb27_trigger_failure_uses_cached_list(self):
        """WB-27 netsh: if the fresh scan cannot be requested, the cached list is still used"""
        nets, sleep, _ = self.netsh(NETSH_SAMPLE, triggered=False)
        sleep.assert_not_called()
        self.assertEqual(len(nets), 3)

    def test_wb28_location_permission_blocked(self):
        """WB-28 netsh: Windows Location block -> demo data with a Location hint"""
        _, _, _ = self.netsh(LOCATION_BLOCKED, rc=1)
        self.assertEqual(self.s.last_scan_mode, 'demo')
        self.assertIn('Location', self.s.last_scan_note)

    def test_wb29_no_networks_explained(self):
        """WB-29 netsh: no networks reported -> demo data with a Wi-Fi hint"""
        self.netsh('Interface name : Wi-Fi\nThere are 0 networks currently visible.\n')
        self.assertEqual(self.s.last_scan_mode, 'demo')
        self.assertIn('Wi-Fi is switched on', self.s.last_scan_note)

    def test_wb30_trigger_without_wlanapi(self):
        """WB-30 _trigger_windows_scan: no wlanapi.dll (non-Windows) -> False, no exception"""
        with mock.patch.object(self.s, '_load_wlanapi', side_effect=OSError('not Windows')), quiet():
            self.assertFalse(self.s._trigger_windows_scan())

    def test_wb31_trigger_open_handle_fails(self):
        """WB-31 _trigger_windows_scan: WlanOpenHandle error code -> False"""
        fake = mock.Mock()
        fake.WlanOpenHandle.return_value = 1062            # ERROR_SERVICE_NOT_ACTIVE
        with mock.patch.object(self.s, '_load_wlanapi', return_value=fake):
            self.assertFalse(self.s._trigger_windows_scan())
        fake.WlanScan.assert_not_called()


class DatabaseBranches(unittest.TestCase):

    def test_wb21_new_database_creates_schema(self):
        """WB-21 Database() on a brand-new file creates all 4 tables"""
        path = os.path.join(tempfile.mkdtemp(), 'fresh.db')
        with quiet():
            Database(path)
        tables = {r[0] for r in sqlite3.connect(path).execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({'scans', 'networks', 'alerts', 'whitelist'} <= tables)

    def test_wb22_alerts_only_for_medium_and_high(self):
        """WB-22 save_scan() writes alert rows only for MEDIUM and HIGH networks"""
        path = os.path.join(tempfile.mkdtemp(), 'alerts.db')
        with quiet():
            db = Database(path)
        rows = [dict(net(str(i)), risk_level=lvl, risk_score=s, risk_factors=[])
                for i, (lvl, s) in enumerate([('low', 0), ('medium', 40), ('high', 80)])]
        db.save_scan(rows)
        self.assertEqual(db.get_statistics()['total_alerts'], 2)


if __name__ == '__main__':
    unittest.main()
