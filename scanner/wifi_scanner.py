"""
WiFi Network Scanner Module

Scans for nearby WiFi networks using multiple methods:
1. Primary: scapy packet sniffing (requires root)
2. Fallback: nmcli / iwlist system commands (Linux)
3. Fallback: netsh (Windows)

Each method returns a standardized list of network dictionaries.
"""

import os
import subprocess
import platform
import re
import time
import json
from datetime import datetime


class WiFiScanner:
    """Scans for nearby WiFi access points using available system tools."""

    def __init__(self):
        self.os_type = platform.system().lower()
        self.scan_method = self._detect_scan_method()
        self.previous_scan = []
        self.last_scan_mode = None   # 'live' or 'demo' after each scan
        self.last_scan_note = None   # why demo data was used (shown on the dashboard)
        print(f"[Scanner] OS: {self.os_type}, Method: {self.scan_method}")

    def _scapy_usable(self):
        """
        Scapy beacon sniffing only works on Linux, as root, with an interface
        in monitor mode. Previously scapy was chosen whenever it was importable,
        so on Windows (where it is installed by requirements.txt) every scan
        sniffed for 10 seconds and returned 0 networks, even though netsh worked.
        """
        if self.os_type != 'linux' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
            return False
        try:
            import scapy.all  # noqa: F401
            return True
        except ImportError:
            return False

    def _system_scan_method(self):
        """Pick the OS scanning tool (used directly, or as scapy's fallback)."""
        if self.os_type == 'linux':
            # Check for nmcli (NetworkManager)
            try:
                result = subprocess.run(['which', 'nmcli'], capture_output=True, text=True)
                if result.returncode == 0:
                    return 'nmcli'
            except FileNotFoundError:
                pass

            # Check for iwlist
            try:
                result = subprocess.run(['which', 'iwlist'], capture_output=True, text=True)
                if result.returncode == 0:
                    return 'iwlist'
            except FileNotFoundError:
                pass

            # Check for iw
            try:
                result = subprocess.run(['which', 'iw'], capture_output=True, text=True)
                if result.returncode == 0:
                    return 'iw'
            except FileNotFoundError:
                pass

        elif self.os_type == 'windows':
            return 'netsh'

        elif self.os_type == 'darwin':
            return 'airport'

        return 'none'

    def _detect_scan_method(self):
        """Detect the best available scanning method."""
        if self._scapy_usable():
            return 'scapy'
        return self._system_scan_method()

    def scan(self):
        """
        Perform a WiFi scan and return a list of detected networks.

        Returns:
            list: List of network dictionaries with keys:
                - ssid (str): Network name
                - bssid (str): MAC address of access point
                - signal_strength (int): Signal in dBm
                - channel (int): WiFi channel number
                - frequency (str): Frequency band (2.4GHz / 5GHz)
                - encryption (str): Security type (WPA2, WPA3, WEP, Open)
                - timestamp (str): ISO format scan time
        """
        print(f"[Scanner] Starting scan using {self.scan_method}...")
        start_time = time.time()

        # Assume live data; _generate_demo_data() switches this to 'demo' so
        # the dashboard can tell the user when results are not real.
        self.last_scan_mode = 'live'
        self.last_scan_note = None

        try:
            networks = self._run_method(self.scan_method)
            if not networks and self.scan_method == 'scapy':
                # Sniffing captured nothing (e.g. no monitor mode): use the OS tool.
                fallback = self._system_scan_method()
                print(f"[Scanner] Scapy captured no beacons, falling back to {fallback}.")
                networks = self._run_method(fallback)
        except PermissionError:
            print("[Scanner] Permission denied. Try running with sudo.")
            networks = self._generate_demo_data('Permission denied while scanning. Try running with sudo.')
        except Exception as e:
            print(f"[Scanner] Scan error: {e}")
            networks = self._generate_demo_data(f'The {self.scan_method} scan failed: {e}')

        elapsed = time.time() - start_time
        print(f"[Scanner] Scan complete: {len(networks)} networks found in {elapsed:.2f}s "
              f"(mode: {self.last_scan_mode})")

        # Store for comparison in next scan
        self.previous_scan = networks
        return networks

    def _run_method(self, method):
        """Dispatch to one scanning back-end."""
        handlers = {
            'scapy': self._scan_scapy,
            'nmcli': self._scan_nmcli,
            'iwlist': self._scan_iwlist,
            'iw': self._scan_iw,
            'netsh': self._scan_netsh,
            'airport': self._scan_airport,
        }
        handler = handlers.get(method)
        if handler is None:
            return self._generate_demo_data(
                'No Wi-Fi scanning tool (nmcli, iwlist, iw, netsh or airport) was found on this machine.')
        return handler()

    # ─────────────────────────────────────
    # Scanning Methods
    # ─────────────────────────────────────

    def _scan_scapy(self):
        """Scan using scapy - most detailed method (requires root)."""
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff, Dot11ProbeResp

        networks = {}
        timestamp = datetime.now().isoformat()

        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                bssid = pkt[Dot11].addr2
                if bssid in networks:
                    # Update signal strength (track changes)
                    if hasattr(pkt, 'dBm_AntSignal'):
                        networks[bssid]['signal_strength'] = pkt.dBm_AntSignal
                    return

                # Extract SSID
                ssid = ""
                stats = pkt[Dot11Beacon].network_stats() if pkt.haslayer(Dot11Beacon) else {}

                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 0:  # SSID
                        try:
                            ssid = elt.info.decode('utf-8', errors='replace')
                        except:
                            ssid = "<Hidden>"
                    elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None

                # Extract channel
                channel = self._extract_channel_scapy(pkt)

                # Extract encryption
                encryption = self._extract_encryption_scapy(pkt, stats)

                # Signal strength
                signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100

                # Frequency
                freq = "5GHz" if channel > 14 else "2.4GHz"

                networks[bssid] = {
                    'ssid': ssid if ssid else '<Hidden>',
                    'bssid': bssid.upper(),
                    'signal_strength': signal,
                    'channel': channel,
                    'frequency': freq,
                    'encryption': encryption,
                    'timestamp': timestamp,
                    'beacon_count': 1
                }

        # Sniff for beacon frames (10 seconds)
        try:
            sniff(prn=packet_handler, timeout=10, store=False,
                  lfilter=lambda p: p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp))
        except Exception as e:
            print(f"[Scanner/Scapy] Sniffing error: {e}")

        return list(networks.values())

    def _extract_channel_scapy(self, pkt):
        """Extract channel number from scapy packet."""
        from scapy.all import Dot11Elt
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 3:  # DS Parameter Set
                return ord(elt.info) if isinstance(elt.info, bytes) and len(elt.info) == 1 else 0
            elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None
        return 0

    def _extract_encryption_scapy(self, pkt, stats):
        """Extract encryption type from scapy packet."""
        from scapy.all import Dot11Beacon
        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}") if pkt.haslayer(Dot11Beacon) else ""

        if 'privacy' not in cap.lower() if isinstance(cap, str) else True:
            return 'Open'

        # Check for RSN (WPA2/WPA3)
        from scapy.all import Dot11Elt
        elt = pkt.getlayer(Dot11Elt)
        has_rsn = False
        has_wpa = False
        while elt:
            if elt.ID == 48:  # RSN Information Element
                has_rsn = True
            if elt.ID == 221 and hasattr(elt, 'info'):  # Vendor specific (WPA)
                if b'\x00\x50\xf2\x01' in elt.info[:4]:
                    has_wpa = True
            elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None

        if has_rsn:
            return 'WPA2/WPA3'
        elif has_wpa:
            return 'WPA'
        else:
            return 'WEP'

    def _scan_nmcli(self):
        """Scan using NetworkManager's nmcli tool (Linux)."""
        try:
            # Trigger a fresh scan
            subprocess.run(['nmcli', 'device', 'wifi', 'rescan'],
                          capture_output=True, timeout=15)
            time.sleep(2)  # Wait for scan to complete

            # Get results in machine-readable format
            result = subprocess.run(
                ['nmcli', '-t', '-f',
                 'SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,MODE',
                 'device', 'wifi', 'list'],
                capture_output=True, text=True, timeout=15
            )

            if result.returncode != 0:
                print(f"[Scanner/nmcli] Error: {result.stderr}")
                return self._generate_demo_data()

            networks = self._parse_nmcli(result.stdout, datetime.now().isoformat())

        except subprocess.TimeoutExpired:
            print("[Scanner/nmcli] Scan timed out")
            networks = []
        except FileNotFoundError:
            print("[Scanner/nmcli] nmcli not found")
            networks = []

        return networks if networks else self._generate_demo_data()

    def _parse_nmcli(self, output, timestamp):
        r"""
        Parse `nmcli -t -f SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,MODE` output.

        In terse mode nmcli escapes ':' inside values as '\:' (BSSIDs always
        contain colons). The previous parser split on every ':', so every
        BSSID came out as 'AA\:BB\:...', which then failed MAC validation
        and added a false 'MAC Address Anomaly' to every network.
        """
        networks = []
        for line in output.splitlines():
            if not line.strip():
                continue

            # Split only on unescaped ':' then unescape the values
            parts = [re.sub(r'\\(.)', r'\1', p)
                     for p in re.split(r'(?<!\\):', line)]
            if len(parts) < 6:
                continue
            ssid, bssid, chan, freq, signal, security = parts[:6]

            try:
                channel = int(chan)
            except ValueError:
                channel = 0
            try:
                frequency = "5GHz" if int(freq.replace('MHz', '').strip()) > 3000 else "2.4GHz"
            except ValueError:
                frequency = "2.4GHz"
            try:
                signal_dbm = self._percent_to_dbm(int(signal))
            except ValueError:
                signal_dbm = -100

            networks.append({
                'ssid': ssid or '<Hidden>',
                'bssid': bssid.strip().upper(),
                'signal_strength': signal_dbm,
                'channel': channel,
                'frequency': frequency,
                'encryption': self._normalise_security(security),
                'timestamp': timestamp
            })
        return networks

    @staticmethod
    def _normalise_security(text):
        """Map a tool's security description to WPA3 / WPA2 / WPA / WEP / Open."""
        text = (text or '').upper()
        for label in ('WPA3', 'WPA2', 'WPA', 'WEP'):
            if label in text:
                return label
        return 'Open'

    def _scan_iwlist(self):
        """Scan using iwlist (Linux, requires root)."""
        timestamp = datetime.now().isoformat()
        networks = []

        try:
            # Detect wireless interface
            iface = self._get_wireless_interface()
            if not iface:
                print("[Scanner/iwlist] No wireless interface found")
                return self._generate_demo_data()

            result = subprocess.run(
                ['sudo', 'iwlist', iface, 'scan'],
                capture_output=True, text=True, timeout=20
            )

            if result.returncode != 0:
                print(f"[Scanner/iwlist] Error: {result.stderr}")
                return self._generate_demo_data()

            current_network = {}
            for line in result.stdout.split('\n'):
                line = line.strip()

                # New cell = new network
                if 'Cell' in line and 'Address:' in line:
                    if current_network.get('bssid'):
                        current_network['timestamp'] = timestamp
                        networks.append(current_network)
                    bssid_match = re.search(r'Address:\s*([0-9A-Fa-f:]+)', line)
                    current_network = {
                        'bssid': bssid_match.group(1).upper() if bssid_match else '',
                        'ssid': '<Hidden>',
                        'signal_strength': -100,
                        'channel': 0,
                        'frequency': '2.4GHz',
                        'encryption': 'Open'
                    }

                elif 'ESSID:' in line:
                    ssid_match = re.search(r'ESSID:"(.*)"', line)
                    if ssid_match:
                        current_network['ssid'] = ssid_match.group(1) or '<Hidden>'

                elif 'Channel:' in line:
                    ch_match = re.search(r'Channel:(\d+)', line)
                    if ch_match:
                        ch = int(ch_match.group(1))
                        current_network['channel'] = ch
                        current_network['frequency'] = "5GHz" if ch > 14 else "2.4GHz"

                elif 'Signal level' in line:
                    sig_match = re.search(r'Signal level[=:](-?\d+)', line)
                    if sig_match:
                        current_network['signal_strength'] = int(sig_match.group(1))

                elif 'Encryption key:on' in line:
                    current_network['encryption'] = 'WEP'

                elif 'WPA2' in line or 'RSN' in line:
                    current_network['encryption'] = 'WPA2'

                elif 'WPA ' in line:
                    if current_network.get('encryption') != 'WPA2':
                        current_network['encryption'] = 'WPA'

            # Don't forget last network
            if current_network.get('bssid'):
                current_network['timestamp'] = timestamp
                networks.append(current_network)

        except subprocess.TimeoutExpired:
            print("[Scanner/iwlist] Scan timed out")
        except FileNotFoundError:
            print("[Scanner/iwlist] iwlist not found")

        return networks if networks else self._generate_demo_data()

    def _scan_iw(self):
        """Scan using iw tool (Linux, modern alternative)."""
        timestamp = datetime.now().isoformat()
        networks = []

        try:
            iface = self._get_wireless_interface()
            if not iface:
                return self._generate_demo_data()

            # Trigger scan
            subprocess.run(['sudo', 'iw', iface, 'scan', 'trigger'],
                          capture_output=True, timeout=10)
            time.sleep(3)

            result = subprocess.run(
                ['sudo', 'iw', iface, 'scan', 'dump'],
                capture_output=True, text=True, timeout=15
            )

            current_network = {}
            for line in result.stdout.split('\n'):
                line = line.strip()

                if line.startswith('BSS '):
                    if current_network.get('bssid'):
                        current_network['timestamp'] = timestamp
                        networks.append(current_network)
                    bssid = line.split()[1].split('(')[0].upper()
                    current_network = {
                        'bssid': bssid,
                        'ssid': '<Hidden>',
                        'signal_strength': -100,
                        'channel': 0,
                        'frequency': '2.4GHz',
                        'encryption': 'Open'
                    }

                elif line.startswith('SSID:'):
                    ssid = line.split(':', 1)[1].strip()
                    current_network['ssid'] = ssid if ssid else '<Hidden>'

                elif line.startswith('signal:'):
                    sig_match = re.search(r'(-?\d+\.?\d*)', line)
                    if sig_match:
                        current_network['signal_strength'] = int(float(sig_match.group(1)))

                elif line.startswith('DS Parameter set: channel'):
                    ch_match = re.search(r'channel\s+(\d+)', line)
                    if ch_match:
                        ch = int(ch_match.group(1))
                        current_network['channel'] = ch
                        current_network['frequency'] = "5GHz" if ch > 14 else "2.4GHz"

                elif 'RSN:' in line:
                    current_network['encryption'] = 'WPA2'

                elif 'WPA:' in line:
                    if current_network.get('encryption') != 'WPA2':
                        current_network['encryption'] = 'WPA'

            if current_network.get('bssid'):
                current_network['timestamp'] = timestamp
                networks.append(current_network)

        except Exception as e:
            print(f"[Scanner/iw] Error: {e}")

        return networks if networks else self._generate_demo_data()

    def _scan_netsh(self):
        """
        Scan using netsh (Windows).

        `netsh wlan show networks` does not scan: it lists whatever Windows saw
        in its last background scan, which happens rarely while the laptop is
        connected to Wi-Fi. On the test laptop it reported 1 network when 7
        were in range. We therefore ask Windows for a fresh scan first and give
        the adapter a few seconds to collect beacons.
        """
        networks = []
        try:
            if self._trigger_windows_scan():
                time.sleep(self.WINDOWS_SCAN_WAIT)
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True, text=True, timeout=15
            )
            output = (result.stdout or '') + (result.stderr or '')
            networks = self._parse_netsh(result.stdout or '', datetime.now().isoformat())
            if not networks and 'location' in output.lower():
                # Windows 11 (24H2 and later) blocks WLAN listing without Location access
                return self._generate_demo_data(
                    'Windows blocked the Wi-Fi scan because Location access is off. Turn on '
                    'Settings > Privacy & security > Location, including "Let desktop apps '
                    'access your location", then scan again.')
        except Exception as e:
            print(f"[Scanner/netsh] Error: {e}")
            return self._generate_demo_data(f'netsh failed: {e}')

        if networks:
            return networks
        return self._generate_demo_data(
            'netsh reported no Wi-Fi networks. Check that Wi-Fi is switched on and that a '
            'wireless adapter is installed.')

    # Seconds to wait after WlanScan; drivers must finish a scan within 4 s,
    # and on the test laptop all networks appeared within 2 s.
    WINDOWS_SCAN_WAIT = 3.0

    def _load_wlanapi(self):
        """Return the Windows Native Wifi API DLL (separate method so tests can replace it)."""
        import ctypes
        return ctypes.windll.wlanapi

    def _trigger_windows_scan(self):
        """
        Ask every wireless interface for a fresh scan via WlanScan (wlanapi.dll).
        Uses only the standard library (ctypes). Returns True if at least one
        scan was requested; on any failure returns False and the cached list
        is used, so this can never make a scan fail.
        """
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [('Data1', wintypes.DWORD), ('Data2', wintypes.WORD),
                        ('Data3', wintypes.WORD), ('Data4', ctypes.c_ubyte * 8)]

        class InterfaceInfo(ctypes.Structure):
            _fields_ = [('InterfaceGuid', GUID), ('strInterfaceDescription', ctypes.c_wchar * 256),
                        ('isState', ctypes.c_uint)]

        class InterfaceInfoList(ctypes.Structure):
            _fields_ = [('dwNumberOfItems', wintypes.DWORD), ('dwIndex', wintypes.DWORD),
                        ('InterfaceInfo', InterfaceInfo * 1)]

        try:
            wlan = self._load_wlanapi()
            handle, version = wintypes.HANDLE(), wintypes.DWORD()
            if wlan.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)) != 0:
                return False
            requested = 0
            try:
                iface_list = ctypes.POINTER(InterfaceInfoList)()
                if wlan.WlanEnumInterfaces(handle, None, ctypes.byref(iface_list)) != 0:
                    return False
                count = iface_list.contents.dwNumberOfItems
                if count:
                    items = ctypes.cast(ctypes.byref(iface_list.contents.InterfaceInfo),
                                        ctypes.POINTER(InterfaceInfo * count)).contents
                    for item in items:
                        if wlan.WlanScan(handle, ctypes.byref(item.InterfaceGuid), None, None, None) == 0:
                            requested += 1
                wlan.WlanFreeMemory(iface_list)
            finally:
                wlan.WlanCloseHandle(handle, None)
            return requested > 0
        except (OSError, AttributeError, ValueError) as e:
            print(f"[Scanner/netsh] Could not trigger a fresh scan ({e}); using cached results.")
            return False

    def _parse_netsh(self, output, timestamp):
        """
        Parse `netsh wlan show networks mode=bssid` output.

        netsh lists every access point (BSSID 1, BSSID 2, ...) under the SSID
        block it belongs to. The previous parser kept a single dict per SSID
        and overwrote its BSSID for each AP, so only the *last* access point
        of every SSID survived - which hid exactly the same-name duplicates
        the detector needs to see.
        """
        networks = []
        ssid, encryption, current = None, 'Open', None

        for raw in output.splitlines():
            line = raw.strip()
            key, _, value = line.partition(':')
            key, value = key.strip(), value.strip()

            if re.match(r'^SSID \d+$', key):
                ssid, encryption, current = value or '<Hidden>', 'Open', None
            elif key == 'Authentication':
                encryption = self._normalise_security(value)
            elif re.match(r'^BSSID \d+$', key) and ssid is not None:
                current = {
                    'ssid': ssid,
                    'bssid': value.upper(),
                    'signal_strength': -100,
                    'channel': 0,
                    'frequency': '2.4GHz',
                    'encryption': encryption,
                    'timestamp': timestamp,
                }
                networks.append(current)
            elif current is not None and key == 'Signal':
                pct = re.search(r'(\d+)%', value)
                if pct:
                    current['signal_strength'] = self._percent_to_dbm(int(pct.group(1)))
            elif current is not None and key == 'Channel' and value.isdigit():
                current['channel'] = int(value)
                current['frequency'] = "5GHz" if int(value) > 14 else "2.4GHz"

        return networks

    def _scan_airport(self):
        """Scan using airport utility (macOS)."""
        timestamp = datetime.now().isoformat()
        networks = []

        try:
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
                capture_output=True, text=True, timeout=15
            )

            for line in result.stdout.split('\n')[1:]:  # Skip header
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 7:
                    networks.append({
                        'ssid': parts[0] if parts[0] else '<Hidden>',
                        'bssid': parts[1].upper(),
                        'signal_strength': int(parts[2]),
                        'channel': int(parts[3].split(',')[0]),
                        'frequency': "5GHz" if int(parts[3].split(',')[0]) > 14 else "2.4GHz",
                        'encryption': parts[6] if len(parts) > 6 else 'Unknown',
                        'timestamp': timestamp
                    })

        except Exception as e:
            print(f"[Scanner/airport] Error: {e}")

        return networks if networks else self._generate_demo_data()

    # ─────────────────────────────────────
    # Helper Methods
    # ─────────────────────────────────────

    def _get_wireless_interface(self):
        """Detect the wireless network interface name."""
        try:
            # Try /sys/class/net (Linux)
            result = subprocess.run(
                ['bash', '-c', 'ls /sys/class/net/*/wireless 2>/dev/null | cut -d/ -f5'],
                capture_output=True, text=True
            )
            interfaces = result.stdout.strip().split('\n')
            if interfaces and interfaces[0]:
                return interfaces[0]

            # Try ip link
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                for prefix in ['wlan', 'wlp', 'wlx']:
                    if prefix in line:
                        match = re.search(rf'({prefix}\S+?):', line)
                        if match:
                            return match.group(1)

            # Try iwconfig
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'IEEE' in line or 'ESSID' in line:
                    return line.split()[0]

        except Exception:
            pass

        return None

    def _percent_to_dbm(self, percent):
        """Convert signal percentage to approximate dBm."""
        if percent <= 0:
            return -100
        elif percent >= 100:
            return -30
        else:
            return int(-100 + (percent * 0.7))

    def _generate_demo_data(self, reason=None):
        """
        Generate realistic demo data for testing/demonstration.
        Simulates a coffee shop environment with an Evil Twin attack.
        `reason` explains why the live scan could not be used; the dashboard
        shows it to the user.
        """
        self.last_scan_mode = 'demo'
        self.last_scan_note = reason or 'No scanning tool or permission was available on this machine.'
        print(f"[Scanner] Using demo data: {self.last_scan_note}")
        timestamp = datetime.now().isoformat()

        demo_networks = [
            # Legitimate coffee shop network
            {
                'ssid': 'CoffeeShop_WiFi',
                'bssid': 'AA:BB:CC:11:22:33',
                'signal_strength': -45,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': timestamp
            },
            # EVIL TWIN - same SSID, different BSSID, stronger signal, open network
            {
                'ssid': 'CoffeeShop_WiFi',
                'bssid': 'DE:AD:BE:EF:00:01',
                'signal_strength': -30,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': timestamp
            },
            # Legitimate corporate network
            {
                'ssid': 'TechCorp_Secure',
                'bssid': '00:1A:2B:3C:4D:5E',
                'signal_strength': -55,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': timestamp
            },
            # EVIL TWIN - corporate network clone (different encryption)
            {
                'ssid': 'TechCorp_Secure',
                'bssid': 'FF:EE:DD:CC:BB:AA',
                'signal_strength': -35,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'WPA',
                'timestamp': timestamp
            },
            # Normal home network
            {
                'ssid': 'HomeNet-5G',
                'bssid': '10:20:30:40:50:60',
                'signal_strength': -65,
                'channel': 36,
                'frequency': '5GHz',
                'encryption': 'WPA2',
                'timestamp': timestamp
            },
            # Suspicious open network
            {
                'ssid': 'Free_Airport_WiFi',
                'bssid': 'BA:AD:FO:OD:12:34',
                'signal_strength': -40,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': timestamp
            },
            # Normal network
            {
                'ssid': 'Apartment_204',
                'bssid': '11:22:33:44:55:66',
                'signal_strength': -70,
                'channel': 9,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': timestamp
            },
            # Hidden network (suspicious)
            {
                'ssid': '<Hidden>',
                'bssid': '99:88:77:66:55:44',
                'signal_strength': -50,
                'channel': 3,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': timestamp
            },
            # Another normal network
            {
                'ssid': 'NETGEAR-Home',
                'bssid': 'A1:B2:C3:D4:E5:F6',
                'signal_strength': -75,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': timestamp
            },
            # Suspicious duplicate with different channel
            {
                'ssid': 'NETGEAR-Home',
                'bssid': 'F6:E5:D4:C3:B2:A1',
                'signal_strength': -38,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': timestamp
            },
        ]

        return demo_networks
