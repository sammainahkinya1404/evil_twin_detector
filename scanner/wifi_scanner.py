"""
WiFi Network Scanner Module

Scans for nearby WiFi networks using multiple methods:
1. Primary: scapy packet sniffing (requires root)
2. Fallback: nmcli / iwlist system commands (Linux)
3. Fallback: netsh (Windows)

Each method returns a standardized list of network dictionaries.
"""

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
        print(f"[Scanner] OS: {self.os_type}, Method: {self.scan_method}")

    def _detect_scan_method(self):
        """Detect the best available scanning method."""
        # Try scapy first (most detailed)
        try:
            import scapy.all
            return 'scapy'
        except ImportError:
            pass

        # Try system tools
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

        try:
            if self.scan_method == 'scapy':
                networks = self._scan_scapy()
            elif self.scan_method == 'nmcli':
                networks = self._scan_nmcli()
            elif self.scan_method == 'iwlist':
                networks = self._scan_iwlist()
            elif self.scan_method == 'iw':
                networks = self._scan_iw()
            elif self.scan_method == 'netsh':
                networks = self._scan_netsh()
            elif self.scan_method == 'airport':
                networks = self._scan_airport()
            else:
                print("[Scanner] No scanning tool available. Using demo data.")
                networks = self._generate_demo_data()
        except PermissionError:
            print("[Scanner] Permission denied. Try running with sudo.")
            print("[Scanner] Falling back to demo data.")
            networks = self._generate_demo_data()
        except Exception as e:
            print(f"[Scanner] Scan error: {e}")
            print("[Scanner] Falling back to demo data.")
            networks = self._generate_demo_data()

        elapsed = time.time() - start_time
        print(f"[Scanner] Scan complete: {len(networks)} networks found in {elapsed:.2f}s")

        # Store for comparison in next scan
        self.previous_scan = networks
        return networks

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
        timestamp = datetime.now().isoformat()
        networks = []

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

            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue

                # nmcli -t uses ':' as separator, but BSSID contains ':'
                # Format: SSID:BSSID:CHAN:FREQ:SIGNAL:SECURITY:MODE
                parts = line.split(':')
                if len(parts) < 12:  # Minimum expected parts
                    continue

                # BSSID is 6 hex pairs separated by ':'
                ssid = parts[0] if parts[0] else '<Hidden>'
                # Reconstruct BSSID (parts 1-6 are the MAC octets due to : splitting)
                bssid = ':'.join(parts[1:7]).strip().upper()
                
                try:
                    channel = int(parts[7]) if parts[7].strip().isdigit() else 0
                except (ValueError, IndexError):
                    channel = 0

                try:
                    freq_mhz = parts[8].strip().replace(' MHz', '')
                    frequency = "5GHz" if int(freq_mhz) > 3000 else "2.4GHz"
                except (ValueError, IndexError):
                    frequency = "2.4GHz"

                try:
                    signal_pct = int(parts[9]) if parts[9].strip().isdigit() else 0
                    signal_dbm = self._percent_to_dbm(signal_pct)
                except (ValueError, IndexError):
                    signal_dbm = -100

                try:
                    encryption = parts[10].strip() if parts[10] else 'Open'
                except IndexError:
                    encryption = 'Unknown'

                networks.append({
                    'ssid': ssid,
                    'bssid': bssid,
                    'signal_strength': signal_dbm,
                    'channel': channel,
                    'frequency': frequency,
                    'encryption': encryption,
                    'timestamp': timestamp
                })

        except subprocess.TimeoutExpired:
            print("[Scanner/nmcli] Scan timed out")
        except FileNotFoundError:
            print("[Scanner/nmcli] nmcli not found")

        return networks if networks else self._generate_demo_data()

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
        """Scan using netsh (Windows)."""
        timestamp = datetime.now().isoformat()
        networks = []

        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True, text=True, timeout=15
            )

            current_network = {}
            for line in result.stdout.split('\n'):
                line = line.strip()

                if line.startswith('SSID') and 'BSSID' not in line:
                    ssid_match = re.search(r'SSID\s+\d+\s*:\s*(.*)', line)
                    if ssid_match:
                        if current_network.get('bssid'):
                            current_network['timestamp'] = timestamp
                            networks.append(current_network)
                        current_network = {
                            'ssid': ssid_match.group(1).strip() or '<Hidden>',
                            'bssid': '',
                            'signal_strength': -100,
                            'channel': 0,
                            'frequency': '2.4GHz',
                            'encryption': 'Open'
                        }

                elif 'BSSID' in line:
                    bssid_match = re.search(r'BSSID\s+\d+\s*:\s*(.*)', line)
                    if bssid_match:
                        current_network['bssid'] = bssid_match.group(1).strip().upper()

                elif 'Signal' in line:
                    sig_match = re.search(r'(\d+)%', line)
                    if sig_match:
                        current_network['signal_strength'] = self._percent_to_dbm(int(sig_match.group(1)))

                elif 'Channel' in line:
                    ch_match = re.search(r':\s*(\d+)', line)
                    if ch_match:
                        ch = int(ch_match.group(1))
                        current_network['channel'] = ch
                        current_network['frequency'] = "5GHz" if ch > 14 else "2.4GHz"

                elif 'Authentication' in line or 'Encryption' in line:
                    if 'WPA3' in line:
                        current_network['encryption'] = 'WPA3'
                    elif 'WPA2' in line:
                        current_network['encryption'] = 'WPA2'
                    elif 'WPA' in line:
                        current_network['encryption'] = 'WPA'
                    elif 'WEP' in line:
                        current_network['encryption'] = 'WEP'
                    elif 'Open' in line:
                        current_network['encryption'] = 'Open'

            if current_network.get('bssid'):
                current_network['timestamp'] = timestamp
                networks.append(current_network)

        except Exception as e:
            print(f"[Scanner/netsh] Error: {e}")

        return networks if networks else self._generate_demo_data()

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

    def _generate_demo_data(self):
        """
        Generate realistic demo data for testing/demonstration.
        Simulates a coffee shop environment with an Evil Twin attack.
        """
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
