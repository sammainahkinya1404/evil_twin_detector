"""
Threat Simulator Module

Generates realistic Evil Twin attack scenarios for testing,
demonstration, and presentation purposes.

Includes multiple pre-built scenarios:
1. Coffee Shop Attack - Classic Evil Twin with open network
2. Corporate Espionage - Sophisticated attack with MAC spoofing
3. Airport Honeypot - Multiple fake free WiFi networks
4. University Campus - Large-scale multi-AP attack
5. Hotel Attack - Captive portal phishing scenario
6. Custom Mix - Randomized combination of attack types

Each scenario generates a mix of legitimate and malicious networks
to demonstrate the detection engine's capabilities.
"""

import random
import string
from datetime import datetime


class ThreatSimulator:
    """Generates realistic Evil Twin attack scenarios."""

    def __init__(self):
        self.last_threat_bssids = set()
        self.scenarios = {
            'coffee_shop': self._scenario_coffee_shop,
            'corporate': self._scenario_corporate,
            'airport': self._scenario_airport,
            'university': self._scenario_university,
            'hotel': self._scenario_hotel,
            'multi_attack': self._scenario_multi_attack,
        }

    def get_available_scenarios(self):
        """Return list of available simulation scenarios."""
        return [
            {
                'id': 'coffee_shop',
                'name': 'Coffee Shop Attack',
                'description': 'Classic Evil Twin: attacker clones cafe WiFi with open network and stronger signal.',
                'difficulty': 'Basic',
                'networks': 8,
                'threats': 2,
            },
            {
                'id': 'corporate',
                'name': 'Corporate Espionage',
                'description': 'Sophisticated attack targeting corporate WPA2 network with MAC spoofing.',
                'difficulty': 'Advanced',
                'networks': 10,
                'threats': 3,
            },
            {
                'id': 'airport',
                'name': 'Airport Honeypot',
                'description': 'Multiple fake free WiFi networks targeting travelers.',
                'difficulty': 'Intermediate',
                'networks': 12,
                'threats': 4,
            },
            {
                'id': 'university',
                'name': 'University Campus',
                'description': 'Large-scale attack in dense WiFi environment with eduroam clones.',
                'difficulty': 'Advanced',
                'networks': 15,
                'threats': 5,
            },
            {
                'id': 'hotel',
                'name': 'Hotel WiFi Attack',
                'description': 'Fake hotel network with captive portal phishing for room credentials.',
                'difficulty': 'Intermediate',
                'networks': 9,
                'threats': 3,
            },
            {
                'id': 'multi_attack',
                'name': 'Multi-Vector Attack',
                'description': 'Simultaneous Evil Twin attacks on multiple networks. Worst-case scenario.',
                'difficulty': 'Critical',
                'networks': 14,
                'threats': 6,
            },
        ]

    def simulate(self, scenario_id):
        """
        Generate networks for a specific attack scenario.

        Args:
            scenario_id: One of the scenario keys

        Returns:
            list: List of network dicts (same format as WiFiScanner output)
        """
        generator = self.scenarios.get(scenario_id)
        if not generator:
            raise ValueError(f"Unknown scenario: {scenario_id}. Available: {list(self.scenarios.keys())}")

        networks = generator()

        # Ground truth for testing/evaluation: which BSSIDs are planted threats.
        # The label is removed from the network dicts so the detector (and the
        # dashboard) only ever see what a real scan would provide.
        self.last_threat_bssids = {
            net['bssid'] for net in networks if net.pop('_threat', False)
        }

        # Add slight random variation to make each run unique
        for net in networks:
            net['signal_strength'] += random.randint(-3, 3)
            net['signal_strength'] = max(-95, min(-20, net['signal_strength']))

        return networks

    def _random_mac(self, prefix=None):
        """Generate a random MAC address."""
        if prefix:
            remaining = 6 - len(prefix.split(':'))
            suffix = ':'.join(f'{random.randint(0, 255):02X}' for _ in range(remaining))
            return f"{prefix}:{suffix}"
        return ':'.join(f'{random.randint(0, 255):02X}' for _ in range(6))

    def _locally_administered_mac(self):
        """Generate a MAC with locally administered bit set (spoofed indicator)."""
        first_byte = random.randint(0, 255) | 0x02  # Set LA bit
        rest = ':'.join(f'{random.randint(0, 255):02X}' for _ in range(5))
        return f"{first_byte:02X}:{rest}"

    def _ts(self):
        """Current timestamp."""
        return datetime.now().isoformat()

    # ═══════════════════════════════════════
    # Scenario Generators
    # ═══════════════════════════════════════

    def _scenario_coffee_shop(self):
        """
        SCENARIO: Coffee Shop Attack
        
        Setting: A busy coffee shop with free WiFi.
        Attack: Attacker sets up Evil Twin with same name but no encryption
                and a stronger signal to lure victims.
        """
        ts = self._ts()
        return [
            # ✅ Legitimate coffee shop network
            {
                'ssid': 'Brew & Bean WiFi',
                'bssid': '30:B5:C2:A1:44:21',  # TP-Link OUI
                'signal_strength': -52,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - same name, open, stronger signal
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'Brew & Bean WiFi',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -28,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ Legitimate 5GHz band
            {
                'ssid': 'Brew & Bean WiFi 5G',
                'bssid': '30:B5:C2:A1:44:22',
                'signal_strength': -48,
                'channel': 36,
                'frequency': '5GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 Suspicious free WiFi honeypot
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'Free Coffee WiFi',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -35,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ Neighboring business
            {
                'ssid': 'BookStore_Net',
                'bssid': 'E8:48:B8:55:22:11',  # D-Link OUI
                'signal_strength': -68,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Nearby apartment
            {
                'ssid': 'NETGEAR-Home-2F',
                'bssid': 'A0:63:91:88:33:C2',  # Netgear OUI
                'signal_strength': -75,
                'channel': 9,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Mobile hotspot
            {
                'ssid': 'Sarah\'s iPhone',
                'bssid': '88:E9:FE:71:A0:33',  # Apple OUI
                'signal_strength': -60,
                'channel': 4,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Another neighbor
            {
                'ssid': 'Apartment_3B',
                'bssid': 'C8:3A:35:12:67:89',  # Linksys OUI
                'signal_strength': -78,
                'channel': 3,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
        ]

    def _scenario_corporate(self):
        """
        SCENARIO: Corporate Espionage

        Setting: Office building with corporate WPA2-Enterprise network.
        Attack: Attacker deploys sophisticated Evil Twin with cloned BSSID
                prefix and downgraded encryption to capture credentials.
        """
        ts = self._ts()
        return [
            # ✅ Corporate main network
            {
                'ssid': 'TechVentures-Corp',
                'bssid': '44:94:FC:AA:11:01',  # Ubiquiti OUI
                'signal_strength': -45,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'WPA2-Enterprise',
                'timestamp': ts
            },
            # ✅ Corporate AP 2
            {
                'ssid': 'TechVentures-Corp',
                'bssid': '44:94:FC:AA:11:02',  # Same Ubiquiti OUI
                'signal_strength': -50,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2-Enterprise',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - Corporate clone with WPA (downgrade)
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'TechVentures-Corp',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -30,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA',
                'timestamp': ts
            },
            # ✅ Corporate guest network
            {
                'ssid': 'TechVentures-Guest',
                'bssid': '44:94:FC:AA:22:01',
                'signal_strength': -55,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - Guest network clone (open)
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'TechVentures-Guest',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -32,
                'channel': 3,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # 🚨 Hidden rogue AP
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': '<Hidden>',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -38,
                'channel': 8,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ Nearby office
            {
                'ssid': 'LawFirm-5thFloor',
                'bssid': '80:2A:A8:CC:55:01',
                'signal_strength': -65,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Building management
            {
                'ssid': 'BuildingMgmt-IoT',
                'bssid': 'C0:25:E9:11:22:33',
                'signal_strength': -72,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ 5GHz corporate
            {
                'ssid': 'TechVentures-5G',
                'bssid': '44:94:FC:AA:33:01',
                'signal_strength': -42,
                'channel': 44,
                'frequency': '5GHz',
                'encryption': 'WPA2-Enterprise',
                'timestamp': ts
            },
            # ✅ Printer network
            {
                'ssid': 'DIRECT-HP-Printer',
                'bssid': '00:14:22:AB:CD:EF',
                'signal_strength': -58,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
        ]

    def _scenario_airport(self):
        """
        SCENARIO: Airport Honeypot

        Setting: International airport terminal with multiple WiFi networks.
        Attack: Multiple fake free WiFi networks targeting travelers,
                plus a clone of the airport's official network.
        """
        ts = self._ts()
        return [
            # ✅ Official airport WiFi
            {
                'ssid': 'Airport-FreeWiFi',
                'bssid': 'F0:9F:C2:10:20:01',  # Ubiquiti OUI
                'signal_strength': -50,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Official airport AP 2
            {
                'ssid': 'Airport-FreeWiFi',
                'bssid': 'F0:9F:C2:10:20:02',
                'signal_strength': -55,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - Airport clone (open)
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'Airport-FreeWiFi',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -25,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # 🚨 Fake free WiFi honeypot 1
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'Free_Airport_Internet',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -30,
                'channel': 3,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # 🚨 Fake free WiFi honeypot 2
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'FREE-WIFI-AIRPORT',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -28,
                'channel': 9,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # 🚨 Airline lounge fake
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'SkyLounge-Premium',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -33,
                'channel': 4,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ Airline official lounge
            {
                'ssid': 'SkyLounge-Premium',
                'bssid': '18:E8:29:AA:BB:01',  # Ubiquiti
                'signal_strength': -48,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Airport shop
            {
                'ssid': 'DutyFree-Guest',
                'bssid': '50:C7:BF:11:22:33',
                'signal_strength': -62,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Restaurant
            {
                'ssid': 'Skybites-Cafe',
                'bssid': '6C:B0:CE:44:55:66',
                'signal_strength': -58,
                'channel': 8,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Traveler hotspot
            {
                'ssid': 'Mike\'s Galaxy S24',
                'bssid': 'F4:F5:D8:99:88:77',
                'signal_strength': -65,
                'channel': 2,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Airport operations (hidden)
            {
                'ssid': '<Hidden>',
                'bssid': '68:72:51:DD:EE:FF',
                'signal_strength': -70,
                'channel': 44,
                'frequency': '5GHz',
                'encryption': 'WPA2-Enterprise',
                'timestamp': ts
            },
            # ✅ Another gate
            {
                'ssid': 'Airport-FreeWiFi',
                'bssid': 'F0:9F:C2:10:20:03',
                'signal_strength': -60,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
        ]

    def _scenario_university(self):
        """
        SCENARIO: University Campus

        Setting: Dense university campus with eduroam and department networks.
        Attack: Multiple Evil Twins targeting eduroam and library WiFi.
        """
        ts = self._ts()
        return [
            # ✅ eduroam AP 1
            {
                'ssid': 'eduroam',
                'bssid': '74:83:C2:11:22:01',  # Ubiquiti
                'signal_strength': -45,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'WPA2-Enterprise',
                'timestamp': ts
            },
            # ✅ eduroam AP 2
            {
                'ssid': 'eduroam',
                'bssid': '74:83:C2:11:22:02',
                'signal_strength': -52,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2-Enterprise',
                'timestamp': ts
            },
            # ✅ eduroam AP 3
            {
                'ssid': 'eduroam',
                'bssid': '74:83:C2:11:22:03',
                'signal_strength': -58,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA2-Enterprise',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - eduroam clone (WPA instead of Enterprise)
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'eduroam',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -25,
                'channel': 3,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - eduroam open clone
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'eduroam',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -30,
                'channel': 8,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ University library
            {
                'ssid': 'UniLibrary-WiFi',
                'bssid': 'B4:FB:E4:AA:BB:01',
                'signal_strength': -40,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - Library clone
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'UniLibrary-WiFi',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -22,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ Student center
            {
                'ssid': 'StudentCenter-Free',
                'bssid': 'FC:EC:DA:CC:DD:01',
                'signal_strength': -55,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 Fake free WiFi
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'University-Free-WiFi',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -32,
                'channel': 4,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # 🚨 Hidden rogue
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': '<Hidden>',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -35,
                'channel': 10,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ CS Department
            {
                'ssid': 'CS-Lab-Network',
                'bssid': '00:27:22:11:33:55',
                'signal_strength': -62,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Student phone
            {
                'ssid': 'Ahmed-Hotspot',
                'bssid': 'AC:BC:32:77:88:99',
                'signal_strength': -70,
                'channel': 7,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ 5GHz eduroam
            {
                'ssid': 'eduroam',
                'bssid': '74:83:C2:11:22:04',
                'signal_strength': -48,
                'channel': 36,
                'frequency': '5GHz',
                'encryption': 'WPA2-Enterprise',
                'timestamp': ts
            },
            # ✅ Nearby cafe
            {
                'ssid': 'CampusCafe',
                'bssid': '20:4E:7F:55:66:77',
                'signal_strength': -72,
                'channel': 9,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Admin network (hidden, secure)
            {
                'ssid': '<Hidden>',
                'bssid': '24:A4:3C:88:99:AA',
                'signal_strength': -65,
                'channel': 44,
                'frequency': '5GHz',
                'encryption': 'WPA2-Enterprise',
                'timestamp': ts
            },
        ]

    def _scenario_hotel(self):
        """
        SCENARIO: Hotel WiFi Attack

        Setting: Hotel with guest WiFi requiring room number + last name.
        Attack: Fake hotel network with captive portal to harvest credentials.
        """
        ts = self._ts()
        return [
            # ✅ Hotel official WiFi
            {
                'ssid': 'GrandHotel-Guest',
                'bssid': 'C0:25:E9:AA:BB:01',  # TP-Link
                'signal_strength': -48,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Hotel official AP 2
            {
                'ssid': 'GrandHotel-Guest',
                'bssid': 'C0:25:E9:AA:BB:02',
                'signal_strength': -55,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - Hotel clone (open, for captive portal phishing)
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'GrandHotel-Guest',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -26,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ Hotel conference room
            {
                'ssid': 'GrandHotel-Conference',
                'bssid': 'C0:25:E9:AA:CC:01',
                'signal_strength': -60,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 Fake conference clone
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'GrandHotel-Conference',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -30,
                'channel': 3,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # 🚨 Generic hotel honeypot
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'Hotel-Free-Internet',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -33,
                'channel': 8,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ Hotel staff network
            {
                'ssid': '<Hidden>',
                'bssid': 'C0:25:E9:AA:DD:01',
                'signal_strength': -65,
                'channel': 44,
                'frequency': '5GHz',
                'encryption': 'WPA2-Enterprise',
                'timestamp': ts
            },
            # ✅ Neighboring restaurant
            {
                'ssid': 'Rooftop-Bar-WiFi',
                'bssid': '28:10:7B:11:22:33',
                'signal_strength': -70,
                'channel': 9,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Guest personal hotspot
            {
                'ssid': 'Travel-iPhone',
                'bssid': 'A4:83:E7:44:55:66',
                'signal_strength': -68,
                'channel': 5,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
        ]

    def _scenario_multi_attack(self):
        """
        SCENARIO: Multi-Vector Attack (Worst Case)

        Setting: Shopping mall with many networks.
        Attack: Simultaneous Evil Twins on multiple networks + honeypots.
        """
        ts = self._ts()
        return [
            # ✅ Mall WiFi
            {
                'ssid': 'MegaMall-WiFi',
                'bssid': '84:1B:5E:11:22:01',
                'signal_strength': -50,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - Mall clone
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'MegaMall-WiFi',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -22,
                'channel': 1,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ Starbucks
            {
                'ssid': 'Starbucks WiFi',
                'bssid': '22:33:44:55:66:01',
                'signal_strength': -55,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - Starbucks clone
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'Starbucks WiFi',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -28,
                'channel': 6,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ Phone carrier WiFi
            {
                'ssid': 'xfinitywifi',
                'bssid': 'AA:BB:CC:DD:EE:01',
                'signal_strength': -60,
                'channel': 11,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # 🚨 EVIL TWIN - carrier clone
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'xfinitywifi',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -30,
                'channel': 3,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # 🚨 Honeypot 1
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'Free_Public_WiFi',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -25,
                'channel': 4,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # 🚨 Honeypot 2
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': 'FREE INTERNET',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -27,
                'channel': 9,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # 🚨 Hidden rogue
            {
                '_threat': True,  # ground-truth label, removed before analysis
                'ssid': '<Hidden>',
                'bssid': self._locally_administered_mac(),
                'signal_strength': -32,
                'channel': 7,
                'frequency': '2.4GHz',
                'encryption': 'Open',
                'timestamp': ts
            },
            # ✅ Food court
            {
                'ssid': 'FoodCourt-Guest',
                'bssid': '3C:5A:B4:77:88:99',
                'signal_strength': -58,
                'channel': 8,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Cinema
            {
                'ssid': 'CinePlex-WiFi',
                'bssid': '00:1B:63:AA:BB:CC',
                'signal_strength': -65,
                'channel': 2,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Gym
            {
                'ssid': 'FitZone-Members',
                'bssid': '00:1E:58:DD:EE:FF',
                'signal_strength': -72,
                'channel': 10,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Phone hotspot
            {
                'ssid': 'Galaxy-Note-AP',
                'bssid': 'FC:FC:48:12:34:56',
                'signal_strength': -68,
                'channel': 5,
                'frequency': '2.4GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
            # ✅ Mall 5GHz
            {
                'ssid': 'MegaMall-5G',
                'bssid': '84:1B:5E:11:22:02',
                'signal_strength': -45,
                'channel': 36,
                'frequency': '5GHz',
                'encryption': 'WPA2',
                'timestamp': ts
            },
        ]
