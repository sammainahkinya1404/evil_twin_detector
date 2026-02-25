"""
Evil Twin Detection Engine

Analyzes WiFi networks for Evil Twin attack indicators using
a behavior-based, multi-factor scoring system.

Detection Factors:
1. SSID Duplication - Multiple APs with same network name
2. MAC Address Analysis - OUI vendor verification, randomization detection
3. Encryption Anomalies - Downgrade attacks (WPA2 → Open)
4. Signal Strength Analysis - Unusually strong signals, instability
5. Channel Analysis - Unusual channel assignments
6. Behavioral Patterns - Combined risk scoring

Risk Levels:
- LOW (0-30):    Normal network behavior
- MEDIUM (31-60): Some suspicious indicators, investigate further
- HIGH (61-100):  Strong Evil Twin indicators, avoid connecting
"""

import re
import json
from datetime import datetime
from collections import defaultdict


# Known legitimate OUI prefixes (first 3 bytes of MAC address)
# This is a subset; a full production system would use the IEEE OUI database
KNOWN_VENDORS = {
    '00:1A:2B': 'Cisco Systems',
    'AA:BB:CC': 'TP-Link',
    '10:20:30': 'Netgear',
    '00:50:56': 'VMware',
    'DC:A6:32': 'Raspberry Pi',
    'B8:27:EB': 'Raspberry Pi',
    '00:0C:29': 'VMware',
    'F4:F5:D8': 'Google',
    '3C:5A:B4': 'Google',
    'AC:BC:32': 'Apple',
    '00:1B:63': 'Apple',
    '88:E9:FE': 'Apple',
    'FC:FC:48': 'Apple',
    'A4:83:E7': 'Apple',
    '00:14:22': 'Dell',
    '00:24:E8': 'Dell',
    '30:B5:C2': 'TP-Link',
    '50:C7:BF': 'TP-Link',
    'C0:25:E9': 'TP-Link',
    'E8:48:B8': 'D-Link',
    '00:1C:F0': 'D-Link',
    '28:10:7B': 'D-Link',
    '00:1E:58': 'D-Link',
    'A0:63:91': 'Netgear',
    '20:4E:7F': 'Netgear',
    '6C:B0:CE': 'Netgear',
    '00:22:3F': 'Netgear',
    '84:1B:5E': 'Netgear',
    'C8:3A:35': 'Linksys',
    '00:18:F8': 'Linksys',
    '00:1A:70': 'Linksys',
    '44:94:FC': 'Ubiquiti',
    '80:2A:A8': 'Ubiquiti',
    '24:A4:3C': 'Ubiquiti',
    'F0:9F:C2': 'Ubiquiti',
    '00:27:22': 'Ubiquiti',
    '18:E8:29': 'Ubiquiti',
    '68:72:51': 'Ubiquiti',
    '74:83:C2': 'Ubiquiti',
    'B4:FB:E4': 'Ubiquiti',
    'FC:EC:DA': 'Ubiquiti',
}

# Common legitimate SSIDs often targeted by Evil Twin attacks
COMMONLY_SPOOFED_SSIDS = {
    'attwifi', 'xfinity', 'xfinitywifi', 'starbucks', 'google starbucks',
    'boingo', 'boingo hotspot', 'tmobile', 't-mobile', 'free wifi',
    'airport wifi', 'airport free wifi', 'hotel wifi', 'guest',
    'public wifi', 'free internet', 'open', 'linksys', 'netgear',
    'default', 'dlink', 'belkin', 'home', 'office wifi'
}


class EvilTwinDetector:
    """
    Behavior-based Evil Twin attack detection engine.

    Uses multi-factor analysis to score each network's risk level
    based on various suspicious indicators.
    """

    def __init__(self):
        self.whitelist = []  # Trusted BSSIDs
        self.network_history = defaultdict(list)  # Track changes over time
        self.weights = {
            'ssid_duplication': 25,
            'encryption_mismatch': 20,
            'signal_anomaly': 15,
            'channel_anomaly': 10,
            'mac_anomaly': 15,
            'open_network': 10,
            'common_spoof_target': 5,
        }

    def update_whitelist(self, whitelist):
        """Update the trusted networks whitelist."""
        self.whitelist = [entry['bssid'] for entry in whitelist]

    def analyze(self, networks):
        """
        Analyze a list of scanned networks for Evil Twin indicators.

        Args:
            networks: List of network dicts from WiFiScanner

        Returns:
            List of network dicts with added analysis fields:
                - risk_score (int): 0-100
                - risk_level (str): 'low', 'medium', 'high'
                - risk_factors (list): Detected suspicious indicators
                - vendor (str): Identified hardware vendor
        """
        if not networks:
            return []

        # Group networks by SSID for duplicate analysis
        ssid_groups = defaultdict(list)
        for network in networks:
            ssid_groups[network['ssid']].append(network)

        # Analyze each network
        analyzed = []
        for network in networks:
            result = self._analyze_single(network, ssid_groups)
            analyzed.append(result)

            # Update history
            self._update_history(network)

        # Sort by risk score (highest first)
        analyzed.sort(key=lambda x: x['risk_score'], reverse=True)

        return analyzed

    def _analyze_single(self, network, ssid_groups):
        """Analyze a single network for all risk factors."""
        risk_factors = []
        risk_score = 0
        ssid = network['ssid']
        bssid = network['bssid']

        # ─── Check Whitelist ───
        if bssid in self.whitelist:
            network['risk_score'] = 0
            network['risk_level'] = 'low'
            network['risk_factors'] = ['Whitelisted (trusted network)']
            network['vendor'] = self._identify_vendor(bssid)
            network['is_whitelisted'] = True
            return network

        # ─── Factor 1: SSID Duplication ───
        duplicates = ssid_groups.get(ssid, [])
        if len(duplicates) > 1 and ssid != '<Hidden>':
            risk_score += self.weights['ssid_duplication']
            other_bssids = [n['bssid'] for n in duplicates if n['bssid'] != bssid]
            risk_factors.append({
                'factor': 'SSID Duplication',
                'severity': 'high',
                'detail': f'Multiple access points ({len(duplicates)}) share the name "{ssid}". '
                         f'Other BSSIDs: {", ".join(other_bssids[:3])}'
            })

            # ─── Factor 2: Encryption Mismatch (within duplicates) ───
            encryption_types = set(n['encryption'] for n in duplicates)
            if len(encryption_types) > 1:
                risk_score += self.weights['encryption_mismatch']
                risk_factors.append({
                    'factor': 'Encryption Mismatch',
                    'severity': 'high',
                    'detail': f'Networks with same name use different encryption: '
                             f'{", ".join(encryption_types)}. '
                             f'This is a strong indicator of an Evil Twin attack.'
                })

            # ─── Signal Comparison (within duplicates) ───
            signals = [(n['bssid'], n['signal_strength']) for n in duplicates]
            my_signal = network['signal_strength']
            others_avg = sum(s for b, s in signals if b != bssid) / max(len(signals) - 1, 1)

            if my_signal > others_avg + 15:  # Suspiciously stronger
                risk_score += self.weights['signal_anomaly']
                risk_factors.append({
                    'factor': 'Abnormal Signal Strength',
                    'severity': 'medium',
                    'detail': f'Signal ({my_signal} dBm) is significantly stronger than '
                             f'other "{ssid}" networks (avg {others_avg:.0f} dBm). '
                             f'Attackers often use high-power antennas.'
                })

            # ─── Channel Analysis (within duplicates) ───
            channels = set(n['channel'] for n in duplicates)
            if len(channels) > 1:
                risk_score += self.weights['channel_anomaly']
                risk_factors.append({
                    'factor': 'Channel Discrepancy',
                    'severity': 'medium',
                    'detail': f'Same-name networks operate on different channels: '
                             f'{", ".join(str(c) for c in channels)}. '
                             f'Legitimate multi-AP setups usually share the same channel or use a consistent pattern.'
                })

        # ─── Factor 3: Open Network Warning ───
        if network['encryption'] == 'Open':
            risk_score += self.weights['open_network']
            risk_factors.append({
                'factor': 'Open Network (No Encryption)',
                'severity': 'medium',
                'detail': 'This network has no encryption. All traffic can be intercepted. '
                         'Avoid transmitting sensitive data.'
            })

        # ─── Factor 4: MAC Address Analysis ───
        vendor = self._identify_vendor(bssid)
        mac_issues = self._analyze_mac(bssid)
        if mac_issues:
            risk_score += self.weights['mac_anomaly']
            risk_factors.append({
                'factor': 'MAC Address Anomaly',
                'severity': 'medium',
                'detail': mac_issues
            })

        # ─── Factor 5: Commonly Spoofed SSID ───
        if ssid.lower().strip() in COMMONLY_SPOOFED_SSIDS:
            risk_score += self.weights['common_spoof_target']
            risk_factors.append({
                'factor': 'Common Spoof Target',
                'severity': 'low',
                'detail': f'"{ssid}" is a commonly spoofed network name. '
                         f'Extra caution is advised.'
            })

        # ─── Factor 6: Historical Analysis ───
        historical_risk = self._check_history(network)
        if historical_risk:
            risk_score += 10
            risk_factors.append(historical_risk)

        # ─── Factor 7: Hidden SSID with Open encryption ───
        if ssid == '<Hidden>' and network['encryption'] == 'Open':
            risk_score += 15
            risk_factors.append({
                'factor': 'Hidden Open Network',
                'severity': 'medium',
                'detail': 'Hidden network with no encryption is suspicious. '
                         'Legitimate networks rarely hide their SSID while being open.'
            })

        # ─── Calculate Final Risk Level ───
        risk_score = min(risk_score, 100)  # Cap at 100

        if risk_score >= 61:
            risk_level = 'high'
        elif risk_score >= 31:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        # Build result
        network['risk_score'] = risk_score
        network['risk_level'] = risk_level
        network['risk_factors'] = risk_factors
        network['vendor'] = vendor
        network['is_whitelisted'] = False
        network['duplicate_count'] = len(ssid_groups.get(ssid, []))

        return network

    def _identify_vendor(self, bssid):
        """Identify the hardware vendor from the MAC address OUI."""
        if not bssid:
            return 'Unknown'

        oui = bssid[:8].upper()
        vendor = KNOWN_VENDORS.get(oui)

        if vendor:
            return vendor

        # Check if it looks like a locally administered MAC (bit 1 of first byte set)
        try:
            first_byte = int(bssid.split(':')[0], 16)
            if first_byte & 0x02:
                return 'Locally Administered (possibly spoofed)'
        except ValueError:
            pass

        return 'Unknown Vendor'

    def _analyze_mac(self, bssid):
        """Analyze MAC address for anomalies."""
        if not bssid:
            return "Missing MAC address"

        try:
            first_byte = int(bssid.split(':')[0], 16)

            # Check for locally administered bit (LA bit)
            if first_byte & 0x02:
                return (
                    f'MAC address {bssid} has the locally administered bit set. '
                    f'This means it may be manually assigned or spoofed, '
                    f'rather than assigned by a legitimate hardware manufacturer.'
                )

            # Check for multicast bit (shouldn't be set for APs)
            if first_byte & 0x01:
                return (
                    f'MAC address {bssid} has the multicast bit set, '
                    f'which is abnormal for a WiFi access point.'
                )

        except (ValueError, IndexError):
            return f'MAC address {bssid} has an invalid format.'

        return None

    def _check_history(self, network):
        """Check network against historical observations."""
        bssid = network['bssid']
        history = self.network_history.get(bssid, [])

        if len(history) < 2:
            return None

        # Check for encryption changes
        prev_encryption = history[-1].get('encryption')
        curr_encryption = network.get('encryption')

        if prev_encryption and curr_encryption and prev_encryption != curr_encryption:
            return {
                'factor': 'Encryption Change Detected',
                'severity': 'high',
                'detail': f'Network encryption changed from {prev_encryption} to {curr_encryption}. '
                         f'This could indicate an attack or configuration change.'
            }

        # Check for large signal strength changes
        prev_signal = history[-1].get('signal_strength', -100)
        curr_signal = network.get('signal_strength', -100)

        if abs(curr_signal - prev_signal) > 25:
            return {
                'factor': 'Signal Strength Fluctuation',
                'severity': 'medium',
                'detail': f'Signal changed from {prev_signal} dBm to {curr_signal} dBm. '
                         f'Large fluctuations can indicate a rogue access point.'
            }

        return None

    def _update_history(self, network):
        """Store network observation in history."""
        bssid = network['bssid']
        self.network_history[bssid].append({
            'timestamp': network.get('timestamp'),
            'signal_strength': network.get('signal_strength'),
            'encryption': network.get('encryption'),
            'channel': network.get('channel'),
            'ssid': network.get('ssid'),
        })

        # Keep only last 50 observations per BSSID
        if len(self.network_history[bssid]) > 50:
            self.network_history[bssid] = self.network_history[bssid][-50:]

    def get_threat_summary(self, analyzed_networks):
        """Generate a human-readable threat summary."""
        if not analyzed_networks:
            return "No networks detected."

        total = len(analyzed_networks)
        high_risk = sum(1 for n in analyzed_networks if n['risk_level'] == 'high')
        medium_risk = sum(1 for n in analyzed_networks if n['risk_level'] == 'medium')
        low_risk = sum(1 for n in analyzed_networks if n['risk_level'] == 'low')

        summary = {
            'total_networks': total,
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'threat_level': 'critical' if high_risk > 0 else ('warning' if medium_risk > 0 else 'safe'),
            'message': ''
        }

        if high_risk > 0:
            summary['message'] = (
                f'⚠️ DANGER: {high_risk} high-risk network(s) detected! '
                f'Possible Evil Twin attack in progress. '
                f'Avoid connecting to suspicious networks.'
            )
        elif medium_risk > 0:
            summary['message'] = (
                f'⚡ CAUTION: {medium_risk} network(s) with suspicious behavior detected. '
                f'Exercise caution when connecting.'
            )
        else:
            summary['message'] = (
                f'✅ SAFE: All {total} detected network(s) appear normal. '
                f'No Evil Twin indicators found.'
            )

        return summary
