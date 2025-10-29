"""
Bluetooth Low Energy (BLE) Analyzer
Heuristic detection of BLE advertising and GATT-like traffic in captures with HCI/BTLE layers
"""

from typing import Dict, List, Any, Optional
from scapy.all import BTLE, BTLE_ADV, BTLE_SCAN_REQ, BTLE_SCAN_RSP, BTLE_DATA
from collections import defaultdict


class BLEAnalyzer:
    """BLE advertising and basic data channel analysis"""

    def __init__(self):
        self.advertisers = defaultdict(int)
        self.scan_requests = defaultdict(int)
        self.connections = defaultdict(int)

    def analyze_packet(self, pkt) -> Optional[Dict[str, Any]]:
        if not pkt.haslayer(BTLE):
            return None

        result = {'type': None, 'addr': None, 'details': {}}

        if pkt.haslayer(BTLE_ADV):
            adv = pkt[BTLE_ADV]
            addr = getattr(adv, 'AdvA', None) or getattr(adv, 'InitA', None)
            if addr:
                self.advertisers[addr] += 1
            result['type'] = 'advertising'
            result['addr'] = addr
        elif pkt.haslayer(BTLE_SCAN_REQ):
            req = pkt[BTLE_SCAN_REQ]
            addr = getattr(req, 'ScanA', None)
            if addr:
                self.scan_requests[addr] += 1
            result['type'] = 'scan_req'
            result['addr'] = addr
        elif pkt.haslayer(BTLE_SCAN_RSP):
            result['type'] = 'scan_rsp'
        elif pkt.haslayer(BTLE_DATA):
            result['type'] = 'data'

        return result if result['type'] else None

    def analyze_ble(self, packets: List) -> Dict[str, Any]:
        results = {
            'advertisers': {},
            'scan_requests': {},
            'connections': {},
            'suspicious_patterns': []
        }

        for pkt in packets:
            self.analyze_packet(pkt)

        results['advertisers'] = dict(self.advertisers)
        results['scan_requests'] = dict(self.scan_requests)
        results['connections'] = dict(self.connections)

        # Suspicious: excessive scans
        total_scans = sum(self.scan_requests.values())
        if total_scans > 100:
            results['suspicious_patterns'].append({
                'type': 'ble_scanning',
                'severity': 'low',
                'description': f'{total_scans} BLE scan requests observed'
            })

        return results


def analyze_ble_traffic(packets: List) -> Dict[str, Any]:
    analyzer = BLEAnalyzer()
    return analyzer.analyze_ble(packets)
