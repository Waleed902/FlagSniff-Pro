"""
ZigBee (802.15.4) Analyzer
Heuristic parsing of 802.15.4/ZigBee frame control fields
"""

from typing import Dict, List, Any, Optional
from scapy.all import Dot15d4, ZigbeeNWK, ZigbeeAppDataPayload
from collections import defaultdict


class ZigBeeAnalyzer:
    """ZigBee network and app payload heuristics"""

    def __init__(self):
        self.nwk_sources = defaultdict(int)
        self.app_profiles = defaultdict(int)

    def analyze_packet(self, pkt) -> Optional[Dict[str, Any]]:
        if not pkt.haslayer(Dot15d4):
            return None

        result = {'type': '802.15.4', 'details': {}}

        if pkt.haslayer(ZigbeeNWK):
            nwk = pkt[ZigbeeNWK]
            src = getattr(nwk, 'source', None)
            dst = getattr(nwk, 'destination', None)
            if src:
                self.nwk_sources[src] += 1
            result['details'].update({'nwk_src': src, 'nwk_dst': dst})

        if pkt.haslayer(ZigbeeAppDataPayload):
            app = pkt[ZigbeeAppDataPayload]
            profile = getattr(app, 'profile', None)
            if profile is not None:
                self.app_profiles[profile] += 1
            result['details']['app_profile'] = profile

        return result

    def analyze_zigbee(self, packets: List) -> Dict[str, Any]:
        results = {
            'nwk_sources': {},
            'app_profiles': {},
            'suspicious_patterns': []
        }

        for pkt in packets:
            self.analyze_packet(pkt)

        results['nwk_sources'] = dict(self.nwk_sources)
        results['app_profiles'] = dict(self.app_profiles)

        return results


def analyze_zigbee_traffic(packets: List) -> Dict[str, Any]:
    analyzer = ZigBeeAnalyzer()
    return analyzer.analyze_zigbee(packets)
