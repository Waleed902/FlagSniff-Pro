"""
Wi-Fi (802.11) Analyzer
Detects EAPOL handshakes, deauth attacks, AP/client stats
"""

from typing import Dict, List, Any, Optional
from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11ProbeReq, Dot11ProbeResp, EAPOL
from collections import defaultdict


class WiFiAnalyzer:
    """802.11 management/control plane analyzer"""

    def __init__(self):
        self.aps = {}
        self.clients = defaultdict(set)
        self.deauth_counts = defaultdict(int)
        self.eapol_pairs = defaultdict(list)  # key: (sta, ap)

    def analyze_packet(self, pkt) -> Optional[Dict[str, Any]]:
        if not pkt.haslayer(Dot11):
            return None

        result = {
            'type': None,
            'ap': None,
            'client': None,
            'details': {}
        }

        dot11 = pkt[Dot11]
        addr1 = getattr(dot11, 'addr1', None)
        addr2 = getattr(dot11, 'addr2', None)
        addr3 = getattr(dot11, 'addr3', None)

        # Beacon frames -> Access Point
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Beacon].network_stats().get('ssid', '')
            channel = pkt[Dot11Beacon].network_stats().get('channel', None)
            bssid = addr2 or addr3
            if bssid:
                self.aps[bssid] = {
                    'ssid': ssid,
                    'channel': channel
                }
                result['type'] = 'beacon'
                result['ap'] = bssid
                result['details'] = {'ssid': ssid, 'channel': channel}

        # Probe requests/responses
        elif pkt.haslayer(Dot11ProbeReq):
            result['type'] = 'probe_req'
            result['client'] = addr2
        elif pkt.haslayer(Dot11ProbeResp):
            result['type'] = 'probe_resp'
            result['ap'] = addr2

        # Association
        elif pkt.haslayer(Dot11AssoReq):
            result['type'] = 'assoc_req'
            result['client'] = addr2
            result['ap'] = addr1
            if addr1 and addr2:
                self.clients[addr1].add(addr2)
        elif pkt.haslayer(Dot11AssoResp):
            result['type'] = 'assoc_resp'
            result['ap'] = addr2
            result['client'] = addr1

        # Deauthentication
        elif pkt.haslayer(Dot11Deauth):
            result['type'] = 'deauth'
            src = addr2
            dst = addr1
            key = (src, dst)
            self.deauth_counts[key] += 1
            result['details'] = {'src': src, 'dst': dst}

        # EAPOL (WPA handshake)
        if pkt.haslayer(EAPOL):
            # Track per client/AP pair
            sta = addr2 if addr2 else 'unknown'
            ap = addr1 if addr1 else 'unknown'
            self.eapol_pairs[(sta, ap)].append({'len': len(pkt), 'fcf': dot11.FCfield if hasattr(dot11, 'FCfield') else 0})
            result['type'] = (result['type'] or '') + ('+eapol' if result['type'] else 'eapol')
            result['client'] = sta
            result['ap'] = ap

        return result if result['type'] else None

    def analyze_wifi(self, packets: List) -> Dict[str, Any]:
        results = {
            'aps': self.aps,
            'clients_per_ap': {ap: list(clients) for ap, clients in self.clients.items()},
            'deauth_events': [],
            'eapol_handshakes': [],
            'suspicious_patterns': []
        }

        for pkt in packets:
            self.analyze_packet(pkt)

        # Summarize deauth
        for (src, dst), count in self.deauth_counts.items():
            if count > 0:
                results['deauth_events'].append({'src': src, 'dst': dst, 'count': count})

        # Summarize EAPOL (4-way handshake heuristics: >=4 frames between same pair)
        for (sta, ap), frames in self.eapol_pairs.items():
            if len(frames) >= 4:
                results['eapol_handshakes'].append({'sta': sta, 'ap': ap, 'frames': len(frames)})

        # Suspicious patterns
        total_deauth = sum(c for c in self.deauth_counts.values())
        if total_deauth > 50:
            results['suspicious_patterns'].append({
                'type': 'deauth_attack',
                'severity': 'high',
                'description': f'{total_deauth} deauth frames seen (possible deauth attack)'
            })
        if len(results['eapol_handshakes']) > 10:
            results['suspicious_patterns'].append({
                'type': 'mass_handshakes',
                'severity': 'medium',
                'description': 'Many EAPOL handshakes observed (wardriving or attack)'
            })

        return results


def analyze_wifi_traffic(packets: List) -> Dict[str, Any]:
    analyzer = WiFiAnalyzer()
    return analyzer.analyze_wifi(packets)
