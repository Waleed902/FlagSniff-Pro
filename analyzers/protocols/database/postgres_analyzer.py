"""
PostgreSQL Protocol Analyzer (heuristic)
Detects PostgreSQL startup and simple query frames
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw
from collections import defaultdict
import struct


class PostgresAnalyzer:
    PORTS = {5432}

    def is_postgres(self, pkt) -> bool:
        if not pkt.haslayer(TCP):
            return False
        return pkt[TCP].sport in self.PORTS or pkt[TCP].dport in self.PORTS

    def parse_startup(self, payload: bytes) -> Optional[Dict[str, Any]]:
        # StartupMessage: Int32 length + Int32 protocol version (e.g., 196608 for 3.0)
        if len(payload) >= 8:
            length = struct.unpack('>I', payload[0:4])[0]
            if 8 <= length <= 10000 and len(payload) >= length:
                proto = struct.unpack('>I', payload[4:8])[0]
                if proto in (196608, 196608 + 1) or proto == 80877103:  # 3.0 or SSLRequest
                    return {'length': length, 'protocol': proto}
        return None

    def analyze_packet(self, pkt) -> Optional[Dict[str, Any]]:
        if not (self.is_postgres(pkt) and pkt.haslayer(Raw)):
            return None
        payload = bytes(pkt[Raw].load)
        res = {'type': 'data', 'details': {}}
        st = self.parse_startup(payload)
        if st:
            res['type'] = 'startup'
            res['details'] = st
        else:
            # Simple Query: 'Q' + length + query string
            if len(payload) > 5 and payload[0:1] == b'Q':
                res['type'] = 'query'
        return res

    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        stats = {'total_postgres': 0, 'startups': 0, 'queries': 0}
        for pkt in packets:
            res = self.analyze_packet(pkt)
            if not res:
                continue
            stats['total_postgres'] += 1
            if res['type'] == 'startup':
                stats['startups'] += 1
            elif res['type'] == 'query':
                stats['queries'] += 1
        return stats


def analyze_postgres_traffic(packets: List) -> Dict[str, Any]:
    return PostgresAnalyzer().analyze_traffic(packets)
