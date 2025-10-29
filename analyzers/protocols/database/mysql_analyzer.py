"""
MySQL Protocol Analyzer (heuristic)
Detects MySQL handshakes and queries on default ports
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw
from collections import defaultdict


class MySQLAnalyzer:
    """MySQL protocol analyzer based on packet heuristics"""

    PORTS = {3306}

    def is_mysql(self, pkt) -> bool:
        if not pkt.haslayer(TCP):
            return False
        return pkt[TCP].sport in self.PORTS or pkt[TCP].dport in self.PORTS

    def parse_handshake(self, payload: bytes) -> Optional[Dict[str, Any]]:
        # MySQL initial handshake packet typically starts with protocol version 0x0a
        if len(payload) > 5 and payload[4] == 0x0a:
            # Server version string starts at 5 until null byte
            try:
                end = payload.find(b'\x00', 5)
                server_ver = payload[5:end].decode('utf-8', errors='ignore') if end > 5 else 'unknown'
                return {'protocol': 10, 'server_version': server_ver}
            except:
                return {'protocol': 10, 'server_version': 'unknown'}
        return None

    def analyze_packet(self, pkt) -> Optional[Dict[str, Any]]:
        if not (self.is_mysql(pkt) and pkt.haslayer(Raw)):
            return None
        payload = bytes(pkt[Raw].load)
        result = {'type': 'data', 'details': {}}
        hs = self.parse_handshake(payload)
        if hs:
            result['type'] = 'handshake'
            result['details'] = hs
        else:
            # Heuristic query detection (contains SQL-like keywords)
            pl = payload.lower()
            if any(k in pl for k in [b'select', b'insert', b'update', b'delete', b'from', b'where', b'limit']):
                result['type'] = 'query'
        return result

    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        stats = {'total_mysql': 0, 'handshakes': 0, 'queries': 0}
        for pkt in packets:
            res = self.analyze_packet(pkt)
            if not res:
                continue
            stats['total_mysql'] += 1
            if res['type'] == 'handshake':
                stats['handshakes'] += 1
            elif res['type'] == 'query':
                stats['queries'] += 1
        return stats


def analyze_mysql_traffic(packets: List) -> Dict[str, Any]:
    return MySQLAnalyzer().analyze_traffic(packets)
