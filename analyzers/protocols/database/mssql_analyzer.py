"""
Microsoft SQL Server (TDS) Analyzer (heuristic)
Detects TDS prelogin/login on default ports 1433
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw


class MSSQLAnalyzer:
    PORTS = {1433}

    def is_mssql(self, pkt) -> bool:
        if not pkt.haslayer(TCP):
            return False
        return pkt[TCP].sport in self.PORTS or pkt[TCP].dport in self.PORTS

    def parse_tds(self, payload: bytes) -> Optional[str]:
        # TDS packet header: 8 bytes; first byte is type (0x12 Prelogin, 0x10 SQL Batch, 0x11 RPC, 0x17 SSPI)
        if len(payload) >= 8:
            ptype = payload[0]
            if ptype == 0x12:
                return 'Prelogin'
            elif ptype == 0x10:
                return 'SQLBatch'
            elif ptype == 0x11:
                return 'RPC'
            elif ptype == 0x17:
                return 'SSPI'
        return None

    def analyze_packet(self, pkt) -> Optional[Dict[str, Any]]:
        if not (self.is_mssql(pkt) and pkt.haslayer(Raw)):
            return None
        payload = bytes(pkt[Raw].load)
        t = self.parse_tds(payload)
        if not t:
            return None
        return {'type': t}

    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        stats = {'total_mssql': 0, 'types': {}}
        for pkt in packets:
            res = self.analyze_packet(pkt)
            if not res:
                continue
            stats['total_mssql'] += 1
            t = res['type']
            stats['types'][t] = stats['types'].get(t, 0) + 1
        return stats


def analyze_mssql_traffic(packets: List) -> Dict[str, Any]:
    return MSSQLAnalyzer().analyze_traffic(packets)
