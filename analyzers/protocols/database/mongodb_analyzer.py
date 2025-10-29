"""
MongoDB Protocol Analyzer (heuristic)
Legacy wire opcodes + modern Msg flags; default port 27017
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw
import struct


class MongoDBAnalyzer:
    PORTS = {27017}

    OPCODES = {
        1: 'Update', 2001: 'Update',
        2002: 'Insert',
        2004: 'Query',
        2005: 'GetMore',
        2006: 'Delete',
        2010: 'Msg'
    }

    def is_mongo(self, pkt) -> bool:
        if not pkt.haslayer(TCP):
            return False
        return pkt[TCP].sport in self.PORTS or pkt[TCP].dport in self.PORTS

    def parse_header(self, payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) >= 16:
            length, req_id, resp_to, opcode = struct.unpack('<iiii', payload[0:16])
            if 16 <= length <= 10_000_000:
                return {'length': length, 'opcode': opcode, 'opcode_name': self.OPCODES.get(opcode, 'Unknown')}
        return None

    def analyze_packet(self, pkt) -> Optional[Dict[str, Any]]:
        if not (self.is_mongo(pkt) and pkt.haslayer(Raw)):
            return None
        payload = bytes(pkt[Raw].load)
        header = self.parse_header(payload)
        if not header:
            return None
        return {'type': 'mongo', 'details': header}

    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        stats = {'total_mongodb': 0, 'opcodes': {}}
        for pkt in packets:
            res = self.analyze_packet(pkt)
            if not res:
                continue
            stats['total_mongodb'] += 1
            name = res['details']['opcode_name']
            stats['opcodes'][name] = stats['opcodes'].get(name, 0) + 1
        return stats


def analyze_mongodb_traffic(packets: List) -> Dict[str, Any]:
    return MongoDBAnalyzer().analyze_traffic(packets)
