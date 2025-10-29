"""
Redis Protocol Analyzer (RESP)
Detects Redis commands by RESP framing on default port 6379
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw


class RedisAnalyzer:
    PORTS = {6379}

    def is_redis(self, pkt) -> bool:
        if not pkt.haslayer(TCP):
            return False
        return pkt[TCP].sport in self.PORTS or pkt[TCP].dport in self.PORTS

    def parse_resp(self, payload: bytes) -> Optional[str]:
        # RESP starts with '*<num>\r\n$<len>\r\nCMD\r\n...'
        if not payload:
            return None
        first = payload[:1]
        if first in (b'*', b'+', b'-', b':', b'$'):
            # Heuristic: try to find first word (command)
            try:
                text = payload.decode('utf-8', errors='ignore')
                # Extract first upper-case token
                tokens = [t for t in text.replace('\r','\n').split('\n') if t]
                for t in tokens:
                    if t.isalpha():
                        return t.upper()
                # Fallback: last uppercase word
                words = text.split()
                for w in words:
                    if w.isalpha():
                        return w.upper()
            except:
                return None
        return None

    def analyze_packet(self, pkt) -> Optional[Dict[str, Any]]:
        if not (self.is_redis(pkt) and pkt.haslayer(Raw)):
            return None
        payload = bytes(pkt[Raw].load)
        cmd = self.parse_resp(payload)
        if not cmd:
            return None
        return {'type': 'command', 'command': cmd}

    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        stats = {'total_redis': 0, 'commands': {}}
        for pkt in packets:
            res = self.analyze_packet(pkt)
            if not res:
                continue
            stats['total_redis'] += 1
            cmd = res['command']
            stats['commands'][cmd] = stats['commands'].get(cmd, 0) + 1
        return stats


def analyze_redis_traffic(packets: List) -> Dict[str, Any]:
    return RedisAnalyzer().analyze_traffic(packets)
