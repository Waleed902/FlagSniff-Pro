"""
IPv6 Tunneling Detection
Detects 6in4, 6to4, Teredo, ISATAP tunneling mechanisms
"""

from typing import Dict, List, Any, Optional
from scapy.all import IPv6, IP, UDP
from collections import defaultdict


class IPv6TunnelingDetector:
    """Detect IPv6 tunneling mechanisms"""
    
    TUNNEL_TYPES = {
        '6in4': 'IPv6 in IPv4 (Protocol 41)',
        '6to4': '6to4 Relay (2002::/16)',
        'teredo': 'Teredo (2001:0::/32)',
        'isatap': 'ISATAP (fe80::*:5efe:*)',
        '6rd': '6rd (ISP specific)',
        'ds-lite': 'DS-Lite (Dual-Stack Lite)'
    }
    
    def __init__(self):
        self.tunnel_stats = defaultdict(int)
        
    def detect_tunneling(self, packets: List) -> Dict[str, Any]:
        """Detect IPv6 tunneling in packet capture"""
        results = {
            'detected_tunnels': [],
            'tunnel_statistics': defaultdict(int),
            'tunnel_endpoints': defaultdict(list),
            'suspicious_tunnels': []
        }
        
        for packet in packets:
            # 6in4 detection (Protocol 41)
            if packet.haslayer(IP) and packet[IP].proto == 41:
                if packet.haslayer(IPv6):
                    results['detected_tunnels'].append({
                        'type': '6in4',
                        'description': 'IPv6-in-IPv4 tunnel (Protocol 41)',
                        'outer_src': packet[IP].src,
                        'outer_dst': packet[IP].dst,
                        'inner_src': packet[IPv6].src,
                        'inner_dst': packet[IPv6].dst
                    })
                    results['tunnel_statistics']['6in4'] += 1
                    results['tunnel_endpoints']['6in4'].append(
                        f"{packet[IP].src} -> {packet[IP].dst}"
                    )
            
            # 6to4 detection (2002::/16 prefix)
            if packet.haslayer(IPv6):
                ipv6_addr = packet[IPv6].src
                if ipv6_addr.startswith('2002:'):
                    # Extract embedded IPv4 address
                    embedded_ipv4 = self._extract_6to4_address(ipv6_addr)
                    results['detected_tunnels'].append({
                        'type': '6to4',
                        'description': '6to4 automatic tunnel',
                        'ipv6_address': ipv6_addr,
                        'embedded_ipv4': embedded_ipv4
                    })
                    results['tunnel_statistics']['6to4'] += 1
                    
            # Teredo detection (2001:0::/32 prefix and UDP port 3544)
            if packet.haslayer(IPv6) and packet.haslayer(UDP):
                ipv6_addr = packet[IPv6].src
                if ipv6_addr.startswith('2001:0:') or ipv6_addr.startswith('2001::'):
                    if packet[UDP].sport == 3544 or packet[UDP].dport == 3544:
                        results['detected_tunnels'].append({
                            'type': 'teredo',
                            'description': 'Teredo NAT traversal tunnel',
                            'ipv6_address': ipv6_addr,
                            'udp_port': packet[UDP].sport
                        })
                        results['tunnel_statistics']['teredo'] += 1
                        
            # ISATAP detection (fe80::*:5efe:* pattern)
            if packet.haslayer(IPv6):
                ipv6_addr = packet[IPv6].src.lower()
                if '5efe' in ipv6_addr and ipv6_addr.startswith('fe80::'):
                    results['detected_tunnels'].append({
                        'type': 'isatap',
                        'description': 'ISATAP intra-site tunnel',
                        'ipv6_address': packet[IPv6].src
                    })
                    results['tunnel_statistics']['isatap'] += 1
        
        # Analyze for suspicious patterns
        results['suspicious_tunnels'] = self._detect_suspicious_tunnels(results)
        
        # Convert defaultdicts
        results['tunnel_statistics'] = dict(results['tunnel_statistics'])
        results['tunnel_endpoints'] = dict(results['tunnel_endpoints'])
        
        results['summary'] = {
            'total_tunneled_packets': len(results['detected_tunnels']),
            'tunnel_types_found': list(results['tunnel_statistics'].keys()),
            'has_suspicious': len(results['suspicious_tunnels']) > 0
        }
        
        return results
    
    def _extract_6to4_address(self, ipv6_addr: str) -> str:
        """Extract embedded IPv4 address from 6to4 address"""
        try:
            parts = ipv6_addr.split(':')
            if len(parts) >= 3:
                hex1 = parts[1]
                hex2 = parts[2]
                # Convert hex to IPv4
                oct1 = int(hex1[:2], 16)
                oct2 = int(hex1[2:], 16)
                oct3 = int(hex2[:2], 16)
                oct4 = int(hex2[2:], 16)
                return f"{oct1}.{oct2}.{oct3}.{oct4}"
        except:
            pass
        return "unknown"
    
    def _detect_suspicious_tunnels(self, results: Dict) -> List[Dict]:
        """Detect suspicious tunneling patterns"""
        suspicious = []
        
        # Multiple tunnel types (possible evasion)
        if len(results['tunnel_statistics']) > 2:
            suspicious.append({
                'type': 'Multiple Tunnel Types',
                'severity': 'medium',
                'description': f'Multiple tunneling mechanisms detected: {list(results["tunnel_statistics"].keys())}'
            })
        
        # High volume of Teredo (often used for bypassing)
        if results['tunnel_statistics'].get('teredo', 0) > 50:
            suspicious.append({
                'type': 'High Teredo Usage',
                'severity': 'medium',
                'description': f'{results["tunnel_statistics"]["teredo"]} Teredo packets (often used to bypass firewalls)'
            })
        
        # 6in4 from unusual sources
        if '6in4' in results['tunnel_endpoints']:
            endpoints = set(results['tunnel_endpoints']['6in4'])
            if len(endpoints) > 10:
                suspicious.append({
                    'type': 'Multiple 6in4 Endpoints',
                    'severity': 'low',
                    'description': f'{len(endpoints)} different 6in4 tunnel endpoints'
                })
        
        return suspicious


def detect_ipv6_tunneling(packets: List) -> Dict[str, Any]:
    """
    Detect IPv6 tunneling mechanisms
    
    Args:
        packets: List of Scapy packets
        
    Returns:
        Dictionary with tunnel detection results
    """
    detector = IPv6TunnelingDetector()
    return detector.detect_tunneling(packets)
