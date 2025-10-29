"""
ICMPv6 Analyzer
Neighbor Discovery, Router Advertisements, and ICMPv6 analysis
"""

from typing import Dict, List, Any, Optional
from scapy.all import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6ND_RS, ICMPv6EchoRequest, ICMPv6EchoReply
from collections import defaultdict


class ICMPv6Analyzer:
    """Comprehensive ICMPv6 analyzer"""
    
    ICMPV6_TYPES = {
        1: "Destination Unreachable",
        2: "Packet Too Big",
        3: "Time Exceeded",
        4: "Parameter Problem",
        128: "Echo Request",
        129: "Echo Reply",
        133: "Router Solicitation",
        134: "Router Advertisement",
        135: "Neighbor Solicitation",
        136: "Neighbor Advertisement",
        137: "Redirect Message"
    }
    
    def __init__(self):
        self.nd_cache = defaultdict(dict)  # Neighbor Discovery cache
        
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze single ICMPv6 packet"""
        if not packet.haslayer(IPv6):
            return None
            
        result = {
            'src': packet[IPv6].src,
            'dst': packet[IPv6].dst,
            'type': None,
            'details': {}
        }
        
        # Neighbor Discovery - Neighbor Solicitation
        if packet.haslayer(ICMPv6ND_NS):
            ns = packet[ICMPv6ND_NS]
            result['type'] = 'Neighbor Solicitation'
            result['details'] = {
                'target': ns.tgt,
                'purpose': 'Address resolution or reachability check'
            }
            
        # Neighbor Discovery - Neighbor Advertisement
        elif packet.haslayer(ICMPv6ND_NA):
            na = packet[ICMPv6ND_NA]
            result['type'] = 'Neighbor Advertisement'
            result['details'] = {
                'target': na.tgt,
                'router': na.R,
                'solicited': na.S,
                'override': na.O
            }
            
        # Router Advertisement
        elif packet.haslayer(ICMPv6ND_RA):
            ra = packet[ICMPv6ND_RA]
            result['type'] = 'Router Advertisement'
            result['details'] = {
                'hop_limit': ra.chlim,
                'managed': ra.M,  # DHCPv6 managed
                'other_config': ra.O,  # DHCPv6 other config
                'router_lifetime': ra.routerlifetime
            }
            
        # Router Solicitation
        elif packet.haslayer(ICMPv6ND_RS):
            result['type'] = 'Router Solicitation'
            result['details'] = {'purpose': 'Request for router advertisement'}
            
        # Echo Request/Reply
        elif packet.haslayer(ICMPv6EchoRequest):
            echo = packet[ICMPv6EchoRequest]
            result['type'] = 'Echo Request'
            result['details'] = {
                'id': echo.id,
                'seq': echo.seq
            }
            
        elif packet.haslayer(ICMPv6EchoReply):
            echo = packet[ICMPv6EchoReply]
            result['type'] = 'Echo Reply'
            result['details'] = {
                'id': echo.id,
                'seq': echo.seq
            }
            
        return result if result['type'] else None
    
    def analyze_icmpv6_traffic(self, packets: List) -> Dict[str, Any]:
        """Analyze ICMPv6 traffic patterns"""
        results = {
            'total_icmpv6': 0,
            'type_distribution': defaultdict(int),
            'neighbor_discovery': {
                'solicitations': [],
                'advertisements': [],
                'nd_mappings': {}
            },
            'router_discovery': {
                'routers': [],
                'solicitations': 0
            },
            'echo_traffic': {
                'requests': 0,
                'replies': 0
            },
            'suspicious_patterns': []
        }
        
        for packet in packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            results['total_icmpv6'] += 1
            msg_type = analysis['type']
            results['type_distribution'][msg_type] += 1
            
            # Track Neighbor Discovery
            if msg_type == 'Neighbor Solicitation':
                results['neighbor_discovery']['solicitations'].append({
                    'src': analysis['src'],
                    'target': analysis['details']['target']
                })
                
            elif msg_type == 'Neighbor Advertisement':
                results['neighbor_discovery']['advertisements'].append({
                    'src': analysis['src'],
                    'target': analysis['details']['target'],
                    'is_router': analysis['details']['router']
                })
                # Build ND cache
                target = analysis['details']['target']
                results['neighbor_discovery']['nd_mappings'][target] = analysis['src']
                
            # Track Router Discovery
            elif msg_type == 'Router Advertisement':
                results['router_discovery']['routers'].append({
                    'src': analysis['src'],
                    'lifetime': analysis['details']['router_lifetime'],
                    'managed': analysis['details']['managed'],
                    'other_config': analysis['details']['other_config']
                })
                
            elif msg_type == 'Router Solicitation':
                results['router_discovery']['solicitations'] += 1
                
            # Track Echo traffic
            elif msg_type == 'Echo Request':
                results['echo_traffic']['requests'] += 1
            elif msg_type == 'Echo Reply':
                results['echo_traffic']['replies'] += 1
        
        # Detect suspicious patterns
        results['suspicious_patterns'] = self._detect_suspicious_patterns(results)
        
        # Convert defaultdict
        results['type_distribution'] = dict(results['type_distribution'])
        
        return results
    
    def _detect_suspicious_patterns(self, results: Dict) -> List[Dict]:
        """Detect suspicious ICMPv6 patterns"""
        suspicious = []
        
        # Excessive Neighbor Solicitations (scanning)
        ns_count = len(results['neighbor_discovery']['solicitations'])
        if ns_count > 100:
            suspicious.append({
                'type': 'IPv6 Address Scanning',
                'severity': 'high',
                'description': f'{ns_count} neighbor solicitations detected (possible network scanning)'
            })
        
        # Rogue Router Advertisements
        ra_count = len(results['router_discovery']['routers'])
        if ra_count > 5:
            unique_routers = set(r['src'] for r in results['router_discovery']['routers'])
            if len(unique_routers) > 3:
                suspicious.append({
                    'type': 'Multiple Router Advertisements',
                    'severity': 'medium',
                    'description': f'{len(unique_routers)} different routers advertising (possible rogue RA attack)'
                })
        
        # Neighbor Discovery cache poisoning
        na_count = len(results['neighbor_discovery']['advertisements'])
        if na_count > 50:
            suspicious.append({
                'type': 'Excessive Neighbor Advertisements',
                'severity': 'medium',
                'description': f'{na_count} neighbor advertisements (possible ND cache poisoning)'
            })
        
        # Echo imbalance (possible tunneling)
        req = results['echo_traffic']['requests']
        rep = results['echo_traffic']['replies']
        if req > 0 and abs(req - rep) > req * 0.3:
            suspicious.append({
                'type': 'ICMPv6 Echo Imbalance',
                'severity': 'low',
                'description': f'Mismatch: {req} requests vs {rep} replies'
            })
        
        return suspicious


def analyze_icmpv6_packets(packets: List) -> Dict[str, Any]:
    """
    Analyze ICMPv6 traffic
    
    Args:
        packets: List of Scapy packets
        
    Returns:
        Dictionary with ICMPv6 analysis results
    """
    analyzer = ICMPv6Analyzer()
    return analyzer.analyze_icmpv6_traffic(packets)
