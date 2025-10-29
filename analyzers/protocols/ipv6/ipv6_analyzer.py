"""
IPv6 Protocol Analyzer
Comprehensive IPv6 header and extension header analysis
"""

import struct
from typing import Dict, List, Any, Optional
from scapy.all import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrRouting, IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop
from collections import defaultdict


class IPv6Analyzer:
    """Comprehensive IPv6 packet analyzer"""
    
    def __init__(self):
        self.ipv6_flows = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.extension_headers = defaultdict(int)
        
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze single IPv6 packet"""
        if not packet.haslayer(IPv6):
            return None
            
        ipv6 = packet[IPv6]
        
        result = {
            'version': ipv6.version,
            'traffic_class': ipv6.tc,
            'flow_label': ipv6.fl,
            'payload_length': ipv6.plen,
            'next_header': ipv6.nh,
            'hop_limit': ipv6.hlim,
            'src': ipv6.src,
            'dst': ipv6.dst,
            'extension_headers': [],
            'is_multicast': self._is_multicast(ipv6.dst),
            'is_link_local': self._is_link_local(ipv6.src) or self._is_link_local(ipv6.dst),
            'address_types': self._classify_addresses(ipv6.src, ipv6.dst)
        }
        
        # Parse extension headers
        current = packet
        while current:
            if current.haslayer(IPv6ExtHdrFragment):
                frag = current[IPv6ExtHdrFragment]
                result['extension_headers'].append({
                    'type': 'Fragment',
                    'next_header': frag.nh,
                    'offset': frag.offset,
                    'more_fragments': frag.m,
                    'id': frag.id
                })
                current = frag.payload
                
            elif current.haslayer(IPv6ExtHdrRouting):
                route = current[IPv6ExtHdrRouting]
                result['extension_headers'].append({
                    'type': 'Routing',
                    'routing_type': route.type,
                    'segments_left': route.segleft
                })
                current = route.payload
                
            elif current.haslayer(IPv6ExtHdrDestOpt):
                result['extension_headers'].append({'type': 'Destination Options'})
                current = current[IPv6ExtHdrDestOpt].payload
                
            elif current.haslayer(IPv6ExtHdrHopByHop):
                result['extension_headers'].append({'type': 'Hop-by-Hop Options'})
                current = current[IPv6ExtHdrHopByHop].payload
            else:
                break
                
        return result
    
    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        """Analyze IPv6 traffic patterns"""
        ipv6_packets = [p for p in packets if p.haslayer(IPv6)]
        
        if not ipv6_packets:
            return {'found': False, 'message': 'No IPv6 packets found'}
            
        results = {
            'total_packets': len(ipv6_packets),
            'unique_sources': set(),
            'unique_destinations': set(),
            'flow_distribution': defaultdict(int),
            'extension_header_usage': defaultdict(int),
            'multicast_traffic': 0,
            'link_local_traffic': 0,
            'address_types': defaultdict(int),
            'fragmentation_analysis': {
                'fragmented_packets': 0,
                'fragment_chains': defaultdict(list)
            },
            'routing_headers': [],
            'suspicious_patterns': []
        }
        
        for packet in ipv6_packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            # Track sources and destinations
            results['unique_sources'].add(analysis['src'])
            results['unique_destinations'].add(analysis['dst'])
            
            # Flow distribution
            flow_key = f"{analysis['src']} -> {analysis['dst']}"
            results['flow_distribution'][flow_key] += 1
            
            # Track multicast and link-local
            if analysis['is_multicast']:
                results['multicast_traffic'] += 1
            if analysis['is_link_local']:
                results['link_local_traffic'] += 1
                
            # Address types
            for addr_type in analysis['address_types']:
                results['address_types'][addr_type] += 1
                
            # Extension headers
            for ext_hdr in analysis['extension_headers']:
                ext_type = ext_hdr['type']
                results['extension_header_usage'][ext_type] += 1
                
                # Track fragmentation
                if ext_type == 'Fragment':
                    results['fragmentation_analysis']['fragmented_packets'] += 1
                    frag_id = ext_hdr['id']
                    results['fragmentation_analysis']['fragment_chains'][frag_id].append({
                        'offset': ext_hdr['offset'],
                        'more': ext_hdr['more_fragments']
                    })
                    
                # Track routing headers (potential security issue)
                if ext_type == 'Routing':
                    results['routing_headers'].append(ext_hdr)
                    if ext_hdr['routing_type'] == 0:  # Type 0 routing deprecated
                        results['suspicious_patterns'].append({
                            'type': 'Deprecated Routing Header Type 0',
                            'severity': 'high',
                            'description': 'Type 0 routing headers are deprecated due to security issues'
                        })
        
        # Detect suspicious patterns
        results.update(self._detect_suspicious_patterns(results))
        
        # Convert sets to lists for JSON serialization
        results['unique_sources'] = list(results['unique_sources'])
        results['unique_destinations'] = list(results['unique_destinations'])
        results['flow_distribution'] = dict(results['flow_distribution'])
        results['extension_header_usage'] = dict(results['extension_header_usage'])
        results['address_types'] = dict(results['address_types'])
        
        return results
    
    def _is_multicast(self, addr: str) -> bool:
        """Check if address is multicast (ff00::/8)"""
        return addr.lower().startswith('ff')
    
    def _is_link_local(self, addr: str) -> bool:
        """Check if address is link-local (fe80::/10)"""
        return addr.lower().startswith('fe8') or addr.lower().startswith('fe9') or \
               addr.lower().startswith('fea') or addr.lower().startswith('feb')
    
    def _classify_addresses(self, src: str, dst: str) -> List[str]:
        """Classify IPv6 address types"""
        types = []
        
        for addr in [src, dst]:
            addr_lower = addr.lower()
            
            if addr_lower == '::1':
                types.append('loopback')
            elif self._is_link_local(addr):
                types.append('link-local')
            elif self._is_multicast(addr):
                types.append('multicast')
            elif addr_lower.startswith('fc') or addr_lower.startswith('fd'):
                types.append('unique-local')
            elif addr_lower.startswith('2001:db8'):
                types.append('documentation')
            elif addr_lower.startswith('2001:'):
                types.append('global-unicast')
            elif addr_lower.startswith('::'):
                types.append('ipv4-mapped')
            else:
                types.append('global-unicast')
                
        return list(set(types))
    
    def _detect_suspicious_patterns(self, results: Dict) -> Dict[str, Any]:
        """Detect suspicious IPv6 patterns"""
        suspicious = {'suspicious_patterns': results.get('suspicious_patterns', [])}
        
        # Excessive extension headers (possible evasion)
        if results['extension_header_usage']:
            total_ext = sum(results['extension_header_usage'].values())
            if total_ext > results['total_packets'] * 0.5:
                suspicious['suspicious_patterns'].append({
                    'type': 'Excessive Extension Headers',
                    'severity': 'medium',
                    'description': f'{total_ext} extension headers in {results["total_packets"]} packets (possible evasion)'
                })
        
        # Fragmentation attack indicators
        frag_data = results['fragmentation_analysis']
        if frag_data['fragmented_packets'] > 10:
            # Check for overlapping fragments
            for frag_id, fragments in frag_data['fragment_chains'].items():
                if len(fragments) > 20:
                    suspicious['suspicious_patterns'].append({
                        'type': 'Excessive Fragmentation',
                        'severity': 'high',
                        'description': f'Fragment chain {frag_id} has {len(fragments)} fragments (possible attack)'
                    })
        
        # Many unique destinations (scanning)
        if len(results['unique_destinations']) > 100:
            suspicious['suspicious_patterns'].append({
                'type': 'IPv6 Network Scanning',
                'severity': 'medium',
                'description': f'{len(results["unique_destinations"])} unique destinations contacted'
            })
        
        return suspicious


def analyze_ipv6_traffic(packets: List) -> Dict[str, Any]:
    """
    Main function to analyze IPv6 traffic
    
    Args:
        packets: List of Scapy packets
        
    Returns:
        Dictionary with IPv6 analysis results
    """
    analyzer = IPv6Analyzer()
    return analyzer.analyze_traffic(packets)
