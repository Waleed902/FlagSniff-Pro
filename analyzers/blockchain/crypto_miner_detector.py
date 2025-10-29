"""
Cryptocurrency Mining Traffic Detector
Detects mining pool connections and mining protocols
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw, DNS, DNSQR
from collections import defaultdict
import re


class CryptoMinerDetector:
    """Cryptocurrency mining traffic detector"""
    
    # Known mining pools and ports
    MINING_POOLS = [
        # Hostnames
        'pool.ntp.org', 'stratum', 'mining', 'pool', 'miner',
        'nicehash.com', 'minergate.com', 'slushpool.com',
        'f2pool.com', 'antpool.com', 'ethermine.org',
        'nanopool.org', 'sparkpool.com', '2miners.com',
        'hiveon.net', 'flexpool.io'
    ]
    
    MINING_PORTS = [
        3333, 3334, 3335, 3336,  # Stratum
        4444, 5555, 7777, 8888, 9999,  # Common mining ports
        14433, 14444,  # XMR/Monero
        20560, 20570,  # ZEC/Zcash
        3357,  # ETH
        5000, 5001  # Various
    ]
    
    # Stratum protocol patterns
    STRATUM_PATTERNS = [
        rb'"method"\s*:\s*"mining\.',
        rb'"method"\s*:\s*"eth_',
        rb'"jsonrpc"\s*:\s*"2\.0"',
        rb'"id"\s*:\s*\d+',
        rb'mining\.subscribe',
        rb'mining\.authorize',
        rb'mining\.submit',
        rb'eth_submitWork',
        rb'eth_getWork',
        rb'eth_submitHashrate'
    ]
    
    def __init__(self):
        self.mining_connections = defaultdict(list)
        self.dns_queries = []
        
    def is_mining_port(self, port: int) -> bool:
        """Check if port is commonly used for mining"""
        return port in self.MINING_PORTS
    
    def is_mining_pool_dns(self, dns_query: str) -> bool:
        """Check if DNS query is for a mining pool"""
        query_lower = dns_query.lower()
        return any(pool in query_lower for pool in self.MINING_POOLS)
    
    def is_stratum_packet(self, packet) -> bool:
        """Check if packet contains Stratum mining protocol"""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return False
            
        payload = bytes(packet[Raw].load)
        
        # Check for Stratum JSON-RPC patterns
        return any(re.search(pattern, payload) for pattern in self.STRATUM_PATTERNS)
    
    def parse_stratum_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse Stratum protocol message"""
        try:
            import json
            message = json.loads(data.decode('utf-8', errors='ignore'))
            
            return {
                'method': message.get('method', 'N/A'),
                'id': message.get('id', 'N/A'),
                'params': message.get('params', [])
            }
        except:
            return None
    
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze single packet for mining activity"""
        result = None
        
        # Check DNS queries for mining pools
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            if self.is_mining_pool_dns(query):
                result = {
                    'type': 'DNS_Mining_Pool',
                    'query': query,
                    'src': packet['IP'].src if packet.haslayer('IP') else 'N/A'
                }
        
        # Check for mining ports
        elif packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            if self.is_mining_port(sport) or self.is_mining_port(dport):
                result = {
                    'type': 'Mining_Port',
                    'src': f"{packet['IP'].src}:{sport}" if packet.haslayer('IP') else 'N/A',
                    'dst': f"{packet['IP'].dst}:{dport}" if packet.haslayer('IP') else 'N/A',
                    'mining_port': dport if self.is_mining_port(dport) else sport
                }
        
        # Check for Stratum protocol
        if packet.haslayer(TCP) and self.is_stratum_packet(packet):
            payload = bytes(packet[Raw].load)
            stratum_data = self.parse_stratum_message(payload)
            
            result = {
                'type': 'Stratum_Protocol',
                'src': f"{packet['IP'].src}:{packet[TCP].sport}" if packet.haslayer('IP') else 'N/A',
                'dst': f"{packet['IP'].dst}:{packet[TCP].dport}" if packet.haslayer('IP') else 'N/A',
                'method': stratum_data['method'] if stratum_data else 'N/A'
            }
        
        return result
    
    def detect_mining(self, packets: List) -> Dict[str, Any]:
        """Detect cryptocurrency mining activity"""
        results = {
            'total_mining_indicators': 0,
            'dns_mining_queries': [],
            'mining_port_connections': [],
            'stratum_connections': [],
            'mining_methods': defaultdict(int),
            'suspected_miners': set(),
            'severity': 'none'
        }
        
        for packet in packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            results['total_mining_indicators'] += 1
            
            if analysis['type'] == 'DNS_Mining_Pool':
                results['dns_mining_queries'].append({
                    'query': analysis['query'],
                    'src': analysis['src']
                })
                results['suspected_miners'].add(analysis['src'])
            
            elif analysis['type'] == 'Mining_Port':
                results['mining_port_connections'].append({
                    'src': analysis['src'],
                    'dst': analysis['dst'],
                    'port': analysis['mining_port']
                })
                src_ip = analysis['src'].split(':')[0]
                results['suspected_miners'].add(src_ip)
            
            elif analysis['type'] == 'Stratum_Protocol':
                results['stratum_connections'].append({
                    'src': analysis['src'],
                    'dst': analysis['dst'],
                    'method': analysis['method']
                })
                results['mining_methods'][analysis['method']] += 1
                src_ip = analysis['src'].split(':')[0]
                results['suspected_miners'].add(src_ip)
        
        # Convert sets/defaultdicts
        results['suspected_miners'] = list(results['suspected_miners'])
        results['mining_methods'] = dict(results['mining_methods'])
        
        # Determine severity
        if results['total_mining_indicators'] == 0:
            results['severity'] = 'none'
        elif results['total_mining_indicators'] < 10:
            results['severity'] = 'low'
        elif results['total_mining_indicators'] < 100:
            results['severity'] = 'medium'
        else:
            results['severity'] = 'high'
        
        # Analysis summary
        results['analysis'] = {
            'has_mining_activity': results['total_mining_indicators'] > 0,
            'dns_queries_count': len(results['dns_mining_queries']),
            'port_connections_count': len(results['mining_port_connections']),
            'stratum_connections_count': len(results['stratum_connections']),
            'unique_miners': len(results['suspected_miners'])
        }
        
        return results


def detect_crypto_mining(packets: List) -> Dict[str, Any]:
    """Detect cryptocurrency mining traffic"""
    detector = CryptoMinerDetector()
    return detector.detect_mining(packets)
