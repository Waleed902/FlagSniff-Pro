"""
Bitcoin P2P Protocol Analyzer
Detects and analyzes Bitcoin network traffic
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw
from collections import defaultdict
import struct
import hashlib


class BitcoinAnalyzer:
    """Bitcoin P2P protocol analyzer"""
    
    # Bitcoin magic bytes for different networks
    MAGIC_BYTES = {
        0xF9BEB4D9: "mainnet",
        0x0B110907: "testnet3",
        0xFABFB5DA: "regtest"
    }
    
    # Bitcoin P2P commands
    COMMANDS = {
        b'version': 'Version handshake',
        b'verack': 'Version acknowledgment',
        b'addr': 'IP Address broadcast',
        b'inv': 'Inventory vectors',
        b'getdata': 'Get data',
        b'notfound': 'Not found',
        b'getblocks': 'Get blocks',
        b'getheaders': 'Get headers',
        b'tx': 'Transaction',
        b'block': 'Block',
        b'headers': 'Block headers',
        b'getaddr': 'Get addresses',
        b'mempool': 'Request mempool',
        b'ping': 'Ping',
        b'pong': 'Pong',
        b'reject': 'Rejection',
        b'sendheaders': 'Send headers',
        b'feefilter': 'Fee filter',
        b'sendcmpct': 'Send compact blocks',
        b'cmpctblock': 'Compact block'
    }
    
    def __init__(self):
        self.nodes = defaultdict(dict)
        self.transactions = []
        
    def is_bitcoin_packet(self, packet) -> bool:
        """Check if packet is Bitcoin P2P"""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return False
            
        # Bitcoin typically uses port 8333 (mainnet)
        if packet[TCP].sport not in [8333, 18333, 18444] and \
           packet[TCP].dport not in [8333, 18333, 18444]:
            return False
            
        payload = bytes(packet[Raw].load)
        if len(payload) < 24:  # Minimum Bitcoin message header
            return False
            
        # Check magic bytes
        try:
            magic = struct.unpack('<I', payload[0:4])[0]
            return magic in self.MAGIC_BYTES
        except:
            return False
    
    def parse_bitcoin_header(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse Bitcoin P2P message header"""
        try:
            if len(data) < 24:
                return None
                
            magic = struct.unpack('<I', data[0:4])[0]
            command = data[4:16].rstrip(b'\x00')
            payload_size = struct.unpack('<I', data[16:20])[0]
            checksum = data[20:24]
            
            return {
                'network': self.MAGIC_BYTES.get(magic, 'unknown'),
                'command': command,
                'command_name': self.COMMANDS.get(command, command.decode('utf-8', errors='ignore')),
                'payload_size': payload_size,
                'checksum': checksum.hex()
            }
        except:
            return None
    
    def parse_version_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse Bitcoin version message"""
        try:
            if len(data) < 100:
                return None
                
            version = struct.unpack('<i', data[24:28])[0]
            services = struct.unpack('<Q', data[28:36])[0]
            timestamp = struct.unpack('<q', data[36:44])[0]
            
            return {
                'protocol_version': version,
                'services': services,
                'timestamp': timestamp
            }
        except:
            return None
    
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze single Bitcoin packet"""
        if not self.is_bitcoin_packet(packet):
            return None
            
        payload = bytes(packet[Raw].load)
        header = self.parse_bitcoin_header(payload)
        
        if not header:
            return None
            
        result = {
            'src': f"{packet['IP'].src}:{packet[TCP].sport}" if packet.haslayer('IP') else 'N/A',
            'dst': f"{packet['IP'].dst}:{packet[TCP].dport}" if packet.haslayer('IP') else 'N/A',
            'network': header['network'],
            'command': header['command_name'],
            'payload_size': header['payload_size']
        }
        
        # Parse specific messages
        if header['command'] == b'version':
            version_info = self.parse_version_message(payload)
            if version_info:
                result['version_info'] = version_info
        
        return result
    
    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        """Analyze Bitcoin P2P traffic"""
        results = {
            'total_bitcoin': 0,
            'command_distribution': defaultdict(int),
            'networks': set(),
            'nodes': set(),
            'transactions': 0,
            'blocks': 0,
            'suspicious_patterns': []
        }
        
        for packet in packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            results['total_bitcoin'] += 1
            results['command_distribution'][analysis['command']] += 1
            results['networks'].add(analysis['network'])
            
            # Track nodes
            results['nodes'].add(analysis['src'].split(':')[0])
            results['nodes'].add(analysis['dst'].split(':')[0])
            
            # Count transactions and blocks
            if analysis['command'] == 'Transaction':
                results['transactions'] += 1
            elif analysis['command'] == 'Block':
                results['blocks'] += 1
        
        # Convert sets/defaultdicts
        results['networks'] = list(results['networks'])
        results['nodes'] = list(results['nodes'])
        results['command_distribution'] = dict(results['command_distribution'])
        
        # Security analysis
        results['security_analysis'] = self._security_analysis(results)
        
        return results
    
    def _security_analysis(self, results: Dict) -> Dict[str, Any]:
        """Perform security analysis"""
        analysis = {
            'total_nodes': len(results['nodes']),
            'network_types': results['networks']
        }
        
        risks = []
        if 'testnet3' in results['networks'] or 'regtest' in results['networks']:
            risks.append('Non-mainnet Bitcoin traffic detected')
        if results['total_nodes'] > 50:
            risks.append('Large number of Bitcoin nodes (possible mining pool)')
        if results['transactions'] > 1000:
            risks.append('High transaction volume detected')
            
        analysis['identified_risks'] = risks
        return analysis


def analyze_bitcoin_traffic(packets: List) -> Dict[str, Any]:
    """Analyze Bitcoin P2P traffic"""
    analyzer = BitcoinAnalyzer()
    return analyzer.analyze_traffic(packets)
