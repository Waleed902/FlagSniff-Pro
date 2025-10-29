"""
Ethereum Protocol Analyzer
Detects and analyzes Ethereum network traffic (RPC, WebSocket, DevP2P)
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, UDP, Raw
from collections import defaultdict
import json
import struct


class EthereumAnalyzer:
    """Ethereum protocol analyzer"""
    
    # Ethereum DevP2P packet types
    DEVP2P_PACKETS = {
        0x00: "Hello",
        0x01: "Disconnect",
        0x02: "Ping",
        0x03: "Pong"
    }
    
    # Ethereum RPC methods
    RPC_METHODS = {
        'eth_blockNumber': 'Get block number',
        'eth_getBalance': 'Get balance',
        'eth_sendTransaction': 'Send transaction',
        'eth_sendRawTransaction': 'Send raw transaction',
        'eth_call': 'Call contract',
        'eth_getTransactionReceipt': 'Get transaction receipt',
        'eth_getTransactionByHash': 'Get transaction',
        'eth_getLogs': 'Get logs',
        'net_version': 'Get network version',
        'web3_clientVersion': 'Get client version'
    }
    
    def __init__(self):
        self.rpc_calls = []
        self.transactions = []
        
    def is_ethereum_rpc(self, packet) -> bool:
        """Check if packet is Ethereum JSON-RPC"""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return False
            
        # Ethereum RPC typically on 8545 or 8546
        if packet[TCP].sport not in [8545, 8546] and \
           packet[TCP].dport not in [8545, 8546]:
            return False
            
        payload = bytes(packet[Raw].load)
        try:
            # Try to parse as JSON
            data = json.loads(payload.decode('utf-8', errors='ignore'))
            return 'jsonrpc' in data or 'method' in data
        except:
            return False
    
    def is_ethereum_devp2p(self, packet) -> bool:
        """Check if packet is Ethereum DevP2P"""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return False
            
        # Ethereum P2P typically on 30303
        if packet[TCP].sport != 30303 and packet[TCP].dport != 30303:
            return False
            
        return True
    
    def parse_rpc_request(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse Ethereum JSON-RPC request"""
        try:
            rpc_data = json.loads(data.decode('utf-8'))
            return {
                'method': rpc_data.get('method', 'unknown'),
                'params': rpc_data.get('params', []),
                'id': rpc_data.get('id', None)
            }
        except:
            return None
    
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze single Ethereum packet"""
        result = None
        
        # Check for JSON-RPC
        if self.is_ethereum_rpc(packet):
            payload = bytes(packet[Raw].load)
            rpc_data = self.parse_rpc_request(payload)
            
            if rpc_data:
                result = {
                    'type': 'RPC',
                    'src': f"{packet['IP'].src}:{packet[TCP].sport}" if packet.haslayer('IP') else 'N/A',
                    'dst': f"{packet['IP'].dst}:{packet[TCP].dport}" if packet.haslayer('IP') else 'N/A',
                    'method': rpc_data['method'],
                    'method_description': self.RPC_METHODS.get(rpc_data['method'], 'Unknown'),
                    'has_params': len(rpc_data['params']) > 0
                }
                
                # Extract wallet addresses from transactions
                if rpc_data['method'] in ['eth_sendTransaction', 'eth_sendRawTransaction']:
                    if rpc_data['params']:
                        tx_data = rpc_data['params'][0] if isinstance(rpc_data['params'], list) else rpc_data['params']
                        if isinstance(tx_data, dict):
                            result['wallet_from'] = tx_data.get('from', 'N/A')
                            result['wallet_to'] = tx_data.get('to', 'N/A')
        
        # Check for DevP2P
        elif self.is_ethereum_devp2p(packet):
            result = {
                'type': 'DevP2P',
                'src': f"{packet['IP'].src}:{packet[TCP].sport}" if packet.haslayer('IP') else 'N/A',
                'dst': f"{packet['IP'].dst}:{packet[TCP].dport}" if packet.haslayer('IP') else 'N/A'
            }
        
        return result
    
    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        """Analyze Ethereum traffic"""
        results = {
            'total_ethereum': 0,
            'rpc_methods': defaultdict(int),
            'transactions': [],
            'wallets': set(),
            'devp2p_connections': 0,
            'suspicious_patterns': []
        }
        
        for packet in packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            results['total_ethereum'] += 1
            
            if analysis['type'] == 'RPC':
                results['rpc_methods'][analysis['method']] += 1
                
                # Track transactions
                if 'wallet_from' in analysis:
                    results['transactions'].append({
                        'from': analysis['wallet_from'],
                        'to': analysis['wallet_to']
                    })
                    results['wallets'].add(analysis['wallet_from'])
                    results['wallets'].add(analysis['wallet_to'])
            
            elif analysis['type'] == 'DevP2P':
                results['devp2p_connections'] += 1
        
        # Convert sets/defaultdicts
        results['wallets'] = list(results['wallets'])
        results['rpc_methods'] = dict(results['rpc_methods'])
        
        # Security analysis
        results['security_analysis'] = self._security_analysis(results)
        
        return results
    
    def _security_analysis(self, results: Dict) -> Dict[str, Any]:
        """Perform security analysis"""
        analysis = {
            'transaction_count': len(results['transactions']),
            'unique_wallets': len(results['wallets']),
            'rpc_call_count': sum(results['rpc_methods'].values())
        }
        
        risks = []
        if analysis['transaction_count'] > 100:
            risks.append('High transaction volume detected')
        if results['rpc_methods'].get('eth_sendRawTransaction', 0) > 50:
            risks.append('High number of raw transactions (possible automated trading)')
        if analysis['rpc_call_count'] > 1000:
            risks.append('Very high RPC activity detected')
            
        analysis['identified_risks'] = risks
        return analysis


def analyze_ethereum_traffic(packets: List) -> Dict[str, Any]:
    """Analyze Ethereum traffic"""
    analyzer = EthereumAnalyzer()
    return analyzer.analyze_traffic(packets)
