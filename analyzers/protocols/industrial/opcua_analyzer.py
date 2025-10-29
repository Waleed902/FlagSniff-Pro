"""
OPC UA Protocol Analyzer
Open Platform Communications Unified Architecture
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw
from collections import defaultdict
import struct


class OPCUAAnalyzer:
    """OPC UA industrial communication analyzer"""
    
    MESSAGE_TYPES = {
        b'HEL': 'Hello',
        b'ACK': 'Acknowledge',
        b'ERR': 'Error',
        b'OPN': 'Open Secure Channel',
        b'CLO': 'Close Secure Channel',
        b'MSG': 'Message'
    }
    
    SERVICE_TYPES = {
        0x01B5: "CreateSession",
        0x01B8: "ActivateSession",
        0x01BE: "CloseSession",
        0x027B: "Browse",
        0x027E: "BrowseNext",
        0x0235: "Read",
        0x02A1: "Write",
        0x02F6: "Call",
        0x0340: "CreateMonitoredItems",
        0x0343: "ModifyMonitoredItems",
        0x0346: "DeleteMonitoredItems"
    }
    
    def __init__(self):
        self.sessions = defaultdict(dict)
        
    def is_opcua_packet(self, packet) -> bool:
        """Check if packet is OPC UA"""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return False
            
        # OPC UA typically on TCP port 4840
        if packet[TCP].sport != 4840 and packet[TCP].dport != 4840:
            return False
            
        payload = bytes(packet[Raw].load)
        # Check for OPC UA message header
        if len(payload) < 8:
            return False
            
        msg_type = payload[0:3]
        return msg_type in self.MESSAGE_TYPES
    
    def parse_opcua_header(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse OPC UA header"""
        try:
            if len(data) < 8:
                return None
                
            msg_type = data[0:3]
            chunk_type = chr(data[3])
            message_size = struct.unpack('<I', data[4:8])[0]
            
            result = {
                'message_type': self.MESSAGE_TYPES.get(msg_type, 'Unknown'),
                'chunk_type': chunk_type,
                'message_size': message_size
            }
            
            # Parse secure channel ID for messages
            if len(data) >= 12 and msg_type in [b'OPN', b'MSG', b'CLO']:
                secure_channel_id = struct.unpack('<I', data[8:12])[0]
                result['secure_channel_id'] = secure_channel_id
            
            return result
        except:
            return None
    
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze single OPC UA packet"""
        if not self.is_opcua_packet(packet):
            return None
            
        payload = bytes(packet[Raw].load)
        header = self.parse_opcua_header(payload)
        
        if not header:
            return None
            
        result = {
            'src': f"{packet['IP'].src}:{packet[TCP].sport}" if packet.haslayer('IP') else 'N/A',
            'dst': f"{packet['IP'].dst}:{packet[TCP].dport}" if packet.haslayer('IP') else 'N/A',
            'message_type': header['message_type'],
            'chunk_type': header['chunk_type'],
            'message_size': header['message_size'],
            'secure_channel_id': header.get('secure_channel_id', 0)
        }
        
        return result
    
    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        """Analyze OPC UA traffic patterns"""
        results = {
            'total_opcua': 0,
            'message_distribution': defaultdict(int),
            'secure_channels': set(),
            'sessions': [],
            'suspicious_patterns': []
        }
        
        for packet in packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            results['total_opcua'] += 1
            results['message_distribution'][analysis['message_type']] += 1
            
            # Track secure channels
            if analysis['secure_channel_id'] > 0:
                results['secure_channels'].add(analysis['secure_channel_id'])
            
            # Track session establishment
            if analysis['message_type'] == 'Open Secure Channel':
                results['sessions'].append({
                    'type': 'SecureChannel',
                    'src': analysis['src'],
                    'dst': analysis['dst'],
                    'channel_id': analysis['secure_channel_id']
                })
        
        # Convert sets/defaultdicts
        results['secure_channels'] = list(results['secure_channels'])
        results['message_distribution'] = dict(results['message_distribution'])
        
        # Security analysis
        results['security_analysis'] = self._security_analysis(results)
        
        return results
    
    def _security_analysis(self, results: Dict) -> Dict[str, Any]:
        """Perform security analysis"""
        analysis = {
            'total_channels': len(results['secure_channels']),
            'session_count': len(results['sessions'])
        }
        
        risks = []
        if analysis['total_channels'] > 10:
            risks.append('Multiple secure channels (possible enumeration)')
        if results['message_distribution'].get('Error', 0) > results['total_opcua'] * 0.2:
            risks.append('High error rate detected')
            
        analysis['identified_risks'] = risks
        return analysis


def analyze_opcua_traffic(packets: List) -> Dict[str, Any]:
    """Analyze OPC UA traffic"""
    analyzer = OPCUAAnalyzer()
    return analyzer.analyze_traffic(packets)
