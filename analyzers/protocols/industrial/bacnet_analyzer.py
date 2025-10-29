"""
BACnet Protocol Analyzer
Building Automation and Control Networks
"""

from typing import Dict, List, Any, Optional
from scapy.all import UDP, Raw
from collections import defaultdict
import struct


class BACnetAnalyzer:
    """BACnet building automation protocol analyzer"""
    
    BACNET_SERVICES = {
        0x00: "Acknowledge Alarm",
        0x01: "Confirmed COV Notification",
        0x04: "Get Alarm Summary",
        0x05: "Get Enrollment Summary",
        0x06: "Subscribe COV",
        0x0C: "Read Property",
        0x0E: "Read Property Multiple",
        0x0F: "Write Property",
        0x10: "Write Property Multiple",
        0x12: "Reinitialize Device",
        0x14: "Create Object",
        0x15: "Delete Object"
    }
    
    OBJECT_TYPES = {
        0: "Analog Input",
        1: "Analog Output",
        2: "Analog Value",
        3: "Binary Input",
        4: "Binary Output",
        5: "Binary Value",
        8: "Device",
        13: "Multi-state Input",
        14: "Multi-state Output",
        19: "Multi-state Value"
    }
    
    def __init__(self):
        self.devices = defaultdict(dict)
        
    def is_bacnet_packet(self, packet) -> bool:
        """Check if packet is BACnet"""
        if not packet.haslayer(UDP) or not packet.haslayer(Raw):
            return False
            
        # BACnet/IP typically on UDP port 47808 (0xBAC0)
        if packet[UDP].dport != 47808 and packet[UDP].sport != 47808:
            return False
            
        payload = bytes(packet[Raw].load)
        # BACnet/IP header: 0x81 (BVLC type)
        return len(payload) >= 4 and payload[0] == 0x81
    
    def parse_bacnet_header(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse BACnet header"""
        try:
            if len(data) < 4:
                return None
                
            bvlc_type = data[0]
            if bvlc_type != 0x81:  # BACnet/IP
                return None
                
            bvlc_function = data[1]
            bvlc_length = struct.unpack('>H', data[2:4])[0]
            
            # Parse NPDU if present
            npdu_version = data[4] if len(data) > 4 else None
            npdu_control = data[5] if len(data) > 5 else None
            
            return {
                'bvlc_function': bvlc_function,
                'bvlc_length': bvlc_length,
                'npdu_version': npdu_version,
                'has_destination': bool(npdu_control & 0x20) if npdu_control else False,
                'has_source': bool(npdu_control & 0x08) if npdu_control else False
            }
        except:
            return None
    
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze single BACnet packet"""
        if not self.is_bacnet_packet(packet):
            return None
            
        payload = bytes(packet[Raw].load)
        header = self.parse_bacnet_header(payload)
        
        if not header:
            return None
            
        result = {
            'src_ip': packet['IP'].src if packet.haslayer('IP') else 'N/A',
            'dst_ip': packet['IP'].dst if packet.haslayer('IP') else 'N/A',
            'src_port': packet[UDP].sport,
            'dst_port': packet[UDP].dport,
            'bvlc_function': header['bvlc_function'],
            'has_routing': header['has_destination'] or header['has_source']
        }
        
        return result
    
    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        """Analyze BACnet traffic patterns"""
        results = {
            'total_bacnet': 0,
            'function_distribution': defaultdict(int),
            'devices': set(),
            'broadcast_count': 0,
            'suspicious_patterns': []
        }
        
        for packet in packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            results['total_bacnet'] += 1
            results['function_distribution'][analysis['bvlc_function']] += 1
            
            # Track devices
            results['devices'].add(analysis['src_ip'])
            
            # Count broadcasts
            if analysis['dst_ip'].endswith('.255'):
                results['broadcast_count'] += 1
            
            # Detect excessive device discovery
            if analysis['bvlc_function'] == 0x08:  # Who-Is broadcast
                pass  # Normal discovery
        
        # Convert sets/defaultdicts
        results['devices'] = list(results['devices'])
        results['function_distribution'] = dict(results['function_distribution'])
        
        # Security analysis
        results['security_analysis'] = self._security_analysis(results)
        
        return results
    
    def _security_analysis(self, results: Dict) -> Dict[str, Any]:
        """Perform security analysis"""
        analysis = {
            'total_devices': len(results['devices']),
            'broadcast_ratio': results['broadcast_count'] / results['total_bacnet'] if results['total_bacnet'] > 0 else 0
        }
        
        risks = []
        if analysis['total_devices'] > 50:
            risks.append('Large number of BACnet devices detected')
        if analysis['broadcast_ratio'] > 0.5:
            risks.append('High broadcast traffic (possible scanning)')
            
        analysis['identified_risks'] = risks
        return analysis


def analyze_bacnet_traffic(packets: List) -> Dict[str, Any]:
    """Analyze BACnet building automation traffic"""
    analyzer = BACnetAnalyzer()
    return analyzer.analyze_traffic(packets)
