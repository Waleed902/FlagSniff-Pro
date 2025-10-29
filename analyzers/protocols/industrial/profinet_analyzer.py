"""
PROFINET Protocol Analyzer
Process Field Network - Siemens industrial Ethernet
"""

from typing import Dict, List, Any, Optional
from scapy.all import Ether, Raw
from collections import defaultdict
import struct


class PROFINETAnalyzer:
    """PROFINET industrial protocol analyzer"""
    
    # PROFINET frame IDs
    FRAME_IDS = {
        0x8000: "RT_CLASS_1",  # Real-time class 1
        0x8001: "RT_CLASS_2",  # Real-time class 2
        0xC000: "RT_CLASS_3",  # Real-time class 3 (IRT)
        0xFC01: "Alarm High",
        0xFE01: "Alarm Low",
        0xFF00: "DCP Identify Request",
        0xFF01: "DCP Identify Response"
    }
    
    DCP_SERVICE_IDS = {
        0x00: "Get",
        0x01: "Set",
        0x03: "Identify",
        0x04: "Hello"
    }
    
    def __init__(self):
        self.devices = defaultdict(dict)
        
    def is_profinet_packet(self, packet) -> bool:
        """Check if packet is PROFINET"""
        if not packet.haslayer(Ether):
            return False
            
        # PROFINET uses EtherType 0x8892
        ethertype = packet[Ether].type
        return ethertype == 0x8892
    
    def parse_profinet_header(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse PROFINET real-time header"""
        try:
            if len(data) < 4:
                return None
                
            frame_id = struct.unpack('>H', data[0:2])[0]
            
            result = {
                'frame_id': frame_id,
                'frame_type': self._classify_frame(frame_id)
            }
            
            # Parse DCP if it's a DCP frame
            if frame_id in [0xFF00, 0xFF01]:
                if len(data) >= 10:
                    service_id = data[2]
                    service_type = data[3]
                    result['dcp_service'] = self.DCP_SERVICE_IDS.get(service_id, 'Unknown')
                    result['dcp_type'] = 'Request' if service_type == 0 else 'Response'
            
            return result
        except:
            return None
    
    def _classify_frame(self, frame_id: int) -> str:
        """Classify PROFINET frame type"""
        if frame_id in self.FRAME_IDS:
            return self.FRAME_IDS[frame_id]
        elif 0x0000 <= frame_id < 0x0100:
            return "RT_CLASS_1"
        elif 0x8000 <= frame_id < 0xC000:
            return "RT_CLASS_2"
        elif 0xC000 <= frame_id < 0xFC00:
            return "RT_CLASS_3_IRT"
        elif 0xFC00 <= frame_id < 0xFF00:
            return "RTA"
        else:
            return "Unknown"
    
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze single PROFINET packet"""
        if not self.is_profinet_packet(packet):
            return None
            
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        
        payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b''
        header = self.parse_profinet_header(payload)
        
        if not header:
            return None
            
        result = {
            'src_mac': src_mac,
            'dst_mac': dst_mac,
            'frame_id': header['frame_id'],
            'frame_type': header['frame_type'],
            'is_real_time': 'RT_CLASS' in header['frame_type']
        }
        
        if 'dcp_service' in header:
            result['dcp_service'] = header['dcp_service']
            result['dcp_type'] = header['dcp_type']
        
        return result
    
    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        """Analyze PROFINET traffic patterns"""
        results = {
            'total_profinet': 0,
            'frame_distribution': defaultdict(int),
            'devices': set(),
            'real_time_traffic': 0,
            'dcp_messages': [],
            'suspicious_patterns': []
        }
        
        for packet in packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            results['total_profinet'] += 1
            results['frame_distribution'][analysis['frame_type']] += 1
            
            # Track devices
            results['devices'].add(analysis['src_mac'])
            results['devices'].add(analysis['dst_mac'])
            
            # Count real-time traffic
            if analysis['is_real_time']:
                results['real_time_traffic'] += 1
            
            # Track DCP messages
            if 'dcp_service' in analysis:
                results['dcp_messages'].append({
                    'service': analysis['dcp_service'],
                    'type': analysis['dcp_type'],
                    'src': analysis['src_mac']
                })
        
        # Convert sets/defaultdicts
        results['devices'] = list(results['devices'])
        results['frame_distribution'] = dict(results['frame_distribution'])
        
        # Security analysis
        results['security_analysis'] = self._security_analysis(results)
        
        return results
    
    def _security_analysis(self, results: Dict) -> Dict[str, Any]:
        """Perform security analysis"""
        analysis = {
            'total_devices': len(results['devices']),
            'real_time_percentage': (results['real_time_traffic'] / results['total_profinet'] * 100) 
                                   if results['total_profinet'] > 0 else 0,
            'dcp_activity': len(results['dcp_messages'])
        }
        
        risks = []
        if analysis['dcp_activity'] > 100:
            risks.append('High DCP activity (possible device enumeration)')
        if analysis['total_devices'] > 50:
            risks.append('Large number of devices detected')
        if analysis['real_time_percentage'] < 50 and results['total_profinet'] > 100:
            risks.append('Low real-time traffic ratio (unexpected for PROFINET)')
            
        analysis['identified_risks'] = risks
        return analysis


def analyze_profinet_traffic(packets: List) -> Dict[str, Any]:
    """Analyze PROFINET traffic"""
    analyzer = PROFINETAnalyzer()
    return analyzer.analyze_traffic(packets)
