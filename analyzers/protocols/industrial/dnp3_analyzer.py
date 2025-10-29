"""
DNP3 Protocol Analyzer
Distributed Network Protocol 3.0 - Common in electric/water utilities
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw
from collections import defaultdict
import struct


class DNP3Analyzer:
    """DNP3 SCADA protocol analyzer"""
    
    DNP3_FUNCTIONS = {
        0: "CONFIRM",
        1: "READ",
        2: "WRITE",
        3: "SELECT",
        4: "OPERATE",
        5: "DIRECT_OPERATE",
        6: "DIRECT_OPERATE_NR",
        13: "COLD_RESTART",
        14: "WARM_RESTART",
        23: "ENABLE_UNSOLICITED",
        24: "DISABLE_UNSOLICITED",
        129: "RESPONSE"
    }
    
    def __init__(self):
        self.sessions = defaultdict(list)
        
    def is_dnp3_packet(self, packet) -> bool:
        """Check if packet is DNP3"""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return False
            
        payload = bytes(packet[Raw].load)
        # DNP3 starts with 0x05 0x64
        return len(payload) >= 10 and payload[0] == 0x05 and payload[1] == 0x64
    
    def parse_dnp3_header(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DNP3 data link layer header"""
        if len(data) < 10:
            return None
            
        try:
            start = struct.unpack('BB', data[0:2])
            if start != (0x05, 0x64):
                return None
                
            length = data[2]
            control = data[3]
            destination = struct.unpack('<H', data[4:6])[0]
            source = struct.unpack('<H', data[6:8])[0]
            crc = struct.unpack('<H', data[8:10])[0]
            
            return {
                'length': length,
                'control': control,
                'destination': destination,
                'source': source,
                'direction': 'master_to_slave' if (control & 0x80) else 'slave_to_master',
                'fcb': bool(control & 0x20),  # Frame Count Bit
                'fcv': bool(control & 0x10),  # Frame Count Valid
                'function_code': control & 0x0F
            }
        except:
            return None
    
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze single DNP3 packet"""
        if not self.is_dnp3_packet(packet):
            return None
            
        payload = bytes(packet[Raw].load)
        header = self.parse_dnp3_header(payload)
        
        if not header:
            return None
            
        result = {
            'src': packet[TCP].sport,
            'dst': packet[TCP].dport,
            'dnp3_src': header['source'],
            'dnp3_dst': header['destination'],
            'direction': header['direction'],
            'function': self.DNP3_FUNCTIONS.get(header['function_code'], f"Unknown ({header['function_code']})"),
            'fcb': header['fcb'],
            'fcv': header['fcv']
        }
        
        return result
    
    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        """Analyze DNP3 traffic patterns"""
        results = {
            'total_dnp3': 0,
            'function_distribution': defaultdict(int),
            'communication_pairs': defaultdict(int),
            'devices': set(),
            'suspicious_patterns': []
        }
        
        for packet in packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            results['total_dnp3'] += 1
            results['function_distribution'][analysis['function']] += 1
            
            # Track device pairs
            pair = f"{analysis['dnp3_src']} -> {analysis['dnp3_dst']}"
            results['communication_pairs'][pair] += 1
            
            # Track unique devices
            results['devices'].add(analysis['dnp3_src'])
            results['devices'].add(analysis['dnp3_dst'])
            
            # Check for suspicious patterns
            if analysis['function'] in ['COLD_RESTART', 'WARM_RESTART']:
                results['suspicious_patterns'].append({
                    'type': 'Device Restart Command',
                    'severity': 'high',
                    'details': f"Restart command from {analysis['dnp3_src']} to {analysis['dnp3_dst']}"
                })
        
        # Convert sets/defaultdicts
        results['devices'] = list(results['devices'])
        results['function_distribution'] = dict(results['function_distribution'])
        results['communication_pairs'] = dict(results['communication_pairs'])
        
        # Additional security analysis
        results['security_analysis'] = self._security_analysis(results)
        
        return results
    
    def _security_analysis(self, results: Dict) -> Dict[str, Any]:
        """Perform security analysis on DNP3 traffic"""
        analysis = {
            'total_devices': len(results['devices']),
            'command_count': sum(
                count for func, count in results['function_distribution'].items()
                if func in ['OPERATE', 'DIRECT_OPERATE', 'WRITE']
            ),
            'restart_commands': results['function_distribution'].get('COLD_RESTART', 0) + 
                               results['function_distribution'].get('WARM_RESTART', 0)
        }
        
        # Risk assessment
        risks = []
        if analysis['restart_commands'] > 0:
            risks.append('Device restart commands detected')
        if analysis['command_count'] > 100:
            risks.append('High volume of control commands')
        if analysis['total_devices'] > 20:
            risks.append('Large number of devices (possible scanning)')
            
        analysis['identified_risks'] = risks
        return analysis


def analyze_dnp3_traffic(packets: List) -> Dict[str, Any]:
    """Analyze DNP3 SCADA traffic"""
    analyzer = DNP3Analyzer()
    return analyzer.analyze_traffic(packets)
