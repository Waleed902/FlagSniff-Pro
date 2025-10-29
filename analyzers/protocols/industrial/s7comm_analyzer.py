"""
S7comm Protocol Analyzer
Siemens S7 Communication - Used in Siemens PLCs
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw
from collections import defaultdict
import struct


class S7commAnalyzer:
    """Siemens S7comm protocol analyzer"""
    
    S7_FUNCTIONS = {
        0x04: "Read Var",
        0x05: "Write Var",
        0x00: "Job Request (CPU services)",
        0xF0: "Setup Communication",
        0x1A: "Request Download",
        0x1B: "Download Block",
        0x1C: "Download Ended",
        0x1D: "Start Upload",
        0x1E: "Upload",
        0x1F: "End Upload",
        0x28: "PI Service (Program Invocation)",
        0x29: "PLC Stop"
    }
    
    PARAMETER_TYPES = {
        0x10: "CPU functions",
        0x00: "Push/Pop",
        0x04: "Read Var",
        0x05: "Write Var"
    }
    
    def __init__(self):
        self.plc_operations = defaultdict(list)
        
    def is_s7comm_packet(self, packet) -> bool:
        """Check if packet is S7comm"""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return False
            
        # S7comm typically on TCP port 102
        if packet[TCP].sport != 102 and packet[TCP].dport != 102:
            return False
            
        payload = bytes(packet[Raw].load)
        # TPKT header: version 3, COTP follows
        return len(payload) >= 7 and payload[0] == 0x03 and payload[1] == 0x00
    
    def parse_s7_header(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse S7comm header"""
        try:
            # Skip TPKT (4 bytes) and COTP (3 bytes) headers
            if len(data) < 10:
                return None
                
            s7_offset = 7
            if len(data) < s7_offset + 10:
                return None
                
            protocol_id = data[s7_offset]
            if protocol_id != 0x32:  # S7 protocol ID
                return None
                
            msg_type = data[s7_offset + 1]
            pdu_ref = struct.unpack('>H', data[s7_offset + 4:s7_offset + 6])[0]
            param_length = struct.unpack('>H', data[s7_offset + 6:s7_offset + 8])[0]
            data_length = struct.unpack('>H', data[s7_offset + 8:s7_offset + 10])[0]
            
            # Parse function code from parameters if available
            function = None
            if param_length > 0 and len(data) > s7_offset + 10:
                function = data[s7_offset + 10]
            
            return {
                'msg_type': msg_type,
                'pdu_ref': pdu_ref,
                'param_length': param_length,
                'data_length': data_length,
                'function': function
            }
        except:
            return None
    
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze single S7comm packet"""
        if not self.is_s7comm_packet(packet):
            return None
            
        payload = bytes(packet[Raw].load)
        header = self.parse_s7_header(payload)
        
        if not header:
            return None
            
        result = {
            'src': f"{packet[TCP].sport}",
            'dst': f"{packet[TCP].dport}",
            'msg_type': 'Job' if header['msg_type'] == 0x01 else 'Ack_Data' if header['msg_type'] == 0x03 else 'Unknown',
            'pdu_ref': header['pdu_ref'],
            'function': self.S7_FUNCTIONS.get(header['function'], f"Unknown (0x{header['function']:02x})" if header['function'] else "N/A"),
            'has_data': header['data_length'] > 0
        }
        
        return result
    
    def analyze_traffic(self, packets: List) -> Dict[str, Any]:
        """Analyze S7comm traffic patterns"""
        results = {
            'total_s7comm': 0,
            'function_distribution': defaultdict(int),
            'plc_operations': [],
            'suspicious_patterns': []
        }
        
        for packet in packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            results['total_s7comm'] += 1
            results['function_distribution'][analysis['function']] += 1
            
            # Track PLC operations
            if analysis['function'] in ['Write Var', 'Download Block', 'PLC Stop']:
                results['plc_operations'].append({
                    'operation': analysis['function'],
                    'src': analysis['src'],
                    'dst': analysis['dst']
                })
            
            # Detect critical operations
            if analysis['function'] == 'PLC Stop':
                results['suspicious_patterns'].append({
                    'type': 'PLC Stop Command',
                    'severity': 'critical',
                    'details': f"PLC stop command detected from {analysis['src']}"
                })
            elif analysis['function'] == 'Download Block':
                results['suspicious_patterns'].append({
                    'type': 'PLC Program Download',
                    'severity': 'high',
                    'details': f"Program block download from {analysis['src']}"
                })
        
        # Convert defaultdicts
        results['function_distribution'] = dict(results['function_distribution'])
        
        # Security analysis
        results['security_analysis'] = self._security_analysis(results)
        
        return results
    
    def _security_analysis(self, results: Dict) -> Dict[str, Any]:
        """Perform security analysis"""
        analysis = {
            'write_operations': results['function_distribution'].get('Write Var', 0),
            'download_operations': results['function_distribution'].get('Download Block', 0),
            'stop_commands': results['function_distribution'].get('PLC Stop', 0),
            'total_critical_ops': len(results['plc_operations'])
        }
        
        risks = []
        if analysis['stop_commands'] > 0:
            risks.append('PLC stop commands detected (possible attack)')
        if analysis['download_operations'] > 0:
            risks.append('Program download detected (possible unauthorized modification)')
        if analysis['write_operations'] > 50:
            risks.append('High volume of write operations')
            
        analysis['identified_risks'] = risks
        return analysis


def analyze_s7comm_traffic(packets: List) -> Dict[str, Any]:
    """Analyze Siemens S7comm traffic"""
    analyzer = S7commAnalyzer()
    return analyzer.analyze_traffic(packets)
