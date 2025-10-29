"""
ICMP Protocol Analyzer
Analyzes ICMP packets for tunneling, exfiltration, and covert channels
"""

import struct
import math
from typing import Dict, List, Any, Optional, Tuple, Set
from scapy.all import ICMP, IP, Raw, Ether
from collections import defaultdict
import re
import base64
import binascii


class ICMPAnalyzer:
    """Comprehensive ICMP packet analyzer"""
    
    def __init__(self):
        self.icmp_streams = defaultdict(list)
        self.icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp Request",
            14: "Timestamp Reply",
            15: "Information Request",
            16: "Information Reply",
            17: "Address Mask Request",
            18: "Address Mask Reply"
        }
        
    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze a single ICMP packet"""
        if not packet.haslayer(ICMP):
            return None
            
        icmp = packet[ICMP]
        ip = packet[IP] if packet.haslayer(IP) else None
        
        result = {
            'type': icmp.type,
            'type_name': self.icmp_types.get(icmp.type, f"Unknown ({icmp.type})"),
            'code': icmp.code,
            'checksum': icmp.chksum,
            'timestamp': packet.time if hasattr(packet, 'time') else None,
            'size': len(packet),
            'has_payload': packet.haslayer(Raw),
            'payload_size': len(packet[Raw].load) if packet.haslayer(Raw) else 0
        }
        
        if ip:
            result.update({
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'ttl': ip.ttl,
                'id': ip.id
            })
            
        # Extract payload if present
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            result['payload'] = payload
            result['payload_hex'] = binascii.hexlify(payload).decode()
            result['payload_entropy'] = self._calculate_entropy(payload)
            
            # Check for text data
            try:
                text = payload.decode('utf-8', errors='ignore')
                if self._is_printable(text):
                    result['payload_text'] = text
            except:
                pass
                
        # Analyze specific ICMP types
        if icmp.type == 8 or icmp.type == 0:  # Echo Request/Reply
            result['icmp_id'] = icmp.id if hasattr(icmp, 'id') else None
            result['icmp_seq'] = icmp.seq if hasattr(icmp, 'seq') else None
            
        return result
    
    def analyze_stream(self, packets: List) -> Dict[str, Any]:
        """Analyze ICMP traffic patterns across multiple packets"""
        icmp_packets = [p for p in packets if p.haslayer(ICMP)]
        
        if not icmp_packets:
            return {'found': False, 'message': 'No ICMP packets found'}
            
        results = {
            'total_packets': len(icmp_packets),
            'type_distribution': defaultdict(int),
            'conversations': defaultdict(lambda: {'request': 0, 'reply': 0, 'data_size': 0}),
            'suspicious_patterns': [],
            'payloads': [],
            'potential_tunneling': False,
            'potential_exfiltration': False
        }
        
        payload_sizes = []
        payload_contents = []
        
        for packet in icmp_packets:
            analysis = self.analyze_packet(packet)
            if not analysis:
                continue
                
            # Track type distribution
            results['type_distribution'][analysis['type_name']] += 1
            
            # Track conversations
            if 'src_ip' in analysis and 'dst_ip' in analysis:
                conv_key = f"{analysis['src_ip']} <-> {analysis['dst_ip']}"
                if analysis['type'] == 8:  # Echo Request
                    results['conversations'][conv_key]['request'] += 1
                elif analysis['type'] == 0:  # Echo Reply
                    results['conversations'][conv_key]['reply'] += 1
                results['conversations'][conv_key]['data_size'] += analysis.get('payload_size', 0)
                
            # Collect payloads
            if analysis['has_payload']:
                payload_sizes.append(analysis['payload_size'])
                payload_contents.append(analysis.get('payload', b''))
                
                payload_info = {
                    'size': analysis['payload_size'],
                    'entropy': analysis.get('payload_entropy', 0),
                    'hex': analysis.get('payload_hex', ''),
                    'timestamp': analysis.get('timestamp')
                }
                
                if 'payload_text' in analysis:
                    payload_info['text'] = analysis['payload_text']
                    
                results['payloads'].append(payload_info)
        
        # Analyze for suspicious patterns
        results.update(self._detect_suspicious_patterns(
            icmp_packets, payload_sizes, payload_contents
        ))
        
        # Convert defaultdicts to regular dicts for JSON serialization
        results['type_distribution'] = dict(results['type_distribution'])
        results['conversations'] = dict(results['conversations'])
        
        return results
    
    def _detect_suspicious_patterns(
        self, 
        packets: List, 
        payload_sizes: List[int], 
        payload_contents: List[bytes]
    ) -> Dict[str, Any]:
        """Detect suspicious ICMP patterns"""
        suspicious = {
            'suspicious_patterns': [],
            'potential_tunneling': False,
            'potential_exfiltration': False,
            'extracted_data': []
        }
        
        # Check for non-standard payload sizes
        if payload_sizes:
            avg_size = sum(payload_sizes) / len(payload_sizes)
            if avg_size > 56:  # Standard ping payload is 56 bytes
                suspicious['suspicious_patterns'].append({
                    'type': 'Large Payloads',
                    'description': f'Average payload size ({avg_size:.1f} bytes) exceeds standard ping size',
                    'severity': 'medium'
                })
                suspicious['potential_tunneling'] = True
        
        # Check for high entropy (encrypted/compressed data)
        high_entropy_count = 0
        for payload_info in suspicious.get('payloads', []):
            if payload_info.get('entropy', 0) > 7.0:
                high_entropy_count += 1
                
        if high_entropy_count > len(payload_sizes) * 0.5:
            suspicious['suspicious_patterns'].append({
                'type': 'High Entropy Payloads',
                'description': f'{high_entropy_count} payloads show high entropy (possible encryption)',
                'severity': 'high'
            })
            suspicious['potential_exfiltration'] = True
        
        # Check for sequential data patterns
        if len(payload_contents) >= 3:
            sequential = self._check_sequential_patterns(payload_contents)
            if sequential:
                suspicious['suspicious_patterns'].append({
                    'type': 'Sequential Data Pattern',
                    'description': 'ICMP payloads contain sequential data (possible file transfer)',
                    'severity': 'high'
                })
                suspicious['potential_exfiltration'] = True
                
                # Try to reconstruct the data
                reconstructed = b''.join(payload_contents)
                suspicious['extracted_data'].append({
                    'type': 'Reconstructed ICMP Stream',
                    'size': len(reconstructed),
                    'data': binascii.hexlify(reconstructed[:1000]).decode(),  # First 1KB
                    'preview': self._extract_preview(reconstructed)
                })
        
        # Check for encoded data patterns
        for i, payload in enumerate(payload_contents):
            if self._looks_like_base64(payload):
                try:
                    decoded = base64.b64decode(payload)
                    suspicious['extracted_data'].append({
                        'type': 'Base64 Decoded',
                        'packet_index': i,
                        'original_size': len(payload),
                        'decoded_size': len(decoded),
                        'preview': self._extract_preview(decoded)
                    })
                except:
                    pass
        
        return suspicious
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
            
        entropy = 0.0
        length = len(data)
        
        # Count byte frequencies
        frequencies = defaultdict(int)
        for byte in data:
            frequencies[byte] += 1
            
        # Calculate entropy using Shannon formula
        for count in frequencies.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
                
        return entropy
    
    def _is_printable(self, text: str, threshold: float = 0.8) -> bool:
        """Check if text is mostly printable characters"""
        if not text:
            return False
        printable_count = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        return (printable_count / len(text)) >= threshold
    
    def _check_sequential_patterns(self, payloads: List[bytes]) -> bool:
        """Check if payloads show sequential patterns"""
        if len(payloads) < 3:
            return False
            
        # Check if each payload shares data with the next
        sequential_count = 0
        for i in range(len(payloads) - 1):
            # Check for overlapping bytes or sequential patterns
            curr = payloads[i]
            next_payload = payloads[i + 1]
            
            if len(curr) > 0 and len(next_payload) > 0:
                # Check if they're part of a sequence
                if curr[-4:] == next_payload[:4] or abs(len(curr) - len(next_payload)) < 10:
                    sequential_count += 1
                    
        return sequential_count >= len(payloads) * 0.5
    
    def _looks_like_base64(self, data: bytes) -> bool:
        """Check if data looks like base64"""
        try:
            text = data.decode('ascii', errors='ignore')
            # Base64 uses A-Z, a-z, 0-9, +, /, =
            base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            valid_chars = sum(1 for c in text if c in base64_chars)
            return len(text) > 10 and (valid_chars / len(text)) > 0.9
        except:
            return False
    
    def _extract_preview(self, data: bytes, max_length: int = 200) -> str:
        """Extract a readable preview of data"""
        try:
            text = data[:max_length].decode('utf-8', errors='ignore')
            if self._is_printable(text, threshold=0.6):
                return text
        except:
            pass
        return f"<binary data, {len(data)} bytes>"


class ICMPTunnelDetector:
    """Detect ICMP tunneling and covert channels"""
    
    def __init__(self):
        self.analyzer = ICMPAnalyzer()
        
    def detect_tunneling(self, packets: List) -> Dict[str, Any]:
        """Detect potential ICMP tunneling"""
        analysis = self.analyzer.analyze_stream(packets)
        
        if not analysis.get('total_packets'):
            return {'detected': False, 'confidence': 0}
            
        indicators = []
        confidence_score = 0
        
        # High volume of ICMP traffic
        if analysis['total_packets'] > 100:
            indicators.append('High volume of ICMP packets')
            confidence_score += 20
            
        # Large payloads
        if analysis.get('potential_tunneling'):
            indicators.append('Non-standard payload sizes detected')
            confidence_score += 30
            
        # High entropy
        if analysis.get('potential_exfiltration'):
            indicators.append('High entropy payloads suggest encrypted data')
            confidence_score += 30
            
        # Sequential patterns
        if any('Sequential' in p.get('type', '') for p in analysis.get('suspicious_patterns', [])):
            indicators.append('Sequential data patterns detected')
            confidence_score += 20
            
        return {
            'detected': confidence_score >= 40,
            'confidence': min(confidence_score, 100),
            'indicators': indicators,
            'analysis': analysis
        }


def analyze_icmp_packets(packets: List) -> Dict[str, Any]:
    """
    Analyze ICMP packets in a capture
    
    Args:
        packets: List of Scapy packets
        
    Returns:
        Dictionary with analysis results
    """
    analyzer = ICMPAnalyzer()
    tunnel_detector = ICMPTunnelDetector()
    
    # Basic analysis
    analysis = analyzer.analyze_stream(packets)
    
    # Tunneling detection
    tunnel_results = tunnel_detector.detect_tunneling(packets)
    
    # Combine results
    results = {
        'icmp_analysis': analysis,
        'tunnel_detection': tunnel_results,
        'summary': {
            'total_icmp_packets': analysis.get('total_packets', 0),
            'suspicious': tunnel_results['detected'],
            'confidence': tunnel_results['confidence'],
            'key_findings': []
        }
    }
    
    # Add key findings
    if tunnel_results['detected']:
        results['summary']['key_findings'].append({
            'type': 'ICMP Tunneling Detected',
            'severity': 'high',
            'description': f"Confidence: {tunnel_results['confidence']}%",
            'indicators': tunnel_results['indicators']
        })
        
    if analysis.get('extracted_data'):
        results['summary']['key_findings'].append({
            'type': 'Data Extraction',
            'severity': 'medium',
            'description': f"Extracted {len(analysis['extracted_data'])} data segments from ICMP payloads"
        })
        
    return results
