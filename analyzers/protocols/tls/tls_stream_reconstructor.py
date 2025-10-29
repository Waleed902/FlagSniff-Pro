"""
TLS Stream Reconstruction
Reconstructs TLS sessions and extracts metadata even without decryption
"""

import struct
from typing import Dict, List, Any, Optional, Tuple, Set
from scapy.all import TCP, IP, Raw
from collections import defaultdict, OrderedDict
import binascii


class TLSStreamReconstructor:
    """Reconstruct and analyze TLS streams"""
    
    # TLS Content Types
    CONTENT_TYPES = {
        20: "ChangeCipherSpec",
        21: "Alert",
        22: "Handshake",
        23: "Application Data",
        24: "Heartbeat"
    }
    
    # TLS Handshake Types
    HANDSHAKE_TYPES = {
        0: "HelloRequest",
        1: "ClientHello",
        2: "ServerHello",
        11: "Certificate",
        12: "ServerKeyExchange",
        13: "CertificateRequest",
        14: "ServerHelloDone",
        15: "CertificateVerify",
        16: "ClientKeyExchange",
        20: "Finished"
    }
    
    # TLS Versions
    TLS_VERSIONS = {
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
        0x0300: "SSL 3.0"
    }
    
    def __init__(self):
        self.sessions = defaultdict(lambda: {
            'client_hello': None,
            'server_hello': None,
            'certificates': [],
            'handshake_messages': [],
            'app_data_records': [],
            'alerts': [],
            'metadata': {}
        })
        
    def reconstruct_stream(self, packets: List) -> Dict[str, Any]:
        """Reconstruct TLS streams from packets"""
        tls_packets = self._filter_tls_packets(packets)
        
        if not tls_packets:
            return {'found': False, 'message': 'No TLS packets found'}
            
        results = {
            'total_tls_packets': len(tls_packets),
            'sessions': {},
            'summary': {
                'total_sessions': 0,
                'completed_handshakes': 0,
                'cipher_suites': set(),
                'tls_versions': set(),
                'server_names': [],
                'certificates': []
            }
        }
        
        # Group packets by TCP stream
        streams = self._group_by_stream(tls_packets)
        
        # Process each stream
        for stream_id, stream_packets in streams.items():
            session_data = self._process_tls_session(stream_packets)
            if session_data:
                results['sessions'][stream_id] = session_data
                
                # Update summary
                if session_data.get('handshake_complete'):
                    results['summary']['completed_handshakes'] += 1
                    
                if 'cipher_suite' in session_data:
                    results['summary']['cipher_suites'].add(session_data['cipher_suite'])
                    
                if 'version' in session_data:
                    results['summary']['tls_versions'].add(session_data['version'])
                    
                if 'server_name' in session_data:
                    results['summary']['server_names'].append(session_data['server_name'])
                    
                if session_data.get('certificates'):
                    results['summary']['certificates'].extend(session_data['certificates'])
        
        results['summary']['total_sessions'] = len(results['sessions'])
        
        # Convert sets to lists for JSON serialization
        results['summary']['cipher_suites'] = list(results['summary']['cipher_suites'])
        results['summary']['tls_versions'] = list(results['summary']['tls_versions'])
        
        return results
    
    def _filter_tls_packets(self, packets: List) -> List:
        """Filter packets that contain TLS data"""
        tls_packets = []
        
        for packet in packets:
            if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
                continue
                
            tcp = packet[TCP]
            # Common TLS ports
            if tcp.dport in [443, 8443, 10443] or tcp.sport in [443, 8443, 10443]:
                payload = bytes(packet[Raw].load)
                # Check for TLS record header
                if self._is_tls_record(payload):
                    tls_packets.append(packet)
                    
        return tls_packets
    
    def _is_tls_record(self, data: bytes) -> bool:
        """Check if data starts with a TLS record header"""
        if len(data) < 5:
            return False
            
        content_type = data[0]
        version = struct.unpack('>H', data[1:3])[0]
        
        # Valid content types: 20-24
        # Valid versions: 0x0300-0x0304
        return (20 <= content_type <= 24 and 
                0x0300 <= version <= 0x0304)
    
    def _group_by_stream(self, packets: List) -> Dict[str, List]:
        """Group packets by TCP stream"""
        streams = defaultdict(list)
        
        for packet in packets:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                ip = packet[IP]
                tcp = packet[TCP]
                
                # Create stream identifier
                stream_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
                streams[stream_id].append(packet)
                
        return streams
    
    def _process_tls_session(self, packets: List) -> Optional[Dict[str, Any]]:
        """Process a single TLS session"""
        session = {
            'packets': len(packets),
            'handshake_messages': [],
            'app_data_size': 0,
            'handshake_complete': False,
            'records': []
        }
        
        for packet in packets:
            if not packet.haslayer(Raw):
                continue
                
            payload = bytes(packet[Raw].load)
            records = self._parse_tls_records(payload)
            
            for record in records:
                session['records'].append(record)
                
                # Process handshake messages
                if record['content_type'] == 22:  # Handshake
                    handshake_msg = self._parse_handshake(record.get('data', b''))
                    if handshake_msg:
                        session['handshake_messages'].append(handshake_msg)
                        
                        # Extract specific handshake data
                        if handshake_msg['type'] == 1:  # ClientHello
                            session.update(self._extract_client_hello(handshake_msg))
                        elif handshake_msg['type'] == 2:  # ServerHello
                            session.update(self._extract_server_hello(handshake_msg))
                        elif handshake_msg['type'] == 11:  # Certificate
                            cert_info = self._extract_certificate(handshake_msg)
                            if cert_info:
                                if 'certificates' not in session:
                                    session['certificates'] = []
                                session['certificates'].append(cert_info)
                        elif handshake_msg['type'] == 20:  # Finished
                            session['handshake_complete'] = True
                            
                # Count application data
                elif record['content_type'] == 23:  # Application Data
                    session['app_data_size'] += record.get('length', 0)
                    
                # Process alerts
                elif record['content_type'] == 21:  # Alert
                    alert = self._parse_alert(record.get('data', b''))
                    if alert:
                        if 'alerts' not in session:
                            session['alerts'] = []
                        session['alerts'].append(alert)
        
        return session if session['records'] else None
    
    def _parse_tls_records(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse TLS records from data"""
        records = []
        offset = 0
        
        while offset < len(data):
            if len(data) - offset < 5:
                break
                
            # Parse record header
            content_type = data[offset]
            version = struct.unpack('>H', data[offset+1:offset+3])[0]
            length = struct.unpack('>H', data[offset+3:offset+5])[0]
            
            if not (20 <= content_type <= 24):
                break
                
            record = {
                'content_type': content_type,
                'content_type_name': self.CONTENT_TYPES.get(content_type, f"Unknown ({content_type})"),
                'version': version,
                'version_name': self.TLS_VERSIONS.get(version, f"Unknown ({hex(version)})"),
                'length': length,
                'offset': offset
            }
            
            # Extract record data
            data_start = offset + 5
            data_end = data_start + length
            
            if data_end <= len(data):
                record['data'] = data[data_start:data_end]
                records.append(record)
                
            offset = data_end
            
        return records
    
    def _parse_handshake(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse TLS handshake message"""
        if len(data) < 4:
            return None
            
        msg_type = data[0]
        msg_length = struct.unpack('>I', b'\x00' + data[1:4])[0]
        
        handshake = {
            'type': msg_type,
            'type_name': self.HANDSHAKE_TYPES.get(msg_type, f"Unknown ({msg_type})"),
            'length': msg_length,
            'data': data[4:4+msg_length] if len(data) >= 4+msg_length else data[4:]
        }
        
        return handshake
    
    def _extract_client_hello(self, handshake: Dict[str, Any]) -> Dict[str, Any]:
        """Extract information from ClientHello"""
        data = handshake.get('data', b'')
        result = {}
        
        try:
            offset = 0
            
            # Version (2 bytes)
            if len(data) >= 2:
                version = struct.unpack('>H', data[offset:offset+2])[0]
                result['client_version'] = self.TLS_VERSIONS.get(version, f"Unknown ({hex(version)})")
                offset += 2
                
            # Random (32 bytes)
            offset += 32
            
            # Session ID
            if len(data) > offset:
                session_id_len = data[offset]
                offset += 1 + session_id_len
                
            # Cipher Suites
            if len(data) > offset + 1:
                cipher_suites_len = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                result['cipher_suites_count'] = cipher_suites_len // 2
                offset += cipher_suites_len
                
            # Compression Methods
            if len(data) > offset:
                compression_len = data[offset]
                offset += 1 + compression_len
                
            # Extensions (parse SNI)
            if len(data) > offset + 1:
                extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                sni = self._parse_sni_extension(data[offset:offset+extensions_len])
                if sni:
                    result['server_name'] = sni
                    
        except:
            pass
            
        return result
    
    def _extract_server_hello(self, handshake: Dict[str, Any]) -> Dict[str, Any]:
        """Extract information from ServerHello"""
        data = handshake.get('data', b'')
        result = {}
        
        try:
            offset = 0
            
            # Version (2 bytes)
            if len(data) >= 2:
                version = struct.unpack('>H', data[offset:offset+2])[0]
                result['version'] = self.TLS_VERSIONS.get(version, f"Unknown ({hex(version)})")
                offset += 2
                
            # Random (32 bytes)
            offset += 32
            
            # Session ID
            if len(data) > offset:
                session_id_len = data[offset]
                offset += 1 + session_id_len
                
            # Cipher Suite (2 bytes)
            if len(data) > offset + 1:
                cipher_suite = struct.unpack('>H', data[offset:offset+2])[0]
                result['cipher_suite'] = f"0x{cipher_suite:04X}"
                result['cipher_suite_name'] = self._get_cipher_suite_name(cipher_suite)
                
        except:
            pass
            
        return result
    
    def _extract_certificate(self, handshake: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract certificate information"""
        data = handshake.get('data', b'')
        
        try:
            if len(data) < 3:
                return None
                
            # Certificates length
            certs_len = struct.unpack('>I', b'\x00' + data[0:3])[0]
            offset = 3
            
            # Parse first certificate
            if len(data) > offset + 2:
                cert_len = struct.unpack('>I', b'\x00' + data[offset:offset+3])[0]
                offset += 3
                
                if len(data) >= offset + cert_len:
                    cert_data = data[offset:offset+cert_len]
                    
                    return {
                        'size': cert_len,
                        'data_preview': binascii.hexlify(cert_data[:100]).decode()
                    }
        except:
            pass
            
        return None
    
    def _parse_alert(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse TLS alert message"""
        if len(data) < 2:
            return None
            
        alert_level = data[0]
        alert_description = data[1]
        
        levels = {1: "Warning", 2: "Fatal"}
        
        return {
            'level': levels.get(alert_level, f"Unknown ({alert_level})"),
            'description': alert_description
        }
    
    def _parse_sni_extension(self, extensions_data: bytes) -> Optional[str]:
        """Parse Server Name Indication extension"""
        offset = 0
        
        while offset < len(extensions_data) - 3:
            try:
                ext_type = struct.unpack('>H', extensions_data[offset:offset+2])[0]
                ext_len = struct.unpack('>H', extensions_data[offset+2:offset+4])[0]
                offset += 4
                
                # SNI extension type is 0
                if ext_type == 0 and len(extensions_data) >= offset + ext_len:
                    ext_data = extensions_data[offset:offset+ext_len]
                    
                    # Parse server name list
                    if len(ext_data) > 5:
                        name_type = ext_data[2]
                        name_len = struct.unpack('>H', ext_data[3:5])[0]
                        
                        if name_type == 0 and len(ext_data) >= 5 + name_len:
                            server_name = ext_data[5:5+name_len].decode('utf-8', errors='ignore')
                            return server_name
                            
                offset += ext_len
            except:
                break
                
        return None
    
    def _get_cipher_suite_name(self, cipher_suite: int) -> str:
        """Get cipher suite name (basic mapping)"""
        # Common cipher suites
        suites = {
            0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
            0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
            0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0x1301: "TLS_AES_128_GCM_SHA256",
            0x1302: "TLS_AES_256_GCM_SHA384",
            0x1303: "TLS_CHACHA20_POLY1305_SHA256"
        }
        
        return suites.get(cipher_suite, f"Unknown (0x{cipher_suite:04X})")


def reconstruct_tls_streams(packets: List) -> Dict[str, Any]:
    """
    Reconstruct TLS streams from packet capture
    
    Args:
        packets: List of Scapy packets
        
    Returns:
        Dictionary with TLS stream analysis
    """
    reconstructor = TLSStreamReconstructor()
    results = reconstructor.reconstruct_stream(packets)
    
    # Add summary findings
    if results.get('sessions'):
        findings = []
        
        for stream_id, session in results['sessions'].items():
            if session.get('server_name'):
                findings.append({
                    'type': 'TLS Server Name',
                    'value': session['server_name'],
                    'stream': stream_id
                })
                
            if session.get('cipher_suite_name'):
                findings.append({
                    'type': 'Cipher Suite',
                    'value': session['cipher_suite_name'],
                    'stream': stream_id
                })
                
            if session.get('alerts'):
                for alert in session['alerts']:
                    findings.append({
                        'type': 'TLS Alert',
                        'level': alert['level'],
                        'description': alert['description'],
                        'stream': stream_id
                    })
        
        results['findings'] = findings
        
    return results
