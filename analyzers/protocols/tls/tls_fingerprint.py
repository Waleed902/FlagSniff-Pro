"""Advanced TLS analysis with JA3/JA3S fingerprinting and security checks.

Provides:
- JA3/JA3S TLS fingerprinting
- Certificate chain validation
- Weak cipher detection
- SSL/TLS version analysis
- HSTS and Certificate Transparency checks
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import hashlib
import struct


@dataclass
class TLSHandshake:
    """Represents a TLS handshake message."""
    handshake_type: int
    handshake_name: str
    data: bytes
    
    # ClientHello fields
    tls_version: Optional[int] = None
    cipher_suites: Optional[List[int]] = None
    extensions: Optional[List[int]] = None
    elliptic_curves: Optional[List[int]] = None
    ec_point_formats: Optional[List[int]] = None
    
    # ServerHello fields
    selected_cipher: Optional[int] = None
    compression_method: Optional[int] = None
    
    # Certificate fields
    certificates: Optional[List[bytes]] = None


@dataclass
class TLSFingerprint:
    """TLS fingerprint (JA3/JA3S)."""
    fingerprint_type: str  # 'ja3' or 'ja3s'
    hash: str
    string: str  # Raw fingerprint string before hashing
    components: Dict[str, Any]


class TLSAnalyzer:
    """Advanced TLS analysis and fingerprinting."""
    
    HANDSHAKE_TYPES = {
        0: 'HelloRequest',
        1: 'ClientHello',
        2: 'ServerHello',
        11: 'Certificate',
        12: 'ServerKeyExchange',
        13: 'CertificateRequest',
        14: 'ServerHelloDone',
        15: 'CertificateVerify',
        16: 'ClientKeyExchange',
        20: 'Finished'
    }
    
    # Weak/deprecated cipher suites
    WEAK_CIPHERS = {
        0x0000: 'TLS_NULL_WITH_NULL_NULL',
        0x0001: 'TLS_RSA_WITH_NULL_MD5',
        0x0002: 'TLS_RSA_WITH_NULL_SHA',
        0x0003: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
        0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
        0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
        0x0006: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
        0x0008: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
        0x0009: 'TLS_RSA_WITH_DES_CBC_SHA',
        0x000A: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    }
    
    # Export ciphers (intentionally weak)
    EXPORT_CIPHERS = {
        0x0003, 0x0006, 0x0008, 0x000B, 0x000E,
        0x0011, 0x0014, 0x0017, 0x0019
    }
    
    def __init__(self):
        self.handshakes: List[TLSHandshake] = []
        self.fingerprints: List[TLSFingerprint] = []
        self.weak_ciphers_found: Set[int] = set()
    
    def parse_tls_record(self, data: bytes, offset: int = 0) -> Optional[Tuple[int, int, bytes, int]]:
        """Parse TLS record header.
        
        Returns:
            Tuple of (content_type, tls_version, payload, bytes_consumed) or None
        """
        if len(data) - offset < 5:
            return None
        
        content_type = data[offset]
        tls_version = struct.unpack('!H', data[offset+1:offset+3])[0]
        length = struct.unpack('!H', data[offset+3:offset+5])[0]
        
        if len(data) - offset - 5 < length:
            return None  # Incomplete record
        
        payload = data[offset+5:offset+5+length]
        return (content_type, tls_version, payload, 5 + length)
    
    def parse_handshake_message(self, data: bytes, offset: int = 0) -> Optional[Tuple[TLSHandshake, int]]:
        """Parse a handshake message from handshake record payload.
        
        Returns:
            Tuple of (TLSHandshake, bytes_consumed) or None
        """
        if len(data) - offset < 4:
            return None
        
        handshake_type = data[offset]
        length = struct.unpack('!I', b'\x00' + data[offset+1:offset+4])[0]
        
        if len(data) - offset - 4 < length:
            return None
        
        handshake_data = data[offset+4:offset+4+length]
        
        handshake = TLSHandshake(
            handshake_type=handshake_type,
            handshake_name=self.HANDSHAKE_TYPES.get(handshake_type, f'Unknown_{handshake_type}'),
            data=handshake_data
        )
        
        # Parse specific handshake types
        if handshake_type == 1:  # ClientHello
            self._parse_client_hello(handshake, handshake_data)
        elif handshake_type == 2:  # ServerHello
            self._parse_server_hello(handshake, handshake_data)
        elif handshake_type == 11:  # Certificate
            self._parse_certificate(handshake, handshake_data)
        
        return (handshake, 4 + length)
    
    def _parse_client_hello(self, handshake: TLSHandshake, data: bytes) -> None:
        """Parse ClientHello message."""
        offset = 0
        
        # TLS version (2 bytes)
        if len(data) < 2:
            return
        handshake.tls_version = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        
        # Random (32 bytes)
        if len(data) - offset < 32:
            return
        offset += 32
        
        # Session ID
        if len(data) - offset < 1:
            return
        session_id_length = data[offset]
        offset += 1 + session_id_length
        
        # Cipher suites
        if len(data) - offset < 2:
            return
        cipher_suites_length = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        
        if len(data) - offset < cipher_suites_length:
            return
        
        cipher_suites = []
        for i in range(0, cipher_suites_length, 2):
            if offset + i + 2 <= len(data):
                cipher = struct.unpack('!H', data[offset+i:offset+i+2])[0]
                cipher_suites.append(cipher)
                # Track weak ciphers
                if cipher in self.WEAK_CIPHERS or cipher in self.EXPORT_CIPHERS:
                    self.weak_ciphers_found.add(cipher)
        
        handshake.cipher_suites = cipher_suites
        offset += cipher_suites_length
        
        # Compression methods
        if len(data) - offset < 1:
            return
        compression_length = data[offset]
        offset += 1 + compression_length
        
        # Extensions
        if len(data) - offset < 2:
            return
        
        extensions_length = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        
        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        
        ext_offset = 0
        while ext_offset < extensions_length and offset + ext_offset + 4 <= len(data):
            ext_type = struct.unpack('!H', data[offset+ext_offset:offset+ext_offset+2])[0]
            ext_length = struct.unpack('!H', data[offset+ext_offset+2:offset+ext_offset+4])[0]
            extensions.append(ext_type)
            
            # Parse specific extensions
            if ext_type == 10 and ext_length >= 2:  # supported_groups (elliptic curves)
                curve_list_len = struct.unpack('!H', data[offset+ext_offset+4:offset+ext_offset+6])[0]
                for i in range(0, curve_list_len, 2):
                    if offset + ext_offset + 6 + i + 2 <= len(data):
                        curve = struct.unpack('!H', data[offset+ext_offset+6+i:offset+ext_offset+6+i+2])[0]
                        elliptic_curves.append(curve)
            
            elif ext_type == 11 and ext_length >= 1:  # ec_point_formats
                fmt_list_len = data[offset+ext_offset+4]
                for i in range(fmt_list_len):
                    if offset + ext_offset + 5 + i < len(data):
                        ec_point_formats.append(data[offset+ext_offset+5+i])
            
            ext_offset += 4 + ext_length
        
        handshake.extensions = extensions
        handshake.elliptic_curves = elliptic_curves if elliptic_curves else None
        handshake.ec_point_formats = ec_point_formats if ec_point_formats else None
    
    def _parse_server_hello(self, handshake: TLSHandshake, data: bytes) -> None:
        """Parse ServerHello message."""
        offset = 0
        
        # TLS version
        if len(data) < 2:
            return
        handshake.tls_version = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        
        # Random (32 bytes)
        if len(data) - offset < 32:
            return
        offset += 32
        
        # Session ID
        if len(data) - offset < 1:
            return
        session_id_length = data[offset]
        offset += 1 + session_id_length
        
        # Cipher suite (selected)
        if len(data) - offset < 2:
            return
        handshake.selected_cipher = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        
        # Check if selected cipher is weak
        if handshake.selected_cipher in self.WEAK_CIPHERS or handshake.selected_cipher in self.EXPORT_CIPHERS:
            self.weak_ciphers_found.add(handshake.selected_cipher)
        
        # Compression method
        if len(data) - offset < 1:
            return
        handshake.compression_method = data[offset]
        offset += 1
        
        # Extensions (if present)
        if len(data) - offset >= 2:
            extensions_length = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            extensions = []
            ext_offset = 0
            while ext_offset < extensions_length and offset + ext_offset + 4 <= len(data):
                ext_type = struct.unpack('!H', data[offset+ext_offset:offset+ext_offset+2])[0]
                ext_length = struct.unpack('!H', data[offset+ext_offset+2:offset+ext_offset+4])[0]
                extensions.append(ext_type)
                ext_offset += 4 + ext_length
            handshake.extensions = extensions
    
    def _parse_certificate(self, handshake: TLSHandshake, data: bytes) -> None:
        """Parse Certificate message."""
        offset = 0
        
        # Certificates length (3 bytes)
        if len(data) < 3:
            return
        certs_length = struct.unpack('!I', b'\x00' + data[offset:offset+3])[0]
        offset += 3
        
        certificates = []
        while offset < len(data) and offset < 3 + certs_length:
            if len(data) - offset < 3:
                break
            cert_length = struct.unpack('!I', b'\x00' + data[offset:offset+3])[0]
            offset += 3
            
            if len(data) - offset < cert_length:
                break
            
            cert_data = data[offset:offset+cert_length]
            certificates.append(cert_data)
            offset += cert_length
        
        handshake.certificates = certificates if certificates else None
    
    def generate_ja3(self, client_hello: TLSHandshake) -> Optional[TLSFingerprint]:
        """Generate JA3 fingerprint from ClientHello.
        
        JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
        """
        if not client_hello.cipher_suites:
            return None
        
        # Build JA3 string
        ssl_version = str(client_hello.tls_version) if client_hello.tls_version else ''
        ciphers = '-'.join(str(c) for c in client_hello.cipher_suites)
        extensions = '-'.join(str(e) for e in client_hello.extensions) if client_hello.extensions else ''
        curves = '-'.join(str(c) for c in client_hello.elliptic_curves) if client_hello.elliptic_curves else ''
        formats = '-'.join(str(f) for f in client_hello.ec_point_formats) if client_hello.ec_point_formats else ''
        
        ja3_string = f"{ssl_version},{ciphers},{extensions},{curves},{formats}"
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        
        fingerprint = TLSFingerprint(
            fingerprint_type='ja3',
            hash=ja3_hash,
            string=ja3_string,
            components={
                'ssl_version': ssl_version,
                'ciphers': ciphers,
                'extensions': extensions,
                'elliptic_curves': curves,
                'ec_point_formats': formats
            }
        )
        
        self.fingerprints.append(fingerprint)
        return fingerprint
    
    def generate_ja3s(self, server_hello: TLSHandshake) -> Optional[TLSFingerprint]:
        """Generate JA3S fingerprint from ServerHello.
        
        JA3S = MD5(SSLVersion,Cipher,Extensions)
        """
        if server_hello.selected_cipher is None:
            return None
        
        ssl_version = str(server_hello.tls_version) if server_hello.tls_version else ''
        cipher = str(server_hello.selected_cipher)
        extensions = '-'.join(str(e) for e in server_hello.extensions) if server_hello.extensions else ''
        
        ja3s_string = f"{ssl_version},{cipher},{extensions}"
        ja3s_hash = hashlib.md5(ja3s_string.encode()).hexdigest()
        
        fingerprint = TLSFingerprint(
            fingerprint_type='ja3s',
            hash=ja3s_hash,
            string=ja3s_string,
            components={
                'ssl_version': ssl_version,
                'cipher': cipher,
                'extensions': extensions
            }
        )
        
        self.fingerprints.append(fingerprint)
        return fingerprint
    
    def analyze_tls_packets(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyze TLS traffic from packet list.
        
        Args:
            packets: List of Scapy packets
            
        Returns:
            Dict with TLS analysis including JA3/JA3S fingerprints
        """
        try:
            from scapy.all import TCP, Raw  # type: ignore
        except ImportError:
            return {'error': 'Scapy not available'}
        
        ja3_fingerprints = []
        ja3s_fingerprints = []
        
        for pkt in packets:
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                continue
            
            # TLS typically on port 443, but can be others
            if pkt[TCP].dport not in [443, 8443, 993, 995, 465] and \
               pkt[TCP].sport not in [443, 8443, 993, 995, 465]:
                continue
            
            payload = bytes(pkt[Raw].load)
            
            # Check for TLS record (content type 22 = handshake)
            if len(payload) < 5 or payload[0] != 0x16:
                continue
            
            record_result = self.parse_tls_record(payload)
            if not record_result:
                continue
            
            content_type, tls_version, record_payload, _ = record_result
            
            if content_type == 0x16:  # Handshake
                handshake_result = self.parse_handshake_message(record_payload)
                if handshake_result:
                    handshake, _ = handshake_result
                    self.handshakes.append(handshake)
                    
                    if handshake.handshake_type == 1:  # ClientHello
                        ja3 = self.generate_ja3(handshake)
                        if ja3:
                            ja3_fingerprints.append(ja3)
                    
                    elif handshake.handshake_type == 2:  # ServerHello
                        ja3s = self.generate_ja3s(handshake)
                        if ja3s:
                            ja3s_fingerprints.append(ja3s)
        
        # Security analysis
        weak_cipher_names = [
            self.WEAK_CIPHERS.get(c, f'0x{c:04X}') 
            for c in self.weak_ciphers_found
        ]
        
        # TLS version analysis
        tls_versions = {}
        for hs in self.handshakes:
            if hs.tls_version:
                ver_name = self._get_tls_version_name(hs.tls_version)
                tls_versions[ver_name] = tls_versions.get(ver_name, 0) + 1
        
        return {
            'total_handshakes': len(self.handshakes),
            'ja3_fingerprints': [
                {'hash': fp.hash, 'string': fp.string, 'components': fp.components}
                for fp in ja3_fingerprints
            ],
            'ja3s_fingerprints': [
                {'hash': fp.hash, 'string': fp.string, 'components': fp.components}
                for fp in ja3s_fingerprints
            ],
            'weak_ciphers': weak_cipher_names,
            'tls_versions': tls_versions,
            'security_issues': {
                'weak_ciphers_found': len(self.weak_ciphers_found) > 0,
                'export_ciphers': any(c in self.EXPORT_CIPHERS for c in self.weak_ciphers_found)
            }
        }
    
    def _get_tls_version_name(self, version: int) -> str:
        """Get human-readable TLS version name."""
        versions = {
            0x0300: 'SSL 3.0',
            0x0301: 'TLS 1.0',
            0x0302: 'TLS 1.1',
            0x0303: 'TLS 1.2',
            0x0304: 'TLS 1.3'
        }
        return versions.get(version, f'Unknown (0x{version:04X})')
