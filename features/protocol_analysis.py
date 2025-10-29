#!/usr/bin/env python3
"""
Protocol-Specific Deep Analysis for FlagSniff Pro
Implements enterprise, industrial, and custom protocol analysis
"""

import struct
import re
import hashlib
import base64
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import binascii

class SMBAnalyzer:
    """SMB/CIFS protocol analysis"""
    
    def __init__(self):
        self.smb_commands = {
            0x72: 'SMB_COM_NEGOTIATE',
            0x73: 'SMB_COM_SESSION_SETUP_ANDX',
            0x75: 'SMB_COM_TREE_CONNECT_ANDX',
            0x2D: 'SMB_COM_OPEN_ANDX',
            0x2E: 'SMB_COM_READ_ANDX',
            0x2F: 'SMB_COM_WRITE_ANDX',
            0x04: 'SMB_COM_CLOSE',
            0x31: 'SMB_COM_TRANSACTION2',
            0x32: 'SMB_COM_TRANSACTION2_SECONDARY',
            0x33: 'SMB_COM_FIND_CLOSE2',
            0x34: 'SMB_COM_FIND_NOTIFY_CLOSE'
        }
    
    def analyze_smb_traffic(self, packets: List[bytes]) -> Dict[str, Any]:
        """Analyze SMB/CIFS traffic"""
        analysis = {
            'total_packets': len(packets),
            'smb_sessions': [],
            'file_operations': [],
            'share_enumeration': [],
            'credential_attempts': [],
            'suspicious_activities': []
        }
        
        for packet_data in packets:
            smb_info = self._parse_smb_packet(packet_data)
            if smb_info:
                analysis = self._process_smb_packet(analysis, smb_info, packet_data)
        
        return analysis
    
    def _parse_smb_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse SMB packet structure"""
        # Look for SMB signature
        smb1_sig = b'\xffSMB'
        smb2_sig = b'\xfeSMB'
        
        smb1_pos = data.find(smb1_sig)
        smb2_pos = data.find(smb2_sig)
        
        if smb1_pos != -1:
            return self._parse_smb1_header(data, smb1_pos)
        elif smb2_pos != -1:
            return self._parse_smb2_header(data, smb2_pos)
        
        return None
    
    def _parse_smb1_header(self, data: bytes, offset: int) -> Dict[str, Any]:
        """Parse SMB1 header"""
        if len(data) < offset + 32:
            return None
        
        try:
            header = struct.unpack('<4sBBBBHHHHHHHHHH', data[offset:offset+32])
            
            return {
                'version': 1,
                'command': header[1],
                'command_name': self.smb_commands.get(header[1], f'UNKNOWN_{header[1]:02X}'),
                'status': header[2],
                'flags': header[3],
                'flags2': header[4],
                'pid_high': header[5],
                'signature': header[6:14],
                'tid': header[14],
                'pid': header[15],
                'uid': header[16],
                'mid': header[17],
                'offset': offset
            }
        except:
            return None
    
    def _parse_smb2_header(self, data: bytes, offset: int) -> Dict[str, Any]:
        """Parse SMB2 header"""
        if len(data) < offset + 64:
            return None
        
        try:
            # SMB2 header is more complex, simplified parsing
            signature = data[offset:offset+4]
            header_length = struct.unpack('<H', data[offset+4:offset+6])[0]
            command = struct.unpack('<H', data[offset+12:offset+14])[0]
            
            return {
                'version': 2,
                'command': command,
                'command_name': f'SMB2_CMD_{command:02X}',
                'header_length': header_length,
                'offset': offset
            }
        except:
            return None
    
    def _process_smb_packet(self, analysis: Dict, smb_info: Dict, packet_data: bytes) -> Dict[str, Any]:
        """Process individual SMB packet"""
        command = smb_info['command_name']
        
        # Session setup analysis
        if 'SESSION_SETUP' in command:
            cred_info = self._extract_smb_credentials(packet_data, smb_info['offset'])
            if cred_info:
                analysis['credential_attempts'].append(cred_info)
        
        # Tree connect analysis (share enumeration)
        elif 'TREE_CONNECT' in command:
            share_info = self._extract_share_info(packet_data, smb_info['offset'])
            if share_info:
                analysis['share_enumeration'].append(share_info)
        
        # File operations
        elif any(op in command for op in ['OPEN', 'READ', 'WRITE', 'CREATE']):
            file_info = self._extract_file_operation(packet_data, smb_info['offset'], command)
            if file_info:
                analysis['file_operations'].append(file_info)
        
        # Check for suspicious activities
        suspicious = self._detect_smb_suspicious_activity(smb_info, packet_data)
        if suspicious:
            analysis['suspicious_activities'].extend(suspicious)
        
        return analysis
    
    def _extract_smb_credentials(self, data: bytes, offset: int) -> Optional[Dict[str, Any]]:
        """Extract credential information from SMB session setup"""
        cred_info = {
            'type': 'smb_session_setup',
            'username': None,
            'domain': None,
            'ntlm_hash': None,
            'challenge_response': None
        }
        
        # Look for NTLM authentication data
        ntlm_sig = b'NTLMSSP\x00'
        ntlm_pos = data.find(ntlm_sig, offset)
        
        if ntlm_pos != -1:
            cred_info.update(self._parse_ntlm_data(data, ntlm_pos))
        
        # Look for plaintext credentials (older protocols)
        username_patterns = [
            rb'username[:\s=]+([^\s\r\n]+)',
            rb'user[:\s=]+([^\s\r\n]+)'
        ]
        
        for pattern in username_patterns:
            match = re.search(pattern, data[offset:offset+500], re.IGNORECASE)
            if match:
                cred_info['username'] = match.group(1).decode('utf-8', errors='ignore')
                break
        
        return cred_info if any(cred_info.values()) else None
    
    def _parse_ntlm_data(self, data: bytes, offset: int) -> Dict[str, Any]:
        """Parse NTLM authentication data"""
        ntlm_info = {}
        
        try:
            if len(data) >= offset + 12:
                msg_type = struct.unpack('<L', data[offset+8:offset+12])[0]
                
                if msg_type == 1:  # Type 1 message
                    ntlm_info['message_type'] = 'negotiate'
                elif msg_type == 2:  # Type 2 message (challenge)
                    ntlm_info['message_type'] = 'challenge'
                    if len(data) >= offset + 24:
                        challenge = data[offset+24:offset+32]
                        ntlm_info['challenge'] = challenge.hex()
                elif msg_type == 3:  # Type 3 message (authenticate)
                    ntlm_info['message_type'] = 'authenticate'
                    # Extract username, domain, and response hashes
                    ntlm_info.update(self._parse_ntlm_type3(data, offset))
        except:
            pass
        
        return ntlm_info
    
    def _parse_ntlm_type3(self, data: bytes, offset: int) -> Dict[str, Any]:
        """Parse NTLM Type 3 (authenticate) message"""
        info = {}
        
        try:
            # NTLM Type 3 has a complex structure with offsets
            # Simplified parsing for demonstration
            
            # Look for Unicode strings (username, domain)
            unicode_pattern = rb'(?:[^\x00]\x00){3,20}'
            matches = list(re.finditer(unicode_pattern, data[offset:offset+200]))
            
            strings = []
            for match in matches:
                try:
                    unicode_str = match.group().decode('utf-16le', errors='ignore')
                    if unicode_str.isprintable() and len(unicode_str) > 2:
                        strings.append(unicode_str)
                except:
                    continue
            
            if len(strings) >= 2:
                info['username'] = strings[0]
                info['domain'] = strings[1]
            
            # Look for NTLM response (24 bytes)
            if len(data) >= offset + 100:
                # NTLM response is typically 24 bytes
                for i in range(offset, min(offset + 200, len(data) - 24)):
                    potential_response = data[i:i+24]
                    if len(set(potential_response)) > 10:  # Not all zeros/same byte
                        info['ntlm_response'] = potential_response.hex()
                        break
        
        except:
            pass
        
        return info
    
    def _extract_share_info(self, data: bytes, offset: int) -> Optional[Dict[str, Any]]:
        """Extract share information from tree connect"""
        share_info = {
            'type': 'tree_connect',
            'share_name': None,
            'server': None
        }
        
        # Look for UNC paths
        unc_pattern = rb'\\\\([^\\]+)\\([^\\]+)'
        match = re.search(unc_pattern, data[offset:offset+200])
        
        if match:
            share_info['server'] = match.group(1).decode('utf-8', errors='ignore')
            share_info['share_name'] = match.group(2).decode('utf-8', errors='ignore')
            return share_info
        
        return None
    
    def _extract_file_operation(self, data: bytes, offset: int, command: str) -> Optional[Dict[str, Any]]:
        """Extract file operation information"""
        file_info = {
            'type': 'file_operation',
            'command': command,
            'filename': None,
            'file_size': None
        }
        
        # Look for filename patterns
        filename_patterns = [
            rb'([A-Za-z]:\\[^\\/:*?"<>|\r\n]*\.[A-Za-z]{1,4})',
            rb'\\([^\\/:*?"<>|\r\n]*\.[A-Za-z]{1,4})'
        ]
        
        for pattern in filename_patterns:
            match = re.search(pattern, data[offset:offset+300])
            if match:
                file_info['filename'] = match.group(1).decode('utf-8', errors='ignore')
                break
        
        return file_info if file_info['filename'] else None
    
    def _detect_smb_suspicious_activity(self, smb_info: Dict, packet_data: bytes) -> List[Dict[str, Any]]:
        """Detect suspicious SMB activities"""
        suspicious = []
        
        # Check for admin share access
        admin_shares = [b'ADMIN$', b'C$', b'IPC$']
        for share in admin_shares:
            if share in packet_data:
                suspicious.append({
                    'type': 'admin_share_access',
                    'share': share.decode('utf-8'),
                    'severity': 'high'
                })
        
        # Check for credential dumping tools
        dumping_tools = [b'mimikatz', b'pwdump', b'fgdump', b'gsecdump']
        for tool in dumping_tools:
            if tool in packet_data.lower():
                suspicious.append({
                    'type': 'credential_dumping_tool',
                    'tool': tool.decode('utf-8'),
                    'severity': 'critical'
                })
        
        return suspicious

class LDAPAnalyzer:
    """LDAP protocol analysis"""
    
    def analyze_ldap_traffic(self, packets: List[bytes]) -> Dict[str, Any]:
        """Analyze LDAP traffic"""
        analysis = {
            'total_packets': len(packets),
            'bind_attempts': [],
            'search_operations': [],
            'directory_enumeration': [],
            'credential_attempts': [],
            'suspicious_queries': []
        }
        
        for packet_data in packets:
            ldap_info = self._parse_ldap_packet(packet_data)
            if ldap_info:
                analysis = self._process_ldap_packet(analysis, ldap_info, packet_data)
        
        return analysis
    
    def _parse_ldap_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse LDAP packet (simplified ASN.1 parsing)"""
        # LDAP uses ASN.1 BER encoding
        # Look for LDAP message structure
        
        # Simple heuristic: look for common LDAP patterns
        ldap_patterns = [
            b'\x30',  # SEQUENCE tag
            b'bindRequest',
            b'searchRequest',
            b'searchResEntry',
            b'objectClass',
            b'distinguishedName'
        ]
        
        for pattern in ldap_patterns:
            if pattern in data:
                return {
                    'has_ldap_content': True,
                    'pattern_found': pattern
                }
        
        return None
    
    def _process_ldap_packet(self, analysis: Dict, ldap_info: Dict, packet_data: bytes) -> Dict[str, Any]:
        """Process LDAP packet content"""
        
        # Look for bind attempts
        if b'bindRequest' in packet_data or b'simple' in packet_data:
            bind_info = self._extract_ldap_bind(packet_data)
            if bind_info:
                analysis['bind_attempts'].append(bind_info)
        
        # Look for search operations
        if b'searchRequest' in packet_data or b'baseObject' in packet_data:
            search_info = self._extract_ldap_search(packet_data)
            if search_info:
                analysis['search_operations'].append(search_info)
        
        # Look for directory enumeration
        enum_patterns = [b'objectClass', b'memberOf', b'sAMAccountName', b'userPrincipalName']
        for pattern in enum_patterns:
            if pattern in packet_data:
                analysis['directory_enumeration'].append({
                    'type': 'attribute_enumeration',
                    'attribute': pattern.decode('utf-8', errors='ignore')
                })
        
        return analysis
    
    def _extract_ldap_bind(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Extract LDAP bind information"""
        bind_info = {
            'type': 'ldap_bind',
            'username': None,
            'auth_method': 'simple'
        }
        
        # Look for DN patterns
        dn_pattern = rb'CN=([^,]+),.*?DC=([^,]+)'
        match = re.search(dn_pattern, data, re.IGNORECASE)
        if match:
            bind_info['username'] = match.group(1).decode('utf-8', errors='ignore')
            bind_info['domain'] = match.group(2).decode('utf-8', errors='ignore')
        
        return bind_info
    
    def _extract_ldap_search(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Extract LDAP search information"""
        search_info = {
            'type': 'ldap_search',
            'base_dn': None,
            'filter': None,
            'attributes': []
        }
        
        # Look for base DN
        base_patterns = [
            rb'DC=([^,\s]+)',
            rb'OU=([^,\s]+)',
            rb'CN=([^,\s]+)'
        ]
        
        for pattern in base_patterns:
            match = re.search(pattern, data, re.IGNORECASE)
            if match:
                search_info['base_dn'] = match.group().decode('utf-8', errors='ignore')
                break
        
        # Look for common attributes
        attributes = [b'sAMAccountName', b'mail', b'memberOf', b'objectClass']
        for attr in attributes:
            if attr in data:
                search_info['attributes'].append(attr.decode('utf-8'))
        
        return search_info if search_info['base_dn'] or search_info['attributes'] else None

class KerberosAnalyzer:
    """Kerberos protocol analysis"""
    
    def analyze_kerberos_traffic(self, packets: List[bytes]) -> Dict[str, Any]:
        """Analyze Kerberos traffic"""
        analysis = {
            'total_packets': len(packets),
            'as_requests': [],
            'tgs_requests': [],
            'ticket_extractions': [],
            'golden_ticket_indicators': [],
            'asrep_roasting': []
        }
        
        for packet_data in packets:
            krb_info = self._parse_kerberos_packet(packet_data)
            if krb_info:
                analysis = self._process_kerberos_packet(analysis, krb_info, packet_data)
        
        return analysis
    
    def _parse_kerberos_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse Kerberos packet"""
        # Kerberos uses ASN.1 encoding
        # Look for Kerberos message types
        
        # Check for Kerberos application tags
        krb_tags = {
            b'\x6a': 'AS-REQ',
            b'\x6b': 'AS-REP', 
            b'\x6c': 'TGS-REQ',
            b'\x6d': 'TGS-REP',
            b'\x6e': 'AP-REQ',
            b'\x6f': 'AP-REP'
        }
        
        for tag, msg_type in krb_tags.items():
            if tag in data:
                return {
                    'message_type': msg_type,
                    'tag': tag.hex()
                }
        
        return None
    
    def _process_kerberos_packet(self, analysis: Dict, krb_info: Dict, packet_data: bytes) -> Dict[str, Any]:
        """Process Kerberos packet"""
        msg_type = krb_info['message_type']
        
        if msg_type == 'AS-REQ':
            as_req_info = self._extract_as_request(packet_data)
            if as_req_info:
                analysis['as_requests'].append(as_req_info)
        
        elif msg_type == 'TGS-REQ':
            tgs_req_info = self._extract_tgs_request(packet_data)
            if tgs_req_info:
                analysis['tgs_requests'].append(tgs_req_info)
        
        # Check for AS-REP roasting indicators
        if msg_type == 'AS-REP':
            asrep_info = self._check_asrep_roasting(packet_data)
            if asrep_info:
                analysis['asrep_roasting'].append(asrep_info)
        
        return analysis
    
    def _extract_as_request(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Extract AS-REQ information"""
        as_req = {
            'type': 'as_request',
            'username': None,
            'realm': None,
            'encryption_types': []
        }
        
        # Look for principal names (simplified)
        principal_pattern = rb'([a-zA-Z0-9._-]+)@([A-Z0-9.-]+)'
        match = re.search(principal_pattern, data)
        if match:
            as_req['username'] = match.group(1).decode('utf-8', errors='ignore')
            as_req['realm'] = match.group(2).decode('utf-8', errors='ignore')
        
        return as_req
    
    def _extract_tgs_request(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Extract TGS-REQ information"""
        tgs_req = {
            'type': 'tgs_request',
            'service': None,
            'realm': None
        }
        
        # Look for service principal names
        spn_pattern = rb'([a-zA-Z]+)/([a-zA-Z0-9.-]+)'
        match = re.search(spn_pattern, data)
        if match:
            tgs_req['service'] = match.group().decode('utf-8', errors='ignore')
        
        return tgs_req
    
    def _check_asrep_roasting(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Check for AS-REP roasting indicators"""
        # AS-REP roasting involves accounts with "Do not require Kerberos preauthentication"
        # Look for specific patterns in AS-REP responses
        
        asrep_info = {
            'type': 'asrep_roasting_candidate',
            'encrypted_part': None
        }
        
        # Look for encrypted timestamp (simplified)
        if len(data) > 100:
            # Check for high entropy sections that might be encrypted data
            for i in range(0, len(data) - 50, 10):
                chunk = data[i:i+50]
                if self._calculate_entropy(chunk) > 7.0:
                    asrep_info['encrypted_part'] = chunk[:32].hex()
                    return asrep_info
        
        return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy

class ProtocolAnalysisEngine:
    """Main protocol analysis engine"""
    
    def __init__(self):
        self.smb_analyzer = SMBAnalyzer()
        self.ldap_analyzer = LDAPAnalyzer()
        self.kerberos_analyzer = KerberosAnalyzer()
    
    def analyze_protocols(self, packets: List[bytes]) -> Dict[str, Any]:
        """Comprehensive protocol analysis"""
        analysis = {
            'total_packets': len(packets),
            'protocols_detected': [],
            'smb_analysis': {},
            'ldap_analysis': {},
            'kerberos_analysis': {},
            'custom_protocols': {},
            'security_findings': []
        }
        
        # Separate packets by protocol
        smb_packets = []
        ldap_packets = []
        kerberos_packets = []
        unknown_packets = []
        
        for packet in packets:
            if self._is_smb_packet(packet):
                smb_packets.append(packet)
                if 'SMB' not in analysis['protocols_detected']:
                    analysis['protocols_detected'].append('SMB')
            elif self._is_ldap_packet(packet):
                ldap_packets.append(packet)
                if 'LDAP' not in analysis['protocols_detected']:
                    analysis['protocols_detected'].append('LDAP')
            elif self._is_kerberos_packet(packet):
                kerberos_packets.append(packet)
                if 'Kerberos' not in analysis['protocols_detected']:
                    analysis['protocols_detected'].append('Kerberos')
            else:
                unknown_packets.append(packet)
        
        # Analyze each protocol
        if smb_packets:
            analysis['smb_analysis'] = self.smb_analyzer.analyze_smb_traffic(smb_packets)
        
        if ldap_packets:
            analysis['ldap_analysis'] = self.ldap_analyzer.analyze_ldap_traffic(ldap_packets)
        
        if kerberos_packets:
            analysis['kerberos_analysis'] = self.kerberos_analyzer.analyze_kerberos_traffic(kerberos_packets)
        
        # Analyze unknown protocols
        if unknown_packets:
            analysis['custom_protocols'] = self._analyze_custom_protocols(unknown_packets)
        
        # Generate security findings
        analysis['security_findings'] = self._generate_security_findings(analysis)
        
        return analysis
    
    def _is_smb_packet(self, data: bytes) -> bool:
        """Check if packet contains SMB data"""
        return b'\xffSMB' in data or b'\xfeSMB' in data
    
    def _is_ldap_packet(self, data: bytes) -> bool:
        """Check if packet contains LDAP data"""
        ldap_indicators = [b'bindRequest', b'searchRequest', b'objectClass', b'distinguishedName']
        return any(indicator in data for indicator in ldap_indicators)
    
    def _is_kerberos_packet(self, data: bytes) -> bool:
        """Check if packet contains Kerberos data"""
        krb_tags = [b'\x6a', b'\x6b', b'\x6c', b'\x6d', b'\x6e', b'\x6f']
        return any(tag in data for tag in krb_tags)
    
    def _analyze_custom_protocols(self, packets: List[bytes]) -> Dict[str, Any]:
        """Analyze unknown/custom protocols"""
        analysis = {
            'total_unknown_packets': len(packets),
            'protocol_patterns': [],
            'potential_protocols': [],
            'binary_analysis': {}
        }
        
        if not packets:
            return analysis
        
        # Combine all packet data for analysis
        combined_data = b''.join(packets)
        
        # Look for repeating patterns
        patterns = self._find_protocol_patterns(combined_data)
        analysis['protocol_patterns'] = patterns
        
        # Try to identify potential protocols
        potential = self._identify_potential_protocols(combined_data)
        analysis['potential_protocols'] = potential
        
        # Binary analysis
        analysis['binary_analysis'] = {
            'total_size': len(combined_data),
            'entropy': self._calculate_entropy(combined_data),
            'printable_ratio': self._calculate_printable_ratio(combined_data)
        }
        
        return analysis
    
    def _find_protocol_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Find repeating patterns in protocol data"""
        patterns = []
        
        # Look for repeating byte sequences
        for length in [2, 4, 8]:
            pattern_counts = defaultdict(int)
            
            for i in range(len(data) - length + 1):
                pattern = data[i:i+length]
                pattern_counts[pattern] += 1
            
            # Find most common patterns
            for pattern, count in pattern_counts.items():
                if count > 5 and len(set(pattern)) > 1:  # Avoid all-same-byte patterns
                    patterns.append({
                        'pattern': pattern.hex(),
                        'length': length,
                        'count': count,
                        'frequency': count / (len(data) - length + 1)
                    })
        
        return sorted(patterns, key=lambda x: x['count'], reverse=True)[:10]
    
    def _identify_potential_protocols(self, data: bytes) -> List[Dict[str, Any]]:
        """Identify potential protocol types"""
        potential = []
        
        # Check for common protocol signatures
        protocol_signatures = {
            'HTTP': [b'GET ', b'POST ', b'HTTP/'],
            'FTP': [b'USER ', b'PASS ', b'RETR ', b'STOR '],
            'SMTP': [b'HELO ', b'MAIL FROM:', b'RCPT TO:'],
            'DNS': [b'\x00\x01\x00\x01', b'\x81\x80'],  # DNS query/response flags
            'DHCP': [b'\x01\x01\x06\x00'],  # DHCP message type
            'SNMP': [b'\x30', b'\x02\x01'],  # ASN.1 SEQUENCE, INTEGER
        }
        
        for protocol, signatures in protocol_signatures.items():
            for signature in signatures:
                if signature in data:
                    potential.append({
                        'protocol': protocol,
                        'signature': signature.hex(),
                        'confidence': 70
                    })
                    break
        
        return potential
    
    def _calculate_printable_ratio(self, data: bytes) -> float:
        """Calculate ratio of printable characters"""
        if not data:
            return 0.0
        
        printable_count = sum(1 for byte in data if 32 <= byte <= 126)
        return printable_count / len(data)
    
    def _generate_security_findings(self, analysis: Dict) -> List[Dict[str, Any]]:
        """Generate security findings from protocol analysis"""
        findings = []
        
        # SMB security findings
        smb_analysis = analysis.get('smb_analysis', {})
        if smb_analysis.get('suspicious_activities'):
            for activity in smb_analysis['suspicious_activities']:
                findings.append({
                    'protocol': 'SMB',
                    'type': 'suspicious_activity',
                    'severity': activity.get('severity', 'medium'),
                    'description': f"SMB {activity['type']}: {activity.get('share', activity.get('tool', 'unknown'))}",
                    'details': activity
                })
        
        # LDAP security findings
        ldap_analysis = analysis.get('ldap_analysis', {})
        if len(ldap_analysis.get('bind_attempts', [])) > 10:
            findings.append({
                'protocol': 'LDAP',
                'type': 'excessive_bind_attempts',
                'severity': 'medium',
                'description': f"High number of LDAP bind attempts: {len(ldap_analysis['bind_attempts'])}",
                'count': len(ldap_analysis['bind_attempts'])
            })
        
        # Kerberos security findings
        kerberos_analysis = analysis.get('kerberos_analysis', {})
        if kerberos_analysis.get('asrep_roasting'):
            findings.append({
                'protocol': 'Kerberos',
                'type': 'asrep_roasting',
                'severity': 'high',
                'description': 'Potential AS-REP roasting attack detected',
                'count': len(kerberos_analysis['asrep_roasting'])
            })
        
        return findings