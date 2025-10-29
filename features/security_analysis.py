#!/usr/bin/env python3
"""
Consolidated Security Analysis Module for FlagSniff Pro
Unified credential extraction, threat detection, and risk assessment
"""

import re
import base64
import hashlib
from typing import Dict, List, Any, Optional
from collections import Counter
from features.core_patterns import CredentialPatterns, FlagPatterns, SuspiciousPatterns, PatternUtils

class UnifiedCredentialExtractor:
    """Consolidated credential extraction from all sources"""
    
    def __init__(self):
        self.patterns = CredentialPatterns()
        self.utils = PatternUtils()
    
    def extract_all_credentials(self, data: bytes) -> Dict[str, List[Dict[str, Any]]]:
        """Extract all types of credentials from data"""
        credentials = {
            'passwords': [],
            'hashes': [],
            'auth_tokens': [],
            'api_keys': [],
            'ssh_keys': [],
            'certificates': [],
            'browser_data': [],
            'wifi_credentials': [],
            'application_secrets': []
        }
        
        # Extract passwords
        credentials['passwords'] = self._extract_passwords(data)
        
        # Extract hashes
        credentials['hashes'] = self._extract_hashes(data)
        
        # Extract authentication tokens
        credentials['auth_tokens'] = self._extract_auth_tokens(data)
        
        # Extract API keys
        credentials['api_keys'] = self._extract_api_keys(data)
        
        # Extract SSH keys and certificates
        credentials['ssh_keys'] = self._extract_ssh_keys(data)
        credentials['certificates'] = self._extract_certificates(data)
        
        # Extract browser data
        credentials['browser_data'] = self._extract_browser_data(data)
        
        # Extract WiFi credentials
        credentials['wifi_credentials'] = self._extract_wifi_credentials(data)
        
        # Extract application secrets
        credentials['application_secrets'] = self._extract_application_secrets(data)
        
        return credentials
    
    def _extract_passwords(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract password-like strings"""
        passwords = []
        
        for pattern in self.patterns.PASSWORD_PATTERNS:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                try:
                    password = match.group(1).decode('utf-8', errors='ignore')
                    if self._is_valid_password(password):
                        passwords.append({
                            'password': password,
                            'offset': match.start(),
                            'context': self._get_context(data, match.start(), match.end()),
                            'confidence': self._calculate_password_confidence(password)
                        })
                except:
                    continue
        
        return passwords
    
    def _extract_hashes(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract password hashes"""
        hashes = []
        
        for hash_type, pattern in self.patterns.HASH_PATTERNS.items():
            for match in re.finditer(pattern, data):
                hash_value = match.group().decode('utf-8')
                hashes.append({
                    'type': hash_type,
                    'hash': hash_value,
                    'offset': match.start(),
                    'context': self._get_context(data, match.start(), match.end()),
                    'confidence': 85
                })
        
        return hashes
    
    def _extract_auth_tokens(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract authentication tokens"""
        tokens = []
        
        for auth_type, pattern in self.patterns.AUTH_PATTERNS.items():
            for match in re.finditer(pattern, data, re.IGNORECASE):
                try:
                    if auth_type == 'form_data':
                        username = match.group(1).decode('utf-8', errors='ignore')
                        password = match.group(2).decode('utf-8', errors='ignore')
                        tokens.append({
                            'type': auth_type,
                            'username': username,
                            'password': password,
                            'offset': match.start(),
                            'confidence': 90
                        })
                    else:
                        token = match.group(1).decode('utf-8', errors='ignore')
                        tokens.append({
                            'type': auth_type,
                            'token': token,
                            'offset': match.start(),
                            'confidence': 85
                        })
                except:
                    continue
        
        return tokens
    
    def _extract_api_keys(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract API keys and tokens"""
        api_keys = []
        
        # Use the API key pattern from CredentialPatterns
        pattern = self.patterns.AUTH_PATTERNS['api_key']
        for match in re.finditer(pattern, data, re.IGNORECASE):
            try:
                api_key = match.group(1).decode('utf-8', errors='ignore')
                if len(api_key) >= 20:  # Minimum length for API keys
                    api_keys.append({
                        'api_key': api_key,
                        'offset': match.start(),
                        'context': self._get_context(data, match.start(), match.end()),
                        'confidence': 80
                    })
            except:
                continue
        
        return api_keys
    
    def _extract_ssh_keys(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract SSH keys"""
        ssh_keys = []
        
        for pattern in self.patterns.CRYPTO_PATTERNS:
            for match in re.finditer(pattern, data):
                try:
                    key_data = match.group().decode('utf-8', errors='ignore')
                    ssh_keys.append({
                        'type': 'ssh_key',
                        'key': key_data[:200] + '...' if len(key_data) > 200 else key_data,
                        'offset': match.start(),
                        'confidence': 95
                    })
                except:
                    continue
        
        return ssh_keys
    
    def _extract_certificates(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract X.509 certificates"""
        certificates = []
        
        cert_patterns = [p for p in self.patterns.CRYPTO_PATTERNS if b'CERTIFICATE' in p or b'PRIVATE KEY' in p]
        for pattern in cert_patterns:
            for match in re.finditer(pattern, data):
                try:
                    cert_data = match.group().decode('utf-8', errors='ignore')
                    certificates.append({
                        'type': 'certificate',
                        'certificate': cert_data[:200] + '...' if len(cert_data) > 200 else cert_data,
                        'offset': match.start(),
                        'confidence': 90
                    })
                except:
                    continue
        
        return certificates
    
    def _extract_browser_data(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract browser credential data"""
        browser_data = []
        
        # Look for Chrome/Firefox login data
        login_patterns = [
            rb'origin_url.*username_value.*password_value',
            rb'formSubmitURL.*usernameField.*passwordField',
            rb'Login Data',
            rb'Web Data',
            rb'Cookies'
        ]
        
        for pattern in login_patterns:
            for match in re.finditer(pattern, data, re.DOTALL | re.IGNORECASE):
                browser_data.append({
                    'type': 'browser_data',
                    'data': match.group()[:100].decode('utf-8', errors='ignore'),
                    'offset': match.start(),
                    'confidence': 70
                })
        
        return browser_data
    
    def _extract_wifi_credentials(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract WiFi credentials"""
        wifi_creds = []
        
        # Look for WiFi profile data
        wifi_patterns = [
            rb'<name>([^<]+)</name>.*<keyMaterial>([^<]+)</keyMaterial>',
            rb'SSID.*PSK.*',
            rb'WPA.*PSK.*'
        ]
        
        for pattern in wifi_patterns:
            for match in re.finditer(pattern, data, re.DOTALL | re.IGNORECASE):
                wifi_creds.append({
                    'type': 'wifi_credential',
                    'data': match.group().decode('utf-8', errors='ignore'),
                    'offset': match.start(),
                    'confidence': 75
                })
        
        return wifi_creds
    
    def _extract_application_secrets(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract application-specific secrets"""
        secrets = []
        
        for pattern in self.patterns.SECRET_PATTERNS:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                try:
                    secret = match.group(1).decode('utf-8', errors='ignore')
                    secrets.append({
                        'type': 'application_secret',
                        'secret': secret[:50] + '...' if len(secret) > 50 else secret,
                        'offset': match.start(),
                        'confidence': 70
                    })
                except:
                    continue
        
        return secrets
    
    def _is_valid_password(self, password: str) -> bool:
        """Validate if a string is a legitimate password"""
        if len(password) < 3 or len(password) > 100:
            return False
        
        # Exclude common false positives
        false_positives = ['password', 'admin', 'user', 'test', 'guest', 'root', 'windows', 'microsoft']
        if password.lower() in false_positives:
            return False
        
        # Must not be all digits or all same character
        if password.isdigit() or len(set(password)) == 1:
            return False
        
        return True
    
    def _calculate_password_confidence(self, password: str) -> int:
        """Calculate confidence score for password"""
        confidence = 50
        
        # Length bonus
        if len(password) >= 8:
            confidence += 20
        elif len(password) >= 6:
            confidence += 10
        
        # Complexity bonus
        if any(c.isupper() for c in password):
            confidence += 10
        if any(c.islower() for c in password):
            confidence += 10
        if any(c.isdigit() for c in password):
            confidence += 10
        if any(c in '!@#$%^&*()_+-=' for c in password):
            confidence += 15
        
        return min(confidence, 95)
    
    def _get_context(self, data: bytes, start: int, end: int, context_size: int = 50) -> str:
        """Get context around a match"""
        context_start = max(0, start - context_size)
        context_end = min(len(data), end + context_size)
        context = data[context_start:context_end].decode('utf-8', errors='ignore')
        return context

class UnifiedThreatDetector:
    """Consolidated threat detection and analysis"""
    
    def __init__(self):
        self.suspicious_patterns = SuspiciousPatterns()
        self.utils = PatternUtils()
    
    def analyze_threats(self, data: bytes) -> Dict[str, Any]:
        """Comprehensive threat analysis"""
        analysis = {
            'threat_indicators': self.suspicious_patterns.scan_for_threats(data),
            'risk_assessment': self._assess_risk(data),
            'behavioral_analysis': self._analyze_behavior(data),
            'attack_patterns': self._detect_attack_patterns(data),
            'anomalies': self._detect_anomalies(data)
        }
        
        return analysis
    
    def _assess_risk(self, data: bytes) -> Dict[str, Any]:
        """Assess overall risk level"""
        risk_score = 0
        risk_factors = []
        
        # Check for malware indicators
        malware_count = len(self.suspicious_patterns.scan_for_threats(data)['malware'])
        if malware_count > 0:
            risk_score += malware_count * 25
            risk_factors.append(f'Malware indicators: {malware_count}')
        
        # Check for attack patterns
        attack_count = len(self.suspicious_patterns.scan_for_threats(data)['attacks'])
        if attack_count > 0:
            risk_score += attack_count * 20
            risk_factors.append(f'Attack patterns: {attack_count}')
        
        # Check entropy (high entropy might indicate encryption/packing)
        entropy = self.utils.calculate_entropy(data)
        if entropy > 7.5:
            risk_score += 15
            risk_factors.append(f'High entropy: {entropy:.2f}')
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = 'CRITICAL'
        elif risk_score >= 60:
            risk_level = 'HIGH'
        elif risk_score >= 40:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_level': risk_level,
            'risk_score': min(risk_score, 100),
            'risk_factors': risk_factors,
            'recommendations': self._generate_recommendations(risk_level, risk_factors)
        }
    
    def _analyze_behavior(self, data: bytes) -> Dict[str, Any]:
        """Analyze behavioral patterns"""
        behavior = {
            'data_size': len(data),
            'entropy': self.utils.calculate_entropy(data),
            'printable_ratio': self.utils.calculate_printable_ratio(data),
            'null_byte_ratio': data.count(0) / len(data) if data else 0,
            'repeated_patterns': self._find_repeated_patterns(data),
            'suspicious_sequences': self._find_suspicious_sequences(data)
        }
        
        return behavior
    
    def _detect_attack_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect specific attack patterns"""
        attacks = []
        
        # Directory traversal
        traversal_patterns = [b'../../../', b'..\\..\\..\\', b'....//....//']
        for pattern in traversal_patterns:
            if pattern in data:
                attacks.append({
                    'type': 'directory_traversal',
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'severity': 'high'
                })
        
        # SQL injection
        sql_patterns = [b'SELECT * FROM', b'UNION SELECT', b'DROP TABLE', b"' OR '1'='1"]
        for pattern in sql_patterns:
            if pattern.lower() in data.lower():
                attacks.append({
                    'type': 'sql_injection',
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'severity': 'high'
                })
        
        # XSS patterns
        xss_patterns = [b'<script', b'javascript:', b'eval(', b'document.cookie']
        for pattern in xss_patterns:
            if pattern.lower() in data.lower():
                attacks.append({
                    'type': 'xss',
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'severity': 'medium'
                })
        
        # Command injection
        cmd_patterns = [b'cmd.exe', b'/bin/sh', b'/bin/bash', b'powershell.exe']
        for pattern in cmd_patterns:
            if pattern.lower() in data.lower():
                attacks.append({
                    'type': 'command_injection',
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'severity': 'high'
                })
        
        return attacks
    
    def _detect_anomalies(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect anomalous patterns"""
        anomalies = []
        
        # Check for unusual character frequency
        char_counts = Counter(data)
        total_chars = len(data)
        
        for char, count in char_counts.most_common(5):
            frequency = count / total_chars
            if frequency > 0.3:  # More than 30% of data is same character
                anomalies.append({
                    'type': 'high_character_frequency',
                    'character': chr(char) if 32 <= char <= 126 else f'\\x{char:02x}',
                    'frequency': frequency,
                    'severity': 'medium'
                })
        
        # Check for long repeated sequences
        repeated_pattern = re.search(rb'(.{4,})\1{5,}', data)
        if repeated_pattern:
            pattern = repeated_pattern.group(1)
            anomalies.append({
                'type': 'repeated_sequence',
                'pattern': pattern[:20].decode('utf-8', errors='ignore'),
                'severity': 'low'
            })
        
        return anomalies
    
    def _find_repeated_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Find repeated byte patterns"""
        patterns = []
        
        # Look for repeated 4-byte patterns
        for i in range(len(data) - 8):
            pattern = data[i:i+4]
            count = 0
            pos = i
            
            while pos < len(data) - 4:
                pos = data.find(pattern, pos + 1)
                if pos == -1:
                    break
                count += 1
            
            if count > 5:  # Pattern repeats more than 5 times
                patterns.append({
                    'pattern': pattern.hex(),
                    'count': count,
                    'first_offset': i
                })
        
        return patterns[:10]  # Return top 10
    
    def _find_suspicious_sequences(self, data: bytes) -> List[Dict[str, Any]]:
        """Find suspicious byte sequences"""
        sequences = []
        
        # Look for NOP sleds (common in exploits)
        nop_patterns = [b'\x90' * 20, b'\x41' * 20]  # x86 NOP, 'A' padding
        for pattern in nop_patterns:
            if pattern in data:
                sequences.append({
                    'type': 'nop_sled',
                    'pattern': pattern[:10].hex(),
                    'offset': data.find(pattern)
                })
        
        # Look for shellcode patterns
        shellcode_patterns = [b'\xeb\xfe', b'\x31\xc0', b'\x50\x68']  # Common shellcode opcodes
        for pattern in shellcode_patterns:
            if pattern in data:
                sequences.append({
                    'type': 'potential_shellcode',
                    'pattern': pattern.hex(),
                    'offset': data.find(pattern)
                })
        
        return sequences
    
    def _generate_recommendations(self, risk_level: str, risk_factors: List[str]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.extend([
                'Immediately isolate and analyze the source',
                'Scan for malware using updated antivirus',
                'Check system logs for compromise indicators',
                'Consider forensic analysis'
            ])
        
        if 'malware' in str(risk_factors).lower():
            recommendations.append('Run comprehensive malware scan')
        
        if 'attack' in str(risk_factors).lower():
            recommendations.append('Review security controls and access logs')
        
        if 'entropy' in str(risk_factors).lower():
            recommendations.append('Analyze for encrypted or packed content')
        
        if not recommendations:
            recommendations = [
                'Continue monitoring for suspicious activity',
                'Maintain current security posture',
                'Regular security assessments recommended'
            ]
        
        return recommendations

class UnifiedFlagDetector:
    """Consolidated flag detection and validation"""
    
    def __init__(self):
        self.flag_patterns = FlagPatterns()
        self.utils = PatternUtils()
    
    def detect_flags(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect and validate flags in data"""
        flags = []
        
        # Search for flag patterns
        all_patterns = self.flag_patterns.FLAG_PATTERNS + self.flag_patterns.ADVANCED_FLAG_PATTERNS
        
        for pattern in all_patterns:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                try:
                    flag_text = match.group().decode('utf-8', errors='ignore')
                    
                    if self.flag_patterns.is_valid_flag(flag_text):
                        flags.append({
                            'flag': flag_text,
                            'offset': match.start(),
                            'pattern_type': self._identify_pattern_type(pattern),
                            'confidence': self._calculate_flag_confidence(flag_text),
                            'context': self._get_flag_context(data, match.start(), match.end())
                        })
                except:
                    continue
        
        return flags
    
    def _identify_pattern_type(self, pattern: bytes) -> str:
        """Identify the type of flag pattern"""
        pattern_str = pattern.decode('utf-8', errors='ignore')
        
        if 'picoCTF' in pattern_str:
            return 'picoCTF'
        elif 'DUCTF' in pattern_str:
            return 'DownUnderCTF'
        elif 'HTB' in pattern_str:
            return 'HackTheBox'
        elif 'flag' in pattern_str.lower():
            return 'generic_flag'
        elif '[A-Z]' in pattern_str:
            return 'ctf_format'
        else:
            return 'unknown'
    
    def _calculate_flag_confidence(self, flag_text: str) -> int:
        """Calculate confidence score for flag"""
        confidence = 70  # Base confidence
        
        # Length bonus
        if '{' in flag_text and '}' in flag_text:
            content = flag_text.split('{')[1].split('}')[0]
            if len(content) >= 10:
                confidence += 15
            elif len(content) >= 6:
                confidence += 10
        
        # Format bonus
        if flag_text.upper().startswith(('FLAG{', 'CTF{', 'PICOCTF{', 'HTB{')):
            confidence += 20
        
        # Content analysis
        if '{' in flag_text and '}' in flag_text:
            content = flag_text.split('{')[1].split('}')[0]
            
            # Alphanumeric content is good
            if content.replace('_', '').replace('-', '').isalnum():
                confidence += 10
            
            # Mixed case is good
            if any(c.isupper() for c in content) and any(c.islower() for c in content):
                confidence += 5
        
        return min(confidence, 95)
    
    def _get_flag_context(self, data: bytes, start: int, end: int, context_size: int = 100) -> str:
        """Get context around a flag"""
        context_start = max(0, start - context_size)
        context_end = min(len(data), end + context_size)
        context = data[context_start:context_end].decode('utf-8', errors='ignore')
        return context

class SecurityAnalysisEngine:
    """Main security analysis engine combining all components"""
    
    def __init__(self):
        self.credential_extractor = UnifiedCredentialExtractor()
        self.threat_detector = UnifiedThreatDetector()
        self.flag_detector = UnifiedFlagDetector()
    
    def comprehensive_security_analysis(self, data: bytes) -> Dict[str, Any]:
        """Perform comprehensive security analysis"""
        analysis = {
            'data_size': len(data),
            'credentials': self.credential_extractor.extract_all_credentials(data),
            'threats': self.threat_detector.analyze_threats(data),
            'flags': self.flag_detector.detect_flags(data),
            'summary': {}
        }
        
        # Generate summary
        analysis['summary'] = self._generate_summary(analysis)
        
        return analysis
    
    def _generate_summary(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analysis summary"""
        total_credentials = sum(len(creds) for creds in analysis['credentials'].values())
        total_threats = len(analysis['threats']['threat_indicators']['malware']) + \
                       len(analysis['threats']['threat_indicators']['attacks'])
        total_flags = len(analysis['flags'])
        
        return {
            'total_credentials_found': total_credentials,
            'total_threats_detected': total_threats,
            'total_flags_found': total_flags,
            'risk_level': analysis['threats']['risk_assessment']['risk_level'],
            'risk_score': analysis['threats']['risk_assessment']['risk_score'],
            'high_confidence_findings': len([
                f for f in analysis['flags'] if f['confidence'] > 80
            ]) + len([
                c for creds in analysis['credentials'].values() 
                for c in creds if c.get('confidence', 0) > 80
            ])
        }