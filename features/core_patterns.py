#!/usr/bin/env python3
"""
Core Patterns Library for FlagSniff Pro
Centralized repository for all file signatures, patterns, and detection rules
"""

import re
from typing import Dict, List, Pattern

class FileSignatures:
    """Centralized file signature detection"""
    
    # Comprehensive file signatures
    SIGNATURES = {
        # Archives
        b'PK\x03\x04': {'ext': 'zip', 'name': 'ZIP Archive'},
        b'PK\x05\x06': {'ext': 'zip', 'name': 'ZIP Archive (empty)'},
        b'PK\x07\x08': {'ext': 'zip', 'name': 'ZIP Archive (spanned)'},
        b'Rar!\x1a\x07\x00': {'ext': 'rar', 'name': 'RAR Archive v1.5+'},
        b'Rar!\x1a\x07\x01\x00': {'ext': 'rar', 'name': 'RAR Archive v5.0+'},
        b'\x1f\x8b\x08': {'ext': 'gz', 'name': 'GZIP Archive'},
        b'BZh': {'ext': 'bz2', 'name': 'BZIP2 Archive'},
        b'\xfd7zXZ\x00': {'ext': 'xz', 'name': 'XZ Archive'},
        b'7z\xbc\xaf\x27\x1c': {'ext': '7z', 'name': '7-Zip Archive'},
        b'MSCF': {'ext': 'cab', 'name': 'Microsoft Cabinet'},
        
        # Images
        b'\x89PNG\r\n\x1a\n': {'ext': 'png', 'name': 'PNG Image'},
        b'\xff\xd8\xff': {'ext': 'jpg', 'name': 'JPEG Image'},
        b'GIF87a': {'ext': 'gif', 'name': 'GIF Image (87a)'},
        b'GIF89a': {'ext': 'gif', 'name': 'GIF Image (89a)'},
        b'BM': {'ext': 'bmp', 'name': 'Bitmap Image'},
        b'\x00\x00\x01\x00': {'ext': 'ico', 'name': 'Icon File'},
        b'\x00\x00\x02\x00': {'ext': 'cur', 'name': 'Cursor File'},
        b'RIFF': {'ext': 'webp', 'name': 'WebP Image'},  # Need to check for WEBP after RIFF
        b'II*\x00': {'ext': 'tiff', 'name': 'TIFF Image (little-endian)'},
        b'MM\x00*': {'ext': 'tiff', 'name': 'TIFF Image (big-endian)'},
        
        # Audio/Video
        b'RIFF....WAVE': {'ext': 'wav', 'name': 'WAV Audio'},
        b'fLaC': {'ext': 'flac', 'name': 'FLAC Audio'},
        b'OggS': {'ext': 'ogg', 'name': 'OGG Audio'},
        b'ID3': {'ext': 'mp3', 'name': 'MP3 Audio'},
        b'\xff\xfb': {'ext': 'mp3', 'name': 'MP3 Audio (no ID3)'},
        b'\x00\x00\x00\x18ftyp': {'ext': 'mp4', 'name': 'MP4 Video'},
        b'\x00\x00\x00\x1cftyp': {'ext': 'mp4', 'name': 'MP4 Video'},
        b'ftypqt': {'ext': 'mov', 'name': 'QuickTime Video'},
        b'\x1aE\xdf\xa3': {'ext': 'mkv', 'name': 'Matroska Video'},
        b'FLV\x01': {'ext': 'flv', 'name': 'Flash Video'},
        b'RIFF....AVI': {'ext': 'avi', 'name': 'AVI Video'},
        
        # Documents
        b'%PDF': {'ext': 'pdf', 'name': 'PDF Document'},
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': {'ext': 'doc', 'name': 'MS Office Document (legacy)'},
        b'PK\x03\x04\x14\x00\x06\x00': {'ext': 'docx', 'name': 'MS Office Document (2007+)'},
        b'{\\rtf': {'ext': 'rtf', 'name': 'Rich Text Format'},
        b'\x89HDF\r\n\x1a\n': {'ext': 'hdf5', 'name': 'HDF5 Data'},
        
        # Executables
        b'MZ': {'ext': 'exe', 'name': 'PE Executable'},
        b'\x7fELF': {'ext': 'elf', 'name': 'ELF Executable'},
        b'\xfe\xed\xfa\xce': {'ext': 'macho', 'name': 'Mach-O Executable (32-bit BE)'},
        b'\xfe\xed\xfa\xcf': {'ext': 'macho', 'name': 'Mach-O Executable (64-bit BE)'},
        b'\xce\xfa\xed\xfe': {'ext': 'macho', 'name': 'Mach-O Executable (32-bit LE)'},
        b'\xcf\xfa\xed\xfe': {'ext': 'macho', 'name': 'Mach-O Executable (64-bit LE)'},
        b'\xca\xfe\xba\xbe': {'ext': 'class', 'name': 'Java Class File'},
        
        # Databases
        b'SQLite format 3\x00': {'ext': 'sqlite', 'name': 'SQLite Database'},
        b'SQLite format 3': {'ext': 'sqlite3', 'name': 'SQLite3 Database'},
        
        # Certificates
        b'-----BEGIN': {'ext': 'pem', 'name': 'PEM Certificate'},
        b'0\x82': {'ext': 'der', 'name': 'DER Certificate'},
        
        # CTF-specific signatures
        b'FLAG{': {'ext': 'txt', 'name': 'CTF Flag File'},
        b'CTF{': {'ext': 'txt', 'name': 'CTF Challenge File'},
        b'PICOCTF{': {'ext': 'txt', 'name': 'PicoCTF Challenge File'},
        b'HTB{': {'ext': 'txt', 'name': 'HackTheBox Flag File'},
        b'DUCTF{': {'ext': 'txt', 'name': 'DownUnderCTF Flag File'},
        b'TJCTF{': {'ext': 'txt', 'name': 'TJCTF Flag File'},
        b'CSAW{': {'ext': 'txt', 'name': 'CSAW Flag File'},
        b'UTCTF{': {'ext': 'txt', 'name': 'UTCTF Flag File'},
        b'TAMU{': {'ext': 'txt', 'name': 'TAMU Flag File'},
        b'RCTF{': {'ext': 'txt', 'name': 'RCTF Flag File'},
        b'0xGame{': {'ext': 'txt', 'name': '0xGame Flag File'},
    }
    
    @classmethod
    def detect_file_type(cls, data: bytes) -> Dict[str, str]:
        """Detect file type from binary data"""
        for signature, info in cls.SIGNATURES.items():
            if data.startswith(signature):
                return info
            # Special handling for RIFF-based formats
            elif signature == b'RIFF....WAVE' and data.startswith(b'RIFF') and b'WAVE' in data[:12]:
                return info
            elif signature == b'RIFF....AVI' and data.startswith(b'RIFF') and b'AVI' in data[:12]:
                return info
        
        return {'ext': 'unknown', 'name': 'Unknown File Type'}

class CredentialPatterns:
    """Centralized credential detection patterns"""
    
    # Password patterns
    PASSWORD_PATTERNS = [
        rb'password[:\s=]+([^\s\r\n]+)',
        rb'pwd[:\s=]+([^\s\r\n]+)',
        rb'pass[:\s=]+([^\s\r\n]+)',
        rb'passwd[:\s=]+([^\s\r\n]+)',
    ]
    
    # Authentication patterns
    AUTH_PATTERNS = {
        'basic_auth': rb'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)',
        'bearer_token': rb'Authorization:\s*Bearer\s+([A-Za-z0-9+/=\-_.]+)',
        'api_key': rb'(?:api[_-]?key|apikey)\s*[:=]\s*([A-Za-z0-9+/=]{20,})',
        'form_data': rb'(?:username|user)=([^&\s]+).*?(?:password|pass)=([^&\s]+)',
        'cookie_auth': rb'Cookie:\s*([^\r\n]+)',
    }
    
    # Hash patterns
    HASH_PATTERNS = {
        'md5': rb'[a-fA-F0-9]{32}',
        'sha1': rb'[a-fA-F0-9]{40}',
        'sha256': rb'[a-fA-F0-9]{64}',
        'sha512': rb'[a-fA-F0-9]{128}',
        'ntlm': rb'[a-fA-F0-9]{32}',  # Same as MD5 but context-dependent
    }
    
    # SSH/Certificate patterns
    CRYPTO_PATTERNS = [
        rb'-----BEGIN RSA PRIVATE KEY-----',
        rb'-----BEGIN OPENSSH PRIVATE KEY-----',
        rb'-----BEGIN CERTIFICATE-----',
        rb'-----BEGIN PRIVATE KEY-----',
        rb'ssh-rsa AAAA[A-Za-z0-9+/]+',
        rb'ssh-dss AAAA[A-Za-z0-9+/]+',
        rb'ssh-ed25519 AAAA[A-Za-z0-9+/]+',
    ]
    
    # Application secrets
    SECRET_PATTERNS = [
        rb'secret[_-]?key[:\s=]+([A-Za-z0-9+/]{20,})',
        rb'token[:\s=]+([A-Za-z0-9+/]{20,})',
        rb'bearer[:\s]+([A-Za-z0-9+/]{20,})',
        rb'access[_-]?token[:\s=]+([A-Za-z0-9+/]{20,})',
        rb'refresh[_-]?token[:\s=]+([A-Za-z0-9+/]{20,})',
    ]

class FlagPatterns:
    """Centralized flag detection patterns"""
    
    # Standard flag patterns
    FLAG_PATTERNS = [
        rb'flag\{[^}]+\}',
        rb'FLAG\{[^}]+\}',
        rb'[A-Z]{2,10}\{[^}]+\}',  # Generic CTF format
        rb'picoCTF\{[^}]+\}',
        rb'DUCTF\{[^}]+\}',
        rb'HTB\{[^}]+\}',
        rb'TJCTF\{[^}]+\}',
        rb'CSAW\{[^}]+\}',
        rb'UTCTF\{[^}]+\}',
        rb'TAMU\{[^}]+\}',
        rb'RCTF\{[^}]+\}',
        rb'0xGame\{[^}]+\}',
    ]
    
    # Advanced flag patterns
    ADVANCED_FLAG_PATTERNS = [
        rb'[A-Z]{2,10}[0-9]{2,4}\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}',  # Pattern like XXXNNNN{...}
        rb'[a-f0-9]{32}\{[^}]+\}',  # MD5-like prefix
        rb'[a-f0-9]{40}\{[^}]+\}',  # SHA1-like prefix
    ]
    
    # False positive patterns to exclude
    FALSE_POSITIVE_PATTERNS = [
        rb'windows.*build',
        rb'version.*\d+',
        rb'system.*info',
        rb'64-bit.*windows',
        rb'microsoft.*corp',
        rb'copyright.*\d{4}',
        rb'all.*rights.*reserved',
        rb'program.*files',
        rb'temp.*folder',
        rb'user.*profile',
    ]
    
    @classmethod
    def is_valid_flag(cls, flag_data: str) -> bool:
        """Validate if a string is a legitimate flag"""
        # Check against valid patterns
        valid = any(re.match(pattern.decode('utf-8', errors='ignore'), flag_data, re.IGNORECASE) 
                   for pattern in cls.FLAG_PATTERNS + cls.ADVANCED_FLAG_PATTERNS)
        
        if not valid:
            return False
        
        # Check against false positives
        for fp_pattern in cls.FALSE_POSITIVE_PATTERNS:
            if re.search(fp_pattern.decode('utf-8', errors='ignore'), flag_data.lower()):
                return False
        
        # Must have meaningful content
        if '{' in flag_data and '}' in flag_data:
            content = flag_data.split('{')[1].split('}')[0]
            if len(content) < 4:
                return False
        
        return True

class EncodingPatterns:
    """Centralized encoding detection patterns"""
    
    ENCODING_PATTERNS = {
        'base64': rb'[A-Za-z0-9+/]{4,}={0,2}',
        'base32': rb'[A-Z2-7]{8,}={0,6}',
        'base58': rb'[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{4,}',
        'hex': rb'[0-9A-Fa-f]{8,}',
        'url_encoded': rb'%[0-9A-Fa-f]{2}',
        'unicode_escape': rb'\\u[0-9A-Fa-f]{4}',
        'html_entity': rb'&[a-zA-Z][a-zA-Z0-9]*;',
        'decimal': rb'&#\d+;',
    }
    
    @classmethod
    def detect_encoding(cls, data: str) -> List[str]:
        """Detect possible encodings in text data"""
        detected = []
        
        for encoding_name, pattern in cls.ENCODING_PATTERNS.items():
            if re.search(pattern, data.encode('utf-8', errors='ignore')):
                detected.append(encoding_name)
        
        return detected

class ProtocolPatterns:
    """Centralized protocol detection patterns"""
    
    PROTOCOL_INDICATORS = {
        'http': [b'http/', b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS '],
        'https': [b'https/', b'SSL', b'TLS'],
        'ftp': [b'FTP', b'USER ', b'PASS ', b'RETR ', b'STOR ', b'LIST'],
        'ssh': [b'SSH-', b'OpenSSH'],
        'dns': [b'DNS', b'query', b'response'],
        'smtp': [b'SMTP', b'MAIL FROM:', b'RCPT TO:', b'HELO', b'EHLO'],
        'pop3': [b'POP3', b'+OK', b'-ERR'],
        'imap': [b'IMAP', b'* OK', b'* BAD'],
        'telnet': [b'TELNET'],
        'snmp': [b'SNMP', b'community'],
        'tftp': [b'TFTP'],
        'smb': [b'SMB', b'\xffSMB', b'\xfeSMB'],
        'ldap': [b'LDAP', b'bindRequest', b'searchRequest'],
        'kerberos': [b'\x6a', b'\x6b', b'\x6c', b'\x6d', b'\x6e', b'\x6f'],  # ASN.1 tags
    }
    
    @classmethod
    def detect_protocol(cls, data: bytes) -> List[str]:
        """Detect protocols in binary data"""
        detected = []
        data_lower = data.lower()
        
        for protocol, indicators in cls.PROTOCOL_INDICATORS.items():
            for indicator in indicators:
                if indicator.lower() in data_lower:
                    detected.append(protocol)
                    break
        
        return detected

class SuspiciousPatterns:
    """Centralized suspicious activity patterns"""
    
    MALWARE_INDICATORS = [
        b'backdoor', b'keylogger', b'trojan', b'virus', b'malware',
        b'rootkit', b'botnet', b'exploit', b'payload', b'shellcode',
        b'mimikatz', b'pwdump', b'fgdump', b'gsecdump',
    ]
    
    ATTACK_PATTERNS = [
        b'../../../', b'..\\..\\..\\',  # Directory traversal
        b'<script', b'javascript:', b'eval(',  # XSS
        b'SELECT * FROM', b'UNION SELECT', b'DROP TABLE',  # SQL injection
        b'cmd.exe', b'/bin/sh', b'/bin/bash',  # Command injection
        b'AAAA' * 25,  # Buffer overflow pattern
    ]
    
    CRYPTO_INDICATORS = [
        b'AES', b'RSA', b'DES', b'MD5', b'SHA', b'encrypt', b'decrypt',
        b'cipher', b'crypto', b'hash', b'HMAC', b'PBKDF2',
    ]
    
    @classmethod
    def scan_for_threats(cls, data: bytes) -> Dict[str, List[int]]:
        """Scan data for threat indicators"""
        threats = {
            'malware': [],
            'attacks': [],
            'crypto': []
        }
        
        data_lower = data.lower()
        
        for pattern in cls.MALWARE_INDICATORS:
            pos = data_lower.find(pattern)
            if pos != -1:
                threats['malware'].append(pos)
        
        for pattern in cls.ATTACK_PATTERNS:
            pos = data_lower.find(pattern.lower())
            if pos != -1:
                threats['attacks'].append(pos)
        
        for pattern in cls.CRYPTO_INDICATORS:
            pos = data_lower.find(pattern.lower())
            if pos != -1:
                threats['crypto'].append(pos)
        
        return threats

class PatternUtils:
    """Utility functions for pattern matching"""
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
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
    
    @staticmethod
    def calculate_printable_ratio(data: bytes) -> float:
        """Calculate ratio of printable characters"""
        if not data:
            return 0.0
        
        printable_count = sum(1 for byte in data if 32 <= byte <= 126)
        return printable_count / len(data)
    
    @staticmethod
    def is_likely_text(data: bytes) -> bool:
        """Check if data is likely readable text"""
        try:
            text = data.decode('utf-8', errors='ignore')
            printable_ratio = sum(1 for c in text if c.isprintable()) / len(text) if text else 0
            return printable_ratio > 0.7
        except:
            return False
    
    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4) -> List[Dict[str, any]]:
        """Extract printable strings from binary data"""
        strings = []
        
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        for match in re.finditer(ascii_pattern, data):
            string_data = match.group().decode('ascii')
            strings.append({
                'type': 'ascii',
                'value': string_data,
                'offset': match.start(),
                'length': len(string_data)
            })
        
        # Unicode strings (UTF-16LE)
        unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        for match in re.finditer(unicode_pattern, data):
            try:
                string_data = match.group().decode('utf-16le')
                strings.append({
                    'type': 'unicode',
                    'value': string_data,
                    'offset': match.start(),
                    'length': len(string_data)
                })
            except:
                continue
        
        return strings