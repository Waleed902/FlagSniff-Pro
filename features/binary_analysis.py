#!/usr/bin/env python3
"""
Binary Analysis & Reverse Engineering Suite for FlagSniff Pro
Implements PE/ELF analysis, packer detection, and malware analysis
"""

import struct
import re
import hashlib
import os
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import binascii

class PEAnalyzer:
    """Portable Executable (PE) file analysis"""
    
    def __init__(self):
        self.packer_signatures = {
            'UPX': [b'UPX0', b'UPX1', b'UPX!'],
            'ASPack': [b'aPLib', b'.aspack'],
            'Themida': [b'.themida', b'Themida'],
            'VMProtect': [b'VMProtect', b'.vmp0', b'.vmp1'],
            'PECompact': [b'PECompact', b'pec1', b'pec2'],
            'FSG': [b'FSG!', b'fsg'],
            'MEW': [b'MEW', b'\x49\x6E\x74\x65\x72\x6E\x61\x6C'],
            'Petite': [b'petite', b'.petite']
        }
        
        self.anti_analysis_patterns = [
            b'IsDebuggerPresent',
            b'CheckRemoteDebuggerPresent',
            b'OutputDebugString',
            b'GetTickCount',
            b'QueryPerformanceCounter',
            b'cpuid',
            b'rdtsc'
        ]
    
    def analyze_pe(self, data: bytes) -> Dict[str, Any]:
        """Comprehensive PE file analysis"""
        if not self._is_pe_file(data):
            return {'error': 'Not a valid PE file'}
        
        analysis = {
            'file_type': 'PE',
            'size': len(data),
            'headers': {},
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': [],
            'strings': [],
            'packer_detection': {},
            'anti_analysis': [],
            'suspicious_indicators': []
        }
        
        try:
            # Parse DOS header
            dos_header = self._parse_dos_header(data)
            analysis['headers']['dos'] = dos_header
            
            # Parse PE header
            pe_offset = dos_header['e_lfanew']
            pe_header = self._parse_pe_header(data, pe_offset)
            analysis['headers']['pe'] = pe_header
            
            # Parse sections
            sections = self._parse_sections(data, pe_offset, pe_header)
            analysis['sections'] = sections
            
            # Extract strings
            analysis['strings'] = self._extract_strings(data)
            
            # Detect packers
            analysis['packer_detection'] = self._detect_packers(data, sections)
            
            # Detect anti-analysis techniques
            analysis['anti_analysis'] = self._detect_anti_analysis(data)
            
            # Parse imports/exports
            analysis['imports'] = self._parse_imports(data, pe_header, sections)
            analysis['exports'] = self._parse_exports(data, pe_header, sections)
            
            # Suspicious indicators
            analysis['suspicious_indicators'] = self._find_suspicious_indicators(analysis)
            
        except Exception as e:
            analysis['error'] = f'Analysis failed: {str(e)}'
        
        return analysis
    
    def _is_pe_file(self, data: bytes) -> bool:
        """Check if data is a valid PE file"""
        if len(data) < 64:
            return False
        
        # Check DOS signature
        if data[:2] != b'MZ':
            return False
        
        # Check PE signature
        try:
            pe_offset = struct.unpack('<L', data[60:64])[0]
            if pe_offset >= len(data) - 4:
                return False
            return data[pe_offset:pe_offset+4] == b'PE\x00\x00'
        except:
            return False
    
    def _parse_dos_header(self, data: bytes) -> Dict[str, Any]:
        """Parse DOS header"""
        dos_header = struct.unpack('<HHHHHHHHHHHHHHHH', data[:32])
        return {
            'e_magic': dos_header[0],
            'e_cblp': dos_header[1],
            'e_cp': dos_header[2],
            'e_crlc': dos_header[3],
            'e_cparhdr': dos_header[4],
            'e_minalloc': dos_header[5],
            'e_maxalloc': dos_header[6],
            'e_ss': dos_header[7],
            'e_sp': dos_header[8],
            'e_csum': dos_header[9],
            'e_ip': dos_header[10],
            'e_cs': dos_header[11],
            'e_lfarlc': dos_header[12],
            'e_ovno': dos_header[13],
            'e_lfanew': struct.unpack('<L', data[60:64])[0]
        }
    
    def _parse_pe_header(self, data: bytes, pe_offset: int) -> Dict[str, Any]:
        """Parse PE header"""
        # PE signature already verified
        coff_header = struct.unpack('<HHLLHH', data[pe_offset+4:pe_offset+24])
        
        optional_header_size = coff_header[4]
        optional_header_data = data[pe_offset+24:pe_offset+24+optional_header_size]
        
        # Parse optional header (simplified)
        magic = struct.unpack('<H', optional_header_data[:2])[0]
        is_64bit = magic == 0x20b
        
        return {
            'machine': coff_header[0],
            'number_of_sections': coff_header[1],
            'time_date_stamp': coff_header[2],
            'pointer_to_symbol_table': coff_header[3],
            'number_of_symbols': coff_header[4],
            'size_of_optional_header': coff_header[5],
            'characteristics': coff_header[6],
            'is_64bit': is_64bit,
            'magic': magic
        }
    
    def _parse_sections(self, data: bytes, pe_offset: int, pe_header: Dict) -> List[Dict[str, Any]]:
        """Parse section headers"""
        sections = []
        section_offset = pe_offset + 24 + pe_header['size_of_optional_header']
        
        for i in range(pe_header['number_of_sections']):
            section_data = data[section_offset + i*40:section_offset + (i+1)*40]
            if len(section_data) < 40:
                break
            
            section = struct.unpack('<8sLLLLLLHHL', section_data)
            sections.append({
                'name': section[0].rstrip(b'\x00').decode('utf-8', errors='ignore'),
                'virtual_size': section[1],
                'virtual_address': section[2],
                'size_of_raw_data': section[3],
                'pointer_to_raw_data': section[4],
                'pointer_to_relocations': section[5],
                'pointer_to_line_numbers': section[6],
                'number_of_relocations': section[7],
                'number_of_line_numbers': section[8],
                'characteristics': section[9]
            })
        
        return sections
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
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
        
        # Filter and sort by relevance
        filtered_strings = []
        for s in strings:
            # Skip very common/boring strings
            if any(boring in s['value'].lower() for boring in ['microsoft', 'windows', 'system32']):
                continue
            
            # Prioritize interesting strings
            score = 0
            interesting_keywords = ['flag', 'ctf', 'password', 'key', 'secret', 'admin', 'root']
            for keyword in interesting_keywords:
                if keyword in s['value'].lower():
                    score += 10
            
            if score > 0 or len(s['value']) > 20:
                s['score'] = score
                filtered_strings.append(s)
        
        return sorted(filtered_strings, key=lambda x: x.get('score', 0), reverse=True)[:50]
    
    def _detect_packers(self, data: bytes, sections: List[Dict]) -> Dict[str, Any]:
        """Detect known packers and obfuscators"""
        detected_packers = []
        
        # Signature-based detection
        for packer_name, signatures in self.packer_signatures.items():
            for signature in signatures:
                if signature in data:
                    detected_packers.append({
                        'name': packer_name,
                        'method': 'signature',
                        'confidence': 90
                    })
                    break
        
        # Heuristic detection
        if sections:
            # Check for suspicious section names
            section_names = [s['name'] for s in sections]
            suspicious_names = ['.upx', '.aspack', '.themida', '.vmp', '.fsg']
            
            for name in section_names:
                for suspicious in suspicious_names:
                    if suspicious in name.lower():
                        packer_name = suspicious[1:].upper()
                        detected_packers.append({
                            'name': packer_name,
                            'method': 'section_name',
                            'confidence': 80
                        })
            
            # Check entropy of sections (high entropy might indicate packing)
            for section in sections:
                if section['size_of_raw_data'] > 0:
                    section_data = data[section['pointer_to_raw_data']:
                                      section['pointer_to_raw_data'] + section['size_of_raw_data']]
                    entropy = self._calculate_entropy(section_data)
                    if entropy > 7.5:  # High entropy threshold
                        detected_packers.append({
                            'name': 'Unknown Packer',
                            'method': 'high_entropy',
                            'section': section['name'],
                            'entropy': entropy,
                            'confidence': 60
                        })
        
        return {
            'detected': detected_packers,
            'is_packed': len(detected_packers) > 0
        }
    
    def _detect_anti_analysis(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect anti-analysis and evasion techniques"""
        techniques = []
        
        for pattern in self.anti_analysis_patterns:
            if pattern in data:
                techniques.append({
                    'technique': pattern.decode('utf-8', errors='ignore'),
                    'type': 'api_call',
                    'description': self._get_anti_analysis_description(pattern)
                })
        
        return techniques
    
    def _get_anti_analysis_description(self, pattern: bytes) -> str:
        """Get description for anti-analysis technique"""
        descriptions = {
            b'IsDebuggerPresent': 'Checks if debugger is attached',
            b'CheckRemoteDebuggerPresent': 'Checks for remote debugger',
            b'OutputDebugString': 'Anti-debugging technique',
            b'GetTickCount': 'Timing-based evasion',
            b'QueryPerformanceCounter': 'High-resolution timing check',
            b'cpuid': 'VM detection via CPU features',
            b'rdtsc': 'Timing-based VM detection'
        }
        return descriptions.get(pattern, 'Unknown anti-analysis technique')
    
    def _parse_imports(self, data: bytes, pe_header: Dict, sections: List[Dict]) -> List[Dict[str, Any]]:
        """Parse import table (simplified)"""
        # This is a simplified implementation
        # Full implementation would require parsing the import directory
        imports = []
        
        # Look for common API calls in strings
        api_patterns = [
            'CreateFile', 'WriteFile', 'ReadFile', 'RegOpenKey', 'RegSetValue',
            'CreateProcess', 'VirtualAlloc', 'LoadLibrary', 'GetProcAddress'
        ]
        
        for string_info in self._extract_strings(data):
            for api in api_patterns:
                if api in string_info['value']:
                    imports.append({
                        'function': api,
                        'library': 'Unknown',
                        'offset': string_info['offset']
                    })
        
        return imports[:20]  # Limit results
    
    def _parse_exports(self, data: bytes, pe_header: Dict, sections: List[Dict]) -> List[Dict[str, Any]]:
        """Parse export table (simplified)"""
        # Simplified implementation
        return []
    
    def _find_suspicious_indicators(self, analysis: Dict) -> List[Dict[str, Any]]:
        """Find suspicious indicators in the analysis"""
        indicators = []
        
        # Check for suspicious strings
        for string_info in analysis.get('strings', []):
            suspicious_keywords = ['backdoor', 'keylog', 'steal', 'inject', 'hook', 'rootkit']
            for keyword in suspicious_keywords:
                if keyword in string_info['value'].lower():
                    indicators.append({
                        'type': 'suspicious_string',
                        'value': string_info['value'],
                        'keyword': keyword,
                        'severity': 'high'
                    })
        
        # Check for packer detection
        if analysis.get('packer_detection', {}).get('is_packed'):
            indicators.append({
                'type': 'packed_executable',
                'description': 'File appears to be packed or obfuscated',
                'severity': 'medium'
            })
        
        # Check for anti-analysis techniques
        if analysis.get('anti_analysis'):
            indicators.append({
                'type': 'anti_analysis',
                'description': 'Contains anti-debugging/analysis techniques',
                'count': len(analysis['anti_analysis']),
                'severity': 'high'
            })
        
        return indicators
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy

class ELFAnalyzer:
    """ELF (Executable and Linkable Format) file analysis"""
    
    def analyze_elf(self, data: bytes) -> Dict[str, Any]:
        """Analyze ELF file"""
        if not self._is_elf_file(data):
            return {'error': 'Not a valid ELF file'}
        
        analysis = {
            'file_type': 'ELF',
            'size': len(data),
            'header': {},
            'sections': [],
            'strings': [],
            'suspicious_indicators': []
        }
        
        try:
            # Parse ELF header
            analysis['header'] = self._parse_elf_header(data)
            
            # Extract strings
            analysis['strings'] = self._extract_strings(data)
            
            # Find suspicious indicators
            analysis['suspicious_indicators'] = self._find_elf_suspicious_indicators(analysis)
            
        except Exception as e:
            analysis['error'] = f'Analysis failed: {str(e)}'
        
        return analysis
    
    def _is_elf_file(self, data: bytes) -> bool:
        """Check if data is a valid ELF file"""
        return len(data) >= 16 and data[:4] == b'\x7fELF'
    
    def _parse_elf_header(self, data: bytes) -> Dict[str, Any]:
        """Parse ELF header"""
        header = {
            'magic': data[:4],
            'class': data[4],  # 1=32-bit, 2=64-bit
            'data': data[5],   # 1=little-endian, 2=big-endian
            'version': data[6],
            'os_abi': data[7],
            'abi_version': data[8]
        }
        
        # Parse rest of header based on class
        if header['class'] == 1:  # 32-bit
            fmt = '<HHLLLLHHHHHH'
            offset = 16
        else:  # 64-bit
            fmt = '<HHLQQQLHHHHHH'
            offset = 16
        
        try:
            parsed = struct.unpack(fmt, data[offset:offset + struct.calcsize(fmt)])
            header.update({
                'type': parsed[0],
                'machine': parsed[1],
                'version2': parsed[2],
                'entry': parsed[3],
                'phoff': parsed[4],
                'shoff': parsed[5],
                'flags': parsed[6],
                'ehsize': parsed[7],
                'phentsize': parsed[8],
                'phnum': parsed[9],
                'shentsize': parsed[10],
                'shnum': parsed[11],
                'shstrndx': parsed[12]
            })
        except:
            pass
        
        return header
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """Extract strings from ELF file"""
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
        
        # Filter interesting strings
        filtered_strings = []
        for s in strings:
            score = 0
            interesting_keywords = ['flag', 'ctf', 'password', 'key', 'secret', '/bin/', '/etc/']
            for keyword in interesting_keywords:
                if keyword in s['value'].lower():
                    score += 10
            
            if score > 0 or len(s['value']) > 15:
                s['score'] = score
                filtered_strings.append(s)
        
        return sorted(filtered_strings, key=lambda x: x.get('score', 0), reverse=True)[:30]
    
    def _find_elf_suspicious_indicators(self, analysis: Dict) -> List[Dict[str, Any]]:
        """Find suspicious indicators in ELF analysis"""
        indicators = []
        
        # Check for suspicious strings
        for string_info in analysis.get('strings', []):
            suspicious_keywords = ['backdoor', 'rootkit', '/tmp/', 'chmod 777', 'nc -l']
            for keyword in suspicious_keywords:
                if keyword in string_info['value'].lower():
                    indicators.append({
                        'type': 'suspicious_string',
                        'value': string_info['value'],
                        'keyword': keyword,
                        'severity': 'high'
                    })
        
        return indicators

class YARAEngine:
    """YARA rule engine for malware detection"""
    
    def __init__(self):
        # Simple built-in rules for common malware patterns
        self.builtin_rules = {
            'suspicious_strings': [
                b'backdoor', b'keylogger', b'trojan', b'virus', b'malware',
                b'rootkit', b'botnet', b'exploit', b'payload', b'shellcode'
            ],
            'crypto_patterns': [
                b'AES', b'RSA', b'DES', b'MD5', b'SHA', b'encrypt', b'decrypt',
                b'cipher', b'crypto', b'hash'
            ],
            'network_patterns': [
                b'socket', b'connect', b'bind', b'listen', b'send', b'recv',
                b'HTTP', b'TCP', b'UDP', b'IP'
            ]
        }
    
    def scan_data(self, data: bytes) -> Dict[str, Any]:
        """Scan data with built-in YARA-like rules"""
        matches = {
            'suspicious_strings': [],
            'crypto_patterns': [],
            'network_patterns': [],
            'total_matches': 0
        }
        
        for category, patterns in self.builtin_rules.items():
            for pattern in patterns:
                if pattern in data.lower():
                    matches[category].append({
                        'pattern': pattern.decode('utf-8', errors='ignore'),
                        'offset': data.lower().find(pattern)
                    })
                    matches['total_matches'] += 1
        
        return matches

class BinaryAnalysisEngine:
    """Main binary analysis engine"""
    
    def __init__(self):
        self.pe_analyzer = PEAnalyzer()
        self.elf_analyzer = ELFAnalyzer()
        self.yara_engine = YARAEngine()
    
    def analyze_binary(self, data: bytes, filename: str = None) -> Dict[str, Any]:
        """Comprehensive binary analysis"""
        analysis = {
            'filename': filename,
            'size': len(data),
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
            'file_type': 'unknown',
            'analysis': {},
            'yara_matches': {},
            'entropy': self._calculate_entropy(data)
        }
        
        # Determine file type and analyze accordingly
        if data[:2] == b'MZ':  # PE file
            analysis['file_type'] = 'PE'
            analysis['analysis'] = self.pe_analyzer.analyze_pe(data)
        elif data[:4] == b'\x7fELF':  # ELF file
            analysis['file_type'] = 'ELF'
            analysis['analysis'] = self.elf_analyzer.analyze_elf(data)
        else:
            # Generic binary analysis
            analysis['analysis'] = self._generic_binary_analysis(data)
        
        # YARA scanning
        analysis['yara_matches'] = self.yara_engine.scan_data(data)
        
        return analysis
    
    def _generic_binary_analysis(self, data: bytes) -> Dict[str, Any]:
        """Generic analysis for unknown binary formats"""
        return {
            'strings': self._extract_generic_strings(data),
            'entropy_analysis': self._analyze_entropy_distribution(data),
            'file_signatures': self._detect_file_signatures(data)
        }
    
    def _extract_generic_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract strings from generic binary data"""
        strings = []
        
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        for match in re.finditer(ascii_pattern, data):
            strings.append(match.group().decode('ascii'))
        
        return strings[:50]  # Limit results
    
    def _analyze_entropy_distribution(self, data: bytes, block_size: int = 1024) -> List[float]:
        """Analyze entropy distribution across file blocks"""
        entropies = []
        
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            if len(block) > 0:
                entropies.append(self._calculate_entropy(block))
        
        return entropies
    
    def _detect_file_signatures(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect embedded file signatures"""
        signatures = {
            'ZIP': b'PK\x03\x04',
            'RAR': b'Rar!\x1a\x07\x00',
            'PDF': b'%PDF',
            'JPEG': b'\xff\xd8\xff',
            'PNG': b'\x89PNG\r\n\x1a\n',
            'GIF': b'GIF8',
            'BMP': b'BM'
        }
        
        detected = []
        for file_type, signature in signatures.items():
            offset = data.find(signature)
            if offset != -1:
                detected.append({
                    'type': file_type,
                    'offset': offset,
                    'signature': signature.hex()
                })
        
        return detected
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy