#!/usr/bin/env python3
"""
Memory Forensics Integration for FlagSniff Pro
Implements memory analysis, process reconstruction, and credential recovery
"""

import struct
import re
import hashlib
import base64
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import json

class ProcessReconstructor:
    """Reconstruct process memory from network captures"""
    
    def __init__(self):
        self.process_patterns = {
            'windows_exe': rb'MZ[\x00-\xFF]{58}PE\x00\x00',
            'elf_binary': rb'\x7fELF',
            'dll_library': rb'MZ[\x00-\xFF]*\.dll',
            'java_class': rb'\xca\xfe\xba\xbe'
        }
        
        self.memory_patterns = {
            'heap_header': rb'HEAP',
            'stack_frame': rb'\x55\x8b\xec',  # Common function prologue
            'pe_header': rb'PE\x00\x00',
            'dll_export': rb'EXPORT'
        }
    
    def reconstruct_from_packets(self, packet_data: List[bytes]) -> Dict[str, Any]:
        """Reconstruct process memory from packet payloads"""
        reconstruction = {
            'total_data': 0,
            'processes': [],
            'memory_regions': [],
            'executables': [],
            'libraries': [],
            'heap_analysis': {},
            'stack_analysis': {}
        }
        
        # Combine all packet data
        combined_data = b''.join(packet_data)
        reconstruction['total_data'] = len(combined_data)
        
        # Look for executable patterns
        reconstruction['executables'] = self._find_executables(combined_data)
        
        # Look for library patterns
        reconstruction['libraries'] = self._find_libraries(combined_data)
        
        # Analyze memory structures
        reconstruction['memory_regions'] = self._analyze_memory_regions(combined_data)
        
        # Heap analysis
        reconstruction['heap_analysis'] = self._analyze_heap_structures(combined_data)
        
        # Stack analysis
        reconstruction['stack_analysis'] = self._analyze_stack_structures(combined_data)
        
        return reconstruction
    
    def _find_executables(self, data: bytes) -> List[Dict[str, Any]]:
        """Find executable files in memory data"""
        executables = []
        
        for pattern_name, pattern in self.process_patterns.items():
            for match in re.finditer(pattern, data):
                exe_info = {
                    'type': pattern_name,
                    'offset': match.start(),
                    'size': self._estimate_executable_size(data, match.start()),
                    'md5': None,
                    'analysis': {}
                }
                
                # Extract executable data
                exe_data = data[match.start():match.start() + exe_info['size']]
                exe_info['md5'] = hashlib.md5(exe_data).hexdigest()
                
                # Basic analysis
                if pattern_name in ['windows_exe', 'dll_library']:
                    exe_info['analysis'] = self._analyze_pe_in_memory(exe_data)
                elif pattern_name == 'elf_binary':
                    exe_info['analysis'] = self._analyze_elf_in_memory(exe_data)
                
                executables.append(exe_info)
        
        return executables
    
    def _find_libraries(self, data: bytes) -> List[Dict[str, Any]]:
        """Find loaded libraries in memory"""
        libraries = []
        
        # Look for DLL names and paths
        dll_pattern = rb'[A-Za-z]:\\[^\\/:*?"<>|\r\n]*\.dll'
        for match in re.finditer(dll_pattern, data, re.IGNORECASE):
            try:
                dll_path = match.group().decode('utf-8', errors='ignore')
                libraries.append({
                    'path': dll_path,
                    'offset': match.start(),
                    'type': 'dll_path'
                })
            except:
                continue
        
        # Look for common library names
        common_libs = [b'kernel32.dll', b'ntdll.dll', b'user32.dll', b'advapi32.dll']
        for lib in common_libs:
            if lib in data:
                libraries.append({
                    'name': lib.decode('utf-8'),
                    'offset': data.find(lib),
                    'type': 'system_library'
                })
        
        return libraries
    
    def _analyze_memory_regions(self, data: bytes) -> List[Dict[str, Any]]:
        """Analyze memory regions and their characteristics"""
        regions = []
        block_size = 4096  # Standard page size
        
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            if len(block) < block_size:
                continue
            
            region = {
                'offset': i,
                'size': len(block),
                'entropy': self._calculate_entropy(block),
                'null_bytes': block.count(b'\x00'),
                'printable_ratio': self._calculate_printable_ratio(block),
                'type': 'unknown'
            }
            
            # Classify region type
            if region['null_bytes'] > block_size * 0.9:
                region['type'] = 'unallocated'
            elif region['entropy'] > 7.5:
                region['type'] = 'encrypted_or_compressed'
            elif region['printable_ratio'] > 0.8:
                region['type'] = 'text_data'
            elif any(pattern in block for pattern in [b'MZ', b'PE\x00\x00']):
                region['type'] = 'executable_code'
            
            regions.append(region)
        
        return regions
    
    def _analyze_heap_structures(self, data: bytes) -> Dict[str, Any]:
        """Analyze heap structures for buffer overflows and corruption"""
        heap_analysis = {
            'heap_blocks': [],
            'potential_overflows': [],
            'use_after_free': [],
            'heap_spray': []
        }
        
        # Look for heap block headers (simplified)
        heap_pattern = rb'HEAP|_HEAP'
        for match in re.finditer(heap_pattern, data):
            heap_analysis['heap_blocks'].append({
                'offset': match.start(),
                'type': 'heap_header'
            })
        
        # Look for potential buffer overflow patterns
        overflow_patterns = [
            rb'A' * 100,  # Long sequences of same character
            rb'\x41' * 50,  # Hex representation
            rb'%s' * 20,   # Format string patterns
        ]
        
        for pattern in overflow_patterns:
            for match in re.finditer(pattern, data):
                heap_analysis['potential_overflows'].append({
                    'offset': match.start(),
                    'pattern': pattern[:20],
                    'length': len(match.group())
                })
        
        return heap_analysis
    
    def _analyze_stack_structures(self, data: bytes) -> Dict[str, Any]:
        """Analyze stack structures for ROP chains and manipulation"""
        stack_analysis = {
            'stack_frames': [],
            'return_addresses': [],
            'rop_gadgets': [],
            'stack_cookies': []
        }
        
        # Look for function prologues (stack frame setup)
        prologue_patterns = [
            rb'\x55\x8b\xec',      # push ebp; mov ebp, esp
            rb'\x48\x89\xe5',      # mov rbp, rsp (x64)
            rb'\x55\x48\x89\xe5'   # push rbp; mov rbp, rsp (x64)
        ]
        
        for pattern in prologue_patterns:
            for match in re.finditer(pattern, data):
                stack_analysis['stack_frames'].append({
                    'offset': match.start(),
                    'type': 'function_prologue',
                    'architecture': 'x64' if b'\x48' in pattern else 'x86'
                })
        
        # Look for potential ROP gadgets
        rop_patterns = [
            rb'\xc3',              # ret
            rb'\x5d\xc3',          # pop ebp; ret
            rb'\x58\xc3',          # pop eax; ret
        ]
        
        for pattern in rop_patterns:
            for match in re.finditer(pattern, data):
                stack_analysis['rop_gadgets'].append({
                    'offset': match.start(),
                    'gadget': pattern.hex(),
                    'type': 'potential_rop'
                })
        
        return stack_analysis
    
    def _estimate_executable_size(self, data: bytes, offset: int) -> int:
        """Estimate size of executable in memory"""
        # Simple heuristic: look for next major structure or end of data
        max_size = min(len(data) - offset, 1024 * 1024)  # Max 1MB
        
        # Look for PE sections or other indicators
        if offset + 64 < len(data):
            try:
                # Try to read PE header if it's a PE file
                if data[offset:offset+2] == b'MZ':
                    pe_offset = struct.unpack('<L', data[offset+60:offset+64])[0]
                    if offset + pe_offset + 24 < len(data):
                        # Read size from optional header
                        return min(max_size, 64 * 1024)  # Default to 64KB
            except:
                pass
        
        return min(max_size, 32 * 1024)  # Default to 32KB
    
    def _analyze_pe_in_memory(self, data: bytes) -> Dict[str, Any]:
        """Analyze PE file found in memory"""
        analysis = {
            'is_valid_pe': False,
            'sections': [],
            'imports': [],
            'suspicious_indicators': []
        }
        
        try:
            if len(data) > 64 and data[:2] == b'MZ':
                pe_offset = struct.unpack('<L', data[60:64])[0]
                if pe_offset < len(data) - 4 and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    analysis['is_valid_pe'] = True
                    
                    # Basic PE analysis
                    analysis['sections'] = self._extract_pe_sections_from_memory(data, pe_offset)
                    analysis['imports'] = self._extract_pe_imports_from_memory(data)
        except:
            pass
        
        return analysis
    
    def _analyze_elf_in_memory(self, data: bytes) -> Dict[str, Any]:
        """Analyze ELF file found in memory"""
        analysis = {
            'is_valid_elf': False,
            'architecture': 'unknown',
            'sections': []
        }
        
        if len(data) > 16 and data[:4] == b'\x7fELF':
            analysis['is_valid_elf'] = True
            analysis['architecture'] = '64-bit' if data[4] == 2 else '32-bit'
        
        return analysis
    
    def _extract_pe_sections_from_memory(self, data: bytes, pe_offset: int) -> List[Dict[str, Any]]:
        """Extract PE sections from memory image"""
        sections = []
        
        try:
            # Read COFF header
            coff_header = struct.unpack('<HHLLHH', data[pe_offset+4:pe_offset+24])
            num_sections = coff_header[1]
            optional_header_size = coff_header[4]
            
            # Section headers start after optional header
            section_offset = pe_offset + 24 + optional_header_size
            
            for i in range(min(num_sections, 10)):  # Limit to 10 sections
                section_data = data[section_offset + i*40:section_offset + (i+1)*40]
                if len(section_data) >= 40:
                    section = struct.unpack('<8sLLLLLLHHL', section_data)
                    sections.append({
                        'name': section[0].rstrip(b'\x00').decode('utf-8', errors='ignore'),
                        'virtual_size': section[1],
                        'virtual_address': section[2],
                        'characteristics': section[9]
                    })
        except:
            pass
        
        return sections
    
    def _extract_pe_imports_from_memory(self, data: bytes) -> List[str]:
        """Extract import information from PE in memory"""
        imports = []
        
        # Look for common API names
        api_names = [
            b'CreateFileA', b'CreateFileW', b'WriteFile', b'ReadFile',
            b'RegOpenKeyA', b'RegSetValueA', b'CreateProcessA',
            b'VirtualAlloc', b'LoadLibraryA', b'GetProcAddress'
        ]
        
        for api in api_names:
            if api in data:
                imports.append(api.decode('utf-8'))
        
        return imports
    
    def _calculate_entropy(self, data: bytes) -> float:
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
    
    def _calculate_printable_ratio(self, data: bytes) -> float:
        """Calculate ratio of printable characters"""
        if not data:
            return 0.0
        
        printable_count = sum(1 for byte in data if 32 <= byte <= 126)
        return printable_count / len(data)

class CredentialRecovery:
    """Credential recovery from memory dumps and network data"""
    
    def __init__(self):
        self.credential_patterns = {
            'windows_passwords': [
                rb'password[:\s=]+([^\s\r\n]+)',
                rb'pwd[:\s=]+([^\s\r\n]+)',
                rb'pass[:\s=]+([^\s\r\n]+)'
            ],
            'ssh_keys': [
                rb'-----BEGIN RSA PRIVATE KEY-----',
                rb'-----BEGIN OPENSSH PRIVATE KEY-----',
                rb'ssh-rsa AAAA[A-Za-z0-9+/]+'
            ],
            'certificates': [
                rb'-----BEGIN CERTIFICATE-----',
                rb'-----BEGIN PRIVATE KEY-----'
            ],
            'browser_data': [
                rb'Login Data',
                rb'Web Data',
                rb'Cookies'
            ]
        }
        
        self.hash_patterns = {
            'ntlm': rb'[a-fA-F0-9]{32}',
            'md5': rb'[a-fA-F0-9]{32}',
            'sha1': rb'[a-fA-F0-9]{40}',
            'sha256': rb'[a-fA-F0-9]{64}'
        }
    
    def extract_credentials(self, data: bytes) -> Dict[str, Any]:
        """Extract credentials from memory or network data"""
        credentials = {
            'passwords': [],
            'hashes': [],
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
        
        # Extract SSH keys
        credentials['ssh_keys'] = self._extract_ssh_keys(data)
        
        # Extract certificates
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
        
        for pattern in self.credential_patterns['windows_passwords']:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                try:
                    password = match.group(1).decode('utf-8', errors='ignore')
                    if len(password) > 3 and len(password) < 100:
                        passwords.append({
                            'password': password,
                            'offset': match.start(),
                            'context': data[max(0, match.start()-20):match.end()+20].decode('utf-8', errors='ignore')
                        })
                except:
                    continue
        
        return passwords
    
    def _extract_hashes(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract password hashes"""
        hashes = []
        
        for hash_type, pattern in self.hash_patterns.items():
            for match in re.finditer(pattern, data):
                hash_value = match.group().decode('utf-8')
                hashes.append({
                    'type': hash_type,
                    'hash': hash_value,
                    'offset': match.start()
                })
        
        return hashes
    
    def _extract_ssh_keys(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract SSH keys and certificates"""
        keys = []
        
        for pattern in self.credential_patterns['ssh_keys']:
            for match in re.finditer(pattern, data):
                key_data = match.group().decode('utf-8', errors='ignore')
                keys.append({
                    'type': 'ssh_key',
                    'key': key_data[:200] + '...' if len(key_data) > 200 else key_data,
                    'offset': match.start()
                })
        
        return keys
    
    def _extract_certificates(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract X.509 certificates"""
        certificates = []
        
        for pattern in self.credential_patterns['certificates']:
            for match in re.finditer(pattern, data):
                cert_data = match.group().decode('utf-8', errors='ignore')
                certificates.append({
                    'type': 'certificate',
                    'certificate': cert_data[:200] + '...' if len(cert_data) > 200 else cert_data,
                    'offset': match.start()
                })
        
        return certificates
    
    def _extract_browser_data(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract browser credential data"""
        browser_data = []
        
        # Look for Chrome/Firefox login data
        login_patterns = [
            rb'origin_url.*username_value.*password_value',
            rb'formSubmitURL.*usernameField.*passwordField'
        ]
        
        for pattern in login_patterns:
            for match in re.finditer(pattern, data, re.DOTALL):
                browser_data.append({
                    'type': 'browser_login',
                    'data': match.group()[:100].decode('utf-8', errors='ignore'),
                    'offset': match.start()
                })
        
        return browser_data
    
    def _extract_wifi_credentials(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract WiFi credentials"""
        wifi_creds = []
        
        # Look for WiFi profile data
        wifi_patterns = [
            rb'<name>([^<]+)</name>.*<keyMaterial>([^<]+)</keyMaterial>',
            rb'SSID.*PSK.*'
        ]
        
        for pattern in wifi_patterns:
            for match in re.finditer(pattern, data, re.DOTALL | re.IGNORECASE):
                wifi_creds.append({
                    'type': 'wifi_credential',
                    'data': match.group().decode('utf-8', errors='ignore'),
                    'offset': match.start()
                })
        
        return wifi_creds
    
    def _extract_application_secrets(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract application-specific secrets"""
        secrets = []
        
        # Common secret patterns
        secret_patterns = [
            rb'api[_-]?key[:\s=]+([A-Za-z0-9+/]{20,})',
            rb'secret[_-]?key[:\s=]+([A-Za-z0-9+/]{20,})',
            rb'token[:\s=]+([A-Za-z0-9+/]{20,})',
            rb'bearer[:\s]+([A-Za-z0-9+/]{20,})'
        ]
        
        for pattern in secret_patterns:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                try:
                    secret = match.group(1).decode('utf-8', errors='ignore')
                    secrets.append({
                        'type': 'api_secret',
                        'secret': secret[:50] + '...' if len(secret) > 50 else secret,
                        'offset': match.start()
                    })
                except:
                    continue
        
        return secrets

class MemoryForensicsEngine:
    """Main memory forensics engine"""
    
    def __init__(self):
        self.process_reconstructor = ProcessReconstructor()
        self.credential_recovery = CredentialRecovery()
    
    def analyze_memory_data(self, packet_payloads: List[bytes]) -> Dict[str, Any]:
        """Comprehensive memory forensics analysis"""
        analysis = {
            'total_packets': len(packet_payloads),
            'total_data_size': sum(len(payload) for payload in packet_payloads),
            'process_reconstruction': {},
            'credential_analysis': {},
            'memory_artifacts': {},
            'timeline': []
        }
        
        # Combine all packet data for analysis
        combined_data = b''.join(packet_payloads)
        
        # Process reconstruction
        analysis['process_reconstruction'] = self.process_reconstructor.reconstruct_from_packets(packet_payloads)
        
        # Credential recovery
        analysis['credential_analysis'] = self.credential_recovery.extract_credentials(combined_data)
        
        # Memory artifacts
        analysis['memory_artifacts'] = self._find_memory_artifacts(combined_data)
        
        # Build timeline
        analysis['timeline'] = self._build_memory_timeline(analysis)
        
        return analysis
    
    def _find_memory_artifacts(self, data: bytes) -> Dict[str, Any]:
        """Find various memory artifacts"""
        artifacts = {
            'registry_keys': [],
            'file_paths': [],
            'network_artifacts': [],
            'process_names': []
        }
        
        # Registry keys
        reg_patterns = [
            rb'HKEY_LOCAL_MACHINE\\[^\\]+(?:\\[^\\]+)*',
            rb'HKEY_CURRENT_USER\\[^\\]+(?:\\[^\\]+)*'
        ]
        
        for pattern in reg_patterns:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                try:
                    reg_key = match.group().decode('utf-8', errors='ignore')
                    artifacts['registry_keys'].append({
                        'key': reg_key,
                        'offset': match.start()
                    })
                except:
                    continue
        
        # File paths
        file_patterns = [
            rb'[A-Za-z]:\\[^\\/:*?"<>|\r\n]*\.[A-Za-z]{2,4}',
            rb'/[^/\s\r\n]*(?:/[^/\s\r\n]*)*\.[A-Za-z]{2,4}'
        ]
        
        for pattern in file_patterns:
            for match in re.finditer(pattern, data):
                try:
                    file_path = match.group().decode('utf-8', errors='ignore')
                    artifacts['file_paths'].append({
                        'path': file_path,
                        'offset': match.start()
                    })
                except:
                    continue
        
        # Network artifacts
        network_patterns = [
            rb'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
            rb'https?://[^\s\r\n]+'
        ]
        
        for pattern in network_patterns:
            for match in re.finditer(pattern, data):
                try:
                    network_item = match.group().decode('utf-8', errors='ignore')
                    artifacts['network_artifacts'].append({
                        'item': network_item,
                        'offset': match.start()
                    })
                except:
                    continue
        
        return artifacts
    
    def _build_memory_timeline(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build timeline of memory events"""
        timeline = []
        
        # Add process events
        for exe in analysis.get('process_reconstruction', {}).get('executables', []):
            timeline.append({
                'type': 'process_found',
                'offset': exe['offset'],
                'description': f"Found {exe['type']} at offset {exe['offset']}",
                'details': exe
            })
        
        # Add credential events
        for cred_type, creds in analysis.get('credential_analysis', {}).items():
            for cred in creds:
                if isinstance(cred, dict) and 'offset' in cred:
                    timeline.append({
                        'type': 'credential_found',
                        'offset': cred['offset'],
                        'description': f"Found {cred_type} at offset {cred['offset']}",
                        'details': cred
                    })
        
        # Sort by offset
        timeline.sort(key=lambda x: x['offset'])
        
        return timeline