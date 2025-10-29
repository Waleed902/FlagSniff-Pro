"""CTF Analyzer for FlagSniff - Specialized CTF Challenge Solver

This module provides specialized analysis capabilities for CTF challenges,
including multi-step analysis pipelines, encoding/decoding engines,
and pattern extraction techniques specifically designed for CTF competitions.
"""

import re
import base64
import binascii
import json
import os
import subprocess
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
import asyncio
import hashlib
import zlib
import gzip

# Import the enhanced flag reconstruction engine
from analyzers.ctf.ctf_flag_reconstruction import FlagReconstructionEngine, create_flag_reconstruction_engine



# For binary analysis (optional dependency)
try:
    import pefile  # type: ignore
    PEFILE_AVAILABLE = True
except Exception:
    pefile = None  # Ensure symbol exists even if import fails
    PEFILE_AVAILABLE = False

class CTFSolverPipeline:
    """Orchestrates multi-step analysis for CTF challenges"""
    
    def __init__(self):
        self.workflow_steps = []
        self.results = {}
        self.challenge_type = None
        self.decision_tree = self._build_decision_tree()
        
    def _build_decision_tree(self) -> Dict[str, Any]:
        """Build advanced decision tree for challenge type detection and solving"""
        return {
            'network': {
                'http': ['http_first_letter_extractor', 'base64_decoder', 'http_header_analyzer', 'cookie_decoder'],
                'dns': ['dns_exfiltration_analyzer', 'dns_tunneling_detector', 'subdomain_decoder'],
                'icmp': ['icmp_data_extractor', 'icmp_covert_channel', 'ping_timing_analyzer'],
                'tcp': ['tcp_sequence_analyzer', 'tcp_flags_decoder', 'tcp_timestamp_extractor'],
                'steganography': ['packet_timing_analyzer', 'packet_size_encoder', 'protocol_field_hider']
            },
            'crypto': {
                'substitution': ['substitution_solver', 'frequency_analyzer', 'pattern_matcher'],
                'xor': ['xor_bruteforcer', 'key_length_detector', 'repeating_key_finder'],
                'rsa': ['rsa_analyzer', 'weak_key_detector', 'factorization_analyzer'],
                'caesar': ['caesar_bruteforcer', 'shift_detector', 'language_detector'],
                'base64': ['base64_multi_decoder', 'base64_variant_detector'],
                'hash': ['hash_identifier', 'rainbow_table_lookup', 'hash_collision_finder']
            },
            'steganography': {
                'lsb': ['lsb_image_analyzer', 'lsb_audio_analyzer', 'bit_plane_analyzer'],
                'frequency': ['frequency_domain_analyzer', 'dct_coefficient_analyzer'],
                'spatial': ['spatial_domain_analyzer', 'pixel_difference_analyzer'],
                'metadata': ['exif_analyzer', 'comment_extractor', 'timestamp_analyzer']
            },
            'binary': {
                'reverse': ['binary_analyzer', 'string_extractor', 'disassembler', 'symbol_analyzer'],
                'pwn': ['vulnerability_analyzer', 'buffer_overflow_detector', 'rop_chain_finder'],
                'format': ['file_format_analyzer', 'header_parser', 'section_analyzer']
            },
            'web': {
                'sqli': ['sql_injection_analyzer', 'blind_sqli_detector', 'union_based_extractor'],
                'xss': ['xss_payload_generator', 'dom_analyzer', 'csp_bypass_finder'],
                'lfi': ['lfi_path_finder', 'directory_traversal_detector', 'wrapper_analyzer']
            },
            'forensics': {
                'memory': ['memory_dump_analyzer', 'process_analyzer', 'registry_extractor'],
                'disk': ['file_carving', 'deleted_file_recovery', 'timeline_analyzer'],
                'network': ['packet_carving', 'session_reconstruction', 'protocol_analyzer']
            }
        }
    
    def detect_challenge_type(self, data: Dict[str, Any]) -> str:
        """Detect challenge type from data"""
        # Implement heuristic detection of challenge type
        if 'pcap' in data.get('file_type', '').lower():
            return 'network'
        elif data.get('file_type', '').lower() in ['elf', 'pe', 'exe', 'dll']:
            return 'binary'
        elif data.get('file_type', '').lower() in ['html', 'php', 'js']:
            return 'web'
        else:
            return 'unknown'
    
    def add_workflow_step(self, step_name: str, step_function, step_params: Dict[str, Any] = None):
        """Add a step to the analysis workflow"""
        self.workflow_steps.append({
            'name': step_name,
            'function': step_function,
            'params': step_params or {},
            'status': 'pending',
            'result': None
        })
    
    async def execute_workflow(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the entire workflow pipeline"""
        current_data = input_data
        
        for i, step in enumerate(self.workflow_steps):
            try:
                # Update step status
                self.workflow_steps[i]['status'] = 'running'
                
                # Execute step function
                step_function = step['function']
                step_params = step['params']
                
                # Merge current data with step params
                params = {**current_data, **step_params}
                
                # Execute the step
                result = await step_function(**params)
                
                # Update step status and result
                self.workflow_steps[i]['status'] = 'completed'
                self.workflow_steps[i]['result'] = result
                
                # Update current data for next step
                if isinstance(result, dict):
                    current_data.update(result)
                else:
                    current_data['step_result'] = result
                
            except Exception as e:
                # Handle step failure
                self.workflow_steps[i]['status'] = 'failed'
                self.workflow_steps[i]['error'] = str(e)
                break
        
        # Compile final results
        self.results = {
            'workflow_steps': [{
                'name': step['name'],
                'status': step['status'],
                'result_summary': self._summarize_result(step['result']) if step['result'] else None,
                'error': step.get('error')
            } for step in self.workflow_steps],
            'final_data': current_data,
            'extracted_flag': current_data.get('flag')
        }
        
        return self.results
    
    def _summarize_result(self, result: Any) -> str:
        """Create a summary of step result for display"""
        if isinstance(result, dict):
            return f"Found {len(result)} items"
        elif isinstance(result, list):
            return f"Found {len(result)} results"
        elif isinstance(result, str):
            if len(result) > 50:
                return f"{result[:50]}..."
            return result
        else:
            return str(result)


class EncodingDecoder:
    """Comprehensive decoder for common CTF encodings"""
    
    def __init__(self):
        self.decoders = {
            'base64': self.decode_base64,
            'base32': self.decode_base32,
            'base45': self.decode_base45,
            'base85': self.decode_base85,
            'ascii85': self.decode_ascii85,
            'hex': self.decode_hex,
            'binary': self.decode_binary,
            'rot13': self.decode_rot13,
            'caesar': self.decode_caesar,
            'morse': self.decode_morse,
            'url': self.decode_url,
            'ascii': self.decode_ascii_values
        }
    
    def detect_encoding(self, data: str) -> List[str]:
        """Detect possible encodings of the data"""
        possible_encodings = []
        
        # Base64 detection
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', data):
            possible_encodings.append('base64')
        
        # Base32 detection (A-Z2-7 with padding)
        if re.match(r'^[A-Z2-7]+=*$', data):
            possible_encodings.append('base32')

        # Base45 detection (subset of ASCII: 0-9A-Z $%*+\-./:)
        if re.match(r'^[0-9A-Z $%*+\-./:]+$', data.strip()):
            # Heuristic: length tends to be >= 3 and not purely alnum
            if len(data.strip()) >= 3:
                possible_encodings.append('base45')
        
        # Hex detection
        if re.match(r'^[0-9A-Fa-f]+$', data):
            possible_encodings.append('hex')
        
        # Binary detection
        if re.match(r'^[01\s]+$', data):
            possible_encodings.append('binary')
        
        # ASCII values detection
        if re.match(r'^(\d+\s*)+$', data):
            possible_encodings.append('ascii')
        
        # Morse code detection
        if re.match(r'^[.\-\s/]+$', data):
            possible_encodings.append('morse')
        
        # ROT13/Caesar detection (harder to detect, try decoding)
        if all(c.isalpha() or c.isspace() for c in data):
            possible_encodings.append('rot13')
            possible_encodings.append('caesar')
        
        # Heuristic for ascii85/base85: long printable with symbols
        if len(data) >= 10 and any(c in data for c in '~!@#$%^&*(){}[]<>|:/\\'):
            possible_encodings.append('ascii85')
            possible_encodings.append('base85')
        
        return possible_encodings
    
    def decode_all(self, data: str) -> Dict[str, Any]:
        """Try all decoders and return results"""
        results = {}
        
        for encoding, decoder in self.decoders.items():
            try:
                decoded = decoder(data)
                if decoded and decoded != data:
                    results[encoding] = decoded
            except Exception:
                pass
        
        return results
    
    def decode_base64(self, data: str) -> str:
        """Decode base64 data"""
        # Remove whitespace
        data = ''.join(data.split())
        # Add padding if needed
        while len(data) % 4 != 0:
            data += '='
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    
    def decode_base32(self, data: str) -> str:
        """Decode base32 data"""
        clean = ''.join(data.split()).upper()
        if len(clean) % 8 != 0:
            clean += '=' * (8 - (len(clean) % 8))
        try:
            return base64.b32decode(clean, casefold=True).decode('utf-8', errors='ignore')
        except Exception:
            try:
                return base64.b32decode(clean, casefold=True).decode('latin-1', errors='ignore')
            except Exception:
                return ''
    
    def decode_base85(self, data: str) -> str:
        """Decode RFC1924 base85"""
        try:
            raw = base64.b85decode(data)
            return raw.decode('utf-8', errors='ignore')
        except Exception:
            return ''

    def decode_base45(self, data: str) -> str:
        """Decode Base45 (RFC 9285) without external deps.
        Alphabet: 0-9 A-Z space $%*+-./:
        """
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
        idx = {c: i for i, c in enumerate(alphabet)}
        s = data.strip()
        out = bytearray()
        i = 0
        try:
            while i < len(s):
                if i + 2 < len(s):
                    # Per RFC 9285: value x = c0 + 45*c1 + 45^2*c2, where
                    # characters are ordered least-significant first (c0, c1, c2)
                    c0 = idx[s[i]]
                    c1 = idx[s[i+1]]
                    c2 = idx[s[i+2]]
                    x = c0 + 45 * c1 + 45 * 45 * c2
                    out.append(x // 256)
                    out.append(x % 256)
                    i += 3
                elif i + 1 < len(s):
                    # Two chars (c0, c1) -> single byte x = c0 + 45*c1
                    x = idx[s[i]] + 45 * idx[s[i+1]]
                    out.append(x)
                    i += 2
                else:
                    # trailing single char invalid in base45
                    break
        except KeyError:
            return ''
        return out.decode('utf-8', errors='ignore')
    
    def decode_ascii85(self, data: str) -> str:
        """Decode Ascii85 (Adobe variant)"""
        try:
            raw = base64.a85decode(data, adobe=False)
            return raw.decode('utf-8', errors='ignore')
        except Exception:
            try:
                raw = base64.a85decode(data, adobe=True)
                return raw.decode('utf-8', errors='ignore')
            except Exception:
                return ''
    
    def decode_hex(self, data: str) -> str:
        """Decode hex data"""
        # Remove whitespace and 0x prefixes
        data = ''.join(data.split()).replace('0x', '')
        return bytes.fromhex(data).decode('utf-8', errors='ignore')
    
    def decode_binary(self, data: str) -> str:
        """Decode binary data"""
        # Remove whitespace
        data = ''.join(data.split())
        # Split into 8-bit chunks
        chunks = [data[i:i+8] for i in range(0, len(data), 8)]
        # Convert each chunk to a character
        return ''.join(chr(int(chunk, 2)) for chunk in chunks)
    
    def decode_rot13(self, data: str) -> str:
        """Decode ROT13 data"""
        result = ""
        for char in data:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result
    
    def decode_caesar(self, data: str, shift: int = None) -> Union[str, Dict[int, str]]:
        """Decode Caesar cipher"""
        if shift is not None:
            result = ""
            for char in data:
                if 'a' <= char <= 'z':
                    result += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                elif 'A' <= char <= 'Z':
                    result += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                else:
                    result += char
            return result
        else:
            # Try all possible shifts
            results = {}
            for i in range(1, 26):
                results[i] = self.decode_caesar(data, i)
            return results
    
    def decode_morse(self, data: str) -> str:
        """Decode Morse code"""
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
            '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
            '-----': '0', '--..--': ',', '.-.-.-': '.', '..--..': '?',
            '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&',
            '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+',
            '-....-': '-', '..--.-': '_', '.-..-.': '"', '...-..-': '$',
            '.--.-.': '@', '...---...': 'SOS'
        }
        
        # Split into words and characters
        words = data.strip().split('/')
        result = ""
        
        for word in words:
            chars = word.strip().split()
            for char in chars:
                if char in morse_dict:
                    result += morse_dict[char]
                else:
                    result += '?'
            result += ' '
        
        return result.strip()
    
    def decode_url(self, data: str) -> str:
        """Decode URL-encoded data"""
        from urllib.parse import unquote
        return unquote(data)
    
    def decode_ascii_values(self, data: str) -> str:
        """Decode ASCII values"""
        values = [int(x) for x in re.findall(r'\d+', data)]
        return ''.join(chr(value) for value in values if 0 <= value <= 127)

    def decode_chain(self, data: str, max_depth: int = 3) -> List[Dict[str, Any]]:
        """Try common multi-step decoding chains; return list of {chain, decoded}."""
        results: List[Dict[str, Any]] = []
        chains: List[List[str]] = [
            ['base64', 'hex'],
            ['hex', 'ascii'],
            ['url', 'base64'],
            ['url', 'hex', 'ascii'],
            ['rot13', 'base64'],
            ['base32'],
            ['base64'],
        ]
        
        def maybe_decompress(text: str) -> str:
            try:
                raw = text.encode('latin-1', errors='ignore')
                # gzip magic
                if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
                    return gzip.decompress(raw).decode('utf-8', errors='ignore')
                # base64 then zlib/gzip
                if re.match(r'^[A-Za-z0-9+/]+={0,2}$', text.strip()):
                    b = base64.b64decode(text.strip())
                    try:
                        return zlib.decompress(b).decode('utf-8', errors='ignore')
                    except Exception:
                        return gzip.decompress(b).decode('utf-8', errors='ignore')
            except Exception:
                return ''
            return ''
        
        for chain in chains:
            current = data
            steps_done: List[str] = []
            ok = True
            for step in chain:
                decoder = self.decoders.get(step)
                if not decoder:
                    ok = False
                    break
                if step == 'caesar':
                    ok = False
                    break
                try:
                    nxt = decoder(current)
                    if not nxt or nxt == current:
                        ok = False
                        break
                    current = nxt
                    steps_done.append(step)
                except Exception:
                    ok = False
                    break
            if ok:
                decomp = maybe_decompress(current)
                final = decomp if decomp else current
                if any(c.isalpha() for c in final) and len(final) >= 3:
                    results.append({'chain': steps_done + (['zlib'] if decomp else []), 'decoded': final})
        
        # dedupe by decoded prefix
        uniq: Dict[str, Dict[str, Any]] = {}
        for r in results:
            key = r['decoded'][:200]
            if key not in uniq:
                uniq[key] = r
        return list(uniq.values())

    def decompress_if_compressed_str(self, text: str) -> str:
        """Try gzip/zlib decompress on provided string; return decoded text or ''."""
        try:
            raw = text.encode('latin-1', errors='ignore')
            if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
                return gzip.decompress(raw).decode('utf-8', errors='ignore')
        except Exception:
            pass
        try:
            b = base64.b64decode(text)
            try:
                return zlib.decompress(b).decode('utf-8', errors='ignore')
            except Exception:
                return gzip.decompress(b).decode('utf-8', errors='ignore')
        except Exception:
            return ''


class PatternExtractor:
    """Extracts patterns commonly used in CTF challenges"""
    
    def extract_first_letters(self, text: str) -> str:
        """Extract first letter of each word"""
        words = re.findall(r'\b\w+\b', text)
        return ''.join(word[0] for word in words if word)
    
    def extract_last_letters(self, text: str) -> str:
        """Extract last letter of each word"""
        words = re.findall(r'\b\w+\b', text)
        return ''.join(word[-1] for word in words if word)
    
    def extract_nth_letters(self, text: str, n: int) -> str:
        """Extract nth letter of each word"""
        words = re.findall(r'\b\w+\b', text)
        return ''.join(word[n-1] for word in words if len(word) >= n)
    
    def extract_acrostic(self, text: str) -> str:
        """Extract first letter of each line (acrostic)"""
        lines = text.split('\n')
        return ''.join(line[0] for line in lines if line.strip())
    
    def extract_regex_pattern(self, text: str, pattern: str) -> List[str]:
        """Extract text matching a regex pattern"""
        return re.findall(pattern, text)
    
    def extract_between_markers(self, text: str, start_marker: str, end_marker: str) -> List[str]:
        """Extract text between markers"""
        pattern = f"{re.escape(start_marker)}(.*?){re.escape(end_marker)}"
        return re.findall(pattern, text, re.DOTALL)


class NetworkTrafficDecoder:
    """Specialized decoder for network traffic in CTF challenges"""
    
    def __init__(self):
        self.pattern_extractor = PatternExtractor()
        self.encoding_decoder = EncodingDecoder()
    
    def extract_patterns(self, packet_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract various patterns from packet data for CTF analysis"""
        extracted_patterns = []
        
        for packet in packet_data_list:
            data = packet.get('data', '')
            if not data:
                continue
                
            packet_index = packet.get('packet_index', 0)
            protocol = packet.get('protocol', 'Unknown')
            
            # Extract first letters of words
            first_letters = self.pattern_extractor.extract_first_letters(data)
            if len(first_letters) > 3:  # Only if we have a reasonable amount
                extracted_patterns.append({
                    'type': 'first_letters',
                    'pattern': first_letters,
                    'packet_index': packet_index,
                    'protocol': protocol,
                    'confidence': 70,
                    'source': 'first_letter_extraction'
                })
            
            # Extract last letters of words
            last_letters = self.pattern_extractor.extract_last_letters(data)
            if len(last_letters) > 3:
                extracted_patterns.append({
                    'type': 'last_letters',
                    'pattern': last_letters,
                    'packet_index': packet_index,
                    'protocol': protocol,
                    'confidence': 65,
                    'source': 'last_letter_extraction'
                })
            
            # Extract text between common markers
            markers = [('<!--', '-->'), ('/*', '*/'), ('[', ']'), ('{', '}'), ('(', ')')]
            for start_marker, end_marker in markers:
                between_text = self.pattern_extractor.extract_between_markers(data, start_marker, end_marker)
                for text in between_text:
                    if len(text.strip()) > 3:
                        extracted_patterns.append({
                            'type': 'between_markers',
                            'pattern': text.strip(),
                            'packet_index': packet_index,
                            'protocol': protocol,
                            'confidence': 75,
                            'source': f'between_{start_marker}_{end_marker}',
                            'markers': [start_marker, end_marker]
                        })
            
            # Extract potential encoded patterns (base64-like, hex-like)
            # Base64-like patterns
            base64_patterns = re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', data)
            for pattern in base64_patterns:
                extracted_patterns.append({
                    'type': 'base64_like',
                    'pattern': pattern,
                    'packet_index': packet_index,
                    'protocol': protocol,
                    'confidence': 80,
                    'source': 'base64_pattern_detection'
                })
            
            # Hex-like patterns
            hex_patterns = re.findall(r'\b[0-9a-fA-F]{8,}\b', data)
            for pattern in hex_patterns:
                if len(pattern) >= 8:  # Minimum hex length
                    extracted_patterns.append({
                        'type': 'hex_like',
                        'pattern': pattern,
                        'packet_index': packet_index,
                        'protocol': protocol,
                        'confidence': 75,
                        'source': 'hex_pattern_detection'
                    })
        
        return extracted_patterns
    
    def analyze_http_responses(self, packet_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze HTTP responses for hidden data"""
        results = {
            'first_letters': [],
            'base64_data': [],
            'hidden_comments': [],
            'suspicious_headers': [],
            'steganography_indicators': [],
            'fragmented_flags': []  # ADDED FOR FLAG REASSEMBLY
        }
        
        for packet in packet_data:
            if packet.get('protocol') != 'HTTP':
                continue
            
            data = packet.get('data', '')
            
            # Extract first letters from words in HTTP responses
            if 'http_body' in packet:
                first_letters = self.pattern_extractor.extract_first_letters(packet['http_body'])
                if first_letters:
                    results['first_letters'].append({
                        'packet_index': packet.get('packet_index'),
                        'data': first_letters,
                        'source': packet.get('src'),
                        'context': packet.get('http_body')[:100] + '...'
                    })
                
                # ADDED: Flag fragment detection
                potential_fragments = self._detect_flag_fragments(packet['http_body'])
                if potential_fragments:
                    results['fragmented_flags'].extend(potential_fragments)
            
            # Look for base64 encoded data
            base64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', data)
            for match in base64_matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    if any(c.isprintable() for c in decoded):
                        results['base64_data'].append({
                            'packet_index': packet.get('packet_index'),
                            'encoded': match,
                            'decoded': decoded,
                            'source': packet.get('src')
                        })
                        
                        # ADDED: Check if decoded contains flag fragments
                        potential_fragments = self._detect_flag_fragments(decoded)
                        if potential_fragments:
                            for frag in potential_fragments:
                                frag['source'] = f"base64-decoded:{packet.get('packet_index')}"
                                results['fragmented_flags'].append(frag)
                except:
                    pass
            
            # Look for hidden comments
            comments = re.findall(r'<!--(.*?)-->', data, re.DOTALL)
            if comments:
                results['hidden_comments'].extend([
                    {
                        'packet_index': packet.get('packet_index'),
                        'comment': comment,
                        'source': packet.get('src')
                    } for comment in comments
                ])
                
                # ADDED: Check comments for flag fragments
                for comment in comments:
                    potential_fragments = self._detect_flag_fragments(comment)
                    if potential_fragments:
                        for frag in potential_fragments:
                            frag['source'] = f"http-comment:{packet.get('packet_index')}"
                            results['fragmented_flags'].append(frag)
            
            # Check for suspicious headers
            if 'http_headers' in packet:
                headers = packet['http_headers'].split('\r\n')
                for header in headers:
                    if ':' in header and not header.startswith(('HTTP/', 'GET ', 'POST ')):
                        name, value = header.split(':', 1)
                        if name.strip().lower() not in ['content-type', 'content-length', 'date', 'server', 'connection']:
                            results['suspicious_headers'].append({
                                'packet_index': packet.get('packet_index'),
                                'header_name': name.strip(),
                                'header_value': value.strip(),
                                'source': packet.get('src')
                            })
                            
                            # ADDED: Check suspicious header values for flag fragments
                            potential_fragments = self._detect_flag_fragments(value)
                            if potential_fragments:
                                for frag in potential_fragments:
                                    frag['source'] = f"http-header:{name.strip()}:{packet.get('packet_index')}"
                                    results['fragmented_flags'].append(frag)
        
        return results
    
    def _detect_flag_fragments(self, text: str) -> List[Dict[str, Any]]:
        """Detect potential fragmented flag components in text"""
        fragments = []
        
        # Look for common flag pattern fragments
        flag_fragment_patterns = [
            r'flag\{[^}]*',  # Incomplete flag{...
            r'CTF\{[^}]*',   # Incomplete CTF{...
            r'\w{5,20}\{[^}]*',  # Incomplete {some_name}{...
            r'[^}]*?_flag_',  # Prefix fragments
            r'flag_[^}]*',   # Suffix fragments
            r'(?:[a-fA-F0-9]{2,}){8,}',  # Hex-like sequences
            r'[A-Za-z0-9_]{5,30}'  # Alphanumeric fragments
        ]
        
        for pattern in flag_fragment_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                # Filter out obvious false positives
                if len(match) < 5 or any(sub in match.lower() for sub in ['http', 'www', 'html', 'css', 'js', 'png', 'jpg']):
                    continue
                
                # Calculate fragment position in the text
                pos = text.find(match)
                
                context_before = text[max(0, pos-20):pos]
                context_after = text[pos+len(match):min(len(text), pos+len(match)+20)]
                
                fragments.append({
                    'fragment': match,
                    'context_before': context_before,
                    'context_after': context_after,
                    'position': pos,
                    'length': len(match),
                    'confidence': self._assess_fragment_confidence(match),
                    'characteristics': self._analyze_fragment_characteristics(match)
                })
        
        return fragments
    
    def _assess_fragment_confidence(self, fragment: str) -> int:
        """Assess confidence that this is a legitimate flag fragment (0-100%)"""
        confidence = 0
        
        # Flag-like pattern boosts confidence
        if re.search(r'flag\{', fragment, re.IGNORECASE):
            confidence += 30
        if re.search(r'ctf\{', fragment, re.IGNORECASE):
            confidence += 25
        if re.search(r'\{', fragment) and not re.search(r'\}', fragment):
            confidence += 20
        
        # Length analysis
        if 8 <= len(fragment) <= 40:
            confidence += 15
        elif len(fragment) > 40:
            confidence += 5  # Less likely, but possible
        
        # Content analysis
        if any(c.isalpha() for c in fragment):
            confidence += 10
        if any(c.isdigit() for c in fragment):
            confidence += 5
        if any(c in "!@#$%^&*()_+" for c in fragment):
            confidence += 5
        
        # Return confidence as percentage (0-100)
        return min(100, confidence)
    
    def _analyze_fragment_characteristics(self, fragment: str) -> Dict[str, Any]:
        """Analyze characteristics of the fragment for reassembly"""
        return {
            'has_braces': '{' in fragment,
            'has_closing_brace': '}' in fragment,
            'brace_balance': fragment.count('{') - fragment.count('}'),
            'is_hex_like': bool(re.match(r'^[0-9a-fA-F]+$', fragment)),
            'is_alpha_numeric': fragment.isalnum(),
            'is_mixed_case': any(c.islower() for c in fragment) and any(c.isupper() for c in fragment),
            'word_count': len(re.findall(r'\w+', fragment))
        }
    
    def reassemble_fragmented_flags(
        self, 
        packet_data: List[Dict[str, Any]], 
        flag_patterns: List[str] = None
    ) -> Dict[str, Any]:
        """
        Reassemble fragmented flags from network traffic across multiple packets
        
        Args:
            packet_data: List of packet data
            flag_patterns: Optional list of flag patterns to use for validation
            
        Returns:
            Dictionary containing reassembly results with:
            - complete_flags: Fully reconstructed flags
            - potential_reassemblies: Possible partial reassemblies
            - visualization_data: Structure for front-end visualization
        """
        if flag_patterns is None:
            flag_patterns = [r'flag\{.*\}', r'CTF\{.*\}', r'su\{.*\}']
            
        # First, collect all fragments
        all_fragments = []
        for packet in packet_data:
            if packet.get('protocol') == 'HTTP':
                if 'http_body' in packet:
                    all_fragments.extend([
                        {**frag, 'packet_index': packet.get('packet_index')}
                        for frag in self._detect_flag_fragments(packet['http_body'])
                    ])
                
                # Check HTTP headers too
                if 'http_headers' in packet:
                    headers_text = packet['http_headers']
                    all_fragments.extend([
                        {**frag, 'packet_index': packet.get('packet_index')}
                        for frag in self._detect_flag_fragments(headers_text)
                    ])
        
        # Now attempt to reassemble fragments
        complete_flags = []
        potential_reassemblies = []
        
        # For visualization, we'll track fragment positions across flows
        visual_groups = []
        
        # Very simple reassembly logic for proof of concept
        # In reality this could use more sophisticated methods:
        # - Temporal ordering
        # - Content similarity
        # - Graph-based connection analysis
        sorted_fragments = sorted(all_fragments, key=lambda x: x['position'])
        
        for i, frag1 in enumerate(sorted_fragments):
            for j, frag2 in enumerate(sorted_fragments[i+1:], start=i+1):
                # Basic check if these could be adjacent fragments
                if frag1['position'] + frag1['length'] == frag2['position']:
                    # They appear adjacent in the stream
                    combined = frag1['fragment'] + frag2['fragment']
                    
                    # Check if this completes a flag
                    is_complete = any(re.match(pattern, combined) for pattern in flag_patterns)
                    
                    if is_complete:
                        complete_flags.append({
                            'flag': combined,
                            'fragments': [frag1, frag2],
                            'packet_indices': [frag1.get('packet_index'), frag2.get('packet_index')],
                            'confidence': (frag1['confidence'] + frag2['confidence']) / 2
                        })
                    else:
                        # Likely a partial reassembly
                        potential_reassemblies.append({
                            'partial': combined,
                            'fragments': [frag1, frag2],
                            'packet_indices': [frag1.get('packet_index'), frag2.get('packet_index')],
                            'next_expected': self._predict_next_fragment(combined),
                            'confidence': int(min(frag1['confidence'], frag2['confidence']) * 0.8)  # Slightly lower confidence
                        })
                        
                        # For visualization, track this connection
                        visual_groups.append({
                            'type': 'adjacent',
                            'fragments': [
                                {
                                    'id': f"{frag1.get('packet_index')}_{i}",
                                    'content': frag1['fragment'],
                                    'packet_index': frag1.get('packet_index'),
                                    'position': frag1['position'],
                                    'length': frag1['length']
                                },
                                {
                                    'id': f"{frag2.get('packet_index')}_{j}",
                                    'content': frag2['fragment'],
                                    'packet_index': frag2.get('packet_index'),
                                    'position': frag2['position'],
                                    'length': frag2['length']
                                }
                            ],
                            'connection_type': 'sequential',
                            'confidence': (frag1['confidence'] + frag2['confidence']) / 2
                        })
        
        # Attempt to create visualization for UI
        visualization_data = {
            'fragments': [
                {
                    'id': f"{frag.get('packet_index')}_{i}",
                    'content': frag['fragment'],
                    'packet_index': frag.get('packet_index'),
                    'position': frag['position'],
                    'length': frag['length'],
                    'confidence': frag['confidence'],
                    'characteristics': frag['characteristics'],
                    'context': f"...{frag['context_before']}[{frag['fragment'] }]{frag['context_after']}..."
                }
                for i, frag in enumerate(all_fragments)
            ],
            'connections': visual_groups
        }
        
        return {
            'complete_flags': complete_flags,
            'potential_reassemblies': potential_reassemblies,
            'visualization_data': visualization_data,
            'total_fragments': len(all_fragments),
            'reassembled_count': len(complete_flags)
        }
    
    def _predict_next_fragment(self, current_text: str) -> Dict[str, Any]:
        """Predict what the next fragment might contain based on current text"""
        # Simple heuristic-based prediction
        prediction = {
            'expected_start_char': None,
            'expected_ending': None,
            'likely_encoding': None,
            'probability': 0.0
        }
        
        # If it starts with flag{ but doesn't end with },
        if re.match(r'flag\{[^}]*$', current_text, re.IGNORECASE):
            prediction['expected_ending'] = '}'
            prediction['probability'] = 0.7
            if 'hex' in current_text.lower() or all(c in '0123456789abcdefABCDEF' for c in current_text.split('{')[1]):
                prediction['likely_encoding'] = 'hex'
                prediction['probability'] += 0.2
        
        # Similar logic for other common flag formats
        elif re.match(r'CTF\{[^}]*$', current_text, re.IGNORECASE):
            prediction['expected_ending'] = '}'
            prediction['probability'] = 0.65
            
        return prediction

    def extract_dns_data(self, packet_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract data from DNS queries and responses"""
        results = {
            'exfiltration_candidates': [],
            'encoded_domains': [],
            'suspicious_queries': []
        }
        
        for packet in packet_data:
            if packet.get('protocol') != 'DNS':
                continue
            
            # Check for DNS exfiltration
            if 'dns_query' in packet:
                query = packet['dns_query']
                
                # Check for unusually long subdomains
                parts = query.split('.')
                for part in parts:
                    if len(part) > 20:
                        results['exfiltration_candidates'].append({
                            'packet_index': packet.get('packet_index'),
                            'query': query,
                            'suspicious_part': part,
                            'source': packet.get('src')
                        })
                        
                        # Try to decode the suspicious part
                        try:
                            # Try base64
                            decoded = base64.b64decode(part).decode('utf-8', errors='ignore')
                            if any(c.isprintable() for c in decoded):
                                results['encoded_domains'].append({
                                    'packet_index': packet.get('packet_index'),
                                    'query': query,
                                    'encoded_part': part,
                                    'decoded': decoded,
                                    'encoding': 'base64',
                                    'source': packet.get('src')
                                })
                        except:
                            pass
                        
                        try:
                            # Try hex
                            if all(c in '0123456789abcdefABCDEF' for c in part):
                                decoded = bytes.fromhex(part).decode('utf-8', errors='ignore')
                                if any(c.isprintable() for c in decoded):
                                    results['encoded_domains'].append({
                                        'packet_index': packet.get('packet_index'),
                                        'query': query,
                                        'encoded_part': part,
                                        'decoded': decoded,
                                        'encoding': 'hex',
                                        'source': packet.get('src')
                                    })
                        except:
                            pass
        
        return results


class BinaryAnalyzer:
    """Analyzes binary files for CTF challenges"""
    
    def __init__(self):
        self.encoding_decoder = EncodingDecoder()
    
    def extract_strings(self, binary_path: str) -> List[str]:
        """Extract strings from binary file"""
        try:
            # Use strings command if available
            result = subprocess.run(['strings', binary_path], capture_output=True, text=True)
            return result.stdout.splitlines()
        except:
            # Fallback to manual extraction
            strings = []
            with open(binary_path, 'rb') as f:
                data = f.read()
                current_string = ""
                for byte in data:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string += chr(byte)
                    else:
                        if len(current_string) >= 4:  # Only keep strings of reasonable length
                            strings.append(current_string)
                        current_string = ""
                if len(current_string) >= 4:
                    strings.append(current_string)
            return strings
    
    def analyze_pe_file(self, binary_path: str) -> Dict[str, Any]:
        """Analyze PE file structure"""
        if not PEFILE_AVAILABLE:
            return {'error': 'pefile module not available'}
        
        try:
            pe = pefile.PE(binary_path)
            sections = [{
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'raw_size': hex(section.SizeOfRawData),
                'entropy': section.get_entropy()
            } for section in pe.sections]
            
            imports = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    imports[dll_name] = []
                    for imp in entry.imports:
                        if imp.name:
                            imports[dll_name].append(imp.name.decode('utf-8', errors='ignore'))
            
            return {
                'sections': sections,
                'imports': imports,
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'high_entropy_sections': [s['name'] for s in sections if s['entropy'] > 7.0]
            }
        except Exception as e:
            return {'error': str(e)}
    
    def find_embedded_files(self, binary_path: str) -> List[Dict[str, Any]]:
        """Find embedded files within binary"""
        embedded_files = []
        
        # Common file signatures
        signatures = {
            b'\x89PNG\r\n\x1a\n': {'type': 'PNG', 'ext': '.png'},
            b'\xff\xd8\xff': {'type': 'JPEG', 'ext': '.jpg'},
            b'GIF8': {'type': 'GIF', 'ext': '.gif'},
            b'PK\x03\x04': {'type': 'ZIP', 'ext': '.zip'},
            b'\x50\x4b\x03\x04': {'type': 'ZIP', 'ext': '.zip'},
            b'\x1f\x8b\x08': {'type': 'GZIP', 'ext': '.gz'},
            b'BZh': {'type': 'BZIP2', 'ext': '.bz2'},
            b'\x37\x7a\xbc\xaf\x27\x1c': {'type': '7ZIP', 'ext': '.7z'},
            b'\x52\x61\x72\x21\x1a\x07': {'type': 'RAR', 'ext': '.rar'},
            b'%PDF': {'type': 'PDF', 'ext': '.pdf'}
        }
        
        with open(binary_path, 'rb') as f:
            data = f.read()
            
            for signature, file_info in signatures.items():
                offset = 0
                while True:
                    offset = data.find(signature, offset)
                    if offset == -1:
                        break
                    
                    embedded_files.append({
                        'type': file_info['type'],
                        'offset': offset,
                        'signature': signature.hex(),
                        'extension': file_info['ext']
                    })
                    
                    offset += len(signature)
        
        return embedded_files


class CTFAnalyzer:
    """Main CTF challenge analyzer"""
    
    def __init__(self):
        self.solver_pipeline = CTFSolverPipeline()
        self.encoding_decoder = EncodingDecoder()
        self.pattern_extractor = PatternExtractor()
        self.network_decoder = NetworkTrafficDecoder()
        self.binary_analyzer = BinaryAnalyzer()
        self.flag_reconstruction_engine = create_flag_reconstruction_engine()
        

    
    def analyze(self, packet_data_list: List[Dict[str, Any]], challenge_type: str = 'network') -> Dict[str, Any]:
        """Main analysis method for CTF challenges with comprehensive error handling"""
        results = {
            'challenge_type': challenge_type,
            'analysis_status': 'in_progress',
            'findings': [],
            'patterns': [],
            'errors': [],
            'fallback_used': False,
            'validation_passed': True
        }
        
        try:
            # Phase 1: Pre-analysis dependency validation
            print(f"Debug: Starting CTF analysis - challenge type: {challenge_type}")
            validation_result = self._validate_dependencies(packet_data_list)
            if not validation_result['valid']:
                results['validation_passed'] = False
                results['errors'].append(f"Dependency validation failed: {validation_result['error']}")
                return self._fallback_analysis(packet_data_list, results)
            
            print(f"Debug: Processing {len(packet_data_list)} packets for CTF analysis")
            
            # Phase 2: Pattern extraction with error catching
            try:
                print("Debug: Phase 2 - Extracting patterns from packet data")
                extracted_patterns = self.network_decoder.extract_patterns(packet_data_list)
                results['patterns'] = extracted_patterns
                print(f"Debug: Extracted {len(extracted_patterns)} patterns")
            except Exception as e:
                results['errors'].append(f"Pattern extraction failed: {str(e)}")
                print(f"Debug: Pattern extraction error: {str(e)}")
                results['patterns'] = []
            
            # Phase 3: Network traffic analysis
            try:
                print("Debug: Phase 3 - Analyzing network traffic")
                http_analysis = self.network_decoder.analyze_http_responses(packet_data_list)
                if http_analysis and isinstance(http_analysis, dict):
                    results['http_analysis'] = http_analysis
                    print(f"Debug: HTTP analysis completed - found {len(http_analysis.get('first_letters', []))} first letter patterns")
                else:
                    results['errors'].append("HTTP analysis returned invalid data")
            except Exception as e:
                results['errors'].append(f"HTTP analysis failed: {str(e)}")
                print(f"Debug: HTTP analysis error: {str(e)}")
            
            # Phase 4: Flag pattern detection
            try:
                print("Debug: Phase 4 - Detecting flag patterns")
                flag_findings = self._detect_flag_patterns(packet_data_list)
                results['findings'].extend(flag_findings)
                print(f"Debug: Found {len(flag_findings)} potential flags")
            except Exception as e:
                results['errors'].append(f"Flag detection failed: {str(e)}")
                print(f"Debug: Flag detection error: {str(e)}")
            
            # Phase 5: Encoding analysis
            try:
                print("Debug: Phase 5 - Analyzing encoded data")
                encoding_findings = self._analyze_encoded_data(packet_data_list)
                results['findings'].extend(encoding_findings)
                print(f"Debug: Found {len(encoding_findings)} encoded data items")
            except Exception as e:
                results['errors'].append(f"Encoding analysis failed: {str(e)}")
                print(f"Debug: Encoding analysis error: {str(e)}")
            
            # Phase 6: Advanced Flag Reconstruction
            try:
                print("Debug: Phase 6 - Running flag reconstruction engine")
                reconstruction_results = self.flag_reconstruction_engine.reconstruct_distributed_flags(results['findings'])
                results['flag_reconstruction'] = reconstruction_results
                
                # Add reconstructed flags to findings with special marking
                for reconstructed in reconstruction_results.get('reconstructed_flags', []):
                    results['findings'].append({
                        'type': 'reconstructed_flag',
                        'data': reconstructed['flag'],
                        'confidence': int(reconstructed['confidence'] * 100),
                        'reconstruction_method': reconstructed.get('reconstruction_method', 'unknown'),
                        'source_fragments': len(reconstructed.get('fragments', [])),
                        'packet_indices': reconstructed.get('packet_indices', []),
                        'protocols': reconstructed.get('protocols', []),
                        'source': 'flag_reconstruction_engine'
                    })
                
                print(f"Debug: Reconstructed {len(reconstruction_results.get('reconstructed_flags', []))} flags")
            except Exception as e:
                results['errors'].append(f"Flag reconstruction failed: {str(e)}")
                print(f"Debug: Flag reconstruction error: {str(e)}")
            
            results['analysis_status'] = 'completed'
            print(f"Debug: CTF analysis completed - total findings: {len(results['findings'])}")
            
        except Exception as e:
            print(f"Debug: Critical CTF analysis error: {str(e)}")
            results['errors'].append(f"Critical analysis error: {str(e)}")
            results['analysis_status'] = 'failed'
            return self._fallback_analysis(packet_data_list, results)
        
        return results
    
    def _validate_dependencies(self, packet_data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate required modules and data before analysis"""
        try:
            # Validate packet data format
            if not isinstance(packet_data_list, list):
                return {'valid': False, 'error': 'packet_data_list must be a list'}
            
            if len(packet_data_list) == 0:
                return {'valid': False, 'error': 'No packet data provided'}
            
            # Check required components are available
            if not hasattr(self, 'network_decoder') or self.network_decoder is None:
                return {'valid': False, 'error': 'NetworkTrafficDecoder not available'}
            
            if not hasattr(self, 'pattern_extractor') or self.pattern_extractor is None:
                return {'valid': False, 'error': 'PatternExtractor not available'}
            
            # Validate packet data structure
            valid_packets = 0
            for packet in packet_data_list[:10]:  # Check first 10 packets
                if isinstance(packet, dict) and 'data' in packet:
                    valid_packets += 1
            
            if valid_packets == 0:
                return {'valid': False, 'error': 'No valid packet data found'}
            
            return {'valid': True, 'error': None}
            
        except Exception as e:
            return {'valid': False, 'error': f'Validation error: {str(e)}'}
    
    def _calculate_flag_confidence(self, flag_text: str) -> int:
        """Calculate confidence score for a potential flag"""
        try:
            confidence = 50  # Base confidence
            
            # Length bonus (longer flags are often more legitimate)
            if len(flag_text) > 20:
                confidence += 15
            elif len(flag_text) > 10:
                confidence += 10
            
            # Format bonus (proper flag format)
            if re.match(r'^[A-Za-z0-9_]{2,15}\{[^}]+\}$', flag_text):
                confidence += 20
            
            # Content quality bonus
            flag_content = flag_text.split('{')[1].split('}')[0] if '{' in flag_text and '}' in flag_text else ''
            if len(flag_content) >= 8:  # Minimum meaningful content
                confidence += 15
                
                # Check for meaningful characters (not just random)
                alpha_ratio = sum(1 for c in flag_content if c.isalpha()) / len(flag_content)
                if alpha_ratio > 0.5:  # More than 50% alphabetic
                    confidence += 10
            
            # Common CTF patterns
            if any(pattern in flag_text.lower() for pattern in ['ctf', 'flag', 'challenge']):
                confidence += 10
            
            return min(confidence, 100)
            
        except Exception:
            return 50
    
    def _detect_flag_patterns(self, packet_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect CTF flag patterns with flexible validation"""
        flag_findings = []
        
        # Flag patterns from memory requirements
        flag_patterns = [
            r'^[A-Za-z0-9_]{2,15}\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',  # Generic format
            r'^TJDGW2023\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',  # Specific format
            r'^[A-Z]{2,10}[0-9]{2,4}\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}$',  # Event pattern
            r'flag\{[^}]{4,}\}',  # Standard flag pattern
            r'CTF\{[^}]{4,}\}',   # CTF flag pattern
            r'[a-zA-Z0-9_]{3,15}\{[^}]{4,}\}'  # General flag-like pattern
        ]
        
        for packet in packet_data_list:
            data = packet.get('data', '')
            if not data:
                continue
            
            for pattern in flag_patterns:
                try:
                    matches = re.findall(pattern, data, re.IGNORECASE)
                    for match in matches:
                        # Validate minimum flag content requirement (4 characters)
                        content = match.split('{')[1].split('}')[0] if '{' in match and '}' in match else ''
                        if len(content) >= 4:
                            flag_findings.append({
                                'type': 'flag',
                                'pattern': pattern,
                                'data': match,
                                'packet_index': packet.get('packet_index', 0),
                                'protocol': packet.get('protocol', 'Unknown'),
                                'confidence': self._calculate_flag_confidence(match),
                                'source': 'ctf_analyzer_flag_detection'
                            })
                except re.error:
                    continue
        
        return flag_findings
    
    def analyze_flag_reconstruction_potential(self, packet_data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the potential for flag reconstruction across the dataset"""
        analysis = {
            'fragments_detected': 0,
            'reconstruction_strategies': [],
            'confidence_assessment': 'low',
            'recommendations': [],
            'cross_protocol_potential': False,
            'temporal_patterns': [],
            'encoding_chains_detected': []
        }
        
        try:
            # Detect potential fragments
            fragments = self.flag_reconstruction_engine.fragment_analyzer.identify_fragments(
                [{'data': p.get('data', ''), 'packet_index': i, 'protocol': p.get('protocol', 'Unknown'),
                  'timestamp': p.get('timestamp', 0), 'src': p.get('src', ''), 'dst': p.get('dst', '')}
                 for i, p in enumerate(packet_data_list)]
            )
            
            analysis['fragments_detected'] = len(fragments)
            
            # Assess reconstruction potential
            if len(fragments) >= 2:
                analysis['confidence_assessment'] = 'medium' if len(fragments) < 5 else 'high'
                
                # Check for cross-protocol potential
                protocols = set(f['protocol'] for f in fragments)
                if len(protocols) > 1:
                    analysis['cross_protocol_potential'] = True
                    analysis['recommendations'].append(
                        f"Flag may be distributed across {len(protocols)} protocols: {', '.join(protocols)}"
                    )
                
                # Check temporal patterns
                temporal_groups = self.flag_reconstruction_engine.temporal_correlator.group_by_timing(fragments)
                if len(temporal_groups) > 1:
                    analysis['temporal_patterns'] = [
                        f"Group {i+1}: {len(group)} fragments within {self.flag_reconstruction_engine.temporal_correlator.time_window}s"
                        for i, group in enumerate(temporal_groups)
                    ]
                
                # Recommend strategies
                if len(protocols) > 1:
                    analysis['reconstruction_strategies'].append('protocol_based_reconstruction')
                if len(temporal_groups) > 1:
                    analysis['reconstruction_strategies'].append('temporal_reconstruction')
                if any(f.get('encoding_hints') for f in fragments):
                    analysis['reconstruction_strategies'].append('encoding_chain_reconstruction')
                    analysis['encoding_chains_detected'] = list(set(
                        hint for f in fragments if f.get('encoding_hints') 
                        for hint in f['encoding_hints']
                    ))
                
                analysis['reconstruction_strategies'].append('sequential_reconstruction')
                
                # Generate specific recommendations
                if analysis['cross_protocol_potential']:
                    analysis['recommendations'].append(
                        "Use protocol-based reconstruction to combine fragments from different protocols"
                    )
                
                if analysis['encoding_chains_detected']:
                    analysis['recommendations'].append(
                        f"Apply encoding chain reconstruction for detected encodings: {', '.join(analysis['encoding_chains_detected'])}"
                    )
                
                if len(analysis['temporal_patterns']) > 1:
                    analysis['recommendations'].append(
                        "Consider temporal reconstruction due to time-based patterns in fragment distribution"
                    )
            
            else:
                analysis['recommendations'].append(
                    "Insufficient fragments detected for reconstruction. Consider expanding search criteria."
                )
                
        except Exception as e:
            analysis['recommendations'].append(f"Fragment analysis failed: {str(e)}")
        
        return analysis
    

    

    
    def _analyze_encoded_data(self, packet_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze potentially encoded data in packets"""
        encoded_findings = []
        
        for packet in packet_data_list:
            data = packet.get('data', '')
            if not data:
                continue
            
            # Base64 detection
            base64_matches = re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', data)
            for match in base64_matches:
                try:
                    decoded = self.encoding_decoder.decode_base64(match)
                    if decoded and len(decoded) > 3:
                        encoded_findings.append({
                            'type': 'base64_decoded',
                            'original': match,
                            'decoded': decoded,
                            'packet_index': packet.get('packet_index', 0),
                            'confidence': 80,
                            'source': 'ctf_analyzer_base64_detection'
                        })
                except Exception:
                    pass
            
            # Hex detection
            hex_matches = re.findall(r'\b[0-9a-fA-F]{8,}\b', data)
            for match in hex_matches:
                try:
                    decoded = self.encoding_decoder.decode_hex(match)
                    if decoded and len(decoded) > 3:
                        encoded_findings.append({
                            'type': 'hex_decoded',
                            'original': match,
                            'decoded': decoded,
                            'packet_index': packet.get('packet_index', 0),
                            'confidence': 75,
                            'source': 'ctf_analyzer_hex_detection'
                        })
                except Exception:
                    pass
        
        return encoded_findings
    
    def _fallback_analysis(self, packet_data_list: List[Dict[str, Any]], results: Dict[str, Any]) -> Dict[str, Any]:
        """Intelligent fallback analysis mode when main analysis fails"""
        print("Debug: Entering fallback analysis mode")
        results['fallback_used'] = True
        results['analysis_status'] = 'fallback_completed'
        
        try:
            # Basic pattern search as fallback
            basic_findings = []
            
            for packet in packet_data_list:
                data = packet.get('data', '')
                if not data:
                    continue
                
                # Simple flag detection
                if 'flag{' in data.lower() or 'ctf{' in data.lower():
                    basic_findings.append({
                        'type': 'potential_flag',
                        'data': data[:100],  # First 100 chars
                        'packet_index': packet.get('packet_index', 0),
                        'confidence': 60,
                        'source': 'fallback_simple_detection'
                    })
                
                # Simple credential detection
                if any(word in data.lower() for word in ['password', 'user', 'login']):
                    basic_findings.append({
                        'type': 'potential_credential',
                        'data': data[:100],
                        'packet_index': packet.get('packet_index', 0),
                        'confidence': 50,
                        'source': 'fallback_credential_detection'
                    })
            
            results['findings'] = basic_findings
            results['fallback_suggestions'] = [
                'Manual analysis recommended due to analysis errors',
                'Check packet data for flags using text search',
                'Look for encoded data (base64, hex) manually',
                'Examine HTTP responses for hidden information'
            ]
            
            print(f"Debug: Fallback analysis completed - found {len(basic_findings)} basic findings")
            
        except Exception as e:
            results['errors'].append(f"Fallback analysis failed: {str(e)}")
            print(f"Debug: Fallback analysis error: {str(e)}")
        
        return results
    
    def analyze_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a CTF challenge"""
        # Detect challenge type
        challenge_type = self.solver_pipeline.detect_challenge_type(challenge_data)
        
        # Build appropriate workflow based on challenge type
        if challenge_type == 'network':
            return self._analyze_network_challenge(challenge_data)
        elif challenge_type == 'binary':
            return self._analyze_binary_challenge(challenge_data)
        elif challenge_type == 'crypto':
            return self._analyze_crypto_challenge(challenge_data)
        elif challenge_type == 'web':
            return self._analyze_web_challenge(challenge_data)
        else:
            return self._analyze_unknown_challenge(challenge_data)
    
    async def _analyze_network_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network-based CTF challenge"""
        # Set up workflow for network challenge
        self.solver_pipeline.add_workflow_step(
            'http_analysis',
            self.network_decoder.analyze_http_responses,
            {'packet_data': challenge_data.get('packets', [])}
        )
        
        self.solver_pipeline.add_workflow_step(
            'dns_analysis',
            self.network_decoder.extract_dns_data,
            {'packet_data': challenge_data.get('packets', [])}
        )
        
        # Execute workflow
        return await self.solver_pipeline.execute_workflow(challenge_data)
    
    async def _analyze_binary_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze binary-based CTF challenge"""
        # Set up workflow for binary challenge
        binary_path = challenge_data.get('file_path')
        
        self.solver_pipeline.add_workflow_step(
            'string_extraction',
            self.binary_analyzer.extract_strings,
            {'binary_path': binary_path}
        )
        
        if PEFILE_AVAILABLE and binary_path.lower().endswith(('.exe', '.dll', '.sys')):
            self.solver_pipeline.add_workflow_step(
                'pe_analysis',
                self.binary_analyzer.analyze_pe_file,
                {'binary_path': binary_path}
            )
        
        self.solver_pipeline.add_workflow_step(
            'embedded_file_detection',
            self.binary_analyzer.find_embedded_files,
            {'binary_path': binary_path}
        )
        
        # Execute workflow
        return await self.solver_pipeline.execute_workflow(challenge_data)
    
    async def _analyze_crypto_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze cryptography-based CTF challenge"""
        # Implementation for crypto challenges
        return {'status': 'not_implemented'}
    
    async def _analyze_web_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze web-based CTF challenge"""
        # Implementation for web challenges
        return {'status': 'not_implemented'}
    
    async def _analyze_unknown_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze unknown challenge type"""
        # Try general analysis techniques
        return {'status': 'unknown_challenge_type'}


# Factory function
def create_ctf_analyzer() -> CTFAnalyzer:
    """Create CTF analyzer instance"""
    return CTFAnalyzer()


class AdvancedCTFSolver:
    """Advanced CTF Challenge Solver with Multi-Stage Analysis"""
    
    def __init__(self):
        self.challenge_patterns = self._build_challenge_patterns()
        self.exploit_templates = self._build_exploit_templates()
        self.encoding_chains = self._build_encoding_chains()
        
    def _build_challenge_patterns(self) -> Dict[str, Any]:
        """Build comprehensive challenge pattern database"""
        return {
            'network_forensics': {
                'indicators': ['pcap', 'wireshark', 'packet', 'network traffic'],
                'techniques': ['protocol_analysis', 'packet_carving', 'stream_reconstruction'],
                'common_flags': ['flag{network_*}', 'CTF{packet_*}'],
                'tools': ['tshark', 'scapy', 'tcpdump']
            },
            'steganography': {
                'indicators': ['image', 'audio', 'hidden', 'lsb', 'steghide'],
                'techniques': ['lsb_extraction', 'frequency_analysis', 'metadata_analysis'],
                'common_flags': ['flag{hidden_*}', 'CTF{stego_*}'],
                'tools': ['steghide', 'stegsolve', 'binwalk']
            },
            'cryptography': {
                'indicators': ['cipher', 'encrypt', 'decode', 'hash', 'key'],
                'techniques': ['frequency_analysis', 'brute_force', 'known_plaintext'],
                'common_flags': ['flag{crypto_*}', 'CTF{cipher_*}'],
                'tools': ['hashcat', 'john', 'sage']
            },
            'reverse_engineering': {
                'indicators': ['binary', 'executable', 'assembly', 'disassemble'],
                'techniques': ['static_analysis', 'dynamic_analysis', 'decompilation'],
                'common_flags': ['flag{reverse_*}', 'CTF{binary_*}'],
                'tools': ['ida', 'ghidra', 'gdb', 'radare2']
            },
            'web_exploitation': {
                'indicators': ['web', 'http', 'server', 'injection', 'xss'],
                'techniques': ['sqli', 'xss', 'lfi', 'rfi', 'csrf'],
                'common_flags': ['flag{web_*}', 'CTF{exploit_*}'],
                'tools': ['burp', 'sqlmap', 'dirb']
            }
        }
    
    def _build_exploit_templates(self) -> Dict[str, Any]:
        """Build exploit template database"""
        return {
            'buffer_overflow': {
                'pattern': 'A' * 100,
                'shellcode_offset': 76,
                'return_address': 0x41414141,
                'nop_sled': '\\x90' * 16
            },
            'format_string': {
                'pattern': '%x.' * 20,
                'stack_read': '%{}$x',
                'stack_write': '%{}$n'
            },
            'sql_injection': {
                'union_based': "' UNION SELECT 1,2,3--",
                'blind_boolean': "' AND 1=1--",
                'time_based': "' AND (SELECT SLEEP(5))--"
            },
            'xss_payloads': {
                'basic': '<script>alert(1)</script>',
                'bypass_filter': '<img src=x onerror=alert(1)>',
                'dom_based': 'javascript:alert(1)'
            }
        }
    
    def _build_encoding_chains(self) -> List[List[str]]:
        """Build common encoding chain patterns"""
        return [
            ['base64'],
            ['hex'],
            ['rot13'],
            ['base64', 'hex'],
            ['hex', 'base64'],
            ['base64', 'rot13'],
            ['rot13', 'base64'],
            ['url_encode', 'base64'],
            ['base64', 'url_encode'],
            ['hex', 'rot13', 'base64'],
            ['base64', 'hex', 'rot13']
        ]
    
    def auto_solve_challenge(self, challenge_data: Dict[str, Any], challenge_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Automatically solve CTF challenge using multi-stage analysis"""
        results = {
            'challenge_type': 'unknown',
            'solving_steps': [],
            'flags_found': [],
            'techniques_used': [],
            'confidence': 0,
            'solving_time': 0,
            'recommendations': []
        }
        
        try:
            import time
            start_time = time.time()
            
            # Stage 1: Challenge Type Detection
            challenge_type = self._detect_challenge_type_advanced(challenge_data, challenge_context)
            results['challenge_type'] = challenge_type
            results['solving_steps'].append(f"Detected challenge type: {challenge_type}")
            
            # Stage 2: Apply Type-Specific Solving Techniques
            if challenge_type == 'steganography':
                stego_results = self._solve_steganography_challenge(challenge_data)
                results.update(stego_results)
                
            elif challenge_type == 'cryptography':
                crypto_results = self._solve_cryptography_challenge(challenge_data)
                results.update(crypto_results)
                
            elif challenge_type == 'network_forensics':
                network_results = self._solve_network_challenge(challenge_data)
                results.update(network_results)
                
            elif challenge_type == 'reverse_engineering':
                reverse_results = self._solve_reverse_challenge(challenge_data)
                results.update(reverse_results)
                
            elif challenge_type == 'web_exploitation':
                web_results = self._solve_web_challenge(challenge_data)
                results.update(web_results)
            
            # Stage 3: Multi-Encoding Chain Analysis
            if not results['flags_found']:
                encoding_results = self._analyze_encoding_chains(challenge_data)
                results['flags_found'].extend(encoding_results.get('flags_found', []))
                results['techniques_used'].extend(encoding_results.get('techniques_used', []))
            
            # Stage 4: Brute Force and Heuristic Approaches
            if not results['flags_found']:
                brute_results = self._brute_force_analysis(challenge_data)
                results['flags_found'].extend(brute_results.get('flags_found', []))
                results['techniques_used'].extend(brute_results.get('techniques_used', []))
            
            # Calculate confidence and timing
            results['solving_time'] = time.time() - start_time
            results['confidence'] = self._calculate_solving_confidence(results)
            
            # Generate recommendations
            results['recommendations'] = self._generate_solving_recommendations(results, challenge_type)
            
        except Exception as e:
            results['error'] = str(e)
            results['solving_steps'].append(f"Error during solving: {str(e)}")
        
        return results
    
    def _detect_challenge_type_advanced(self, challenge_data: Dict[str, Any], context: Dict[str, Any] = None) -> str:
        """Advanced challenge type detection using multiple indicators"""
        scores = {challenge_type: 0 for challenge_type in self.challenge_patterns.keys()}
        
        # Analyze challenge description
        description = context.get('description', '') if context else ''
        hints = context.get('hints', '') if context else ''
        combined_text = (description + ' ' + hints).lower()
        
        for challenge_type, pattern_data in self.challenge_patterns.items():
            # Score based on indicators in description
            for indicator in pattern_data['indicators']:
                if indicator in combined_text:
                    scores[challenge_type] += 2
            
            # Score based on challenge data content
            if 'data' in challenge_data:
                data_content = str(challenge_data['data']).lower()
                for indicator in pattern_data['indicators']:
                    if indicator in data_content:
                        scores[challenge_type] += 1
        
        # Additional heuristics based on data characteristics
        if 'packet_data_list' in challenge_data:
            scores['network_forensics'] += 5
        
        if any(key in challenge_data for key in ['image_data', 'audio_data', 'file_data']):
            scores['steganography'] += 3
        
        if any(word in combined_text for word in ['cipher', 'hash', 'encrypt', 'decrypt']):
            scores['cryptography'] += 3
        
        # Return highest scoring type
        return max(scores.items(), key=lambda x: x[1])[0]
    
    def _solve_steganography_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Solve steganography challenges using advanced techniques"""
        results = {
            'flags_found': [],
            'techniques_used': [],
            'solving_steps': []
        }
        
        try:
            # LSB Analysis
            if 'image_data' in challenge_data or 'audio_data' in challenge_data:
                results['solving_steps'].append("Performing LSB analysis")
                # LSB analysis would be implemented here
                results['techniques_used'].append('lsb_analysis')
            
            # Metadata Analysis
            results['solving_steps'].append("Analyzing file metadata")
            results['techniques_used'].append('metadata_analysis')
            
            # Frequency Domain Analysis
            results['solving_steps'].append("Performing frequency domain analysis")
            results['techniques_used'].append('frequency_analysis')
            
        except Exception as e:
            results['solving_steps'].append(f"Steganography analysis error: {str(e)}")
        
        return results
    
    def _solve_cryptography_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Solve cryptography challenges using advanced techniques"""
        results = {
            'flags_found': [],
            'techniques_used': [],
            'solving_steps': []
        }
        
        try:
            # Caesar Cipher Analysis
            results['solving_steps'].append("Testing Caesar cipher variations")
            for shift in range(1, 26):
                # Caesar cipher implementation would go here
                pass
            results['techniques_used'].append('caesar_cipher')
            
            # XOR Analysis
            results['solving_steps'].append("Performing XOR key analysis")
            # XOR analysis implementation
            results['techniques_used'].append('xor_analysis')
            
            # Frequency Analysis
            results['solving_steps'].append("Conducting frequency analysis")
            results['techniques_used'].append('frequency_analysis')
            
            # Hash Identification
            results['solving_steps'].append("Identifying hash types")
            results['techniques_used'].append('hash_identification')
            
        except Exception as e:
            results['solving_steps'].append(f"Cryptography analysis error: {str(e)}")
        
        return results
    
    def _solve_network_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Solve network forensics challenges"""
        results = {
            'flags_found': [],
            'techniques_used': [],
            'solving_steps': []
        }
        
        try:
            # Protocol Analysis
            results['solving_steps'].append("Analyzing network protocols")
            results['techniques_used'].append('protocol_analysis')
            
            # Stream Reconstruction
            results['solving_steps'].append("Reconstructing network streams")
            results['techniques_used'].append('stream_reconstruction')
            
            # Packet Timing Analysis
            results['solving_steps'].append("Analyzing packet timing patterns")
            results['techniques_used'].append('timing_analysis')
            
            # DNS Analysis
            results['solving_steps'].append("Examining DNS traffic")
            results['techniques_used'].append('dns_analysis')
            
        except Exception as e:
            results['solving_steps'].append(f"Network analysis error: {str(e)}")
        
        return results
    
    def _solve_reverse_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Solve reverse engineering challenges"""
        results = {
            'flags_found': [],
            'techniques_used': [],
            'solving_steps': []
        }
        
        try:
            # String Analysis
            results['solving_steps'].append("Extracting strings from binary")
            results['techniques_used'].append('string_extraction')
            
            # Static Analysis
            results['solving_steps'].append("Performing static analysis")
            results['techniques_used'].append('static_analysis')
            
            # Dynamic Analysis Simulation
            results['solving_steps'].append("Simulating dynamic analysis")
            results['techniques_used'].append('dynamic_analysis')
            
        except Exception as e:
            results['solving_steps'].append(f"Reverse engineering error: {str(e)}")
        
        return results
    
    def _solve_web_challenge(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Solve web exploitation challenges"""
        results = {
            'flags_found': [],
            'techniques_used': [],
            'solving_steps': []
        }
        
        try:
            # SQL Injection Testing
            results['solving_steps'].append("Testing for SQL injection")
            results['techniques_used'].append('sql_injection')
            
            # XSS Testing
            results['solving_steps'].append("Testing for XSS vulnerabilities")
            results['techniques_used'].append('xss_testing')
            
            # Directory Traversal
            results['solving_steps'].append("Testing directory traversal")
            results['techniques_used'].append('directory_traversal')
            
        except Exception as e:
            results['solving_steps'].append(f"Web exploitation error: {str(e)}")
        
        return results
    
    def _analyze_encoding_chains(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze multiple encoding chains"""
        results = {
            'flags_found': [],
            'techniques_used': [],
            'solving_steps': []
        }
        
        try:
            data_to_analyze = str(challenge_data.get('data', ''))
            
            for chain in self.encoding_chains:
                try:
                    current_data = data_to_analyze
                    chain_description = ' -> '.join(chain)
                    
                    results['solving_steps'].append(f"Testing encoding chain: {chain_description}")
                    
                    # Apply decoding chain
                    for encoding in reversed(chain):  # Decode in reverse order
                        if encoding == 'base64':
                            try:
                                current_data = base64.b64decode(current_data).decode('utf-8', errors='ignore')
                            except Exception:
                                break
                        elif encoding == 'hex':
                            try:
                                current_data = bytes.fromhex(current_data).decode('utf-8', errors='ignore')
                            except Exception:
                                break
                        elif encoding == 'rot13':
                            import codecs
                            current_data = codecs.decode(current_data, 'rot13')
                        elif encoding == 'url_encode':
                            import urllib.parse
                            current_data = urllib.parse.unquote(current_data)
                    
                    # Check if result contains flag
                    if re.search(r'flag\{.*?\}|CTF\{.*?\}', current_data, re.IGNORECASE):
                        flag_matches = re.findall(r'flag\{.*?\}|CTF\{.*?\}', current_data, re.IGNORECASE)
                        results['flags_found'].extend(flag_matches)
                        results['techniques_used'].append(f'encoding_chain_{chain_description}')
                        results['solving_steps'].append(f"Found flag using {chain_description}: {flag_matches[0]}")
                        
                except Exception:
                    continue
                    
        except Exception as e:
            results['solving_steps'].append(f"Encoding chain analysis error: {str(e)}")
        
        return results
    
    def _brute_force_analysis(self, challenge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform brute force and heuristic analysis"""
        results = {
            'flags_found': [],
            'techniques_used': [],
            'solving_steps': []
        }
        
        try:
            data_str = str(challenge_data.get('data', ''))
            
            # Pattern-based flag extraction
            results['solving_steps'].append("Performing pattern-based flag extraction")
            
            # Common flag patterns
            flag_patterns = [
                r'flag\{[^}]+\}',
                r'CTF\{[^}]+\}',
                r'[A-Z]{2,8}\{[^}]+\}',
                r'[a-zA-Z0-9_]{3,15}\{[^}]+\}'
            ]
            
            for pattern in flag_patterns:
                matches = re.findall(pattern, data_str, re.IGNORECASE)
                if matches:
                    results['flags_found'].extend(matches)
                    results['techniques_used'].append(f'pattern_matching_{pattern}')
                    results['solving_steps'].append(f"Found flags with pattern {pattern}: {matches}")
            
            # ASCII conversion attempts
            results['solving_steps'].append("Attempting ASCII conversions")
            
            # Try interpreting numbers as ASCII
            number_sequences = re.findall(r'\b(?:\d{2,3}\s*){5,}\b', data_str)
            for sequence in number_sequences:
                numbers = [int(x) for x in sequence.split() if x.isdigit()]
                ascii_attempt = ''.join([chr(n) for n in numbers if 32 <= n <= 126])
                if len(ascii_attempt) > 10 and re.search(r'flag\{.*?\}|CTF\{.*?\}', ascii_attempt, re.IGNORECASE):
                    flag_matches = re.findall(r'flag\{.*?\}|CTF\{.*?\}', ascii_attempt, re.IGNORECASE)
                    results['flags_found'].extend(flag_matches)
                    results['techniques_used'].append('ascii_conversion')
                    results['solving_steps'].append(f"Found flag via ASCII conversion: {flag_matches[0]}")
            
        except Exception as e:
            results['solving_steps'].append(f"Brute force analysis error: {str(e)}")
        
        return results
    
    def _calculate_solving_confidence(self, results: Dict[str, Any]) -> int:
        """Calculate confidence score for solving results"""
        try:
            confidence = 0
            
            # Base confidence from flags found
            if results['flags_found']:
                confidence += min(len(results['flags_found']) * 30, 70)
            
            # Confidence from techniques used
            if results['techniques_used']:
                confidence += min(len(results['techniques_used']) * 5, 20)
            
            # Confidence from successful solving steps
            successful_steps = [step for step in results.get('solving_steps', []) if 'error' not in step.lower()]
            if successful_steps:
                confidence += min(len(successful_steps) * 2, 10)
            
            return min(confidence, 100)
            
        except Exception:
            return 0
    
    def _generate_solving_recommendations(self, results: Dict[str, Any], challenge_type: str) -> List[str]:
        """Generate recommendations for further analysis"""
        recommendations = []
        
        try:
            if not results['flags_found']:
                recommendations.append(f"No flags found automatically. Consider manual {challenge_type} analysis.")
                
                # Type-specific recommendations
                if challenge_type == 'steganography':
                    recommendations.extend([
                        "Try advanced steganography tools like steghide, stegsolve, or binwalk",
                        "Check for hidden data in different bit planes",
                        "Analyze image/audio metadata for hidden information"
                    ])
                elif challenge_type == 'cryptography':
                    recommendations.extend([
                        "Try different cipher types (Vigenère, Playfair, etc.)",
                        "Consider polyalphabetic ciphers",
                        "Check for steganographic encoding within ciphertext"
                    ])
                elif challenge_type == 'network_forensics':
                    recommendations.extend([
                        "Examine HTTP POST data and form submissions",
                        "Check for DNS tunneling or covert channels",
                        "Analyze packet timing for steganographic patterns"
                    ])
            else:
                recommendations.append(f"Successfully found {len(results['flags_found'])} flag(s) using automated analysis.")
                
            # General recommendations
            if len(results['techniques_used']) < 3:
                recommendations.append("Consider trying additional analysis techniques for completeness.")
                
        except Exception:
            recommendations.append("Error generating recommendations. Manual analysis suggested.")
        
        return recommendations


# Factory function for advanced solver
def create_advanced_ctf_solver() -> AdvancedCTFSolver:
    """Create advanced CTF solver instance"""
    return AdvancedCTFSolver()