"""
Advanced Encoding Chain Decoder for CTF Analysis
Handles multi-layer encoding and automatic decoding chains
"""

import base64
import binascii
import urllib.parse
import html
import codecs
import re
import json
import zlib
import string
from typing import Dict, List, Any, Tuple, Optional, Union
from datetime import datetime

class EncodingChainAnalyzer:
    """Advanced multi-layer encoding detection and decoding"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.max_decode_depth = 10
        self.confidence_threshold = 70
        
        # Encoding detection patterns
        self.encoding_patterns = {
            'base64': r'^[A-Za-z0-9+/]{4,}={0,2}$',
            'base32': r'^[A-Z2-7]{8,}={0,6}$',
            'hex': r'^[0-9A-Fa-f]{8,}$',
            'url': r'%[0-9A-Fa-f]{2}',
            'html': r'&#?\w+;',
            'rot13': r'^[A-Za-z\s]{4,}$',
            'binary': r'^[01]{8,}$',
            'morse': r'^[.-\s]{10,}$',
            'unicode_escape': r'\\u[0-9A-Fa-f]{4}',
            'gzip_base64': r'^H4sIA',  # gzip magic in base64
            'json': r'^\s*[\{\[]',
            'jwt': r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$'
        }
        
        # Caesar cipher detection
        self.common_words = ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HAD', 'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'GET', 'HAS', 'HIM', 'HIS', 'HOW', 'ITS', 'MAY', 'NEW', 'NOW', 'OLD', 'SEE', 'TWO', 'WHO', 'BOY', 'DID', 'LET', 'MAN', 'PUT', 'SAY', 'SHE', 'TOO', 'USE']
        
    def analyze_encoding_chains(self, data_samples: List[Dict]) -> Dict[str, Any]:
        """Analyze multiple data samples for encoding chains"""
        results = {
            'encoding_chains': [],
            'successful_decodes': [],
            'failed_attempts': [],
            'statistics': {
                'total_samples': len(data_samples),
                'successful_chains': 0,
                'average_chain_length': 0,
                'encoding_types_found': set()
            },
            'metadata': {
                'analysis_timestamp': datetime.now().isoformat(),
                'max_depth_used': self.max_decode_depth
            }
        }
        
        try:
            successful_chains = []
            all_encoding_types = set()
            
            for i, sample in enumerate(data_samples[:50]):  # Limit analysis
                data = sample.get('data', '')
                if isinstance(data, dict):
                    data = json.dumps(data)
                elif not isinstance(data, str):
                    data = str(data)
                    
                if len(data) < 4:
                    continue
                    
                # Analyze this data sample
                chain_result = self.detect_and_decode_chain(data)
                
                if chain_result['success']:
                    chain_result['source_packet'] = sample.get('packet_index', i)
                    chain_result['source_protocol'] = sample.get('protocol', 'Unknown')
                    successful_chains.append(chain_result)
                    all_encoding_types.update(chain_result['encoding_chain'])
                    
                    # Check if final decoded data looks like a flag
                    final_data = chain_result['final_decoded']
                    if self._is_potential_flag(final_data):
                        results['successful_decodes'].append({
                            'packet_index': sample.get('packet_index', i),
                            'original_data': data[:100] + ('...' if len(data) > 100 else ''),
                            'decoded_flag': final_data,
                            'encoding_chain': chain_result['encoding_chain'],
                            'confidence': chain_result['confidence'],
                            'method': 'Multi-layer decoding'
                        })
                else:
                    results['failed_attempts'].append({
                        'packet_index': sample.get('packet_index', i),
                        'data_preview': data[:50] + ('...' if len(data) > 50 else ''),
                        'attempted_encodings': chain_result.get('attempted_encodings', []),
                        'failure_reason': chain_result.get('error', 'Unknown')
                    })
                    
            # Update statistics
            results['encoding_chains'] = successful_chains
            results['statistics']['successful_chains'] = len(successful_chains)
            results['statistics']['encoding_types_found'] = list(all_encoding_types)
            
            if successful_chains:
                avg_length = sum(len(chain['encoding_chain']) for chain in successful_chains) / len(successful_chains)
                results['statistics']['average_chain_length'] = round(avg_length, 2)
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Encoding chain analysis failed: {str(e)}")
            results['error'] = str(e)
            
        return results
    
    def detect_and_decode_chain(self, data: str) -> Dict[str, Any]:
        """Detect and decode a single encoding chain"""
        result = {
            'success': False,
            'original_data': data,
            'encoding_chain': [],
            'decode_steps': [],
            'final_decoded': data,
            'confidence': 0,
            'attempted_encodings': []
        }
        
        try:
            current_data = data.strip()
            decode_history = []
            
            for depth in range(self.max_decode_depth):
                # Detect possible encodings
                detected_encodings = self.detect_encoding_types(current_data)
                
                if not detected_encodings:
                    break
                    
                # Try to decode with the most likely encoding
                best_encoding = max(detected_encodings.items(), key=lambda x: x[1])
                encoding_type = best_encoding[0]
                confidence = best_encoding[1]
                
                result['attempted_encodings'].append(encoding_type)
                
                # Attempt decoding
                decoded_data = self.decode_data(current_data, encoding_type)
                
                if decoded_data and decoded_data != current_data:
                    decode_step = {
                        'step': depth + 1,
                        'encoding': encoding_type,
                        'input': current_data[:100] + ('...' if len(current_data) > 100 else ''),
                        'output': decoded_data[:100] + ('...' if len(decoded_data) > 100 else ''),
                        'confidence': confidence
                    }
                    decode_history.append(decode_step)
                    result['encoding_chain'].append(encoding_type)
                    current_data = decoded_data
                    
                    # Check if we've found something meaningful
                    if self._is_meaningful_result(current_data):
                        result['success'] = True
                        break
                else:
                    break
                    
            result['decode_steps'] = decode_history
            result['final_decoded'] = current_data
            
            # Calculate overall confidence
            if result['encoding_chain']:
                step_confidences = [step['confidence'] for step in decode_history]
                result['confidence'] = int(sum(step_confidences) / len(step_confidences))
                
                # Bonus for finding flags
                if self._is_potential_flag(current_data):
                    result['confidence'] = min(95, result['confidence'] + 15)
                    result['success'] = True
                    
        except Exception as e:
            result['error'] = str(e)
            
        return result
    
    def detect_encoding_types(self, data: str) -> Dict[str, int]:
        """Detect possible encoding types with confidence scores"""
        detected = {}
        
        try:
            # Clean data for analysis
            clean_data = data.strip()
            
            # Base64 detection
            if re.match(self.encoding_patterns['base64'], clean_data):
                if len(clean_data) % 4 == 0 or '=' in clean_data:
                    detected['base64'] = 90
                else:
                    detected['base64'] = 70
                    
            # Base32 detection
            if re.match(self.encoding_patterns['base32'], clean_data.upper()):
                detected['base32'] = 85
                
            # Hex detection
            if re.match(self.encoding_patterns['hex'], clean_data):
                if len(clean_data) % 2 == 0:
                    detected['hex'] = 88
                else:
                    detected['hex'] = 65
                    
            # URL encoding detection
            if re.search(self.encoding_patterns['url'], clean_data):
                detected['url'] = 80
                
            # HTML entity detection
            if re.search(self.encoding_patterns['html'], clean_data):
                detected['html'] = 82
                
            # Binary detection
            if re.match(self.encoding_patterns['binary'], clean_data):
                if len(clean_data) % 8 == 0:
                    detected['binary'] = 85
                else:
                    detected['binary'] = 70
                    
            # Morse code detection
            if re.match(self.encoding_patterns['morse'], clean_data):
                detected['morse'] = 75
                
            # Unicode escape detection
            if re.search(self.encoding_patterns['unicode_escape'], clean_data):
                detected['unicode_escape'] = 85
                
            # JWT detection
            if re.match(self.encoding_patterns['jwt'], clean_data):
                detected['jwt'] = 92
                
            # JSON detection
            if re.match(self.encoding_patterns['json'], clean_data):
                detected['json'] = 80
                
            # Gzipped base64 detection
            if clean_data.startswith('H4sIA'):
                detected['gzip_base64'] = 90
                
            # ROT13/Caesar cipher detection
            if re.match(self.encoding_patterns['rot13'], clean_data) and len(clean_data) > 10:
                detected['rot13'] = self._detect_caesar_cipher(clean_data)
                
            # Custom CTF encodings
            custom_confidence = self._detect_custom_encodings(clean_data)
            if custom_confidence > 0:
                detected['custom'] = custom_confidence
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Encoding detection failed: {str(e)}")
                
        return detected
    
    def decode_data(self, data: str, encoding_type: str) -> Optional[str]:
        """Decode data using specified encoding type"""
        try:
            clean_data = data.strip()
            
            if encoding_type == 'base64':
                return self._decode_base64(clean_data)
            elif encoding_type == 'base32':
                return self._decode_base32(clean_data)
            elif encoding_type == 'hex':
                return self._decode_hex(clean_data)
            elif encoding_type == 'url':
                return self._decode_url(clean_data)
            elif encoding_type == 'html':
                return self._decode_html(clean_data)
            elif encoding_type == 'binary':
                return self._decode_binary(clean_data)
            elif encoding_type == 'morse':
                return self._decode_morse(clean_data)
            elif encoding_type == 'unicode_escape':
                return self._decode_unicode_escape(clean_data)
            elif encoding_type == 'jwt':
                return self._decode_jwt(clean_data)
            elif encoding_type == 'json':
                return self._decode_json(clean_data)
            elif encoding_type == 'gzip_base64':
                return self._decode_gzip_base64(clean_data)
            elif encoding_type == 'rot13':
                return self._decode_caesar_cipher(clean_data)
            elif encoding_type == 'custom':
                return self._decode_custom(clean_data)
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Decoding failed for {encoding_type}: {str(e)}")
                
        return None
    
    # Decoding methods
    def _decode_base64(self, data: str) -> Optional[str]:
        """Decode base64 data"""
        try:
            # Add padding if necessary
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
                
            decoded_bytes = base64.b64decode(data)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    def _decode_base32(self, data: str) -> Optional[str]:
        """Decode base32 data"""
        try:
            decoded_bytes = base64.b32decode(data.upper())
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    def _decode_hex(self, data: str) -> Optional[str]:
        """Decode hexadecimal data"""
        try:
            decoded_bytes = bytes.fromhex(data)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    def _decode_url(self, data: str) -> Optional[str]:
        """Decode URL-encoded data"""
        try:
            return urllib.parse.unquote(data)
        except Exception:
            return None
    
    def _decode_html(self, data: str) -> Optional[str]:
        """Decode HTML entities"""
        try:
            return html.unescape(data)
        except Exception:
            return None
    
    def _decode_binary(self, data: str) -> Optional[str]:
        """Decode binary data"""
        try:
            # Pad to byte boundary
            while len(data) % 8 != 0:
                data = '0' + data
                
            decoded_chars = []
            for i in range(0, len(data), 8):
                byte = data[i:i+8]
                if len(byte) == 8:
                    char_code = int(byte, 2)
                    if 0 <= char_code <= 255:
                        decoded_chars.append(chr(char_code))
                        
            return ''.join(decoded_chars)
        except Exception:
            return None
    
    def _decode_morse(self, data: str) -> Optional[str]:
        """Decode Morse code"""
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6',
            '--...': '7', '---..': '8', '----.': '9'
        }
        
        try:
            # Split on multiple spaces or obvious delimiters
            words = re.split(r'\s{2,}|/|\|', data)
            decoded_text = ''
            
            for word in words:
                letters = word.split()
                for letter_code in letters:
                    letter_code = letter_code.strip()
                    if letter_code in morse_dict:
                        decoded_text += morse_dict[letter_code]
                decoded_text += ' '
                
            return decoded_text.strip()
        except Exception:
            return None
    
    def _decode_unicode_escape(self, data: str) -> Optional[str]:
        """Decode Unicode escape sequences"""
        try:
            return codecs.decode(data, 'unicode_escape')
        except Exception:
            return None
    
    def _decode_jwt(self, data: str) -> Optional[str]:
        """Decode JWT token"""
        try:
            parts = data.split('.')
            if len(parts) >= 2:
                # Decode header and payload
                header = self._decode_base64(parts[0])
                payload = self._decode_base64(parts[1])
                
                if header and payload:
                    return f"Header: {header}\nPayload: {payload}"
                    
        except Exception:
            pass
        return None
    
    def _decode_json(self, data: str) -> Optional[str]:
        """Decode and pretty-print JSON"""
        try:
            parsed = json.loads(data)
            return json.dumps(parsed, indent=2)
        except Exception:
            return None
    
    def _decode_gzip_base64(self, data: str) -> Optional[str]:
        """Decode gzipped base64 data"""
        try:
            # First decode base64
            base64_decoded = base64.b64decode(data)
            # Then decompress gzip
            decompressed = zlib.decompress(base64_decoded, 16 + zlib.MAX_WBITS)
            return decompressed.decode('utf-8', errors='ignore')
        except Exception:
            return None
    
    def _decode_caesar_cipher(self, data: str) -> Optional[str]:
        """Decode Caesar cipher by trying all shifts"""
        try:
            best_decode = None
            best_score = 0
            
            for shift in range(1, 26):
                decoded = ''
                for char in data:
                    if char.isalpha():
                        ascii_offset = 65 if char.isupper() else 97
                        shifted = ((ord(char) - ascii_offset + shift) % 26) + ascii_offset
                        decoded += chr(shifted)
                    else:
                        decoded += char
                        
                # Score based on common English words
                score = self._score_english_text(decoded)
                if score > best_score:
                    best_score = score
                    best_decode = decoded
                    
            return best_decode if best_score > 2 else None
        except Exception:
            return None
    
    def _decode_custom(self, data: str) -> Optional[str]:
        """Decode custom CTF encodings"""
        try:
            # Atbash cipher
            atbash_result = self._decode_atbash(data)
            if atbash_result and self._is_meaningful_result(atbash_result):
                return atbash_result
                
            # Reverse string
            reversed_data = data[::-1]
            if self._is_meaningful_result(reversed_data):
                return reversed_data
                
            # XOR with common keys
            for key in ['key', 'flag', 'ctf', '123', 'abc']:
                xor_result = self._xor_decode(data, key)
                if xor_result and self._is_meaningful_result(xor_result):
                    return xor_result
                    
        except Exception:
            pass
        return None
    
    def _decode_atbash(self, data: str) -> Optional[str]:
        """Decode Atbash cipher"""
        try:
            result = ''
            for char in data:
                if char.isalpha():
                    if char.isupper():
                        result += chr(ord('Z') - (ord(char) - ord('A')))
                    else:
                        result += chr(ord('z') - (ord(char) - ord('a')))
                else:
                    result += char
            return result
        except Exception:
            return None
    
    def _xor_decode(self, data: str, key: str) -> Optional[str]:
        """XOR decode with repeating key"""
        try:
            result = ''
            for i, char in enumerate(data):
                key_char = key[i % len(key)]
                xor_char = chr(ord(char) ^ ord(key_char))
                if 32 <= ord(xor_char) <= 126:  # Printable ASCII
                    result += xor_char
                else:
                    return None  # Non-printable result, likely wrong key
            return result
        except Exception:
            return None
    
    # Helper methods
    def _detect_caesar_cipher(self, data: str) -> int:
        """Detect if data might be a Caesar cipher"""
        try:
            # Quick check for Caesar cipher likelihood
            alpha_count = sum(1 for c in data if c.isalpha())
            if alpha_count < len(data) * 0.7:
                return 0
                
            # Try a few shifts and see if we get English-like text
            max_score = 0
            for shift in [13, 1, 25]:  # ROT13 and adjacent shifts
                decoded = ''
                for char in data:
                    if char.isalpha():
                        ascii_offset = 65 if char.isupper() else 97
                        shifted = ((ord(char) - ascii_offset + shift) % 26) + ascii_offset
                        decoded += chr(shifted)
                    else:
                        decoded += char
                        
                score = self._score_english_text(decoded)
                max_score = max(max_score, score)
                
            return min(85, 40 + max_score * 10) if max_score > 1 else 0
        except Exception:
            return 0
    
    def _detect_custom_encodings(self, data: str) -> int:
        """Detect custom CTF encodings"""
        confidence = 0
        
        try:
            # Check for Atbash patterns
            if data.isalpha() and len(data) > 10:
                atbash_result = self._decode_atbash(data)
                if atbash_result and self._score_english_text(atbash_result) > 2:
                    confidence = max(confidence, 70)
                    
            # Check for reverse string patterns
            if len(data) > 10:
                reversed_data = data[::-1]
                if self._score_english_text(reversed_data) > 2:
                    confidence = max(confidence, 65)
                    
            # Check for XOR patterns (high entropy but structured)
            if 20 <= len(data) <= 200:
                entropy = self._calculate_entropy(data)
                if 3.5 <= entropy <= 6.5:  # Medium entropy suggests XOR
                    confidence = max(confidence, 60)
                    
        except Exception:
            pass
            
        return confidence
    
    def _score_english_text(self, text: str) -> int:
        """Score text for English-like characteristics"""
        try:
            if not text or len(text) < 3:
                return 0
                
            text_upper = text.upper()
            score = 0
            
            # Check for common English words
            for word in self.common_words:
                if word in text_upper:
                    score += 1
                    
            # Check for reasonable letter frequency
            letter_count = sum(1 for c in text if c.isalpha())
            if letter_count > len(text) * 0.6:
                score += 1
                
            # Check for flag patterns
            if re.search(r'FLAG\{|CTF\{|\w+\{[^}]+\}', text_upper):
                score += 5
                
            return score
        except Exception:
            return 0
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of data"""
        try:
            if not data:
                return 0
                
            # Count character frequencies
            char_counts = {}
            for char in data:
                char_counts[char] = char_counts.get(char, 0) + 1
                
            # Calculate entropy
            entropy = 0
            data_len = len(data)
            for count in char_counts.values():
                p = count / data_len
                if p > 0:
                    entropy -= p * (p.bit_length() - 1)
                    
            return entropy
        except Exception:
            return 0
    
    def _is_meaningful_result(self, data: str) -> bool:
        """Check if decoded data is meaningful"""
        try:
            if not data or len(data) < 3:
                return False
                
            # Check for flag patterns
            if self._is_potential_flag(data):
                return True
                
            # Check for meaningful English text
            english_score = self._score_english_text(data)
            if english_score >= 2:
                return True
                
            # Check for structured data (JSON, etc.)
            if data.strip().startswith(('{', '[', '<')):
                return True
                
            # Check for printable ASCII with reasonable characteristics
            printable_count = sum(1 for c in data if 32 <= ord(c) <= 126)
            if printable_count / len(data) > 0.8 and len(data) > 10:
                return True
                
            return False
        except Exception:
            return False
    
    def _is_potential_flag(self, data: str) -> bool:
        """Check if data could be a CTF flag"""
        try:
            if not data or len(data) < 6:
                return False
                
            # Following memory specification for CTF flag formats
            flag_patterns = [
                r'flag\{[^}]+\}',
                r'[A-Za-z0-9_]{2,15}\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}',
                r'TJDGW2023\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}',
                r'[A-Z]{2,10}[0-9]{2,4}\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,}\}',
                r'CTF\{[^}]+\}',
                r'ctf\{[^}]+\}',
                r'HTB\{[^}]+\}',
                r'DUCTF\{[^}]+\}',
                r'picoCTF\{[^}]+\}'
            ]
            
            # Check against all patterns
            for pattern in flag_patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    return True
                    
            # Additional simple check for basic flag structure
            if '{' in data and '}' in data:
                # Check if it looks like a flag format
                brace_content = re.search(r'\{([^}]+)\}', data)
                if brace_content and len(brace_content.group(1)) >= 4:
                    # Check if the prefix looks flag-like
                    prefix = data[:data.find('{')].lower()
                    flag_prefixes = ['flag', 'ctf', 'htb', 'ductf', 'pico', 'cyber']
                    if any(prefix.endswith(fp) for fp in flag_prefixes) or any(fp in prefix for fp in flag_prefixes):
                        return True
                    # Check if it's an alphanumeric prefix followed by year
                    if re.match(r'^[a-z]+\d{4}$', prefix):
                        return True
                        
            return False
        except Exception:
            return False