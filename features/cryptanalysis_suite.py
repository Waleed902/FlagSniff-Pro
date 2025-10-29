#!/usr/bin/env python3
"""
Advanced Cryptanalysis Suite for FlagSniff Pro
Implements classical and modern cryptographic analysis tools
"""

import re
import string
import math
import base64
import hashlib
import itertools
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Optional, Any
import binascii

class ClassicalCipherAnalyzer:
    """Classical cipher analysis and breaking tools"""
    
    def __init__(self):
        # English letter frequency (%)
        self.english_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }
        
        # Common English words for validation
        self.common_words = {
            'THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HER',
            'WAS', 'ONE', 'OUR', 'HAD', 'BY', 'WORD', 'BUT', 'WHAT', 'SOME', 'WE',
            'IT', 'OF', 'TO', 'IN', 'A', 'HAVE', 'I', 'THAT', 'FOR', 'ON', 'DO',
            'HE', 'WITH', 'HIS', 'AS', 'THIS', 'BE', 'AT', 'FROM', 'OR', 'SHE',
            'FLAG', 'CTF', 'CAPTURE', 'CHALLENGE', 'CRYPTO', 'CIPHER', 'KEY'
        }
    
    def calculate_ic(self, text: str) -> float:
        """Calculate Index of Coincidence"""
        text = re.sub(r'[^A-Z]', '', text.upper())
        if len(text) < 2:
            return 0.0
        
        n = len(text)
        freq = Counter(text)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return ic
    
    def chi_squared_score(self, text: str) -> float:
        """Calculate chi-squared score against English frequency"""
        text = re.sub(r'[^A-Z]', '', text.upper())
        if not text:
            return float('inf')
        
        observed = Counter(text)
        expected_total = len(text)
        chi_squared = 0.0
        
        for letter in string.ascii_uppercase:
            observed_count = observed.get(letter, 0)
            expected_count = (self.english_freq.get(letter, 0) / 100) * expected_total
            if expected_count > 0:
                chi_squared += ((observed_count - expected_count) ** 2) / expected_count
        
        return chi_squared
    
    def caesar_cipher_break(self, ciphertext: str) -> List[Dict[str, Any]]:
        """Break Caesar cipher using frequency analysis"""
        results = []
        ciphertext = re.sub(r'[^A-Z]', '', ciphertext.upper())
        
        for shift in range(26):
            decrypted = ""
            for char in ciphertext:
                if char.isalpha():
                    shifted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                    decrypted += shifted
                else:
                    decrypted += char
            
            score = self.chi_squared_score(decrypted)
            word_score = sum(1 for word in decrypted.split() if word in self.common_words)
            
            results.append({
                'shift': shift,
                'decrypted': decrypted,
                'chi_squared': score,
                'word_matches': word_score,
                'confidence': max(0, 100 - score) + word_score * 10
            })
        
        return sorted(results, key=lambda x: x['confidence'], reverse=True)
    
    def vigenere_cipher_analyze(self, ciphertext: str) -> List[Dict[str, Any]]:
        """Analyze Vigenère cipher using Kasiski examination and IC"""
        ciphertext = re.sub(r'[^A-Z]', '', ciphertext.upper())
        results = []
        
        # Find repeated sequences (Kasiski examination)
        repeated_sequences = self._find_repeated_sequences(ciphertext)
        key_lengths = self._estimate_key_lengths(repeated_sequences, ciphertext)
        
        for key_length in key_lengths[:5]:  # Try top 5 key lengths
            key = self._break_vigenere_key(ciphertext, key_length)
            if key:
                decrypted = self._vigenere_decrypt(ciphertext, key)
                score = self.chi_squared_score(decrypted)
                word_score = sum(1 for word in decrypted.split() if word in self.common_words)
                
                results.append({
                    'key_length': key_length,
                    'key': key,
                    'decrypted': decrypted,
                    'chi_squared': score,
                    'word_matches': word_score,
                    'confidence': max(0, 100 - score) + word_score * 10
                })
        
        return sorted(results, key=lambda x: x['confidence'], reverse=True)
    
    def _find_repeated_sequences(self, text: str, min_length: int = 3) -> Dict[str, List[int]]:
        """Find repeated sequences and their positions"""
        sequences = defaultdict(list)
        
        for length in range(min_length, min(len(text) // 2, 10)):
            for i in range(len(text) - length + 1):
                seq = text[i:i + length]
                sequences[seq].append(i)
        
        # Filter sequences that appear at least twice
        return {seq: positions for seq, positions in sequences.items() if len(positions) >= 2}
    
    def _estimate_key_lengths(self, repeated_sequences: Dict[str, List[int]], text: str) -> List[int]:
        """Estimate key lengths from repeated sequences"""
        distances = []
        
        for seq, positions in repeated_sequences.items():
            for i in range(len(positions) - 1):
                distance = positions[i + 1] - positions[i]
                distances.append(distance)
        
        # Find common factors
        factor_counts = Counter()
        for distance in distances:
            for factor in range(2, min(distance + 1, 21)):
                if distance % factor == 0:
                    factor_counts[factor] += 1
        
        # Also test IC for different key lengths
        ic_scores = {}
        for key_length in range(2, 21):
            avg_ic = self._average_ic_for_key_length(text, key_length)
            ic_scores[key_length] = avg_ic
        
        # Combine factor analysis and IC analysis
        combined_scores = {}
        for key_length in range(2, 21):
            factor_score = factor_counts.get(key_length, 0)
            ic_score = ic_scores.get(key_length, 0) * 100
            combined_scores[key_length] = factor_score + ic_score
        
        return sorted(combined_scores.keys(), key=lambda x: combined_scores[x], reverse=True)
    
    def _average_ic_for_key_length(self, text: str, key_length: int) -> float:
        """Calculate average IC for assumed key length"""
        groups = [''] * key_length
        
        for i, char in enumerate(text):
            groups[i % key_length] += char
        
        return sum(self.calculate_ic(group) for group in groups) / key_length
    
    def _break_vigenere_key(self, ciphertext: str, key_length: int) -> str:
        """Break Vigenère key using frequency analysis"""
        key = ""
        
        for i in range(key_length):
            # Extract every key_length-th character
            group = ""
            for j in range(i, len(ciphertext), key_length):
                group += ciphertext[j]
            
            # Find best Caesar shift for this group
            best_shift = 0
            best_score = float('inf')
            
            for shift in range(26):
                decrypted = ""
                for char in group:
                    decrypted += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                
                score = self.chi_squared_score(decrypted)
                if score < best_score:
                    best_score = score
                    best_shift = shift
            
            key += chr(best_shift + ord('A'))
        
        return key
    
    def _vigenere_decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt Vigenère cipher with given key"""
        decrypted = ""
        key_length = len(key)
        
        for i, char in enumerate(ciphertext):
            if char.isalpha():
                key_char = key[i % key_length]
                shift = ord(key_char) - ord('A')
                decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                decrypted += decrypted_char
            else:
                decrypted += char
        
        return decrypted
    
    def substitution_cipher_analyze(self, ciphertext: str) -> Dict[str, Any]:
        """Analyze substitution cipher using pattern analysis"""
        ciphertext = re.sub(r'[^A-Z]', '', ciphertext.upper())
        
        # Frequency analysis
        freq = Counter(ciphertext)
        sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        
        # Pattern analysis
        patterns = self._analyze_patterns(ciphertext)
        
        # Attempt substitution based on frequency
        substitution_map = {}
        english_by_freq = sorted(self.english_freq.items(), key=lambda x: x[1], reverse=True)
        
        for i, (cipher_char, _) in enumerate(sorted_freq[:len(english_by_freq)]):
            substitution_map[cipher_char] = english_by_freq[i][0]
        
        # Apply substitution
        decrypted = ""
        for char in ciphertext:
            decrypted += substitution_map.get(char, char)
        
        return {
            'frequency_analysis': dict(sorted_freq),
            'patterns': patterns,
            'substitution_map': substitution_map,
            'decrypted': decrypted,
            'confidence': self._calculate_substitution_confidence(decrypted)
        }
    
    def _analyze_patterns(self, text: str) -> Dict[str, Any]:
        """Analyze letter patterns in text"""
        # Single letter words (likely 'A' or 'I')
        single_letters = set(re.findall(r'\b[A-Z]\b', text))
        
        # Double letters
        double_letters = re.findall(r'([A-Z])\1', text)
        
        # Common patterns
        three_letter_words = re.findall(r'\b[A-Z]{3}\b', text)
        
        return {
            'single_letters': list(single_letters),
            'double_letters': list(set(double_letters)),
            'three_letter_words': list(set(three_letter_words))
        }
    
    def _calculate_substitution_confidence(self, text: str) -> float:
        """Calculate confidence score for substitution cipher solution"""
        word_score = sum(1 for word in text.split() if word in self.common_words)
        chi_score = max(0, 100 - self.chi_squared_score(text))
        return word_score * 15 + chi_score * 0.5

class ModernCryptoAnalyzer:
    """Modern cryptographic weakness detection and analysis"""
    
    def __init__(self):
        self.base64_variants = {
            'standard': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
            'url_safe': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
            'base32': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
            'base58': '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        }
    
    def xor_key_recovery(self, ciphertext: bytes, known_plaintext: bytes = None) -> List[Dict[str, Any]]:
        """Recover XOR keys using known plaintext or crib dragging"""
        results = []
        
        if known_plaintext:
            # Known plaintext attack
            if len(known_plaintext) <= len(ciphertext):
                key = bytes(a ^ b for a, b in zip(ciphertext, known_plaintext))
                results.append({
                    'method': 'known_plaintext',
                    'key': key,
                    'key_hex': key.hex(),
                    'confidence': 95
                })
        
        # Try common patterns as keys
        common_keys = [b'FLAG', b'KEY', b'CTF', b'PASS', b'SECRET']
        for key in common_keys:
            decrypted = self._xor_decrypt(ciphertext, key)
            if self._is_likely_plaintext(decrypted):
                results.append({
                    'method': 'common_key',
                    'key': key,
                    'key_hex': key.hex(),
                    'decrypted': decrypted,
                    'confidence': 70
                })
        
        # Single-byte XOR brute force
        for key_byte in range(256):
            key = bytes([key_byte])
            decrypted = self._xor_decrypt(ciphertext, key)
            if self._is_likely_plaintext(decrypted):
                results.append({
                    'method': 'single_byte',
                    'key': key,
                    'key_hex': key.hex(),
                    'decrypted': decrypted,
                    'confidence': 60
                })
        
        return sorted(results, key=lambda x: x['confidence'], reverse=True)

    # --- Ciphey-inspired addition: repeating-key XOR breaker (Cryptopals-style) ---
    def repeating_xor_break(self, data: bytes, min_key: int = 2, max_key: int = 40, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Attempt to break repeating-key XOR (Vigenère over bytes).

        Approach:
        - Estimate key sizes via normalized Hamming distance across blocks
        - For top candidate sizes, transpose blocks and solve each with single-byte XOR scoring
        - Score plaintext with an English-likeness metric and return best candidates

        Returns list of {method, key, key_hex, decrypted, confidence}
        """
        if not data or len(data) < min_key * 4:
            return []

        def hamming_distance(a: bytes, b: bytes) -> int:
            dist = 0
            for x, y in zip(a, b):
                v = x ^ y
                dist += bin(v).count("1")
            # account for unequal lengths (shouldn't happen in our use)
            extra = abs(len(a) - len(b))
            return dist + extra * 8

        def score_bytes(buf: bytes) -> float:
            # Heuristic score for English-like bytes in a small chunk (column)
            score = 0.0
            for b in buf:
                if 65 <= b <= 90 or 97 <= b <= 122:  # letters
                    score += 2.0
                elif b == 32:  # space
                    score += 3.0
                elif 48 <= b <= 57:  # digits
                    score += 1.0
                elif b in b".,;:'\"?!()-":
                    score += 0.8
                elif b in (9, 10, 13):  # tab/newline
                    score += 0.2
                elif b < 32 or b > 126:
                    score -= 4.0
                else:
                    score += 0.1
            return score / max(1, len(buf))

        def english_score(buf: bytes) -> float:
            # Higher is better for full plaintext
            score = 0.0
            letters = sum(1 for b in buf if (65 <= b <= 90 or 97 <= b <= 122))
            spaces = buf.count(32)
            digits = sum(1 for b in buf if 48 <= b <= 57)
            bad = sum(1 for b in buf if b == 0 or b > 126)
            score += letters * 1.0 + spaces * 1.5 + digits * 0.2
            score -= bad * 3.0
            return score / max(1, len(buf))

        # 1) Guess key sizes
        keysize_scores: List[Tuple[int, float]] = []
        for ks in range(min_key, max_key + 1):
            try:
                blocks = [data[i:i+ks] for i in range(0, ks * 8, ks)]
                if len(blocks) < 4 or any(len(b) < ks for b in blocks[:4]):
                    continue
                dists = [hamming_distance(blocks[i], blocks[i+1]) / ks for i in range(0, 3)]
                score = sum(dists) / len(dists)
                keysize_scores.append((ks, score))
            except Exception:
                continue
        keysize_scores.sort(key=lambda x: x[1])

        # 2) For top key sizes, solve single-byte XOR per transposed column
        candidates: List[Dict[str, Any]] = []
        for ks, _ in keysize_scores[:top_k]:
            # transpose
            cols = [data[i::ks] for i in range(ks)]

            key_bytes = bytearray()
            for col in cols:
                best_k = 0
                best_s = -1.0
                for k in range(256):
                    decoded = bytes(b ^ k for b in col)
                    s = score_bytes(decoded)
                    if s > best_s:
                        best_s = s
                        best_k = k
                key_bytes.append(best_k)

            key = bytes(key_bytes)
            decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
            conf = english_score(decrypted)
            candidates.append({
                'method': 'repeating_xor',
                'key': key,
                'key_hex': key.hex(),
                'decrypted': decrypted,
                'confidence': round(conf * 100, 2)
            })

        candidates.sort(key=lambda x: x['confidence'], reverse=True)
        return candidates
    
    def _xor_decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """XOR decrypt with repeating key"""
        if not key:
            return ciphertext
        
        decrypted = bytearray()
        for i, byte in enumerate(ciphertext):
            decrypted.append(byte ^ key[i % len(key)])
        
        return bytes(decrypted)
    
    def _is_likely_plaintext(self, data: bytes) -> bool:
        """Check if data looks like readable plaintext"""
        try:
            text = data.decode('utf-8', errors='ignore')
            printable_ratio = sum(1 for c in text if c.isprintable()) / len(text) if text else 0
            return printable_ratio > 0.8 and any(word in text.upper() for word in ['FLAG', 'CTF', 'THE', 'AND'])
        except:
            return False
    
    def detect_base64_variants(self, data: str) -> List[Dict[str, Any]]:
        """Detect and decode various Base64 variants"""
        results = []
        
        for variant_name, alphabet in self.base64_variants.items():
            try:
                if variant_name == 'base32':
                    decoded = base64.b32decode(data.upper())
                elif variant_name == 'base58':
                    decoded = self._base58_decode(data)
                else:
                    # Standard and URL-safe base64
                    decoded = base64.b64decode(data)
                
                if self._is_likely_plaintext(decoded):
                    results.append({
                        'variant': variant_name,
                        'decoded': decoded,
                        'decoded_text': decoded.decode('utf-8', errors='ignore'),
                        'confidence': 80
                    })
            except:
                continue
        
        return results

    def detect_aes_ecb(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Heuristic detection of AES-ECB by repeated 16-byte blocks.

        Returns a dict with total/unique/repeated blocks and confidence if suspicious; otherwise None.
        """
        try:
            if not isinstance(data, (bytes, bytearray)) or len(data) < 64:
                return None
            n = len(data) // 16
            if n < 4:
                return None
            blocks = [bytes(data[i*16:(i+1)*16]) for i in range(n)]
            total = len(blocks)
            uniq = len(set(blocks))
            repeats = total - uniq
            if repeats >= 2:
                ratio = uniq / max(1, total)
                confidence = max(0.5, min(0.99, 1.0 - ratio + min(0.2, repeats/20)))
                return {
                    'total_blocks': total,
                    'unique_blocks': uniq,
                    'repeated_blocks': repeats,
                    'confidence': round(confidence, 2)
                }
            return None
        except Exception:
            return None
    
    def _base58_decode(self, data: str) -> bytes:
        """Decode Base58 (simplified implementation)"""
        alphabet = self.base64_variants['base58']
        decoded = 0
        multi = 1
        
        for char in reversed(data):
            if char not in alphabet:
                raise ValueError("Invalid Base58 character")
            decoded += multi * alphabet.index(char)
            multi *= 58
        
        # Convert to bytes
        result = []
        while decoded > 0:
            result.append(decoded % 256)
            decoded //= 256
        
        return bytes(reversed(result))
    
    def analyze_hash_weaknesses(self, hash_value: str) -> Dict[str, Any]:
        """Analyze hash for known weaknesses"""
        hash_value = hash_value.lower().strip()
        
        analysis = {
            'hash_type': self._identify_hash_type(hash_value),
            'length': len(hash_value),
            'weaknesses': [],
            'recommendations': []
        }
        
        # Check for known weak hashes
        if analysis['hash_type'] in ['MD5', 'SHA1']:
            analysis['weaknesses'].append('Cryptographically broken')
            analysis['recommendations'].append('Use SHA-256 or stronger')
        
        # Check for common patterns
        if hash_value == '0' * len(hash_value):
            analysis['weaknesses'].append('All zeros - likely null hash')
        
        if len(set(hash_value)) < 4:
            analysis['weaknesses'].append('Low entropy - suspicious pattern')
        
        return analysis
    
    def _identify_hash_type(self, hash_value: str) -> str:
        """Identify hash type by length and format"""
        length = len(hash_value)
        
        if length == 32 and all(c in '0123456789abcdef' for c in hash_value):
            return 'MD5'
        elif length == 40 and all(c in '0123456789abcdef' for c in hash_value):
            return 'SHA1'
        elif length == 64 and all(c in '0123456789abcdef' for c in hash_value):
            return 'SHA256'
        elif length == 128 and all(c in '0123456789abcdef' for c in hash_value):
            return 'SHA512'
        else:
            return 'Unknown'
    
    def detect_encoding_chains(self, data: str) -> List[Dict[str, Any]]:
        """Detect and decode encoding chains (e.g., Base64 -> Hex -> ROT13)"""
        results = []
        current_data = data
        chain = []
        
        max_depth = 5
        for depth in range(max_depth):
            # Try different decodings
            decoded = None
            method = None
            
            # Try Base64
            try:
                if re.match(r'^[A-Za-z0-9+/]*={0,2}$', current_data):
                    decoded = base64.b64decode(current_data).decode('utf-8', errors='ignore')
                    method = 'base64'
            except:
                pass
            
            # Try Hex
            if not decoded:
                try:
                    if re.match(r'^[0-9a-fA-F]+$', current_data) and len(current_data) % 2 == 0:
                        decoded = bytes.fromhex(current_data).decode('utf-8', errors='ignore')
                        method = 'hex'
                except:
                    pass
            
            # Try URL decode
            if not decoded:
                try:
                    import urllib.parse
                    url_decoded = urllib.parse.unquote(current_data)
                    if url_decoded != current_data:
                        decoded = url_decoded
                        method = 'url'
                except:
                    pass
            
            if decoded and decoded != current_data:
                chain.append({
                    'step': depth + 1,
                    'method': method,
                    'input': current_data[:100] + '...' if len(current_data) > 100 else current_data,
                    'output': decoded[:100] + '...' if len(decoded) > 100 else decoded
                })
                current_data = decoded
                
                # Check if we found something interesting
                if any(keyword in decoded.upper() for keyword in ['FLAG', 'CTF', 'PASS', 'KEY']):
                    results.append({
                        'chain': chain.copy(),
                        'final_result': decoded,
                        'confidence': 90
                    })
                    break
            else:
                break
        
        if chain:
            results.append({
                'chain': chain,
                'final_result': current_data,
                'confidence': 70
            })
        
        return results

class CryptanalysisEngine:
    """Main cryptanalysis engine combining all analysis tools"""
    
    def __init__(self):
        self.classical = ClassicalCipherAnalyzer()
        self.modern = ModernCryptoAnalyzer()
    
    def analyze_text(self, text: str) -> Dict[str, Any]:
        """Comprehensive cryptanalysis of text data"""
        results = {
            'input_text': text[:200] + '...' if len(text) > 200 else text,
            'analysis_type': 'text',
            'findings': []
        }
        
        # Classical cipher analysis
        if re.match(r'^[A-Za-z\s]+$', text):
            # Caesar cipher
            caesar_results = self.classical.caesar_cipher_break(text)
            if caesar_results and caesar_results[0]['confidence'] > 50:
                results['findings'].append({
                    'type': 'caesar_cipher',
                    'results': caesar_results[:3],
                    'confidence': caesar_results[0]['confidence']
                })
            
            # Vigenère cipher
            if len(text) > 20:
                vigenere_results = self.classical.vigenere_cipher_analyze(text)
                if vigenere_results and vigenere_results[0]['confidence'] > 50:
                    results['findings'].append({
                        'type': 'vigenere_cipher',
                        'results': vigenere_results[:3],
                        'confidence': vigenere_results[0]['confidence']
                    })
            
            # Substitution cipher
            substitution_result = self.classical.substitution_cipher_analyze(text)
            if substitution_result['confidence'] > 30:
                results['findings'].append({
                    'type': 'substitution_cipher',
                    'results': substitution_result,
                    'confidence': substitution_result['confidence']
                })
        
        # Modern crypto analysis
        # Base64 variants
        base64_results = self.modern.detect_base64_variants(text)
        if base64_results:
            results['findings'].append({
                'type': 'base64_variants',
                'results': base64_results,
                'confidence': max(r['confidence'] for r in base64_results)
            })
        
        # Encoding chains
        encoding_results = self.modern.detect_encoding_chains(text)
        if encoding_results:
            results['findings'].append({
                'type': 'encoding_chains',
                'results': encoding_results,
                'confidence': max(r['confidence'] for r in encoding_results)
            })
        
        # Hash analysis
        if re.match(r'^[0-9a-fA-F]+$', text.strip()):
            hash_analysis = self.modern.analyze_hash_weaknesses(text.strip())
            results['findings'].append({
                'type': 'hash_analysis',
                'results': hash_analysis,
                'confidence': 60
            })
        
        return results
    
    def analyze_binary(self, data: bytes) -> Dict[str, Any]:
        """Comprehensive cryptanalysis of binary data"""
        results = {
            'data_length': len(data),
            'analysis_type': 'binary',
            'findings': []
        }
        
        # XOR analysis
        xor_results = self.modern.xor_key_recovery(data)
        if xor_results:
            results['findings'].append({
                'type': 'xor_analysis',
                'results': xor_results,
                'confidence': max(r['confidence'] for r in xor_results)
            })
        
        # Try to decode as text and analyze
        try:
            text = data.decode('utf-8', errors='ignore')
            if len(text) > 10:
                text_analysis = self.analyze_text(text)
                if text_analysis['findings']:
                    results['findings'].extend(text_analysis['findings'])
        except:
            pass

        # AES-ECB heuristic
        try:
            ecb = self.detect_aes_ecb(data)
            if ecb and ecb.get('confidence', 0) >= 0.7:
                results['findings'].append({
                    'type': 'aes_ecb_suspect',
                    'results': ecb,
                    'confidence': ecb.get('confidence', 0.7)
                })
        except Exception:
            pass
        
        return results