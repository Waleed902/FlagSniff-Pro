"""
Enhanced Steganography Detection for CTF Analysis
Detects flags hidden in packet timing, sizes, and covert channels
"""

import numpy as np
import statistics
import re
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import base64
import binascii
import struct
import io
import hashlib
import zlib
from itertools import cycle

# Try to import PIL for image analysis, fallback if not available
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Try to import wave for audio analysis
try:
    import wave
    import audioop
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False

class SteganographyDetector:
    """Advanced steganography detection for CTF challenges"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.timing_threshold = 0.1  # seconds
        self.size_variance_threshold = 0.3
        self.pattern_confidence_base = 75
        
    def analyze_all_steganography(self, packets: List[Any], packet_data_list: List[Dict]) -> Dict[str, Any]:
        """Comprehensive steganography analysis with advanced techniques"""
        results = {
            'timing_patterns': [],
            'size_patterns': [],
            'covert_channels': [],
            'lsb_analysis': [],
            'frequency_analysis': [],
            'image_steganography': [],
            'audio_steganography': [],
            'file_signature_analysis': [],
            'metadata': {
                'total_packets': len(packets),
                'analysis_timestamp': datetime.now().isoformat(),
                'detection_methods': ['timing', 'size', 'covert', 'lsb', 'frequency', 'image_lsb', 'audio', 'file_signatures'],
                'advanced_features_available': {
                    'pil_available': PIL_AVAILABLE,
                    'audio_available': AUDIO_AVAILABLE
                }
            }
        }
        
        try:
            # Timing-based steganography
            timing_findings = self.analyze_timing_patterns(packets)
            results['timing_patterns'] = timing_findings
            
            # Size-based steganography
            size_findings = self.analyze_packet_sizes(packet_data_list)
            results['size_patterns'] = size_findings
            
            # Covert channel detection
            covert_findings = self.detect_covert_channels(packet_data_list)
            results['covert_channels'] = covert_findings
            
            # LSB analysis on packet data
            lsb_findings = self.analyze_lsb_steganography(packet_data_list)
            results['lsb_analysis'] = lsb_findings
            
            # Frequency analysis
            freq_findings = self.analyze_frequency_patterns(packet_data_list)
            results['frequency_analysis'] = freq_findings
            
            # Advanced image steganography detection
            image_findings = self.analyze_image_steganography(packet_data_list)
            results['image_steganography'] = image_findings
            
            # Advanced audio steganography detection
            audio_findings = self.analyze_audio_steganography(packet_data_list)
            results['audio_steganography'] = audio_findings
            
            # File signature analysis for hidden data
            signature_findings = self.analyze_file_signatures(packet_data_list)
            results['file_signature_analysis'] = signature_findings
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Steganography analysis failed: {str(e)}")
            results['error'] = str(e)
            
        return results
    
    def analyze_timing_patterns(self, packets: List[Any]) -> List[Dict[str, Any]]:
        """Detect flags hidden in packet timing intervals"""
        findings = []
        
        if len(packets) < 10:
            return findings
            
        try:
            # Extract timestamps
            timestamps = []
            for packet in packets:
                if hasattr(packet, 'time'):
                    timestamps.append(float(packet.time))
                    
            if len(timestamps) < 10:
                return findings
                
            # Calculate inter-arrival times
            intervals = []
            for i in range(1, len(timestamps)):
                interval = timestamps[i] - timestamps[i-1]
                intervals.append(interval)
                
            # Look for patterns in timing
            # Method 1: Binary encoding in timing (short/long intervals)
            binary_pattern = self._extract_binary_from_timing(intervals)
            if binary_pattern:
                findings.append({
                    'type': 'timing_binary',
                    'pattern': binary_pattern,
                    'confidence': 85,
                    'method': 'Binary timing steganography',
                    'data': self._binary_to_ascii(binary_pattern),
                    'evidence': f'Detected {len(binary_pattern)} bit pattern in packet timing'
                })
                
            # Method 2: Morse code in timing
            morse_pattern = self._extract_morse_from_timing(intervals)
            if morse_pattern:
                decoded_morse = self._decode_morse(morse_pattern)
                if decoded_morse:
                    findings.append({
                        'type': 'timing_morse',
                        'pattern': morse_pattern,
                        'confidence': 80,
                        'method': 'Morse code timing steganography',
                        'data': decoded_morse,
                        'evidence': f'Morse pattern: {morse_pattern}'
                    })
                    
            # Method 3: Periodic patterns that could encode data
            periodic_findings = self._analyze_periodic_timing(intervals)
            findings.extend(periodic_findings)
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Timing analysis failed: {str(e)}")
                
        return findings
    
    def analyze_packet_sizes(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """Look for flags encoded in packet size variations"""
        findings = []
        
        if len(packet_data_list) < 5:
            return findings
            
        try:
            sizes = []
            for packet_data in packet_data_list:
                size = len(packet_data.get('data', ''))
                if size > 0:
                    sizes.append(size)
                    
            if len(sizes) < 5:
                return findings
                
            # Method 1: Binary encoding in size (small/large packets)
            mean_size = statistics.mean(sizes)
            binary_from_size = []
            
            for size in sizes:
                binary_from_size.append('1' if size > mean_size else '0')
                
            binary_pattern = ''.join(binary_from_size)
            if len(binary_pattern) >= 32:  # Minimum meaningful length
                decoded_text = self._binary_to_ascii(binary_pattern)
                if self._contains_meaningful_text(decoded_text):
                    findings.append({
                        'type': 'size_binary',
                        'pattern': binary_pattern[:64] + ('...' if len(binary_pattern) > 64 else ''),
                        'confidence': 82,
                        'method': 'Binary size steganography',
                        'data': decoded_text,
                        'evidence': f'Size threshold: {mean_size} bytes'
                    })
                    
            # Method 2: Modulo encoding (size % n reveals data)
            for modulo in [8, 16, 32, 64, 128]:
                modulo_pattern = [size % modulo for size in sizes]
                if self._has_pattern_significance(modulo_pattern):
                    ascii_attempt = ''.join([chr(x) for x in modulo_pattern if 32 <= x <= 126])
                    if len(ascii_attempt) > 4 and self._contains_meaningful_text(ascii_attempt):
                        findings.append({
                            'type': 'size_modulo',
                            'pattern': str(modulo_pattern[:20]) + ('...' if len(modulo_pattern) > 20 else ''),
                            'confidence': 78,
                            'method': f'Modulo-{modulo} size encoding',
                            'data': ascii_attempt,
                            'evidence': f'Pattern extracted using size % {modulo}'
                        })
                        break
                        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Size analysis failed: {str(e)}")
                
        return findings
    
    def detect_covert_channels(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """Identify hidden communication channels"""
        findings = []
        
        try:
            # Method 1: IP ID field covert channel
            ip_id_findings = self._analyze_ip_id_channel(packet_data_list)
            findings.extend(ip_id_findings)
            
            # Method 2: TCP sequence number covert channel
            tcp_seq_findings = self._analyze_tcp_sequence_channel(packet_data_list)
            findings.extend(tcp_seq_findings)
            
            # Method 3: Unused protocol fields
            unused_fields_findings = self._analyze_unused_fields(packet_data_list)
            findings.extend(unused_fields_findings)
            
            # Method 4: DNS tunneling detection
            dns_tunnel_findings = self._analyze_dns_tunneling(packet_data_list)
            findings.extend(dns_tunnel_findings)
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Covert channel analysis failed: {str(e)}")
                
        return findings
    
    def analyze_lsb_steganography(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze Least Significant Bit steganography in packet data"""
        findings = []
        
        try:
            for i, packet_data in enumerate(packet_data_list[:50]):  # Limit analysis
                data = packet_data.get('data', '')
                if len(data) < 100:  # Need sufficient data
                    continue
                    
                # Extract LSBs from byte data
                try:
                    if isinstance(data, str):
                        byte_data = data.encode('utf-8', errors='ignore')
                    else:
                        byte_data = bytes(data, 'utf-8', errors='ignore')
                        
                    lsb_bits = []
                    for byte in byte_data[:200]:  # Analyze first 200 bytes
                        if isinstance(byte, str):
                            byte = ord(byte)
                        lsb_bits.append(str(byte & 1))
                        
                    if len(lsb_bits) >= 64:  # Need minimum bits
                        lsb_binary = ''.join(lsb_bits)
                        decoded_text = self._binary_to_ascii(lsb_binary)
                        
                        if self._contains_meaningful_text(decoded_text):
                            findings.append({
                                'type': 'lsb_steganography',
                                'pattern': lsb_binary[:64] + '...',
                                'confidence': 75,
                                'method': 'LSB extraction from packet data',
                                'data': decoded_text,
                                'packet_index': i,
                                'evidence': f'LSB pattern in packet {i}'
                            })
                            
                except Exception:
                    continue
                    
        except Exception as e:
            if self.logger:
                self.logger.error(f"LSB analysis failed: {str(e)}")
                
        return findings
    
    def analyze_frequency_patterns(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze frequency patterns that might hide data"""
        findings = []
        
        try:
            # Analyze character frequency distributions
            all_data = ''
            for packet_data in packet_data_list[:100]:
                data = packet_data.get('data', '')
                if isinstance(data, str):
                    all_data += data
                    
            if len(all_data) < 1000:
                return findings
                
            # Look for unusual frequency distributions
            char_freq = defaultdict(int)
            for char in all_data:
                char_freq[char] += 1
                
            # Check for steganographic signatures
            freq_analysis = self._analyze_character_frequencies(char_freq, len(all_data))
            if freq_analysis['suspicious']:
                findings.append({
                    'type': 'frequency_anomaly',
                    'pattern': freq_analysis['pattern'],
                    'confidence': freq_analysis['confidence'],
                    'method': 'Character frequency analysis',
                    'data': freq_analysis.get('extracted_data', ''),
                    'evidence': freq_analysis['evidence']
                })
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Frequency analysis failed: {str(e)}")
                
        return findings
    
    # Helper methods
    def _extract_binary_from_timing(self, intervals: List[float]) -> str:
        """Extract binary pattern from timing intervals"""
        if len(intervals) < 16:
            return ''
            
        try:
            median_interval = statistics.median(intervals)
            binary_pattern = ''
            
            for interval in intervals:
                if interval < median_interval:
                    binary_pattern += '0'
                else:
                    binary_pattern += '1'
                    
            # Only return if pattern looks meaningful
            if len(binary_pattern) >= 32 and '0' in binary_pattern and '1' in binary_pattern:
                return binary_pattern
                
        except Exception:
            pass
            
        return ''
    
    def _binary_to_ascii(self, binary_str: str) -> str:
        """Convert binary string to ASCII text"""
        try:
            # Pad to byte boundary
            while len(binary_str) % 8 != 0:
                binary_str += '0'
                
            ascii_chars = []
            for i in range(0, len(binary_str), 8):
                byte = binary_str[i:i+8]
                if len(byte) == 8:
                    char_code = int(byte, 2)
                    if 32 <= char_code <= 126:  # Printable ASCII
                        ascii_chars.append(chr(char_code))
                    elif char_code == 0:
                        break
                        
            return ''.join(ascii_chars)
            
        except Exception:
            return ''
    
    def _contains_meaningful_text(self, text: str) -> bool:
        """Check if text contains meaningful content that could be a flag"""
        if len(text) < 4:
            return False
            
        # Check for flag patterns
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'[A-Za-z0-9_]+\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'[A-Z]{2,10}[0-9]{2,4}\{[^}]+\}'
        ]
        
        for pattern in flag_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
                
        # Check for meaningful words (basic heuristic)
        common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use']
        text_lower = text.lower()
        word_count = sum(1 for word in common_words if word in text_lower)
        
        return word_count >= 2 or len([c for c in text if c.isalpha()]) / len(text) > 0.7
    
    def _extract_morse_from_timing(self, intervals: List[float]) -> str:
        """Extract Morse code pattern from timing"""
        if len(intervals) < 10:
            return ''
            
        try:
            # Simple Morse detection: short/long intervals
            sorted_intervals = sorted(intervals)
            threshold = sorted_intervals[len(sorted_intervals) // 3]  # 33rd percentile
            
            morse_pattern = ''
            for interval in intervals:
                if interval < threshold:
                    morse_pattern += '.'
                else:
                    morse_pattern += '-'
                    
            return morse_pattern if len(morse_pattern) >= 10 else ''
            
        except Exception:
            return ''
    
    def _decode_morse(self, morse_pattern: str) -> str:
        """Decode Morse code pattern"""
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z',
            '.----': '1', '..---': '2', '...--': '3', '....-': '4',
            '.....': '5', '-....': '6', '--...': '7', '---..': '8',
            '----.': '9', '-----': '0'
        }
        
        try:
            # Split on spaces or pauses (represented by multiple dots/dashes)
            words = re.split(r'[.]{3,}|[-]{3,}', morse_pattern)
            decoded_text = ''
            
            for word in words:
                letters = re.findall(r'[.-]+', word)
                for letter_code in letters:
                    if letter_code in morse_dict:
                        decoded_text += morse_dict[letter_code]
                decoded_text += ' '
                
            return decoded_text.strip()
            
        except Exception:
            return ''
    
    def _analyze_periodic_timing(self, intervals: List[float]) -> List[Dict[str, Any]]:
        """Analyze periodic timing patterns"""
        findings = []
        
        try:
            if len(intervals) < 20:
                return findings
                
            # Look for repeating patterns
            for period in range(2, min(10, len(intervals) // 4)):
                pattern_groups = []
                for i in range(0, len(intervals) - period, period):
                    pattern_groups.append(intervals[i:i+period])
                    
                if len(pattern_groups) >= 3:
                    # Check similarity between pattern groups
                    similarity_score = self._calculate_pattern_similarity(pattern_groups)
                    if similarity_score > 0.7:
                        findings.append({
                            'type': 'periodic_timing',
                            'pattern': f'Period-{period} repeating pattern',
                            'confidence': int(similarity_score * 85),
                            'method': 'Periodic timing analysis',
                            'data': f'Detected {len(pattern_groups)} repetitions',
                            'evidence': f'Pattern period: {period}, similarity: {similarity_score:.2f}'
                        })
                        
        except Exception:
            pass
            
        return findings
    
    def _calculate_pattern_similarity(self, pattern_groups: List[List[float]]) -> float:
        """Calculate similarity between pattern groups"""
        try:
            if len(pattern_groups) < 2:
                return 0.0
                
            # Calculate variance within each position across groups
            similarities = []
            pattern_length = len(pattern_groups[0])
            
            for pos in range(pattern_length):
                values = [group[pos] for group in pattern_groups if len(group) > pos]
                if len(values) > 1:
                    variance = statistics.variance(values)
                    mean_val = statistics.mean(values)
                    if mean_val > 0:
                        cv = variance / (mean_val ** 2)  # Coefficient of variation
                        similarity = max(0, 1 - cv)
                        similarities.append(similarity)
                        
            return statistics.mean(similarities) if similarities else 0.0
            
        except Exception:
            return 0.0
    
    def _has_pattern_significance(self, pattern: List[int]) -> bool:
        """Check if a pattern has statistical significance"""
        try:
            if len(pattern) < 5:
                return False
                
            # Check for non-randomness
            unique_values = len(set(pattern))
            if unique_values < 2:
                return False
                
            # Check if pattern is not just noise
            variance = statistics.variance(pattern) if len(pattern) > 1 else 0
            mean_val = statistics.mean(pattern)
            
            return variance > 0 and mean_val > 0 and unique_values >= min(4, len(pattern) // 2)
            
        except Exception:
            return False
    
    def _analyze_ip_id_channel(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze IP ID field for covert channels"""
        findings = []
        
        try:
            # Extract IP ID values if available
            ip_ids = []
            for packet_data in packet_data_list:
                # This is a simplified extraction - in real implementation,
                # you'd parse actual IP headers
                data = packet_data.get('data', '')
                if 'ip_id' in packet_data:
                    ip_ids.append(packet_data['ip_id'])
                    
            if len(ip_ids) > 10:
                # Look for patterns in IP ID sequence
                ascii_attempt = ''
                for ip_id in ip_ids:
                    if 32 <= ip_id <= 126:
                        ascii_attempt += chr(ip_id)
                        
                if len(ascii_attempt) > 4 and self._contains_meaningful_text(ascii_attempt):
                    findings.append({
                        'type': 'ip_id_covert',
                        'pattern': f'IP ID sequence: {ip_ids[:10]}...',
                        'confidence': 80,
                        'method': 'IP ID field covert channel',
                        'data': ascii_attempt,
                        'evidence': f'ASCII data in IP ID field'
                    })
                    
        except Exception:
            pass
            
        return findings
    
    def _analyze_tcp_sequence_channel(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze TCP sequence numbers for covert channels"""
        findings = []
        
        try:
            # Similar analysis for TCP sequence numbers
            # This would require actual TCP header parsing
            pass
            
        except Exception:
            pass
            
        return findings
    
    def _analyze_unused_fields(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """Analyze unused protocol fields"""
        findings = []
        
        try:
            # Look for data in typically unused fields
            # Implementation would depend on actual packet structure
            pass
            
        except Exception:
            pass
            
        return findings
    
    def _analyze_dns_tunneling(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """Detect DNS tunneling for data exfiltration"""
        findings = []
        
        try:
            dns_queries = []
            for packet_data in packet_data_list:
                data = packet_data.get('data', '')
                protocol = packet_data.get('protocol', '')
                
                if protocol == 'DNS' or 'dns' in data.lower():
                    # Extract domain names from DNS queries
                    domain_matches = re.findall(r'([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.)+[a-zA-Z]{2,}', data)
                    dns_queries.extend(domain_matches)
                    
            if dns_queries:
                # Look for suspicious patterns in DNS queries
                for domain in dns_queries:
                    # Check for base64-like subdomains
                    parts = domain.split('.')
                    for part in parts:
                        if len(part) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', part):
                            try:
                                decoded = base64.b64decode(part + '==')  # Add padding
                                decoded_text = decoded.decode('utf-8', errors='ignore')
                                if self._contains_meaningful_text(decoded_text):
                                    findings.append({
                                        'type': 'dns_tunneling',
                                        'pattern': f'Base64 in DNS: {part[:30]}...',
                                        'confidence': 85,
                                        'method': 'DNS tunneling detection',
                                        'data': decoded_text,
                                        'evidence': f'Suspicious domain: {domain}'
                                    })
                            except Exception:
                                continue
                                
        except Exception:
            pass
            
        return findings
    
    def _analyze_character_frequencies(self, char_freq: Dict, total_chars: int) -> Dict[str, Any]:
        """Analyze character frequency for steganographic signatures"""
        try:
            # Calculate frequency distribution
            frequencies = {char: count/total_chars for char, count in char_freq.items()}
            
            # Check for unusual distributions
            ascii_chars = [char for char in frequencies.keys() if 32 <= ord(char) <= 126]
            if len(ascii_chars) < 10:
                return {'suspicious': False}
                
            # Look for flat distribution (possible steganography)
            ascii_frequencies = [frequencies[char] for char in ascii_chars]
            variance = statistics.variance(ascii_frequencies)
            mean_freq = statistics.mean(ascii_frequencies)
            
            # Suspicious if distribution is too flat or too peaked
            cv = variance / (mean_freq ** 2) if mean_freq > 0 else 0
            
            if cv < 0.1:  # Very flat distribution
                return {
                    'suspicious': True,
                    'confidence': 75,
                    'pattern': 'Unusually flat character distribution',
                    'evidence': f'Coefficient of variation: {cv:.3f}',
                    'extracted_data': ''
                }
            elif cv > 10:  # Very peaked distribution
                # Find the most frequent characters
                sorted_chars = sorted(ascii_chars, key=lambda x: frequencies[x], reverse=True)
                top_chars = ''.join(sorted_chars[:20])
                if self._contains_meaningful_text(top_chars):
                    return {
                        'suspicious': True,
                        'confidence': 70,
                        'pattern': 'Highly skewed character distribution',
                        'evidence': f'Top characters: {top_chars}',
                        'extracted_data': top_chars
                    }
                    
            return {'suspicious': False}
            
        except Exception:
            return {'suspicious': False}
    
    def analyze_image_steganography(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """Advanced LSB (Least Significant Bit) analysis in images"""
        findings = []
        
        if not PIL_AVAILABLE:
            return [{
                'type': 'info',
                'message': 'PIL not available - image LSB analysis skipped',
                'confidence': 0
            }]
        
        try:
            for i, packet_data in enumerate(packet_data_list):
                data = packet_data.get('data', '')
                
                # Look for image headers in packet data
                image_signatures = {
                    b'\xff\xd8\xff': 'JPEG',
                    b'\x89PNG\r\n\x1a\n': 'PNG',
                    b'GIF87a': 'GIF87a',
                    b'GIF89a': 'GIF89a',
                    b'BM': 'BMP'
                }
                
                # Convert string data to bytes if needed
                if isinstance(data, str):
                    data_bytes = data.encode('latin-1', errors='ignore')
                else:
                    data_bytes = data
                
                # Check for image signatures
                for signature, format_name in image_signatures.items():
                    if data_bytes.startswith(signature) or signature in data_bytes:
                        try:
                            # Extract potential image data
                            if signature in data_bytes:
                                start_idx = data_bytes.find(signature)
                                image_data = data_bytes[start_idx:start_idx + min(len(data_bytes) - start_idx, 1024*1024)]  # Max 1MB
                            else:
                                image_data = data_bytes[:min(len(data_bytes), 1024*1024)]
                            
                            # Try to load image
                            try:
                                image = Image.open(io.BytesIO(image_data))
                                
                                # Perform LSB analysis
                                lsb_results = self._analyze_image_lsb(image, format_name)
                                if lsb_results['suspicious']:
                                    findings.append({
                                        'type': 'image_lsb',
                                        'packet_index': i,
                                        'image_format': format_name,
                                        'confidence': lsb_results['confidence'],
                                        'method': 'LSB steganography in image',
                                        'data': lsb_results.get('extracted_data', ''),
                                        'evidence': lsb_results.get('evidence', ''),
                                        'pattern': lsb_results.get('pattern', '')
                                    })
                                    
                                # Check for metadata steganography
                                metadata_results = self._analyze_image_metadata(image)
                                if metadata_results['suspicious']:
                                    findings.append({
                                        'type': 'image_metadata',
                                        'packet_index': i,
                                        'image_format': format_name,
                                        'confidence': metadata_results['confidence'],
                                        'method': 'Hidden data in image metadata',
                                        'data': metadata_results.get('extracted_data', ''),
                                        'evidence': metadata_results.get('evidence', '')
                                    })
                                    
                            except Exception as img_error:
                                # Image data might be corrupted or partial
                                continue
                                
                        except Exception as e:
                            continue
                            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Image steganography analysis failed: {str(e)}")
                
        return findings
    
    def _analyze_image_lsb(self, image: 'Image.Image', format_name: str) -> Dict[str, Any]:
        """Analyze LSB patterns in image data"""
        try:
            # Convert to RGB if needed
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            width, height = image.size
            pixels = list(image.getdata())
            
            # Extract LSBs from each color channel
            lsb_data = []
            for pixel in pixels[:min(1000, len(pixels))]:  # Limit analysis to first 1000 pixels
                r, g, b = pixel
                lsb_data.extend([r & 1, g & 1, b & 1])
            
            # Convert LSB bits to bytes
            lsb_bytes = []
            for i in range(0, len(lsb_data) - 7, 8):
                byte_bits = lsb_data[i:i+8]
                if len(byte_bits) == 8:
                    byte_value = sum(bit * (2 ** (7-j)) for j, bit in enumerate(byte_bits))
                    lsb_bytes.append(byte_value)
            
            # Try to decode as ASCII
            ascii_text = ''
            for byte_val in lsb_bytes:
                if 32 <= byte_val <= 126:  # Printable ASCII
                    ascii_text += chr(byte_val)
                elif byte_val == 0:  # Null terminator
                    break
                else:
                    ascii_text += '?'
            
            # Check for meaningful text
            if len(ascii_text) > 10 and self._contains_meaningful_text(ascii_text):
                return {
                    'suspicious': True,
                    'confidence': 88,
                    'pattern': f'LSB pattern in {format_name} image',
                    'extracted_data': ascii_text[:200],  # Limit output
                    'evidence': f'Decoded {len(ascii_text)} characters from LSB'
                }
            
            # Check for entropy anomalies in LSB data
            if len(lsb_data) > 100:
                entropy = self._calculate_entropy(lsb_data)
                if entropy < 0.3:  # Very low entropy suggests hidden data
                    return {
                        'suspicious': True,
                        'confidence': 75,
                        'pattern': f'Low entropy LSB pattern ({entropy:.3f})',
                        'extracted_data': '',
                        'evidence': f'LSB entropy: {entropy:.3f} (threshold: 0.3)'
                    }
            
            return {'suspicious': False}
            
        except Exception:
            return {'suspicious': False}
    
    def _analyze_image_metadata(self, image: 'Image.Image') -> Dict[str, Any]:
        """Analyze image metadata for hidden data"""
        try:
            # Check EXIF data
            if hasattr(image, '_getexif') and image._getexif():
                exif_data = image._getexif()
                for tag_id, value in exif_data.items():
                    if isinstance(value, str) and len(value) > 20:
                        # Check for base64 or flag patterns
                        if re.search(r'flag\{.*\}|CTF\{.*\}', value, re.IGNORECASE):
                            return {
                                'suspicious': True,
                                'confidence': 95,
                                'extracted_data': value,
                                'evidence': f'Flag found in EXIF tag {tag_id}'
                            }
                        
                        # Check for base64
                        if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) > 20:
                            try:
                                decoded = base64.b64decode(value)
                                decoded_text = decoded.decode('utf-8', errors='ignore')
                                if self._contains_meaningful_text(decoded_text):
                                    return {
                                        'suspicious': True,
                                        'confidence': 85,
                                        'extracted_data': decoded_text,
                                        'evidence': f'Base64 data in EXIF tag {tag_id}'
                                    }
                            except Exception:
                                pass
            
            # Check image info/comments
            if hasattr(image, 'info') and image.info:
                for key, value in image.info.items():
                    if isinstance(value, str) and len(value) > 10:
                        if re.search(r'flag\{.*\}|CTF\{.*\}', value, re.IGNORECASE):
                            return {
                                'suspicious': True,
                                'confidence': 95,
                                'extracted_data': value,
                                'evidence': f'Flag found in image info: {key}'
                            }
            
            return {'suspicious': False}
            
        except Exception:
            return {'suspicious': False}
    
    def analyze_audio_steganography(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """Advanced audio steganography detection"""
        findings = []
        
        if not AUDIO_AVAILABLE:
            return [{
                'type': 'info',
                'message': 'Audio libraries not available - audio steganography analysis skipped',
                'confidence': 0
            }]
        
        try:
            for i, packet_data in enumerate(packet_data_list):
                data = packet_data.get('data', '')
                
                # Look for audio file signatures
                audio_signatures = {
                    b'RIFF': 'WAV',
                    b'ID3': 'MP3',
                    b'\xff\xfb': 'MP3',
                    b'\xff\xf3': 'MP3',
                    b'\xff\xf2': 'MP3',
                    b'fLaC': 'FLAC',
                    b'OggS': 'OGG'
                }
                
                # Convert string data to bytes if needed
                if isinstance(data, str):
                    data_bytes = data.encode('latin-1', errors='ignore')
                else:
                    data_bytes = data
                
                # Check for audio signatures
                for signature, format_name in audio_signatures.items():
                    if data_bytes.startswith(signature) or signature in data_bytes:
                        try:
                            # Extract potential audio data
                            if signature in data_bytes:
                                start_idx = data_bytes.find(signature)
                                audio_data = data_bytes[start_idx:start_idx + min(len(data_bytes) - start_idx, 5*1024*1024)]  # Max 5MB
                            else:
                                audio_data = data_bytes[:min(len(data_bytes), 5*1024*1024)]
                            
                            # Analyze audio for steganography
                            if format_name == 'WAV':
                                audio_results = self._analyze_wav_steganography(audio_data)
                                if audio_results['suspicious']:
                                    findings.append({
                                        'type': 'audio_steganography',
                                        'packet_index': i,
                                        'audio_format': format_name,
                                        'confidence': audio_results['confidence'],
                                        'method': audio_results['method'],
                                        'data': audio_results.get('extracted_data', ''),
                                        'evidence': audio_results.get('evidence', ''),
                                        'pattern': audio_results.get('pattern', '')
                                    })
                            
                        except Exception:
                            continue
                            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Audio steganography analysis failed: {str(e)}")
                
        return findings
    
    def _analyze_wav_steganography(self, audio_data: bytes) -> Dict[str, Any]:
        """Analyze WAV files for LSB steganography"""
        try:
            # Simple WAV header parsing
            if len(audio_data) < 44:  # Minimum WAV header size
                return {'suspicious': False}
            
            # Check WAV header
            if audio_data[:4] != b'RIFF' or audio_data[8:12] != b'WAVE':
                return {'suspicious': False}
            
            # Find data chunk
            data_chunk_start = audio_data.find(b'data')
            if data_chunk_start == -1:
                return {'suspicious': False}
            
            # Extract audio sample data (simplified)
            sample_data_start = data_chunk_start + 8
            sample_data = audio_data[sample_data_start:sample_data_start + min(8192, len(audio_data) - sample_data_start)]
            
            # Extract LSBs from audio samples
            lsb_bits = []
            for i in range(0, len(sample_data), 2):  # Assuming 16-bit samples
                if i + 1 < len(sample_data):
                    sample = struct.unpack('<h', sample_data[i:i+2])[0]  # Little-endian short
                    lsb_bits.append(sample & 1)
            
            # Convert LSB bits to bytes
            lsb_bytes = []
            for i in range(0, len(lsb_bits) - 7, 8):
                byte_bits = lsb_bits[i:i+8]
                if len(byte_bits) == 8:
                    byte_value = sum(bit * (2 ** (7-j)) for j, bit in enumerate(byte_bits))
                    lsb_bytes.append(byte_value)
            
            # Try to decode as ASCII
            ascii_text = ''
            for byte_val in lsb_bytes:
                if 32 <= byte_val <= 126:  # Printable ASCII
                    ascii_text += chr(byte_val)
                elif byte_val == 0:  # Null terminator
                    break
                else:
                    ascii_text += '?'
            
            # Check for meaningful text
            if len(ascii_text) > 10 and self._contains_meaningful_text(ascii_text):
                return {
                    'suspicious': True,
                    'confidence': 87,
                    'method': 'LSB steganography in WAV audio',
                    'pattern': f'LSB pattern in audio samples',
                    'extracted_data': ascii_text[:200],
                    'evidence': f'Decoded {len(ascii_text)} characters from audio LSB'
                }
            
            return {'suspicious': False}
            
        except Exception:
            return {'suspicious': False}
    
    def analyze_file_signatures(self, packet_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """File signature analysis for hidden data detection"""
        findings = []
        
        try:
            # Common file signatures
            file_signatures = {
                b'\x50\x4b\x03\x04': 'ZIP/JAR/DOCX/XLSX',
                b'\x50\x4b\x05\x06': 'ZIP (empty)',
                b'\x50\x4b\x07\x08': 'ZIP (spanned)',
                b'\x1f\x8b\x08': 'GZIP',
                b'\x42\x5a\x68': 'BZIP2',
                b'\x37\x7a\xbc\xaf\x27\x1c': '7Z',
                b'\x52\x61\x72\x21\x1a\x07': 'RAR',
                b'\x7f\x45\x4c\x46': 'ELF executable',
                b'\x4d\x5a': 'PE executable',
                b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': 'PNG',
                b'\xff\xd8\xff': 'JPEG',
                b'\x47\x49\x46\x38': 'GIF',
                b'\x25\x50\x44\x46': 'PDF',
                b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'Microsoft Office',
                b'\x4f\x67\x67\x53': 'OGG'
            }
            
            for i, packet_data in enumerate(packet_data_list):
                data = packet_data.get('data', '')
                
                # Convert string data to bytes if needed
                if isinstance(data, str):
                    data_bytes = data.encode('latin-1', errors='ignore')
                else:
                    data_bytes = data
                
                # Check for multiple file signatures in one packet
                found_signatures = []
                for signature, file_type in file_signatures.items():
                    if signature in data_bytes:
                        positions = []
                        start = 0
                        while True:
                            pos = data_bytes.find(signature, start)
                            if pos == -1:
                                break
                            positions.append(pos)
                            start = pos + 1
                        
                        if positions:
                            found_signatures.append({
                                'type': file_type,
                                'signature': signature.hex(),
                                'positions': positions
                            })
                
                # Suspicious if multiple file signatures found
                if len(found_signatures) > 1:
                    findings.append({
                        'type': 'multiple_file_signatures',
                        'packet_index': i,
                        'confidence': 85,
                        'method': 'Multiple embedded file signatures',
                        'data': f"Found {len(found_signatures)} different file types",
                        'evidence': f"File types: {', '.join([sig['type'] for sig in found_signatures])}",
                        'pattern': 'Polyglot file or file concatenation'
                    })
                
                # Check for hidden files after null bytes
                null_positions = []
                start = 0
                while True:
                    pos = data_bytes.find(b'\x00\x00\x00\x00', start)
                    if pos == -1:
                        break
                    null_positions.append(pos)
                    start = pos + 1
                
                for null_pos in null_positions:
                    # Check for file signatures after null padding
                    remaining_data = data_bytes[null_pos + 10:]  # Skip some null bytes
                    for signature, file_type in file_signatures.items():
                        if remaining_data.startswith(signature):
                            findings.append({
                                'type': 'hidden_file_after_nulls',
                                'packet_index': i,
                                'confidence': 90,
                                'method': 'File hidden after null bytes',
                                'data': f"Hidden {file_type} file",
                                'evidence': f"File signature at offset {null_pos + 10}",
                                'pattern': f'Null padding followed by {file_type} signature'
                            })
                            break
                
                # Check for steganographic file appending (files at end of other files)
                for signature, file_type in file_signatures.items():
                    last_occurrence = data_bytes.rfind(signature)
                    if last_occurrence > len(data_bytes) // 2:  # Signature in second half
                        # Check if this might be an appended file
                        prefix_data = data_bytes[:last_occurrence]
                        
                        # Look for another file signature in the prefix
                        for prefix_sig, prefix_type in file_signatures.items():
                            if prefix_sig in prefix_data and prefix_sig != signature:
                                findings.append({
                                    'type': 'appended_file',
                                    'packet_index': i,
                                    'confidence': 82,
                                    'method': 'File appended to another file',
                                    'data': f"{file_type} appended to {prefix_type}",
                                    'evidence': f"Second file signature at offset {last_occurrence}",
                                    'pattern': f'{prefix_type} + {file_type} concatenation'
                                })
                                break
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"File signature analysis failed: {str(e)}")
                
        return findings
    
    def _calculate_entropy(self, data: List[int]) -> float:
        """Calculate Shannon entropy of data"""
        try:
            from collections import Counter
            import math
            
            if not data:
                return 0.0
                
            # Count occurrences of each value
            counts = Counter(data)
            total = len(data)
            
            # Calculate entropy
            entropy = 0.0
            for count in counts.values():
                probability = count / total
                if probability > 0:
                    entropy -= probability * math.log2(probability)
                    
            return entropy
            
        except Exception:
            return 0.0