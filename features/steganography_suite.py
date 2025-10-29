#!/usr/bin/env python3
"""
Enhanced Steganography Suite for FlagSniff Pro
Implements advanced image, audio, video, and text steganography detection
"""

import struct
import math
import re
import base64
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter
import hashlib
import binascii

class ImageSteganographyAnalyzer:
    """Advanced image steganography detection and analysis"""
    
    def __init__(self):
        self.image_signatures = {
            'PNG': b'\x89PNG\r\n\x1a\n',
            'JPEG': b'\xff\xd8\xff',
            'GIF': b'GIF8',
            'BMP': b'BM',
            'TIFF': b'II*\x00'
        }
    
    def analyze_image_steganography(self, data: bytes, filename: str = None) -> Dict[str, Any]:
        """Comprehensive image steganography analysis"""
        analysis = {
            'filename': filename,
            'size': len(data),
            'image_type': self._detect_image_type(data),
            'steganography_findings': [],
            'metadata_analysis': {},
            'statistical_analysis': {},
            'visual_analysis': {}
        }
        
        if not analysis['image_type']:
            return analysis
        
        # LSB Analysis
        lsb_results = self._analyze_lsb_steganography(data, analysis['image_type'])
        if lsb_results['suspicious']:
            analysis['steganography_findings'].append({
                'type': 'LSB_steganography',
                'confidence': lsb_results['confidence'],
                'details': lsb_results
            })
        
        # Metadata analysis
        analysis['metadata_analysis'] = self._analyze_image_metadata(data, analysis['image_type'])
        
        # Statistical analysis
        analysis['statistical_analysis'] = self._statistical_analysis(data)
        
        # Visual analysis (pattern detection)
        analysis['visual_analysis'] = self._visual_pattern_analysis(data, analysis['image_type'])
        
        # DCT coefficient analysis for JPEG
        if analysis['image_type'] == 'JPEG':
            dct_analysis = self._analyze_dct_coefficients(data)
            if dct_analysis['suspicious']:
                analysis['steganography_findings'].append({
                    'type': 'DCT_steganography',
                    'confidence': dct_analysis['confidence'],
                    'details': dct_analysis
                })
        
        # Palette analysis for GIF/PNG
        if analysis['image_type'] in ['GIF', 'PNG']:
            palette_analysis = self._analyze_palette_steganography(data)
            if palette_analysis['suspicious']:
                analysis['steganography_findings'].append({
                    'type': 'palette_steganography',
                    'confidence': palette_analysis['confidence'],
                    'details': palette_analysis
                })
        
        return analysis
    
    def _detect_image_type(self, data: bytes) -> Optional[str]:
        """Detect image file type from signature"""
        for img_type, signature in self.image_signatures.items():
            if data.startswith(signature):
                return img_type
        return None
    
    def _analyze_lsb_steganography(self, data: bytes, image_type: str) -> Dict[str, Any]:
        """Analyze LSB (Least Significant Bit) steganography"""
        analysis = {
            'suspicious': False,
            'confidence': 0,
            'extracted_data': None,
            'entropy_analysis': {},
            'bit_plane_analysis': {}
        }
        
        if image_type == 'PNG':
            analysis.update(self._analyze_png_lsb(data))
        elif image_type == 'BMP':
            analysis.update(self._analyze_bmp_lsb(data))
        
        return analysis
    
    def _analyze_png_lsb(self, data: bytes) -> Dict[str, Any]:
        """Analyze PNG LSB steganography"""
        analysis = {
            'suspicious': False,
            'confidence': 0,
            'extracted_bits': [],
            'extracted_text': None
        }
        
        try:
            # Skip PNG signature
            pos = 8
            
            while pos < len(data) - 8:
                # Read chunk length and type
                if pos + 8 > len(data):
                    break
                
                chunk_length = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8]
                
                if chunk_type == b'IDAT':
                    # This is image data - analyze LSBs
                    chunk_data = data[pos+8:pos+8+chunk_length]
                    lsb_analysis = self._extract_lsb_from_chunk(chunk_data)
                    
                    if lsb_analysis['suspicious']:
                        analysis.update(lsb_analysis)
                        break
                
                pos += 8 + chunk_length + 4  # Skip chunk + CRC
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_bmp_lsb(self, data: bytes) -> Dict[str, Any]:
        """Analyze BMP LSB steganography"""
        analysis = {
            'suspicious': False,
            'confidence': 0,
            'extracted_bits': [],
            'extracted_text': None
        }
        
        try:
            if len(data) < 54:  # Minimum BMP header size
                return analysis
            
            # Read BMP header
            file_size = struct.unpack('<I', data[2:6])[0]
            data_offset = struct.unpack('<I', data[10:14])[0]
            
            if data_offset < len(data):
                # Extract LSBs from pixel data
                pixel_data = data[data_offset:]
                lsb_analysis = self._extract_lsb_from_pixels(pixel_data)
                analysis.update(lsb_analysis)
        
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis
    
    def _extract_lsb_from_chunk(self, chunk_data: bytes) -> Dict[str, Any]:
        """Extract LSBs from image chunk data"""
        analysis = {
            'suspicious': False,
            'confidence': 0,
            'extracted_bits': [],
            'extracted_text': None
        }
        
        # Extract LSBs
        lsb_bits = []
        for byte in chunk_data[:1000]:  # Limit analysis
            lsb_bits.append(byte & 1)
        
        # Convert bits to bytes
        extracted_bytes = []
        for i in range(0, len(lsb_bits) - 7, 8):
            byte_bits = lsb_bits[i:i+8]
            byte_value = sum(bit << (7-j) for j, bit in enumerate(byte_bits))
            extracted_bytes.append(byte_value)
        
        # Check if extracted data looks like text
        try:
            extracted_text = bytes(extracted_bytes).decode('utf-8', errors='ignore')
            printable_ratio = sum(1 for c in extracted_text if c.isprintable()) / len(extracted_text)
            
            if printable_ratio > 0.8 and len(extracted_text) > 10:
                analysis['suspicious'] = True
                analysis['confidence'] = min(95, int(printable_ratio * 100))
                analysis['extracted_text'] = extracted_text[:200]
                
                # Check for flag patterns
                if any(keyword in extracted_text.lower() for keyword in ['flag', 'ctf', 'password']):
                    analysis['confidence'] += 20
        
        except:
            pass
        
        analysis['extracted_bits'] = lsb_bits[:100]  # First 100 bits for analysis
        return analysis
    
    def _extract_lsb_from_pixels(self, pixel_data: bytes) -> Dict[str, Any]:
        """Extract LSBs from raw pixel data"""
        analysis = {
            'suspicious': False,
            'confidence': 0,
            'extracted_text': None
        }
        
        # Extract LSBs from every byte (simplified)
        lsb_bits = [byte & 1 for byte in pixel_data[:8000]]  # Limit analysis
        
        # Convert to text
        extracted_bytes = []
        for i in range(0, len(lsb_bits) - 7, 8):
            byte_bits = lsb_bits[i:i+8]
            byte_value = sum(bit << (7-j) for j, bit in enumerate(byte_bits))
            extracted_bytes.append(byte_value)
        
        try:
            extracted_text = bytes(extracted_bytes).decode('utf-8', errors='ignore')
            printable_ratio = sum(1 for c in extracted_text if c.isprintable()) / len(extracted_text)
            
            if printable_ratio > 0.7:
                analysis['suspicious'] = True
                analysis['confidence'] = int(printable_ratio * 80)
                analysis['extracted_text'] = extracted_text[:200]
        except:
            pass
        
        return analysis
    
    def _analyze_image_metadata(self, data: bytes, image_type: str) -> Dict[str, Any]:
        """Analyze image metadata for hidden information"""
        metadata = {
            'exif_data': {},
            'comments': [],
            'suspicious_metadata': []
        }
        
        if image_type == 'JPEG':
            metadata.update(self._extract_jpeg_metadata(data))
        elif image_type == 'PNG':
            metadata.update(self._extract_png_metadata(data))
        
        return metadata
    
    def _extract_jpeg_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract JPEG EXIF and comment data"""
        metadata = {
            'exif_data': {},
            'comments': [],
            'suspicious_metadata': []
        }
        
        try:
            pos = 2  # Skip JPEG signature
            
            while pos < len(data) - 4:
                if data[pos:pos+2] != b'\xff':
                    break
                
                marker = data[pos+1]
                
                if marker == 0xfe:  # Comment marker
                    length = struct.unpack('>H', data[pos+2:pos+4])[0]
                    comment = data[pos+4:pos+2+length].decode('utf-8', errors='ignore')
                    metadata['comments'].append(comment)
                    
                    # Check for suspicious content
                    if any(keyword in comment.lower() for keyword in ['flag', 'hidden', 'secret']):
                        metadata['suspicious_metadata'].append({
                            'type': 'comment',
                            'content': comment,
                            'suspicious_keywords': [kw for kw in ['flag', 'hidden', 'secret'] if kw in comment.lower()]
                        })
                
                elif marker == 0xe1:  # EXIF marker
                    length = struct.unpack('>H', data[pos+2:pos+4])[0]
                    exif_data = data[pos+4:pos+2+length]
                    metadata['exif_data'] = self._parse_exif_data(exif_data)
                
                # Move to next marker
                if pos + 4 < len(data):
                    length = struct.unpack('>H', data[pos+2:pos+4])[0]
                    pos += 2 + length
                else:
                    break
        
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _extract_png_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract PNG metadata chunks"""
        metadata = {
            'text_chunks': [],
            'suspicious_metadata': []
        }
        
        try:
            pos = 8  # Skip PNG signature
            
            while pos < len(data) - 8:
                chunk_length = struct.unpack('>I', data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8]
                
                if chunk_type in [b'tEXt', b'iTXt', b'zTXt']:
                    chunk_data = data[pos+8:pos+8+chunk_length]
                    text_info = self._parse_png_text_chunk(chunk_data, chunk_type)
                    metadata['text_chunks'].append(text_info)
                    
                    # Check for suspicious content
                    if any(keyword in text_info.get('text', '').lower() for keyword in ['flag', 'hidden', 'secret']):
                        metadata['suspicious_metadata'].append({
                            'type': 'text_chunk',
                            'content': text_info,
                            'chunk_type': chunk_type.decode('utf-8')
                        })
                
                pos += 8 + chunk_length + 4  # Skip chunk + CRC
        
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _parse_exif_data(self, exif_data: bytes) -> Dict[str, Any]:
        """Parse EXIF data (simplified)"""
        exif_info = {}
        
        # Look for text strings in EXIF data
        text_pattern = rb'[\x20-\x7E]{4,}'
        for match in re.finditer(text_pattern, exif_data):
            text = match.group().decode('utf-8', errors='ignore')
            if len(text) > 4:
                exif_info[f'text_{match.start()}'] = text
        
        return exif_info
    
    def _parse_png_text_chunk(self, chunk_data: bytes, chunk_type: bytes) -> Dict[str, Any]:
        """Parse PNG text chunk"""
        text_info = {
            'chunk_type': chunk_type.decode('utf-8'),
            'keyword': '',
            'text': ''
        }
        
        try:
            if chunk_type == b'tEXt':
                # Find null separator
                null_pos = chunk_data.find(b'\x00')
                if null_pos != -1:
                    text_info['keyword'] = chunk_data[:null_pos].decode('utf-8', errors='ignore')
                    text_info['text'] = chunk_data[null_pos+1:].decode('utf-8', errors='ignore')
            
            elif chunk_type == b'iTXt':
                # International text chunk (more complex)
                parts = chunk_data.split(b'\x00', 4)
                if len(parts) >= 2:
                    text_info['keyword'] = parts[0].decode('utf-8', errors='ignore')
                    if len(parts) > 4:
                        text_info['text'] = parts[4].decode('utf-8', errors='ignore')
        
        except Exception as e:
            text_info['error'] = str(e)
        
        return text_info
    
    def _statistical_analysis(self, data: bytes) -> Dict[str, Any]:
        """Statistical analysis for steganography detection"""
        analysis = {
            'entropy': self._calculate_entropy(data),
            'chi_square': self._chi_square_test(data),
            'byte_frequency': {},
            'suspicious_patterns': []
        }
        
        # Byte frequency analysis
        byte_counts = Counter(data)
        analysis['byte_frequency'] = dict(byte_counts.most_common(10))
        
        # Look for suspicious patterns
        if analysis['entropy'] > 7.8:
            analysis['suspicious_patterns'].append('High entropy - possible encryption/compression')
        
        if analysis['chi_square'] > 255:
            analysis['suspicious_patterns'].append('Non-uniform byte distribution')
        
        return analysis
    
    def _visual_pattern_analysis(self, data: bytes, image_type: str) -> Dict[str, Any]:
        """Visual pattern analysis for steganography"""
        analysis = {
            'bit_plane_analysis': {},
            'histogram_analysis': {},
            'pattern_detection': []
        }
        
        # Simplified bit plane analysis
        if len(data) > 1000:
            sample_data = data[100:1100]  # Sample 1000 bytes
            
            for bit_pos in range(8):
                bit_values = [(byte >> bit_pos) & 1 for byte in sample_data]
                bit_entropy = self._calculate_bit_entropy(bit_values)
                analysis['bit_plane_analysis'][f'bit_{bit_pos}'] = {
                    'entropy': bit_entropy,
                    'suspicious': bit_entropy > 0.9
                }
        
        return analysis
    
    def _analyze_dct_coefficients(self, data: bytes) -> Dict[str, Any]:
        """Analyze DCT coefficients for JPEG steganography"""
        analysis = {
            'suspicious': False,
            'confidence': 0,
            'coefficient_analysis': {}
        }
        
        # Simplified DCT analysis - look for patterns in JPEG data
        # This would require full JPEG parsing in a real implementation
        
        # Look for suspicious patterns in JPEG data
        suspicious_patterns = 0
        
        # Check for regular patterns that might indicate steganography
        for i in range(0, len(data) - 100, 100):
            block = data[i:i+100]
            if len(set(block)) < 10:  # Very low variety in block
                suspicious_patterns += 1
        
        if suspicious_patterns > len(data) // 1000:
            analysis['suspicious'] = True
            analysis['confidence'] = min(80, suspicious_patterns * 10)
        
        return analysis
    
    def _analyze_palette_steganography(self, data: bytes) -> Dict[str, Any]:
        """Analyze palette-based steganography"""
        analysis = {
            'suspicious': False,
            'confidence': 0,
            'palette_analysis': {}
        }
        
        # Look for palette modifications (simplified)
        # This would require full image format parsing in a real implementation
        
        return analysis
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        byte_counts = Counter(data)
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_bit_entropy(self, bits: List[int]) -> float:
        """Calculate entropy of bit sequence"""
        if not bits:
            return 0.0
        
        ones = sum(bits)
        zeros = len(bits) - ones
        
        if ones == 0 or zeros == 0:
            return 0.0
        
        p_one = ones / len(bits)
        p_zero = zeros / len(bits)
        
        return -(p_one * math.log2(p_one) + p_zero * math.log2(p_zero))
    
    def _chi_square_test(self, data: bytes) -> float:
        """Chi-square test for randomness"""
        if len(data) < 256:
            return 0.0
        
        expected = len(data) / 256
        byte_counts = Counter(data)
        
        chi_square = 0.0
        for i in range(256):
            observed = byte_counts.get(i, 0)
            chi_square += ((observed - expected) ** 2) / expected
        
        return chi_square

class TextSteganographyAnalyzer:
    """Text steganography detection and analysis"""
    
    def __init__(self):
        self.unicode_steganography_chars = [
            '\u200b',  # Zero width space
            '\u200c',  # Zero width non-joiner
            '\u200d',  # Zero width joiner
            '\u2060',  # Word joiner
            '\ufeff'   # Zero width no-break space
        ]
    
    def analyze_text_steganography(self, text: str) -> Dict[str, Any]:
        """Comprehensive text steganography analysis"""
        analysis = {
            'text_length': len(text),
            'steganography_findings': [],
            'whitespace_analysis': {},
            'unicode_analysis': {},
            'linguistic_analysis': {},
            'format_analysis': {}
        }
        
        # Whitespace steganography
        whitespace_results = self._analyze_whitespace_steganography(text)
        if whitespace_results['suspicious']:
            analysis['steganography_findings'].append({
                'type': 'whitespace_steganography',
                'confidence': whitespace_results['confidence'],
                'details': whitespace_results
            })
        
        # Unicode steganography
        unicode_results = self._analyze_unicode_steganography(text)
        if unicode_results['suspicious']:
            analysis['steganography_findings'].append({
                'type': 'unicode_steganography',
                'confidence': unicode_results['confidence'],
                'details': unicode_results
            })
        
        # Linguistic steganography
        linguistic_results = self._analyze_linguistic_steganography(text)
        if linguistic_results['suspicious']:
            analysis['steganography_findings'].append({
                'type': 'linguistic_steganography',
                'confidence': linguistic_results['confidence'],
                'details': linguistic_results
            })
        
        return analysis
    
    def _analyze_whitespace_steganography(self, text: str) -> Dict[str, Any]:
        """Analyze whitespace-based steganography"""
        analysis = {
            'suspicious': False,
            'confidence': 0,
            'patterns': [],
            'extracted_data': None
        }
        
        # Count different types of whitespace
        spaces = text.count(' ')
        tabs = text.count('\t')
        newlines = text.count('\n')
        
        # Look for suspicious patterns
        lines = text.split('\n')
        trailing_spaces = []
        
        for i, line in enumerate(lines):
            trailing = len(line) - len(line.rstrip(' \t'))
            if trailing > 0:
                trailing_spaces.append((i, trailing))
        
        # Check for binary patterns in trailing spaces
        if len(trailing_spaces) > 5:
            binary_pattern = []
            for _, count in trailing_spaces:
                # Convert trailing space count to binary representation
                if count == 1:
                    binary_pattern.append('0')
                elif count == 2:
                    binary_pattern.append('1')
            
            if len(binary_pattern) >= 8:
                # Try to decode as ASCII
                try:
                    decoded_chars = []
                    for i in range(0, len(binary_pattern) - 7, 8):
                        byte_str = ''.join(binary_pattern[i:i+8])
                        if len(byte_str) == 8:
                            char_code = int(byte_str, 2)
                            if 32 <= char_code <= 126:
                                decoded_chars.append(chr(char_code))
                    
                    if decoded_chars:
                        decoded_text = ''.join(decoded_chars)
                        analysis['suspicious'] = True
                        analysis['confidence'] = 80
                        analysis['extracted_data'] = decoded_text
                        analysis['patterns'].append('trailing_space_binary')
                
                except:
                    pass
        
        # Check for tab/space patterns
        tab_space_pattern = re.findall(r'[\t ]+', text)
        if len(tab_space_pattern) > 10:
            # Look for binary encoding using tabs and spaces
            binary_str = ''
            for pattern in tab_space_pattern:
                if pattern == '\t':
                    binary_str += '1'
                elif pattern == ' ':
                    binary_str += '0'
            
            if len(binary_str) >= 8:
                analysis['patterns'].append('tab_space_binary')
                if not analysis['suspicious']:
                    analysis['confidence'] = 60
                    analysis['suspicious'] = True
        
        return analysis
    
    def _analyze_unicode_steganography(self, text: str) -> Dict[str, Any]:
        """Analyze Unicode-based steganography"""
        analysis = {
            'suspicious': False,
            'confidence': 0,
            'zero_width_chars': [],
            'homoglyphs': [],
            'extracted_data': None
        }
        
        # Count zero-width characters
        for char in self.unicode_steganography_chars:
            count = text.count(char)
            if count > 0:
                analysis['zero_width_chars'].append({
                    'char': char,
                    'unicode': f'U+{ord(char):04X}',
                    'count': count,
                    'positions': [i for i, c in enumerate(text) if c == char]
                })
        
        if analysis['zero_width_chars']:
            analysis['suspicious'] = True
            analysis['confidence'] = 70
            
            # Try to extract hidden message
            positions = []
            for char_info in analysis['zero_width_chars']:
                positions.extend(char_info['positions'])
            
            positions.sort()
            
            # Convert positions to binary pattern
            if len(positions) >= 8:
                # Simple extraction: presence of zero-width char = 1, absence = 0
                binary_pattern = []
                for i in range(min(len(text), max(positions) + 1)):
                    if i in positions:
                        binary_pattern.append('1')
                    else:
                        binary_pattern.append('0')
                
                # Try to decode
                try:
                    decoded_chars = []
                    for i in range(0, len(binary_pattern) - 7, 8):
                        byte_str = ''.join(binary_pattern[i:i+8])
                        char_code = int(byte_str, 2)
                        if 32 <= char_code <= 126:
                            decoded_chars.append(chr(char_code))
                    
                    if decoded_chars:
                        analysis['extracted_data'] = ''.join(decoded_chars)
                        analysis['confidence'] = 90
                
                except:
                    pass
        
        # Look for homoglyph substitution
        homoglyph_pairs = [
            ('a', 'а'),  # Latin 'a' vs Cyrillic 'а'
            ('o', 'о'),  # Latin 'o' vs Cyrillic 'о'
            ('p', 'р'),  # Latin 'p' vs Cyrillic 'р'
            ('e', 'е'),  # Latin 'e' vs Cyrillic 'е'
        ]
        
        for latin, cyrillic in homoglyph_pairs:
            if cyrillic in text:
                analysis['homoglyphs'].append({
                    'latin': latin,
                    'substitute': cyrillic,
                    'count': text.count(cyrillic)
                })
        
        if analysis['homoglyphs']:
            analysis['suspicious'] = True
            analysis['confidence'] = max(analysis['confidence'], 60)
        
        return analysis
    
    def _analyze_linguistic_steganography(self, text: str) -> Dict[str, Any]:
        """Analyze linguistic steganography patterns"""
        analysis = {
            'suspicious': False,
            'confidence': 0,
            'patterns': [],
            'extracted_data': None
        }
        
        # Look for acrostic patterns (first letter of each line/sentence)
        lines = text.split('\n')
        if len(lines) > 5:
            first_letters = []
            for line in lines:
                line = line.strip()
                if line:
                    first_letters.append(line[0].upper())
            
            acrostic = ''.join(first_letters)
            
            # Check if acrostic contains meaningful words
            if any(keyword in acrostic for keyword in ['FLAG', 'CTF', 'HIDDEN', 'SECRET']):
                analysis['suspicious'] = True
                analysis['confidence'] = 85
                analysis['extracted_data'] = acrostic
                analysis['patterns'].append('acrostic')
        
        # Look for word substitution patterns
        sentences = re.split(r'[.!?]+', text)
        if len(sentences) > 5:
            # Check for unusual word choices or patterns
            word_lengths = []
            for sentence in sentences:
                words = sentence.strip().split()
                if words:
                    word_lengths.append(len(words[0]) % 2)  # Even/odd first word length
            
            # If there's a clear binary pattern in word lengths
            if len(word_lengths) >= 8:
                binary_str = ''.join(str(length) for length in word_lengths)
                
                try:
                    decoded_chars = []
                    for i in range(0, len(binary_str) - 7, 8):
                        byte_str = binary_str[i:i+8]
                        char_code = int(byte_str, 2)
                        if 32 <= char_code <= 126:
                            decoded_chars.append(chr(char_code))
                    
                    if decoded_chars and len(decoded_chars) > 2:
                        decoded_text = ''.join(decoded_chars)
                        if any(keyword in decoded_text.upper() for keyword in ['FLAG', 'CTF']):
                            analysis['suspicious'] = True
                            analysis['confidence'] = 75
                            analysis['extracted_data'] = decoded_text
                            analysis['patterns'].append('word_length_encoding')
                
                except:
                    pass
        
        return analysis

class SteganographySuite:
    """Main steganography analysis suite"""
    
    def __init__(self):
        self.image_analyzer = ImageSteganographyAnalyzer()
        self.text_analyzer = TextSteganographyAnalyzer()
    
    def analyze_data(self, data: bytes, filename: str = None, data_type: str = None) -> Dict[str, Any]:
        """Comprehensive steganography analysis"""
        analysis = {
            'filename': filename,
            'data_size': len(data),
            'data_type': data_type or self._detect_data_type(data),
            'steganography_findings': [],
            'analysis_results': {}
        }
        
        # Image steganography analysis
        if analysis['data_type'] in ['PNG', 'JPEG', 'GIF', 'BMP']:
            image_results = self.image_analyzer.analyze_image_steganography(data, filename)
            analysis['analysis_results']['image'] = image_results
            analysis['steganography_findings'].extend(image_results.get('steganography_findings', []))
        
        # Text steganography analysis
        try:
            text = data.decode('utf-8', errors='ignore')
            if len(text) > 50 and self._is_likely_text(text):
                text_results = self.text_analyzer.analyze_text_steganography(text)
                analysis['analysis_results']['text'] = text_results
                analysis['steganography_findings'].extend(text_results.get('steganography_findings', []))
        except:
            pass
        
        # Audio/Video analysis placeholder
        if analysis['data_type'] in ['WAV', 'MP3', 'MP4', 'AVI']:
            analysis['analysis_results']['audio_video'] = self._analyze_audio_video_steganography(data)
        
        return analysis
    
    def _detect_data_type(self, data: bytes) -> str:
        """Detect data type from file signature"""
        signatures = {
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'\xff\xd8\xff': 'JPEG',
            b'GIF8': 'GIF',
            b'BM': 'BMP',
            b'RIFF': 'WAV',
            b'ID3': 'MP3',
            b'\x00\x00\x00\x18ftypmp4': 'MP4'
        }
        
        for signature, file_type in signatures.items():
            if data.startswith(signature):
                return file_type
        
        return 'unknown'
    
    def _is_likely_text(self, text: str) -> bool:
        """Check if string is likely readable text"""
        printable_ratio = sum(1 for c in text if c.isprintable()) / len(text)
        return printable_ratio > 0.7
    
    def _analyze_audio_video_steganography(self, data: bytes) -> Dict[str, Any]:
        """Placeholder for audio/video steganography analysis"""
        return {
            'note': 'Audio/video steganography analysis not yet implemented',
            'file_size': len(data),
            'potential_techniques': [
                'LSB in audio samples',
                'Phase encoding',
                'Echo hiding',
                'Spread spectrum'
            ]
        }