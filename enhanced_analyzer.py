"""
Enhanced PCAP analyzer with advanced features for FlagSniff Pro
"""

import os
import re
import base64
import hashlib
import tempfile
import json
import binascii
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from scapy.all import rdpcap, PcapReader, TCP, IP, UDP, Raw
import tempfile

from utils.parsers import PacketParser
from utils.patterns import PatternMatcher
from analyzers.ctf.ctf_analyzer import CTFAnalyzer, NetworkTrafficDecoder, EncodingDecoder, PatternExtractor
from ai.workflow_orchestrator import WorkflowOrchestrator, WorkflowStep, create_network_ctf_workflow
from ai.multi_agent_system import MultiAgentCoordinator, NetworkAnalysisAgent, CryptoAnalysisAgent, WebAnalysisAgent, BinaryAnalysisAgent, create_multi_agent_system

class EnhancedWebPcapAnalyzer:
    """Enhanced PCAP analyzer with advanced features for web interface"""
    
    def __init__(self, logger=None, ai_agent=None, ctf_analyzer=None):
        self.parser = PacketParser()
        self.pattern_matcher = PatternMatcher()
        self.logger = logger
        self.ai_agent = ai_agent
        self.ctf_analyzer = ctf_analyzer or CTFAnalyzer()
        self.network_decoder = NetworkTrafficDecoder()
        self.encoding_decoder = EncodingDecoder()
        self.pattern_extractor = PatternExtractor()
        
        # Initialize workflow orchestrator
        self.workflow_orchestrator = WorkflowOrchestrator(logger)
        
        # Initialize multi-agent system
        self.multi_agent_coordinator, self.agents = create_multi_agent_system(logger)
        
        # Configure network agent with our decoders
        if 'network' in self.agents:
            self.agents['network'].network_decoder = self.network_decoder
        
        # Configure crypto agent with our decoders
        if 'crypto' in self.agents:
            self.agents['crypto'].encoding_decoder = self.encoding_decoder
        
        # File signatures for carving
        self.file_signatures = {
            b'\x89PNG\r\n\x1a\n': {'ext': 'png', 'name': 'PNG Image'},
            b'\xff\xd8\xff': {'ext': 'jpg', 'name': 'JPEG Image'},
            b'GIF87a': {'ext': 'gif', 'name': 'GIF Image'},
            b'GIF89a': {'ext': 'gif', 'name': 'GIF Image'},
            b'%PDF': {'ext': 'pdf', 'name': 'PDF Document'},
            b'PK\x03\x04': {'ext': 'zip', 'name': 'ZIP Archive'},
            b'PK\x05\x06': {'ext': 'zip', 'name': 'ZIP Archive'},
            b'PK\x07\x08': {'ext': 'zip', 'name': 'ZIP Archive'},
            b'\x1f\x8b\x08': {'ext': 'gz', 'name': 'GZIP Archive'},
            b'BZh': {'ext': 'bz2', 'name': 'BZIP2 Archive'},
            b'\x7fELF': {'ext': 'elf', 'name': 'ELF Binary'},
            b'MZ': {'ext': 'exe', 'name': 'Windows Executable'},
            b'\x00\x00\x01\x00': {'ext': 'ico', 'name': 'Windows Icon'},
            b'RIFF': {'ext': 'wav', 'name': 'WAV Audio'},
            b'ID3': {'ext': 'mp3', 'name': 'MP3 Audio'},
            b'\x00\x00\x00\x20\x66\x74\x79\x70': {'ext': 'mp4', 'name': 'MP4 Video'},
            b'\x00\x00\x00\x18\x66\x74\x79\x70': {'ext': 'mp4', 'name': 'MP4 Video'},
            b'\x00\x00\x00\x1c\x66\x74\x79\x70': {'ext': 'mp4', 'name': 'MP4 Video'},
            
            # Extended CTF-specific signatures
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
            
            # Steganography containers
            b'\x89PNG\r\n\x1a\n': {'ext': 'png', 'name': 'PNG with Potential Steganography'},
            b'\xff\xd8\xff': {'ext': 'jpg', 'name': 'JPEG with Potential Steganography'},
            
            # Additional document formats
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': {'ext': 'doc', 'name': 'Microsoft Word Document'},
            b'PK\x03\x04\x14\x00\x06\x00': {'ext': 'docx', 'name': 'Microsoft Word Document (XML)'},
            b'{\\rtf': {'ext': 'rtf', 'name': 'Rich Text Format'},
            
            # Additional archive formats
            b'\x37\x7a\xbc\xaf\x27\x1c': {'ext': '7z', 'name': '7-Zip Archive'},
            b'\x52\x61\x72\x21\x1a\x07': {'ext': 'rar', 'name': 'RAR Archive'},
            b'7z\xbc\xaf\x27\x1c': {'ext': '7z', 'name': '7-Zip Archive'},
            
            # Additional media formats
            b'RIFF....AVI': {'ext': 'avi', 'name': 'AVI Video'},
            b'FLV\x01': {'ext': 'flv', 'name': 'Flash Video'},
            b'\x1aE\xdf\xa3': {'ext': 'mkv', 'name': 'Matroska Video'},
            
            # Database files
            b'SQLite format 3\x00': {'ext': 'db', 'name': 'SQLite Database'},
            b'\x00\x01\x02\x03': {'ext': 'dbf', 'name': 'dBase Database'},
            
            # Certificate files
            b'-----BEGIN': {'ext': 'pem', 'name': 'PEM Certificate'},
            b'0\x82': {'ext': 'der', 'name': 'DER Certificate'},
        }
        
        self.results = {
            'total_packets': 0,
            'analyzed_packets': 0,
            'findings': [],
            'statistics': {},
            'analysis_time': None,
            'file_info': {},
            'ctf_findings': [],
            'hints': [],
            'suspicious_packets': [],
            'decoded_data': [],
            'extracted_patterns': [],
            'potential_flags': [],
            'workflow_steps': [],
            'agent_activities': [],
            'multi_agent_report': {},
            'reconstructed_streams': {},
            'flag_reassemblies': [],
            'encryption_attempts': [],
            # New advanced features
            'extracted_files': [],
            'sessions': {},
            'exploit_suggestions': [],
            'timeline': [],
            'correlation_graph': {'nodes': [], 'edges': []},
            'ai_hints': [],
            'file_carving_results': [],
            'malware_analysis': [],
            'protocol_sessions': {}
        }
    
    def _reconstruct_tcp_streams(self, packets):
        """Reconstruct TCP streams from packets"""
        streams = {}
        for i, pkt in enumerate(packets):
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            tcp = pkt[TCP]
            # Use 4-tuple as stream key (handle both directions)
            key_fwd = (ip.src, tcp.sport, ip.dst, tcp.dport)
            key_rev = (ip.dst, tcp.dport, ip.src, tcp.sport)
            if key_fwd in streams:
                stream = streams[key_fwd]
            elif key_rev in streams:
                stream = streams[key_rev]
            else:
                stream = {
                    'packets': [],
                    'src_ip': ip.src,
                    'src_port': tcp.sport,
                    'dst_ip': ip.dst,
                    'dst_port': tcp.dport,
                    'protocol': 'TCP',
                    'data': b'',
                    'packet_indices': [],
                    'http_requests': [],
                    'http_responses': []
                }
                streams[key_fwd] = stream
            # Add packet to stream
            stream['packets'].append(pkt)
            stream['packet_indices'].append(i)
            # Append payload if present
            if pkt.haslayer(Raw):
                stream['data'] += pkt[Raw].load
        # Try to extract HTTP messages from streams
        for stream in streams.values():
            try:
                text = stream['data'].decode('utf-8', errors='ignore')
                # Split HTTP requests/responses
                http_msgs = text.split('\r\n\r\n')
                for msg in http_msgs:
                    if msg.startswith('GET') or msg.startswith('POST') or msg.startswith('PUT') or msg.startswith('DELETE'):
                        stream['http_requests'].append(msg)
                    elif msg.startswith('HTTP/'):
                        stream['http_responses'].append(msg)
            except Exception:
                pass
        return streams

    def _reassemble_flag_chunks(self, findings):
        """Attempt to reassemble flags split across multiple findings"""
        flag_pattern = re.compile(r'(flag\{[^}]*|CTF\{[^}]*|HTB\{[^}]*|DUCTF\{[^}]*|PICOCTF\{[^}]*|FLAG\{[^}]*|\})', re.IGNORECASE)
        partials = []
        for f in findings:
            match = flag_pattern.search(f.get('data', ''))
            if match:
                partials.append((f['packet_index'], match.group(0), f))
        # Try to join partials by packet order
        reassembled = []
        used = set()
        for i, (idx1, chunk1, f1) in enumerate(partials):
            if idx1 in used:
                continue
            flag = chunk1
            context = [chunk1]
            used.add(idx1)
            for j, (idx2, chunk2, f2) in enumerate(partials):
                if idx2 in used or idx2 == idx1:
                    continue
                # If chunk1 is an opening and chunk2 is a closing, or vice versa
                if (flag.endswith('{') and not chunk2.startswith('flag{')) or (not flag.endswith('}') and chunk2.endswith('}')):
                    flag += chunk2
                    context.append(chunk2)
                    used.add(idx2)
            if flag.startswith(('flag{', 'CTF{', 'HTB{', 'DUCTF{', 'PICOCTF{', 'FLAG{')) and flag.endswith('}') and len(flag) > 8:
                reassembled.append({'reassembled_flag': flag, 'flag_chunks': context, 'packet_indices': [idx1] + [idx2 for idx2 in used if idx2 != idx1]})
        return reassembled

    def _attempt_decryption(self, findings, user_decrypt_key):
        """Try to decrypt detected blobs with user-supplied key/password"""
        from Crypto.Cipher import AES
        attempts = []
        if not user_decrypt_key:
            return attempts
        for f in findings:
            data = f.get('data', '')
            # Try base64 decode + XOR
            try:
                decoded = base64.b64decode(data)
                # XOR with key
                key = user_decrypt_key.encode()
                xored = bytes([b ^ key[i % len(key)] for i, b in enumerate(decoded)])
                attempts.append({'method': 'Base64+XOR', 'input': data, 'output': xored.decode('utf-8', errors='ignore'), 'status': 'success', 'key': user_decrypt_key})
            except Exception:
                pass
            # Try AES decryption (CBC, 16-byte key)
            try:
                if len(user_decrypt_key) in (16, 24, 32):
                    cipher = AES.new(user_decrypt_key.encode(), AES.MODE_ECB)
                    decrypted = cipher.decrypt(base64.b64decode(data))
                    attempts.append({'method': 'AES-ECB', 'input': data, 'output': decrypted.decode('utf-8', errors='ignore'), 'status': 'success', 'key': user_decrypt_key})
            except Exception:
                pass
        return attempts

    def _enhanced_file_carving(self, streams):
        """Delegate to analyzers.forensics.enhanced_file_carving."""
        from analyzers.forensics import enhanced_file_carving as _enhanced
        return _enhanced(streams, self.file_signatures)

    def _analyze_carved_files(self, carved_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched = []
        for f in carved_files:
            data = f.get('data', b'') or b''
            ext = (f.get('extension') or '').lower()
            analysis = {'metadata': {}, 'stego': [], 'strings': []}
            try:
                # EXIF/metadata for images
                if ext in ('png', 'jpg', 'jpeg', 'gif') and data:
                    try:
                        from PIL import Image, ExifTags
                        img = Image.open(io.BytesIO(data))
                        analysis['metadata']['format'] = getattr(img, 'format', '')
                        analysis['metadata']['size'] = getattr(img, 'size', '')
                        analysis['metadata']['mode'] = getattr(img, 'mode', '')
                        if hasattr(img, '_getexif') and img._getexif():
                            raw_exif = img._getexif() or {}
                            exif_info = {}
                            for tag, val in raw_exif.items():
                                name = ExifTags.TAGS.get(tag, str(tag))
                                exif_info[name] = str(val)[:200]
                            if exif_info:
                                analysis['metadata']['exif'] = exif_info
                    except Exception:
                        pass
                
                # PNG chunk scan and text extraction
                if ext == 'png' and data:
                    try:
                        stego_text = self._png_lsb_extract(data)
                        if stego_text:
                            analysis['stego'].append({
                                'type': 'lsb',
                                'content': stego_text[:500],
                                'method': 'PNG LSB Steganography'
                            })
                    except Exception:
                        pass
                
                # ZIP file analysis
                if ext == 'zip' and data:
                    try:
                        import zipfile
                        import io
                        zip_io = io.BytesIO(data)
                        with zipfile.ZipFile(zip_io, 'r') as zip_file:
                            file_list = zip_file.namelist()
                            analysis['metadata']['zip_files'] = file_list[:20]  # Limit to first 20 files
                            analysis['metadata']['zip_file_count'] = len(file_list)
                            
                            # Look for interesting files in the ZIP
                            interesting_patterns = [
                                r'flag', r'password', r'key', r'secret', r'hidden',
                                r'\.(txt|doc|pdf|jpg|png|gif)$'
                            ]
                            
                            interesting_files = []
                            for filename in file_list:
                                for pattern in interesting_patterns:
                                    if re.search(pattern, filename, re.IGNORECASE):
                                        interesting_files.append(filename)
                                        break
                            
                            if interesting_files:
                                analysis['metadata']['interesting_files'] = interesting_files
                                
                            # Extract and analyze text files within the ZIP
                            for filename in file_list:
                                if filename.lower().endswith(('.txt', '.doc', '.rtf', '.md', '.csv')):
                                    try:
                                        with zip_file.open(filename) as file:
                                            content = file.read().decode('utf-8', errors='ignore')
                                            # Look for flags in the content
                                            flag_patterns = [
                                                r'[A-Z0-9_]+\{[^\}]{4,}\}',  # CTF flag format
                                                r'flag\s*:.*',  # flag: format
                                                r'password\s*:.*',  # password: format
                                                r'secret\s*:.*',  # secret: format
                                            ]
                                            
                                            for pattern in flag_patterns:
                                                matches = re.findall(pattern, content, re.IGNORECASE)
                                                for match in matches:
                                                    analysis['stego'].append({
                                                        'type': 'hidden_string',
                                                        'content': match,
                                                        'method': f'Found in ZIP file {filename}',
                                                        'filename': filename
                                                    })
                                    except Exception:
                                        pass
                    except Exception:
                        pass
                
                # Extract strings from binary files
                if data and ext not in ['txt', 'html', 'css', 'js', 'json', 'xml']:
                    try:
                        # Extract printable strings
                        strings = self._extract_strings(data)
                        if strings:
                            # Filter for potentially interesting strings
                            interesting_strings = []
                            flag_patterns = [
                                r'[A-Z0-9_]+\{[^\}]{4,}\}',  # CTF flag format
                                r'flag\s*:.*',  # flag: format
                                r'password\s*:.*',  # password: format
                                r'secret\s*:.*',  # secret: format
                                r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64 strings
                            ]
                            
                            for s in strings[:100]:  # Limit to first 100 strings
                                # Check for flags
                                for pattern in flag_patterns:
                                    if re.search(pattern, s, re.IGNORECASE):
                                        analysis['stego'].append({
                                            'type': 'hidden_string',
                                            'content': s,
                                            'method': 'String Analysis'
                                        })
                                        break
                                else:
                                    # Add long strings that might be interesting
                                    if len(s) > 20:
                                        interesting_strings.append(s)
                            
                            if interesting_strings:
                                analysis['strings'] = interesting_strings[:20]  # Limit to 20 strings
                    except Exception:
                        pass
                
                # Add analysis to file object
                f['analysis'] = analysis
                
            except Exception:
                # Continue with basic file info even if analysis fails
                f['analysis'] = analysis
            
            enriched.append(f)
        
        return enriched

    def _extract_ftp_files(self, streams):
        """Delegate to analyzers.forensics.extract_ftp_files."""
        from analyzers.forensics import extract_ftp_files as _extract
        return _extract(streams)

    def _extract_http_files(self, packets):
        """Delegate to analyzers.forensics.extract_http_files."""
        from analyzers.forensics import extract_http_files as _extract
        return _extract(packets)

    def _extract_file_with_boundaries(self, data, pos, file_info):
        """Delegate to analyzers.forensics.extract_file_with_boundaries."""
        from analyzers.forensics import extract_file_with_boundaries as _extract
        return _extract(data, pos, file_info)

    def _extract_archive_data(self, data, pos, file_info):
        """Delegate to analyzers.forensics.extract_archive_data."""
        from analyzers.forensics import extract_archive_data as _extract
        return _extract(data, pos, file_info)

    def _carve_files_from_streams(self, streams):
        """Delegate to analyzers.forensics.carve_files_from_streams plus extras."""
        from analyzers.forensics import (
            carve_files_from_streams as _carve,
            extract_ftp_files as _ftp,
            enhanced_file_carving as _enhanced,
        )
        carved_files = _carve(streams, self.file_signatures)
        carved_files.extend(_ftp(streams))
        carved_files.extend(_enhanced(streams, self.file_signatures))
        return carved_files

    def _is_likely_file_data(self, data):
        from analyzers.forensics import is_likely_file_data as _is
        return _is(data)
    
    def _looks_like_text(self, data):
        from analyzers.forensics import looks_like_text as _looks
        return _looks(data)
    
    def _determine_file_type_from_data(self, data, ext):
        from analyzers.forensics import determine_file_type_from_data as _det
        return _det(data, ext)

    def _extract_file_from_position(self, data, pos, file_info):
        """Extract file data starting from a specific position"""
        try:
            if file_info['ext'] in ['png', 'jpg', 'gif']:
                # For images, try to find the end marker
                if file_info['ext'] == 'png':
                    end_marker = b'\x00\x00\x00\x00IEND\xaeB`\x82'
                elif file_info['ext'] == 'jpg':
                    end_marker = b'\xff\xd9'
                else:  # gif
                    end_marker = b'\x00\x3b'
                
                end_pos = data.find(end_marker, pos)
                if end_pos != -1:
                    return data[pos:end_pos + len(end_marker)]
            
            elif file_info['ext'] == 'pdf':
                # For PDF, look for %%EOF
                end_pos = data.find(b'%%EOF', pos)
                if end_pos != -1:
                    return data[pos:end_pos + 5]
            
            elif file_info['ext'] == 'zip':
                # For ZIP, try to parse the central directory
                # This is simplified - in practice you'd need proper ZIP parsing
                return data[pos:pos + 1024]  # Extract first 1KB as sample
            
            else:
                # For other files, extract a reasonable chunk
                return data[pos:pos + 1024]
                
        except Exception:
            return None

    def _build_sessions(self, packets):
        """Delegate to analyzers.forensics.build_sessions."""
        from analyzers.forensics import build_sessions as _build
        return _build(packets)

    def _generate_exploit_suggestions(self, findings):
        """Generate exploit suggestions based on findings"""
        suggestions = []
        
        for finding in findings:
            finding_type = finding.get('display_type', '')
            data = finding.get('data', '')
            protocol = finding.get('protocol', '')
            
            if finding_type == 'CREDENTIAL':
                # SQL Injection suggestions
                if 'username=' in data or 'password=' in data:
                    suggestions.append({
                        'type': 'SQL Injection',
                        'target': finding.get('src_ip', ''),
                        'description': 'Potential SQL injection in login form',
                        'payloads': [
                            "' OR '1'='1",
                            "' UNION SELECT 1,2,3--",
                            "admin'--",
                            "'; DROP TABLE users--"
                        ],
                        'tools': ['sqlmap', 'burp suite'],
                        'finding_id': len(suggestions)
                    })
                
                # Default credential suggestions
                if 'admin' in data.lower() or 'root' in data.lower():
                    suggestions.append({
                        'type': 'Default Credentials',
                        'target': finding.get('src_ip', ''),
                        'description': 'Default credentials detected',
                        'payloads': [
                            'admin:admin',
                            'root:root',
                            'admin:password',
                            'administrator:password'
                        ],
                        'tools': ['hydra', 'medusa'],
                        'finding_id': len(suggestions)
                    })
            
            elif finding_type == 'FLAG':
                # Flag format analysis
                if 'flag{' in data.lower():
                    suggestions.append({
                        'type': 'Flag Analysis',
                        'target': finding.get('src_ip', ''),
                        'description': 'Flag found - check for additional flags',
                        'payloads': [
                            'Search for similar patterns',
                            'Check for encoded/encrypted flags',
                            'Look for flag chunks in other packets'
                        ],
                        'tools': ['grep', 'strings', 'hexdump'],
                        'finding_id': len(suggestions)
                    })
            
            elif protocol == 'HTTP':
                # HTTP-based exploits
                if 'GET' in data or 'POST' in data:
                    suggestions.append({
                        'type': 'HTTP Exploitation',
                        'target': finding.get('src_ip', ''),
                        'description': 'HTTP traffic detected - potential web exploitation',
                        'payloads': [
                            'Directory traversal: ../../../etc/passwd',
                            'XSS: <script>alert(1)</script>',
                            'Command injection: | whoami',
                            'LFI: ?file=../../../etc/passwd'
                        ],
                        'tools': ['burp suite', 'nikto', 'dirb'],
                        'finding_id': len(suggestions)
                    })
            
            elif protocol == 'FTP':
                # FTP exploits
                suggestions.append({
                    'type': 'FTP Exploitation',
                    'target': finding.get('src_ip', ''),
                    'description': 'FTP service detected',
                    'payloads': [
                        'Anonymous login: ftp anonymous@target',
                        'Brute force: hydra -l user -P wordlist ftp://target',
                        'Check for writable directories'
                    ],
                    'tools': ['ftp', 'hydra', 'nmap'],
                    'finding_id': len(suggestions)
                })
        
        return suggestions

    def _build_timeline(self, packets, findings):
        """Build chronological timeline of events"""
        timeline = []
        
        # Add packet events
        for i, pkt in enumerate(packets):
            if not pkt.haslayer(IP):
                continue
                
            timestamp = pkt.time if hasattr(pkt, 'time') else datetime.now().timestamp()
            ip = pkt[IP]
            
            event = {
                'timestamp': timestamp,
                'datetime': datetime.fromtimestamp(timestamp).isoformat(),
                'type': 'packet',
                'protocol': self._get_protocol(pkt),
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'packet_index': i,
                'description': f"{ip.src} -> {ip.dst} ({self._get_protocol(pkt)})"
            }
            
            if pkt.haslayer(TCP):
                event['src_port'] = pkt[TCP].sport
                event['dst_port'] = pkt[TCP].dport
                event['description'] += f":{pkt[TCP].sport} -> :{pkt[TCP].dport}"
            elif pkt.haslayer(UDP):
                event['src_port'] = pkt[UDP].sport
                event['dst_port'] = pkt[UDP].dport
                event['description'] += f":{pkt[UDP].sport} -> :{pkt[UDP].dport}"
            
            timeline.append(event)
        
        # Add finding events
        for finding in findings:
            timestamp = finding.get('timestamp', datetime.now().timestamp())
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()
                except:
                    timestamp = datetime.now().timestamp()
            
            event = {
                'timestamp': timestamp,
                'datetime': datetime.fromtimestamp(timestamp).isoformat(),
                'type': 'finding',
                'finding_type': finding.get('display_type', ''),
                'protocol': finding.get('protocol', ''),
                'src_ip': finding.get('src_ip', ''),
                'dst_ip': finding.get('dst_ip', ''),
                'description': f"Found {finding.get('display_type', '')}: {finding.get('data', '')[:50]}...",
                'data': finding.get('data', '')
            }
            timeline.append(event)
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        return timeline
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        return timeline

    def _build_correlation_graph(self, findings, streams, sessions):
        """Build correlation graph of entities and relationships"""
        nodes = []
        edges = []
        node_ids = {}
        
        def add_node(node_type, node_id, properties=None):
            if node_id not in node_ids:
                node_ids[node_id] = len(nodes)
                nodes.append({
                    'id': node_id,
                    'type': node_type,
                    'properties': properties or {}
                })
            return node_ids[node_id]
        
        # Add IP nodes
        for finding in findings:
            src_ip = finding.get('src_ip', '')
            dst_ip = finding.get('dst_ip', '')
            
            if src_ip:
                add_node('ip', src_ip, {'role': 'source'})
            if dst_ip:
                add_node('ip', dst_ip, {'role': 'destination'})
            
            if src_ip and dst_ip:
                edges.append({
                    'source': src_ip,
                    'target': dst_ip,
                    'type': 'flow',
                    'protocol': finding.get('protocol', ''),
                    'finding_type': finding.get('display_type', '')
                })
        
        # Add flag nodes
        for finding in findings:
            if finding.get('display_type') == 'FLAG':
                flag_data = finding.get('data', '')
                if flag_data:
                    add_node('flag', flag_data, {
                        'protocol': finding.get('protocol', ''),
                        'src_ip': finding.get('src_ip', ''),
                        'dst_ip': finding.get('dst_ip', '')
                    })
        
        # Add credential nodes
        for finding in findings:
            if finding.get('display_type') == 'CREDENTIAL':
                cred_data = finding.get('data', '')
                if cred_data:
                    add_node('credential', cred_data, {
                        'protocol': finding.get('protocol', ''),
                        'src_ip': finding.get('src_ip', ''),
                        'dst_ip': finding.get('dst_ip', '')
                    })
        
        # Add session nodes
        for session_type, session_dict in sessions.items():
            for session_id, session_data in session_dict.items():
                add_node('session', session_id, {
                    'type': session_type,
                    'src_ip': session_data.get('src_ip', ''),
                    'dst_ip': session_data.get('dst_ip', ''),
                    'start_time': session_data.get('start_time', ''),
                    'end_time': session_data.get('end_time', '')
                })
        
        return {'nodes': nodes, 'edges': edges}

    def _generate_ai_hints(self, findings, challenge_description=None):
        """Generate AI-powered hints based on findings and challenge context"""
        hints = []
        
        # Analyze findings for patterns
        flag_count = sum(1 for f in findings if f.get('display_type') == 'FLAG')
        cred_count = sum(1 for f in findings if f.get('display_type') == 'CREDENTIAL')
        http_count = sum(1 for f in findings if f.get('protocol') == 'HTTP')
        ftp_count = sum(1 for f in findings if f.get('protocol') == 'FTP')
        
        # Generate contextual hints
        if flag_count > 0:
            hints.append({
                'type': 'flag_analysis',
                'priority': 'high',
                'hint': f"Found {flag_count} flag(s). Look for additional flags in other protocols or encoded formats.",
                'suggestions': [
                    'Check for base64 encoded flags',
                    'Look for hex-encoded data',
                    'Search for flag chunks across multiple packets',
                    'Check for steganography in images'
                ]
            })
        
        if cred_count > 0:
            hints.append({
                'type': 'credential_analysis',
                'priority': 'high',
                'hint': f"Found {cred_count} credential(s). These might be used for authentication or contain hidden data.",
                'suggestions': [
                    'Try these credentials on other services',
                    'Check for password reuse patterns',
                    'Look for encoded passwords',
                    'Test for default credential vulnerabilities'
                ]
            })
        
        if http_count > 0:
            hints.append({
                'type': 'web_analysis',
                'priority': 'medium',
                'hint': f"Detected {http_count} HTTP interactions. Web traffic often contains hidden data.",
                'suggestions': [
                    'Check HTTP headers for hidden information',
                    'Look for encoded data in URLs',
                    'Examine HTTP response bodies',
                    'Search for hidden directories'
                ]
            })
        
        if ftp_count > 0:
            hints.append({
                'type': 'ftp_analysis',
                'priority': 'medium',
                'hint': f"Found {ftp_count} FTP interactions. FTP can be used for data exfiltration.",
                'suggestions': [
                    'Check for file uploads/downloads',
                    'Look for hidden files',
                    'Examine FTP command sequences',
                    'Check for anonymous access'
                ]
            })
        
        # Protocol-specific hints
        protocols = set(f.get('protocol') for f in findings)
        if 'DNS' in protocols:
            hints.append({
                'type': 'dns_analysis',
                'priority': 'medium',
                'hint': 'DNS traffic detected. DNS can be used for data exfiltration or command & control.',
                'suggestions': [
                    'Check for DNS tunneling',
                    'Look for encoded data in DNS queries',
                    'Examine DNS response patterns',
                    'Search for suspicious domain names'
                ]
            })
        
        # General CTF hints
        hints.append({
            'type': 'general_ctf',
            'priority': 'low',
            'hint': 'General CTF analysis tips:',
            'suggestions': [
                'Always check for encoded/encrypted data',
                'Look for patterns in packet timing',
                'Examine all protocol layers',
                'Check for steganography',
                'Look for command & control traffic',
                'Search for file transfers'
            ]
        })
        
        return hints

    def _get_protocol(self, packet):
        """Get protocol name from packet"""
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                return 'HTTP'
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                return 'FTP'
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                return 'SSH'
            elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
                return 'Telnet'
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                return 'HTTPS'
            else:
                return 'TCP'
        elif packet.haslayer(UDP):
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                return 'DNS'
            else:
                return 'UDP'
        else:
            return 'Unknown'
    
    def analyze_file(self, file_path: str, search_options: Dict[str, bool], 
                    custom_regex: Optional[str] = None, progress_callback=None, user_decrypt_key: str = None,
                    packets=None) -> Dict[str, Any]:
        """
        Analyze PCAP file with given search options
        
        Args:
            file_path: Path to PCAP file
            search_options: Dict with search flags (flags, credentials, tokens, etc.)
            custom_regex: Optional custom regex pattern
            progress_callback: Optional callback for progress updates
            user_decrypt_key: Optional key for decryption attempts
            packets: Optional pre-loaded packets (for HTTP file extraction)
        
        Returns:
            Analysis results dictionary
        """
        start_time = datetime.now()
        
        try:
            # Get file info
            file_size = os.path.getsize(file_path)
            self.results['file_info'] = {
                'name': os.path.basename(file_path),
                'size': file_size,
                'size_mb': round(file_size / (1024 * 1024), 2)
            }
            
            # Read packets
            if progress_callback:
                progress_callback("Reading PCAP file...")
            
            packets = rdpcap(file_path)
            self.results['total_packets'] = len(packets)
            
            # Reconstruct TCP streams
            if progress_callback:
                progress_callback("Reconstructing TCP streams...")
            self.results['reconstructed_streams'] = self._reconstruct_tcp_streams(packets)
            
            # Build sessions
            if progress_callback:
                progress_callback("Building protocol sessions...")
            self.results['sessions'] = self._build_sessions(packets)
            
            # Carve files from streams
            if progress_callback:
                progress_callback("Carving files from streams...")
            # Extract files from TCP/UDP streams using file signatures
            try:
                self.results['extracted_files'] = self._carve_files_from_streams(self.results['reconstructed_streams'])
                # Extract HTTP files if packets are available
                if packets:
                    http_files = self._extract_http_files(packets)
                    self.results['extracted_files'].extend(http_files)
                # Analyze carved files for metadata and stego indicators
                if self.results['extracted_files']:
                    self.results['extracted_files'] = self._analyze_carved_files(self.results['extracted_files'])
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"File carving failed: {str(e)}")
                self.results['extracted_files'] = []
            
            # Determine search types
            search_types = []
            if search_options.get('flags', False):
                search_types.append('flag')
            if search_options.get('credentials', False):
                search_types.append('credentials')
            if search_options.get('tokens', False):
                search_types.append('tokens')
            if search_options.get('emails', False):
                search_types.append('emails')
            if search_options.get('hashes', False):
                search_types.append('hashes')
            
            # Analyze packets
            analyzed_count = 0
            findings = []
            
            for i, packet in enumerate(packets):
                if progress_callback and i % 100 == 0:
                    progress = (i / len(packets)) * 100
                    progress_callback(f"Analyzing packets... {progress:.1f}%")
                
                # Parse packet
                packet_data = self.parser.extract_data(packet)
                if not packet_data:
                    continue
                
                analyzed_count += 1
                
                # Search for patterns
                packet_findings = self.pattern_matcher.search_patterns(
                    packet_data, search_types, custom_regex
                )
                
                # Add packet index and timestamp to findings
                for finding in packet_findings:
                    finding['packet_index'] = i
                    finding['timestamp'] = packet.time if hasattr(packet, 'time') else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    findings.append(finding)
            
            self.results['analyzed_packets'] = analyzed_count
            self.results['findings'] = findings
            
            # Reassemble flag chunks
            if progress_callback:
                progress_callback("Reassembling flag chunks...")
            self.results['flag_reassemblies'] = self._reassemble_flag_chunks(findings)
            
            # Attempt decryption
            if progress_callback:
                progress_callback("Attempting decryption...")
            self.results['encryption_attempts'] = self._attempt_decryption(findings, user_decrypt_key)
            
            # Generate exploit suggestions
            if progress_callback:
                progress_callback("Generating exploit suggestions...")
            self.results['exploit_suggestions'] = self._generate_exploit_suggestions(findings)
            
            # Build timeline
            if progress_callback:
                progress_callback("Building timeline...")
            self.results['timeline'] = self._build_timeline(packets, findings)
            
            # Build correlation graph
            if progress_callback:
                progress_callback("Building correlation graph...")
            self.results['correlation_graph'] = self._build_correlation_graph(
                findings, self.results['reconstructed_streams'], self.results['sessions']
            )
            
            # Generate AI hints
            if progress_callback:
                progress_callback("Generating AI hints...")
            self.results['ai_hints'] = self._generate_ai_hints(findings)
            
            # Calculate statistics
            if progress_callback:
                progress_callback("Calculating statistics...")
            
            # Count findings by type
            by_type = {}
            by_protocol = {}
            unique_sources = set()
            unique_destinations = set()
            
            for finding in findings:
                finding_type = finding.get('display_type', 'Unknown')
                protocol = finding.get('protocol', 'Unknown')
                src_ip = finding.get('src_ip', '')
                dst_ip = finding.get('dst_ip', '')
                
                by_type[finding_type] = by_type.get(finding_type, 0) + 1
                by_protocol[protocol] = by_protocol.get(protocol, 0) + 1
                
                if src_ip:
                    unique_sources.add(src_ip)
                if dst_ip:
                    unique_destinations.add(dst_ip)
            
            self.results['statistics'] = {
                'total_findings': len(findings),
                'by_type': by_type,
                'by_protocol': by_protocol,
                'unique_sources': len(unique_sources),
                'unique_destinations': len(unique_destinations),
                'extracted_files': len(self.results['extracted_files']),
                'sessions': sum(len(sessions) for sessions in self.results['sessions'].values()),
                'exploit_suggestions': len(self.results['exploit_suggestions']),
                'ai_hints': len(self.results['ai_hints'])
            }
            
            # Calculate analysis time
            end_time = datetime.now()
            duration = end_time - start_time
            self.results['analysis_time'] = {
                'duration': str(duration),
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            }
            
            if progress_callback:
                progress_callback("Analysis complete!")
            
            return self.results
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error analyzing file: {str(e)}")
            raise e
