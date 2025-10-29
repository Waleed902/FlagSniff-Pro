"""
Enhanced PCAP analyzer for web interface integration
"""

import os
import re
import base64
import hashlib
import tempfile
import json
import binascii
import string
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from scapy.all import rdpcap, PcapReader, TCP, IP, UDP, Raw
import tempfile
import audioop
import struct
import io
import zlib

from utils.parsers import PacketParser
from utils.patterns import PatternMatcher
from analyzers.ctf.ctf_analyzer import CTFAnalyzer, NetworkTrafficDecoder, EncodingDecoder, PatternExtractor
from ai.workflow_orchestrator import WorkflowOrchestrator, WorkflowStep, create_network_ctf_workflow
from ai.multi_agent_system import MultiAgentCoordinator, NetworkAnalysisAgent, CryptoAnalysisAgent, WebAnalysisAgent, BinaryAnalysisAgent, create_multi_agent_system
from utils.email_extractors import extract_html_parts_from_stream, is_mail_port
import re as _re_pair
from apps.tshark_ai import run_tshark_analysis, tshark_available
from analyzers.protocols.http.http_pairing import pair_http_by_index
from analyzers.protocols.dns import detect_dns_exfiltration
from analyzers.protocols.tcp.streams import reconstruct_tcp_streams
from analyzers.web.flag_reassembly import reassemble_flag_chunks
from core.models import default_results_dict, Finding
from dataclasses import asdict
from analyzers.protocols.tls.tls_decrypt import decrypt_tls_with_keylog
from analyzers.forensics import identify_suspicious_packets
from analyzers.ctf.ctf_automated_reporting import AutomatedReporting
from utils.iocs import extract_from_results as extract_iocs_from_results, export_iocs as export_iocs_to_files

from utils.io_graphs import generate_io_graph_data
from utils.protocol_hierarchy import get_protocol_hierarchy
from utils.filters import apply_display_filter
from detectors.tracking_pixels import extract_pixels, reconstruct_sequences, reconstruct_sequences_relaxed
from analyzers.protocols.database.mysql import analyze_mysql_traffic
from analyzers.protocols.database.redis import analyze_redis_traffic
from analyzers.protocols.database.postgresql import analyze_postgresql_traffic
from analyzers.protocols.database.mongodb import analyze_mongodb_traffic
from analyzers.protocols.database.mssql import analyze_mssql_traffic
from analyzers.malware.signature_matcher import detect_malware_signatures
from analyzers.malware.c2_detector import detect_c2_communication
from analyzers.protocols.tls.certificate_analyzer import analyze_tls_certificates
from utils.yara_scanner import scan_with_yara

class WebPcapAnalyzer:
    """Enhanced PCAP analyzer optimized for web interface"""
    
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
        }
        
        self.results = default_results_dict()

    # (moved) DNS exfiltration detection and TCP stream reconstruction are now in analyzers.*

    # (moved) Flag reassembly now in analyzers.web.flag_reassembly

    def _attempt_decryption(self, findings, user_decrypt_key):
        """Try to decrypt detected blobs with user-supplied key/password"""
        import base64
        try:
            from Crypto.Cipher import AES  # type: ignore[import-not-found]
        except Exception:  # pragma: no cover - optional dependency
            AES = None  # type: ignore[assignment]
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
            # Try AES decryption (ECB), only if Crypto is available
            try:
                if AES is not None and len(user_decrypt_key) in (16, 24, 32):
                    cipher = AES.new(user_decrypt_key.encode(), AES.MODE_ECB)
                    decrypted = cipher.decrypt(base64.b64decode(data))
                    attempts.append({'method': 'AES-ECB', 'input': data, 'output': decrypted.decode('utf-8', errors='ignore'), 'status': 'success', 'key': user_decrypt_key})
            except Exception:
                pass
        return attempts
    
    def analyze_database_traffic(self, packets):
        """Analyzes all supported database protocols."""
        db_results = {
            'mysql': analyze_mysql_traffic(packets),
            'redis': analyze_redis_traffic(packets),
            'postgresql': analyze_postgresql_traffic(packets),
            'mongodb': analyze_mongodb_traffic(packets),
            'mssql': analyze_mssql_traffic(packets),
        }
        return db_results

    def analyze_malware_traffic(self, packets):
        """Analyzes network traffic for malware indicators."""
        malware_results = {
            'signatures': detect_malware_signatures(packets),
            'c2': detect_c2_communication(packets),
        }
        return malware_results

    def analyze_file(self, file_path: str, search_options: Dict[str, bool], 
                    custom_regex: Optional[str] = None, progress_callback=None, user_decrypt_key: str = None,
                     tls_keylog_file: Optional[str] = None, display_filter: Optional[str] = None, yara_rules: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyze PCAP file with given search options
        
        Args:
            file_path: Path to PCAP file
            search_options: Dict with search flags (flags, credentials, tokens, etc.)
            custom_regex: Optional custom regex pattern
            progress_callback: Optional callback for progress updates
            user_decrypt_key: Optional key for decryption attempts
            display_filter: Optional display filter expression
            yara_rules: Optional list of paths to YARA rule files
        
        Returns:
            Analysis results dictionary
        """
        # CRITICAL: Ensure results dict exists and is never None
        if not hasattr(self, 'results') or self.results is None:
            self.results = default_results_dict()

        start_time = datetime.now()
        
        try:
            # Get file info
            file_size = os.path.getsize(file_path)
            self.results['file_info'] = {
                'name': os.path.basename(file_path),
                'size': file_size,
                'size_mb': round(file_size / (1024 * 1024), 2)
            }
        
            # Optionally run TShark AI orchestrator first to enrich context (if enabled)
            try:
                use_tshark = bool(search_options.get('tshark_ai')) or os.environ.get('FLAGSNIFF_TSHARK','0') == '1'
            except Exception:
                use_tshark = False

            if use_tshark and tshark_available():
                if progress_callback:
                    progress_callback("Running TShark (AI-assisted) pre-analysis...")
                try:
                    tshark_res = run_tshark_analysis(file_path, ai_agent=self.ai_agent, limit=int(os.environ.get('FLAGSNIFF_TSHARK_LIMIT','5000')))
                    self.results['tshark_summary'] = tshark_res
                    # Convert HTTP summary lines into lightweight findings to seed later phases
                    for s in (tshark_res.get('summaries') or []):
                        summ = s.get('summary') or {}
                        for h in (summ.get('http') or []):
                            uri = h.get('uri') or ''
                            if not uri:
                                continue
                            f = Finding(
                                kind='http_uri', data=uri, protocol='HTTP', confidence=0.7,
                                via='tshark', display_type='HTTP', icon='🌐'
                            )
                            self.results.setdefault('findings', []).append(asdict(f))
                        for d in (summ.get('dns') or []):
                            q = d.get('query') or ''
                            if q:
                                f = Finding(
                                    kind='dns_query', data=q, protocol='DNS', confidence=0.65,
                                    via='tshark', display_type='DNS', icon='📡'
                                )
                                self.results.setdefault('findings', []).append(asdict(f))
                except Exception:
                    # Safe fallback if tshark errors
                    pass

            # Read packets
            if progress_callback:
                progress_callback("Reading PCAP file...")
            
            all_packets = rdpcap(file_path)
            self.results['total_packets'] = len(all_packets)

            # Apply display filter
            packets = apply_display_filter(all_packets, display_filter)
            self.results['filtered_packets'] = len(packets)

            # Analyze database traffic
            self.results['database_analysis'] = self.analyze_database_traffic(packets)

            # Analyze malware traffic
            self.results['malware_analysis'] = self.analyze_malware_traffic(packets)

            # Reconstruct TCP streams
            self.results['reconstructed_streams'] = reconstruct_tcp_streams(packets)
            
            # Generate protocol hierarchy
            self.results['protocol_hierarchy'] = get_protocol_hierarchy(packets)

            # Generate IO graph data
            self.results['io_graph_data'] = generate_io_graph_data(packets)

            # Analyze TLS certificates
            self.results['tls_certificates'] = analyze_tls_certificates(packets)

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
                
                # Add timestamp and additional info to findings
                normalized_findings = []
                for finding in packet_findings:
                    # Ensure finding is a dict
                    if isinstance(finding, str):
                        finding = {'data': finding, 'type': 'raw', 'confidence': 80}
                    elif not isinstance(finding, dict):
                        continue
                        
                    # Create a new dict to avoid modifying the original
                    normalized = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'packet_index': i,
                        'src_ip': packet_data.get('src', ''),
                        'dst_ip': packet_data.get('dst', ''),
                        'data': finding.get('data', str(finding)),
                        'type': finding.get('type', 'unknown'),
                        'protocol': packet_data.get('protocol', 'Unknown'),
                        'confidence': finding.get('confidence', 85)  # Default high confidence
                    }
                    normalized.update(finding)
                    
                    # Categorize finding type for display
                    if normalized.get('type') == 'flag':
                        normalized['display_type'] = 'FLAG'
                        normalized['icon'] = '🚩'
                        normalized['confidence'] = finding.get('confidence', 95)  # Flags get highest confidence
                    elif normalized.get('type') == 'credentials':
                        normalized['display_type'] = 'CREDENTIAL'
                        normalized['icon'] = '🔐'
                        normalized['confidence'] = finding.get('confidence', 90)
                    elif normalized.get('type') == 'tokens':
                        normalized['display_type'] = 'TOKEN'
                        normalized['icon'] = '🎫'
                        normalized['confidence'] = finding.get('confidence', 88)
                    elif normalized.get('type') == 'emails':
                        normalized['display_type'] = 'EMAIL'
                        normalized['icon'] = '📧'
                        normalized['confidence'] = finding.get('confidence', 85)
                    elif normalized.get('type') == 'hashes':
                        normalized['display_type'] = 'HASH'
                        normalized['icon'] = '🔒'
                        normalized['confidence'] = finding.get('confidence', 80)
                    else:
                        normalized['display_type'] = 'CUSTOM'
                        normalized['icon'] = '🔍'
                        normalized['confidence'] = finding.get('confidence', 75)
                    
                    normalized_findings.append(normalized)
            
            findings.extend(normalized_findings)
            
            self.results['analyzed_packets'] = analyzed_count
            self.results['findings'] = findings

            # Prepare packet data list for deeper CTF-oriented extraction/decoding
            packet_data_list = []
            for i, packet in enumerate(packets):
                pdata = self.parser.extract_data(packet)
                if pdata:
                    pdata['packet_index'] = i
                    packet_data_list.append(pdata)

            # Ensure results is not None before proceeding
            if self.results is None:
                self.results = {'findings': [], 'decoded_data': [], 'jwt_tokens': []}
            
            # Always run decoding and pattern extraction (useful for CTFs)
            decoded_items = self._decode_potential_data(packet_data_list)

            # Optional: Try TLS decryption using a provided NSS key log (SSLKEYLOGFILE format)
            if tls_keylog_file:
                try:
                    if progress_callback:
                        progress_callback("Attempting TLS decryption with provided key log...")
                    tls_decoded = decrypt_tls_with_keylog(file_path, tls_keylog_file)
                    if tls_decoded:
                        if not decoded_items:
                            decoded_items = []
                        decoded_items.extend(tls_decoded)
                        # Track that we attempted TLS decryption
                        self.results.setdefault('encryption_attempts', []).append({
                            'method': 'TLS keylog decrypt',
                            'status': 'success',
                            'details': f"Decrypted {len(tls_decoded)} payloads from TLS sessions"
                        })
                except Exception as _tls_err:
                    # Graceful fallback
                    self.results.setdefault('encryption_attempts', []).append({
                        'method': 'TLS keylog decrypt',
                        'status': 'failed',
                        'details': str(_tls_err)
                    })

            # DNS exfiltration reconstruction (optional)
            try:
                dns_decoded = detect_dns_exfiltration(packet_data_list)
                if dns_decoded:
                    if not decoded_items:
                        decoded_items = []
                    decoded_items.extend(dns_decoded)
            except Exception:
                pass

            if decoded_items:
                self.results['decoded_data'].extend(decoded_items)

            # AI-assisted local decode hunt (Ciphey-like) to enrich decoded_data
            try:
                if getattr(self, 'ai_agent', None) and hasattr(self.ai_agent, 'auto_decode_hunt'):
                    ai_decodes = self.ai_agent.auto_decode_hunt(self.results) or []
                    if ai_decodes:
                        # Deduplicate by (original, decoded)
                        seen_pairs = set((d.get('original',''), d.get('decoded','')) for d in self.results.get('decoded_data', []))
                        for d in ai_decodes:
                            key = (d.get('original',''), d.get('decoded',''))
                            if key not in seen_pairs and d.get('decoded'):
                                self.results.setdefault('decoded_data', []).append(d)
                                seen_pairs.add(key)
            except Exception:
                pass

            # Tracking pixel detection (pure Python): analyze HTML in HTTP and email streams
            try:
                tracking_findings: List[Dict[str, Any]] = []
                tracking_events: List[Dict[str, Any]] = []

                # 1) Collect HTML bodies from HTTP packets
                http_htmls: List[Tuple[str, Optional[int], Optional[str]]] = []  # (html, packet_index, stream_id)
                for p in packet_data_list:
                    try:
                        if (p.get('protocol') == 'HTTP') and p.get('http_body'):
                            body = str(p.get('http_body') or '')
                            if '<html' in body.lower() or '<img' in body.lower():
                                http_htmls.append((body, p.get('packet_index'), None))
                    except Exception:
                        continue

                # 2) Collect HTML parts from SMTP/IMAP/POP3 streams
                email_htmls: List[Tuple[str, Optional[int], Optional[str]]] = []
                for sid, s in (self.results.get('reconstructed_streams') or {}).items():
                    try:
                        sp = s.get('src_port'); dp = s.get('dst_port')
                        if is_mail_port(sp) or is_mail_port(dp):
                            data_bytes = s.get('data') or b''
                            if isinstance(data_bytes, (bytes, bytearray)) and len(data_bytes) > 0:
                                parts = extract_html_parts_from_stream(data_bytes)
                                for html in parts or []:
                                    email_htmls.append((html, (s.get('packet_indices') or [None])[0], str(sid)))
                    except Exception:
                        continue

                # 3) Build lightweight HTTP request index per stream for correlation
                def parse_host(req_text: str) -> Optional[str]:
                    try:
                        m = re.search(r"^Host:\s*([^\r\n]+)", req_text, re.IGNORECASE | re.MULTILINE)
                        return m.group(1).strip() if m else None
                    except Exception:
                        return None

                def parse_req_path(req_text: str) -> Optional[str]:
                    try:
                        m = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)", req_text)
                        return m.group(2) if m else None
                    except Exception:
                        return None

                def parse_resp_headers(resp_text: str) -> Dict[str, Any]:
                    info: Dict[str, Any] = {}
                    try:
                        cl_m = re.search(r"Content-Length:\s*(\d+)", resp_text, re.IGNORECASE)
                        if cl_m:
                            info['content_length'] = int(cl_m.group(1))
                    except Exception:
                        pass
                    try:
                        ct_m = re.search(r"Content-Type:\s*([^\r\n]+)", resp_text, re.IGNORECASE)
                        if ct_m:
                            info['content_type'] = ct_m.group(1).strip()
                    except Exception:
                        pass
                    return info

                http_index: Dict[str, Dict[str, Any]] = {}
                for sid, s in (self.results.get('reconstructed_streams') or {}).items():
                    req_msgs = s.get('http_requests', []) or []
                    resp_msgs = s.get('http_responses', []) or []
                    pairs = pair_http_by_index(req_msgs, resp_msgs)
                    # Expose reqs/resps too for correlation loop
                    http_index[str(sid)] = {
                        'reqs': [p.get('req') for p in pairs if p.get('req')],
                        'resps': [p.get('resp') for p in pairs if p.get('resp')],
                        'pairs': pairs
                    }

                # Helper to estimate small response size in a stream
                def estimate_smallest_cl(s: Dict[str, Any]) -> Optional[int]:
                    cl: Optional[int] = None
                    for resp in s.get('http_responses', []) or []:
                        try:
                            m = re.search(r"Content-Length:\s*(\d+)", resp, re.IGNORECASE)
                            if m:
                                v = int(m.group(1))
                                if cl is None or v < cl:
                                    cl = v
                        except Exception:
                            continue
                    return cl

                # 4) Run detector on collected HTML and correlate
                def process_html_list(items: List[Tuple[str, Optional[int], Optional[str]]], source: str):
                    for html, pkt_idx, sid in items:
                        try:
                            pxs = extract_pixels(html)
                            if not pxs:
                                continue
                            # reconstruct sequences per (host,path)
                            seqs = reconstruct_sequences(pxs)
                            # per-pixel correlation with HTTP request/response pairs in same stream (if any)
                            hidx = http_index.get(str(sid)) if sid is not None else None
                            reqs = (hidx.get('reqs') if isinstance(hidx, dict) else []) or []
                            pairs = (hidx.get('pairs') if isinstance(hidx, dict) else []) or []
                            # estimate tiny image response size in same stream
                            s_obj = (self.results.get('reconstructed_streams') or {}).get(sid) if sid is not None else None
                            smallest_cl = estimate_smallest_cl(s_obj) if isinstance(s_obj, dict) else None

                            for px in pxs:
                                host = (px.get('host') or '').lower()
                                path = px.get('path') or ''
                                match = None
                                matched_pair = None
                                for i, r in enumerate(reqs):
                                    if (r.get('host') or '').lower() == host and (r.get('path') or '').startswith(path):
                                        match = r
                                        matched_pair = pairs[i] if i < len(pairs) else None
                                        break

                                # Per-request response metrics
                                resp_cl = None
                                resp_ct = None
                                if matched_pair and matched_pair.get('resp'):
                                    resp_cl = matched_pair['resp'].get('content_length')
                                    resp_ct = matched_pair['resp'].get('content_type')

                                evt = {
                                    'src_url': px.get('src'),
                                    'host': host,
                                    'path': path,
                                    'query': px.get('query'),
                                    'hints': px.get('hints'),
                                    'tokens': px.get('tokens'),
                                    'source': source,
                                    'stream_id': sid,
                                    'packet_index': pkt_idx,
                                    'http_match': match,
                                    'response_smallest_content_length': smallest_cl,
                                    'response_content_length': resp_cl,
                                    'response_content_type': resp_ct
                                }
                                tracking_events.append(evt)

                                # Also surface as a finding
                                fobj = Finding(
                                    kind='tracking_pixel',
                                    data=px.get('src', ''),
                                    protocol='HTTP' if source == 'HTTP_HTML' else 'SMTP/IMAP',
                                    packet_index=pkt_idx,
                                    confidence=0.8 if (px.get('hints', {}).get('is_1x1') or px.get('hints', {}).get('css_hidden') or px.get('hints', {}).get('tracker_path')) else 0.6,
                                    display_type='TRACKING PIXEL',
                                    icon='📷',
                                )
                                finding = asdict(fobj)
                                finding['type'] = 'tracking_pixel'
                                finding['where_found'] = {
                                    'stream_id': sid,
                                    'source': source,
                                    'http_matched': bool(match),
                                    'content_length_hint': resp_cl if resp_cl is not None else smallest_cl,
                                    'content_type_hint': resp_ct
                                }
                                # attach any decoded token previews
                                try:
                                    decs = [t.get('decoded') for t in (px.get('tokens') or []) if t.get('decoded')]
                                    if decs:
                                        finding['decoded'] = '\n'.join([d for d in decs if d])[:500]
                                except Exception:
                                    pass
                                tracking_findings.append(finding)

                            # add reconstructed sequences as findings with boosted confidence
                            for seq in (seqs or []):
                                fobj = Finding(
                                    kind='tracking_sequence',
                                    data=seq.get('joined', ''),
                                    protocol='HTTP' if source == 'HTTP_HTML' else 'SMTP/IMAP',
                                    packet_index=pkt_idx,
                                    confidence=0.9,
                                    display_type='TRACKING SEQUENCE',
                                    icon='🧩',
                                )
                                fdict = asdict(fobj)
                                fdict['type'] = 'tracking_pixel_sequence'
                                fdict['where_found'] = {'stream_id': sid, 'source': source, 'group': seq.get('group')}
                                tracking_findings.append(fdict)
                            # relaxed reconstruction to handle alternating hosts/CDNs
                            relaxed_seqs = reconstruct_sequences_relaxed(pxs)
                            for seq in (relaxed_seqs or []):
                                fobj = Finding(
                                    kind='tracking_sequence',
                                    data=seq.get('joined', ''),
                                    protocol='HTTP' if source == 'HTTP_HTML' else 'SMTP/IMAP',
                                    packet_index=pkt_idx,
                                    confidence=0.88,
                                    display_type='TRACKING SEQUENCE',
                                    icon='🧩',
                                )
                                fdict = asdict(fobj)
                                fdict['type'] = 'tracking_pixel_sequence'
                                fdict['where_found'] = {'stream_id': sid, 'source': source, 'group': seq.get('group'), 'relaxed': True}
                                tracking_findings.append(fdict)
                        except Exception:
                            continue

                process_html_list(http_htmls, 'HTTP_HTML')
                process_html_list(email_htmls, 'EMAIL_HTML')

                if tracking_events:
                    self.results['tracking_pixels'] = tracking_events
                if tracking_findings:
                    # Merge with existing findings; dedupe by data+type
                    all_findings = (self.results.get('findings') or []) + tracking_findings
                    seen = set()
                    unique = []
                    for f in all_findings:
                        key = f"{f.get('data','')}|{f.get('type','')}"
                        if key not in seen:
                            seen.add(key)
                            unique.append(f)
                    self.results['findings'] = unique
            except Exception:
                # keep analysis robust if detector fails
                pass
                
            # Parse JWTs from raw and decoded content
            jwt_items = self._detect_and_parse_jwts(packet_data_list, decoded_items)
            if jwt_items:
                self.results['jwt_tokens'].extend(jwt_items)
                # Also surface as findings
                for j in jwt_items:
                    fobj = Finding(
                        kind='jwt',
                        data=json.dumps(j.get('claims', {})),
                        protocol=j.get('protocol', 'Unknown'),
                        packet_index=j.get('packet_index'),
                        display_type='JWT',
                        icon='🎫'
                    )
                    fdict = asdict(fobj)
                    fdict['src_ip'] = j.get('src_ip', '')
                    fdict['dst_ip'] = j.get('dst_ip', '')
                    fdict['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    self.results['findings'].append(fdict)
            
            extracted_patterns = self._extract_patterns_from_packets(packet_data_list)
            if extracted_patterns:
                self.results['extracted_patterns'].extend(extracted_patterns)
                # Also surface patterns as typed findings (non-intrusive 'pattern' kind)
                try:
                    for p in (extracted_patterns or []):
                        pdata = p.get('data') if isinstance(p, dict) else None
                        if not pdata:
                            # try alternative common keys
                            pdata = p.get('value') if isinstance(p, dict) else None
                        if not pdata:
                            continue
                        fobj = Finding(
                            kind='pattern',
                            data=str(pdata),
                            packet_index=p.get('packet_index', -1) if isinstance(p, dict) else None,
                            confidence=float(p.get('confidence', 0.6)) if isinstance(p, dict) else 0.6,
                            display_type=str(p.get('type', 'PATTERN')).upper() if isinstance(p, dict) else 'PATTERN',
                            icon='🔎'
                        )
                        fdict = asdict(fobj)
                        if isinstance(p, dict):
                            fdict['type'] = p.get('type', 'pattern')
                        findings.append(fdict)
                except Exception:
                    pass
            
            potential_flags, custom_flag_findings = self._identify_potential_flags(packet_data_list, custom_regex)
            
            # Create comprehensive findings list that includes ALL sources
            findings = []
            
            # 1. Add standard pattern-matched flags
            if 'potential_flags' in self.results:
                for flag in self.results['potential_flags']:
                    disp = 'FLAG' if 'flag{' in (flag.get('data') or '').lower() else 'POTENTIAL FLAG'
                    icon = '🏆' if disp == 'FLAG' else '🚩'
                    fobj = Finding(
                        kind='flag',
                        data=flag.get('data', ''),
                        packet_index=flag.get('packet_index', -1),
                        confidence=float(flag.get('confidence', 0.9)),
                        display_type=disp,
                        icon=icon
                    )
                    fdict = asdict(fobj)
                    fdict['context'] = flag.get('context', '')
                    fdict['type'] = flag.get('type', 'direct_match')
                    findings.append(fdict)
            
            # 2. Add AI agent findings (CRITICAL FIX)
            agent_results = {}
            if self.ai_agent:
                agent_results = self.ai_agent.analyze(packet_data_list)
            for task_id, result in agent_results.items():
                if 'result' in result and isinstance(result['result'], dict):
                    # Add AI-generated potential flags
                    if 'potential_flags' in result['result']:
                        for flag in result['result']['potential_flags']:
                            # Normalize to standard finding structure using typed model
                            fobj = Finding(
                                kind='flag',
                                data=flag.get('data', flag.get('flag', '')),
                                packet_index=flag.get('packet_index', -1),
                                confidence=float(flag.get('confidence', 0.85)),
                                display_type='AI FINDING',
                                icon='🤖'
                            )
                            fdict = asdict(fobj)
                            fdict['context'] = (flag.get('explanation', '') or '')[:200]
                            fdict['ai_explanation'] = flag.get('explanation', '')
                            fdict['source_agent'] = flag.get('source_agent', result.get('agent_id', 'ai'))
                            fdict['type'] = 'ai_find'
                            findings.append(fdict)
            
            # 3. Add crypto analysis findings (CRITICAL FIX)
            if 'decoded_data' in self.results:
                for decoded in self.results['decoded_data']:
                    # Only add as findings if it looks like a flag
                    if self._is_potential_flag(decoded.get('result', '')):
                        fobj = Finding(
                            kind='flag',
                            data=decoded.get('result', ''),
                            packet_index=decoded.get('packet_index', -1),
                            confidence=float(decoded.get('confidence', 0.95)),
                            display_type='DECRYPTED FLAG',
                            icon='🔓'
                        )
                        fdict = asdict(fobj)
                        fdict['decoding_chain'] = decoded.get('chain', [])
                        fdict['original_encoding'] = decoded.get('original_type', '')
                        fdict['type'] = 'crypto_flag'
                        findings.append(fdict)

            # 3b. Link decoded entries to related findings and add decoded-only findings
            try:
                dec_by_idx = {}
                for d in (self.results.get('decoded_data') or []):
                    idx = d.get('packet_index', -1)
                    if idx is None:
                        continue
                    dec_by_idx.setdefault(idx, []).append(d)
                # Sort decodes by confidence desc per packet
                for idx, arr in dec_by_idx.items():
                    arr.sort(key=lambda x: x.get('confidence', 0.5), reverse=True)

                # Attach best decoded text to any existing finding for same packet
                for f in findings:
                    idx = f.get('packet_index')
                    if idx in dec_by_idx and not f.get('decoded'):
                        best = dec_by_idx[idx][0]
                        f['decoded'] = best.get('decoded') or best.get('result', '')
                        f['decode_method'] = ' -> '.join(best.get('chain', [])) if best.get('chain') else None
                        if best.get('chain'):
                            f['decoding_chain'] = best.get('chain')
                        if 'confidence' in best:
                            f['decoded_confidence'] = best.get('confidence')
                # Add standalone decoded findings for packets without any finding
                existing_idx = {f.get('packet_index') for f in findings}
                for idx, arr in dec_by_idx.items():
                    if idx not in existing_idx:
                        # Avoid adding if clearly a flag (already added above)
                        for d in arr[:1]:
                            txt = d.get('decoded') or d.get('result', '')
                            if not txt:
                                continue
                            if self._is_potential_flag(txt):
                                continue
                            fobj = Finding(
                                kind='decoded',
                                data=txt,
                                packet_index=idx,
                                protocol=d.get('protocol', 'Unknown'),
                                confidence=int(50 + (d.get('confidence', 0.5) * 40)) / 100.0,
                                display_type='DECODED DATA',
                                icon='🧩'
                            )
                            fdict = asdict(fobj)
                            fdict['src_ip'] = d.get('src_ip', '')
                            fdict['dst_ip'] = d.get('dst_ip', '')
                            fdict['decoded'] = txt
                            fdict['decode_method'] = ' -> '.join(d.get('chain', [])) if d.get('chain') else None
                            fdict['decoding_chain'] = d.get('chain', [])
                            findings.append(fdict)
            except Exception:
                pass
            
            # 4. Add any custom flag findings from plugins
            if custom_flag_findings:
                findings.extend(custom_flag_findings)
            
            # Deduplicate findings based on content
            seen = set()
            unique_findings = []
            for finding in findings:
                finding_key = f"{finding.get('data', '')}|{finding.get('type', '')}"
                if finding_key not in seen and finding.get('data'):
                    seen.add(finding_key)
                    unique_findings.append(finding)
            
            # Final findings assignment
            self.results['findings'] = unique_findings
            
            # Attach stream context to findings
            for finding in unique_findings:
                # Find which stream this finding belongs to
                for stream_id, stream in self.results['reconstructed_streams'].items():
                    if finding.get('packet_index') in stream['packet_indices']:
                        finding['stream_id'] = str(stream_id)
                        finding['stream_data'] = stream['data'][:1000].decode('utf-8', errors='ignore') if stream['data'] else ''
                        break
            
            # Generate statistics
            # Attach AI confidence scores to findings and generate final statistics
            try:
                # Ensure results exists before AI analysis
                if self.results is None:
                    self.results = {'findings': [], 'statistics': {}}
                    
                enhanced_findings = self._enhance_findings_with_ai_analysis(unique_findings)
                if enhanced_findings:
                    unique_findings = enhanced_findings
            except Exception as e:
                if self.logger:
                    self.logger.error(f"AI analysis failed: {str(e)}")
                # Continue with original findings
            
            # Ensure results still exists after AI analysis
            if self.results is None:
                self.results = {'statistics': {}, 'findings': unique_findings}
                    
            self.results['statistics'] = self._generate_statistics(unique_findings)
            
            # Run CTF-specific analysis
            if progress_callback:
                progress_callback("Running CTF analysis...")
            
            # Extract HTTP packets for specialized analysis
            http_packets = [p for i, p in enumerate(packets) if self.parser.extract_data(p) and
                          self.parser.extract_data(p).get('protocol') == 'HTTP']
            
            # Always run basic CTF analysis, enhanced if CTF mode is enabled
            ctf_mode_enabled = search_options.get('ctf_mode', True)  # Default to True for compatibility
            
            # Create basic CTF analysis results from current findings
            ctf_analysis = {
                'flag_candidates': [],
                'metadata': {
                    'primary_protocol': self._get_primary_protocol(findings),
                    'total_findings': len(findings),
                    'analysis_mode': 'enhanced' if ctf_mode_enabled else 'basic'
                }
            }
            
            # Extract flag candidates from findings
            for finding in findings:
                if finding.get('display_type') == 'FLAG' or 'flag' in str(finding.get('data', '')).lower():
                    ctf_analysis['flag_candidates'].append({
                        'flag': finding.get('data', ''),
                        'confidence': finding.get('confidence', 80),
                        'pattern': finding.get('type', 'unknown'),
                        'protocol': finding.get('protocol', 'Unknown'),
                        'packet_number': finding.get('packet_index', 0) + 1,
                        'ai_analysis': f"Flag detected in {finding.get('protocol', 'unknown')} traffic with {finding.get('confidence', 80)}% confidence"
                    })
            
            # Add potential flag candidates from decoded data (boost confidence using chain + score)
            for decoded in (self.results.get('decoded_data', []) or []):
                decoded_text = decoded.get('decoded', '') or decoded.get('result', '')
                if self._is_potential_flag(decoded_text):
                    score = float(decoded.get('confidence', 0.6))
                    chain = decoded.get('chain', [])
                    # Confidence boost: model score + small bump per chain step
                    conf = int(min(99, max(80, 60 + score*30 + min(3, len(chain))*5)))
                    ctf_analysis['flag_candidates'].append({
                        'flag': decoded_text,
                        'confidence': conf,
                        'pattern': 'decoded_flag',
                        'protocol': decoded.get('protocol', 'Unknown'),
                        'packet_number': decoded.get('packet_index', 0) + 1,
                        'decoding_chain': chain,
                        'source': 'decoded_data',
                        'ai_analysis': f"Flag found in decoded {decoded.get('type', 'unknown')} data via chain: {' -> '.join(chain) if chain else 'n/a'}"
                    })
            
            # Store CTF analysis results
            self.results['ctf_analysis'] = ctf_analysis
            
            # Perform specialized CTF analysis if mode is enabled
            if ctf_mode_enabled:
                if progress_callback:
                    progress_callback("Setting up multi-agent analysis...")
                
                # Configure workflow orchestrator for network CTF challenges
                create_network_ctf_workflow(
                    self.workflow_orchestrator, 
                    self.parser, 
                    self.pattern_matcher, 
                    self.network_decoder, 
                    self.encoding_decoder, 
                    self.ctf_analyzer
                )
                
                # Start the workflow with initial context
                if progress_callback:
                    progress_callback("Starting multi-step analysis workflow...")
                
                workflow_result = self.workflow_orchestrator.start_workflow('network_ctf', {
                    'pcap_file': file_path,
                    'packet_data_list': packet_data_list
                })
                
                # Execute all possible steps in the workflow
                workflow_result = self.workflow_orchestrator.execute_all_steps()
                
                # Store workflow steps in results
                self.results['workflow_steps'] = self.workflow_orchestrator.get_workflow_status().get('steps_history', [])
                
                # Dispatch tasks to specialized agents
                if progress_callback:
                    progress_callback("Dispatching tasks to specialized agents...")
                
                # Network analysis agent
                self.multi_agent_coordinator.dispatch_task(
                    self.agents['network'].agent_id,
                    {
                        'type': 'analyze_network',
                        'packet_data': packet_data_list
                    }
                )
                
                # Extract potential encoded data for crypto agent
                encoded_data = []
                for packet in packet_data_list:
                    if 'data' in packet and packet['data']:
                        # Look for potential base64 encoded strings
                        import re
                        base64_patterns = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', packet['data'])
                        encoded_data.extend(base64_patterns)
            
                # Web analysis agent - extract HTTP content
                html_content = []
                javascript_content = []
                http_requests = []
                
                for packet in packet_data_list:
                    if packet.get('protocol') == 'HTTP':
                        if 'http_type' in packet:
                            if packet['http_type'] == 'request':
                                http_requests.append(packet)
                            elif packet['http_type'] == 'response' and 'http_body' in packet:
                                if 'content_type' in packet and 'html' in packet['content_type'].lower():
                                    html_content.append(packet['http_body'])
                                elif 'content_type' in packet and 'javascript' in packet['content_type'].lower():
                                    javascript_content.append(packet['http_body'])
                
                # Web analysis agent
                if html_content or javascript_content or http_requests:
                    self.multi_agent_coordinator.dispatch_task(
                        self.agents['web'].agent_id,
                        {
                            'type': 'analyze_web',
                            'html_content': '\n'.join(html_content) if html_content else None,
                            'javascript_content': '\n'.join(javascript_content) if javascript_content else None,
                            'http_requests': http_requests
                        }
                    )
                
                # Process agent tasks
                if progress_callback:
                    progress_callback("Processing agent tasks...")
                
                agent_results = self.multi_agent_coordinator.process_agent_tasks()
                
                # Process agent messages
                self.multi_agent_coordinator.process_messages()
                
                # Generate multi-agent report
                self.results['multi_agent_report'] = self.multi_agent_coordinator.generate_report()
                
                # Extract findings from agent results
                for task_id, result in agent_results.items():
                    agent_id = result['agent_id']
                    agent_result = result['result']
                    
                    # Extract potential flags
                    if 'potential_flags' in agent_result:
                        self.results['potential_flags'].extend(agent_result['potential_flags'])
                    
                    # Extract decoded data
                    if 'decoded_data' in agent_result:
                        self.results['decoded_data'].extend(agent_result['decoded_data'])
                    
                    # Extract HTTP findings
                    if 'http_findings' in agent_result:
                        self.results['ctf_findings'].extend(self._format_http_findings(agent_result['http_findings']))
                    
                    # Extract HTML analysis
                    if 'html_analysis' in agent_result and agent_result['html_analysis'].get('potential_flags'):
                        for flag in agent_result['html_analysis']['potential_flags']:
                            self.results['potential_flags'].append({
                                'data': flag,
                                'source': 'html_content',
                                'type': 'direct_match'
                            })
                
                # Store agent activities
                self.results['agent_activities'] = [
                    {
                        'agent_id': agent_id,
                        'name': agent.name,
                        'tasks_completed': sum(1 for task in agent.tasks if task['status'] == 'completed'),
                        'tasks_failed': sum(1 for task in agent.tasks if task['status'] == 'failed')
                    } for agent_id, agent in self.agents.items()
                ]
                
                # Generate hints based on findings
                if search_options.get('ctf_mode', False):
                    self.results['hints'] = self._generate_hints()
                else:
                    # Basic hints for non-CTF mode
                    self.results['hints'] = [
                        "🔍 Try looking for base64 encoded data in unusual places",
                        "🌐 Check DNS queries for hidden data or tunneling",
                        "⏰ Analyze packet timing patterns for steganography"
                    ]
            
            # Identify suspicious packets
            self.results['suspicious_packets'] = identify_suspicious_packets(packet_data_list)
            # Surface suspicious packets also as typed findings for unified UI
            try:
                pre_len = len(self.results.get('findings') or [])
                for sp in (self.results.get('suspicious_packets') or []):
                    # Use a neutral 'note' kind; preserve reasons in context
                    fobj = Finding(
                        kind='note',
                        data=sp.get('data_preview', ''),
                        protocol=sp.get('protocol', 'Unknown'),
                        packet_index=sp.get('packet_index'),
                        display_type='SUSPICIOUS',
                        icon='⚠️',
                        confidence=0.5
                    )
                    fdict = asdict(fobj)
                    fdict['src_ip'] = sp.get('src_ip', '')
                    fdict['dst_ip'] = sp.get('dst_ip', '')
                    fdict['context'] = '; '.join(sp.get('reasons', [])[:4])
                    fdict['type'] = 'suspicious'
                    self.results.setdefault('findings', []).append(fdict)
                # Attach stream context to newly added suspicious findings
                streams = self.results.get('reconstructed_streams') or {}
                for f in (self.results.get('findings') or [])[pre_len:]:
                    pkt_idx = f.get('packet_index')
                    if pkt_idx is None:
                        continue
                    for stream_id, stream in streams.items():
                        if pkt_idx in (stream.get('packet_indices') or []):
                            f['stream_id'] = str(stream_id)
                            try:
                                data_bytes = stream.get('data') or b''
                                f['stream_data'] = data_bytes[:1000].decode('utf-8', errors='ignore') if isinstance(data_bytes, (bytes, bytearray)) else ''
                            except Exception:
                                pass
                            break
            except Exception:
                pass
            
            # After findings are generated:
            self.results['flag_reassemblies'] = reassemble_flag_chunks(findings)
            # Attach reassembly context to findings
            for reassembly in self.results['flag_reassemblies']:
                for f in findings:
                    if f['packet_index'] in reassembly['packet_indices']:
                        f['flag_chunks'] = reassembly['flag_chunks']
                        f['reassembled_flag'] = reassembly['reassembled_flag']
            
            # Analysis time
            end_time = datetime.now()
            self.results['analysis_time'] = {
                'duration': str(end_time - start_time),
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            }
            
            if progress_callback:
                progress_callback("Analysis complete!")
            
            # Generate exploit suggestions
            self.results['exploit_suggestions'] = self._generate_exploit_suggestions(findings)
            
            # Extract files from TCP/UDP streams using file signatures
            self.results['extracted_files'] = self._carve_files_from_streams(self.results['reconstructed_streams'])
            # Analyze carved files for metadata and stego indicators
            if self.results['extracted_files']:
                self.results['extracted_files'] = self._analyze_carved_files(self.results['extracted_files'])

            # Heuristic AES-ECB detector over reconstructed streams
            try:
                def _detect_aes_ecb(data: bytes) -> Optional[Dict[str, Any]]:
                    if not isinstance(data, (bytes, bytearray)) or len(data) < 64:
                        return None
                    # Consider only full 16-byte blocks region
                    n = len(data) // 16
                    if n < 4:
                        return None
                    blocks = [bytes(data[i*16:(i+1)*16]) for i in range(n)]
                    total = len(blocks)
                    uniq = len(set(blocks))
                    repeats = total - uniq
                    # Confidence grows with repeats and size
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

                ecb_hits = []
                for sid, s in (self.results.get('reconstructed_streams') or {}).items():
                    try:
                        data_bytes = s.get('data') or b''
                        hit = _detect_aes_ecb(data_bytes)
                        if hit and hit['confidence'] >= 0.7:
                            entry = {
                                'stream_id': str(sid),
                                'src_ip': s.get('src_ip',''),
                                'dst_ip': s.get('dst_ip',''),
                                'evidence': hit
                            }
                            ecb_hits.append(entry)
                            # Surface as a finding
                            fobj = Finding(
                                kind='crypto',
                                data=f"Repeated 16-byte blocks in stream {sid} (repeats={hit['repeated_blocks']}/{hit['total_blocks']})",
                                protocol=s.get('protocol','Unknown'),
                                confidence=float(hit['confidence']),
                                display_type='AES-ECB SUSPECT',
                                icon='🧊'
                            )
                            fdict = asdict(fobj)
                            fdict['type'] = 'aes_ecb_suspect'
                            fdict['stream_id'] = str(sid)
                            self.results.setdefault('findings', []).append(fdict)
                    except Exception:
                        continue
                if ecb_hits:
                    self.results.setdefault('crypto_indicators', {}).setdefault('aes_ecb', []).extend(ecb_hits)
            except Exception:
                pass

            # Export correlation graph to JSON and GraphML (if available)
            try:
                graph = self.results.get('correlation_graph') or {}
                graph_exports = {}
                # JSON export
                try:
                    import tempfile as _tmp_g, os as _os_g, json as _json_g
                    gjson = _os_g.join(_tmp_g.gettempdir(), 'flagsniff_graph.json')
                    with open(gjson, 'w', encoding='utf-8') as f:
                        _json_g.dump(graph, f, indent=2)
                    graph_exports['json'] = gjson
                except Exception:
                    pass
                # GraphML export (optional, requires networkx)
                try:
                    import networkx as nx  # type: ignore
                    G = nx.DiGraph()
                    for n in (graph.get('nodes') or []):
                        G.add_node(n.get('id'), **{k:v for k,v in n.items() if k!='id'})
                    for e in (graph.get('edges') or []):
                        G.add_edge(e.get('from'), e.get('to'), **{k:v for k,v in e.items() if k not in ('from','to')})
                    gml = _os_g.join(_tmp_g.gettempdir(), 'flagsniff_graph.graphml')
                    nx.write_graphml(G, gml)
                    graph_exports['graphml'] = gml
                except Exception:
                    pass
                if graph_exports:
                    self.results['graph_exports'] = graph_exports
            except Exception:
                pass

            # Export reconstructed streams to ZIP for convenience
            try:
                import tempfile as _tmp_s, os as _os_s, zipfile as _zip_s
                streams = self.results.get('reconstructed_streams') or {}
                if streams:
                    tmpd = _tmp_s.mkdtemp(prefix='flagsniff_streams_')
                    count = 0
                    for sid, s in streams.items():
                        try:
                            data = s.get('data') or b''
                            if not isinstance(data, (bytes, bytearray)) or len(data) == 0:
                                continue
                            # Limit per-stream size to 1MB
                            b = bytes(data[:1024*1024])
                            fn = _os_s.path.join(tmpd, f"stream_{sid}.bin")
                            with open(fn, 'wb') as f:
                                f.write(b)
                            count += 1
                        except Exception:
                            continue
                    if count:
                        zpath = _os_s.path.join(_tmp_s.gettempdir(), 'flagsniff_streams.zip')
                        with _zip_s.ZipFile(zpath, 'w', _zip_s.ZIP_DEFLATED) as z:
                            for name in _os_s.listdir(tmpd):
                                try:
                                    full = _os_s.path.join(tmpd, name)
                                    z.write(full, arcname=name)
                                except Exception:
                                    continue
                        self.results.setdefault('exports', {})['streams_zip'] = zpath
            except Exception:
                pass
            
            # Build timeline first
            self.results['timeline'] = self._build_timeline(packets, findings)
            self.results['ai_hints'] = self._generate_ai_hints(findings, self.results['timeline'], challenge_description=None)

            # Build sessions, then session views
            self.results['sessions'] = self._build_sessions(packets)
            self.results['session_views'] = self._reconstruct_sessions(packets, self.results['sessions'])

            # Protocol details aggregation
            self.results['protocol_details'] = self._collect_protocol_details(findings, self.results['sessions'])

            # Correlation graph (after sessions are available)
            self.results['correlation_graph'] = self._build_correlation_graph(
                findings,
                self.results['reconstructed_streams'],
                self.results['sessions']
            )

            # VoIP audio extraction
            self.results['voip_audio'] = self._extract_voip_audio(self.results['sessions'])
            
            # Replay commands (merge AI-generated + rule-based fallback)
            ai_cmds = self._build_replay_ai_commands(self.results) if getattr(self, 'ai_agent', None) else []
            rb_cmds = self._build_replay_commands(self.results['sessions'])
            merged = []
            seen = set()
            for c in (ai_cmds or []) + (rb_cmds or []):
                s = (c.get('command') or c.get('cmd') or '').strip()
                if not s or s in seen:
                    continue
                seen.add(s)
                merged.append({'command': s, 'source': c.get('source','ai' if c in (ai_cmds or []) else 'rules')})
            self.results['replay_commands'] = merged

            # IOC extraction and export
            try:
                iocs = extract_iocs_from_results(self.results)
                self.results['iocs'] = iocs
                ioc_exports = export_iocs_to_files(iocs)
                self.results['ioc_exports'] = ioc_exports
                # Add safe hash cracking command suggestions
                try:
                    hash_cmds = []
                    for h in (iocs.get('hashes') or [])[:20]:
                        hs = str(h).lower()
                        mode = None
                        tool_hint = None
                        if len(hs) == 32 and re.fullmatch(r"[0-9a-f]{32}", hs):
                            mode = '0'  # MD5
                            tool_hint = 'MD5'
                        elif len(hs) == 40 and re.fullmatch(r"[0-9a-f]{40}", hs):
                            mode = '100'  # SHA1
                            tool_hint = 'SHA1'
                        elif len(hs) == 64 and re.fullmatch(r"[0-9a-f]{64}", hs):
                            mode = '1400'  # SHA256
                            tool_hint = 'SHA256'
                        if mode:
                            hashcat_cmd = f"hashcat -m {mode} <hashes.txt> <wordlist>"
                            john_cmd = "john --format=raw-{} <hashes.txt> --wordlist=<wordlist>".format(tool_hint.lower()) if tool_hint else None
                            if hashcat_cmd and hashcat_cmd not in (c.get('command') for c in self.results.get('replay_commands', [])):
                                self.results['replay_commands'].append({'command': hashcat_cmd, 'source': 'rules'})
                            if john_cmd and john_cmd not in (c.get('command') for c in self.results.get('replay_commands', [])):
                                self.results['replay_commands'].append({'command': john_cmd, 'source': 'rules'})
                except Exception:
                    pass
            except Exception:
                pass
            
            # YARA Scan
            if yara_rules:
                self.results['yara_matches'] = []
                for packet in packets:
                    if packet.haslayer(Raw):
                        matches = scan_with_yara(packet[Raw].load, yara_rules)
                        if matches:
                            self.results['yara_matches'].extend(matches)
                if 'extracted_files' in self.results:
                    for file_info in self.results['extracted_files']:
                        matches = scan_with_yara(file_info['data'], yara_rules)
                        if matches:
                            self.results['yara_matches'].extend(matches)

            # Auto-generate a lightweight HTML and Markdown report
            try:
                reporter = AutomatedReporting(logger=self.logger)
                challenge_context = {
                    'name': self.results.get('file_info', {}).get('name', os.path.basename(file_path)),
                    'type': 'forensics',
                    'difficulty': 'Medium',
                    'analyst': 'FlagSniff User',
                    'analysis_duration': self.results.get('analysis_time', {}).get('duration', '')
                }
                user_progress = {
                    'steps_completed': len(self.results.get('workflow_steps', [])),
                    'findings': len(self.results.get('findings', []))
                }
                report = reporter.generate_comprehensive_report(self.results, user_progress, challenge_context, include_writeup=False)
                html_export = reporter.export_report(report, 'html')
                md_export = reporter.export_report(report, 'markdown')
                pdf_export = reporter.export_report(report, 'pdf')
                self.results['report_exports'] = {
                    'html': {k: v for k, v in (html_export or {}).items() if k != 'content'},
                    'markdown': {k: v for k, v in (md_export or {}).items() if k != 'content'},
                    'pdf': {k: v for k, v in (pdf_export or {}).items() if k != 'content'}
                }
            except Exception:
                # Non-fatal if report generation fails
                pass

            return self.results
        
        except Exception as e:
            # Ensure results is not None even on error
            if self.results is None:
                self.results = {'error': str(e), 'findings': []}
            self.results['error'] = str(e)
            if self.logger:
                self.logger.error(f"Analysis failed: {str(e)}")
            raise
    
    def _generate_exploit_suggestions(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate high-level, safe suggestions based on findings.
        
        This implementation is intentionally conservative and avoids providing
        actual exploit details. It returns investigation suggestions that help
        guide analysis without revealing sensitive details.
        """
        suggestions = []
        
        try:
            # Track what we've seen to avoid duplicate suggestions
            seen_types = set()
            
            for f in (findings or []):
                f_type = f.get('display_type', '').upper()
                if f_type in seen_types:
                    continue
                seen_types.add(f_type)
                
                # JWT token guidance
                if 'JWT' in f_type or (f.get('data') and 'eyJ' in str(f.get('data'))):
                    suggestions.append({
                        'type': 'jwt_analysis',
                        'title': 'JWT Token Analysis',
                        'finding_type': f_type,
                        'risk_level': 'Medium',
                        'suggestion': 'Review JWT claims and headers. Consider checking signature verification and expiration.',
                        'packet_index': f.get('packet_index'),
                        'protocol': f.get('protocol', 'Unknown')
                    })
                
                # Suspicious HTTP patterns
                if f.get('protocol') == 'HTTP' and any(x in str(f.get('data', '')).upper() for x in ['UNION', 'SELECT', 'INSERT', 'DROP']):
                    suggestions.append({
                        'type': 'http_injection',
                        'title': 'HTTP Parameter Analysis',
                        'finding_type': f_type,
                        'risk_level': 'High',
                        'suggestion': 'Review HTTP parameters for potential SQL patterns. Consider input validation.',
                        'packet_index': f.get('packet_index'),
                        'protocol': 'HTTP'
                    })
                
                # Base64/encoded content
                if 'BASE64' in f_type or (f.get('data') and re.search(r'[A-Za-z0-9+/]{30,}={0,2}', str(f.get('data')))):
                    suggestions.append({
                        'type': 'encoded_content',
                        'title': 'Encoded Content Analysis',
                        'finding_type': f_type,
                        'risk_level': 'Low',
                        'suggestion': 'Review base64-encoded content. Consider multi-layer decoding.',
                        'packet_index': f.get('packet_index'),
                        'protocol': f.get('protocol', 'Unknown')
                    })
                
                # Flag format detection
                if 'FLAG' in f_type or self._is_potential_flag(str(f.get('data', ''))):
                    suggestions.append({
                        'type': 'flag_analysis',
                        'title': 'Potential Flag Analysis',
                        'finding_type': f_type,
                        'risk_level': 'Info',
                        'suggestion': 'Verify flag format and consider surrounding packet context.',
                        'packet_index': f.get('packet_index'),
                        'protocol': f.get('protocol', 'Unknown')
                    })
                
                # DNS anomalies
                if f.get('protocol') == 'DNS' and len(str(f.get('data', ''))) > 200:
                    suggestions.append({
                        'type': 'dns_analysis',
                        'title': 'DNS Query Analysis',
                        'finding_type': f_type,
                        'risk_level': 'Medium',
                        'suggestion': 'Review long DNS queries for potential DNS tunneling.',
                        'packet_index': f.get('packet_index'),
                        'protocol': 'DNS'
                    })
                
                # General binary/hex content
                if re.search(r'\\x[0-9a-fA-F]{2}', str(f.get('data', ''))):
                    suggestions.append({
                        'type': 'binary_analysis',
                        'title': 'Binary Content Review',
                        'finding_type': f_type,
                        'risk_level': 'Medium',
                        'suggestion': 'Examine hex-encoded content for potential shellcode or embedded files.',
                        'packet_index': f.get('packet_index'),
                        'protocol': f.get('protocol', 'Unknown')
                    })
            
            # Add protocol-specific suggestions based on what we've seen
            protocols = {f.get('protocol', '').upper() for f in findings if f.get('protocol')}
            
            if 'HTTP' in protocols:
                suggestions.append({
                    'type': 'http_review',
                    'title': 'HTTP Traffic Review',
                    'finding_type': 'PROTOCOL',
                    'risk_level': 'Info',
                    'suggestion': 'Review HTTP headers, cookies, and POST data for sensitive information.',
                    'protocol': 'HTTP'
                })
            
            if 'DNS' in protocols:
                suggestions.append({
                    'type': 'dns_review',
                    'title': 'DNS Query Review',
                    'finding_type': 'PROTOCOL',
                    'risk_level': 'Info',
                    'suggestion': 'Analyze DNS query patterns and subdomain structure.',
                    'protocol': 'DNS'
                })
            
            # Deduplicate by suggestion type
            seen = set()
            unique = []
            for s in suggestions:
                key = f"{s['type']}|{s.get('packet_index', '')}"
                if key not in seen:
                    seen.add(key)
                    unique.append(s)
            
            return unique
        
        except Exception:
            # On any error, return an empty list to keep pipeline running
            return []
    
    def _get_primary_protocol(self, findings):
        """Determine the primary protocol from findings"""
        if not findings:
            return 'Unknown'
        
        protocol_counts = {}
        for finding in findings:
            protocol = finding.get('protocol', 'Unknown')
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        # Return the most common protocol
        return max(protocol_counts.items(), key=lambda x: x[1])[0] if protocol_counts else 'Unknown'
    
    def _detect_packet_obfuscation(self, packet_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect common packet obfuscation techniques"""
        obfuscation_findings = []
        
        # 1. Check for fragmented packets that could hide data
        fragmented_packets = [
            p for p in packet_data_list 
            if p.get('flags') == 'MF' or (p.get('flags') == 'DF' and p.get('fragment_offset', 0) > 0)
        ]
        if fragmented_packets:
            primary_packet = fragmented_packets[0]
            evidence_packets = [p['packet_index'] for p in fragmented_packets]
            obfuscation_findings.append({
                'technique': 'Packet Fragmentation',
                'confidence': 0.85,
                'evidence': f"{len(fragmented_packets)} fragmented packets detected",
                'packet_indices': evidence_packets,
                'primary_packet_index': primary_packet['packet_index'],
                'evidence_snippet': f"Fragment offset: {primary_packet.get('fragment_offset', 'N/A')}"
            })
        
        # 2. Check for unusual IP ID values (sequential/random)
        ip_ids = [p['ip_id'] for p in packet_data_list if 'ip_id' in p]
        if ip_ids and len(set(ip_ids)) < len(ip_ids) * 0.3:  # High repetition
            obfuscation_findings.append({
                'technique': 'IP ID Spoofing',
                'confidence': 0.7,
                'evidence': f"Highly repetitive IP IDs ({len(ip_ids)-len(set(ip_ids))} duplicates)",
                'packet_indices': [p['packet_index'] for p in packet_data_list if 'ip_id' in p and ip_ids.count(p['ip_id']) > 1],
                'primary_packet_index': packet_data_list[0]['packet_index'],
                'evidence_snippet': f"Common IP IDs: {', '.join(str(x) for x in list(set(ip_ids))[:3])}"
            })
        
        # 3. Check for oversized DNS requests (tunneling)
        dns_packets = [p for p in packet_data_list if p.get('protocol') == 'DNS' and len(p.get('data', '')) > 250]
        if dns_packets:
            primary_packet = dns_packets[0]
            obfuscation_findings.append({
                'technique': 'DNS Tunneling',
                'confidence': 0.9,
                'evidence': f"{len(dns_packets)} oversized DNS packets detected (>250 bytes)",
                'packet_indices': [p['packet_index'] for p in dns_packets],
                'primary_packet_index': primary_packet['packet_index'],
                'evidence_snippet': f"DNS size: {len(primary_packet['data'])} bytes"
            })
        
        # 4. Check for HTTP request smuggling patterns
        http_packets = [p for p in packet_data_list if p.get('protocol') == 'HTTP']
        smuggling_patterns = []
        for packet in http_packets:
            headers = packet.get('http_headers', '')
            if 'Content-Length' in headers and 'Transfer-Encoding' in headers:
                smuggling_patterns.append(packet)
            if 'chunked' in headers and 'Content-Length' in headers:
                smuggling_patterns.append(packet)
                
        if smuggling_patterns:
            primary_packet = smuggling_patterns[0]
            obfuscation_findings.append({
                'technique': 'HTTP Request Smuggling',
                'confidence': 0.95,
                'evidence': f"{len(smuggling_patterns)} potential HTTP smuggling vectors detected",
                'packet_indices': [p['packet_index'] for p in smuggling_patterns],
                'primary_packet_index': primary_packet['packet_index'],
                'evidence_snippet': primary_packet.get('http_headers', '')[:100]
            })
        
        # 5. Check for unusual TCP flag combinations
        suspicious_tcp_flags = []
        for packet in packet_data_list:
            if packet.get('protocol') == 'TCP':
                flags = packet.get('tcp_flags', '')
                # SYN+FIN is unusual
                if 'S' in flags and 'F' in flags:
                    suspicious_tcp_flags.append(packet)
        
        if suspicious_tcp_flags:
            primary_packet = suspicious_tcp_flags[0]
            obfuscation_findings.append({
                'technique': 'Suspicious TCP Flags',
                'confidence': 0.75,
                'evidence': f"{len(suspicious_tcp_flags)} packets with unusual TCP flag combinations",
                'packet_indices': [p['packet_index'] for p in suspicious_tcp_flags],
                'primary_packet_index': primary_packet['packet_index'],
                'evidence_snippet': f"Flags: {primary_packet.get('tcp_flags', 'N/A')}"
            })
        
        # 6. Check for data encoded in packet timing
        # (Simplified version - would need actual timing analysis)
        if len(packet_data_list) > 10:
            time_deltas = []  # Would normally calculate packet time differentials
            timing_pattern = False
            if timing_pattern:  # Would have actual pattern recognition logic
                obfuscation_findings.append({
                    'technique': 'Timing-Based Covert Channel',
                    'confidence': 0.8,
                    'evidence': "Suspicious packet timing patterns detected",
                    'packet_indices': [p['packet_index'] for p in packet_data_list],
                    'primary_packet_index': packet_data_list[0]['packet_index'],
                    'evidence_snippet': "Irregular packet intervals detected"
                })
        
        # 7. Check for data hidden in padding
        padded_packets = [
            p for p in packet_data_list 
            if p.get('padding_size', 0) > 10 and len(p.get('data', '')) > p.get('padding_size', 0)
        ]
        if padded_packets:
            primary_packet = padded_packets[0]
            obfuscation_findings.append({
                'technique': 'Padding-Based Hiding',
                'confidence': 0.65,
                'evidence': f"{len(padded_packets)} packets with significant padding detected",
                'packet_indices': [p['packet_index'] for p in padded_packets],
                'primary_packet_index': primary_packet['packet_index'],
                'evidence_snippet': f"Padding size: {primary_packet.get('padding_size', 'N/A')} bytes"
            })
        
        # 8. Check for protocol tunneling (e.g., HTTP over DNS)
        protocol_mismatches = []
        for packet in packet_data_list:
            if packet.get('protocol') == 'DNS' and 'HTTP' in (packet.get('data', '')[:200]):
                protocol_mismatches.append(packet)
            if packet.get('protocol') == 'ICMP' and len(packet.get('data', '')) > 100:
                protocol_mismatches.append(packet)
                
        if protocol_mismatches:
            primary_packet = protocol_mismatches[0]
            obfuscation_findings.append({
                'technique': 'Protocol Tunneling',
                'confidence': 0.85,
                'evidence': f"{len(protocol_mismatches)} potential protocol tunneling instances",
                'packet_indices': [p['packet_index'] for p in protocol_mismatches],
                'primary_packet_index': primary_packet['packet_index'],
                'evidence_snippet': f"Mismatch: {primary_packet.get('protocol')} containing other protocol data"
            })
        
        return obfuscation_findings

    def _carve_files_from_streams(self, streams: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use centralized forensics helpers to carve files from streams."""
        if not streams:
            return []
        try:
            from analyzers.forensics import (
                carve_files_from_streams as _carve,
                extract_ftp_files as _ftp,
                enhanced_file_carving as _enhanced,
            )
            carved = _carve(streams, self.file_signatures)
            # Augment with FTP and enhanced carving strategies
            carved.extend(_ftp(streams))
            carved.extend(_enhanced(streams, self.file_signatures))
            return carved
        except Exception:
            # Fallback to empty on any error to keep pipeline robust
            return []

    def _build_timeline(self, packets: List[Any], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build a simple timeline combining packet timestamps and finding timestamps.

        Returns a list of events sorted by timestamp. Each event is a dict with
        keys: 'time', 'type', 'description', and optional 'packet_index'.
        This implementation is intentionally lightweight and defensive.
        """
        events: List[Dict[str, Any]] = []
        try:
            # Add packet-based events (limited to summary entries to avoid huge outputs)
            if packets:
                for i, pkt in enumerate(packets):
                    try:
                        ts = getattr(pkt, 'time', None)
                    except Exception:
                        ts = None
                    if ts is not None:
                        events.append({
                            'time': ts,
                            'type': 'packet',
                            'description': f'Packet {i}',
                            'packet_index': i
                        })

            # Add finding events if they include timestamps or packet indices
            for f in (findings or []):
                t = None
                if isinstance(f.get('timestamp'), str):
                    # try to parse ISO-like timestamp, fallback to None
                    try:
                        from datetime import datetime
                        t = datetime.fromisoformat(f['timestamp']).timestamp()
                    except Exception:
                        t = None
                elif isinstance(f.get('timestamp'), (int, float)):
                    t = float(f.get('timestamp'))

                if t is not None:
                    events.append({
                        'time': t,
                        'type': f.get('type', 'finding'),
                        'description': f.get('data', '')[:200] if f.get('data') else f.get('display_type', ''),
                        'packet_index': f.get('packet_index')
                    })

            # Sort events by time when available; stable sort keeps insertion order for None
            events = sorted(events, key=lambda e: (e.get('time') is None, e.get('time') if e.get('time') is not None else 0))
        except Exception:
            # On any unexpected error, return an empty timeline to keep analysis robust
            return []

        return events

    def _build_sessions(self, packets: List[Any]) -> Dict[str, Any]:
        """Delegate to analyzers.forensics.build_sessions for consistency."""
        try:
            from analyzers.forensics import build_sessions as _build
            return _build(packets)
        except Exception:
            return {}
    
    def _reconstruct_sessions(self, packets: List[Any], sessions: Dict[str, Any]) -> Dict[str, Any]:
        """Create a lightweight 'view' of sessions suitable for UI display.

        This function is defensive: it tolerates None/empty inputs and returns
        a dict mapping protocol types to session summaries. Each summary contains
        normalized messages suitable for UI display.
        """
        views: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        try:
            if not sessions:
                return views

            for sid, s in sessions.items():
                try:
                    if not isinstance(s, dict):
                        continue
                        
                    protocol = s.get('protocol', 'UNKNOWN')
                    messages = []
                    
                    # Extract messages based on session type
                    if protocol == 'HTTP':
                        for req in s.get('http_requests', []):
                            messages.append({
                                'timestamp': s.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                                'direction': 'REQUEST',
                                'content': req,
                                'type': 'request'
                            })
                        for resp in s.get('http_responses', []):
                            messages.append({
                                'timestamp': s.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                                'direction': 'RESPONSE',
                                'content': resp,
                                'type': 'response'
                            })
                    else:
                        # Generic session data
                        content = s.get('data', '')
                        if content:
                            messages.append({
                                'timestamp': s.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                                'direction': f"{s.get('src_ip', 'unknown')} -> {s.get('dst_ip', 'unknown')}",
                                'content': content,
                                'type': 'data'
                            })
                            
                    if messages:
                        if protocol not in views:
                            views[protocol] = {}
                        views[protocol][sid] = messages
                except Exception:
                    # Skip problematic session entries but continue processing others
                    continue
        except Exception:
            return {}

        return views

    def _enhance_findings_with_ai_analysis(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance findings with AI-driven confidence scores and insights.
        Returns the enhanced findings list with AI analysis results.
        """
        if not findings:
            return []

        enhanced_findings = []
        
        try:
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                    
                # Create a deep copy to avoid modifying original
                enhanced = dict(finding)
                

                # Initialize AI analysis fields if not present or not a dict
                if 'ai_analysis' not in enhanced or not isinstance(enhanced.get('ai_analysis'), dict):
                    enhanced['ai_analysis'] = {
                        'confidence': 0.0,
                        'explanation': '',
                        'suggestions': [],
                        'related_findings': [],
                        'risk_level': 'unknown'
                    }

                # Perform AI analysis if agent is available
                # Note: Individual finding analysis is currently not implemented
                # AI analysis happens at the batch level via analyze_findings method
                if self.ai_agent and hasattr(self.ai_agent, 'analyze_findings'):
                    try:
                        # For now, just mark that AI is available
                        # The actual batch analysis happens later
                        enhanced['ai_analysis']['ai_available'] = True
                    except Exception as e:
                        # Log error but continue processing
                        if self.logger:
                            self.logger.error(f"AI analysis error: {str(e)}")

                enhanced_findings.append(enhanced)
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error in AI analysis enhancement: {str(e)}")
            # Return original findings if enhancement fails
            return findings
            
        return enhanced_findings or findings

    def _generate_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate analysis statistics from findings.

        Returns a dict with counts and distributions of finding types,
        protocols, confidence levels etc. This implementation is defensive
        and returns safe defaults on error.
        """
        stats: Dict[str, Any] = {
            'total_findings': 0,
            'by_type': {},
            'by_protocol': {},
            'by_confidence': {
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'timestamp_range': {
                'first': None,
                'last': None
            }
        }

        try:
            stats['total_findings'] = len(findings)

            # Count by type
            for f in findings:
                # Display type counting
                disp_type = f.get('display_type', 'Unknown').upper()
                stats['by_type'][disp_type] = stats['by_type'].get(disp_type, 0) + 1

                # Protocol counting
                proto = (f.get('protocol') or 'Unknown').upper()
                stats['by_protocol'][proto] = stats['by_protocol'].get(proto, 0) + 1

                # Confidence bucketing
                conf = float(f.get('confidence', 0))
                if conf >= 0.8:
                    stats['by_confidence']['high'] += 1
                elif conf >= 0.5:
                    stats['by_confidence']['medium'] += 1
                else:
                    stats['by_confidence']['low'] += 1

                # Track timestamp range
                ts = f.get('timestamp')
                if isinstance(ts, str):
                    try:
                        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                        if not stats['timestamp_range']['first'] or dt < stats['timestamp_range']['first']:
                            stats['timestamp_range']['first'] = dt
                        if not stats['timestamp_range']['last'] or dt > stats['timestamp_range']['last']:
                            stats['timestamp_range']['last'] = dt
                    except Exception:
                        pass

            # Add ratio calculations if we have findings
            if stats['total_findings'] > 0:
                stats['ratios'] = {
                    'high_confidence': stats['by_confidence']['high'] / stats['total_findings'],
                    'flagged_suspicious': sum(1 for f in findings if 'SUSPIC' in (f.get('display_type') or '').upper()) / stats['total_findings']
                }

            # Convert datetime objects to isoformat strings for JSON serialization
            if stats['timestamp_range']['first']:
                stats['timestamp_range']['first'] = stats['timestamp_range']['first'].isoformat()
            if stats['timestamp_range']['last']:
                stats['timestamp_range']['last'] = stats['timestamp_range']['last'].isoformat()

        except Exception:
            # On any error, return minimal valid statistics
            stats = {
                'total_findings': len(findings),
                'by_type': {},
                'by_protocol': {},
                'by_confidence': {'high': 0, 'medium': 0, 'low': 0}
            }

        return stats

    def _generate_ai_hints(self, findings: List[Dict[str, Any]], timeline: List[Dict[str, Any]], challenge_description: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate safe, high-level AI-driven hints for the UI.

        This function is intentionally conservative: it doesn't provide exploit
        steps or sensitive instructions. It summarizes interesting signals
        and suggests safe investigation directions.
        """
        hints: List[Dict[str, Any]] = []
        try:
            if not findings:
                return hints

            # JWT hint
            if any('jwt' in (f.get('type') or '').lower() or (f.get('data') and 'eyJ' in str(f.get('data'))) for f in findings):
                hints.append({
                    'title': 'Inspect JWTs',
                    'hint': 'JWT-like tokens were detected. Review decoded claims for sensitive identifiers, expirations, and scope.',
                    'confidence': 0.9
                })

            # Flag/CTF hint
            if any('flag' in (f.get('type') or '').lower() or ('flag{' in (str(f.get('data') or '').lower())) for f in findings):
                hints.append({
                    'title': 'Potential Flags Found',
                    'hint': 'Content resembling CTF flags was detected. Verify reassembly across streams and decoding chains.',
                    'confidence': 0.95
                })

            # Suspicious packet hint
            if any((f.get('display_type') or '').upper().find('SUSPIC') != -1 for f in findings):
                hints.append({
                    'title': 'Review Suspicious Packets',
                    'hint': 'Packets flagged as suspicious may indicate tunneling or obfuscation. Consider timing and payload analyses.',
                    'confidence': 0.75
                })

            # Heuristic: many HTTP findings
            http_count = sum(1 for f in findings if (f.get('protocol') or '').upper() == 'HTTP' or (f.get('display_type') or '').upper().find('HTTP') != -1)
            if http_count > 5:
                hints.append({
                    'title': 'Web Surface Review',
                    'hint': 'Multiple HTTP-related findings detected. Check headers, cookies, and any exposed endpoints for sensitive data.',
                    'confidence': 0.8
                })

            # Generic fallback
            if not hints:
                hints.append({
                    'title': 'No High-Confidence AI Hints',
                    'hint': 'No clear patterns for AI hints. Consider running deeper decoders, multi-agent workflows, or manual review of unusual payloads.',
                    'confidence': 0.5
                })
        except Exception:
            return []

        return hints

    def _build_correlation_graph(self, findings: List[Dict[str, Any]], streams: Dict[str, Any], sessions: Dict[str, Any]) -> Dict[str, Any]:
        """Build a correlation graph connecting findings, streams, and sessions.
        
        Returns a dict with 'nodes' and 'edges' lists suitable for visualization.
        This implementation is defensive and lightweight to avoid analysis crashes.
        """
        graph = {
            'nodes': [],
            'edges': []
        }
        
        try:
            nodes = {}  # id -> node dict
            edges = set()  # (from_id, to_id, type) tuples
            
            # Helper to safely add nodes
            def add_node(id_: str, type_: str, label: str, data: Dict[str, Any] = None):
                if id_ not in nodes:
                    nodes[id_] = {
                        'id': id_,
                        'type': type_,
                        'label': label,
                        'data': data or {}
                    }
            
            # Helper to safely add edges
            def add_edge(from_id: str, to_id: str, type_: str):
                if from_id in nodes and to_id in nodes:
                    edges.add((from_id, to_id, type_))
            
            # Add findings as nodes
            for i, f in enumerate(findings or []):
                finding_id = f'finding_{i}'
                add_node(
                    finding_id,
                    'finding',
                    f"{f.get('display_type', 'Finding')}: {str(f.get('data', ''))[:30]}",
                    {
                        'type': f.get('type'),
                        'display_type': f.get('display_type'),
                        'protocol': f.get('protocol'),
                        'confidence': f.get('confidence', 0.5)
                    }
                )
                
                # Link to stream if available
                if f.get('stream_id'):
                    stream_id = f'stream_{f["stream_id"]}'
                    add_node(
                        stream_id,
                        'stream',
                        f"Stream {f['stream_id']}",
                        streams.get(f['stream_id'], {})
                    )
                    add_edge(finding_id, stream_id, 'found_in')
            
            # Add sessions and their relationships
            for session_id, session in (sessions or {}).items():
                if not isinstance(session, dict):
                    continue
                    
                session_node_id = f'session_{session_id}'
                add_node(
                    session_node_id,
                    'session',
                    f"Session {session_id}",
                    {
                        'protocol': session.get('protocol'),
                        'src': session.get('src'),
                        'dst': session.get('dst'),
                        'packet_count': session.get('packet_count', 0)
                    }
                )
                
                # Link related streams
                for stream_id, stream in (streams or {}).items():
                    if not isinstance(stream, dict):
                        continue
                    # Simple heuristic: link if IPs match
                    if (session.get('src') == stream.get('src_ip') and 
                        session.get('dst') == stream.get('dst_ip')):
                        stream_node_id = f'stream_{stream_id}'
                        add_node(
                            stream_node_id,
                            'stream',
                            f"Stream {stream_id}",
                            stream
                        )
                        add_edge(session_node_id, stream_node_id, 'contains')
            
            # Build final graph structure
            graph['nodes'] = list(nodes.values())
            graph['edges'] = [
                {
                    'from': src,
                    'to': dst,
                    'type': type_,
                    'id': f"edge_{i}"
                }
                for i, (src, dst, type_) in enumerate(edges)
            ]
            
        except Exception:
            # On any error return empty but valid graph
            graph = {'nodes': [], 'edges': []}
        
        return graph

    def _collect_protocol_details(self, findings: List[Dict[str, Any]], sessions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect individual protocol details for the UI display.

        Returns a list of protocol detail entries, each with keys: 'protocol', 'src_ip', 'dst_ip', 'summary', 'sni'.
        This function is defensive and returns empty list on unexpected input.
        """
        details: List[Dict[str, Any]] = []
        seen_entries = set()  # To avoid duplicates
        
        try:
            # Extract details from findings
            for f in (findings or []):
                proto = f.get('protocol', 'Unknown')
                src_ip = f.get('src_ip', f.get('src', ''))
                dst_ip = f.get('dst_ip', f.get('dst', ''))
                
                # Create entry key to avoid duplicates
                entry_key = f"{proto}|{src_ip}|{dst_ip}"
                if entry_key in seen_entries:
                    continue
                seen_entries.add(entry_key)
                
                # Extract additional details based on finding type
                summary = ""
                sni = ""
                
                if f.get('display_type') == 'JWT':
                    summary = "JWT token detected"
                elif f.get('display_type') == 'FLAG':
                    summary = "Potential flag found"
                elif f.get('display_type') == 'CREDENTIAL':
                    summary = "Credential detected"
                elif f.get('type') == 'http':
                    method = f.get('http_method', '')
                    path = f.get('http_path', '')
                    if method and path:
                        summary = f"{method} {path[:50]}"
                
                # Check for SNI in TLS/HTTPS connections
                if proto.upper() in ['HTTPS', 'TLS']:
                    # Try to extract SNI from data
                    data = str(f.get('data', ''))
                    if '.' in data and len(data.split('.')) > 1:
                        # Simple heuristic for domain-like strings
                        potential_sni = data.split()[0] if ' ' in data else data
                        if len(potential_sni) < 100 and '.' in potential_sni:
                            sni = potential_sni[:50]
                
                details.append({
                    'protocol': proto,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'summary': summary,
                    'sni': sni if sni else None
                })

            # Extract details from sessions if available
            if isinstance(sessions, dict):
                for session_id, session in sessions.items():
                    try:
                        if not isinstance(session, dict):
                            continue
                            
                        proto = session.get('protocol', 'Unknown')
                        src_ip = session.get('src', '')
                        dst_ip = session.get('dst', '')
                        
                        # Create entry key to avoid duplicates
                        entry_key = f"{proto}|{src_ip}|{dst_ip}"
                        if entry_key in seen_entries:
                            continue
                        seen_entries.add(entry_key)
                        
                        # Generate summary based on session data
                        summary = ""
                        packet_count = session.get('packet_count', 0)
                        if packet_count > 0:
                            summary = f"{packet_count} packets"
                        
                        # Check for HTTP requests/responses in session
                        if session.get('http_requests') or session.get('http_responses'):
                            req_count = len(session.get('http_requests', []))
                            resp_count = len(session.get('http_responses', []))
                            if req_count > 0 or resp_count > 0:
                                summary = f"{req_count} requests, {resp_count} responses"
                        
                        details.append({
                            'protocol': proto,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'summary': summary,
                            'sni': None
                        })
                        
                    except Exception:
                        continue

            # If no details found, add a placeholder entry
            if not details:
                details.append({
                    'protocol': 'No Data',
                    'src_ip': '',
                    'dst_ip': '',
                    'summary': 'No protocol details available',
                    'sni': None
                })
            
            return details[:100]  # Limit to 100 entries to avoid UI performance issues
            
        except Exception:
            # On any error, return a safe default
            return [{
                'protocol': 'Error',
                'src_ip': '',
                'dst_ip': '',
                'summary': 'Error collecting protocol details',
                'sni': None
            }]

    def _detect_and_parse_jwts(self, packet_data_list: List[Dict[str, Any]], decoded_items: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Detect JWT-like tokens in packet data and decoded artifacts and parse their claims.

        Returns a list of dicts with keys: token, header, claims, protocol, src_ip, packet_index
        """
        import re, base64, json

        jwt_regex = re.compile(r'([A-Za-z0-9-_]+)\.([A-Za-z0-9-_]+)\.([A-Za-z0-9-_]+)')
        results = []
        decoded_items = decoded_items or []

        # Combine raw packet data and decoded artifacts for searching
        candidates = []
        for p in (packet_data_list or []):
            # prefer consolidated string fields
            candidates.append({
                'text': p.get('data') or p.get('http_body') or p.get('raw', '') or '',
                'protocol': p.get('protocol', ''),
                'src_ip': p.get('src', ''),
                'packet_index': p.get('packet_index')
            })
        for d in decoded_items:
            candidates.append({
                'text': d.get('decoded') or d.get('result') or d.get('data') or '',
                'protocol': d.get('protocol', ''),
                'src_ip': d.get('src_ip', d.get('src', '')),
                'packet_index': d.get('packet_index')
            })

        def _b64url_decode(s: str) -> bytes:
            s = s.encode('utf-8') if isinstance(s, str) else s
            # pad
            rem = len(s) % 4
            if rem:
                s += b'=' * (4 - rem)
            try:
                return base64.urlsafe_b64decode(s)
            except Exception:
                return b''

        for cand in candidates:
            text = cand.get('text') or ''
            if not text:
                continue
            for m in jwt_regex.finditer(text):
                token = m.group(0)
                parts = token.split('.')
                header = None
                claims = None
                try:
                    header_bytes = _b64url_decode(parts[0])
                    payload_bytes = _b64url_decode(parts[1])
                    try:
                        header = json.loads(header_bytes.decode('utf-8', errors='ignore'))
                    except Exception:
                        header = None
                    try:
                        claims = json.loads(payload_bytes.decode('utf-8', errors='ignore'))
                    except Exception:
                        claims = None
                except Exception:
                    header = None
                    claims = None

                results.append({
                    'token': token,
                    'header': header,
                    'claims': claims,
                    'protocol': cand.get('protocol'),
                    'src_ip': cand.get('src_ip'),
                    'packet_index': cand.get('packet_index')
                })

        return results

    def _identify_potential_flags(self, packet_data_list: List[Dict[str, Any]], custom_regex: Optional[str] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Identify potential flags in packet data, supporting custom regex. Returns (potential_flags, custom_flag_findings)"""
        potential_flags = []
        custom_flag_findings = []
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'htb\{[^}]+\}',
            r'DUCTF\{[^}]+\}',
            r'PICOCTF\{[^}]+\}',
            r'flag:[\s]*[a-zA-Z0-9_\-!@#$%^&*()]+'
        ]
        if custom_regex:
            flag_patterns.insert(0, custom_regex)
        for packet in packet_data_list:
            data = packet.get('data', '')
            if not data:
                continue
            for pattern in flag_patterns:
                matches = re.finditer(pattern, data, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    match_data = match.group(0)
                    potential_flags.append({
                        'type': 'direct_match',
                        'display_type': 'POTENTIAL FLAG',
                        'icon': '🚩',
                        'data': match_data,
                        'packet_index': packet.get('packet_index'),
                        'src_ip': packet.get('src', ''),
                        'protocol': packet.get('protocol', 'Unknown'),
                        'confidence': 'high'
                    })
                    if custom_regex and re.fullmatch(custom_regex, match_data):
                        custom_flag_findings.append({
                            'type': 'custom_flag',
                            'display_type': 'CUSTOM FLAG',
                            'icon': '🚩',
                            'data': match_data,
                            'packet_index': packet.get('packet_index'),
                            'src_ip': packet.get('src', ''),
                            'protocol': packet.get('protocol', 'Unknown'),
                            'confidence': 'high',
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })
            candidates = set()
            candidates.update(re.findall(r'\b[A-Za-z0-9+/=]{12,}\b', data))
            candidates.update(re.findall(r'\b[0-9A-Fa-f]{16,}\b', data))
            candidates.update(re.findall(r'\b[A-Z2-7]{8,}=*\b', data))
            for word in candidates:
                decoded_variants: List[Tuple[str, str]] = []
                for enc in ['base64', 'base32', 'hex', 'rot13', 'url']:
                    decoder = self.encoding_decoder.decoders.get(enc)
                    if not decoder:
                        continue
                    try:
                        dec = decoder(word)
                        if dec and dec != word:
                            decoded_variants.append((enc, dec))
                    except Exception:
                        pass
                for res in self.encoding_decoder.decode_chain(word):
                    decoded_variants.append(('->'.join(res.get('chain', [])), res.get('decoded', '')))
                for method, dec_txt in decoded_variants:
                    for pattern in flag_patterns:
                        match_obj = re.search(pattern, dec_txt, re.IGNORECASE)
                        if match_obj:
                            match_data = match_obj.group(0)
                            frame_no = (packet.get('packet_index') or 0) + 1
                            extraction_steps = []
                            for part in method.split('->') if method else []:
                                if part == 'base64':
                                    extraction_steps.append({'method': 'base64', 'command': f"echo '<prev>' | base64 -d"})
                                elif part == 'base32':
                                    extraction_steps.append({'method': 'base32', 'command': f"echo '<prev>' | base32 -d"})
                                elif part == 'hex':
                                    extraction_steps.append({'method': 'hex', 'command': f"echo -n '<prev>' | xxd -r -p"})
                                elif part == 'rot13':
                                    extraction_steps.append({'method': 'rot13', 'command': "python -c \"import codecs;print(codecs.decode('<prev>','rot_13'))\""})
                                elif part == 'url':
                                    extraction_steps.append({'method': 'url', 'command': "python -c \"from urllib.parse import unquote;print(unquote('<prev>'))\""})
                                elif part == 'zlib':
                                    extraction_steps.append({'method': 'zlib', 'command': "python -c \"import zlib,sys;print(zlib.decompress(sys.stdin.buffer.read()).decode())\" < decoded.bin"})
                            potential_flags.append({
                                'type': 'encoded_flag',
                                'display_type': 'ENCODED FLAG',
                                'icon': '🔑',
                                'original': word,
                                'decoded': dec_txt,
                                'encoding': method,
                                'poc': {
                                    'where_found': {
                                        'packet_index': packet.get('packet_index'),
                                        'frame_number': frame_no,
                                        'protocol': packet.get('protocol', 'Unknown'),
                                        'src_ip': packet.get('src', ''),
                                        'dst_ip': packet.get('dst', '')
                                    },
                                    'extraction_steps': extraction_steps if extraction_steps else [{'method': method, 'command': ''}]
                                },
                                'packet_index': packet.get('packet_index'),
                                'src_ip': packet.get('src', ''),
                                'protocol': packet.get('protocol', 'Unknown'),
                                'confidence': 'medium'
                            })
                            if custom_regex and re.fullmatch(custom_regex, match_data):
                                custom_flag_findings.append({
                                    'type': 'custom_flag',
                                    'display_type': 'CUSTOM FLAG',
                                    'icon': '🚩',
                                    'data': match_data,
                                    'packet_index': packet.get('packet_index'),
                                    'src_ip': packet.get('src', ''),
                                    'protocol': packet.get('protocol', 'Unknown'),
                                    'confidence': 'medium',
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                })
        return potential_flags, custom_flag_findings

    def _is_potential_flag(self, text: str) -> bool:
        """Check if a string looks like a CTF flag format.
        
        This is a defensive implementation that checks for common flag formats
        without being too aggressive. Returns True if the text matches flag-like
        patterns, False otherwise or on error.
        """
        if not isinstance(text, str):
            return False
        
        try:
            # Common CTF flag formats
            flag_patterns = [
                r'flag\{[^}]+\}',
                r'CTF\{[^}]+\}',
                r'HTB\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'DUCTF\{[^}]+\}',
                r'PICOCTF\{[^}]+\}',
                # Simple flags with alphanumeric content
                r'flag:[\s]*[a-zA-Z0-9_\-!@#$%^&*()]+',
                r'key:[\s]*[a-zA-Z0-9_\-!@#$%^&*()]+',
                # Additional cases
                r'\{[0-9a-fA-F]{32}\}',  # MD5-like
                r'\{[0-9a-fA-F]{40}\}',  # SHA1-like
                r'\{[0-9a-fA-F]{64}\}'   # SHA256-like
            ]
            
            # Check each pattern
            for pattern in flag_patterns:
                if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                    return True
            
            # Additional heuristics for possible flags
            if len(text) >= 8 and '{' in text and '}' in text:
                inner = text[text.find('{')+1:text.find('}')]
                if len(inner) >= 4:
                    # Look for hex/base64/ascii printable content
                    if all(c in '0123456789abcdefABCDEF' for c in inner):
                        return True
                    if all(c in string.printable for c in inner):
                        return True
            
            return False
        except Exception:
            return False

    def _generate_exploit_suggestions(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate high-level, safe suggestions based on findings.
        
        This implementation is intentionally conservative and avoids providing
        actual exploit details. It returns investigation suggestions that help
        guide analysis without revealing sensitive details.
        """
        suggestions = []
        
        try:
            # Track what we've seen to avoid duplicate suggestions
            seen_types = set()
            
            for f in (findings or []):
                f_type = f.get('display_type', '').upper()
                if f_type in seen_types:
                    continue
                seen_types.add(f_type)
                
                # JWT token guidance
                if 'JWT' in f_type or (f.get('data') and 'eyJ' in str(f.get('data'))):
                    suggestions.append({
                        'type': 'jwt_analysis',
                        'title': 'JWT Token Analysis',
                        'finding_type': f_type,
                        'risk_level': 'Medium',
                        'suggestion': 'Review JWT claims and headers. Consider checking signature verification and expiration.',
                        'packet_index': f.get('packet_index'),
                        'protocol': f.get('protocol', 'Unknown')
                    })
                
                # Suspicious HTTP patterns
                if f.get('protocol') == 'HTTP' and any(x in str(f.get('data', '')).upper() for x in ['UNION', 'SELECT', 'INSERT', 'DROP']):
                    suggestions.append({
                        'type': 'http_injection',
                        'title': 'HTTP Parameter Analysis',
                        'finding_type': f_type,
                        'risk_level': 'High',
                        'suggestion': 'Review HTTP parameters for potential SQL patterns. Consider input validation.',
                        'packet_index': f.get('packet_index'),
                        'protocol': 'HTTP'
                    })
                
                # Base64/encoded content
                if 'BASE64' in f_type or (f.get('data') and re.search(r'[A-Za-z0-9+/]{30,}={0,2}', str(f.get('data')))):
                    suggestions.append({
                        'type': 'encoded_content',
                        'title': 'Encoded Content Analysis',
                        'finding_type': f_type,
                        'risk_level': 'Low',
                        'suggestion': 'Review base64-encoded content. Consider multi-layer decoding.',
                        'packet_index': f.get('packet_index'),
                        'protocol': f.get('protocol', 'Unknown')
                    })
                
                # Flag format detection
                if 'FLAG' in f_type or self._is_potential_flag(str(f.get('data', ''))):
                    suggestions.append({
                        'type': 'flag_analysis',
                        'title': 'Potential Flag Analysis',
                        'finding_type': f_type,
                        'risk_level': 'Info',
                        'suggestion': 'Verify flag format and consider surrounding packet context.',
                        'packet_index': f.get('packet_index'),
                        'protocol': f.get('protocol', 'Unknown')
                    })
                
                # DNS anomalies
                if f.get('protocol') == 'DNS' and len(str(f.get('data', ''))) > 200:
                    suggestions.append({
                        'type': 'dns_analysis',
                        'title': 'DNS Query Analysis',
                        'finding_type': f_type,
                        'risk_level': 'Medium',
                        'suggestion': 'Review long DNS queries for potential DNS tunneling.',
                        'packet_index': f.get('packet_index'),
                        'protocol': 'DNS'
                    })
                
                # General binary/hex content
                if re.search(r'\\x[0-9a-fA-F]{2}', str(f.get('data', ''))):
                    suggestions.append({
                        'type': 'binary_analysis',
                        'title': 'Binary Content Review',
                        'finding_type': f_type,
                        'risk_level': 'Medium',
                        'suggestion': 'Examine hex-encoded content for potential shellcode or embedded files.',
                        'packet_index': f.get('packet_index'),
                        'protocol': f.get('protocol', 'Unknown')
                    })
            
            # Add protocol-specific suggestions based on what we've seen
            protocols = {f.get('protocol', '').upper() for f in findings if f.get('protocol')}
            
            if 'HTTP' in protocols:
                suggestions.append({
                    'type': 'http_review',
                    'title': 'HTTP Traffic Review',
                    'finding_type': 'PROTOCOL',
                    'risk_level': 'Info',
                    'suggestion': 'Review HTTP headers, cookies, and POST data for sensitive information.',
                    'protocol': 'HTTP'
                })
            
            if 'DNS' in protocols:
                suggestions.append({
                    'type': 'dns_review',
                    'title': 'DNS Query Review',
                    'finding_type': 'PROTOCOL',
                    'risk_level': 'Info',
                    'suggestion': 'Analyze DNS query patterns and subdomain structure.',
                    'protocol': 'DNS'
                })
            
            # Deduplicate by suggestion type
            seen = set()
            unique = []
            for s in suggestions:
                key = f"{s['type']}|{s.get('packet_index', '')}"
                if key not in seen:
                    seen.add(key)
                    unique.append(s)
            
            return unique
        
        except Exception:
            # On any error, return an empty list to keep pipeline running
            return []

    def _detect_and_parse_jwts(self, packet_data_list: List[Dict[str, Any]], decoded_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect JWT tokens in raw and decoded content and pretty-print claims."""
        import re
        import base64 as _b64
        from typing import Optional as _Optional

        def _b64url_to_json(segment: str) -> _Optional[dict]:
            try:
                seg = segment + '=' * (-len(segment) % 4)
                data = _b64.urlsafe_b64decode(seg)
                import json as _json
                return _json.loads(data.decode('utf-8', errors='ignore'))
            except Exception:
                return None

        jwt_re = re.compile(r"eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}")
        tokens: List[Dict[str, Any]] = []

        # scan raw packet data
        for p in packet_data_list:
            text = p.get('data', '') or ''
            for m in jwt_re.finditer(text):
                tok = m.group(0)
                parts = tok.split('.')
                if len(parts) != 3:
                    continue
                hdr = _b64url_to_json(parts[0])
                pld = _b64url_to_json(parts[1])
                if hdr and pld:
                    tokens.append({
                        'token': tok,
                        'header': hdr,
                        'claims': pld,
                        'packet_index': p.get('packet_index'),
                        'protocol': p.get('protocol', 'Unknown'),
                        'src_ip': p.get('src', ''),
                        'dst_ip': p.get('dst', '')
                    })

        # scan decoded items
        for d in decoded_items or []:
            text = d.get('decoded', '') or d.get('data', '') or ''
            for m in jwt_re.finditer(text):
                tok = m.group(0)
                parts = tok.split('.')
                if len(parts) != 3:
                    continue
                hdr = _b64url_to_json(parts[0])
                pld = _b64url_to_json(parts[1])
                if hdr and pld:
                    tokens.append({
                        'token': tok,
                        'header': hdr,
                        'claims': pld,
                        'packet_index': d.get('packet_index'),
                        'protocol': d.get('protocol', 'Unknown'),
                        'src_ip': d.get('src_ip', d.get('src', '')),
                        'dst_ip': d.get('dst_ip', d.get('dst', ''))
                    })

        # dedupe by token string
        seen = set()
        deduped = []
        for t in tokens:
            if t['token'] in seen:
                continue
            seen.add(t['token'])
            deduped.append(t)
        return deduped

    def _build_replay_commands(self, sessions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate safe replay commands for traffic reconstruction.
        
        Returns a list of dicts with metadata and commands for replaying traffic.
        This implementation is defensive and focuses on common protocols (HTTP, DNS)
        without including potentially dangerous payloads.
        """
        commands = []
        
        try:
            for session_id, session in (sessions or {}).items():
                if not isinstance(session, dict):
                    continue
                
                proto = (session.get('protocol') or '').upper()
                src = session.get('src', '')
                dst = session.get('dst', '')
                src_port = session.get('src_port')
                dst_port = session.get('dst_port')
                
                if not all([proto, src, dst]):
                    continue
                
                # HTTP requests
                if proto == 'HTTP' and isinstance(session.get('http_requests'), list):
                    for req in session['http_requests']:
                        if not isinstance(req, (str, bytes)):
                            continue
                            
                        try:
                            # Parse first line for method, path
                            if isinstance(req, bytes):
                                req = req.decode('utf-8', errors='ignore')
                            first_line = req.split('\n')[0].strip()
                            method, path, _ = first_line.split(' ', 2)
                            
                            if method in ['GET', 'HEAD']:  # Safe methods only
                                commands.append({
                                    'type': 'http_request',
                                    'session_id': session_id,
                                    'description': f'HTTP {method} request to {dst}:{dst_port}',
                                    'command': f'curl -X {method} -v "http://{dst}:{dst_port}{path}"',
                                    'protocol': 'HTTP',
                                    'src': src,
                                    'dst': dst,
                                    'risk_level': 'low'
                                })
                        except Exception:
                            continue
                
                # DNS queries
                if proto == 'DNS':
                    base_cmd = "nslookup"  # Default to simple nslookup
                    if session.get('dns_queries'):
                        for query in session['dns_queries']:
                            if isinstance(query, str) and len(query) < 255:  # Basic safety check
                                commands.append({
                                    'type': 'dns_query',
                                    'session_id': session_id,
                                    'description': f'DNS query for {query}',
                                    'command': f'{base_cmd} {query} {dst}',
                                    'protocol': 'DNS',
                                    'src': src,
                                    'dst': dst,
                                    'risk_level': 'low'
                                })
                
                # TCP connections (netcat-style, without payloads)
                if proto == 'TCP' and src_port and dst_port:
                    commands.append({
                        'type': 'tcp_connect',
                        'session_id': session_id,
                        'description': f'TCP connection to {dst}:{dst_port}',
                        'command': f'nc -v -w 5 {dst} {dst_port}',
                        'protocol': 'TCP',
                        'src': src,
                        'dst': dst,
                        'risk_level': 'medium'
                    })
                
                # ICMP ping (if ICMP traffic seen)
                if proto == 'ICMP':
                    commands.append({
                        'type': 'icmp_ping',
                        'session_id': session_id,
                        'description': f'ICMP ping to {dst}',
                        'command': f'ping -c 4 {dst}',
                        'protocol': 'ICMP',
                        'src': src,
                        'dst': dst,
                        'risk_level': 'low'
                    })
            
            # Add general tcpreplay/tshark commands if we have any sessions
            if sessions:
                commands.append({
                    'type': 'pcap_replay',
                    'description': 'Replay entire capture (requires tcpreplay)',
                    'command': 'tcpreplay -i <interface> capture.pcap',
                    'protocol': 'ALL',
                    'risk_level': 'high'
                })
                
                commands.append({
                    'type': 'pcap_analysis',
                    'description': 'Detailed protocol analysis (requires tshark)',
                    'command': 'tshark -r capture.pcap -q -z io,phs',
                    'protocol': 'ALL',
                    'risk_level': 'low'
                })
        
        except Exception:
            # On any error, return empty list to keep analysis robust
            return []
        
        return commands

    def _build_replay_ai_commands(self, results_ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Ask the AI agent for replay commands and filters only (no descriptions).

        Returns a list of {'command': str, 'source': 'ai'} entries.
        """
        try:
            agent = getattr(self, 'ai_agent', None)
            if not agent or not hasattr(agent, '_call_openrouter'):
                return []

            # Summarize context to keep prompt bounded
            findings = (results_ctx.get('findings') or [])[:12]
            sessions = list((results_ctx.get('sessions') or {}).items())[:8]
            summary = {
                'findings_preview': [
                    {
                        'type': f.get('display_type', f.get('type','')),
                        'protocol': f.get('protocol',''),
                        'sample': str(f.get('data',''))[:140]
                    } for f in findings
                ],
                'sessions_preview': [
                    {
                        'id': sid,
                        'proto': s.get('protocol',''),
                        'src': s.get('src', s.get('src_ip','')),
                        'dst': s.get('dst', s.get('dst_ip','')),
                        'ports': f"{s.get('src_port','')}->{s.get('dst_port','')}"
                    } for sid, s in sessions
                ]
            }

            prompt = (
                "You are a PCAP replay assistant. Based ONLY on the provided context, output a STRICT list of steps/commands "
                "for traffic reproduction and analysis. No explanations.\n\n"
                "CONTEXT (preview):\n" + json.dumps(summary)[:2500] + "\n\n"
                "OUTPUT RULES:\n"
                "- Provide concise step lines only (no prose).\n"
                "- Include Wireshark display filters first.\n"
                "- Include tshark commands next.\n"
                "- Optionally include tcpdump/tcpreplay/curl/nslookup as needed.\n"
                "- One command per line.\n"
                "- Do NOT include descriptions or numbering words, just the commands/filters.\n\n"
                "FORMAT: a plain list of lines, or a fenced code block."
            )

            resp = agent._call_openrouter(prompt)
            if not resp:
                return []

            # Extract lines from code blocks or plain text
            cmds: List[str] = []
            try:
                import re as _re
                blocks = _re.findall(r"```[a-zA-Z]*\s*([\s\S]*?)```", resp)
                raw = '\n'.join(blocks) if blocks else resp
                for line in raw.splitlines():
                    s = line.strip()
                    if not s:
                        continue
                    # Skip bullets/numbering
                    s = _re.sub(r"^[-*\d.]+\s*", "", s)
                    if s:
                        cmds.append(s)
            except Exception:
                pass

            out = [{'command': c, 'source': 'ai'} for c in cmds[:30]]
            return out
        except Exception:
            return []

    def _extract_voip_audio(self, sessions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Delegate to analyzers.forensics VoIP helper for RTP audio extraction."""
        try:
            from analyzers.forensics import extract_voip_audio_from_sessions as _x
            return _x(sessions)
        except Exception:
            return []

    def _extract_patterns_from_packets(self, packet_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Conservative pattern extraction from packet data.

        Returns a list of dicts with keys: 'pattern', 'type', 'packet_index', 'confidence', 'data'.
        Uses `self.pattern_extractor` when available, otherwise falls back to safe regex heuristics.
        """
        patterns: List[Dict[str, Any]] = []
        if not packet_data_list:
            return patterns

        try:
            for p in packet_data_list:
                data = p.get('data', '') if isinstance(p, dict) else ''
                if not data:
                    continue
                pkt_idx = p.get('packet_index', -1) if isinstance(p, dict) else -1
                timestamp = p.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

                # Helper function to normalize findings
                def normalize_finding(finding):
                    if isinstance(finding, str):
                        return {'data': finding, 'type': 'raw'}
                    elif isinstance(finding, dict):
                        return finding
                    return None

                # Prefer an existing pattern_extractor if it provides an extract() method
                if hasattr(self, 'pattern_extractor') and getattr(self.pattern_extractor, 'extract', None):
                    try:
                        extracted = self.pattern_extractor.extract(data)
                        if isinstance(extracted, list):
                            for e in extracted:
                                normalized = normalize_finding(e)
                                if normalized:
                                    normalized.setdefault('packet_index', pkt_idx)
                                    normalized.setdefault('timestamp', timestamp)
                                    normalized.setdefault('display_type', normalized.get('type', 'PATTERN').upper())
                                    normalized.setdefault('icon', '🔍')
                                    patterns.append(normalized)
                            continue
                    except Exception:
                        # Fall through to regex heuristics on extractor failure
                        pass

                # Fallback heuristics (conservative)
                # Create a base pattern dict with common fields
                def create_pattern_dict(pattern, ptype, confidence):
                    return {
                        'pattern': pattern,
                        'type': ptype,
                        'packet_index': pkt_idx,
                        'confidence': confidence,
                        'data': pattern,
                        'display_type': ptype.upper(),
                        'icon': {
                            'base64': '📝',
                            'hex': '🔢',
                            'url': '🌐',
                            'email': '📧'
                        }.get(ptype, '🔍')
                    }

                # Base64-like long strings
                for m in re.findall(r'([A-Za-z0-9+/]{40,}={0,2})', str(data)):
                    patterns.append(create_pattern_dict(m, 'base64', 0.65))

                # Long hex sequences
                for m in re.findall(r'\b([0-9a-fA-F]{16,})\b', str(data)):
                    patterns.append(create_pattern_dict(m, 'hex', 0.6))

                # URLs
                for m in re.findall(r'https?://[^\s\'\"]+', str(data)):
                    patterns.append(create_pattern_dict(m, 'url', 0.8))

                # Email addresses
                for m in re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', str(data)):
                    patterns.append(create_pattern_dict(m, 'email', 0.9))

        except Exception:
            # On unexpected errors return empty list to keep analysis robust
            return []

        # Final pass to ensure all patterns have required fields
        normalized_patterns = []
        for pattern in patterns:
            if not isinstance(pattern, dict):
                continue
                
            # Ensure all required fields are present with defaults
            normalized = {
                'type': pattern.get('type', 'unknown'),
                'display_type': pattern.get('display_type', pattern.get('type', 'PATTERN').upper()),
                'icon': pattern.get('icon', '🔍'),
                'data': pattern.get('data', pattern.get('pattern', '')),
                'packet_index': pattern.get('packet_index', -1),
                'confidence': pattern.get('confidence', 0.5),
                'timestamp': pattern.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                'context': pattern.get('context', '')
            }
            
            normalized_patterns.append(normalized)

        return normalized_patterns
    
    def _generate_hints(self) -> List[str]:
        """Generate hints based on findings"""
        hints = []
        
        # Check if we found first letters patterns
        if any(item.get('type') == 'first_letters' for item in self.results.get('extracted_patterns', [])):
            hints.append("🔤 Found patterns of first letters - try combining them to form a message")
        
        # Check if we found base64 encoded data
        if any(item.get('type') == 'base64' for item in self.results.get('decoded_data', [])):
            hints.append("🔐 Found base64 encoded data - check decoded content for hidden messages")
        
        # Check if we found potential flags
        if self.results.get('potential_flags', []):
            hints.append("🚩 Found potential flags - verify if they match the expected format")
        
        # Add general hints for CTF challenges
        hints.extend([
            "🔍 Look for patterns across multiple packets",
            "🌐 Check for unusual HTTP headers or request patterns",
            "📊 Analyze traffic patterns for anomalies",
            "🧩 Try combining findings from different packets"
        ])
        
        return hints
    
    # (moved) Suspicious packet identification now in analyzers.forensics
    
    def export_results(self, format_type: str = 'json') -> str:
        """Export results in specified format"""
        
        if format_type.lower() == 'json':
            return json.dumps(self.results, indent=2, default=str)
        
        elif format_type.lower() == 'csv':
            import pandas as pd
            
            # Convert findings to DataFrame
            df_data = []
            for finding in self.results['findings']:
                df_data.append({
                    'Type': finding.get('display_type', ''),
                    'Protocol': finding.get('protocol', ''),
                    'Source IP': finding.get('src_ip', ''),
                    'Destination IP': finding.get('dst_ip', ''),
                    'Content': finding.get('data', ''),
                    'Context': finding.get('context', ''),
                    'Timestamp': finding.get('timestamp', '')
                })
            
            df = pd.DataFrame(df_data)
            return df.to_csv(index=False)
        
        elif format_type.lower() == 'html':
            return self._generate_html_report()
        
        elif format_type.lower() == 'pdf':
            return self._generate_pdf_report()
        
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
            
    def _generate_pdf_report(self) -> bytes:
        """Generate a PDF report of the analysis results"""
        try:
            from fpdf import FPDF
            import io
            from datetime import datetime
            
            # Create PDF object
            pdf = FPDF()
            pdf.add_page()
            
            # Set up fonts
            pdf.set_font("Arial", "B", 16)
            
            # Title
            pdf.cell(0, 10, "FlagSniff Analysis Report", 0, 1, "C")
            pdf.set_font("Arial", "I", 10)
            pdf.cell(0, 10, f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, "C")
            pdf.ln(5)
            
            # Statistics section
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Analysis Statistics", 0, 1, "L")
            pdf.set_font("Arial", "", 10)
            
            # Create statistics table
            stats = [
                ["Total Packets", str(self.results.get('stats', {}).get('total_packets', 0))],
                ["Analyzed Packets", str(self.results.get('stats', {}).get('analyzed_packets', 0))],
                ["HTTP Requests", str(self.results.get('stats', {}).get('http_requests', 0))],
                ["HTTP Responses", str(self.results.get('stats', {}).get('http_responses', 0))],
                ["Suspicious Packets", str(self.results.get('stats', {}).get('suspicious_packets', 0))],
                ["Potential Flags", str(len([f for f in self.results.get('findings', []) if f.get('display_type') == 'Flag']))]
            ]
            
            # Add statistics table
            for stat in stats:
                pdf.cell(80, 8, stat[0], 1)
                pdf.cell(80, 8, stat[1], 1)
                pdf.ln()
            
            pdf.ln(10)
            
            # Findings section
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Key Findings", 0, 1, "L")
            
            # Add findings
            findings = self.results.get('findings', [])
            for i, finding in enumerate(findings):
                if i > 0:
                    pdf.add_page()  # New page for each finding after the first
                
                # Finding header
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, f"Finding #{i+1}: {finding.get('display_type', 'Unknown')}", 0, 1, "L")
                
                # Finding details
                pdf.set_font("Arial", "", 10)
                pdf.cell(40, 8, "Protocol:", 0)
                pdf.cell(0, 8, finding.get('protocol', 'Unknown'), 0, 1)
                
                pdf.cell(40, 8, "Source IP:", 0)
                pdf.cell(0, 8, finding.get('src_ip', 'Unknown'), 0, 1)
                
                pdf.cell(40, 8, "Destination IP:", 0)
                pdf.cell(0, 8, finding.get('dst_ip', 'Unknown'), 0, 1)
                
                pdf.cell(40, 8, "Timestamp:", 0)
                pdf.cell(0, 8, str(finding.get('timestamp', 'Unknown')), 0, 1)
                
                # Finding content
                pdf.ln(5)
                pdf.set_font("Arial", "B", 10)
                pdf.cell(0, 8, "Content:", 0, 1)
                pdf.set_font("Arial", "", 9)
                
                # Handle multiline content
                content = finding.get('data', '')
                if len(content) > 80:  # Wrap long content
                    wrapped_content = [content[i:i+80] for i in range(0, len(content), 80)]
                    for line in wrapped_content:
                        pdf.multi_cell(0, 5, line)
                else:
                    pdf.multi_cell(0, 5, content)
                
                pdf.ln(5)
                
                # Context if available
                if finding.get('context'):
                    pdf.set_font("Arial", "B", 10)
                    pdf.cell(0, 8, "Context:", 0, 1)
                    pdf.set_font("Arial", "", 9)
                    pdf.multi_cell(0, 5, finding.get('context', ''))
                
                pdf.ln(5)
            
            # Summary section if available
            if self.results.get('summary'):
                pdf.add_page()
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "Analysis Summary", 0, 1, "L")
                pdf.set_font("Arial", "", 10)
                pdf.multi_cell(0, 5, self.results.get('summary', ''))
            
            # Output PDF to bytes
            pdf_bytes = io.BytesIO()
            pdf.output(pdf_bytes)
            pdf_bytes.seek(0)
            return pdf_bytes.getvalue()
            
        except ImportError:
            # Fallback if fpdf is not available
            return bytes(f"PDF generation requires fpdf library. Please install with 'pip install fpdf2'.", 'utf-8')
    
    def _generate_html_report(self) -> str:
        """Generate detailed HTML report"""
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>FlagSniff Analysis Report</title>
            <meta charset="UTF-8">
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; 
                }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                .header {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px;
                }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
                .stat-card {{ 
                    background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; 
                    border-left: 4px solid #667eea;
                }}
                .stat-number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
                .stat-label {{ color: #666; margin-top: 5px; }}
                .findings-section {{ margin: 30px 0; }}
                .finding-item {{ 
                    background: #fff; border: 1px solid #e9ecef; border-radius: 8px; 
                    margin: 10px 0; padding: 20px; border-left: 4px solid #28a745;
                }}
                .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
                .finding-type {{ 
                    background: #667eea; color: white; padding: 5px 15px; 
                    border-radius: 20px; font-size: 0.9em; font-weight: bold;
                }}
                .finding-content {{ 
                    background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; word-break: break-all;
                }}
                .meta-info {{ color: #666; font-size: 0.9em; margin-top: 10px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>FlagSniff Analysis Report</h1>
                    <p>Generated on {timestamp}</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{total_packets}</div>
                        <div class="stat-label">Total Packets</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{analyzed_packets}</div>
                        <div class="stat-label">Analyzed Packets</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{findings_count}</div>
                        <div class="stat-label">Findings</div>
                    </div>
                </div>
                
                <div class="findings-section">
                    <h2>Findings</h2>
                    {findings_html}
                </div>
            </div>
        </body>
        </html>
        """
        
        # Generate findings HTML
        findings_html = ""
        for finding in self.results.get('findings', []):
            findings_html += f"""
            <div class="finding-item">
                <div class="finding-header">
                    <div class="finding-type">{finding.get('display_type', 'Unknown')}</div>
                    <div>{finding.get('protocol', '')}</div>
                </div>
                <div class="finding-content">{finding.get('data', '')}</div>
                <div class="meta-info">
                    Source: {finding.get('src_ip', '')} → Destination: {finding.get('dst_ip', '')}
                    <br>Timestamp: {finding.get('timestamp', '')}
                </div>
            </div>
            """
        
        # Fill in template
        from datetime import datetime
        html_report = html_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_packets=self.results.get('total_packets', 0),
            analyzed_packets=self.results.get('analyzed_packets', 0),
            findings_count=len(self.results.get('findings', [])),
            findings_html=findings_html
        )
        
        return html_report
        
    def _generate_pdf_report(self) -> bytes:
        """Generate PDF report of analysis results"""
        try:
            from fpdf import FPDF
            import io
            
            # Create PDF object
            pdf = FPDF()
            pdf.add_page()
            
            # Set styles
            pdf.set_font("Arial", "B", 16)
            pdf.set_fill_color(102, 126, 234)  # Header background color
            pdf.set_text_color(255, 255, 255)  # Header text color
            
            # Header
            pdf.cell(0, 20, "FlagSniff Analysis Report", 1, 1, "C", True)
            pdf.set_font("Arial", "I", 10)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 10, f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, "C")
            
            # Stats
            pdf.ln(10)
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Analysis Statistics", 0, 1, "L")
            pdf.set_font("Arial", "", 12)
            
            # Create stats table
            pdf.set_fill_color(240, 240, 240)
            pdf.cell(60, 10, "Total Packets", 1, 0, "L", True)
            pdf.cell(0, 10, f"{self.results.get('total_packets', 0):,}", 1, 1, "L")
            
            pdf.cell(60, 10, "Analyzed Packets", 1, 0, "L", True)
            pdf.cell(0, 10, f"{self.results.get('analyzed_packets', 0):,}", 1, 1, "L")
            
            pdf.cell(60, 10, "Findings", 1, 0, "L", True)
            pdf.cell(0, 10, f"{len(self.results.get('findings', []))}", 1, 1, "L")
            
            # Findings
            pdf.ln(10)
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Findings", 0, 1, "L")
            
            # Add findings
            for i, finding in enumerate(self.results.get('findings', [])):
                # Add page break if needed
                if i > 0 and pdf.get_y() > 220:
                    pdf.add_page()
                
                pdf.set_font("Arial", "B", 12)
                pdf.set_fill_color(102, 126, 234)
                pdf.set_text_color(255, 255, 255)
                pdf.cell(0, 10, f"{finding.get('display_type', 'Unknown')} ({finding.get('protocol', '')})", 1, 1, "L", True)
                
                pdf.set_font("Arial", "", 10)
                pdf.set_text_color(0, 0, 0)
                
                # Source and destination
                pdf.cell(40, 8, "Source IP:", 1, 0, "L", True)
                pdf.cell(0, 8, finding.get('src_ip', ''), 1, 1, "L")
                
                pdf.cell(40, 8, "Destination IP:", 1, 0, "L", True)
                pdf.cell(0, 8, finding.get('dst_ip', ''), 1, 1, "L")
                
                # Content
                pdf.cell(0, 8, "Content:", 1, 1, "L", True)
                
                # Handle long content with wrapping
                content = finding.get('data', '')
                pdf.multi_cell(0, 8, content, 1, "L")
                
                # Timestamp
                pdf.cell(40, 8, "Timestamp:", 1, 0, "L", True)
                pdf.cell(0, 8, str(finding.get('timestamp', '')), 1, 1, "L")
                
                pdf.ln(5)
            
            # Output PDF to bytes
            pdf_bytes = io.BytesIO()
            pdf.output(pdf_bytes)
            pdf_bytes.seek(0)
            return pdf_bytes.getvalue()
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise ValueError(f"Failed to generate PDF: {str(e)}")

    def _carve_files_from_streams(self, streams):
        """Extract files from TCP/UDP streams using file signatures"""
        carved_files = []
        for stream_id, stream in streams.items():
            data = stream.get('data', b'')
            if not data:
                continue
            for signature, file_info in self.file_signatures.items():
                start_pos = 0
                while True:
                    pos = data.find(signature, start_pos)
                    if pos == -1:
                        break
                    file_data = self._extract_file_from_position(data, pos, file_info)
                    if file_data:
                        file_hash = hashlib.md5(file_data).hexdigest()
                        carved_file = {
                            'stream_id': stream_id,
                            'file_type': file_info['name'],
                            'extension': file_info['ext'],
                            'size': len(file_data),
                            'md5_hash': file_hash,
                            'position': pos,
                            'filename': f"carved_{file_hash[:8]}.{file_info['ext']}",
                            'source_protocol': stream.get('protocol', 'Unknown'),
                            'source_ips': [stream.get('src_ip'), stream.get('dst_ip')],
                            'data': file_data
                        }
                        carved_files.append(carved_file)
                    start_pos = pos + 1
        # De-duplicate carved files by (hash, position, extension, stream)
        unique = {}
        for f in carved_files:
            key = (f.get('md5_hash'), f.get('position'), f.get('extension'), f.get('stream_id'))
            if key not in unique:
                unique[key] = f
        return list(unique.values())

    def _extract_file_from_position(self, data, pos, file_info):
        try:
            if file_info['ext'] in ['png', 'jpg', 'gif']:
                if file_info['ext'] == 'png':
                    end_marker = b'\x00\x00\x00\x00IEND\xaeB`\x82'
                elif file_info['ext'] == 'jpg':
                    end_marker = b'\xff\xd9'
                else:
                    end_marker = b'\x00\x3b'
                end_pos = data.find(end_marker, pos)
                if end_pos != -1:
                    return data[pos:end_pos + len(end_marker)]
            elif file_info['ext'] == 'pdf':
                end_pos = data.find(b'%%EOF', pos)
                if end_pos != -1:
                    return data[pos:end_pos + 5]
            elif file_info['ext'] == 'zip':
                return data[pos:pos + 1024]
            else:
                return data[pos:pos + 1024]
        except Exception:
            return None

    def _analyze_carved_files(self, carved_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched = []
        for f in carved_files:
            data = f.get('data', b'') or b''
            ext = (f.get('extension') or '').lower()
            analysis = {'metadata': {}, 'stego': []}
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
                if ext == 'png' and data.startswith(b'\x89PNG\r\n\x1a\n'):
                    chunks = self._parse_png_chunks(data)
                    analysis['metadata']['png_chunks'] = [c['type'] for c in chunks]
                    # Ancillary chunk diffing: flag unusual/rare custom chunk types
                    standard_chunks = {'IHDR','PLTE','IDAT','IEND','tEXt','zTXt','iTXt','bKGD','pHYs','tIME','tRNS','gAMA','cHRM','sRGB','iCCP','sBIT','sPLT','hIST'}
                    custom = [c['type'] for c in chunks if c['type'] not in standard_chunks]
                    if custom:
                        analysis['stego'].append({'type': 'png_custom_chunks', 'content': ', '.join(custom)})
                        self._add_hidden_finding('PNG custom chunks', ', '.join(custom), f)
                    for c in chunks:
                        if c['type'] == 'tEXt':
                            try:
                                text = c['data'].decode('latin-1', errors='ignore')
                                if text:
                                    analysis['stego'].append({'type': 'png_text', 'content': text[:500]})
                                    self._add_hidden_finding('PNG TEXT', text, f)
                            except Exception:
                                pass
                        elif c['type'] == 'zTXt':
                            try:
                                payload = c['data']
                                if b'\x00' in payload:
                                    comp = payload.split(b'\x00', 2)[-1]
                                    if len(comp) > 1:
                                        text = zlib.decompress(comp[1:]).decode('utf-8', errors='ignore')
                                        if text:
                                            analysis['stego'].append({'type': 'png_ztxt', 'content': text[:500]})
                                            self._add_hidden_finding('PNG zTXt', text, f)
                            except Exception:
                                pass
                        elif c['type'] == 'iTXt':
                            try:
                                text = ''.join(chr(b) if 9 <= b < 127 else ' ' for b in c['data'][:1000])
                                if any(ch.isalnum() for ch in text):
                                    analysis['stego'].append({'type': 'png_itxt', 'content': text.strip()[:500]})
                                    self._add_hidden_finding('PNG iTXt', text, f)
                            except Exception:
                                pass
                    # Simple LSB extraction
                    lsb_msg = self._png_lsb_extract(data, max_bits=200000)
                    if lsb_msg:
                        analysis['stego'].append({'type': 'png_lsb', 'content': lsb_msg[:500]})
                        self._add_hidden_finding('PNG LSB', lsb_msg, f)
                # ZIP polyglot detection
                if ext not in ('zip',) and b'PK\x03\x04' in data:
                    positions = []
                    start = 0
                    while True:
                        p = data.find(b'PK\x03\x04', start)
                        if p == -1:
                            break
                        positions.append(p)
                        start = p + 1
                    if positions:
                        analysis['stego'].append({'type': 'zip_polyglot', 'positions': positions[:10]})
                        self._add_hidden_finding('ZIP polyglot', f"Embedded ZIP at positions {positions[:5]}", f)
            except Exception:
                pass
            out = dict(f)
            if analysis['metadata'] or analysis['stego']:
                out['analysis'] = analysis
            enriched.append(out)
        return enriched

    def _parse_png_chunks(self, data: bytes) -> List[Dict[str, Any]]:
        chunks = []
        try:
            stream = io.BytesIO(data)
            stream.seek(8)
            while True:
                len_bytes = stream.read(4)
                if len(len_bytes) < 4:
                    break
                length = int.from_bytes(len_bytes, 'big')
                ctype = stream.read(4)
                if len(ctype) < 4:
                    break
                cdata = stream.read(length)
                stream.read(4)  # crc
                chunks.append({'type': ctype.decode('ascii', errors='ignore'), 'data': cdata})
                if ctype == b'IEND':
                    break
        except Exception:
            pass
        return chunks

    def _png_lsb_extract(self, data: bytes, max_bits: int = 200000) -> Optional[str]:
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(data))
            img = img.convert('RGB')
            width, height = img.size
            bits = []
            count = 0
            for y in range(height):
                for x in range(width):
                    r, g, b = img.getpixel((x, y))
                    bits.append(str(b & 1))
                    count += 1
                    if count >= max_bits:
                        break
                if count >= max_bits:
                    break
            msg_bytes = bytearray()
            for i in range(0, (len(bits)//8)*8, 8):
                msg_bytes.append(int(''.join(bits[i:i+8]), 2))
            text = msg_bytes.decode('utf-8', errors='ignore')
            printable = sum(1 for ch in text[:500] if 32 <= ord(ch) < 127)
            if len(text) >= 16 and printable / max(1, len(text[:500])) > 0.75:
                return text.strip('\x00')
        except Exception:
            return None
        return None

    def _add_hidden_finding(self, label: str, content: str, carved_file: Dict[str, Any]):
        try:
            self.results['findings'].append({
                'type': 'hidden_data',
                'display_type': label,
                'icon': '🕵️',
                'data': content[:200],
                'protocol': carved_file.get('source_protocol', 'Unknown'),
                'src_ip': (carved_file.get('source_ips') or ['',''])[0],
                'dst_ip': (carved_file.get('source_ips') or ['',''])[-1],
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        except Exception:
            pass

    def _decode_potential_data(self, packet_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Beam-search multi-layer decoding for likely encoded blobs in packets.

        - Seeds candidates via regex (base64/base32/hex/url-encoded), then explores
          short chains of decoding ops (depth<=3) with scoring by flag-likeness.
        - Returns conservative, text-like outputs with chain provenance and PoC hints.
        - Designed to be safe and non-destructive; all failures are swallowed.
        """
        import re, base64, urllib.parse, codecs, binascii, zlib, gzip, io

        results: List[Dict[str, Any]] = []
        if not packet_data_list:
            return results

        # Candidate extractors
        b64_re = re.compile(r'([A-Za-z0-9+/]{24,}={0,2})')
        b64url_re = re.compile(r'([A-Za-z0-9_\-]{24,}={0,2})')
        b32_re = re.compile(r'([A-Z2-7]{24,}=*)')
        hex_re = re.compile(r'\b([0-9a-fA-F]{32,})\b')

        # Operations registry (id -> callable that takes bytes -> bytes)
        def _to_bytes(x):
            if isinstance(x, (bytes, bytearray)):
                return bytes(x)
            if isinstance(x, str):
                return x.encode('utf-8', errors='ignore')
            return b''

        def op_b64(b):
            try:
                return base64.b64decode(b, validate=False)
            except Exception:
                return None

        def op_b64url(b):
            try:
                s = b.decode('utf-8', errors='ignore')
                s += '=' * ((4 - len(s) % 4) % 4)
                return base64.urlsafe_b64decode(s)
            except Exception:
                return None

        def op_b32(b):
            try:
                s = b.decode('utf-8', errors='ignore').upper()
                s += '=' * ((8 - len(s) % 8) % 8)
                return base64.b32decode(s)
            except Exception:
                return None

        def op_b85(b):
            try:
                return base64.b85decode(b)
            except Exception:
                return None

        def op_a85(b):
            try:
                return base64.a85decode(b)
            except Exception:
                return None

        def op_z85(b):
            # ZeroMQ Z85 decode; length must be multiple of 5
            try:
                s = b.decode('utf-8', errors='ignore').strip()
                alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
                if len(s) % 5 != 0:
                    return None
                out = bytearray()
                for i in range(0, len(s), 5):
                    acc = 0
                    for j in range(5):
                        ch = s[i+j]
                        idx = alphabet.find(ch)
                        if idx == -1:
                            return None
                        acc = acc * 85 + idx
                    out.extend([(acc >> 24) & 0xFF, (acc >> 16) & 0xFF, (acc >> 8) & 0xFF, acc & 0xFF])
                return bytes(out)
            except Exception:
                return None

        def op_base91(b):
            # Minimal base91 decoder
            try:
                s = b.decode('utf-8', errors='ignore')
                table = [
                    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                    '0','1','2','3','4','5','6','7','8','9','!','#','$','%','&','(',')','*','+',',','.','/',':',';','<','=','>',
                    '?','@','[',']','^','_','`','{','|','}','~','"'
                ]
                d = {c:i for i,c in enumerate(table)}
                v = -1
                bq = 0
                n = 0
                out = bytearray()
                for ch in s:
                    if ch not in d:
                        continue
                    c = d[ch]
                    if v < 0:
                        v = c
                    else:
                        v += c * 91
                        bq |= v << n
                        n += 13 if (v & 8191) > 88 else 14
                        while True:
                            out.append(bq & 255)
                            bq >>= 8
                            n -= 8
                            if n <= 7:
                                break
                        v = -1
                if v + 1:
                    out.append((bq | (v << n)) & 255)
                return bytes(out)
            except Exception:
                return None

        def op_uu(b):
            # Try to UU-decode per-line
            try:
                import binascii as _b
                s = b.decode('utf-8', errors='ignore').splitlines()
                out = bytearray()
                for line in s:
                    try:
                        dec = _b.a2b_uu(line)
                        if dec:
                            out.extend(dec)
                    except Exception:
                        continue
                return bytes(out) if out else None
            except Exception:
                return None

        def op_atbash(b):
            try:
                s = b.decode('utf-8', errors='ignore')
                def tr(c):
                    if 'a' <= c <= 'z':
                        return chr(ord('z') - (ord(c) - ord('a')))
                    if 'A' <= c <= 'Z':
                        return chr(ord('Z') - (ord(c) - ord('A')))
                    return c
                return ''.join(tr(c) for c in s).encode('utf-8', errors='ignore')
            except Exception:
                return None

        def op_baconian(b):
            try:
                s = b.decode('utf-8', errors='ignore')
                # Normalize to A/B
                ab = ''.join(ch for ch in s if ch in 'abAB')
                if len(ab) < 25 or len(ab) % 5 != 0:
                    return None
                ab = ab.lower()
                mapping = {
                    'aaaaa':'A','aaaab':'B','aaaba':'C','aaabb':'D','aabaa':'E','aabab':'F','aabba':'G','aabbb':'H',
                    'abaaa':'I','abaab':'J','ababa':'K','ababb':'L','abbaa':'M','abbab':'N','abbba':'O','abbbb':'P',
                    'baaaa':'Q','baaab':'R','baaba':'S','baabb':'T','babaa':'U','babab':'V','babba':'W','babbb':'X',
                    'bbaaa':'Y','bbaab':'Z'
                }
                out = []
                for i in range(0, len(ab), 5):
                    chunk = ab[i:i+5]
                    out.append(mapping.get(chunk, '?'))
                text = ''.join(out)
                # Require decent printable/text ratio
                if sum(ch.isalpha() for ch in text) < max(5, int(0.6*len(text))):
                    return None
                return text.encode('utf-8', errors='ignore')
            except Exception:
                return None

        def op_railfence(b):
            try:
                s = b.decode('utf-8', errors='ignore')
                def decode_rf(ct: str, rails: int) -> str:
                    if rails < 2 or rails >= len(ct):
                        return ct
                    # Build pattern of indices
                    pattern = list(range(rails)) + list(range(rails-2,0,-1))
                    idxs = [[] for _ in range(rails)]
                    # Assign positions per rail
                    rail_counts = [0]*rails
                    r = 0
                    for i in range(len(ct)):
                        idxs[pattern[r]].append(i)
                        r = (r+1) % len(pattern)
                    # Determine counts per rail
                    counts = [len(idxs[i]) for i in range(rails)]
                    # Determine slices into ciphertext
                    pos = 0
                    rails_slices = []
                    for c in counts:
                        rails_slices.append(list(range(pos, pos+c)))
                        pos += c
                    # Now rebuild
                    res = [''] * len(ct)
                    pos_per_rail = [0]*rails
                    # Map back using the pattern again
                    r = 0
                    for i in range(len(ct)):
                        rail = pattern[r]
                        # fetch next from corresponding slice
                        ci = rails_slices[rail][pos_per_rail[rail]]
                        pos_per_rail[rail] += 1
                        res[idxs[rail][pos_per_rail[rail]-1]] = ct[ci]
                        r = (r+1) % len(pattern)
                    return ''.join(res)

                def printable_score(t: str) -> float:
                    if not t:
                        return 0.0
                    sample = t[:2000]
                    pr = sum(1 for ch in sample if 32 <= ord(ch) < 127) / max(1, len(sample))
                    return pr

                best = ''
                best_s = 0.0
                for rails in (3,4,5):
                    dec = decode_rf(s, rails)
                    sc = printable_score(dec)
                    if sc > best_s:
                        best_s = sc
                        best = dec
                if best and best_s > 0.7:
                    return best.encode('utf-8', errors='ignore')
                return None
            except Exception:
                return None

        def op_hex(b):
            try:
                s = b.decode('utf-8', errors='ignore').strip()
                return binascii.unhexlify(s)
            except Exception:
                return None

        def op_url(b):
            try:
                s = b.decode('utf-8', errors='ignore')
                return urllib.parse.unquote_plus(s).encode('utf-8', errors='ignore')
            except Exception:
                return None

        def op_rot13(b):
            try:
                s = b.decode('utf-8', errors='ignore')
                return codecs.decode(s, 'rot_13').encode('utf-8', errors='ignore')
            except Exception:
                return None

        def op_gzip(b):
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(b)) as f:
                    return f.read()
            except Exception:
                return None

        def op_zlib(b):
            try:
                return zlib.decompress(b)
            except Exception:
                # Try raw DEFLATE
                try:
                    return zlib.decompress(b, -zlib.MAX_WBITS)
                except Exception:
                    return None

        OPS = [
            ('base64', op_b64),
            ('base64url', op_b64url),
            ('base32', op_b32),
            ('base85', op_b85),
            ('ascii85', op_a85),
            ('z85', op_z85),
            ('base91', op_base91),
            ('uu', op_uu),
            ('hex', op_hex),
            ('url', op_url),
            ('rot13', op_rot13),
            ('atbash', op_atbash),
            ('baconian', op_baconian),
            ('railfence', op_railfence),
            ('gzip', op_gzip),
            ('zlib', op_zlib),
        ]

        def score_bytes(b: bytes) -> float:
            """Heuristic scoring for decoded content."""
            if not b:
                return 0.0
            # Prefer text-like
            sample = b[:2000]
            printable = sum(1 for x in sample if 32 <= (x if isinstance(x, int) else ord(x)) < 127)
            ratio = printable / max(1, len(sample))
            score = ratio * 0.6
            try:
                s = b.decode('utf-8', errors='ignore')
            except Exception:
                s = ''
            if s:
                # Flag formats
                if re.search(r'(?i)(flag|ctf|htb|ductf|picoctf)\{[^}]+\}', s):
                    score += 0.4
                # JSON/URL hints
                if '{' in s and '}' in s:
                    score += 0.05
                if 'http' in s.lower() or 'GET /' in s or 'POST /' in s:
                    score += 0.05
            return min(1.0, score)

        def bytes_to_text(b: bytes) -> str:
            try:
                return b.decode('utf-8', errors='ignore')
            except Exception:
                return ''

        MAX_DEPTH = 3
        BEAM_WIDTH = 3

        for p in (packet_data_list or []):
            try:
                # Build a textual corpus to search for seeds
                if isinstance(p.get('data'), (bytes, bytearray)):
                    base_text = p.get('data').decode('utf-8', errors='ignore')
                else:
                    base_text = str(p.get('data') or p.get('http_body') or p.get('raw') or '')

                # Gather seed strings
                seeds: List[str] = []
                for regex in (b64_re, b64url_re, b32_re, hex_re):
                    try:
                        seeds.extend(regex.findall(base_text))
                    except Exception:
                        pass

                # Also try full-text URL decode as a seed
                if '%' in base_text and any(x in base_text for x in ('=', '&', '%3D')):
                    try:
                        url_dec = urllib.parse.unquote_plus(base_text)
                        if url_dec and url_dec != base_text:
                            seeds.append(url_dec[:4000])
                    except Exception:
                        pass

                # Deduplicate seeds conservatively
                seen_seed = set()
                uniq_seeds = []
                for s in seeds[:50]:
                    s2 = s if isinstance(s, str) else str(s)
                    if s2 not in seen_seed:
                        seen_seed.add(s2)
                        uniq_seeds.append(s)

                # Beam search over operations
                for seed in uniq_seeds:
                    try:
                        seed_b = _to_bytes(seed)
                        # Initialize beam with raw and one-step decodes (helps when input is already decoded text)
                        beam = [({'chain': [], 'data': seed_b, 'score': score_bytes(seed_b)})]

                        best_candidates = []  # collect across depths
                        for depth in range(1, MAX_DEPTH + 1):
                            new_beam = []
                            for cand in beam:
                                for op_name, op_fn in OPS:
                                    try:
                                        out = op_fn(cand['data'])
                                        if out is None or out == b'':
                                            continue
                                        sc = score_bytes(out)
                                        new_c = {
                                            'chain': cand['chain'] + [op_name],
                                            'data': out,
                                            'score': sc
                                        }
                                        new_beam.append(new_c)
                                        if sc >= 0.5:
                                            best_candidates.append(new_c)
                                    except Exception:
                                        continue
                            # Keep top-K for next depth
                            new_beam.sort(key=lambda x: x['score'], reverse=True)
                            beam = new_beam[:BEAM_WIDTH]

                        # Emit top results for this seed
                        best_candidates.sort(key=lambda x: x['score'], reverse=True)
                        for bc in best_candidates[:3]:
                            txt = bytes_to_text(bc['data'])
                            if not txt or len(txt.strip()) < 3:
                                continue
                            conf = round(min(0.95, 0.5 + bc['score'] * 0.5), 2)
                            entry = {
                                'result': txt,
                                'decoded': txt,
                                'original': seed if isinstance(seed, str) else str(seed)[:200],
                                'packet_index': p.get('packet_index'),
                                'protocol': p.get('protocol'),
                                'src_ip': p.get('src', ''),
                                'dst_ip': p.get('dst', ''),
                                'confidence': conf,
                                'chain': bc['chain'],
                                'type': 'beam_chain'
                            }
                            # Simple PoC steps for reproduction in terminal tools
                            if bc['chain']:
                                steps = []
                                for step in bc['chain']:
                                    if step in ('base64', 'base64url'):
                                        steps.append({'method': 'base64 -d', 'command': "echo '<DATA>' | base64 -d"})
                                    elif step == 'hex':
                                        steps.append({'method': 'xxd -r -p', 'command': "echo '<HEX>' | xxd -r -p"})
                                    elif step == 'url':
                                        steps.append({'method': 'urldecode', 'command': "python -c \"import urllib.parse,sys;print(urllib.parse.unquote_plus(sys.stdin.read()))\""})
                                    elif step == 'rot13':
                                        steps.append({'method': 'rot13', 'command': "python -c \"import codecs,sys;print(codecs.decode(sys.stdin.read(),'rot_13'))\""})
                                    elif step == 'gzip':
                                        steps.append({'method': 'gunzip', 'command': "python -c \"import sys,gzip;import io;print(gzip.decompress(sys.stdin.buffer.read()).decode('utf-8','ignore'))\""})
                                    elif step == 'zlib':
                                        steps.append({'method': 'zlib', 'command': "python -c \"import sys,zlib;print(zlib.decompress(sys.stdin.buffer.read()).decode('utf-8','ignore'))\""})
                                if steps:
                                    entry['poc'] = {'extraction_steps': steps}
                            results.append(entry)
                    except Exception:
                        continue

            except Exception:
                # Be conservative: ignore problematic packet entries
                continue

        return results
def analyze_sample_pcap(file_path: str, search_options: Optional[Dict[str, bool]] = None, custom_regex: Optional[str] = None, progress_callback=None, user_decrypt_key: str = None) -> Dict[str, Any]:
    """Convenience wrapper to analyze a single pcap using WebPcapAnalyzer.

    This function exists so other modules (like Streamlit app) can import a
    simple entry-point without instantiating the class directly. It forwards
    arguments to WebPcapAnalyzer.analyze_file and returns the results.
    """
    search_options = search_options or {}
    analyzer = WebPcapAnalyzer()
    return analyzer.analyze_file(file_path, search_options, custom_regex=custom_regex, progress_callback=progress_callback, user_decrypt_key=user_decrypt_key)