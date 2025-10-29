"""
Enhanced Packet Sequence Tracking System
Implements advanced fragmentation detection and reassembly for flag reconstruction
"""

import struct
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
import re

@dataclass
class PacketFragment:
    """Represents a packet fragment with metadata"""
    packet_index: int
    sequence_number: int
    fragment_offset: int
    fragment_size: int
    more_fragments: bool
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    timestamp: float
    data: bytes
    fragment_id: str
    stream_id: str

@dataclass 
class ReassemblyBuffer:
    """Buffer for reassembling fragmented data"""
    stream_id: str
    fragments: Dict[int, PacketFragment] = field(default_factory=dict)
    expected_sequence: int = 0
    total_size: Optional[int] = None
    last_activity: float = field(default_factory=time.time)
    is_complete: bool = False
    reassembled_data: Optional[bytes] = None

class SequenceTracker:
    """Tracks packet sequences and identifies fragmentation patterns"""
    
    def __init__(self, timeout_seconds: int = 30):
        self.reassembly_buffers: Dict[str, ReassemblyBuffer] = {}
        self.timeout_seconds = timeout_seconds
        self.fragment_patterns = {
            'tcp_segmentation': self._detect_tcp_segmentation,
            'http_chunked': self._detect_http_chunked,
            'ip_fragmentation': self._detect_ip_fragmentation,
            'custom_fragmentation': self._detect_custom_fragmentation
        }
        
    def process_packet(self, packet_info: Dict[str, Any], packet_index: int) -> List[PacketFragment]:
        """Process a packet and detect fragmentation patterns"""
        fragments = []
        
        # Apply each fragmentation detection pattern
        for pattern_name, pattern_func in self.fragment_patterns.items():
            try:
                detected_fragments = pattern_func(packet_info, packet_index)
                fragments.extend(detected_fragments)
            except Exception as e:
                continue  # Skip failed patterns
        
        # Clean up expired buffers
        self._cleanup_expired_buffers()
        
        return fragments
    
    def _detect_tcp_segmentation(self, packet_info: Dict[str, Any], packet_index: int) -> List[PacketFragment]:
        """Detect TCP segmentation patterns"""
        fragments = []
        
        if packet_info.get('protocol') != 'TCP':
            return fragments
        
        # Extract TCP sequence information
        data = packet_info.get('data', '')
        if not data:
            return fragments
        
        # Create stream identifier
        stream_id = f"tcp_{packet_info.get('src', '')}:{packet_info.get('src_port', 0)}-{packet_info.get('dst', '')}:{packet_info.get('dst_port', 0)}"
        
        # Simulate TCP sequence number (in real implementation, extract from packet)
        sequence_num = packet_index * 1000  # Simplified
        
        fragment = PacketFragment(
            packet_index=packet_index,
            sequence_number=sequence_num,
            fragment_offset=0,
            fragment_size=len(data.encode('utf-8')),
            more_fragments=True,  # Assume more fragments
            protocol='TCP',
            src_ip=packet_info.get('src', ''),
            dst_ip=packet_info.get('dst', ''),
            src_port=packet_info.get('src_port', 0),
            dst_port=packet_info.get('dst_port', 0),
            timestamp=packet_info.get('timestamp', time.time()),
            data=data.encode('utf-8'),
            fragment_id=f"tcp_frag_{packet_index}",
            stream_id=stream_id
        )
        
        fragments.append(fragment)
        return fragments
    
    def _detect_http_chunked(self, packet_info: Dict[str, Any], packet_index: int) -> List[PacketFragment]:
        """Detect HTTP chunked transfer encoding"""
        fragments = []
        
        if packet_info.get('protocol') != 'HTTP':
            return fragments
        
        data = packet_info.get('data', '')
        
        # Look for chunked transfer encoding
        if 'Transfer-Encoding: chunked' in data or re.search(r'[0-9a-fA-F]+\r\n', data):
            
            stream_id = f"http_chunked_{packet_info.get('src', '')}_{packet_index}"
            
            # Parse chunks
            chunk_pattern = re.compile(r'([0-9a-fA-F]+)\r\n(.+?)(?=\r\n[0-9a-fA-F]+|\r\n0\r\n|$)', re.DOTALL)
            matches = chunk_pattern.findall(data)
            
            for i, (size_hex, chunk_data) in enumerate(matches):
                try:
                    chunk_size = int(size_hex, 16)
                    
                    fragment = PacketFragment(
                        packet_index=packet_index,
                        sequence_number=i,
                        fragment_offset=i * 1000,  # Simplified offset
                        fragment_size=chunk_size,
                        more_fragments=(chunk_size > 0),
                        protocol='HTTP_CHUNKED',
                        src_ip=packet_info.get('src', ''),
                        dst_ip=packet_info.get('dst', ''),
                        src_port=packet_info.get('src_port', 80),
                        dst_port=packet_info.get('dst_port', 80),
                        timestamp=packet_info.get('timestamp', time.time()),
                        data=chunk_data.encode('utf-8'),
                        fragment_id=f"http_chunk_{packet_index}_{i}",
                        stream_id=stream_id
                    )
                    
                    fragments.append(fragment)
                    
                except ValueError:
                    continue  # Skip invalid hex values
        
        return fragments
    
    def _detect_ip_fragmentation(self, packet_info: Dict[str, Any], packet_index: int) -> List[PacketFragment]:
        """Detect IP layer fragmentation"""
        fragments = []
        
        # Simplified IP fragmentation detection
        data = packet_info.get('data', '')
        
        # Look for patterns indicating IP fragmentation
        if len(data) > 1400:  # Likely fragmented if larger than typical MTU
            
            fragment_size = 1400
            num_fragments = (len(data) + fragment_size - 1) // fragment_size
            
            stream_id = f"ip_frag_{packet_info.get('src', '')}_{packet_index}"
            
            for i in range(num_fragments):
                start_offset = i * fragment_size
                end_offset = min(start_offset + fragment_size, len(data))
                fragment_data = data[start_offset:end_offset]
                
                fragment = PacketFragment(
                    packet_index=packet_index,
                    sequence_number=i,
                    fragment_offset=start_offset,
                    fragment_size=len(fragment_data),
                    more_fragments=(i < num_fragments - 1),
                    protocol='IP_FRAG',
                    src_ip=packet_info.get('src', ''),
                    dst_ip=packet_info.get('dst', ''),
                    src_port=packet_info.get('src_port', 0),
                    dst_port=packet_info.get('dst_port', 0),
                    timestamp=packet_info.get('timestamp', time.time()),
                    data=fragment_data.encode('utf-8'),
                    fragment_id=f"ip_frag_{packet_index}_{i}",
                    stream_id=stream_id
                )
                
                fragments.append(fragment)
        
        return fragments
    
    def _detect_custom_fragmentation(self, packet_info: Dict[str, Any], packet_index: int) -> List[PacketFragment]:
        """Detect custom fragmentation patterns used in CTF challenges"""
        fragments = []
        
        data = packet_info.get('data', '')
        
        # Pattern 1: Data split by custom delimiters
        custom_delimiters = ['|||', '###', '***', '---']
        
        for delimiter in custom_delimiters:
            if delimiter in data:
                parts = data.split(delimiter)
                if len(parts) > 1:
                    
                    stream_id = f"custom_{delimiter}_{packet_info.get('src', '')}_{packet_index}"
                    
                    for i, part in enumerate(parts):
                        if part.strip():  # Skip empty parts
                            
                            fragment = PacketFragment(
                                packet_index=packet_index,
                                sequence_number=i,
                                fragment_offset=i * 100,  # Simplified
                                fragment_size=len(part),
                                more_fragments=(i < len(parts) - 1),
                                protocol=f'CUSTOM_{delimiter.replace(delimiter[0], "")}',
                                src_ip=packet_info.get('src', ''),
                                dst_ip=packet_info.get('dst', ''),
                                src_port=packet_info.get('src_port', 0),
                                dst_port=packet_info.get('dst_port', 0),
                                timestamp=packet_info.get('timestamp', time.time()),
                                data=part.strip().encode('utf-8'),
                                fragment_id=f"custom_{delimiter}_{packet_index}_{i}",
                                stream_id=stream_id
                            )
                            
                            fragments.append(fragment)
                break  # Only use first matching delimiter
        
        return fragments
    
    def add_fragment_to_buffer(self, fragment: PacketFragment) -> Optional[bytes]:
        """Add a fragment to reassembly buffer and return complete data if ready"""
        
        stream_id = fragment.stream_id
        
        # Create buffer if it doesn't exist
        if stream_id not in self.reassembly_buffers:
            self.reassembly_buffers[stream_id] = ReassemblyBuffer(stream_id=stream_id)
        
        buffer = self.reassembly_buffers[stream_id]
        
        # Add fragment to buffer
        buffer.fragments[fragment.sequence_number] = fragment
        buffer.last_activity = time.time()
        
        # Check if we can reassemble
        return self._attempt_reassembly(buffer)
    
    def _attempt_reassembly(self, buffer: ReassemblyBuffer) -> Optional[bytes]:
        """Attempt to reassemble fragments in buffer"""
        
        if buffer.is_complete:
            return buffer.reassembled_data
        
        # Sort fragments by sequence number
        sorted_fragments = sorted(buffer.fragments.values(), key=lambda x: x.sequence_number)
        
        # Check for sequence continuity
        expected_seq = 0
        reassembled_data = b''
        
        for fragment in sorted_fragments:
            if fragment.sequence_number == expected_seq:
                reassembled_data += fragment.data
                expected_seq += 1
            else:
                # Gap in sequence - can't reassemble yet
                return None
        
        # Check if this is the final fragment
        if sorted_fragments and not sorted_fragments[-1].more_fragments:
            buffer.is_complete = True
            buffer.reassembled_data = reassembled_data
            return reassembled_data
        
        return None
    
    def _cleanup_expired_buffers(self):
        """Remove expired reassembly buffers"""
        current_time = time.time()
        expired_streams = []
        
        for stream_id, buffer in self.reassembly_buffers.items():
            if current_time - buffer.last_activity > self.timeout_seconds:
                expired_streams.append(stream_id)
        
        for stream_id in expired_streams:
            del self.reassembly_buffers[stream_id]
    
    def get_reassembly_status(self) -> Dict[str, Any]:
        """Get current status of all reassembly buffers"""
        status = {
            'active_streams': len(self.reassembly_buffers),
            'completed_streams': sum(1 for b in self.reassembly_buffers.values() if b.is_complete),
            'streams': {}
        }
        
        for stream_id, buffer in self.reassembly_buffers.items():
            status['streams'][stream_id] = {
                'fragment_count': len(buffer.fragments),
                'is_complete': buffer.is_complete,
                'last_activity': buffer.last_activity,
                'total_data_size': len(buffer.reassembled_data) if buffer.reassembled_data else 0
            }
        
        return status

class FragmentationAnalyzer:
    """Analyzes fragmentation patterns for CTF flag reconstruction"""
    
    def __init__(self):
        self.sequence_tracker = SequenceTracker()
        
    def analyze_fragmentation_patterns(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze packets for fragmentation patterns and reassemble data"""
        
        analysis_results = {
            'fragments_detected': [],
            'reassembled_streams': {},
            'fragmentation_types': set(),
            'potential_flags': [],
            'analysis_metadata': {
                'total_packets': len(packets),
                'fragments_found': 0,
                'streams_reassembled': 0,
                'processing_time': 0
            }
        }
        
        start_time = time.time()
        
        # Process each packet
        for i, packet in enumerate(packets):
            fragments = self.sequence_tracker.process_packet(packet, i)
            analysis_results['fragments_detected'].extend(fragments)
            
            # Add fragments to reassembly buffers
            for fragment in fragments:
                analysis_results['fragmentation_types'].add(fragment.protocol)
                
                reassembled_data = self.sequence_tracker.add_fragment_to_buffer(fragment)
                
                if reassembled_data:
                    # Successfully reassembled a stream
                    stream_id = fragment.stream_id
                    analysis_results['reassembled_streams'][stream_id] = {
                        'data': reassembled_data.decode('utf-8', errors='ignore'),
                        'size': len(reassembled_data),
                        'fragment_count': len(self.sequence_tracker.reassembly_buffers[stream_id].fragments),
                        'protocol': fragment.protocol
                    }
                    
                    # Check for flags in reassembled data
                    potential_flags = self._extract_flags_from_data(reassembled_data.decode('utf-8', errors='ignore'))
                    if potential_flags:
                        analysis_results['potential_flags'].extend([
                            {
                                'flag': flag,
                                'stream_id': stream_id,
                                'source': 'fragmentation_reassembly',
                                'confidence': 0.9
                            } for flag in potential_flags
                        ])
        
        # Update metadata
        analysis_results['analysis_metadata'].update({
            'fragments_found': len(analysis_results['fragments_detected']),
            'streams_reassembled': len(analysis_results['reassembled_streams']),
            'processing_time': time.time() - start_time,
            'fragmentation_types': list(analysis_results['fragmentation_types'])
        })
        
        # Get reassembly status
        analysis_results['reassembly_status'] = self.sequence_tracker.get_reassembly_status()
        
        return analysis_results
    
    def _extract_flags_from_data(self, data: str) -> List[str]:
        """Extract potential flags from reassembled data"""
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'[A-Z]{2,8}\{[^}]+\}'
        ]
        
        flags = []
        for pattern in flag_patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            flags.extend(matches)
        
        return list(set(flags))  # Remove duplicates

# Factory function for integration
def create_fragmentation_analyzer() -> FragmentationAnalyzer:
    """Create fragmentation analyzer instance"""
    return FragmentationAnalyzer()