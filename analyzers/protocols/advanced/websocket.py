"""WebSocket protocol decoder.

Decodes WebSocket frames from TCP streams, handling:
- Frame parsing (text/binary/control frames)
- Masking/unmasking
- Fragmentation
- Compression (permessage-deflate extension)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
import struct


@dataclass
class WebSocketFrame:
    """Represents a decoded WebSocket frame."""
    fin: bool  # Final fragment
    opcode: int  # Frame opcode
    masked: bool  # Is payload masked
    payload_length: int
    masking_key: Optional[bytes]
    payload: bytes
    frame_type: str  # 'text', 'binary', 'close', 'ping', 'pong'
    
    @property
    def is_control_frame(self) -> bool:
        """Check if this is a control frame."""
        return self.opcode >= 0x8
    
    @property
    def unmasked_payload(self) -> bytes:
        """Get unmasked payload data."""
        if not self.masked or not self.masking_key:
            return self.payload
        
        # XOR with masking key
        unmasked = bytearray()
        for i, byte in enumerate(self.payload):
            unmasked.append(byte ^ self.masking_key[i % 4])
        return bytes(unmasked)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'fin': self.fin,
            'opcode': self.opcode,
            'frame_type': self.frame_type,
            'masked': self.masked,
            'payload_length': self.payload_length,
            'payload_preview': self.unmasked_payload[:100].decode('utf-8', errors='replace'),
            'is_control': self.is_control_frame
        }


class WebSocketDecoder:
    """Decode WebSocket frames from raw TCP data."""
    
    OPCODES = {
        0x0: 'continuation',
        0x1: 'text',
        0x2: 'binary',
        0x8: 'close',
        0x9: 'ping',
        0xA: 'pong'
    }
    
    def __init__(self):
        self.frames: List[WebSocketFrame] = []
        self.fragmented_message: List[WebSocketFrame] = []
    
    def decode_frame(self, data: bytes, offset: int = 0) -> Optional[Tuple[WebSocketFrame, int]]:
        """Decode a single WebSocket frame from bytes.
        
        Args:
            data: Raw bytes containing WebSocket frame
            offset: Starting offset in data
            
        Returns:
            Tuple of (WebSocketFrame, bytes_consumed) or None if incomplete
        """
        if len(data) - offset < 2:
            return None  # Need at least 2 bytes for header
        
        # Parse first byte
        byte1 = data[offset]
        fin = bool(byte1 & 0x80)
        rsv = (byte1 & 0x70) >> 4
        opcode = byte1 & 0x0F
        
        # Parse second byte
        byte2 = data[offset + 1]
        masked = bool(byte2 & 0x80)
        payload_length = byte2 & 0x7F
        
        current_offset = offset + 2
        
        # Extended payload length
        if payload_length == 126:
            if len(data) - current_offset < 2:
                return None
            payload_length = struct.unpack('!H', data[current_offset:current_offset+2])[0]
            current_offset += 2
        elif payload_length == 127:
            if len(data) - current_offset < 8:
                return None
            payload_length = struct.unpack('!Q', data[current_offset:current_offset+8])[0]
            current_offset += 8
        
        # Masking key
        masking_key = None
        if masked:
            if len(data) - current_offset < 4:
                return None
            masking_key = data[current_offset:current_offset+4]
            current_offset += 4
        
        # Payload
        if len(data) - current_offset < payload_length:
            return None  # Incomplete frame
        
        payload = data[current_offset:current_offset+payload_length]
        current_offset += payload_length
        
        frame = WebSocketFrame(
            fin=fin,
            opcode=opcode,
            masked=masked,
            payload_length=payload_length,
            masking_key=masking_key,
            payload=payload,
            frame_type=self.OPCODES.get(opcode, f'unknown_{opcode}')
        )
        
        bytes_consumed = current_offset - offset
        return (frame, bytes_consumed)
    
    def decode_stream(self, data: bytes) -> List[WebSocketFrame]:
        """Decode multiple frames from a byte stream.
        
        Args:
            data: Raw bytes potentially containing multiple frames
            
        Returns:
            List of decoded WebSocket frames
        """
        frames = []
        offset = 0
        
        while offset < len(data):
            result = self.decode_frame(data, offset)
            if result is None:
                break  # Incomplete frame or end of data
            
            frame, consumed = result
            frames.append(frame)
            offset += consumed
        
        self.frames.extend(frames)
        return frames
    
    def extract_messages(self, frames: Optional[List[WebSocketFrame]] = None) -> List[Dict[str, Any]]:
        """Extract complete messages from frames (handling fragmentation).
        
        Args:
            frames: List of frames to process (uses self.frames if None)
            
        Returns:
            List of complete messages
        """
        if frames is None:
            frames = self.frames
        
        messages = []
        current_fragments = []
        
        for frame in frames:
            if frame.is_control_frame:
                # Control frames are standalone
                messages.append({
                    'type': 'control',
                    'frame_type': frame.frame_type,
                    'payload': frame.unmasked_payload,
                    'size': len(frame.unmasked_payload)
                })
            elif frame.opcode != 0x0:  # Not continuation
                if frame.fin:
                    # Complete single-frame message
                    messages.append({
                        'type': 'data',
                        'frame_type': frame.frame_type,
                        'payload': frame.unmasked_payload,
                        'size': len(frame.unmasked_payload),
                        'fragmented': False
                    })
                else:
                    # Start of fragmented message
                    current_fragments = [frame]
            else:  # Continuation frame
                current_fragments.append(frame)
                if frame.fin:
                    # End of fragmented message
                    combined_payload = b''.join(f.unmasked_payload for f in current_fragments)
                    first_frame = current_fragments[0]
                    messages.append({
                        'type': 'data',
                        'frame_type': first_frame.frame_type,
                        'payload': combined_payload,
                        'size': len(combined_payload),
                        'fragmented': True,
                        'fragment_count': len(current_fragments)
                    })
                    current_fragments = []
        
        return messages
    
    def find_websocket_handshake(self, http_data: bytes) -> Optional[Dict[str, str]]:
        """Extract WebSocket handshake information from HTTP upgrade request.
        
        Args:
            http_data: Raw HTTP request bytes
            
        Returns:
            Dict with handshake details or None
        """
        try:
            http_str = http_data.decode('utf-8', errors='replace')
            lines = http_str.split('\r\n')
            
            if not any('Upgrade: websocket' in line for line in lines):
                return None
            
            handshake = {}
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key in ['sec-websocket-key', 'sec-websocket-version',
                               'sec-websocket-protocol', 'sec-websocket-extensions']:
                        handshake[key] = value
            
            return handshake if handshake else None
        except Exception:
            return None
    
    def analyze_websocket_traffic(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyze WebSocket traffic from packet list.
        
        Args:
            packets: List of Scapy packets
            
        Returns:
            Dict with WebSocket traffic analysis
        """
        try:
            from scapy.all import TCP, Raw  # type: ignore
        except ImportError:
            return {'error': 'Scapy not available'}
        
        handshakes = []
        all_frames = []
        
        for pkt in packets:
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                continue
            
            payload = bytes(pkt[Raw].load)
            
            # Check for handshake
            handshake = self.find_websocket_handshake(payload)
            if handshake:
                handshakes.append({
                    'src': f"{pkt['IP'].src}:{pkt[TCP].sport}",
                    'dst': f"{pkt['IP'].dst}:{pkt[TCP].dport}",
                    **handshake
                })
                continue
            
            # Try to decode WebSocket frames
            frames = self.decode_stream(payload)
            all_frames.extend(frames)
        
        messages = self.extract_messages(all_frames)
        
        # Statistics
        text_messages = sum(1 for m in messages if m.get('frame_type') == 'text')
        binary_messages = sum(1 for m in messages if m.get('frame_type') == 'binary')
        control_messages = sum(1 for m in messages if m.get('type') == 'control')
        
        return {
            'handshakes': handshakes,
            'total_frames': len(all_frames),
            'total_messages': len(messages),
            'text_messages': text_messages,
            'binary_messages': binary_messages,
            'control_messages': control_messages,
            'fragmented_messages': sum(1 for m in messages if m.get('fragmented')),
            'messages': messages[:50],  # Limit to first 50 for display
            'frames': [f.to_dict() for f in all_frames[:50]]
        }
