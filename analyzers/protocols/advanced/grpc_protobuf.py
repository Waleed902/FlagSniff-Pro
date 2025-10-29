"""gRPC and Protocol Buffers decoder.

Decodes gRPC traffic from HTTP/2 streams:
- Service and method extraction
- Protobuf message decoding (best-effort)
- Stream type detection (unary, server streaming, client streaming, bidirectional)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
import struct


@dataclass
class GRPCMessage:
    """Represents a decoded gRPC message."""
    compressed: bool
    length: int
    data: bytes
    direction: str  # 'request' or 'response'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'compressed': self.compressed,
            'length': self.length,
            'direction': self.direction,
            'data_preview': self.data[:100].hex()
        }


@dataclass
class GRPCCall:
    """Represents a gRPC call with metadata."""
    service: str
    method: str
    stream_id: int
    call_type: str  # 'unary', 'server_stream', 'client_stream', 'bidi_stream'
    messages: List[GRPCMessage]
    metadata: Dict[str, str]
    status: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'service': self.service,
            'method': self.method,
            'stream_id': self.stream_id,
            'call_type': self.call_type,
            'message_count': len(self.messages),
            'metadata': self.metadata,
            'status': self.status,
            'messages': [m.to_dict() for m in self.messages[:10]]  # Limit messages
        }


class ProtobufDecoder:
    """Best-effort Protobuf decoder (without schema)."""
    
    WIRE_TYPES = {
        0: 'varint',
        1: 'fixed64',
        2: 'length_delimited',
        3: 'start_group',
        4: 'end_group',
        5: 'fixed32'
    }
    
    def decode_varint(self, data: bytes, offset: int = 0) -> Optional[Tuple[int, int]]:
        """Decode a varint from bytes.
        
        Returns:
            Tuple of (value, bytes_consumed) or None
        """
        result = 0
        shift = 0
        consumed = 0
        
        for i in range(offset, min(offset + 10, len(data))):
            byte = data[i]
            result |= (byte & 0x7F) << shift
            consumed += 1
            
            if not (byte & 0x80):
                return (result, consumed)
            
            shift += 7
        
        return None  # Invalid varint
    
    def decode_field(self, data: bytes, offset: int = 0) -> Optional[Dict[str, Any]]:
        """Decode a single Protobuf field.
        
        Returns:
            Dict with field info or None
        """
        # Decode field tag
        tag_result = self.decode_varint(data, offset)
        if not tag_result:
            return None
        
        tag, tag_size = tag_result
        field_number = tag >> 3
        wire_type = tag & 0x7
        
        current_offset = offset + tag_size
        
        field_info = {
            'field_number': field_number,
            'wire_type': self.WIRE_TYPES.get(wire_type, 'unknown'),
            'wire_type_id': wire_type
        }
        
        # Decode value based on wire type
        if wire_type == 0:  # Varint
            value_result = self.decode_varint(data, current_offset)
            if not value_result:
                return None
            value, value_size = value_result
            field_info['value'] = value
            field_info['size'] = tag_size + value_size
            
        elif wire_type == 1:  # Fixed64
            if len(data) - current_offset < 8:
                return None
            field_info['value'] = struct.unpack('<Q', data[current_offset:current_offset+8])[0]
            field_info['size'] = tag_size + 8
            
        elif wire_type == 2:  # Length-delimited
            length_result = self.decode_varint(data, current_offset)
            if not length_result:
                return None
            length, length_size = length_result
            
            if len(data) - current_offset - length_size < length:
                return None
            
            value_data = data[current_offset + length_size:current_offset + length_size + length]
            
            # Try to decode as string
            try:
                as_string = value_data.decode('utf-8')
                field_info['value'] = as_string
                field_info['value_type'] = 'string'
            except:
                # Could be bytes or nested message
                field_info['value'] = value_data.hex()[:100]
                field_info['value_type'] = 'bytes'
            
            field_info['size'] = tag_size + length_size + length
            
        elif wire_type == 5:  # Fixed32
            if len(data) - current_offset < 4:
                return None
            field_info['value'] = struct.unpack('<I', data[current_offset:current_offset+4])[0]
            field_info['size'] = tag_size + 4
        
        else:
            return None  # Unsupported wire type
        
        return field_info
    
    def decode_message(self, data: bytes) -> List[Dict[str, Any]]:
        """Decode all fields in a Protobuf message.
        
        Returns:
            List of decoded fields
        """
        fields = []
        offset = 0
        
        while offset < len(data):
            field = self.decode_field(data, offset)
            if not field:
                break
            
            fields.append(field)
            offset += field['size']
        
        return fields


class GRPCDecoder:
    """Decode gRPC traffic from HTTP/2."""
    
    def __init__(self):
        self.calls: List[GRPCCall] = []
        self.protobuf_decoder = ProtobufDecoder()
    
    def parse_grpc_message(self, data: bytes, offset: int = 0) -> Optional[Tuple[GRPCMessage, int]]:
        """Parse a single gRPC message from bytes.
        
        gRPC message format:
        - 1 byte: compression flag
        - 4 bytes: message length (big-endian)
        - N bytes: message data
        
        Returns:
            Tuple of (GRPCMessage, bytes_consumed) or None
        """
        if len(data) - offset < 5:
            return None  # Need at least 5 bytes for header
        
        compressed = bool(data[offset] & 0x01)
        length = struct.unpack('!I', data[offset+1:offset+5])[0]
        
        if len(data) - offset - 5 < length:
            return None  # Incomplete message
        
        message_data = data[offset+5:offset+5+length]
        
        message = GRPCMessage(
            compressed=compressed,
            length=length,
            data=message_data,
            direction='unknown'
        )
        
        return (message, 5 + length)
    
    def parse_grpc_stream(self, data: bytes, direction: str = 'request') -> List[GRPCMessage]:
        """Parse multiple gRPC messages from a stream.
        
        Args:
            data: Raw bytes from HTTP/2 data frames
            direction: 'request' or 'response'
            
        Returns:
            List of GRPCMessage objects
        """
        messages = []
        offset = 0
        
        while offset < len(data):
            result = self.parse_grpc_message(data, offset)
            if not result:
                break
            
            message, consumed = result
            message.direction = direction
            messages.append(message)
            offset += consumed
        
        return messages
    
    def extract_grpc_path(self, http_headers: Dict[str, str]) -> Optional[Tuple[str, str]]:
        """Extract service and method from gRPC path.
        
        gRPC path format: /{service}/{method}
        
        Returns:
            Tuple of (service, method) or None
        """
        path = http_headers.get(':path', '')
        if not path or path.count('/') < 2:
            return None
        
        parts = path.strip('/').split('/')
        if len(parts) >= 2:
            return (parts[0], parts[1])
        
        return None
    
    def detect_call_type(self, messages: List[GRPCMessage]) -> str:
        """Detect gRPC call type based on message patterns.
        
        Returns:
            'unary', 'server_stream', 'client_stream', or 'bidi_stream'
        """
        requests = [m for m in messages if m.direction == 'request']
        responses = [m for m in messages if m.direction == 'response']
        
        if len(requests) == 1 and len(responses) == 1:
            return 'unary'
        elif len(requests) == 1 and len(responses) > 1:
            return 'server_stream'
        elif len(requests) > 1 and len(responses) == 1:
            return 'client_stream'
        elif len(requests) > 1 and len(responses) > 1:
            return 'bidi_stream'
        else:
            return 'unknown'
    
    def analyze_grpc_traffic(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyze gRPC traffic from packets.
        
        Args:
            packets: List of Scapy packets (HTTP/2 over TCP)
            
        Returns:
            Dict with gRPC analysis
        """
        # This is a simplified implementation
        # Real implementation would need full HTTP/2 parsing
        
        calls = []
        
        try:
            from scapy.all import TCP, Raw  # type: ignore
        except ImportError:
            return {'error': 'Scapy not available'}
        
        for pkt in packets:
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                continue
            
            payload = bytes(pkt[Raw].load)
            
            # Look for gRPC magic bytes and HTTP/2 patterns
            if b'grpc' in payload.lower() or b'application/grpc' in payload.lower():
                # Try to parse gRPC messages
                messages = self.parse_grpc_stream(payload)
                if messages:
                    # Decode Protobuf fields in each message
                    for msg in messages:
                        msg_fields = self.protobuf_decoder.decode_message(msg.data)
                        # Store decoded fields (simplified)
        
        return {
            'total_calls': len(self.calls),
            'calls': [c.to_dict() for c in self.calls[:20]],
            'services': list(set(c.service for c in self.calls)),
            'methods': list(set(c.method for c in self.calls))
        }
    
    def decode_protobuf_message(self, data: bytes) -> Dict[str, Any]:
        """Decode a Protobuf message without schema.
        
        Returns:
            Dict with decoded fields
        """
        fields = self.protobuf_decoder.decode_message(data)
        return {
            'field_count': len(fields),
            'fields': fields
        }
