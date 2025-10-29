"""MQTT protocol decoder.

Decodes MQTT (Message Queuing Telemetry Transport) traffic:
- Packet type identification
- Topic extraction
- QoS level detection
- Publish/Subscribe pattern analysis
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
import struct


@dataclass
class MQTTPacket:
    """Represents a decoded MQTT packet."""
    packet_type: str
    flags: int
    remaining_length: int
    payload: bytes
    
    # Specific fields based on packet type
    topic: Optional[str] = None
    qos: Optional[int] = None
    retain: bool = False
    message_id: Optional[int] = None
    message: Optional[bytes] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'packet_type': self.packet_type,
            'flags': self.flags,
            'remaining_length': self.remaining_length
        }
        
        if self.topic:
            result['topic'] = self.topic
        if self.qos is not None:
            result['qos'] = self.qos
        if self.retain:
            result['retain'] = self.retain
        if self.message_id is not None:
            result['message_id'] = self.message_id
        if self.message:
            result['message_preview'] = self.message[:100].decode('utf-8', errors='replace')
        
        return result


class MQTTDecoder:
    """Decode MQTT protocol packets."""
    
    PACKET_TYPES = {
        1: 'CONNECT',
        2: 'CONNACK',
        3: 'PUBLISH',
        4: 'PUBACK',
        5: 'PUBREC',
        6: 'PUBREL',
        7: 'PUBCOMP',
        8: 'SUBSCRIBE',
        9: 'SUBACK',
        10: 'UNSUBSCRIBE',
        11: 'UNSUBACK',
        12: 'PINGREQ',
        13: 'PINGRESP',
        14: 'DISCONNECT'
    }
    
    def __init__(self):
        self.packets: List[MQTTPacket] = []
        self.topics: Dict[str, int] = {}  # topic -> message count
        self.subscriptions: List[str] = []
    
    def decode_remaining_length(self, data: bytes, offset: int) -> Optional[Tuple[int, int]]:
        """Decode MQTT variable length encoding.
        
        Returns:
            Tuple of (length, bytes_consumed) or None
        """
        multiplier = 1
        value = 0
        consumed = 0
        
        for i in range(offset, min(offset + 4, len(data))):
            byte = data[i]
            value += (byte & 0x7F) * multiplier
            consumed += 1
            
            if not (byte & 0x80):
                return (value, consumed)
            
            multiplier *= 128
        
        return None  # Invalid encoding
    
    def decode_string(self, data: bytes, offset: int) -> Optional[Tuple[str, int]]:
        """Decode MQTT UTF-8 string (2-byte length + string).
        
        Returns:
            Tuple of (string, bytes_consumed) or None
        """
        if len(data) - offset < 2:
            return None
        
        length = struct.unpack('!H', data[offset:offset+2])[0]
        if len(data) - offset - 2 < length:
            return None
        
        try:
            string = data[offset+2:offset+2+length].decode('utf-8')
            return (string, 2 + length)
        except:
            return None
    
    def parse_publish_packet(self, packet: MQTTPacket, data: bytes, offset: int) -> None:
        """Parse PUBLISH packet payload.
        
        Modifies packet in place with extracted fields.
        """
        # Extract QoS from flags
        packet.qos = (packet.flags >> 1) & 0x03
        packet.retain = bool(packet.flags & 0x01)
        
        # Decode topic
        topic_result = self.decode_string(data, offset)
        if not topic_result:
            return
        
        packet.topic, topic_size = topic_result
        current_offset = offset + topic_size
        
        # Decode message ID if QoS > 0
        if packet.qos > 0:
            if len(data) - current_offset < 2:
                return
            packet.message_id = struct.unpack('!H', data[current_offset:current_offset+2])[0]
            current_offset += 2
        
        # Remaining data is the message payload
        packet.message = data[current_offset:]
        
        # Track topic
        self.topics[packet.topic] = self.topics.get(packet.topic, 0) + 1
    
    def parse_subscribe_packet(self, packet: MQTTPacket, data: bytes, offset: int) -> None:
        """Parse SUBSCRIBE packet payload.
        
        Modifies packet in place with extracted subscriptions.
        """
        # Decode message ID
        if len(data) - offset < 2:
            return
        
        packet.message_id = struct.unpack('!H', data[offset:offset+2])[0]
        current_offset = offset + 2
        
        # Decode topic filters
        topics = []
        while current_offset < len(data):
            topic_result = self.decode_string(data, current_offset)
            if not topic_result:
                break
            
            topic, topic_size = topic_result
            current_offset += topic_size
            
            # QoS byte
            if current_offset < len(data):
                qos = data[current_offset]
                current_offset += 1
                topics.append({'topic': topic, 'qos': qos})
                self.subscriptions.append(topic)
        
        packet.payload = str(topics).encode()  # Store as string representation
    
    def parse_connect_packet(self, packet: MQTTPacket, data: bytes, offset: int) -> Dict[str, Any]:
        """Parse CONNECT packet payload.
        
        Returns:
            Dict with connection parameters
        """
        connect_info = {}
        
        # Protocol name
        proto_result = self.decode_string(data, offset)
        if not proto_result:
            return connect_info
        
        connect_info['protocol'], proto_size = proto_result
        current_offset = offset + proto_size
        
        # Protocol level
        if current_offset < len(data):
            connect_info['protocol_level'] = data[current_offset]
            current_offset += 1
        
        # Connect flags
        if current_offset < len(data):
            flags = data[current_offset]
            connect_info['clean_session'] = bool(flags & 0x02)
            connect_info['will_flag'] = bool(flags & 0x04)
            connect_info['will_qos'] = (flags >> 3) & 0x03
            connect_info['will_retain'] = bool(flags & 0x20)
            connect_info['password_flag'] = bool(flags & 0x40)
            connect_info['username_flag'] = bool(flags & 0x80)
            current_offset += 1
        
        # Keep alive
        if len(data) - current_offset >= 2:
            connect_info['keep_alive'] = struct.unpack('!H', data[current_offset:current_offset+2])[0]
            current_offset += 2
        
        # Client ID
        client_result = self.decode_string(data, current_offset)
        if client_result:
            connect_info['client_id'], _ = client_result
        
        return connect_info
    
    def decode_packet(self, data: bytes, offset: int = 0) -> Optional[Tuple[MQTTPacket, int]]:
        """Decode a single MQTT packet from bytes.
        
        Returns:
            Tuple of (MQTTPacket, bytes_consumed) or None
        """
        if len(data) - offset < 2:
            return None
        
        # Fixed header byte 1
        first_byte = data[offset]
        packet_type_code = (first_byte >> 4) & 0x0F
        flags = first_byte & 0x0F
        
        # Remaining length
        length_result = self.decode_remaining_length(data, offset + 1)
        if not length_result:
            return None
        
        remaining_length, length_size = length_result
        header_size = 1 + length_size
        
        # Check if we have the complete packet
        if len(data) - offset - header_size < remaining_length:
            return None
        
        payload = data[offset + header_size:offset + header_size + remaining_length]
        
        packet = MQTTPacket(
            packet_type=self.PACKET_TYPES.get(packet_type_code, f'UNKNOWN_{packet_type_code}'),
            flags=flags,
            remaining_length=remaining_length,
            payload=payload
        )
        
        # Parse specific packet types
        if packet_type_code == 3:  # PUBLISH
            self.parse_publish_packet(packet, data, offset + header_size)
        elif packet_type_code == 8:  # SUBSCRIBE
            self.parse_subscribe_packet(packet, data, offset + header_size)
        elif packet_type_code == 1:  # CONNECT
            connect_info = self.parse_connect_packet(packet, data, offset + header_size)
            packet.payload = str(connect_info).encode()
        
        bytes_consumed = header_size + remaining_length
        return (packet, bytes_consumed)
    
    def decode_stream(self, data: bytes) -> List[MQTTPacket]:
        """Decode multiple MQTT packets from a byte stream.
        
        Returns:
            List of MQTTPacket objects
        """
        packets = []
        offset = 0
        
        while offset < len(data):
            result = self.decode_packet(data, offset)
            if not result:
                break
            
            packet, consumed = result
            packets.append(packet)
            offset += consumed
        
        self.packets.extend(packets)
        return packets
    
    def analyze_mqtt_traffic(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyze MQTT traffic from packet list.
        
        Args:
            packets: List of Scapy packets
            
        Returns:
            Dict with MQTT traffic analysis
        """
        try:
            from scapy.all import TCP, Raw  # type: ignore
        except ImportError:
            return {'error': 'Scapy not available'}
        
        all_mqtt_packets = []
        
        for pkt in packets:
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                continue
            
            # MQTT typically uses port 1883 (or 8883 for TLS)
            if pkt[TCP].sport not in [1883, 8883] and pkt[TCP].dport not in [1883, 8883]:
                continue
            
            payload = bytes(pkt[Raw].load)
            mqtt_packets = self.decode_stream(payload)
            all_mqtt_packets.extend(mqtt_packets)
        
        # Statistics
        packet_type_counts = {}
        for pkt in all_mqtt_packets:
            packet_type_counts[pkt.packet_type] = packet_type_counts.get(pkt.packet_type, 0) + 1
        
        qos_levels = {}
        for pkt in all_mqtt_packets:
            if pkt.qos is not None:
                qos_levels[pkt.qos] = qos_levels.get(pkt.qos, 0) + 1
        
        return {
            'total_packets': len(all_mqtt_packets),
            'packet_types': packet_type_counts,
            'topics': dict(self.topics),
            'subscriptions': list(set(self.subscriptions)),
            'qos_levels': qos_levels,
            'packets': [p.to_dict() for p in all_mqtt_packets[:50]]
        }
