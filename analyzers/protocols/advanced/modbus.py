"""Modbus and industrial protocol decoders.

Decodes ICS/SCADA protocols:
- Modbus TCP
- Modbus RTU (serial)
- Function code analysis
- Register and coil operations
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
import struct


@dataclass
class ModbusPacket:
    """Represents a decoded Modbus packet."""
    transaction_id: Optional[int]  # TCP only
    protocol_id: Optional[int]  # TCP only
    unit_id: int
    function_code: int
    function_name: str
    data: bytes
    is_exception: bool = False
    exception_code: Optional[int] = None
    
    # Parsed data fields
    start_address: Optional[int] = None
    quantity: Optional[int] = None
    values: Optional[List[int]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'unit_id': self.unit_id,
            'function_code': self.function_code,
            'function_name': self.function_name,
            'is_exception': self.is_exception
        }
        
        if self.transaction_id is not None:
            result['transaction_id'] = self.transaction_id
        if self.protocol_id is not None:
            result['protocol_id'] = self.protocol_id
        if self.exception_code is not None:
            result['exception_code'] = self.exception_code
        if self.start_address is not None:
            result['start_address'] = self.start_address
        if self.quantity is not None:
            result['quantity'] = self.quantity
        if self.values is not None:
            result['values'] = self.values[:20]  # Limit for display
        
        return result


class ModbusDecoder:
    """Decode Modbus TCP and RTU protocols."""
    
    FUNCTION_CODES = {
        1: 'Read Coils',
        2: 'Read Discrete Inputs',
        3: 'Read Holding Registers',
        4: 'Read Input Registers',
        5: 'Write Single Coil',
        6: 'Write Single Register',
        15: 'Write Multiple Coils',
        16: 'Write Multiple Registers',
        23: 'Read/Write Multiple Registers',
        43: 'Read Device Identification'
    }
    
    EXCEPTION_CODES = {
        1: 'Illegal Function',
        2: 'Illegal Data Address',
        3: 'Illegal Data Value',
        4: 'Server Device Failure',
        5: 'Acknowledge',
        6: 'Server Device Busy',
        8: 'Memory Parity Error',
        10: 'Gateway Path Unavailable',
        11: 'Gateway Target Device Failed to Respond'
    }
    
    def __init__(self):
        self.packets: List[ModbusPacket] = []
        self.operations: Dict[str, int] = {}  # function_name -> count
    
    def calculate_crc16(self, data: bytes) -> int:
        """Calculate Modbus RTU CRC-16.
        
        Args:
            data: Bytes to calculate CRC for
            
        Returns:
            CRC-16 value
        """
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc
    
    def parse_read_request(self, data: bytes) -> Tuple[Optional[int], Optional[int]]:
        """Parse read request (functions 1-4).
        
        Returns:
            Tuple of (start_address, quantity) or (None, None)
        """
        if len(data) < 4:
            return (None, None)
        
        start_address = struct.unpack('!H', data[0:2])[0]
        quantity = struct.unpack('!H', data[2:4])[0]
        return (start_address, quantity)
    
    def parse_write_single_request(self, data: bytes) -> Tuple[Optional[int], Optional[int]]:
        """Parse write single coil/register request (functions 5-6).
        
        Returns:
            Tuple of (address, value) or (None, None)
        """
        if len(data) < 4:
            return (None, None)
        
        address = struct.unpack('!H', data[0:2])[0]
        value = struct.unpack('!H', data[2:4])[0]
        return (address, value)
    
    def parse_write_multiple_request(self, data: bytes) -> Tuple[Optional[int], Optional[int], Optional[List[int]]]:
        """Parse write multiple coils/registers request (functions 15-16).
        
        Returns:
            Tuple of (start_address, quantity, values) or (None, None, None)
        """
        if len(data) < 5:
            return (None, None, None)
        
        start_address = struct.unpack('!H', data[0:2])[0]
        quantity = struct.unpack('!H', data[2:4])[0]
        byte_count = data[4]
        
        if len(data) < 5 + byte_count:
            return (None, None, None)
        
        values = []
        for i in range(5, 5 + byte_count, 2):
            if i + 1 < len(data):
                values.append(struct.unpack('!H', data[i:i+2])[0])
        
        return (start_address, quantity, values)
    
    def decode_modbus_tcp(self, data: bytes, offset: int = 0) -> Optional[Tuple[ModbusPacket, int]]:
        """Decode Modbus TCP packet.
        
        Modbus TCP header:
        - 2 bytes: Transaction ID
        - 2 bytes: Protocol ID (0x0000)
        - 2 bytes: Length
        - 1 byte: Unit ID
        - N bytes: PDU (function code + data)
        
        Returns:
            Tuple of (ModbusPacket, bytes_consumed) or None
        """
        if len(data) - offset < 8:
            return None  # Minimum header size
        
        # Parse MBAP header
        transaction_id = struct.unpack('!H', data[offset:offset+2])[0]
        protocol_id = struct.unpack('!H', data[offset+2:offset+4])[0]
        length = struct.unpack('!H', data[offset+4:offset+6])[0]
        unit_id = data[offset+6]
        
        # Validate protocol ID
        if protocol_id != 0:
            return None
        
        # Check if we have complete PDU
        if len(data) - offset - 7 < length - 1:
            return None
        
        # Parse PDU
        function_code = data[offset+7]
        is_exception = bool(function_code & 0x80)
        
        if is_exception:
            # Exception response
            actual_function = function_code & 0x7F
            exception_code = data[offset+8] if len(data) > offset+8 else 0
            
            packet = ModbusPacket(
                transaction_id=transaction_id,
                protocol_id=protocol_id,
                unit_id=unit_id,
                function_code=actual_function,
                function_name=self.FUNCTION_CODES.get(actual_function, f'Unknown_{actual_function}'),
                data=b'',
                is_exception=True,
                exception_code=exception_code
            )
            
            return (packet, 7 + length)
        
        # Normal request/response
        pdu_data = data[offset+8:offset+7+length]
        
        packet = ModbusPacket(
            transaction_id=transaction_id,
            protocol_id=protocol_id,
            unit_id=unit_id,
            function_code=function_code,
            function_name=self.FUNCTION_CODES.get(function_code, f'Unknown_{function_code}'),
            data=pdu_data
        )
        
        # Parse function-specific data
        if function_code in [1, 2, 3, 4]:  # Read operations
            packet.start_address, packet.quantity = self.parse_read_request(pdu_data)
        elif function_code in [5, 6]:  # Write single
            addr, val = self.parse_write_single_request(pdu_data)
            packet.start_address = addr
            packet.values = [val] if val is not None else None
        elif function_code in [15, 16]:  # Write multiple
            packet.start_address, packet.quantity, packet.values = self.parse_write_multiple_request(pdu_data)
        
        # Track operation
        self.operations[packet.function_name] = self.operations.get(packet.function_name, 0) + 1
        
        return (packet, 7 + length)
    
    def decode_modbus_rtu(self, data: bytes, offset: int = 0) -> Optional[Tuple[ModbusPacket, int]]:
        """Decode Modbus RTU packet.
        
        Modbus RTU format:
        - 1 byte: Unit ID
        - 1 byte: Function code
        - N bytes: Data
        - 2 bytes: CRC-16
        
        Returns:
            Tuple of (ModbusPacket, bytes_consumed) or None
        """
        if len(data) - offset < 4:
            return None  # Minimum packet size
        
        # Try to find packet boundaries using CRC
        # This is simplified; real implementation needs more robust framing
        
        unit_id = data[offset]
        function_code = data[offset+1]
        is_exception = bool(function_code & 0x80)
        
        # Estimate packet size based on function code
        # This is a heuristic approach
        estimated_size = 8  # Default estimate
        
        if offset + estimated_size + 2 > len(data):
            estimated_size = len(data) - offset - 2
        
        if estimated_size < 2:
            return None
        
        pdu_data = data[offset+2:offset+estimated_size]
        expected_crc = self.calculate_crc16(data[offset:offset+estimated_size])
        
        if offset + estimated_size + 2 <= len(data):
            actual_crc = struct.unpack('<H', data[offset+estimated_size:offset+estimated_size+2])[0]
            if actual_crc != expected_crc:
                return None  # CRC mismatch
        
        packet = ModbusPacket(
            transaction_id=None,
            protocol_id=None,
            unit_id=unit_id,
            function_code=function_code & 0x7F,
            function_name=self.FUNCTION_CODES.get(function_code & 0x7F, f'Unknown_{function_code & 0x7F}'),
            data=pdu_data,
            is_exception=is_exception
        )
        
        return (packet, estimated_size + 2)
    
    def decode_stream(self, data: bytes, protocol: str = 'tcp') -> List[ModbusPacket]:
        """Decode multiple Modbus packets from a stream.
        
        Args:
            data: Raw bytes
            protocol: 'tcp' or 'rtu'
            
        Returns:
            List of ModbusPacket objects
        """
        packets = []
        offset = 0
        
        decode_func = self.decode_modbus_tcp if protocol == 'tcp' else self.decode_modbus_rtu
        
        while offset < len(data):
            result = decode_func(data, offset)
            if not result:
                break
            
            packet, consumed = result
            packets.append(packet)
            offset += consumed
        
        self.packets.extend(packets)
        return packets
    
    def analyze_modbus_traffic(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyze Modbus traffic from packet list.
        
        Args:
            packets: List of Scapy packets
            
        Returns:
            Dict with Modbus traffic analysis
        """
        try:
            from scapy.all import TCP, Raw  # type: ignore
        except ImportError:
            return {'error': 'Scapy not available'}
        
        all_modbus_packets = []
        
        for pkt in packets:
            if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
                continue
            
            # Modbus TCP typically uses port 502
            if pkt[TCP].sport != 502 and pkt[TCP].dport != 502:
                continue
            
            payload = bytes(pkt[Raw].load)
            modbus_packets = self.decode_stream(payload, protocol='tcp')
            all_modbus_packets.extend(modbus_packets)
        
        # Statistics
        reads = sum(1 for p in all_modbus_packets if p.function_code in [1, 2, 3, 4])
        writes = sum(1 for p in all_modbus_packets if p.function_code in [5, 6, 15, 16])
        exceptions = sum(1 for p in all_modbus_packets if p.is_exception)
        
        # Unique units
        units = list(set(p.unit_id for p in all_modbus_packets))
        
        return {
            'total_packets': len(all_modbus_packets),
            'operations': dict(self.operations),
            'reads': reads,
            'writes': writes,
            'exceptions': exceptions,
            'unique_units': units,
            'packets': [p.to_dict() for p in all_modbus_packets[:50]]
        }
