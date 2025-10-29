# analyzers/protocols/database/redis.py

from scapy.all import *

class RespParser:
    def __init__(self, payload):
        self.payload = payload
        self.index = 0

    def parse(self):
        if not self.payload:
            return None
        return self._parse_value()

    def _parse_value(self):
        if self.index >= len(self.payload):
            return None

        data_type = chr(self.payload[self.index])
        self.index += 1

        if data_type == '+': # Simple String
            return self._parse_simple_string()
        elif data_type == '-': # Error
            return self._parse_error()
        elif data_type == ':': # Integer
            return self._parse_integer()
        elif data_type == '$': # Bulk String
            return self._parse_bulk_string()
        elif data_type == '*': # Array
            return self._parse_array()
        else:
            return None

    def _read_line(self):
        end_index = self.payload.find(b'\r\n', self.index)
        if end_index == -1:
            return None
        line = self.payload[self.index:end_index]
        self.index = end_index + 2
        return line

    def _parse_simple_string(self):
        return self._read_line().decode('utf-8', 'ignore')

    def _parse_error(self):
        return f"Error: {self._read_line().decode('utf-8', 'ignore')}"

    def _parse_integer(self):
        return int(self._read_line())

    def _parse_bulk_string(self):
        length = int(self._read_line())
        if length == -1:
            return None
        data = self.payload[self.index:self.index + length]
        self.index += length + 2 # +2 for \r\n
        return data.decode('utf-8', 'ignore')

    def _parse_array(self):
        num_elements = int(self._read_line())
        if num_elements == -1:
            return None
        return [self._parse_value() for _ in range(num_elements)]

def analyze_redis_traffic(packets):
    """
    Analyzes Redis traffic in a packet capture.
    """
    results = {
        'total_redis_packets': 0,
        'detected_commands': [],
    }

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw) and (packet[TCP].sport == 6379 or packet[TCP].dport == 6379):
            results['total_redis_packets'] += 1

            payload = packet[Raw].load
            parser = RespParser(payload)
            command = parser.parse()
            if command:
                results['detected_commands'].append(command)

    return results
