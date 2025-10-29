# analyzers/protocols/database/mysql.py

from scapy.all import *
import struct

def parse_mysql_packet(payload):
    """
    Parses a MySQL packet payload.
    """
    if len(payload) < 5:
        return None, None

    # MySQL packet header is 4 bytes: 3 bytes for length, 1 byte for sequence number
    packet_length = int.from_bytes(payload[0:3], 'little')
    sequence_id = payload[3]

    # The 5th byte is the command
    command = payload[4]

    return command, packet_length

def analyze_mysql_traffic(packets):
    """
    Analyzes MySQL traffic in a packet capture.
    """
    results = {
        'total_mysql_packets': 0,
        'detected_queries': [],
        'server_greetings': 0,
        'client_authentications': 0,
        'command_distribution': {},
    }

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw) and (packet[TCP].sport == 3306 or packet[TCP].dport == 3306):
            results['total_mysql_packets'] += 1

            payload = packet[Raw].load
            command, _ = parse_mysql_packet(payload)

            if command is not None:
                # Command codes can be found in MySQL documentation
                command_name = {
                    0x03: "COM_QUERY",
                    0x01: "COM_QUIT",
                    0x02: "COM_INIT_DB",
                }.get(command, f"Unknown (0x{command:02x})")

                if command_name not in results['command_distribution']:
                    results['command_distribution'][command_name] = 0
                results['command_distribution'][command_name] += 1

                if command_name == "COM_QUERY":
                    # The query string starts after the command byte
                    query = payload[5:].decode('utf-8', 'ignore')
                    results['detected_queries'].append(query)

    return results
