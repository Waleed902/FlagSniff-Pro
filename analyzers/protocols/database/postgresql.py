# analyzers/protocols/database/postgresql.py

from scapy.all import *
import struct

def parse_postgresql_packet(payload):
    """
    Parses a PostgreSQL packet payload.
    """
    if len(payload) < 5:
        return None, None

    # Message type is the first byte
    message_type = chr(payload[0])
    # Length is a 4-byte integer (including self)
    length = int.from_bytes(payload[1:5], 'big')

    return message_type, length

def analyze_postgresql_traffic(packets):
    """
    Analyzes PostgreSQL traffic in a packet capture.
    """
    results = {
        'total_postgresql_packets': 0,
        'detected_queries': [],
        'ssl_requests': 0,
        'authentication_methods': [],
        'message_distribution': {},
    }

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw) and (packet[TCP].sport == 5432 or packet[TCP].dport == 5432):
            results['total_postgresql_packets'] += 1

            payload = packet[Raw].load
            message_type, length = parse_postgresql_packet(payload)

            if message_type:
                if message_type not in results['message_distribution']:
                    results['message_distribution'][message_type] = 0
                results['message_distribution'][message_type] += 1

                if message_type == 'Q': # Simple Query
                    # The query string is null-terminated
                    query = payload[5:5+length-5].decode('utf-8', 'ignore').strip('\x00')
                    results['detected_queries'].append(query)

    return results
