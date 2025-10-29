# analyzers/protocols/database/mongodb.py

from scapy.all import *
import struct

def parse_mongodb_header(payload):
    """
    Parses the MongoDB wire protocol header.
    """
    if len(payload) < 16:
        return None, None, None, None

    message_length, request_id, response_to, op_code = struct.unpack('<iiii', payload[:16])
    return message_length, request_id, response_to, op_code

def analyze_mongodb_traffic(packets):
    """
    Analyzes MongoDB traffic in a packet capture.
    """
    results = {
        'total_mongodb_packets': 0,
        'detected_queries': [],
        'opcodes': {},
    }

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw) and (packet[TCP].sport == 27017 or packet[TCP].dport == 27017):
            results['total_mongodb_packets'] += 1

            payload = packet[Raw].load
            _, _, _, op_code = parse_mongodb_header(payload)

            if op_code is not None:
                op_code_name = {
                    2004: "OP_QUERY",
                    2013: "OP_MSG",
                }.get(op_code, f"Unknown ({op_code})")

                if op_code_name not in results['opcodes']:
                    results['opcodes'][op_code_name] = 0
                results['opcodes'][op_code_name] += 1

    return results
