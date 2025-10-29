# analyzers/protocols/database/mssql.py

from scapy.all import *
import struct

def parse_tds_header(payload):
    """
    Parses the TDS (Tabular Data Stream) packet header.
    """
    if len(payload) < 8:
        return None, None, None, None

    # TDS header is 8 bytes
    packet_type, status, length, spid = struct.unpack('>BBHH', payload[:6])
    return packet_type, status, length, spid

def analyze_mssql_traffic(packets):
    """
    Analyzes MSSQL traffic in a packet capture.
    """
    results = {
        'total_mssql_packets': 0,
        'detected_queries': [],
        'prelogin_requests': 0,
        'login_requests': 0,
        'packet_type_distribution': {},
    }

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw) and (packet[TCP].sport == 1433 or packet[TCP].dport == 1433):
            results['total_mssql_packets'] += 1

            payload = packet[Raw].load
            packet_type, _, _, _ = parse_tds_header(payload)

            if packet_type is not None:
                packet_type_name = {
                    1: "SQL Batch",
                    2: "Pre-TDS7 Login",
                    4: "RPC",
                    16: "Login7",
                    18: "Pre-login",
                }.get(packet_type, f"Unknown ({packet_type})")

                if packet_type_name not in results['packet_type_distribution']:
                    results['packet_type_distribution'][packet_type_name] = 0
                results['packet_type_distribution'][packet_type_name] += 1

                if packet_type_name == "SQL Batch":
                    # The query is a Unicode string
                    query = payload[8:].decode('utf-16', 'ignore')
                    results['detected_queries'].append(query)

    return results
