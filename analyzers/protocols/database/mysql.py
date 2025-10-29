# analyzers/protocols/database/mysql.py

from scapy.all import *
import struct

def parse_mysql_packet(payload):
    """
    Parses a MySQL packet payload.
    """
    if len(payload) < 5:
        return None, None, None

    # MySQL packet header is 4 bytes: 3 bytes for length, 1 byte for sequence number
    packet_length = int.from_bytes(payload[0:3], 'little')
    sequence_id = payload[3]

    # The 5th byte is the packet type indicator
    packet_type = payload[4]

    return packet_type, packet_length, sequence_id

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
        'responses': [],
    }

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw) and (packet[TCP].sport == 3306 or packet[TCP].dport == 3306):
            results['total_mysql_packets'] += 1

            payload = packet[Raw].load
            packet_type, _, _ = parse_mysql_packet(payload)

            if packet_type is not None:
                # Server greeting (sent on initial connection)
                if packet[TCP].sport == 3306 and packet_type == 0x0a:
                    results['server_greetings'] += 1

                # Client authentication
                elif packet[TCP].dport == 3306 and len(payload) > 36:
                    results['client_authentications'] += 1

                # Command phase
                elif packet[TCP].dport == 3306:
                    command_name = {
                        0x00: "COM_SLEEP", 0x01: "COM_QUIT", 0x02: "COM_INIT_DB", 0x03: "COM_QUERY",
                        0x04: "COM_FIELD_LIST", 0x05: "COM_CREATE_DB", 0x06: "COM_DROP_DB",
                        0x07: "COM_REFRESH", 0x08: "COM_SHUTDOWN", 0x09: "COM_STATISTICS",
                        0x0a: "COM_PROCESS_INFO", 0x0b: "COM_CONNECT", 0x0c: "COM_PROCESS_KILL",
                        0x0d: "COM_DEBUG", 0x0e: "COM_PING", 0x0f: "COM_TIME", 0x10: "COM_DELAYED_INSERT",
                        0x11: "COM_CHANGE_USER", 0x12: "COM_BINLOG_DUMP", 0x13: "COM_TABLE_DUMP",
                        0x14: "COM_CONNECT_OUT", 0x15: "COM_REGISTER_SLAVE", 0x16: "COM_STMT_PREPARE",
                        0x17: "COM_STMT_EXECUTE", 0x18: "COM_STMT_SEND_LONG_DATA", 0x19: "COM_STMT_CLOSE",
                        0x1a: "COM_STMT_RESET", 0x1b: "COM_SET_OPTION", 0x1c: "COM_STMT_FETCH",
                    }.get(packet_type, f"Unknown (0x{packet_type:02x})")

                    if command_name not in results['command_distribution']:
                        results['command_distribution'][command_name] = 0
                    results['command_distribution'][command_name] += 1

                    if command_name == "COM_QUERY":
                        query = payload[5:].decode('utf-8', 'ignore')
                        results['detected_queries'].append(query)

                # Response phase
                elif packet[TCP].sport == 3306:
                    if packet_type == 0x00: # OK_Packet
                        results['responses'].append({'type': 'OK'})
                    elif packet_type == 0xff: # ERR_Packet
                        error_message = payload[9:].decode('utf-8', 'ignore')
                        results['responses'].append({'type': 'Error', 'message': error_message})

    return results
