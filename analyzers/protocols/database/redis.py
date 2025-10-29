# analyzers/protocols/database/redis.py

from scapy.all import *

def parse_resp(payload):
    """
    A very basic RESP parser for Redis commands.
    """
    commands = []
    lines = payload.split(b'\r\n')

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(b'*'):
            # Array of bulk strings
            num_args = int(line[1:])
            for _ in range(num_args):
                i += 1
                if i < len(lines) and lines[i].startswith(b'$'):
                    i += 1
                    if i < len(lines):
                        commands.append(lines[i].decode('utf-8', 'ignore'))
        i += 1

    return commands

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
            commands = parse_resp(payload)
            results['detected_commands'].extend(commands)

    return results
