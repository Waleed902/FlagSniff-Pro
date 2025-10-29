# utils/filters.py

import re

def apply_display_filter(packets, filter_expression):
    """
    Applies a Wireshark-like display filter to a list of packets.
    """
    if not filter_expression:
        return packets

    filtered_packets = []

    # Simple parser for expressions like "ip.addr == 1.2.3.4", "tcp.port == 80"
    match = re.match(r'(\w+\.\w+)\s*==\s*(\S+)', filter_expression)
    if not match:
        # For now, if the filter is not recognized, return all packets
        return packets

    field, value = match.groups()

    for packet in packets:
        try:
            if field == 'ip.addr':
                if packet.haslayer('IP') and (packet['IP'].src == value or packet['IP'].dst == value):
                    filtered_packets.append(packet)
            elif field == 'tcp.port':
                if packet.haslayer('TCP') and (packet['TCP'].sport == int(value) or packet['TCP'].dport == int(value)):
                    filtered_packets.append(packet)
            elif field == 'udp.port':
                if packet.haslayer('UDP') and (packet['UDP'].sport == int(value) or packet['UDP'].dport == int(value)):
                    filtered_packets.append(packet)
        except (ValueError, IndexError):
            # Ignore packets that don't have the specified field or have invalid values
            continue

    return filtered_packets
