# utils/filters.py

import re

def _evaluate_condition(packet, condition):
    """
    Evaluates a single filter condition against a packet.
    """
    condition = condition.strip()

    # Protocol filter
    if re.fullmatch(r'\w+', condition):
        return packet.haslayer(condition.upper())

    # Field-based filter
    match = re.match(r'(\w+\.\w+)\s*==\s*(\S+)', condition)
    if not match:
        return False

    field, value = match.groups()

    try:
        if field == 'ip.addr':
            return packet.haslayer('IP') and (packet['IP'].src == value or packet['IP'].dst == value)
        elif field == 'tcp.port':
            return packet.haslayer('TCP') and (packet['TCP'].sport == int(value) or packet['TCP'].dport == int(value))
        elif field == 'udp.port':
            return packet.haslayer('UDP') and (packet['UDP'].sport == int(value) or packet['UDP'].dport == int(value))
    except (ValueError, IndexError):
        return False

    return False

def apply_display_filter(packets, filter_expression):
    """
    Applies a Wireshark-like display filter to a list of packets.
    """
    if not filter_expression:
        return packets

    filtered_packets = []

    # Split by ||
    or_parts = filter_expression.split('||')

    for packet in packets:
        for or_part in or_parts:
            # Split by &&
            and_parts = or_part.split('&&')

            if all(_evaluate_condition(packet, and_part) for and_part in and_parts):
                filtered_packets.append(packet)
                break # Move to the next packet if any OR condition is met

    return filtered_packets
