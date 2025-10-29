# utils/protocol_hierarchy.py

def get_protocol_hierarchy(packets):
    """
    Generates a protocol hierarchy from a list of packets.
    """
    hierarchy = {'name': 'root', 'children': [], 'value': 0}

    for packet in packets:
        current_level = hierarchy
        protocol_path = []
        layer = packet
        while layer:
            protocol_name = layer.name
            protocol_path.append(protocol_name)

            # Find or create the node for the current protocol
            node = next((child for child in current_level['children'] if child['name'] == protocol_name), None)
            if not node:
                node = {'name': protocol_name, 'children': [], 'value': 0}
                current_level['children'].append(node)

            node['value'] += 1
            current_level = node

            layer = layer.payload

    # Update total packets at the root
    hierarchy['value'] = len(packets)

    return hierarchy
