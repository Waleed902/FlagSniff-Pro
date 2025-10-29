# utils/io_graphs.py

from collections import defaultdict

def generate_io_graph_data(packets):
    """
    Generates data for IO graphs (packets/second and bytes/second).
    """
    packets_per_second = defaultdict(int)
    bytes_per_second = defaultdict(int)

    if not packets:
        return {'packets_per_second': [], 'bytes_per_second': []}

    start_time = packets[0].time

    for packet in packets:
        # Round the timestamp to the nearest second
        timestamp = int(packet.time - start_time)
        packets_per_second[timestamp] += 1
        bytes_per_second[timestamp] += len(packet)

    # Convert to a list of dictionaries for easier plotting
    pps_data = [{'time': t, 'packets': c} for t, c in packets_per_second.items()]
    bps_data = [{'time': t, 'bytes': c} for t, c in bytes_per_second.items()]

    return {
        'packets_per_second': sorted(pps_data, key=lambda x: x['time']),
        'bytes_per_second': sorted(bps_data, key=lambda x: x['time']),
    }
