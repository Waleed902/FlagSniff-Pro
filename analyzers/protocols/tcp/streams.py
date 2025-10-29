from __future__ import annotations

from typing import Any, Dict


def reconstruct_tcp_streams(packets) -> Dict[str, Any]:
    """Reconstruct TCP streams from packets (Scapy packets)."""
    from scapy.all import TCP, IP, Raw  # local import to avoid global dependency at import time
    streams = {}
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        # Use 4-tuple as stream key (handle both directions)
        key_fwd = (ip.src, tcp.sport, ip.dst, tcp.dport)
        key_rev = (ip.dst, tcp.dport, ip.src, tcp.sport)
        if key_fwd in streams:
            stream = streams[key_fwd]
        elif key_rev in streams:
            stream = streams[key_rev]
        else:
            stream = {
                'packets': [],
                'src_ip': ip.src,
                'src_port': tcp.sport,
                'dst_ip': ip.dst,
                'dst_port': tcp.dport,
                'protocol': 'TCP',
                'data': b'',
                'packet_indices': [],
                'http_requests': [],
                'http_responses': []
            }
            streams[key_fwd] = stream
        # Add packet to stream
        stream['packets'].append(pkt)
        stream['packet_indices'].append(i)
        # Append payload if present
        if pkt.haslayer(Raw):
            stream['data'] += pkt[Raw].load
    # Try to extract HTTP messages from streams
    for stream in streams.values():
        try:
            text = stream['data'].decode('utf-8', errors='ignore')
            # Split HTTP requests/responses
            http_msgs = text.split('\r\n\r\n')
            for msg in http_msgs:
                if msg.startswith(('GET', 'POST', 'PUT', 'DELETE')):
                    stream['http_requests'].append(msg)
                elif msg.startswith('HTTP/'):
                    stream['http_responses'].append(msg)
        except Exception:
            pass
    return streams
