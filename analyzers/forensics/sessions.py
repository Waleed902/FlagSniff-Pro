"""Forensics: session builders and summarizers."""
from __future__ import annotations

from typing import Dict, Any, List
from datetime import datetime


def build_sessions(packets: List[Any]) -> Dict[str, Any]:
    """Group packets into basic protocol sessions.

    Returns a dict keyed by session id with lightweight summaries. Defensive
    against malformed inputs.
    """
    try:
        from scapy.all import IP, TCP, UDP, Raw  # type: ignore
    except Exception:  # scapy may not be available at import time
        IP = TCP = UDP = Raw = None  # type: ignore

    sessions: Dict[str, Any] = {
        'http': {},
        'ftp': {},
        'smtp': {},
        'irc': {},
        'ssh': {},
        'telnet': {},
        'dns': {},
        'tcp_generic': {},
        'udp_generic': {},
    }

    for i, pkt in enumerate(packets or []):
        try:
            if IP is None or not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            ts = getattr(pkt, 'time', None) or datetime.now().timestamp()

            if TCP and pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                key = f"{ip.src}:{pkt[TCP].sport}-{ip.dst}:{pkt[TCP].dport}"
                s = sessions['http'].setdefault(key, {
                    'requests': [], 'responses': [], 'start_time': ts, 'end_time': ts,
                    'src_ip': ip.src, 'src_port': pkt[TCP].sport, 'dst_ip': ip.dst, 'dst_port': pkt[TCP].dport
                })
                if Raw and pkt.haslayer(Raw):
                    raw = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if raw.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD')):
                        s['requests'].append({'timestamp': ts, 'data': raw, 'packet_index': i})
                    elif raw.startswith('HTTP/'):
                        s['responses'].append({'timestamp': ts, 'data': raw, 'packet_index': i})
                s['end_time'] = ts
                continue

            if TCP and pkt.haslayer(TCP) and (pkt[TCP].dport == 21 or pkt[TCP].sport == 21):
                key = f"{ip.src}:{pkt[TCP].sport}-{ip.dst}:{pkt[TCP].dport}"
                s = sessions['ftp'].setdefault(key, {
                    'commands': [], 'responses': [], 'start_time': ts, 'end_time': ts,
                    'src_ip': ip.src, 'src_port': pkt[TCP].sport, 'dst_ip': ip.dst, 'dst_port': pkt[TCP].dport
                })
                if Raw and pkt.haslayer(Raw):
                    raw = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if raw.startswith(('USER', 'PASS', 'LIST', 'RETR', 'STOR', 'QUIT')):
                        s['commands'].append({'timestamp': ts, 'data': raw, 'packet_index': i})
                    elif raw.startswith(('220', '331', '230', '226', '221')):
                        s['responses'].append({'timestamp': ts, 'data': raw, 'packet_index': i})
                s['end_time'] = ts
                continue

            if TCP and pkt.haslayer(TCP) and (pkt[TCP].dport == 22 or pkt[TCP].sport == 22):
                key = f"{ip.src}:{pkt[TCP].sport}-{ip.dst}:{pkt[TCP].dport}"
                s = sessions['ssh'].setdefault(key, {
                    'messages': [], 'start_time': ts, 'end_time': ts,
                    'src_ip': ip.src, 'src_port': pkt[TCP].sport, 'dst_ip': ip.dst, 'dst_port': pkt[TCP].dport
                })
                if Raw and pkt.haslayer(Raw):
                    raw = pkt[Raw].load.decode('utf-8', errors='ignore')
                    s['messages'].append({'timestamp': ts, 'data': raw, 'packet_index': i})
                s['end_time'] = ts
                continue

            if TCP and pkt.haslayer(TCP):
                key = f"{ip.src}:{pkt[TCP].sport}-{ip.dst}:{pkt[TCP].dport}"
                s = sessions['tcp_generic'].setdefault(key, {
                    'packets': [], 'start_time': ts, 'end_time': ts,
                    'src_ip': ip.src, 'src_port': pkt[TCP].sport, 'dst_ip': ip.dst, 'dst_port': pkt[TCP].dport
                })
                s['packets'].append({'timestamp': ts, 'packet_index': i, 'data': pkt[Raw].load if Raw and pkt.haslayer(Raw) else b''})
                s['end_time'] = ts
                continue

            if UDP and pkt.haslayer(UDP):
                key = f"{ip.src}:{pkt[UDP].sport}-{ip.dst}:{pkt[UDP].dport}"
                s = sessions['udp_generic'].setdefault(key, {
                    'packets': [], 'start_time': ts, 'end_time': ts,
                    'src_ip': ip.src, 'src_port': pkt[UDP].sport, 'dst_ip': ip.dst, 'dst_port': pkt[UDP].dport
                })
                s['packets'].append({'timestamp': ts, 'packet_index': i, 'data': pkt[Raw].load if Raw and pkt.haslayer(Raw) else b''})
                s['end_time'] = ts
                continue
        except Exception:
            continue

    return sessions
