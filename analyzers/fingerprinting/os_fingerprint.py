"""
Passive OS Fingerprinting (heuristic)
- Initial TTL mapping (Windows ~128, Linux ~64, Network devices ~255)
- TCP options presence/order, window size heuristics
"""

from typing import Dict, List, Any
from scapy.all import IP, IPv6, TCP
from collections import defaultdict


class OSFingerprinter:
    def __init__(self):
        self.host_samples = defaultdict(list)  # ip -> list of observations

    def _ttl_guess(self, ttl: int) -> str:
        # Map observed TTL to most likely initial TTL
        # We round up to nearest known base and infer OS
        if ttl >= 200:
            return 'network_device_or_bsd'  # initial 255
        if ttl >= 100:
            return 'windows'  # initial 128
        if ttl >= 60:
            return 'linux_unix'  # initial 64
        return 'unknown'

    def analyze_packet(self, pkt):
        ip = None
        ttl = None
        if pkt.haslayer(IP):
            ip = pkt[IP]
            ttl = int(ip.ttl)
            src = ip.src
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            # IPv6 Hop Limit ~64 typically
            ttl = int(ip6.hlim)
            src = ip6.src
        else:
            return

        tcp_opts = []
        wscale = None
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if tcp.options:
                for k, v in tcp.options:
                    tcp_opts.append(k)
                    if k == 'WScale':
                        wscale = v
        self.host_samples[src].append({'ttl': ttl, 'tcp_opts': tcp_opts, 'wscale': wscale, 'win': getattr(pkt[TCP], 'window', None) if pkt.haslayer(TCP) else None})

    def summarize(self) -> Dict[str, Any]:
        results = {}
        for host, samples in self.host_samples.items():
            if not samples:
                continue
            avg_ttl = sum(s['ttl'] for s in samples) / len(samples)
            guess = self._ttl_guess(int(avg_ttl))
            # Common TCP option signatures
            sigs = ['-'.join(s['tcp_opts']) for s in samples if s['tcp_opts']]
            common_sig = None
            if sigs:
                from collections import Counter
                common_sig = Counter(sigs).most_common(1)[0][0]
            results[host] = {
                'avg_ttl': round(avg_ttl, 1),
                'os_guess': guess,
                'common_tcp_option_signature': common_sig
            }
        return results


def analyze_os_fingerprints(packets: List) -> Dict[str, Any]:
    f = OSFingerprinter()
    for p in packets:
        f.analyze_packet(p)
    return f.summarize()
