"""
Traffic Anomaly Detector (lightweight)
- Flow statistics aggregation (5-tuple)
- Median Absolute Deviation (MAD) outlier scoring
- Beaconing/C2 heuristic (low variance inter-arrival, fixed sizes)
"""

from typing import Dict, List, Any, Tuple
from scapy.all import IP, IPv6, TCP, UDP, Raw
from collections import defaultdict
import statistics
import math

FlowKey = Tuple[str, int, str, int, str]  # src, sport, dst, dport, proto


def _get_flow_key(pkt) -> FlowKey | None:
    if pkt.haslayer(IP):
        ip = pkt[IP]
        proto = 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else str(ip.proto)
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        return (ip.src, sport, ip.dst, dport, proto)
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        proto = 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else str(ip.nh)
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        return (ip.src, sport, ip.dst, dport, proto)
    return None


def _mad(values: List[float]) -> float:
    if not values:
        return 0.0
    med = statistics.median(values)
    deviations = [abs(v - med) for v in values]
    mad = statistics.median(deviations)
    # Consistent with standard deviation if normal (~1.4826 factor)
    return 1.4826 * mad


def _coef_variation(values: List[float]) -> float:
    if not values:
        return 0.0
    mean = statistics.mean(values)
    if mean == 0:
        return 0.0
    stdev = statistics.pstdev(values)
    return stdev / mean


def analyze_anomalies(packets: List) -> Dict[str, Any]:
    """
    Analyze packets for traffic anomalies using robust statistics.
    Returns a dict with outlier flows and beaconing detections.
    """
    flows: Dict[FlowKey, Dict[str, Any]] = defaultdict(lambda: {
        'bytes': 0, 'pkts': 0, 'sizes': [], 'times': [], 'inter_arrivals': []
    })

    # Aggregate
    for pkt in packets:
        key = _get_flow_key(pkt)
        if not key:
            continue
        meta = flows[key]
        size = len(pkt)
        t = float(getattr(pkt, 'time', 0.0))
        meta['bytes'] += size
        meta['pkts'] += 1
        meta['sizes'].append(size)
        meta['times'].append(t)

    # Compute inter-arrivals
    for meta in flows.values():
        times = sorted(meta['times'])
        meta['inter_arrivals'] = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 >= t1]

    # Outlier detection on bytes and packets using MAD
    bytes_list = [m['bytes'] for m in flows.values()]
    pkts_list = [m['pkts'] for m in flows.values()]
    bytes_med = statistics.median(bytes_list) if bytes_list else 0
    pkts_med = statistics.median(pkts_list) if pkts_list else 0
    bytes_mad = _mad(bytes_list)
    pkts_mad = _mad(pkts_list)

    def zscore_mad(v: float, med: float, mad: float) -> float:
        if mad == 0:
            return 0.0
        return abs(v - med) / mad

    outliers = []
    for key, meta in flows.items():
        b_z = zscore_mad(meta['bytes'], bytes_med, bytes_mad)
        p_z = zscore_mad(meta['pkts'], pkts_med, pkts_mad)
        if b_z > 6 or p_z > 6:  # conservative threshold
            outliers.append({
                'flow': key, 'bytes': meta['bytes'], 'pkts': meta['pkts'], 'b_z': round(b_z,2), 'p_z': round(p_z,2)
            })

    # Beaconing/C2 heuristics per flow
    beacons = []
    for key, meta in flows.items():
        ia = meta['inter_arrivals']
        sizes = meta['sizes']
        if len(ia) >= 5 and len(sizes) >= 6:
            cv = _coef_variation(ia)
            size_cv = _coef_variation(sizes)
            med_ia = statistics.median(ia) if ia else 0
            # beacon-like: very regular timings (cv<0.2) and small/constant sizes
            if cv < 0.2 and size_cv < 0.35 and med_ia > 1.0:
                beacons.append({
                    'flow': key,
                    'median_interval_s': round(med_ia, 3),
                    'interval_cv': round(cv, 3),
                    'size_cv': round(size_cv, 3),
                    'pkts': meta['pkts']
                })

    summary = {
        'total_flows': len(flows),
        'outlier_flows': outliers,
        'beacon_flows': beacons
    }

    return summary


def analyze_ml_anomalies(packets: List) -> Dict[str, Any]:
    """Public helper wrapper"""
    return analyze_anomalies(packets)
