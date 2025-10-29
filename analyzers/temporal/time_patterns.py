"""
Time-Based Pattern Analysis
- Periodicity via autocorrelation peak detection
- Burstiness (B = (sigma - mu) / (sigma + mu))
- Sleep/jitter cycles (long idle gaps then bursts)
- Timeline aggregation into buckets
"""

from typing import Dict, List, Any, Tuple
from scapy.all import IP, IPv6, TCP, UDP
from collections import defaultdict
import statistics

FlowKey = Tuple[str, int, str, int, str]


def _flow_key(pkt) -> FlowKey | None:
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


def _autocorr(series: List[float], max_lag: int) -> List[float]:
    n = len(series)
    if n == 0:
        return []
    mean = statistics.mean(series)
    var = statistics.pvariance(series) if n > 1 else 0.0
    if var == 0:
        return [0.0]* (max_lag+1)
    corr = []
    for lag in range(0, max_lag+1):
        cov = 0.0
        for i in range(n - lag):
            cov += (series[i] - mean) * (series[i + lag] - mean)
        corr.append(cov / ((n - lag) * var) if (n - lag) > 0 else 0.0)
    return corr


def _burstiness(counts: List[int]) -> float:
    if not counts:
        return 0.0
    mu = statistics.mean(counts)
    if mu == 0:
        return 0.0
    sigma = statistics.pstdev(counts)
    return (sigma - mu) / (sigma + mu) if (sigma + mu) != 0 else 0.0


def analyze_time_patterns(packets: List, bucket_seconds: int = 60) -> Dict[str, Any]:
    """
    Compute global and per-flow time-based patterns.
    Returns autocorrelation peaks, burstiness, sleep cycles, and timeline.
    """
    times = [float(getattr(p, 'time', 0.0)) for p in packets]
    if not times:
        return {'timeline': [], 'global': {}, 'per_flow': {}}

    start = min(times)
    end = max(times)
    duration = max(1.0, end - start)

    # Timeline buckets (global)
    bucket_count = max(1, int(duration // bucket_seconds) + 1)
    timeline = [0] * bucket_count
    for t in times:
        idx = int((t - start) // bucket_seconds)
        if 0 <= idx < bucket_count:
            timeline[idx] += 1

    # Global metrics
    auto = _autocorr(timeline, min(120, bucket_count - 1))  # up to 120 lags
    peaks = []
    for lag in range(1, len(auto) - 1):
        if auto[lag] > auto[lag - 1] and auto[lag] > auto[lag + 1] and auto[lag] > 0.3:
            peaks.append({'lag_buckets': lag, 'period_seconds': lag * bucket_seconds, 'corr': round(auto[lag], 3)})
    global_burstiness = round(_burstiness(timeline), 3)

    # Sleep cycles: detect long gaps
    gaps = []
    times_sorted = sorted(times)
    for t1, t2 in zip(times_sorted, times_sorted[1:]):
        gap = t2 - t1
        if gap >= 3600:  # 1 hour idle
            gaps.append({'gap_seconds': round(gap, 1), 'from': t1, 'to': t2})

    # Per-flow analysis (top N by packets to keep work bounded)
    from collections import Counter
    flow_keys = []
    for p in packets:
        k = _flow_key(p)
        if k:
            flow_keys.append(k)
    top_flows = [k for k, _ in Counter(flow_keys).most_common(50)]

    per_flow = {}
    for k in top_flows:
        flow_times = [float(getattr(p, 'time', 0.0)) for p in packets if _flow_key(p) == k]
        if len(flow_times) < 3:
            continue
        # bucketize per flow
        f_timeline = [0] * bucket_count
        for t in flow_times:
            idx = int((t - start) // bucket_seconds)
            if 0 <= idx < bucket_count:
                f_timeline[idx] += 1
        f_auto = _autocorr(f_timeline, min(60, bucket_count - 1))
        f_peaks = []
        for lag in range(1, len(f_auto) - 1):
            if f_auto[lag] > f_auto[lag - 1] and f_auto[lag] > f_auto[lag + 1] and f_auto[lag] > 0.4:
                f_peaks.append({'lag_buckets': lag, 'period_seconds': lag * bucket_seconds, 'corr': round(f_auto[lag], 3)})
        per_flow[str(k)] = {
            'burstiness': round(_burstiness(f_timeline), 3),
            'periodicity': f_peaks
        }

    return {
        'timeline': timeline,
        'global': {
            'duration_seconds': round(duration, 1),
            'bucket_seconds': bucket_seconds,
            'periodicity_peaks': peaks,
            'burstiness': global_burstiness,
            'sleep_gaps': gaps
        },
        'per_flow': per_flow
    }
