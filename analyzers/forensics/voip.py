"""Forensics: VoIP helpers (RTP/SIP) for audio extraction and call summarization.

All functions are defensive and return plain dicts/lists.
Dependencies like scapy are used lazily to avoid hard failures in minimal envs.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def extract_voip_audio_from_sessions(sessions: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan sessions for RTP payloads and return basic audio blobs and metadata.

    Each entry includes: session_id, codec, sample_rate, channels, packets,
    duration_ms, payload_type, raw_audio (bounded), raw_size, src_ip, dst_ip.
    """
    out: List[Dict[str, Any]] = []
    if not isinstance(sessions, dict):
        return out
    # Lazy import to tolerate environments without scapy RTP
    try:
        from scapy.all import RTP  # type: ignore
    except Exception:
        return out

    MAX_AUDIO_SIZE = 1024 * 1024  # 1MB cap
    for sid, s in sessions.items():
        try:
            if not isinstance(s, dict):
                continue
            pkts = s.get('packets') or []
            rtp_list: List[Dict[str, Any]] = []
            for p in pkts:
                try:
                    if getattr(p, 'haslayer', lambda *_: False)(RTP):
                        r = p[RTP]
                        rtp_list.append({
                            'timestamp': getattr(r, 'timestamp', 0),
                            'sequence': getattr(r, 'sequence', 0),
                            'payload_type': getattr(r, 'payload_type', 0),
                            'payload': bytes(getattr(r, 'payload', b'')) if hasattr(r, 'payload') else b'',
                            'marker': bool(getattr(r, 'marker', 0)),
                        })
                except Exception:
                    continue
            if not rtp_list:
                continue
            # Group by payload type
            by_pt: Dict[int, List[Dict[str, Any]]] = {}
            for e in rtp_list:
                by_pt.setdefault(int(e.get('payload_type', 0)), []).append(e)
            for pt, arr in by_pt.items():
                try:
                    arr.sort(key=lambda x: x.get('sequence', 0))
                    combined = b''
                    for e in arr:
                        if len(combined) + len(e.get('payload', b'')) > MAX_AUDIO_SIZE:
                            break
                        combined += e.get('payload', b'')
                    codec = {
                        0: {'name': 'PCMU', 'rate': 8000, 'channels': 1},
                        8: {'name': 'PCMA', 'rate': 8000, 'channels': 1},
                        3: {'name': 'GSM', 'rate': 8000, 'channels': 1},
                        9: {'name': 'G722', 'rate': 16000, 'channels': 1},
                        18: {'name': 'G729', 'rate': 8000, 'channels': 1},
                    }.get(int(pt), {'name': f'Unknown-{pt}', 'rate': 8000, 'channels': 1})
                    duration_ms = 0
                    try:
                        if arr:
                            duration_ms = (arr[-1]['timestamp'] - arr[0]['timestamp']) / max(1, codec['rate']) * 1000
                    except Exception:
                        duration_ms = 0
                    out.append({
                        'session_id': sid,
                        'src_ip': s.get('src', '') or s.get('src_ip', ''),
                        'dst_ip': s.get('dst', '') or s.get('dst_ip', ''),
                        'codec': codec['name'],
                        'sample_rate': codec['rate'],
                        'channels': codec['channels'],
                        'packets': len(arr),
                        'duration_ms': duration_ms,
                        'payload_type': int(pt),
                        'raw_audio': combined if len(combined) <= MAX_AUDIO_SIZE else None,
                        'raw_size': len(combined),
                    })
                except Exception:
                    continue
        except Exception:
            continue
    return out


def detect_sip_sessions(packets: List[Any]) -> List[Dict[str, Any]]:
    """Best-effort SIP session hints from packet payloads.

    Returns list of dicts: call_id, from, to, method, packet_index.
    """
    out: List[Dict[str, Any]] = []
    if not packets:
        return out
    try:
        import re
        from scapy.all import Raw, TCP, UDP  # type: ignore
    except Exception:
        return out
    for i, pkt in enumerate(packets or []):
        try:
            if not (pkt.haslayer(Raw) and (pkt.haslayer(UDP) or pkt.haslayer(TCP))):
                continue
            data = bytes(pkt[Raw].load)
            text = data.decode('utf-8', errors='ignore')
            if 'SIP/2.0' not in text and not text.startswith(('INVITE ', 'REGISTER ', 'BYE ', 'ACK ', 'CANCEL ')):
                continue
            call_id = None
            m = re.search(r'Call-ID:\s*([^\r\n]+)', text, re.IGNORECASE)
            if m:
                call_id = m.group(1).strip()
            from_ = None
            m = re.search(r'From:\s*([^\r\n]+)', text, re.IGNORECASE)
            if m:
                from_ = m.group(1).strip()
            to_ = None
            m = re.search(r'To:\s*([^\r\n]+)', text, re.IGNORECASE)
            if m:
                to_ = m.group(1).strip()
            method = None
            m = re.match(r'^(INVITE|REGISTER|BYE|ACK|CANCEL|OPTIONS|INFO|PRACK|SUBSCRIBE|NOTIFY|UPDATE)\b', text)
            if m:
                method = m.group(1)
            out.append({'packet_index': i, 'call_id': call_id, 'from': from_, 'to': to_, 'method': method})
        except Exception:
            continue
    return out


def reconstruct_voip_calls(sessions: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Skeleton call reconstruction from session map (placeholder, non-destructive)."""
    out: List[Dict[str, Any]] = []
    if not isinstance(sessions, dict):
        return out
    # Minimal grouping: one entry per src/dst pair with packet counts
    for sid, s in sessions.items():
        try:
            if not isinstance(s, dict):
                continue
            proto = (s.get('protocol') or '').upper()
            if 'SIP' in proto or 'UDP' in proto or 'TCP' in proto:
                out.append({
                    'session_id': sid,
                    'src_ip': s.get('src', '') or s.get('src_ip', ''),
                    'dst_ip': s.get('dst', '') or s.get('dst_ip', ''),
                    'packet_count': len(s.get('packets', [])),
                    'notes': 'Heuristic entry; full call graph TBD.'
                })
        except Exception:
            continue
    return out
