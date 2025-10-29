"""Flag reassembly utilities.

Extracted from WebPcapAnalyzer._reassemble_flag_chunks to enable reuse and testing.
"""
from typing import Any, Dict, List
import re


def reassemble_flag_chunks(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Reassemble flags across findings using bracket balancing and stream proximity.

    The algorithm scans findings in stream/packet order, buffering text once a
    start token is seen and tracking brace balance until a complete flag is formed.
    It also includes a fallback regex for single-finding complete flags.
    """
    start_tokens = ['flag{', 'CTF{', 'HTB{', 'DUCTF{', 'PICOCTF{', 'FLAG{']

    # Sort by stream and packet index
    def sort_key(f: Dict[str, Any]):
        return (f.get('stream_id') or '', f.get('packet_index', 0))

    sorted_findings = sorted(findings or [], key=sort_key)

    reassembled: List[Dict[str, Any]] = []
    buffer: Dict[str, Any] | None = None  # {'text': str, 'indices': [], 'stream': str, 'chunks': []}
    open_count = 0

    def flush_if_complete():
        nonlocal buffer, open_count
        if (
            buffer
            and open_count == 0
            and any((buffer.get('text') or '').startswith(t) for t in start_tokens)
            and (buffer.get('text') or '').endswith('}')
        ):
            flag_text = buffer.get('text') or ''
            if len(flag_text) >= 8 and ('{' in flag_text and '}'):
                reassembled.append({
                    'reassembled_flag': flag_text,
                    'flag_chunks': list(buffer.get('chunks') or []),
                    'packet_indices': list(buffer.get('indices') or []),
                    'stream_id': buffer.get('stream')
                })
            buffer = None
            open_count = 0

    for f in sorted_findings:
        text = str(f.get('data', ''))
        stream = f.get('stream_id')
        pkt_idx = f.get('packet_index', 0)

        # Start a new buffer if we see a start token
        if any(tok in text for tok in start_tokens):
            # Reset buffer if changing streams or too far apart
            if buffer and (buffer.get('stream') != stream or (pkt_idx - (buffer.get('indices') or [pkt_idx])[-1]) > 50):
                buffer = None
                open_count = 0
            positions = [text.find(tok) for tok in start_tokens]
            start_positions = [pos for pos in positions if pos != -1]
            start_pos = min(start_positions) if start_positions else -1
            candidate = text[start_pos:] if start_pos >= 0 else text
            if not buffer:
                buffer = {'text': '', 'indices': [], 'stream': stream, 'chunks': []}
                open_count = 0
            buffer['text'] += candidate
            buffer['indices'].append(pkt_idx)
            buffer['chunks'].append(candidate)
            open_count += candidate.count('{') - candidate.count('}')
            flush_if_complete()
            continue

        # If buffering, append subsequent text in same stream within proximity
        if buffer and buffer.get('stream') == stream and (pkt_idx - (buffer.get('indices') or [pkt_idx])[-1]) <= 50:
            if text:
                buffer['text'] += text
                buffer['indices'].append(pkt_idx)
                buffer['chunks'].append(text)
                open_count += text.count('{') - text.count('}')
                flush_if_complete()
            continue

        # Single finding complete flag fallback
        m = re.search(r'(?i)(flag|ctf|htb|ductf|picoctf)\{[^}]+\}', text)
        if m:
            reassembled.append({
                'reassembled_flag': m.group(0),
                'flag_chunks': [m.group(0)],
                'packet_indices': [pkt_idx],
                'stream_id': stream
            })

    return reassembled
