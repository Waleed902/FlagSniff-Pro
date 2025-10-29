from __future__ import annotations

from typing import Any, Dict, List, Optional
import base64
import binascii


def detect_dns_exfiltration(packet_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect and reconstruct DNS exfiltration chunks from dns_query labels.

    Heuristics:
    - Group queries by src->dst and base domain (last 2-3 labels)
    - Concatenate left-most labels that look like encoded chunks
    - Attempt base64, base32, and hex decoding
    - Return decoded items suitable for decoded_data list
    """
    decoded_items: List[Dict[str, Any]] = []
    try:
        import re
        from collections import defaultdict

        def base_domain(q: str) -> str:
            parts = q.strip('.').split('.')
            if len(parts) >= 3:
                return '.'.join(parts[-3:])
            elif len(parts) >= 2:
                return '.'.join(parts[-2:])
            return q

        groups = defaultdict(list)
        for pd in (packet_data_list or []):
            if (pd.get('protocol') == 'DNS' or pd.get('protocol') == 'DNS-TUNNEL') and pd.get('dns_query'):
                q = str(pd.get('dns_query', '')).lower()
                src = pd.get('src'); dst = pd.get('dst')
                key = (src, dst, base_domain(q))
                groups[key].append(pd)

        # regex for chunk-like label
        chunk_re = re.compile(r'^[a-z0-9+/=_-]{6,}$')

        def try_decodes(s: str) -> Optional[str]:
            s_clean = s.replace('-', '+').replace('_', '/')
            # Try base64 with padding fix
            try:
                b = s_clean
                pad = (-len(b)) % 4
                b += '=' * pad
                return base64.b64decode(b, validate=False).decode('utf-8', errors='ignore')
            except Exception:
                pass
            # Try hex
            try:
                if all(c in '0123456789abcdef' for c in s.lower()):
                    return binascii.unhexlify(s).decode('utf-8', errors='ignore')
            except Exception:
                pass
            # Try base32
            try:
                return base64.b32decode(s.upper()).decode('utf-8', errors='ignore')
            except Exception:
                pass
            return None

        for key, items in groups.items():
            # Preserve original order
            buffer = []
            indices = []
            for pd in items:
                q = str(pd.get('dns_query', '')).strip('.')
                labels = q.split('.')
                # Use left labels (excluding base domain) as potential chunks
                if len(labels) > 2:
                    candidate_labels = labels[:-2]
                else:
                    candidate_labels = labels[:-1]

                # strip numeric-only sublabels often used as counters
                chunk_parts = [l for l in candidate_labels if chunk_re.match(l) and not l.isdigit()]
                if not chunk_parts:
                    continue
                chunk = ''.join(chunk_parts)
                if len(chunk) < 6:
                    continue
                buffer.append(chunk)
                indices.append(pd.get('packet_index'))

            if not buffer:
                continue

            joined = ''.join(buffer)
            decoded = try_decodes(joined)
            if decoded and decoded.strip():
                decoded_items.append({
                    'type': 'dns_exfil',
                    'protocol': 'DNS',
                    'result': decoded,
                    'chain': ['dns_exfil'],
                    'packet_index': indices[0] if indices else -1,
                    'confidence': 0.9,
                    'original_type': 'dns_labels_joined'
                })

    except Exception:
        # Best-effort; ignore errors
        pass

    return decoded_items

# Backward-compatibility shim: use the new implementation
try:
    from analyzers.protocols.dns.dns_exfil import detect_dns_exfiltration as _detect_dns_exfiltration_new
    detect_dns_exfiltration = _detect_dns_exfiltration_new
except Exception:
    # If the new module isn't available, fall back to the local implementation above
    pass
