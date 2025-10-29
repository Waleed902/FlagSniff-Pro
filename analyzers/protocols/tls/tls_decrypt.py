"""TLS decryption helpers using pyshark/tshark (optional).

Best-effort utilities; gracefully no-op if pyshark/tshark aren't available.
"""
from typing import Any, Dict, List, Tuple


def decrypt_tls_with_keylog(pcap_path: str, keylog_path: str) -> List[Dict[str, Any]]:
    """Use pyshark/tshark with a TLS key log file to decrypt TLS and extract plaintext.

    Returns a list of decoded items compatible with decoded_data structure, e.g.:
    {'type': 'tls_decrypted', 'protocol': 'HTTPS', 'result': <plaintext>, 'frame': <int>}
    """
    decoded: List[Dict[str, Any]] = []
    try:
        import pyshark  # type: ignore
    except Exception:
        # Pyshark not available; skip silently
        return decoded

    # Build custom parameters for tshark
    custom_params = [
        '-o', f'tls.keylog_file:{keylog_path}',
    ]

    try:
        cap = pyshark.FileCapture(
            pcap_path,
            display_filter='tls || http || http2',
            custom_parameters=custom_params,
            use_json=True
        )
    except Exception:
        # Could be no tshark installed or invalid keylog; return empty
        return decoded

    try:
        for pkt in cap:
            frame_no = None
            try:
                frame_no = int(getattr(pkt.frame_info, 'number', None)) if hasattr(pkt, 'frame_info') else None
            except Exception:
                frame_no = None

            plaintexts: List[Tuple[str, str]] = []  # (kind, content)

            if hasattr(pkt, 'http'):
                http = pkt.http
                if hasattr(http, 'request_full_uri'):
                    plaintexts.append(('http_request_uri', str(http.request_full_uri)))
                if hasattr(http, 'file_data'):
                    plaintexts.append(('http_file_data', str(http.file_data)))
                if hasattr(http, 'request_method') and hasattr(http, 'request_uri'):
                    line = f"{http.request_method} {http.request_uri}"
                    plaintexts.append(('http_request_line', line))
                if hasattr(http, 'response_code') and hasattr(http, 'response_phrase'):
                    line = f"HTTP {http.response_code} {http.response_phrase}"
                    plaintexts.append(('http_response_line', line))

            if hasattr(pkt, 'http2'):
                http2 = pkt.http2
                if hasattr(http2, 'header'):
                    plaintexts.append(('http2_header', str(http2.header)))
                if hasattr(http2, 'data'):
                    try:
                        d = str(http2.data)
                        if d and d != 'None':
                            plaintexts.append(('http2_data', d))
                    except Exception:
                        pass

            for kind, content in plaintexts:
                if not content:
                    continue
                decoded.append({
                    'type': 'tls_decrypted',
                    'protocol': 'HTTPS',
                    'result': content,
                    'frame': frame_no,
                    'source': kind,
                    'confidence': 0.9
                })
    finally:
        try:
            cap.close()
        except Exception:
            pass

    return decoded
