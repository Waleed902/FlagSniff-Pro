from __future__ import annotations

from typing import Any, Dict, List, Optional
import re as _re_pair


def pair_http_by_index(requests: List[str], responses: List[str]) -> List[Dict[str, Any]]:
    """Best-effort pairing of HTTP requests and responses by index.

    Extracts minimal fields from requests (host, path, ua, referer) and responses (content_length, content_type).
    Returns a list of dicts: { 'req': {...}, 'resp': {...} }
    """
    def _parse_host(req_text: str) -> Optional[str]:
        try:
            m = _re_pair.search(r"^Host:\s*([^\r\n]+)", req_text, _re_pair.IGNORECASE | _re_pair.MULTILINE)
            return m.group(1).strip() if m else None
        except Exception:
            return None

    def _parse_req_path(req_text: str) -> Optional[str]:
        try:
            m = _re_pair.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)", req_text)
            return m.group(2) if m else None
        except Exception:
            return None

    def _parse_resp(resp_text: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        try:
            cl_m = _re_pair.search(r"Content-Length:\s*(\d+)", resp_text, _re_pair.IGNORECASE)
            if cl_m:
                info['content_length'] = int(cl_m.group(1))
        except Exception:
            pass
        try:
            ct_m = _re_pair.search(r"Content-Type:\s*([^\r\n]+)", resp_text, _re_pair.IGNORECASE)
            if ct_m:
                info['content_type'] = ct_m.group(1).strip()
        except Exception:
            pass
        return info

    req_objs = []
    for msg in (requests or []):
        try:
            ua_m = _re_pair.search(r"^User-Agent:\s*([^\r\n]+)", msg, _re_pair.IGNORECASE | _re_pair.MULTILINE)
            ref_m = _re_pair.search(r"^Referer:\s*([^\r\n]+)", msg, _re_pair.IGNORECASE | _re_pair.MULTILINE)
            req_objs.append({
                'host': _parse_host(msg),
                'path': _parse_req_path(msg),
                'ua': ua_m.group(1).strip() if ua_m else None,
                'referer': ref_m.group(1).strip() if ref_m else None,
                'raw': msg
            })
        except Exception:
            req_objs.append({'raw': msg})

    resp_objs = []
    for rmsg in (responses or []):
        try:
            hdrs = _parse_resp(rmsg)
            resp_objs.append({'raw': rmsg, **hdrs})
        except Exception:
            resp_objs.append({'raw': rmsg})

    pairs: List[Dict[str, Any]] = []
    l = max(len(req_objs), len(resp_objs))
    for i in range(l):
        pairs.append({'req': req_objs[i] if i < len(req_objs) else None, 'resp': resp_objs[i] if i < len(resp_objs) else None})
    return pairs

# Backward-compatibility shim: use the new implementation
try:
    from analyzers.protocols.http.http_pairing import pair_http_by_index as _pair_http_by_index_new
    pair_http_by_index = _pair_http_by_index_new
except Exception:
    # If the new module isn't available, fall back to the local implementation above
    pass
