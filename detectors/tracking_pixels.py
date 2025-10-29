"""
Tracking pixel detection and token extraction utilities.

Pure-Python implementation with BeautifulSoup when available and
regex fallback when not installed. Designed to be defensive and
side-effect free. Does not fetch remote content.
"""
from typing import List, Dict, Any, Tuple, Optional

import re
from urllib.parse import urlparse, parse_qs, unquote


def _try_import_bs4():
    try:
        from bs4 import BeautifulSoup  # type: ignore
        return BeautifulSoup
    except Exception:
        return None


def _safe_b64_decode(s: str) -> Optional[str]:
    import base64
    try:
        s2 = s.strip()
        # URL-safe to standard
        s2 = s2.replace('-', '+').replace('_', '/')
        s2 += '=' * (-len(s2) % 4)
        return base64.b64decode(s2).decode('utf-8', errors='replace')
    except Exception:
        return None


def _safe_hex_decode(s: str) -> Optional[str]:
    try:
        if all(c in '0123456789abcdefABCDEF' for c in s) and len(s) % 2 == 0:
            return bytes.fromhex(s).decode('utf-8', errors='replace')
    except Exception:
        return None
    return None


def _is_css_hidden(style: str) -> bool:
    s = (style or '').lower()
    return any(k in s for k in ['display:none', 'visibility:hidden', 'opacity:0'])


def _looks_like_1x1(width: Optional[str], height: Optional[str], style: str) -> bool:
    # accept numeric attributes or style hints
    try:
        if width is not None and height is not None:
            w = int(re.sub(r'[^0-9]', '', str(width))) if re.search(r'\d', str(width)) else None
            h = int(re.sub(r'[^0-9]', '', str(height))) if re.search(r'\d', str(height)) else None
            if w == 1 and h == 1:
                return True
    except Exception:
        pass

    s = (style or '').lower()
    if 'width:1px' in s and 'height:1px' in s:
        return True
    return False


def _looks_like_tracker_path(path: str) -> bool:
    p = (path or '').lower()
    return any(t in p for t in ['/pixel', '/beacon', '/open.gif', '/track', '/tracker', 'pixel.gif'])


def _extract_img_tags_regex(html: str) -> List[Dict[str, Any]]:
    # Simple regex fallback if BeautifulSoup is not available
    tags = []
    try:
        for m in re.finditer(r'<img\b[^>]*>', html, flags=re.IGNORECASE):
            tag = m.group(0)
            def attr(name: str) -> Optional[str]:
                am = re.search(rf'{name}\s*=\s*(["\"])?(?P<val>[^>\s"\"]+|[^>]*?)\1', tag, flags=re.IGNORECASE)
                return am.group('val') if am else None
            tags.append({
                'src': attr('src'),
                'width': attr('width'),
                'height': attr('height'),
                'style': attr('style') or ''
            })
    except Exception:
        pass
    return tags


def extract_pixels(html: str) -> List[Dict[str, Any]]:
    """
    Extract candidate tracking pixels from HTML.
    Returns list of dicts with keys:
      - src, host, path, query, params (dict)
      - hints: {is_1x1, css_hidden, tracker_path}
      - tokens: [{'name','raw','decoded'}]
    """
    pixels: List[Dict[str, Any]] = []
    if not html:
        return pixels

    BS = _try_import_bs4()
    img_elems: List[Dict[str, Any]] = []
    if BS is not None:
        try:
            soup = BS(html, 'html.parser')
            for img in soup.find_all('img'):
                img_elems.append({
                    'src': img.get('src'),
                    'width': img.get('width'),
                    'height': img.get('height'),
                    'style': img.get('style') or ''
                })
        except Exception:
            # fall back to regex if parsing fails
            img_elems = _extract_img_tags_regex(html)
    else:
        img_elems = _extract_img_tags_regex(html)

    for img in img_elems:
        src = img.get('src')
        if not src:
            continue
        try:
            parsed = urlparse(src)
        except Exception:
            # attempt to unquote and retry
            try:
                parsed = urlparse(unquote(src))
            except Exception:
                continue

        q = parse_qs(parsed.query)
        style = img.get('style') or ''
        is_1x1 = _looks_like_1x1(img.get('width'), img.get('height'), style)
        is_hidden = _is_css_hidden(style)
        trackerish = _looks_like_tracker_path(parsed.path or '')

        # extract token-like params
        token_names = {'id', 'token', 'uid', 'uid64', 'track', 'p', 'part', 'seq'}
        tokens: List[Dict[str, Any]] = []
        for k, vals in q.items():
            if not vals:
                continue
            v = vals[0]
            if k.lower() in token_names or re.match(r'^(?:id|tok|u(?:id)?|p|part|seq)[0-9_]*$', k, re.I):
                decoded = _safe_b64_decode(v) or _safe_hex_decode(v) or unquote(v)
                tokens.append({'name': k, 'raw': v, 'decoded': decoded if decoded != v else None})

        pixels.append({
            'src': src,
            'host': parsed.netloc,
            'path': parsed.path,
            'query': parsed.query,
            'params': q,
            'hints': {
                'is_1x1': bool(is_1x1),
                'css_hidden': bool(is_hidden),
                'tracker_path': bool(trackerish)
            },
            'tokens': tokens
        })

    return pixels


def reconstruct_sequences(pixels: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Reconstruct ordered token sequences from pixel params.
    Groups by (host, path) and orders by integer p/part/seq if present.
    Returns list of dicts: {'group': (host,path), 'joined': str, 'pieces': [...]}.
    """
    if not pixels:
        return []

    from collections import defaultdict

    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for px in pixels:
        groups[(px.get('host') or '', px.get('path') or '')].append(px)

    results: List[Dict[str, Any]] = []
    for key, arr in groups.items():
        # build items with order key
        items: List[Tuple[int, str]] = []
        for px in arr:
            params = px.get('params') or {}
            order = None
            for k in ('p', 'part', 'seq'):
                if k in params and params[k]:
                    try:
                        order = int(re.sub(r'[^0-9]', '', str(params[k][0])))
                    except Exception:
                        order = None
                    break
            # choose one token param to include per pixel (heuristic: id/token/uid)
            chosen = None
            for name in ('id', 'token', 'uid', 'uid64'):
                if name in params and params[name]:
                    chosen = params[name][0]
                    break
            if chosen is None and params:
                # fallback to first param value
                first_key = next(iter(params))
                chosen = params[first_key][0]
            if chosen is None:
                continue
            # decode chosen
            decoded = _safe_b64_decode(chosen) or _safe_hex_decode(chosen) or unquote(chosen)
            text = decoded if decoded and any(c.isprintable() for c in decoded) else chosen
            items.append((order if order is not None else 10**9, text))

        if not items:
            continue
        items.sort(key=lambda x: x[0])
        joined = ''.join([t for _, t in items])
        results.append({'group': {'host': key[0], 'path': key[1]}, 'joined': joined, 'pieces': [t for _, t in items]})

    return results


def reconstruct_sequences_relaxed(pixels: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Relaxed reconstruction that tolerates alternating hosts/CDNs.

    Strategy:
    - Group primarily by path and base domain (last 2 labels) if available; fallback to path only.
    - Preserve original encounter order from the input list.
    - Choose the same token heuristic as reconstruct_sequences (id/token/uid/uid64, else first param).
    """
    if not pixels:
        return []

    import itertools

    def base_domain(host: str) -> str:
        if not host:
            return ''
        parts = host.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host

    def choose_token(params: Dict[str, List[str]]) -> Optional[str]:
        if not params:
            return None
        for name in ('id', 'token', 'uid', 'uid64'):
            if name in params and params[name]:
                return params[name][0]
        # fallback to first param value
        try:
            k = next(iter(params))
            return params[k][0]
        except Exception:
            return None

    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for idx, px in enumerate(pixels):
        bd = base_domain(px.get('host') or '')
        path = px.get('path') or ''
        key = (bd, path)
        groups.setdefault(key, []).append({'idx': idx, **px})

    results: List[Dict[str, Any]] = []
    for key, arr in groups.items():
        items: List[str] = []
        # original encounter order preserved by arr order
        for obj in arr:
            params = obj.get('params') or {}
            chosen = choose_token(params)
            if chosen is None:
                continue
            decoded = _safe_b64_decode(chosen) or _safe_hex_decode(chosen) or unquote(chosen)
            text = decoded if decoded and any(c.isprintable() for c in decoded) else chosen
            items.append(text)
        if len(items) >= 2:
            joined = ''.join(items)
            results.append({'group': {'base_domain': key[0], 'path': key[1]}, 'joined': joined, 'pieces': list(items)})

    # If nothing found, try a final pass grouping by path only
    if not results:
        by_path: Dict[str, List[Dict[str, Any]]] = {}
        for idx, px in enumerate(pixels):
            p = px.get('path') or ''
            by_path.setdefault(p, []).append({'idx': idx, **px})
        for path, arr in by_path.items():
            items: List[str] = []
            for obj in arr:
                params = obj.get('params') or {}
                chosen = choose_token(params)
                if chosen is None:
                    continue
                decoded = _safe_b64_decode(chosen) or _safe_hex_decode(chosen) or unquote(chosen)
                text = decoded if decoded and any(c.isprintable() for c in decoded) else chosen
                items.append(text)
            if len(items) >= 2:
                results.append({'group': {'path': path}, 'joined': ''.join(items), 'pieces': list(items)})

    return results
