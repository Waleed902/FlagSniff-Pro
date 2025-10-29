"""
Email/MIME extraction helpers for SMTP/IMAP/POP3 streams.

Best-effort parsing from raw TCP stream bytes using Python stdlib.
Falls back to simple heuristics when full messages are not contiguous.
"""
from typing import List, Dict, Any, Optional

import re
from email import message_from_bytes
from email.parser import BytesParser
from email.policy import default


MAIL_PORTS = {25, 465, 587, 110, 995, 143, 993}


def is_mail_port(port: Optional[int]) -> bool:
    try:
        return int(port) in MAIL_PORTS
    except Exception:
        return False


def _decode_part_payload(part) -> Optional[str]:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return None
        charset = part.get_content_charset() or 'utf-8'
        return payload.decode(charset, errors='ignore')
    except Exception:
        return None


def extract_html_parts_from_stream(stream_bytes: bytes) -> List[str]:
    """
    Attempt to extract text/html bodies from a raw SMTP/IMAP/POP3 TCP stream.
    Strategy:
      1) Try to parse entire buffer as one RFC822 message and walk parts.
      2) If none found, try to split by common SMTP end-of-data markers and parse chunks.
      3) As a last resort, regex-scan for 'Content-Type: text/html' sections and extract until next boundary.
    """
    htmls: List[str] = []
    if not stream_bytes:
        return htmls

    # Normalize dot-stuffing (SMTP): lines starting with '..' should be unstuffed to '.'
    try:
        # Only transform when we are within message content boundaries
        # Safe best-effort: replace CRLF.. -> CRLF.
        stream_bytes = re.sub(br"(\r\n)\.\.(?=[^\r\n])", br"\1.", stream_bytes)
    except Exception:
        pass

    # Approach 1: parse entire buffer
    try:
        msg = BytesParser(policy=default).parsebytes(stream_bytes)
        if msg:
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = (part.get_content_type() or '').lower()
                    if ctype == 'text/html':
                        text = _decode_part_payload(part)
                        if text:
                            htmls.append(text)
            else:
                ctype = (msg.get_content_type() or '').lower()
                if ctype == 'text/html':
                    text = _decode_part_payload(msg)
                    if text:
                        htmls.append(text)
    except Exception:
        pass

    if htmls:
        return htmls

    # Approach 2: split by SMTP end marker: CRLF . CRLF, and parse each chunk as a potential message
    try:
        chunks = re.split(br"\r\n\.\r\n", stream_bytes)
        for chunk in chunks:
            if not chunk:
                continue
            # Unwrap any remaining dot-stuffed lines in this chunk
            try:
                chunk = re.sub(br"(\r\n)\.\.(?=[^\r\n])", br"\1.", chunk)
            except Exception:
                pass
            try:
                m = BytesParser(policy=default).parsebytes(chunk)
                if not m:
                    continue
                if m.is_multipart():
                    for part in m.walk():
                        if (part.get_content_type() or '').lower() == 'text/html':
                            text = _decode_part_payload(part)
                            if text:
                                htmls.append(text)
                else:
                    if (m.get_content_type() or '').lower() == 'text/html':
                        text = _decode_part_payload(m)
                        if text:
                            htmls.append(text)
            except Exception:
                continue
    except Exception:
        pass

    if htmls:
        return htmls

    # Approach 3: regex scan for inline HTML parts, including boundary-aware extraction
    try:
        text = stream_bytes.decode('utf-8', errors='ignore')
        # Attempt to honor MIME boundaries if present in the stream
        boundary_match = re.search(r"boundary=\"?([^\";\r\n]+)\"?", text, re.IGNORECASE)
        boundary = boundary_match.group(1) if boundary_match else None
        if boundary:
            # Split by boundary lines
            parts = re.split(rf"\r?\n--{re.escape(boundary)}(?:--)?\r?\n", text)
            for p in parts:
                if not p:
                    continue
                if re.search(r"Content-Type:\s*text/html", p, re.IGNORECASE):
                    # Find blank line (headers/body separator)
                    m = re.search(r"\r?\n\r?\n([\s\S]+)$", p)
                    if m:
                        body = m.group(1)
                        if body and len(body) > 20:
                            htmls.append(body)
        else:
            # Fallback: find sections starting with Content-Type: text/html; capture until next Content-Type or boundary line
            pattern = re.compile(r"Content-Type:\s*text/html[\s\S]*?(?:\r?\n\r?\n)([\s\S]*?)(?=\r?\nContent-Type:|\r?\n--|$)", re.IGNORECASE)
            for m in pattern.finditer(text):
                body = m.group(1)
                if body and len(body) > 20:
                    htmls.append(body)
    except Exception:
        pass

    return htmls
