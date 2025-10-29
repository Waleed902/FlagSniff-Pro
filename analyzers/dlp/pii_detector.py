"""
Data Loss Prevention (DLP) - PII Detector
- Email, SSN, Credit Card detection with Luhn validation
- Scans Raw payloads for matches
"""

from typing import Dict, List, Any
from scapy.all import Raw
import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b")
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _luhn_check(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits[:-1]):
        if i % 2 == parity:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return (checksum + digits[-1]) % 10 == 0


def analyze_dlp(packets: List) -> Dict[str, Any]:
    findings = {'emails': [], 'ssns': [], 'credit_cards': []}
    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        data = bytes(pkt[Raw].load)
        text = None
        try:
            text = data.decode('utf-8', errors='ignore')
        except Exception:
            continue
        for m in EMAIL_RE.findall(text):
            findings['emails'].append(m)
        for m in SSN_RE.findall(text):
            findings['ssns'].append(m)
        for m in CC_RE.findall(text):
            if _luhn_check(m):
                findings['credit_cards'].append(m)
    # Deduplicate
    for k in list(findings.keys()):
        findings[k] = sorted(list(set(findings[k])))
    findings['summary'] = {
        'email_count': len(findings['emails']),
        'ssn_count': len(findings['ssns']),
        'cc_count': len(findings['credit_cards'])
    }
    return findings
