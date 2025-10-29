"""Suspicious packet heuristics.

Extracted from WebPcapAnalyzer._identify_suspicious_packets for reuse and tests.
"""
from typing import Any, Dict, List
import re


def identify_suspicious_packets(packet_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify suspicious packets for further investigation.

    Returns a list of dicts with keys: packet_index, protocol, src_ip, dst_ip,
    reasons (list[str]), data_preview.
    """
    suspicious_packets: List[Dict[str, Any]] = []

    for packet in packet_data_list or []:
        # Skip if no data
        if not packet.get('data'):
            continue

        data = packet.get('data', '')
        is_suspicious = False
        reasons: List[str] = []

        # Check for unusual HTTP methods
        if packet.get('protocol') == 'HTTP' and 'http_headers' in packet:
            headers = packet['http_headers']
            if re.search(r'^(PUT|DELETE|TRACE|CONNECT|OPTIONS|PATCH)', headers):
                is_suspicious = True
                reasons.append("Unusual HTTP method")

        # Check for potential command injection
        if re.search(r'[;|`]\s*[a-zA-Z]+', data):
            is_suspicious = True
            reasons.append("Potential command injection")

        # Check for potential SQL injection
        if re.search(r"['\"\-]\s*OR\s*['\"\-]|UNION\s+SELECT|INSERT\s+INTO|DROP\s+TABLE", data, re.IGNORECASE):
            is_suspicious = True
            reasons.append("Potential SQL injection")

        # Check for potential XSS
        if re.search(r'<script>|javascript:|onerror=|onload=', data, re.IGNORECASE):
            is_suspicious = True
            reasons.append("Potential XSS")

        # Check for base64 executable content
        if re.search(r'TVqQAAMAAAAEAAAA', data) or re.search(r'UEsDBBQAA', data):
            is_suspicious = True
            reasons.append("Base64 encoded executable")

        # Check for potential CTF flags
        if re.search(r'flag\{[^}]+\}|CTF\{[^}]+\}|HTB\{[^}]+\}', data, re.IGNORECASE):
            is_suspicious = True
            reasons.append("Contains potential flag format")

        # Add to suspicious packets if any checks triggered
        if is_suspicious:
            suspicious_packets.append({
                'packet_index': packet.get('packet_index'),
                'protocol': packet.get('protocol', 'Unknown'),
                'src_ip': packet.get('src', ''),
                'dst_ip': packet.get('dst', ''),
                'reasons': reasons,
                'data_preview': (data[:100] + '...') if len(data) > 100 else data
            })

    return suspicious_packets
