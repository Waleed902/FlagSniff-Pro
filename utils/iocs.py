"""
IOC extraction utilities: extract IPs, domains, URLs, emails, hashes from analysis results.
"""

from typing import Dict, Any, List, Tuple
import re
import os
import json
import csv
import tempfile


def _valid_ipv4(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    text = text or ""
    findings: Dict[str, List[str]] = {
        'urls': [],
        'domains': [],
        'ips': [],
        'emails': [],
        'hashes': [],
    }

    try:
        # URLs
        for m in re.findall(r"https?://[^\s\"'<>]+", text, re.IGNORECASE):
            if m not in findings['urls']:
                findings['urls'].append(m)

        # Emails
        for m in re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
            if m not in findings['emails']:
                findings['emails'].append(m)

        # IPv4s
        for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            if _valid_ipv4(m) and m not in findings['ips']:
                findings['ips'].append(m)

        # Domains (avoid capturing plain IPs)
        for m in re.findall(r"\b([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}\b", text):
            if m not in findings['domains']:
                findings['domains'].append(m)

        # Hashes
        for m in re.findall(r"\b[0-9a-fA-F]{32}\b", text):
            if m.lower() not in [h.lower() for h in findings['hashes']]:
                findings['hashes'].append(m)
        for m in re.findall(r"\b[0-9a-fA-F]{40}\b", text):
            if m.lower() not in [h.lower() for h in findings['hashes']]:
                findings['hashes'].append(m)
        for m in re.findall(r"\b[0-9a-fA-F]{64}\b", text):
            if m.lower() not in [h.lower() for h in findings['hashes']]:
                findings['hashes'].append(m)
    except Exception:
        pass

    return findings


def extract_from_results(results: Dict[str, Any]) -> Dict[str, List[str]]:
    agg: Dict[str, List[str]] = {
        'urls': [], 'domains': [], 'ips': [], 'emails': [], 'hashes': []
    }

    def _merge(d: Dict[str, List[str]]):
        for k, vals in (d or {}).items():
            for v in (vals or []):
                if v not in agg[k]:
                    agg[k].append(v)

    # Scan findings
    for f in (results.get('findings') or []):
        txts = [
            str(f.get('data','')),
            str(f.get('decoded','')),
            str(f.get('context','')),
            str(f.get('stream_data','')),
        ]
        for t in txts:
            _merge(extract_iocs_from_text(t))

    # Scan decoded data
    for d in (results.get('decoded_data') or []):
        txts = [
            str(d.get('decoded') or d.get('result') or ''),
            str(d.get('original','')),
        ]
        for t in txts:
            _merge(extract_iocs_from_text(t))

    # Scan TLS SNI and DNS queries if present
    for s in (results.get('reconstructed_streams') or {}).values():
        hostish = [str(s.get('sni','')), str(s.get('host',''))]
        for t in hostish:
            _merge(extract_iocs_from_text(t))

    for f in (results.get('protocol_details') or []):
        _merge(extract_iocs_from_text(str(f.get('summary',''))))

    return agg


def export_iocs(iocs: Dict[str, List[str]]) -> Dict[str, Any]:
    """Export IOCs to JSON and CSV in temp dir; return paths and basic stats."""
    out: Dict[str, Any] = {'success': True, 'files': {}, 'counts': {k: len(v) for k, v in (iocs or {}).items()}}
    try:
        tmp = tempfile.gettempdir()
        json_path = os.path.join(tmp, 'flagsniff_iocs.json')
        csv_path = os.path.join(tmp, 'flagsniff_iocs.csv')

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(iocs, f, indent=2)
        out['files']['json'] = json_path

        # Flatten for CSV
        rows: List[Tuple[str, str]] = []
        for k, vals in (iocs or {}).items():
            for v in (vals or []):
                rows.append((k, v))
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['type', 'value'])
            w.writerows(rows)
        out['files']['csv'] = csv_path

    except Exception as e:
        out['success'] = False
        out['error'] = str(e)
    return out
