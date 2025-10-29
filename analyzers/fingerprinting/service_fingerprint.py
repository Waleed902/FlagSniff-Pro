"""
Service Fingerprinting (HTTP/SSH/TLS-lite)
- HTTP Server header and title (best-effort)
- SSH banner parsing
- TLS ClientHello SNI extraction (minimal parser)
"""

from typing import Dict, List, Any, Optional
from scapy.all import TCP, Raw
import re


class ServiceFingerprinter:
    def __init__(self):
        self.http_servers: Dict[str, Dict[str, int]] = {}
        self.ssh_banners: Dict[str, str] = {}
        self.tls_sni: Dict[str, str] = {}

    def _parse_http(self, payload: bytes) -> Optional[Dict[str, str]]:
        try:
            text = payload.decode('iso-8859-1', errors='ignore')
            if '\r\n' not in text:
                return None
            headers, _, _ = text.partition('\r\n\r\n')
            server = None
            for line in headers.split('\r\n'):
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    break
            # Optional title from small HTML
            title = None
            m = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()
            if server or title:
                return {'server': server or '', 'title': title or ''}
        except Exception:
            return None
        return None

    def _parse_ssh_banner(self, payload: bytes) -> Optional[str]:
        try:
            text = payload.decode('utf-8', errors='ignore')
            if text.startswith('SSH-'):
                line = text.split('\n', 1)[0].strip()
                return line
        except Exception:
            return None
        return None

    def _parse_tls_clienthello_sni(self, payload: bytes) -> Optional[str]:
        # Minimal TLS parser: look for handshake record + ClientHello + extensions, then SNI extension (type 0)
        try:
            data = payload
            if len(data) < 5:
                return None
            # TLS record header
            if data[0] != 0x16:  # Handshake
                return None
            length = (data[3] << 8) | data[4]
            if 5 + length > len(data):
                # may be segmented; best-effort
                pass
            # Handshake header
            hs_type = data[5]
            if hs_type != 0x01:  # ClientHello
                return None
            # Skip to extensions: record basic offsets
            # ClientHello: 1(type)+3(len)+2(version)+32(random)+1(sidlen)+sid+2(ciplen)+ciphers+1(comp_len)+comp+2(ext_len)+ext
            idx = 5 + 4  # type(1)+len(3) already included; move to version
            idx += 2 + 32  # version + random
            if idx >= len(data):
                return None
            sid_len = data[idx]
            idx += 1 + sid_len
            if idx + 2 > len(data):
                return None
            cipher_len = (data[idx] << 8) | data[idx + 1]
            idx += 2 + cipher_len
            if idx >= len(data):
                return None
            comp_len = data[idx]
            idx += 1 + comp_len
            if idx + 2 > len(data):
                return None
            ext_len = (data[idx] << 8) | data[idx + 1]
            idx += 2
            end = idx + ext_len
            while idx + 4 <= len(data) and idx + 4 <= end:
                etype = (data[idx] << 8) | data[idx + 1]
                elen = (data[idx + 2] << 8) | data[idx + 3]
                idx += 4
                if etype == 0:  # SNI
                    # ServerNameList length (2), then name type (1), name len (2), name
                    if idx + 2 <= len(data):
                        snl = (data[idx] << 8) | data[idx + 1]
                        j = idx + 2
                        if j + 3 <= len(data):
                            name_type = data[j]
                            name_len = (data[j + 1] << 8) | data[j + 2]
                            j += 3
                            if j + name_len <= len(data):
                                sni = data[j:j + name_len].decode('idna', errors='ignore')
                                return sni
                idx += elen
        except Exception:
            return None
        return None

    def analyze_packet(self, pkt):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        src = getattr(pkt['IP'], 'src', None) if pkt.haslayer('IP') else None
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        payload = bytes(pkt[Raw].load)

        # HTTP (80/8080/8000 etc.) best-effort; also HTTPS over 443 may carry HTTP if proxy/cleartext
        if dport in (80, 8080, 8000, 8888, 443) or sport in (80, 8080, 8000, 8888):
            h = self._parse_http(payload)
            if h and src:
                key = src
                self.http_servers.setdefault(key, {})
                server = h.get('server', '')
                if server:
                    self.http_servers[key][server] = self.http_servers[key].get(server, 0) + 1
        # SSH banner
        if dport == 22 or sport == 22:
            b = self._parse_ssh_banner(payload)
            if b and src:
                self.ssh_banners[src] = b
        # TLS SNI from ClientHello (usually client->server, dport 443)
        if dport == 443:
            sni = self._parse_tls_clienthello_sni(payload)
            if sni and src:
                self.tls_sni[src] = sni

    def summarize(self) -> Dict[str, Any]:
        return {
            'http_servers': self.http_servers,
            'ssh_banners': self.ssh_banners,
            'tls_sni': self.tls_sni
        }


def analyze_service_fingerprints(packets: List) -> Dict[str, Any]:
    f = ServiceFingerprinter()
    for p in packets:
        f.analyze_packet(p)
    return f.summarize()
