"""
Packet parsing utilities for FlagSniff
"""

from typing import Dict, Optional, Any
from scapy.all import IP, TCP, UDP, DNS, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
import base64

class PacketParser:
    """Handles parsing of different packet types and protocols"""
    
    def parse_pcap(self, pcap_file):
        """Parse PCAP file and extract packet data list"""
        from scapy.all import rdpcap
        
        try:
            packets = rdpcap(pcap_file)
            packet_data_list = []
            
            for i, packet in enumerate(packets):
                packet_data = self.extract_data(packet)
                if packet_data:
                    packet_data['packet_index'] = i
                    packet_data_list.append(packet_data)
            
            return packet_data_list
        except Exception as e:
            return []
    
    def extract_data(self, packet) -> Optional[Dict[str, Any]]:
        """Extract relevant data from packet"""
        try:
            if not packet.haslayer(IP):
                return None
            
            packet_info = {
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'protocol': self._get_protocol(packet),
                'data': '',
                'raw_data': b''
            }
            
            # Extract payload data
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                packet_info['raw_data'] = raw_data
                
                # Try to decode as text
                try:
                    packet_info['data'] = raw_data.decode('utf-8', errors='ignore')
                except Exception:
                    packet_info['data'] = str(raw_data)
            
            # HTTP specific parsing
            if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                packet_info['protocol'] = 'HTTP'
                if packet.haslayer(Raw):
                    http_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    packet_info['data'] = http_data
                    
                    # Extract HTTP headers and body safely
                    if '\r\n\r\n' in http_data:
                        try:
                            headers, body = http_data.split('\r\n\r\n', 1)
                            packet_info['http_headers'] = headers
                            packet_info['http_body'] = body
                        except Exception:
                            pass
            
            # DNS specific parsing
            elif packet.haslayer(DNS):
                packet_info['protocol'] = 'DNS'
                try:
                    if getattr(packet[DNS], 'qr', 0) == 0 and hasattr(packet[DNS], 'qd') and packet[DNS].qd is not None and hasattr(packet[DNS].qd, 'qname'):
                        try:
                            packet_info['dns_query'] = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                        except Exception:
                            packet_info['dns_query'] = str(getattr(packet[DNS].qd, 'qname', ''))
                    else:
                        # Response
                        if hasattr(packet[DNS], 'an') and packet[DNS].an is not None:
                            packet_info['dns_response'] = str(packet[DNS].an)
                except Exception:
                    pass
            
            # FTP/Telnet (port-based detection)
            elif packet.haslayer(TCP):
                if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                    packet_info['protocol'] = 'FTP'
                elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
                    packet_info['protocol'] = 'Telnet'
                else:
                    packet_info['protocol'] = 'TCP'
            
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
            
            # SMB (port 445)
            if packet.haslayer(TCP) and (packet[TCP].dport == 445 or packet[TCP].sport == 445):
                packet_info['protocol'] = 'SMB'
                # Try to extract SMB command or file name (very basic)
                if packet.haslayer(Raw):
                    raw = packet[Raw].load
                    if b'\x00\x00' in raw:
                        try:
                            packet_info['smb_info'] = raw.decode('utf-8', errors='ignore')
                        except Exception:
                            packet_info['smb_info'] = str(raw)
            # RDP (port 3389)
            elif packet.haslayer(TCP) and (packet[TCP].dport == 3389 or packet[TCP].sport == 3389):
                packet_info['protocol'] = 'RDP'
                if packet.haslayer(Raw):
                    packet_info['rdp_data'] = packet[Raw].load.hex()
            # SSH (port 22)
            elif packet.haslayer(TCP) and (packet[TCP].dport == 22 or packet[TCP].sport == 22):
                packet_info['protocol'] = 'SSH'
                if packet.haslayer(Raw):
                    try:
                        packet_info['ssh_banner'] = packet[Raw].load.decode('utf-8', errors='ignore')
                    except Exception:
                        packet_info['ssh_banner'] = str(packet[Raw].load)
            # TLS/SSL (port 443)
            elif packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                packet_info['protocol'] = 'TLS/SSL'
                if packet.haslayer(Raw):
                    raw_bytes = packet[Raw].load
                    packet_info['tls_data'] = raw_bytes.hex()
                    # Try to parse ClientHello SNI
                    try:
                        data = raw_bytes
                        if len(data) > 5 and data[0] == 0x16 and data[5] == 0x01:
                            # TLS Handshake -> ClientHello starting at index 5
                            idx = 5 + 4  # type(1) + version(2) + length(2?), adjusted to skip handshake header: 1 byte type + 3 bytes length
                            # Actually: record header(5) then handshake header: type(1)+len(3)
                            idx = 5
                            if data[idx] != 0x01:
                                pass
                            else:
                                idx += 4  # handshake header
                                idx += 2  # client_version
                                idx += 32  # random
                                # session id
                                if idx + 1 > len(data):
                                    raise Exception("short session id")
                                sid_len = data[idx]
                                idx += 1 + sid_len
                                # cipher suites
                                if idx + 2 > len(data):
                                    raise Exception("short cipher suites")
                                cs_len = int.from_bytes(data[idx:idx+2], 'big')
                                idx += 2 + cs_len
                                # compression methods
                                if idx + 1 > len(data):
                                    raise Exception("short compression")
                                comp_len = data[idx]
                                idx += 1 + comp_len
                                # extensions
                                if idx + 2 > len(data):
                                    raise Exception("no extensions")
                                ext_len = int.from_bytes(data[idx:idx+2], 'big'); idx += 2
                                end_ext = idx + ext_len
                                while idx + 4 <= end_ext and end_ext <= len(data):
                                    etype = int.from_bytes(data[idx:idx+2], 'big'); idx += 2
                                    elen = int.from_bytes(data[idx:idx+2], 'big'); idx += 2
                                    if idx + elen > len(data):
                                        break
                                    if etype == 0x0000 and elen >= 5:  # server_name
                                        # Parse ServerName extension
                                        list_len = int.from_bytes(data[idx:idx+2], 'big'); p = idx + 2
                                        while p + 3 <= idx + 2 + list_len and p + 3 <= len(data):
                                            name_type = data[p]; p += 1
                                            name_len = int.from_bytes(data[p:p+2], 'big'); p += 2
                                            if p + name_len > len(data):
                                                break
                                            server_name = data[p:p+name_len].decode('utf-8', errors='ignore')
                                            if server_name:
                                                packet_info['tls_sni'] = server_name
                                                break
                                            p += name_len
                                    idx += elen
                    except Exception:
                        pass
            # DNS tunneling (long TXT records)
            elif packet.haslayer(DNS):
                try:
                    if hasattr(packet[DNS], 'an') and packet[DNS].an is not None and hasattr(packet[DNS].an, 'rdata') and isinstance(packet[DNS].an.rdata, bytes) and len(packet[DNS].an.rdata) > 50:
                        packet_info['protocol'] = 'DNS-TUNNEL'
                        try:
                            packet_info['dns_tunnel_data'] = packet[DNS].an.rdata.decode('utf-8', errors='ignore')
                        except Exception:
                            packet_info['dns_tunnel_data'] = str(packet[DNS].an.rdata)
                except Exception:
                    pass
            # VoIP (SIP/RTP, ports 5060/5061/16384-32767)
            elif packet.haslayer(UDP) and (packet[UDP].dport in [5060, 5061] or packet[UDP].sport in [5060, 5061]):
                packet_info['protocol'] = 'SIP'
                if packet.haslayer(Raw):
                    try:
                        packet_info['sip_data'] = packet[Raw].load.decode('utf-8', errors='ignore')
                    except Exception:
                        packet_info['sip_data'] = str(packet[Raw].load)
            elif packet.haslayer(UDP) and (16384 <= packet[UDP].dport <= 32767 or 16384 <= packet[UDP].sport <= 32767):
                packet_info['protocol'] = 'RTP'
                packet_info['rtp_data'] = packet[Raw].load.hex() if packet.haslayer(Raw) else ''
            
            return packet_info
            
        except Exception:
            # Silently ignore malformed packets to reduce noise
            return None
    
    def _get_protocol(self, packet) -> str:
        """Determine packet protocol"""
        if packet.haslayer(DNS):
            return 'DNS'
        elif packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            return 'UDP'
        else:
            return 'Unknown'
    
    def extract_http_credentials(self, data: str) -> list:
        """Extract HTTP authentication credentials"""
        credentials = []
        
        # Basic Auth
        if 'Authorization: Basic' in data:
            import re
            auth_match = re.search(r'Authorization: Basic ([A-Za-z0-9+/=]+)', data)
            if auth_match:
                try:
                    encoded = auth_match.group(1)
                    decoded = base64.b64decode(encoded).decode('utf-8')
                    credentials.append({
                        'type': 'basic_auth',
                        'data': decoded,
                        'encoded': encoded
                    })
                except:
                    pass
        
        # Form-based login
        form_patterns = [
            r'username=([^&\s]+)',
            r'user=([^&\s]+)',
            r'login=([^&\s]+)',
            r'password=([^&\s]+)',
            r'pass=([^&\s]+)',
            r'pwd=([^&\s]+)'
        ]
        
        for pattern in form_patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            for match in matches:
                credentials.append({
                    'type': 'form_data',
                    'field': pattern.split('=')[0].replace('(', ''),
                    'value': match
                })
        
        return credentials
