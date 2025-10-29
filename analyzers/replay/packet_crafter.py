"""Interactive packet replay and modification engine.

Provides capabilities for:
- Replaying captured traffic with modifications
- Crafting custom packets from templates
- Protocol fuzzing and injection
- TCP stream manipulation
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
import time


@dataclass
class PacketTemplate:
    """Template for crafting packets."""
    protocol: str
    fields: Dict[str, Any]
    payload: Optional[bytes] = None
    description: str = ""


class PacketCrafter:
    """Craft and modify packets using Scapy."""
    
    def __init__(self):
        self.templates: Dict[str, PacketTemplate] = self._load_default_templates()
    
    def _load_default_templates(self) -> Dict[str, PacketTemplate]:
        """Load default packet templates for common protocols."""
        return {
            'http_get': PacketTemplate(
                protocol='HTTP',
                fields={'method': 'GET', 'path': '/', 'version': 'HTTP/1.1'},
                description='Basic HTTP GET request'
            ),
            'dns_query': PacketTemplate(
                protocol='DNS',
                fields={'qname': 'example.com', 'qtype': 'A'},
                description='DNS A record query'
            ),
            'tcp_syn': PacketTemplate(
                protocol='TCP',
                fields={'flags': 'S', 'sport': 12345, 'dport': 80},
                description='TCP SYN packet'
            ),
            'icmp_ping': PacketTemplate(
                protocol='ICMP',
                fields={'type': 8, 'code': 0},
                description='ICMP echo request'
            ),
        }
    
    def craft_packet(self, template_name: str, **overrides) -> Optional[Any]:
        """Craft a packet from a template with field overrides.
        
        Args:
            template_name: Name of the template to use
            **overrides: Field values to override in the template
            
        Returns:
            Scapy packet object or None if template not found
        """
        try:
            from scapy.all import IP, TCP, UDP, DNS, DNSQR, ICMP, Raw  # type: ignore
        except ImportError:
            return None
        
        if template_name not in self.templates:
            return None
        
        template = self.templates[template_name]
        fields = {**template.fields, **overrides}
        
        try:
            if template.protocol == 'HTTP':
                # Craft HTTP request
                method = fields.get('method', 'GET')
                path = fields.get('path', '/')
                host = fields.get('host', 'example.com')
                http_req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                pkt = IP(dst=fields.get('dst', '127.0.0.1')) / TCP(
                    sport=fields.get('sport', 12345),
                    dport=fields.get('dport', 80)
                ) / Raw(load=http_req.encode())
                return pkt
            
            elif template.protocol == 'DNS':
                pkt = IP(dst=fields.get('dst', '8.8.8.8')) / UDP(
                    sport=fields.get('sport', 12345),
                    dport=53
                ) / DNS(rd=1, qd=DNSQR(qname=fields.get('qname', 'example.com')))
                return pkt
            
            elif template.protocol == 'TCP':
                pkt = IP(dst=fields.get('dst', '127.0.0.1')) / TCP(
                    sport=fields.get('sport', 12345),
                    dport=fields.get('dport', 80),
                    flags=fields.get('flags', 'S')
                )
                if template.payload:
                    pkt = pkt / Raw(load=template.payload)
                return pkt
            
            elif template.protocol == 'ICMP':
                pkt = IP(dst=fields.get('dst', '127.0.0.1')) / ICMP(
                    type=fields.get('type', 8),
                    code=fields.get('code', 0)
                )
                return pkt
            
        except Exception:
            return None
        
        return None
    
    def modify_packet(self, packet: Any, modifications: Dict[str, Any]) -> Optional[Any]:
        """Modify fields in an existing packet.
        
        Args:
            packet: Scapy packet object
            modifications: Dict of field paths to new values
                          (e.g., {'IP.dst': '10.0.0.1', 'TCP.dport': 443})
        
        Returns:
            Modified packet or None on error
        """
        try:
            modified_pkt = packet.copy()
            for field_path, value in modifications.items():
                parts = field_path.split('.')
                if len(parts) == 2:
                    layer_name, field_name = parts
                    if modified_pkt.haslayer(layer_name):
                        setattr(modified_pkt[layer_name], field_name, value)
            return modified_pkt
        except Exception:
            return None
    
    def fuzz_field(self, packet: Any, field_path: str, fuzz_values: List[Any]) -> List[Any]:
        """Generate multiple packets with different values for a field (fuzzing).
        
        Args:
            packet: Base Scapy packet
            field_path: Path to field (e.g., 'TCP.dport')
            fuzz_values: List of values to try
            
        Returns:
            List of fuzzed packets
        """
        fuzzed = []
        for val in fuzz_values:
            fuzzed_pkt = self.modify_packet(packet, {field_path: val})
            if fuzzed_pkt:
                fuzzed.append(fuzzed_pkt)
        return fuzzed


class PacketReplayer:
    """Replay captured packets with optional modifications."""
    
    def __init__(self):
        self.replay_log: List[Dict[str, Any]] = []
    
    def replay_packets(
        self,
        packets: List[Any],
        interface: Optional[str] = None,
        delay: float = 0.0,
        modifications: Optional[Dict[int, Dict[str, Any]]] = None,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Replay a list of packets with optional modifications.
        
        Args:
            packets: List of Scapy packet objects
            interface: Network interface to send on (None = default)
            delay: Delay between packets in seconds
            modifications: Dict mapping packet indices to modification dicts
            dry_run: If True, don't actually send packets (just log)
            
        Returns:
            Dict with replay statistics and log
        """
        try:
            from scapy.all import send, sendp  # type: ignore
        except ImportError:
            return {'error': 'Scapy not available', 'sent': 0}
        
        modifications = modifications or {}
        sent_count = 0
        errors = []
        
        for i, pkt in enumerate(packets):
            try:
                # Apply modifications if specified for this packet
                if i in modifications:
                    crafter = PacketCrafter()
                    pkt = crafter.modify_packet(pkt, modifications[i])
                    if pkt is None:
                        errors.append(f"Packet {i}: modification failed")
                        continue
                
                # Log the replay
                self.replay_log.append({
                    'packet_index': i,
                    'timestamp': time.time(),
                    'summary': pkt.summary() if hasattr(pkt, 'summary') else str(pkt),
                    'modified': i in modifications,
                    'dry_run': dry_run
                })
                
                if not dry_run:
                    # Actually send the packet
                    try:
                        if interface:
                            sendp(pkt, iface=interface, verbose=0)
                        else:
                            send(pkt, verbose=0)
                        sent_count += 1
                    except Exception as e:
                        errors.append(f"Packet {i}: send failed - {e}")
                else:
                    sent_count += 1  # Count as sent in dry-run mode
                
                # Delay between packets
                if delay > 0:
                    time.sleep(delay)
                
            except Exception as e:
                errors.append(f"Packet {i}: {e}")
        
        return {
            'sent': sent_count,
            'total': len(packets),
            'errors': errors,
            'dry_run': dry_run,
            'log': self.replay_log[-sent_count:] if sent_count > 0 else []
        }
    
    def replay_stream(
        self,
        stream_data: bytes,
        dst_ip: str,
        dst_port: int,
        protocol: str = 'TCP',
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Replay a TCP/UDP stream by injecting data.
        
        Args:
            stream_data: Raw bytes to send
            dst_ip: Destination IP address
            dst_port: Destination port
            protocol: 'TCP' or 'UDP'
            dry_run: If True, don't actually send
            
        Returns:
            Dict with result info
        """
        try:
            from scapy.all import IP, TCP, UDP, send  # type: ignore
        except ImportError:
            return {'error': 'Scapy not available'}
        
        try:
            if protocol.upper() == 'TCP':
                pkt = IP(dst=dst_ip) / TCP(dport=dst_port) / stream_data
            elif protocol.upper() == 'UDP':
                pkt = IP(dst=dst_ip) / UDP(dport=dst_port) / stream_data
            else:
                return {'error': f'Unsupported protocol: {protocol}'}
            
            if not dry_run:
                send(pkt, verbose=0)
            
            return {
                'success': True,
                'dst': f"{dst_ip}:{dst_port}",
                'protocol': protocol,
                'size': len(stream_data),
                'dry_run': dry_run
            }
        except Exception as e:
            return {'error': str(e)}


class StreamInjector:
    """Inject data into existing TCP streams."""
    
    def __init__(self):
        self.injection_log: List[Dict[str, Any]] = []
    
    def inject_into_stream(
        self,
        stream_id: str,
        injection_data: bytes,
        position: str = 'append',  # 'append', 'prepend', 'replace'
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Inject data into a reconstructed stream.
        
        Args:
            stream_id: Stream identifier
            injection_data: Data to inject
            position: Where to inject ('append', 'prepend', 'replace')
            dry_run: If True, simulate only
            
        Returns:
            Dict with injection result
        """
        # This is a placeholder for stream injection logic
        # In practice, would need access to live connection or packet reconstruction
        
        result = {
            'stream_id': stream_id,
            'injection_size': len(injection_data),
            'position': position,
            'dry_run': dry_run,
            'timestamp': time.time(),
            'success': dry_run  # Always succeeds in dry-run
        }
        
        self.injection_log.append(result)
        return result
    
    def get_injection_log(self) -> List[Dict[str, Any]]:
        """Get log of all injections performed."""
        return self.injection_log.copy()


def craft_exploit_packet(
    exploit_type: str,
    target: str,
    payload: bytes,
    **kwargs
) -> Optional[Any]:
    """Craft a packet for a specific exploit type.
    
    Args:
        exploit_type: Type of exploit ('sql_injection', 'xss', 'buffer_overflow', etc.)
        target: Target IP or hostname
        payload: Exploit payload
        **kwargs: Additional parameters
        
    Returns:
        Crafted Scapy packet or None
    """
    try:
        from scapy.all import IP, TCP, Raw  # type: ignore
    except ImportError:
        return None
    
    port = kwargs.get('port', 80)
    
    if exploit_type == 'sql_injection':
        # Craft HTTP request with SQL injection in query parameter
        http_req = f"GET /?id={payload.decode('utf-8', errors='ignore')} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        pkt = IP(dst=target) / TCP(dport=port) / Raw(load=http_req.encode())
        return pkt
    
    elif exploit_type == 'buffer_overflow':
        # Raw TCP packet with oversized payload
        pkt = IP(dst=target) / TCP(dport=port) / Raw(load=payload)
        return pkt
    
    elif exploit_type == 'xss':
        # HTTP request with XSS payload
        http_req = f"GET /?search={payload.decode('utf-8', errors='ignore')} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        pkt = IP(dst=target) / TCP(dport=port) / Raw(load=http_req.encode())
        return pkt
    
    # Default: raw packet
    pkt = IP(dst=target) / TCP(dport=port) / Raw(load=payload)
    return pkt
