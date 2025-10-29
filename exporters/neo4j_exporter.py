"""
Neo4j Graph Exporter
- Build flows from packets
- Export to Neo4j (if neo4j driver installed) or CSV fallback
"""

from typing import Dict, List, Any, Tuple, Optional
from collections import defaultdict
from scapy.all import IP, IPv6, TCP, UDP
import os

Flow = Tuple[str, int, str, int, str]


def build_flows_from_packets(packets: List) -> List[Dict[str, Any]]:
    flows_map: Dict[Flow, Dict[str, Any]] = defaultdict(lambda: {'bytes': 0, 'pkts': 0})
    for pkt in packets:
        if pkt.haslayer(IP):
            ip = pkt[IP]
            proto = 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else str(ip.proto)
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            key = (ip.src, sport, ip.dst, dport, proto)
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
            proto = 'TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else str(ip.nh)
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            key = (ip.src, sport, ip.dst, dport, proto)
        else:
            continue
        flows_map[key]['bytes'] += len(pkt)
        flows_map[key]['pkts'] += 1

    flows: List[Dict[str, Any]] = []
    for (src, sport, dst, dport, proto), stats in flows_map.items():
        flows.append({'src': src, 'sport': sport, 'dst': dst, 'dport': dport, 'proto': proto, 'bytes': stats['bytes'], 'pkts': stats['pkts']})
    return flows


def _export_csv(flows: List[Dict[str, Any]], out_dir: str) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    nodes_path = os.path.join(out_dir, 'nodes.csv')
    edges_path = os.path.join(out_dir, 'edges.csv')

    # Build node sets
    src_nodes = set(f['src'] for f in flows)
    dst_nodes = set(f['dst'] for f in flows)
    all_nodes = sorted(src_nodes.union(dst_nodes))

    with open(nodes_path, 'w', encoding='utf-8') as f:
        f.write('ip\n')
        for ip in all_nodes:
            f.write(f'{ip}\n')

    with open(edges_path, 'w', encoding='utf-8') as f:
        f.write('src,dst,proto,sport,dport,bytes,pkts\n')
        for fl in flows:
            f.write(f"{fl['src']},{fl['dst']},{fl['proto']},{fl['sport']},{fl['dport']},{fl['bytes']},{fl['pkts']}\n")

    return {'nodes_csv': nodes_path, 'edges_csv': edges_path}


def export_flows_to_neo4j(flows: List[Dict[str, Any]], uri: Optional[str] = None, user: Optional[str] = None, password: Optional[str] = None, out_dir: str = 'graph_export') -> Dict[str, Any]:
    """
    Export flows to Neo4j if driver is available and URI provided; else CSV fallback.
    Returns dict with mode ('neo4j' or 'csv') and paths or counts.
    """
    # Fallback to CSV if driver not present or no URI
    try:
        if uri and user and password:
            from neo4j import GraphDatabase  # type: ignore
            driver = GraphDatabase.driver(uri, auth=(user, password))
            with driver.session() as session:
                # Create uniqueness constraints
                session.run('CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE')
                # Batch insert
                for fl in flows:
                    session.run(
                        'MERGE (s:Host {ip:$src})\n'
                        'MERGE (d:Host {ip:$dst})\n'
                        'MERGE (s)-[e:FLOW {proto:$proto, sport:$sport, dport:$dport}]->(d)\n'
                        'ON CREATE SET e.bytes=$bytes, e.pkts=$pkts\n'
                        'ON MATCH SET e.bytes = e.bytes + $bytes, e.pkts = e.pkts + $pkts',
                        fl
                    )
            driver.close()
            return {'mode': 'neo4j', 'inserted_flows': len(flows)}
    except Exception as e:
        # Fall through to CSV on error
        pass

    paths = _export_csv(flows, out_dir)
    return {'mode': 'csv', **paths}
