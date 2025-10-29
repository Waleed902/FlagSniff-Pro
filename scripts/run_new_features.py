"""
Run new FlagSniff analyzers on a PCAP and print concise summaries.
Usage: python scripts/run_new_features.py <pcap_path>
"""

import sys
from scapy.all import rdpcap

# IPv6
from analyzers.protocols.ipv6 import analyze_ipv6_traffic, detect_ipv6_tunneling, analyze_icmpv6_packets
# Industrial
from analyzers.protocols.industrial import (
    analyze_dnp3_traffic, analyze_s7comm_traffic, analyze_bacnet_traffic, analyze_opcua_traffic, analyze_profinet_traffic
)
# Blockchain
from analyzers.blockchain import analyze_bitcoin_traffic, analyze_ethereum_traffic, detect_crypto_mining
# RF
from analyzers.rf import analyze_wifi_traffic, analyze_ble_traffic, analyze_zigbee_traffic
# ML
from analyzers.ml.traffic_anomaly import analyze_ml_anomalies
# DB
from analyzers.protocols.database import (
    analyze_mysql_traffic, analyze_postgres_traffic, analyze_mongodb_traffic, analyze_redis_traffic, analyze_mssql_traffic
)
# Malware
from analyzers.malware import detect_malware_traffic
# Temporal
from analyzers.temporal.time_patterns import analyze_time_patterns
# Fingerprinting
from analyzers.fingerprinting import analyze_os_fingerprints, analyze_service_fingerprints
# DLP
from analyzers.dlp.pii_detector import analyze_dlp
# Graph export
from exporters.neo4j_exporter import build_flows_from_packets


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/run_new_features.py <pcap_path>")
        sys.exit(1)
    pcap = sys.argv[1]
    packets = rdpcap(pcap)

    print("=== IPv6 ===")
    print(analyze_ipv6_traffic(packets).get('summary', {}))
    print(detect_ipv6_tunneling(packets).get('summary', {}))
    print(analyze_icmpv6_packets(packets).get('suspicious_patterns', []))

    print("\n=== Industrial ===")
    print({
        'dnp3': analyze_dnp3_traffic(packets).get('security_analysis', {}),
        's7': analyze_s7comm_traffic(packets).get('security_analysis', {}),
        'bacnet': analyze_bacnet_traffic(packets).get('security_analysis', {}),
        'opcua': analyze_opcua_traffic(packets).get('security_analysis', {}),
        'profinet': analyze_profinet_traffic(packets).get('security_analysis', {})
    })

    print("\n=== Blockchain ===")
    print(analyze_bitcoin_traffic(packets).get('security_analysis', {}))
    print(analyze_ethereum_traffic(packets).get('security_analysis', {}))
    print(detect_crypto_mining(packets).get('analysis', {}))

    print("\n=== RF ===")
    print({'wifi': len(analyze_wifi_traffic(packets).get('aps', {})), 'ble_scans': len(analyze_ble_traffic(packets).get('scan_requests', {})), 'zigbee_profiles': len(analyze_zigbee_traffic(packets).get('app_profiles', {}))})

    print("\n=== ML Anomalies ===")
    print(analyze_ml_anomalies(packets))

    print("\n=== Databases ===")
    print({
        'mysql': analyze_mysql_traffic(packets),
        'postgres': analyze_postgres_traffic(packets),
        'mongodb': analyze_mongodb_traffic(packets),
        'redis': analyze_redis_traffic(packets),
        'mssql': analyze_mssql_traffic(packets)
    })

    print("\n=== Malware ===")
    print(detect_malware_traffic(packets).get('suspicious_patterns', []))

    print("\n=== Temporal ===")
    print(analyze_time_patterns(packets).get('global', {}))

    print("\n=== Fingerprinting ===")
    print({'os': len(analyze_os_fingerprints(packets)), 'services': analyze_service_fingerprints(packets)})

    print("\n=== Graph Preview ===")
    flows = build_flows_from_packets(packets)
    print({'flows': len(flows)})


if __name__ == '__main__':
    main()
