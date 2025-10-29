# FlagSniff - New Features Documentation

## 📋 Recently Added Features

This document covers all newly implemented advanced analysis capabilities for network traffic analysis and cybersecurity investigations.

---

## 🌐 1. IPv6 Analysis Suite

### Features
- **Complete IPv6 Protocol Analysis**
  - Extension header parsing (Fragment, Routing, Destination Options, Hop-by-Hop)
  - Address classification (multicast, link-local, unique-local, global)
  - Flow tracking and traffic distribution
  - Fragmentation chain analysis

- **IPv6 Tunneling Detection**
  - 6in4 (IPv6-in-IPv4, Protocol 41)
  - 6to4 (2002::/16 automatic tunneling)
  - Teredo (NAT traversal via UDP 3544)
  - ISATAP (intra-site tunneling)
  - Suspicious tunnel pattern detection

- **ICMPv6 Analysis**
  - Neighbor Discovery Protocol (NDP)
  - Router Discovery (RA/RS)
  - Echo Request/Reply tracking
  - ND cache poisoning detection
  - Rogue router advertisement detection

### Usage Example
```python
from analyzers.protocols.ipv6 import analyze_ipv6_traffic, detect_ipv6_tunneling, analyze_icmpv6_packets
from scapy.all import rdpcap

packets = rdpcap('capture.pcap')

# IPv6 traffic analysis
ipv6_results = analyze_ipv6_traffic(packets)
print(f"Total IPv6 packets: {ipv6_results['total_ipv6']}")
print(f"Suspicious patterns: {ipv6_results['suspicious_patterns']}")

# Tunnel detection
tunnel_results = detect_ipv6_tunneling(packets)
print(f"Detected tunnels: {tunnel_results['detected_tunnels']}")

# ICMPv6 analysis
icmpv6_results = analyze_icmpv6_packets(packets)
print(f"Neighbor Discovery mappings: {icmpv6_results['neighbor_discovery']['nd_mappings']}")
```

### Security Detections
- IPv6 address scanning (excessive Neighbor Solicitations)
- Fragmentation attacks
- Type 0 Routing Header usage (deprecated/insecure)
- Rogue Router Advertisements
- ND cache poisoning attempts
- Teredo bypass detection

---

## 🏭 2. Industrial Protocol Suite (ICS/SCADA)

### Supported Protocols

#### DNP3 (Distributed Network Protocol)
- Used in electric/water utilities
- Function code analysis
- Device communication tracking
- Restart command detection

#### S7comm (Siemens PLC)
- Siemens S7 Communication protocol
- Read/Write variable operations
- Program download detection
- PLC stop command monitoring

#### BACnet (Building Automation)
- Building automation and control
- Object type identification
- Service analysis
- Device discovery monitoring

#### OPC UA (Open Platform Communications)
- Industrial automation standard
- Secure channel tracking
- Session monitoring
- Service invocation analysis

#### PROFINET (Process Field Network)
- Real-time Ethernet for automation
- Frame type classification (RT_CLASS_1/2/3, IRT)
- DCP (Discovery and Configuration Protocol) analysis
- Device enumeration detection

### Usage Example
```python
from analyzers.protocols.industrial import (
    analyze_dnp3_traffic,
    analyze_s7comm_traffic,
    analyze_bacnet_traffic,
    analyze_opcua_traffic,
    analyze_profinet_traffic
)

# DNP3 Analysis
dnp3_results = analyze_dnp3_traffic(packets)
print(f"DNP3 devices: {dnp3_results['devices']}")
print(f"Security risks: {dnp3_results['security_analysis']['identified_risks']}")

# S7comm Analysis
s7_results = analyze_s7comm_traffic(packets)
print(f"PLC operations: {s7_results['plc_operations']}")

# BACnet Analysis
bacnet_results = analyze_bacnet_traffic(packets)
print(f"Building automation devices: {bacnet_results['devices']}")

# OPC UA Analysis
opcua_results = analyze_opcua_traffic(packets)
print(f"Secure channels: {opcua_results['secure_channels']}")

# PROFINET Analysis
profinet_results = analyze_profinet_traffic(packets)
print(f"Real-time traffic: {profinet_results['real_time_traffic']}")
```

### Security Detections
- **DNP3**: Restart commands, unauthorized control operations
- **S7comm**: PLC stop commands, program downloads, excessive writes
- **BACnet**: Device scanning, broadcast floods
- **OPC UA**: Multiple channel attempts, high error rates
- **PROFINET**: DCP enumeration, abnormal traffic patterns

---

## 💎 3. Blockchain & Cryptocurrency Traffic Analysis

### Bitcoin P2P Protocol Analyzer
- Magic byte detection (mainnet/testnet/regtest)
- Command identification (version, tx, block, inv, etc.)
- Node tracking
- Transaction and block counting
- Network type identification

### Ethereum Protocol Analyzer
- JSON-RPC analysis
- DevP2P connection detection
- Smart contract interaction tracking
- Wallet address extraction
- Transaction monitoring

### Cryptocurrency Mining Detector
- Mining pool DNS detection
- Stratum protocol identification
- Mining port detection (3333, 4444, etc.)
- Method analysis (mining.submit, eth_getWork, etc.)
- Severity assessment

### Usage Example
```python
from analyzers.blockchain import (
    analyze_bitcoin_traffic,
    analyze_ethereum_traffic,
    detect_crypto_mining
)

# Bitcoin Analysis
btc_results = analyze_bitcoin_traffic(packets)
print(f"Bitcoin nodes: {btc_results['nodes']}")
print(f"Transactions: {btc_results['transactions']}")
print(f"Network: {btc_results['networks']}")

# Ethereum Analysis
eth_results = analyze_ethereum_traffic(packets)
print(f"RPC methods: {eth_results['rpc_methods']}")
print(f"Wallets: {eth_results['wallets']}")
print(f"Transactions: {eth_results['transactions']}")

# Mining Detection
mining_results = detect_crypto_mining(packets)
print(f"Mining severity: {mining_results['severity']}")
print(f"Suspected miners: {mining_results['suspected_miners']}")
print(f"Stratum connections: {mining_results['stratum_connections']}")
```

### Detection Capabilities
- Mining pool connections (NiceHash, Ethermine, F2Pool, etc.)
- Unauthorized mining activity
- High-volume cryptocurrency transactions
- Testnet/Regtest usage
- Automated trading detection

---

## ⏱️ 4. Time-Based Pattern Analysis

### Features
- Global and per-flow timeline bucketing
- Autocorrelation-based periodicity detection (peaks with period seconds)
- Burstiness metric B = (σ − μ) / (σ + μ)
- Sleep/jitter cycles via long idle gap detection

### Usage
```python
from analyzers.temporal.time_patterns import analyze_time_patterns
results = analyze_time_patterns(packets, bucket_seconds=60)
print(results['global'])
```

---

## 🕸️ 5. Neo4j Graph Exporter

### Features
- Build flows from packets (5‑tuple, bytes, pkts)
- Export directly to Neo4j (if driver installed) or CSV fallback (nodes.csv, edges.csv)

### Usage
```python
from exporters.neo4j_exporter import build_flows_from_packets, export_flows_to_neo4j
flows = build_flows_from_packets(packets)
res = export_flows_to_neo4j(flows, uri=None, user=None, password=None, out_dir='graph_export')
print(res)
```

Optional dependency: neo4j (Python driver)

---

## 🧩 6. Passive OS & Service Fingerprinting

### OS Fingerprinting
- TTL-based OS guess (Windows/Linux/BSD/network device heuristics)
- Common TCP options signature aggregation

### Service Fingerprinting
- HTTP Server header and HTML title extraction
- SSH banner parsing
- TLS ClientHello SNI extraction (minimal parser)

### Usage
```python
from analyzers.fingerprinting import analyze_os_fingerprints, analyze_service_fingerprints
print(analyze_os_fingerprints(packets))
print(analyze_service_fingerprints(packets))
```

---

## 🔒 7. Data Loss Prevention (DLP)

### Features
- Email and SSN regex detection
- Credit card detection with Luhn validation
- Scans Raw payloads and deduplicates findings

### Usage
```python
from analyzers.dlp.pii_detector import analyze_dlp
print(analyze_dlp(packets)['summary'])
```

---

## 🏃 8. Runner Script

Run all new analyzers quickly against a pcap file:

```bash
python scripts/run_new_features.py test_data/sample.pcap
```

---

## 📦 Optional Dependencies
- neo4j (for direct Neo4j export). If missing, exporter writes CSV.

---

## ✅ Status
- IPv6 Suite: Complete
- Industrial Protocols: Complete
- Blockchain/Crypto: Complete
- RF Suite: Complete
- ML Anomaly Detection: Complete
- Time-Based Patterns: Complete
- Neo4j Exporter: Complete
- OS & Service Fingerprinting: Complete
- DLP: Complete
- Runner script: Added

## 🔧 Integration with Existing Tools

All new analyzers integrate seamlessly with FlagSniff's existing infrastructure:

### Web Interface Integration
Add to `web_analyzer.py` or `app_new.py`:

```python
from analyzers.protocols.ipv6 import analyze_ipv6_traffic
from analyzers.protocols.industrial import analyze_dnp3_traffic
from analyzers.blockchain import detect_crypto_mining

# In your analysis function
ipv6_data = analyze_ipv6_traffic(packets)
industrial_data = analyze_dnp3_traffic(packets)
mining_data = detect_crypto_mining(packets)

results = {
    'ipv6': ipv6_data,
    'industrial': industrial_data,
    'crypto_mining': mining_data
}
```

### Command-Line Usage
```python
from scapy.all import rdpcap

# Load capture
packets = rdpcap('suspicious_traffic.pcap')

# Run all analyses
from analyzers.protocols.ipv6 import *
from analyzers.protocols.industrial import *
from analyzers.blockchain import *

print("=== IPv6 Analysis ===")
print(analyze_ipv6_traffic(packets))

print("\n=== Industrial Protocols ===")
print(analyze_dnp3_traffic(packets))
print(analyze_s7comm_traffic(packets))

print("\n=== Cryptocurrency ===")
print(detect_crypto_mining(packets))
```

---

## 📊 Output Format

All analyzers return structured dictionaries with:
- **Statistics**: Counts, distributions, totals
- **Detections**: Specific findings and patterns
- **Security Analysis**: Risks, threats, anomalies
- **Metadata**: Addresses, ports, devices, etc.

Example output structure:
```python
{
    'total_packets': 1234,
    'distribution': {'type1': 100, 'type2': 200},
    'devices': ['192.168.1.1', '192.168.1.2'],
    'suspicious_patterns': [
        {
            'type': 'Suspicious Activity',
            'severity': 'high',
            'description': 'Details here'
        }
    ],
    'security_analysis': {
        'identified_risks': ['Risk 1', 'Risk 2'],
        'total_devices': 5
    }
}
```

---

## 🎯 Use Cases

### 1. Critical Infrastructure Protection
- Monitor SCADA/ICS protocols
- Detect unauthorized PLC commands
- Track industrial device communications

### 2. IPv6 Migration Security
- Identify tunnel usage
- Detect IPv6-based attacks
- Monitor IPv6 deployment

### 3. Cryptocurrency Investigations
- Detect unauthorized mining
- Track cryptocurrency transactions
- Analyze blockchain network traffic

### 4. Network Forensics
- Comprehensive protocol analysis
- Security incident investigation
- Attack pattern recognition

---

## 🚀 Future Enhancements (Pending Implementation)

The following features are planned for future releases:

4. **Radio Frequency (RF) Analysis** - Bluetooth, ZigBee, WiFi, RFID, LoRa
5. **Machine Learning Anomaly Detection** - Traffic classification, behavioral analysis, C2 detection
6. **Database Protocol Analyzers** - MySQL, PostgreSQL, MongoDB, Redis, MSSQL
9. **Malware Traffic Analysis** - Ransomware, backdoor, trojan, exploit kit detection
10. **Time-Based Pattern Analysis** - Periodicity detection, correlation, timeline analysis
11. **Graph Database Integration** - Neo4j export, relationship mapping, attack graphs
12. **Passive OS & Service Fingerprinting** - OS detection, service identification, TLS fingerprinting
13. **Data Loss Prevention (DLP)** - PII detection, policy engine, compliance checking

---

## 📝 Notes

- All analyzers are optimized for performance with large captures
- Scapy is required for packet parsing
- Some protocols may require specific network conditions for detection
- False positives may occur; always verify findings

---

## 🐛 Bug Fixes

### ICMP Entropy Calculation (Fixed)
- **Issue**: `'float' object has no attribute 'bit_length'`
- **Fix**: Replaced `probability.bit_length()` with `math.log2(probability)`
- **File**: `analyzers/protocols/icmp/icmp_analyzer.py`
- **Status**: ✅ Resolved

---

## 📚 Documentation

For more information:
- See individual analyzer files for detailed docstrings
- Check `requirements_web.txt` for dependencies
- Review test files in `test_data/` for example captures

---

**Last Updated**: 2024
**Version**: 2.0
**Contributors**: FlagSniff Development Team
