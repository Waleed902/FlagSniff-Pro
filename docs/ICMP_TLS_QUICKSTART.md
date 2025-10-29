# Quick Start: ICMP & TLS Analysis

## ICMP Analysis

### Basic Usage
```python
from analyzers.protocols.icmp import analyze_icmp_packets

results = analyze_icmp_packets(packets)
print(f"ICMP packets: {results['summary']['total_icmp_packets']}")
print(f"Suspicious: {results['summary']['suspicious']}")
```

### Check for Tunneling
```python
if results['tunnel_detection']['detected']:
    print(f"Confidence: {results['tunnel_detection']['confidence']}%")
    for indicator in results['tunnel_detection']['indicators']:
        print(f"  - {indicator}")
```

### Extract Hidden Data
```python
icmp_analysis = results['icmp_analysis']
for data in icmp_analysis.get('extracted_data', []):
    print(f"Type: {data['type']}")
    print(f"Size: {data['size']} bytes")
    print(f"Preview: {data['preview']}")
```

## TLS Stream Reconstruction

### Basic Usage
```python
from analyzers.protocols.tls import reconstruct_tls_streams

results = reconstruct_tls_streams(packets)
print(f"TLS sessions: {results['summary']['total_sessions']}")
```

### List Server Names (SNI)
```python
for sni in results['summary']['server_names']:
    print(f"Server: {sni}")
```

### Session Details
```python
for stream_id, session in results['sessions'].items():
    print(f"\nStream: {stream_id}")
    print(f"  Version: {session.get('version')}")
    print(f"  Cipher: {session.get('cipher_suite_name')}")
    print(f"  SNI: {session.get('server_name')}")
    print(f"  Complete: {session.get('handshake_complete')}")
```

## In Web Interface

Upload a PCAP and navigate to:
- **Protocols Tab** → **📡 ICMP Analysis**
- **Protocols Tab** → **🔒 TLS Stream Analysis**

## Command Line

```bash
# Test the features
python tests/test_icmp_tls_features.py

# Run web interface
python run_web.py
```

## Common Scenarios

### Detect ICMP Exfiltration
```python
if icmp_results['icmp_analysis'].get('potential_exfiltration'):
    print("⚠️ Possible data exfiltration detected!")
    for pattern in icmp_results['icmp_analysis']['suspicious_patterns']:
        if pattern['severity'] == 'high':
            print(f"  - {pattern['type']}: {pattern['description']}")
```

### Find All TLS Domains
```python
domains = set()
for session in tls_results['sessions'].values():
    if 'server_name' in session:
        domains.add(session['server_name'])
        
print(f"Contacted {len(domains)} unique domains:")
for domain in sorted(domains):
    print(f"  - {domain}")
```

### Check TLS Security
```python
weak_ciphers = ['0x002F', '0x0035']  # Old CBC-based ciphers

for stream_id, session in tls_results['sessions'].items():
    cipher = session.get('cipher_suite')
    if cipher in weak_ciphers:
        print(f"⚠️ Weak cipher in {stream_id}: {session.get('cipher_suite_name')}")
```
