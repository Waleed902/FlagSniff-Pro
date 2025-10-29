"""
Test script for ICMP and TLS analysis features
"""

import sys
sys.path.insert(0, '.')

from scapy.all import IP, ICMP, TCP, Raw
from analyzers.protocols.icmp import analyze_icmp_packets, ICMPAnalyzer
from analyzers.protocols.tls import reconstruct_tls_streams, TLSStreamReconstructor

def test_icmp_analysis():
    """Test ICMP analysis with sample data"""
    print("=" * 60)
    print("Testing ICMP Analysis")
    print("=" * 60)
    
    # Create sample ICMP packets
    packets = []
    
    # Normal ping
    for i in range(5):
        pkt = IP(dst="8.8.8.8")/ICMP(type=8, id=1234, seq=i)/Raw(load=b"Normal ping data" * 4)
        packets.append(pkt)
    
    # Suspicious large payload
    for i in range(3):
        pkt = IP(dst="8.8.8.8")/ICMP(type=8, id=5678, seq=i)/Raw(load=b"X" * 200)
        packets.append(pkt)
    
    # High entropy (simulated encrypted data)
    import os
    for i in range(3):
        pkt = IP(dst="8.8.8.8")/ICMP(type=8, id=9999, seq=i)/Raw(load=os.urandom(150))
        packets.append(pkt)
    
    # Analyze
    results = analyze_icmp_packets(packets)
    
    print(f"\n✓ Total ICMP packets: {results['summary']['total_icmp_packets']}")
    print(f"✓ Tunneling detected: {results['summary']['suspicious']}")
    print(f"✓ Confidence: {results['summary']['confidence']}%")
    
    if results['summary']['key_findings']:
        print("\nKey Findings:")
        for finding in results['summary']['key_findings']:
            print(f"  • {finding['type']}: {finding['description']}")
            if 'indicators' in finding:
                for indicator in finding['indicators']:
                    print(f"    - {indicator}")
    
    print("\n✓ ICMP analysis test passed!")


def test_tls_reconstruction():
    """Test TLS stream reconstruction"""
    print("\n" + "=" * 60)
    print("Testing TLS Stream Reconstruction")
    print("=" * 60)
    
    # Create a simulated TLS ClientHello packet
    # TLS Record: Handshake (22), TLS 1.2 (0x0303)
    client_hello = bytes([
        # TLS Record Header
        0x16,  # Content Type: Handshake (22)
        0x03, 0x03,  # Version: TLS 1.2
        0x00, 0x50,  # Length: 80 bytes
        
        # Handshake Header
        0x01,  # Handshake Type: ClientHello
        0x00, 0x00, 0x4c,  # Length: 76 bytes
        
        # ClientHello
        0x03, 0x03,  # Client Version: TLS 1.2
        
        # Random (32 bytes)
        *([0x00] * 32),
        
        # Session ID Length
        0x00,
        
        # Cipher Suites Length: 4 bytes (2 suites)
        0x00, 0x04,
        0x00, 0x2f,  # TLS_RSA_WITH_AES_128_CBC_SHA
        0xc0, 0x2f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        
        # Compression Methods Length: 1
        0x01,
        0x00,  # No compression
        
        # Extensions Length
        0x00, 0x15,
        
        # SNI Extension
        0x00, 0x00,  # Extension Type: SNI
        0x00, 0x11,  # Length
        0x00, 0x0f,  # Server Name List Length
        0x00,  # Name Type: hostname
        0x00, 0x0c,  # Hostname Length
        *b"example.com"  # Hostname
    ])
    
    # Create packet with TLS data
    pkt = IP(dst="1.2.3.4")/TCP(dport=443, sport=12345)/Raw(load=client_hello)
    
    # Test reconstruction
    reconstructor = TLSStreamReconstructor()
    results = reconstructor.reconstruct_stream([pkt])
    
    print(f"\n✓ Total TLS packets processed: {results['total_tls_packets']}")
    print(f"✓ Sessions found: {results['summary']['total_sessions']}")
    
    if results['sessions']:
        print("\nSession Details:")
        for stream_id, session in results['sessions'].items():
            print(f"\n  Stream: {stream_id}")
            print(f"  • Packets: {session['packets']}")
            print(f"  • Handshake messages: {len(session['handshake_messages'])}")
            
            if 'server_name' in session:
                print(f"  • Server Name (SNI): {session['server_name']}")
            
            if 'client_version' in session:
                print(f"  • Client Version: {session['client_version']}")
    
    print("\n✓ TLS reconstruction test passed!")


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("ICMP and TLS Analysis Feature Tests")
    print("=" * 60)
    
    try:
        test_icmp_analysis()
        test_tls_reconstruction()
        
        print("\n" + "=" * 60)
        print("✓ All tests passed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
