# analyzers/protocols/tls/certificate_analyzer.py

from cryptography import x509
from cryptography.hazmat.backends import default_backend

def parse_certificate(cert_data):
    """
    Parses an X.509 certificate.
    """
    cert = x509.load_der_x509_certificate(cert_data, default_backend())

    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_number': cert.serial_number,
        'validity': {
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat(),
        },
        'extensions': {ext.oid._name: str(ext.value) for ext in cert.extensions},
    }

from scapy.all import *
from scapy.layers.tls.handshake import TLSCertificate

def analyze_tls_certificates(packets):
    """
    Analyzes TLS certificates in a packet capture.
    """
    certificates = []

    for packet in packets:
        if packet.haslayer(TLSCertificate):
            for cert in packet[TLSCertificate].certs:
                try:
                    parsed_cert = parse_certificate(cert.cert)
                    certificates.append(parsed_cert)
                except Exception:
                    # Ignore certificates that can't be parsed
                    continue

    return certificates
