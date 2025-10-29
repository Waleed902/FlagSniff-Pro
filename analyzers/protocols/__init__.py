"""Protocol-specific analyzers (DNS, TLS, FTP, etc.).

Initially re-export selected helpers to provide a stable import path.
"""
try:
    # Re-export DNS exfil detector for convenience
    from .dns import detect_dns_exfiltration  # noqa: F401
except Exception:  # pragma: no cover
    pass
