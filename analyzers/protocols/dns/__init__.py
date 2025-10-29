"""DNS protocol analyzers."""
try:
    from .dns_exfil import detect_dns_exfiltration  # noqa: F401
except Exception:
    pass
