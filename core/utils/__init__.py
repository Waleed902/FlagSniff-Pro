"""Core utilities package.

Provides a stable import path by re-exporting existing utils modules.
"""
try:
    from utils.parsers import *  # noqa: F401,F403
except Exception:
    pass

try:
    from utils.patterns import *  # noqa: F401,F403
except Exception:
    pass

try:
    from utils.email_extractors import *  # noqa: F401,F403
except Exception:
    pass
