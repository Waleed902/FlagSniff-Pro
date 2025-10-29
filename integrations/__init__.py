"""External/optional integrations (e.g., tshark, pyshark).

Re-export selected helpers to provide a modular import surface.
"""

try:
	from apps.tshark_ai import run_tshark_analysis, tshark_available  # noqa: F401
except Exception:  # pragma: no cover
	pass