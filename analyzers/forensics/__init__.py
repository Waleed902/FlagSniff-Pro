"""Forensics analyzers package.

Central place for helpers like suspicious packet detection, file carving,
protocol session building, and transfer extraction. Public API re-exports
keep imports stable for callers.
"""

# Suspicious packet heuristics
try:  # pragma: no cover - optional
	from .suspicious import identify_suspicious_packets  # noqa: F401
except Exception:
	pass

# File carving and transfer extraction
try:  # pragma: no cover - optional
	from .file_carving import (
		carve_files_from_streams,
		enhanced_file_carving,
		extract_ftp_files,
		extract_http_files,
		extract_file_with_boundaries,
		extract_archive_data,
		looks_like_text,
		is_likely_file_data,
		determine_file_type_from_data,
	)  # noqa: F401
except Exception:
	pass

# Sessions
try:  # pragma: no cover - optional
	from .sessions import build_sessions  # noqa: F401
except Exception:
	pass

# VoIP helpers
try:  # pragma: no cover - optional
	from .voip import (
		extract_voip_audio_from_sessions,
		detect_sip_sessions,
		reconstruct_voip_calls,
	)  # noqa: F401
except Exception:
	pass
