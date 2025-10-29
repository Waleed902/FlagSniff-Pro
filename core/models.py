from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Literal, Union


Kind = Literal[
    'flag', 'credential', 'token', 'http_uri', 'dns_query', 'file',
    'stego', 'crypto', 'email', 'hash', 'jwt', 'note', 'pattern',
    'tracking_pixel', 'tracking_sequence', 'decoded'
]


@dataclass
class Finding:
    id: Optional[str] = None
    kind: Optional[Kind] = None
    data: Union[str, bytes, None] = None
    protocol: Optional[str] = None
    confidence: float = 0.0
    packet_index: Optional[int] = None
    stream_id: Optional[str] = None
    decoding_chain: List[str] = field(default_factory=list)
    via: Optional[str] = None  # e.g., 'python', 'tshark'
    # Misc UI fields preserved for compatibility
    display_type: Optional[str] = None
    icon: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    http_headers: Optional[str] = None
    http_body: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    decoded: Optional[str] = None
    decode_method: Optional[str] = None
    flag_chunks: Optional[List[str]] = None
    reassembled_flag: Optional[str] = None
    poc: Optional[Dict[str, Any]] = None


@dataclass
class DecodedItem:
    type: str
    result: str
    packet_index: Optional[int] = None
    chain: List[str] = field(default_factory=list)
    confidence: float = 0.0
    protocol: Optional[str] = None
    source: Optional[str] = None
    frame: Optional[int] = None
    poc: Optional[Dict[str, Any]] = None


@dataclass
class SessionMessage:
    timestamp: Optional[str] = None
    direction: Optional[str] = None
    content: Union[str, Dict[str, Any], List[Any], None] = None
    type: Optional[str] = None  # request/response/data


@dataclass
class Stream:
    stream_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    data: Union[bytes, str, None] = None
    packets: List[int] = field(default_factory=list)
    http_requests: List[str] = field(default_factory=list)
    http_responses: List[str] = field(default_factory=list)


@dataclass
class Results:
    # Core sets
    findings: List[Dict[str, Any]] = field(default_factory=list)
    decoded_data: List[Dict[str, Any]] = field(default_factory=list)
    ctf_findings: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_packets: List[Dict[str, Any]] = field(default_factory=list)

    # Summaries and stats
    total_packets: int = 0
    analyzed_packets: int = 0
    analysis_time: Optional[float] = None
    statistics: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    file_info: Dict[str, Any] = field(default_factory=dict)

    # Advanced sections used by UI
    extracted_patterns: List[Dict[str, Any]] = field(default_factory=list)
    potential_flags: List[Dict[str, Any]] = field(default_factory=list)
    workflow_steps: List[Dict[str, Any]] = field(default_factory=list)
    agent_activities: List[Dict[str, Any]] = field(default_factory=list)
    multi_agent_report: Dict[str, Any] = field(default_factory=dict)
    reconstructed_streams: Dict[str, Any] = field(default_factory=dict)
    flag_reassemblies: List[Dict[str, Any]] = field(default_factory=list)
    encryption_attempts: List[Dict[str, Any]] = field(default_factory=list)
    extracted_files: List[Dict[str, Any]] = field(default_factory=list)
    sessions: Dict[str, Any] = field(default_factory=dict)
    exploit_suggestions: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    ai_analysis_results: Dict[str, Any] = field(default_factory=lambda: {
        'enhanced_findings': [],
        'confidence_scores': {},
        'risk_levels': {},
        'analysis_metadata': {
            'timestamp': '',
            'ai_agent_version': '',
            'analysis_duration': 0
        }
    })
    correlation_graph: Dict[str, Any] = field(default_factory=lambda: {'nodes': [], 'edges': []})
    ai_hints: List[Dict[str, Any]] = field(default_factory=list)
    file_carving_results: List[Dict[str, Any]] = field(default_factory=list)
    malware_analysis: List[Dict[str, Any]] = field(default_factory=list)
    protocol_sessions: Dict[str, Any] = field(default_factory=dict)
    session_views: Dict[str, Any] = field(default_factory=dict)
    voip_audio: List[Dict[str, Any]] = field(default_factory=list)
    protocol_details: List[Dict[str, Any]] = field(default_factory=list)
    replay_commands: List[Dict[str, Any]] = field(default_factory=list)
    jwt_tokens: List[Dict[str, Any]] = field(default_factory=list)
    ai_hints2: List[Dict[str, Any]] = field(default_factory=list)

    # Optional integrations and context
    tshark_summary: Optional[Dict[str, Any]] = None
    ctf_context: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        # Convert to dict with shapes expected by existing UI
        # We keep lists/dicts as-is to preserve compatibility
        d = asdict(self)
        return d


def default_results_dict() -> Dict[str, Any]:
    """Create a default results dict matching existing UI expectations.
    This utility allows introducing typed models incrementally while keeping
    downstream dict-based access stable.
    """
    return Results().to_dict()
