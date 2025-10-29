"""
Optional TShark integration orchestrated by AI-planned filters.

- Checks for tshark availability
- Sanitizes commands to a strict allowlist
- Plans a small set of default commands (offline) and can accept AI-suggested ones
- Executes TShark and parses JSON output safely

This module is optional; if tshark is not installed, callers should skip gracefully.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

ALLOWED_FLAGS = {
    "-r", "-Y", "-T", "-J", "-j", "-e", "-E", "-c", "-n", "-N", "-o"
}

# Only allow JSON or fields output
ALLOWED_T_OUTPUTS = {"json", "fields"}

# Allowed -o preferences keys (keep very narrow)
ALLOWED_O_PREFIXES = {
    "tls.keylog_file",  # to support decryption if explicitly provided
    "tcp.desegment_tcp_streams",
}

# Simple safe defaults for field extraction when using -T fields
SAFE_FIELDS = [
    "frame.number", "frame.time_epoch",
    "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "http.request.method", "http.request.full_uri", "http.host", "http.user_agent",
    "http.response.code", "http.content_type",
    "dns.qry.name", "dns.a", "dns.aaaa", "dns.resp.name",
]

@dataclass
class TsharkPlan:
    args: List[str]
    description: str


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def sanitize_args(args: List[str]) -> List[str]:
    """Sanitize a tshark argument list with a strict allowlist.
    - Keeps only ALLOWED_FLAGS and their values
    - Ensures -T is one of allowed outputs
    - Prevents file writes or shell redirections (we never pass through a shell)
    """
    safe: List[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ALLOWED_FLAGS:
            safe.append(a)
            # Flags that require a following value
            if a in {"-r", "-Y", "-T", "-J", "-j", "-e", "-E", "-c", "-N", "-o"}:
                if i + 1 < len(args):
                    val = args[i + 1]
                    # Validate -T
                    if a == "-T" and val not in ALLOWED_T_OUTPUTS:
                        # force to json as fallback
                        safe.append("json")
                    elif a == "-o":
                        # Only allow specific preference keys
                        if any(val.startswith(pref + ":") for pref in ALLOWED_O_PREFIXES):
                            safe.append(val)
                        else:
                            # Skip unsafe -o entries
                            pass
                    else:
                        # General passthrough for simple values
                        safe.append(val)
                    i += 2
                    continue
            i += 1
            continue
        else:
            # Drop unallowed flags silently
            i += 1
            continue
    return safe


def default_plans(pcap_path: str, limit: int = 5000) -> List[TsharkPlan]:
    plans: List[TsharkPlan] = []
    # General JSON export for common protocols (use display filter instead of -J to avoid field errors)
    plans.append(TsharkPlan(
        args=["-r", pcap_path, "-n", "-T", "json", "-Y", "http || dns || tcp || udp || tls", "-c", str(limit)],
        description="Common protocols JSON dump"
    ))
    # HTTP-focused subset (fields)
    plans.append(TsharkPlan(
        args=["-r", pcap_path, "-n", "-T", "fields"] + sum((['-e', f] for f in SAFE_FIELDS), []) + ["-Y", "http || http2", "-c", str(limit)],
        description="HTTP fields extraction"
    ))
    # DNS-focused subset (fields)
    plans.append(TsharkPlan(
        args=["-r", pcap_path, "-n", "-T", "fields"] + sum((['-e', f] for f in SAFE_FIELDS if f.startswith("dns.") or f in ("frame.number","ip.src","ip.dst")), []) + ["-Y", "dns", "-c", str(limit)],
        description="DNS fields extraction"
    ))
    return plans


def run_tshark_plan(plan: TsharkPlan, timeout: int = 120) -> Tuple[Optional[Any], str]:
    """Run a single TShark plan and parse output if JSON; return (data, stderr)."""
    # Resolve absolute path to avoid PATH issues on Windows and elsewhere
    tshark_path = shutil.which("tshark")
    if not tshark_path:
        return None, "tshark not found"
    # Sanitize only the argument vector (exclude the binary itself)
    safe_args = sanitize_args(plan.args)
    # Compose final command without shell
    cmd = [tshark_path] + safe_args
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except Exception as e:
        return None, f"subprocess error: {e}"

    out = proc.stdout.decode("utf-8", errors="ignore")
    err = proc.stderr.decode("utf-8", errors="ignore")

    data: Optional[Any] = None
    try:
        # If -T json, parse JSON; otherwise return raw lines
        if "-T" in plan.args and plan.args[plan.args.index("-T") + 1] == "json":
            data = json.loads(out) if out.strip().startswith("[") else None
        else:
            data = [l for l in out.splitlines() if l.strip()]
    except Exception:
        data = None
    return data, err


def extract_summary_from_json(packets_json: Any) -> Dict[str, Any]:
    """Extract a lightweight summary from TShark JSON packets."""
    summary: Dict[str, Any] = {"http": [], "dns": []}
    if not isinstance(packets_json, list):
        return summary
    for pkt in packets_json:
        try:
            layers = pkt.get("_source", {}).get("layers", {})
            if "http" in layers:
                http = layers["http"]
                item = {
                    "frame": int(layers.get("frame", {}).get("frame.number", ["0"])[0]) if "frame" in layers else None,
                    "host": (http.get("http.host", [""]) or [""])[0],
                    "uri": (http.get("http.request.full_uri", [""]) or [""])[0],
                    "method": (http.get("http.request.method", [""]) or [""])[0],
                    "code": (http.get("http.response.code", [""]) or [""])[0],
                    "content_type": (http.get("http.content_type", [""]) or [""])[0],
                }
                summary["http"].append(item)
            if "dns" in layers:
                dns = layers["dns"]
                qn = (dns.get("dns.qry.name", [""]) or [""])[0]
                ans = (dns.get("dns.a", []) or []) + (dns.get("dns.aaaa", []) or [])
                item = {
                    "frame": int(layers.get("frame", {}).get("frame.number", ["0"])[0]) if "frame" in layers else None,
                    "query": qn,
                    "answers": ans,
                }
                summary["dns"].append(item)
        except Exception:
            continue
    return summary


def run_tshark_analysis(pcap_path: str, ai_agent=None, limit: int = 5000) -> Dict[str, Any]:
    """Run a sequence of sanitized TShark commands and return a compact analysis.
    If ai_agent is provided and can propose filters, you can extend the default plans externally
    and pass them here; this function remains strictly sanitized.
    """
    if not tshark_available():
        return {"available": False, "error": "tshark not installed"}

    plans = default_plans(pcap_path, limit=limit)
    results: Dict[str, Any] = {
        "available": True,
        "plans": [p.description for p in plans],
        "summaries": [],
        "errors": []
    }

    for plan in plans:
        data, err = run_tshark_plan(plan)
        if err:
            results["errors"].append({"plan": plan.description, "stderr": err[:300]})
        if data is None:
            continue
        if isinstance(data, list) and data and isinstance(data[0], dict):
            # JSON packet list
            results["summaries"].append({
                "plan": plan.description,
                "summary": extract_summary_from_json(data)
            })
        else:
            # raw lines
            results["summaries"].append({
                "plan": plan.description,
                "lines": data[:500]
            })

    return results
