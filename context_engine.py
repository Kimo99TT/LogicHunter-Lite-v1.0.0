"""Compact chronological application-context model for LogicHunter Lite.

Stores metadata and sanitized summaries, never raw credentials or response bodies.
"""
from __future__ import annotations
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_timestamp(value: Any, fallback: int = 0) -> int:
    """Accept Unix seconds/milliseconds or ISO-8601 timestamps; otherwise fallback."""
    if value is None or value == "":
        return fallback
    try:
        n = float(value)
        if n > 10_000_000_000:
            n /= 1000
        if n > 0:
            return int(n)
    except (TypeError, ValueError):
        pass
    try:
        raw = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (TypeError, ValueError, OverflowError):
        return fallback


def chronological(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stable sort; preserves original order for equal/missing timestamps."""
    indexed = list(enumerate(requests))
    indexed.sort(key=lambda pair: (parse_timestamp(pair[1].get("timestamp"), pair[0]), pair[0]))
    return [item for _, item in indexed]


def _short_response_signature(record: dict[str, Any]) -> dict[str, Any]:
    body = record.get("response_body_preview") or ""
    # Keep only small structural signals; never copy response text into the context graph.
    keys: list[str] = []
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            keys = sorted(str(k)[:60] for k in obj.keys())[:30]
        elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
            keys = sorted(str(k)[:60] for k in obj[0].keys())[:30]
    except (ValueError, TypeError):
        pass
    return {
        "status": record.get("status"),
        "mime": str(record.get("mime_type", ""))[:80],
        "length": int(record.get("response_length") or 0),
        "json_keys": keys,
    }


def build_site_context(requests: list[dict[str, Any]], max_endpoints: int = 80) -> dict[str, Any]:
    ordered = chronological(requests)
    endpoints: dict[tuple, dict[str, Any]] = {}
    roles = Counter()
    params = Counter()
    sequence = []
    for idx, rec in enumerate(ordered):
        host = str(rec.get("host", ""))[:200]
        method = str(rec.get("method", "GET"))[:12]
        path = str(rec.get("path", "/"))[:300]
        role = str(rec.get("account_role", "unknown"))[:20]
        roles[role] += 1
        for p in rec.get("query_params", []) + rec.get("body_params", []):
            if isinstance(p, dict) and p.get("key"):
                params[str(p["key"])[:80]] += 1
        key = (host, method, path)
        sig = _short_response_signature(rec)
        sig["role"] = role
        if key not in endpoints:
            endpoints[key] = {"host": host, "method": method, "path": path,
                              "seen": 0, "roles": Counter(), "statuses": Counter(),
                              "param_names": set(), "response_signatures": []}
        e = endpoints[key]
        e["seen"] += 1
        e["roles"][role] += 1
        if sig["status"] is not None:
            e["statuses"][str(sig["status"])] += 1
        e["param_names"].update(str(p.get("key", ""))[:80] for p in rec.get("query_params", []) + rec.get("body_params", []) if isinstance(p, dict) and p.get("key"))
        if sig not in e["response_signatures"] and len(e["response_signatures"]) < 4:
            e["response_signatures"].append(sig)
        # Compact chronological trace, no values/cookies/body content.
        sequence.append({"n": idx + 1, "t": parse_timestamp(rec.get("timestamp"), idx),
                         "time_source": str(rec.get("timestamp_source", "legacy_or_unknown"))[:32],
                         "role": role, "method": method, "path": path,
                         "status": sig["status"], "fingerprint": str(rec.get("fingerprint", ""))[:32]})
    endpoint_list = []
    for e in endpoints.values():
        endpoint_list.append({
            "host": e["host"], "method": e["method"], "path": e["path"],
            "seen": e["seen"], "roles": dict(e["roles"]),
            "statuses": dict(e["statuses"]), "param_names": sorted(e["param_names"])[:40],
            "response_signatures": e["response_signatures"],
        })
    endpoint_list.sort(key=lambda e: (-e["seen"], e["host"], e["path"]))
    return {"schema_version": 1, "request_count": len(ordered),
            "role_counts": dict(roles), "common_parameters": params.most_common(40),
            "endpoints": endpoint_list[:max_endpoints], "chronology": sequence[-120:],
            "privacy_note": "No raw cookies, authorization headers, parameter values, or response bodies stored."}


def compact_focus(context: dict[str, Any], host: str, path: str, max_chars: int = 7000) -> str:
    """Return compact relevant context around a candidate; bounded for token economy."""
    relevant = [e for e in context.get("endpoints", []) if e.get("host") == host and
                (e.get("path") == path or e.get("path", "").rsplit("/", 1)[0] == path.rsplit("/", 1)[0])]
    if not relevant:
        relevant = context.get("endpoints", [])[:12]
    trace = [x for x in context.get("chronology", []) if x.get("path") == path][-12:]
    obj = {"request_count": context.get("request_count", 0),
           "role_counts": context.get("role_counts", {}),
           "common_parameters": context.get("common_parameters", [])[:20],
           "related_endpoints": relevant[:12], "focused_timeline": trace}
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))[:max_chars]
