"""Context graph and bounded outcome-based adaptation for LogicHunter Lite.

This module learns from local test outcomes and captured traffic structure. It
never sends HTTP requests, executes model-generated code, or marks findings
confirmed. The guarded executor and deterministic verifier remain authoritative.
"""
from __future__ import annotations

import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
GRAPH_FILE = DATA / "context_graph.json"
MEMORY_FILE = DATA / "adaptive_memory.json"


def _read(path: Path, default: Any) -> Any:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value
    except (OSError, json.JSONDecodeError):
        return default


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    tmp.replace(path)


def _path_family(path: str) -> str:
    # Group numeric/UUID-like path segments without retaining query strings.
    path = re.sub(r"(?i)(?<=/)[0-9]{1,}(?=/|$)", "{id}", path or "")
    path = re.sub(r"(?i)(?<=/)[0-9a-f]{8}-[0-9a-f-]{27,}(?=/|$)", "{uuid}", path)
    return path.rstrip("/") or "/"


def _signals(candidate: dict) -> set[str]:
    return {str(x) for x in candidate.get("signal", []) if x}


def build_context_graph(candidates: list[dict], requests_data: list[dict] | None = None) -> dict:
    """Build explainable relationships between candidate findings.

    Edges are hypotheses for investigation, never proof that two issues share
    a root cause. Secret values and request/response bodies are not stored.
    """
    requests_data = requests_data or []
    nodes = []
    for c in candidates:
        nodes.append({
            "id": c.get("id"), "host": c.get("host"), "method": c.get("method"),
            "path": c.get("path"), "path_family": _path_family(c.get("path", "")),
            "hypothesis": c.get("hypothesis"), "signals": sorted(_signals(c)),
            "parameters": sorted({str(p) for p in c.get("parameter_names", [])}),
            "source_fingerprint": c.get("source_fingerprint"),
            "correlation_fingerprints": sorted(c.get("correlation_fingerprints", [])),
        })
    edges = []
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            reasons = []
            if a.get("host") and a.get("host") == b.get("host") and a["path_family"] == b["path_family"]:
                reasons.append("same_host_path_family")
            if a.get("host") and a.get("host") == b.get("host") and set(a["parameters"]) & set(b["parameters"]):
                reasons.append("shared_parameter_names")
            if set(a["signals"]) & set(b["signals"]):
                reasons.append("shared_security_signals")
            afp = {a.get("source_fingerprint"), *a.get("correlation_fingerprints", [])} - {None, ""}
            bfp = {b.get("source_fingerprint"), *b.get("correlation_fingerprints", [])} - {None, ""}
            if afp & bfp:
                reasons.append("shared_source_traffic")
            if reasons:
                edges.append({"source": a["id"], "target": b["id"], "reasons": reasons,
                              "strength": round(min(1.0, 0.35 + 0.2 * len(reasons)), 2)})
    graph = {"schema_version": 1, "generated_at": int(time.time()), "nodes": nodes, "edges": edges,
             "note": "Relationships guide test selection; they do not prove exploitability."}
    _write(GRAPH_FILE, graph)
    return graph


def load_graph() -> dict:
    return _read(GRAPH_FILE, {"schema_version": 1, "nodes": [], "edges": []})


def related_context(candidate_id: str, max_items: int = 6) -> list[dict]:
    graph = load_graph()
    node_map = {n.get("id"): n for n in graph.get("nodes", [])}
    related = []
    for edge in graph.get("edges", []):
        if edge.get("source") == candidate_id:
            other = node_map.get(edge.get("target"))
        elif edge.get("target") == candidate_id:
            other = node_map.get(edge.get("source"))
        else:
            continue
        if other:
            related.append({"candidate_id": other.get("id"), "path": other.get("path"),
                            "method": other.get("method"), "hypothesis": other.get("hypothesis"),
                            "signals": other.get("signals", []), "relationship": edge.get("reasons", [])})
    related.sort(key=lambda x: (-len(x.get("relationship", [])), str(x.get("candidate_id"))))
    return related[:max_items]


def _memory() -> dict:
    value = _read(MEMORY_FILE, {})
    if not isinstance(value, dict):
        value = {}
    value.setdefault("schema_version", 1)
    value.setdefault("updated_at", None)
    value.setdefault("signal_outcomes", {})
    value.setdefault("action_outcomes", {})
    value.setdefault("observations", 0)
    return value


def record_outcome(candidate: dict, plan: dict, verdict: str, notes: str = "") -> None:
    """Accumulate outcome counts; never promote confidence solely from LLM claims."""
    if verdict not in {"confirmed", "rejected", "ambiguous"}:
        verdict = "ambiguous"
    mem = _memory()
    signal_outcomes = mem["signal_outcomes"]
    for signal in sorted(_signals(candidate)):
        row = signal_outcomes.setdefault(signal, {"confirmed": 0, "rejected": 0, "ambiguous": 0})
        row[verdict] = int(row.get(verdict, 0)) + 1
    action = str(plan.get("action", "unknown"))
    action_outcomes = mem["action_outcomes"]
    row = action_outcomes.setdefault(action, {"confirmed": 0, "rejected": 0, "ambiguous": 0})
    row[verdict] = int(row.get(verdict, 0)) + 1
    mem["observations"] = int(mem.get("observations", 0)) + 1
    mem["updated_at"] = int(time.time())
    mem.setdefault("recent", []).append({"candidate_id": candidate.get("id"), "signals": sorted(_signals(candidate)),
                                         "action": action, "verdict": verdict,
                                         "notes": str(notes)[:240], "timestamp": int(time.time())})
    mem["recent"] = mem["recent"][-100:]
    _write(MEMORY_FILE, mem)


def adaptive_score(candidate: dict, graph: dict | None = None, memory: dict | None = None) -> float:
    """Rank review candidates by evidence richness, relationships, and novelty."""
    graph = graph or load_graph()
    memory = memory or _memory()
    signals = _signals(candidate)
    score = 1.0 + min(1.5, 0.35 * len(signals))
    high_value = {"potential_idor_multi_value", "potential_missing_authentication",
                  "resource_or_identity_parameter", "authorization_response"}
    score += 0.8 * len(signals & high_value)
    degree = sum(1 for e in graph.get("edges", []) if candidate.get("id") in (e.get("source"), e.get("target")))
    score += min(1.2, degree * 0.2)
    # Favor under-observed signal families; historic success is not treated as proof.
    outcomes = memory.get("signal_outcomes", {})
    for signal in signals:
        row = outcomes.get(signal, {})
        n = sum(int(row.get(k, 0)) for k in ("confirmed", "rejected", "ambiguous"))
        if n == 0:
            score += 0.25
        elif row.get("ambiguous", 0):
            score += min(0.4, 0.1 * int(row["ambiguous"]))
    return round(score, 3)


def rank_candidates(candidates: list[dict]) -> list[dict]:
    graph, memory = load_graph(), _memory()
    return sorted(candidates, key=lambda c: (-adaptive_score(c, graph, memory), str(c.get("id", ""))))


def report() -> dict:
    graph, memory = load_graph(), _memory()
    return {"graph_nodes": len(graph.get("nodes", [])), "graph_edges": len(graph.get("edges", [])),
            "observations": memory.get("observations", 0),
            "signal_outcomes": memory.get("signal_outcomes", {}),
            "action_outcomes": memory.get("action_outcomes", {}),
            "recent": memory.get("recent", [])[-10:],
            "improvement_proposals": improvement_plan()}


def improvement_plan() -> list[dict]:
    """Create reviewable, evidence-driven improvement proposals from local history.

    Proposals are data only: this function never rewrites source code or runs a
    patch. A developer must implement and test any proposed change separately.
    """
    memory = _memory()
    proposals = []
    for signal, counts in sorted(memory.get("signal_outcomes", {}).items()):
        ambiguous = int(counts.get("ambiguous", 0))
        rejected = int(counts.get("rejected", 0))
        confirmed = int(counts.get("confirmed", 0))
        total = ambiguous + rejected + confirmed
        if ambiguous >= 2:
            proposals.append({
                "id": "evidence-" + re.sub(r"[^a-z0-9]+", "-", signal.lower()).strip("-"),
                "area": "verification", "priority": "high" if ambiguous >= 5 else "medium",
                "trigger": f"{ambiguous} ambiguous outcome(s) for signal {signal}",
                "proposal": "Add a deterministic lab fixture and a stronger evidence extractor for this signal; keep the verdict ambiguous until the required evidence exists.",
                "support": {"confirmed": confirmed, "rejected": rejected, "ambiguous": ambiguous, "total": total},
                "status": "proposed_not_applied",
            })
        if total >= 5 and rejected >= 4 and confirmed == 0:
            proposals.append({
                "id": "heuristic-review-" + re.sub(r"[^a-z0-9]+", "-", signal.lower()).strip("-"),
                "area": "triage", "priority": "medium",
                "trigger": f"{rejected} rejected outcome(s), no confirmations, for signal {signal}",
                "proposal": "Review whether this heuristic is too noisy; add positive and negative regression fixtures before changing its weight.",
                "support": {"confirmed": confirmed, "rejected": rejected, "ambiguous": ambiguous, "total": total},
                "status": "proposed_not_applied",
            })
    _write(DATA / "improvement_proposals.json", {"generated_at": int(time.time()), "proposals": proposals})
    return proposals
