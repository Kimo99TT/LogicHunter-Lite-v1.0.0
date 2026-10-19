"""Explainable workflow and cross-role differential analysis.

This module never treats traffic-derived role labels as proof of identity or
response differences as proof of a vulnerability. It produces ranked,
reproducible hypotheses with evidence provenance.
"""
from __future__ import annotations
import hashlib
import json
import re
from collections import Counter, defaultdict
from typing import Any

ID_NAMES = re.compile(r"(^id$|(^|_)(user|owner|account|tenant|org|profile|resource|record|document|order|invoice)_?id$)", re.I)
OWNER_NAMES = {"owner", "owner_id", "user_id", "account_id", "tenant_id", "created_by", "createdby", "principal_id"}


def _params(record: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for p in (record.get("query_params", []) or []) + (record.get("body_params", []) or []):
        if isinstance(p, dict) and p.get("key"):
            out[str(p["key"]).lower()].append(str(p.get("value", "")))
    return dict(out)


def _response_identity(record: dict[str, Any]) -> dict[str, str]:
    """Extract identity-shaped fields for in-memory comparison only."""
    raw = record.get("response_body_preview") or ""
    try:
        obj = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if isinstance(obj, list):
        obj = obj[0] if obj and isinstance(obj[0], dict) else {}
    if not isinstance(obj, dict):
        return {}
    result = {}
    for key, value in obj.items():
        k = str(key).lower()
        if k in OWNER_NAMES or ID_NAMES.search(k):
            if isinstance(value, (str, int)) and len(str(value)) <= 128:
                result[k] = str(value)
    return result


def _route(r: dict[str, Any]) -> tuple[str, str, str]:
    return (str(r.get("host", "")), str(r.get("method", "GET")).upper(), str(r.get("path", "/")))


def _stable_id(kind: str, payload: Any) -> str:
    return hashlib.sha256((kind + json.dumps(payload, sort_keys=True, default=str)).encode()).hexdigest()[:16]


def build_workflow_model(records: list[dict[str, Any]], max_edges: int = 200) -> dict[str, Any]:
    """Build a compact role-labelled event graph from chronologically sorted traffic."""
    indexed = list(enumerate(records))
    def order(item):
        r = item[1]
        ts = r.get("timestamp")
        try: ts = float(ts)
        except (TypeError, ValueError): ts = item[0]
        if ts > 10_000_000_000: ts /= 1000
        return (ts, item[0])
    indexed.sort(key=order)
    ordered = [r for _, r in indexed]
    nodes: dict[tuple, dict[str, Any]] = {}
    transitions: Counter = Counter()
    role_route: dict[str, list[tuple]] = defaultdict(list)
    route_roles: dict[tuple, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for idx, r in enumerate(ordered):
        route = _route(r)
        role = str(r.get("account_role", "unknown"))
        status = r.get("status")
        node = nodes.setdefault(route, {"host": route[0], "method": route[1], "path": route[2], "count": 0, "statuses": Counter(), "roles": Counter(), "param_names": set()})
        node["count"] += 1
        node["roles"][role] += 1
        if status is not None: node["statuses"][str(status)] += 1
        node["param_names"].update(_params(r).keys())
        role_route[role].append(route)
        route_roles[route][role].append(r)
    for role, seq in role_route.items():
        for a, b in zip(seq, seq[1:]):
            if a != b: transitions[(role, a, b)] += 1
    edges = []
    for (role, a, b), count in transitions.most_common(max_edges):
        edges.append({"role": role, "from": {"method": a[1], "path": a[2]}, "to": {"method": b[1], "path": b[2]}, "count": count})
    role_contrasts = []
    for route, by_role in route_roles.items():
        if "attacker" not in by_role or "victim" not in by_role: continue
        summaries = {}
        for role in ("attacker", "victim"):
            group = by_role[role]
            summaries[role] = {"samples": len(group), "statuses": sorted({r.get("status") for r in group}, key=lambda x: str(x)),
                               "response_lengths": sorted({int(r.get("response_length") or 0) for r in group})[:10]}
        if summaries["attacker"] != summaries["victim"]:
            role_contrasts.append({"id": _stable_id("role-contrast", [route, summaries]), "host": route[0], "method": route[1], "path": route[2], "comparison": summaries,
                                   "interpretation": "role-labelled traffic differs; investigate expected policy and test setup; not a vulnerability verdict"})
    node_list = []
    for n in nodes.values():
        node_list.append({"host": n["host"], "method": n["method"], "path": n["path"], "count": n["count"], "statuses": dict(n["statuses"]), "roles": dict(n["roles"]), "param_names": sorted(n["param_names"])[:40]})
    node_list.sort(key=lambda n: (-n["count"], n["host"], n["path"]))
    return {"schema_version": 1, "events": len(ordered), "node_count": len(node_list), "nodes": node_list[:200], "transitions": edges,
            "role_contrasts": role_contrasts[:100], "caveats": ["Roles are operator-supplied labels, not verified identities.", "Observed transitions reflect capture order and may omit uncaptured steps.", "Status/length differences are hypotheses, never proof of unauthorized access."]}


def analyze_cross_role_ownership(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank same-route cross-role response identity differences without confirming them."""
    groups: dict[tuple, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for r in records:
        role = str(r.get("account_role", "unknown"))
        if role in {"attacker", "victim"}:
            groups[_route(r)][role].append(r)
    findings = []
    for route, roles in groups.items():
        if not roles.get("attacker") or not roles.get("victim"): continue
        evidence = []
        for ar in roles["attacker"]:
            ap = _params(ar); ai = _response_identity(ar)
            attacker_principal = str(ar.get("account_principal_id") or "")
            for vr in roles["victim"]:
                vi = _response_identity(vr)
                victim_principal = str(vr.get("account_principal_id") or "")
                shared_keys = set(ai) & set(vi)
                identity_diffs = sorted(k for k in shared_keys if ai[k] != vi[k])
                status_diff = ar.get("status") != vr.get("status")
                owner_keys = sorted(k for k in ai if k in OWNER_NAMES)
                owner_mismatch = bool(attacker_principal and victim_principal and
                                      any(ai[k] != attacker_principal and ai[k] == victim_principal for k in owner_keys) and
                                      ar.get("status") is not None and 200 <= int(ar.get("status") or 0) < 300)
                same_object = bool(ai.get("id") and vi.get("id") and ai.get("id") == vi.get("id"))
                if not same_object:
                    attacker_ids = {v for k, vals in ap.items() if ID_NAMES.search(k) for v in vals}
                    victim_ids = {v for k, vals in _params(vr).items() if ID_NAMES.search(k) for v in vals}
                    same_object = bool(attacker_ids & victim_ids)
                owner_proof_signal = owner_mismatch and same_object
                # Compare identity fields only when both captures appear to refer to
                # the same object. Otherwise ordinary per-user data differences are
                # a major source of false positives. Status differences remain a
                # weaker access-policy signal and are explicitly labelled as such.
                comparable_identity_diffs = identity_diffs if same_object else []
                if comparable_identity_diffs or status_diff or owner_proof_signal:
                    evidence.append({"attacker_status": ar.get("status"), "victim_status": vr.get("status"),
                                     "identity_fields_differ": comparable_identity_diffs,
                                     "owner_matches_victim_but_not_attacker": bool(owner_proof_signal),
                                     "same_object_signal": bool(same_object),
                                     "same_route": True, "attacker_parameter_names": sorted(ap)[:30]})
        if evidence:
            findings.append({"id": _stable_id("ownership", [route, evidence[:10]]), "host": route[0], "method": route[1], "path": route[2],
                             "classification": "cross_role_differential_needs_validation", "confidence": "low_to_medium",
                             "evidence_count": len(evidence), "evidence": evidence[:10],
                             "required_next_step": "Verify both account identities and object ownership from trusted fixture or application rules; repeat controlled same-object access comparison.",
                             "confirmed": False})
    return findings


def rank_cross_role_hypotheses(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach an explainable heuristic priority; this is not a probability of exploitability."""
    ranked = []
    for finding in analyze_cross_role_ownership(records):
        score = 0.15
        reasons = []
        for evidence in finding.get("evidence", []):
            if evidence.get("owner_matches_victim_but_not_attacker") and evidence.get("same_object_signal"):
                score = max(score, 0.90)
                reasons.append("known principal mismatch on apparently same object")
            elif evidence.get("identity_fields_differ") and evidence.get("same_object_signal"):
                score = max(score, 0.65)
                reasons.append("identity fields differ on apparently same object")
            elif evidence.get("attacker_status") != evidence.get("victim_status"):
                score = max(score, 0.30)
                reasons.append("status differs across role-labelled captures")
        item = dict(finding)
        item["priority_score"] = round(score, 2)
        item["priority_reasons"] = sorted(set(reasons))
        item["score_semantics"] = "heuristic triage priority, not exploit probability"
        ranked.append(item)
    return sorted(ranked, key=lambda item: (-item["priority_score"], item["host"], item["path"]))


def benchmark() -> dict[str, Any]:
    """Offline, deterministic fixture suite for conservative differential logic."""
    def rec(role, path, status, body, params=None, ts=0, principal=None):
        return {"account_role": role, "account_principal_id": principal, "host": "lab.local", "method": "GET", "path": path, "status": status,
                "response_body_preview": json.dumps(body), "response_length": len(json.dumps(body)),
                "query_params": [{"key": k, "value": v} for k, v in (params or {}).items()], "body_params": [], "timestamp": ts}
    cases = [
        {"name": "cross_role_owner_field_difference", "label": "positive", "records": [rec("attacker", "/api/record", 200, {"id": "42", "owner_id": "victim-2"}, {"id": "42"}, 1, "attacker-1"), rec("victim", "/api/record", 200, {"id": "42", "owner_id": "victim-2"}, {"id": "42"}, 2, "victim-2")], "expected": "flag"},
        {"name": "role_status_difference", "label": "positive", "records": [rec("attacker", "/api/private", 200, {"id": "9", "owner_id": "victim-2"}, {"id": "9"}, 1), rec("victim", "/api/private", 403, {"error": "forbidden"}, {"id": "9"}, 2)], "expected": "flag"},
        {"name": "same_response_both_roles", "label": "negative", "records": [rec("attacker", "/api/public", 200, {"id": "1", "owner_id": "shared"}, {"id": "1"}, 1), rec("victim", "/api/public", 200, {"id": "1", "owner_id": "shared"}, {"id": "1"}, 2)], "expected": "clean"},
        {"name": "single_role_only", "label": "negative", "records": [rec("attacker", "/api/record", 200, {"id": "42", "owner_id": "victim-2"}, {"id": "42"}, 1)], "expected": "clean"},
        {"name": "same_status_different_lengths_only", "label": "negative", "records": [rec("attacker", "/api/thing", 200, {"message": "short"}, {"id": "1"}, 1), rec("victim", "/api/thing", 200, {"message": "a much longer but harmless message"}, {"id": "1"}, 2)], "expected": "clean"},
        {"name": "status_and_owner_unchanged", "label": "negative", "records": [rec("attacker", "/api/record", 200, {"id": "8", "owner_id": "user-a"}, {"id": "8"}, 1), rec("victim", "/api/record", 200, {"id": "8", "owner_id": "user-a"}, {"id": "8"}, 2)], "expected": "clean"},
        {"name": "different_objects_have_different_owners", "label": "negative", "records": [rec("attacker", "/api/record", 200, {"id": "8", "owner_id": "user-a"}, {"id": "8"}, 1), rec("victim", "/api/record", 200, {"id": "9", "owner_id": "user-b"}, {"id": "9"}, 2)], "expected": "clean"},
        {"name": "same_object_identity_field_diff", "label": "positive", "records": [rec("attacker", "/api/record", 200, {"id": "8", "owner_id": "user-a"}, {"id": "8"}, 1), rec("victim", "/api/record", 200, {"id": "8", "owner_id": "user-b"}, {"id": "8"}, 2)], "expected": "flag"},
        {"name": "same_status_different_nonidentity_fields", "label": "negative", "records": [rec("attacker", "/api/item", 200, {"id": "8", "name": "Alpha"}, {"id": "8"}, 1), rec("victim", "/api/item", 200, {"id": "8", "name": "Beta"}, {"id": "8"}, 2)], "expected": "clean"},
        {"name": "no_shared_identity_fields_same_status", "label": "negative", "records": [rec("attacker", "/api/item", 200, {"message": "ok"}, {"id": "8"}, 1), rec("victim", "/api/item", 200, {"message": "ok"}, {"id": "8"}, 2)], "expected": "clean"},
        {"name": "owner_mismatch_without_matching_object", "label": "negative", "records": [rec("attacker", "/api/record", 200, {"id": "8", "owner_id": "victim-2"}, {"id": "8"}, 1, "attacker-1"), rec("victim", "/api/record", 200, {"id": "9", "owner_id": "victim-2"}, {"id": "9"}, 2, "victim-2")], "expected": "clean"},
        {"name": "status_difference_is_low_strength_signal", "label": "positive", "records": [rec("attacker", "/api/private", 403, {"error": "forbidden"}, {"id": "9"}, 1), rec("victim", "/api/private", 200, {"id": "9", "owner_id": "victim-2"}, {"id": "9"}, 2)], "expected": "flag"},
    ]
    rows = []
    for case in cases:
        findings = analyze_cross_role_ownership(case["records"])
        observed = "flag" if findings else "clean"
        rows.append({"name": case["name"], "label": case["label"], "expected": case["expected"], "observed": observed, "passed": observed == case["expected"]})
    passed = sum(r["passed"] for r in rows)
    tp = sum(r["expected"] == "flag" and r["observed"] == "flag" for r in rows)
    fp = sum(r["expected"] == "clean" and r["observed"] == "flag" for r in rows)
    fn = sum(r["expected"] == "flag" and r["observed"] == "clean" for r in rows)
    tn = sum(r["expected"] == "clean" and r["observed"] == "clean" for r in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"benchmark": "workflow-ownership-mini-v2", "cases": len(rows), "passed": passed, "failed": len(rows) - passed,
            "fixture_pass_rate": round(passed / len(rows), 3),
            "fixture_metrics": {"true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn,
                                "precision": round(precision, 3), "recall": round(recall, 3)},
            "results": rows,
            "limitations": ["Synthetic fixtures only; not a representative real-world benchmark.", "Metrics describe this tiny labelled fixture set only and are not real-world accuracy estimates.", "Status-only differences remain weak hypotheses, not confirmed vulnerabilities.", "No case is automatically confirmed; role labels and ownership must be verified."]}


def run_local_lab_benchmark() -> dict[str, Any]:
    """Exercise known vulnerable and secure controls over an ephemeral loopback HTTP server."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from urllib.parse import urlsplit, parse_qs
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError

    class LabHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query)
            principal = self.headers.get("Cookie", "")
            if parsed.path == "/api/record":
                status, obj = 200, {"id": query.get("id", [""])[0], "owner_id": "victim-2", "name": "Lab record"}
            elif parsed.path == "/api/private":
                if "principal=victim-2" in principal:
                    status, obj = 200, {"id": query.get("id", [""])[0], "owner_id": "victim-2", "name": "Private lab record"}
                else:
                    status, obj = 403, {"error": "forbidden"}
            elif parsed.path == "/api/public":
                status, obj = 200, {"message": "public lab metadata"}
            else:
                status, obj = 404, {"error": "not found"}
            body = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    records = []
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        for role, principal in (("attacker", "attacker-1"), ("victim", "victim-2")):
            for path in ("/api/record?id=42", "/api/private?id=42", "/api/public"):
                headers = {"Cookie": f"principal={principal}"} if role == "victim" else {}
                request = Request(base + path, headers=headers, method="GET")
                try:
                    with urlopen(request, timeout=2) as response:
                        status, body = response.status, response.read().decode("utf-8", "replace")
                except HTTPError as exc:
                    status, body = exc.code, exc.read().decode("utf-8", "replace")
                parsed = urlsplit(path)
                records.append({"account_role": role, "account_principal_id": principal,
                                "host": f"127.0.0.1:{server.server_port}", "method": "GET", "path": parsed.path,
                                "status": status, "response_body_preview": body, "response_length": len(body),
                                "query_params": [{"key": k, "value": v[0]} for k, v in parse_qs(parsed.query).items()],
                                "body_params": [], "timestamp": len(records) + 1})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    findings = analyze_cross_role_ownership(records)
    by_path = {f["path"]: f for f in findings}
    vulnerable = by_path.get("/api/record")
    secure = by_path.get("/api/private")
    public = by_path.get("/api/public")
    vuln_owner_signal = bool(vulnerable and any(e.get("owner_matches_victim_but_not_attacker") for e in vulnerable["evidence"]))
    secure_no_owner_signal = bool(secure and not any(e.get("owner_matches_victim_but_not_attacker") for e in secure["evidence"]))
    public_clean = public is None
    checks = [
        {"name": "known_vulnerable_owner_mismatch_detected", "passed": vuln_owner_signal},
        {"name": "secure_control_has_no_owner_mismatch_proof", "passed": secure_no_owner_signal},
        {"name": "public_control_has_no_cross_role_difference", "passed": public_clean},
    ]
    passed = sum(x["passed"] for x in checks)
    return {"benchmark": "loopback-workflow-lab-v1", "network_scope": "127.0.0.1 ephemeral port only",
            "requests_executed": len(records), "checks": checks, "passed": passed, "failed": len(checks) - passed,
            "differential_hypotheses": [{"path": f["path"], "classification": f["classification"], "confirmed": f["confirmed"]} for f in findings],
            "limitations": ["This validates a tiny controlled fixture, not general real-world detection accuracy.", "The secure private endpoint can still produce a role-difference hypothesis; this is expected policy evidence, not a confirmed vulnerability."]}
