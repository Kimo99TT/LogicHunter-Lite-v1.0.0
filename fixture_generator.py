"""Deterministic synthetic Burp-like fixtures for regression checks, not real-world accuracy estimates."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
FIXTURE_FILE = ROOT / "data" / "generated_fixtures.json"


def _record(name: str, *, path: str = "/api/items", method: str = "GET", status: int = 200,
            params: list[dict[str, str]] | None = None, req_headers: dict[str, str] | None = None,
            resp_headers: dict[str, str] | None = None, body: str = "", mime: str = "application/json",
            response_body: str = "ok") -> dict[str, Any]:
    return {"fixture_name": name, "host": "lab.local", "method": method, "path": path,
            "url": f"http://lab.local{path}", "status": status, "query_params": params or [],
            "body_params": [], "request_headers": req_headers or {}, "response_headers": resp_headers or {},
            "request_body_preview": body, "response_body_preview": response_body,
            "response_length": len(response_body), "mime_type": mime,
            "fingerprint": f"fixture-{name}", "account_role": "unknown", "principal_id": None}


def generate_fixtures() -> list[dict[str, Any]]:
    fixtures = [
        {"name": "identity_parameter", "expected": ["resource_or_identity_parameter"],
         "record": _record("identity_parameter", params=[{"key": "record_id", "value": "42"}])},
        {"name": "admin_path", "expected": ["admin_or_debug_path"],
         "record": _record("admin_path", path="/admin/debug")},
        {"name": "wildcard_cors", "expected": ["cors_wildcard"],
         "record": _record("wildcard_cors", resp_headers={"access-control-allow-origin": "*"})},
        {"name": "ssrf_input", "expected": ["ssrf_input_candidate"],
         "record": _record("ssrf_input", params=[{"key": "url", "value": "https://example.invalid/resource"}])},
        {"name": "xml_input", "expected": ["xml_input_candidate"],
         "record": _record("xml_input", method="POST", req_headers={"content-type": "application/xml"}, body="<root>sample</root>")},
        {"name": "redirect_candidate", "expected": ["redirect_behavior_candidate"],
         "record": _record("redirect_candidate", status=302, params=[{"key": "next", "value": "/home"}], resp_headers={"location": "/home"})},
        {"name": "clean_negative", "expected": [],
         "record": _record("clean_negative", resp_headers={"content-security-policy": "default-src 'self'", "x-frame-options": "DENY", "strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff"})},
    ]
    return fixtures


def write_fixtures(path: Path | None = None) -> Path:
    target = path or FIXTURE_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(generate_fixtures(), indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def check_detection_quality(analyze_fn: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]) -> dict[str, Any]:
    """Check required signals and unexpected signals per fixture; this is regression-only."""
    results = []
    total_expected = total_found = false_positive_signals = 0
    for fixture in generate_fixtures():
        candidates = analyze_fn([fixture["record"]])
        produced = {signal for candidate in candidates for signal in candidate.get("signal", [])}
        expected = set(fixture["expected"])
        missing = sorted(expected - produced)
        unexpected = sorted(produced - expected)
        total_expected += len(expected)
        total_found += len(expected & produced)
        false_positive_signals += len(unexpected)
        results.append({"fixture": fixture["name"], "expected": sorted(expected),
                        "produced": sorted(produced), "missing": missing, "unexpected": unexpected,
                        "passed": not missing and not unexpected})
    return {"kind": "synthetic_regression_only", "cases": len(results),
            "passed": sum(bool(r["passed"]) for r in results), "failed": sum(not r["passed"] for r in results),
            "required_signal_recall": round(total_found / total_expected, 4) if total_expected else 1.0,
            "unexpected_signal_count": false_positive_signals, "results": results,
            "warning": "Synthetic regression results are not estimates of real-world precision or recall."}
