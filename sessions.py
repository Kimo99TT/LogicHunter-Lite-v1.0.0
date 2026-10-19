#!/usr/bin/env python3
"""sessions.py — per-candidate test session storage + guarded execution.

Design (agreed in planning discussion):
- One JSON file per candidate under data/test_sessions/.
- A lightweight _index.json caches {candidate_id: status} for fast reporting
  without opening every session file.
- The AI layer (providers.py) only ever returns a plan. execute_plan() here
  is the ONLY code that sends an HTTP request, and only for whitelisted
  actions, and only after an allowlist host check, and only when --live
  was explicitly passed (dry-run is the default).
"""
from __future__ import annotations
import difflib
import hashlib
import json
import os
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
SESSIONS_DIR = DATA / "test_sessions"
INDEX_FILE = SESSIONS_DIR / "_index.json"

ALLOWED_ACTIONS = {"set_param", "set_body_param", "remove_cookie", "remove_header"}
MAX_ITERATIONS_DEFAULT = 3
MAX_TRY_VALUES = 5
MAX_REQUESTS_PER_RUN_DEFAULT = 30
MAX_VALUE_LENGTH = 128
SAFE_CANDIDATE_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")


def _atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    tmp.replace(path)


# --- Index cache (status-only, for fast reporting) ---

def load_index() -> dict:
    if not INDEX_FILE.exists():
        return {}
    try:
        data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _update_index(candidate_id: str, status: str) -> None:
    idx = load_index()
    idx[candidate_id] = status
    _atomic_write_json(INDEX_FILE, idx)


# --- Session file I/O ---

def session_path(candidate_id: str) -> Path:
    if not isinstance(candidate_id, str) or not SAFE_CANDIDATE_ID.fullmatch(candidate_id):
        raise ValueError("invalid candidate_id")
    return SESSIONS_DIR / f"{candidate_id}.json"


def load_session(candidate_id: str) -> Optional[dict]:
    f = session_path(candidate_id)
    if f.exists():
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def save_session(session: dict) -> None:
    _atomic_write_json(session_path(session["candidate_id"]), session)
    _update_index(session["candidate_id"], session["status"])


def init_session(candidate: dict, original_request: dict,
                 max_iterations: int = MAX_ITERATIONS_DEFAULT) -> dict:
    return {
        "candidate_id": candidate["id"],
        "status": "in_progress",
        "iterations_used": 0,
        "max_iterations": max_iterations,
        "host": candidate.get("host"),
        "path": candidate.get("path"),
        "account_role": original_request.get("account_role", "unknown"),
        "candidate_signals": candidate.get("signal", []),
        "candidate_parameters": candidate.get("parameter_names", []),
        "baseline": {
            "status": original_request.get("status"),
            "length": original_request.get("response_length"),
            # This is a preview, not a complete response. Keep the marker explicit
            # so the verifier never mistakes a preview hash for a full-body hash.
            "body_hash": hashlib.sha256(
                (original_request.get("response_body_preview") or "").encode()
            ).hexdigest()[:16],
            "hash_source": "sanitized_preview",
            "preview_length": len(original_request.get("response_body_preview") or ""),
        },
        "history": [],
    }


# --- Orphan cleanup ---

def cleanup_orphaned_sessions(candidates: list) -> int:
    """Delete session files whose candidate no longer exists in candidates.json
    (happens after re-running analyze() with updated heuristics — fingerprints
    change and candidate IDs change with them)."""
    valid_ids = {c["id"] for c in candidates}
    removed = 0
    if not SESSIONS_DIR.exists():
        return 0
    for f in SESSIONS_DIR.glob("*.json"):
        if f.name == "_index.json":
            continue
        cid = f.stem
        if cid not in valid_ids:
            archive_dir = SESSIONS_DIR / "archive"
            archive_dir.mkdir(parents=True, exist_ok=True)
            destination = archive_dir / f.name
            if destination.exists():
                destination = archive_dir / f"{cid}-{int(time.time())}.json"
            f.replace(destination)
            removed += 1
    idx = load_index()
    idx = {k: v for k, v in idx.items() if k in valid_ids}
    _atomic_write_json(INDEX_FILE, idx)
    return removed


# --- Whitelisted execution (the ONLY place that sends requests) ---

def _apply_action(request: dict, action: str, param: Optional[str],
                  value: str) -> dict:
    """Returns a NEW request dict with the modification applied. Never
    mutates the original — the original is always needed as reference."""
    new_req = json.loads(json.dumps(request))  # cheap deep copy
    if action == "set_param" and param:
        parsed = urllib.parse.urlparse(new_req["url"])
        q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        q[param] = [value]
        new_req["url"] = parsed._replace(
            query=urllib.parse.urlencode(q, doseq=True)
        ).geturl()
    elif action == "set_body_param" and param:
        body = new_req.get("body", "")
        headers = {str(k).lower(): str(v) for k, v in new_req.get("headers", {}).items()}
        ctype = headers.get("content-type", "").lower()
        if "json" in ctype:
            try:
                obj = json.loads(body)
            except (ValueError, TypeError) as exc:
                raise ValueError("invalid_json_body") from exc
            if not isinstance(obj, dict):
                raise ValueError("json_body_not_object")
            parts = param.split(".")
            if len(parts) > 6 or any(not part or part in {"__proto__", "prototype", "constructor"} for part in parts):
                raise ValueError("invalid_json_path")
            current = obj
            for part in parts[:-1]:
                if not isinstance(current, dict) or part not in current or not isinstance(current[part], dict):
                    raise ValueError("json_path_not_found")
                current = current[part]
            leaf = parts[-1]
            if not isinstance(current, dict) or leaf not in current:
                raise ValueError("json_field_not_found")
            old_value = current[leaf]
            if isinstance(old_value, bool) or isinstance(old_value, (dict, list)):
                raise ValueError("json_field_not_scalar")
            if isinstance(old_value, int) and str(value).lstrip("-").isdigit():
                current[leaf] = int(value)
            elif isinstance(old_value, float):
                try:
                    current[leaf] = float(value)
                except ValueError:
                    current[leaf] = str(value)
            else:
                current[leaf] = str(value)
            new_req["body"] = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        elif "application/x-www-form-urlencoded" in ctype:
            parts = urllib.parse.parse_qsl(body, keep_blank_values=True)
            if not any(k == param for k, _ in parts):
                raise ValueError("form_field_not_found")
            new_req["body"] = urllib.parse.urlencode(
                [(k, value if k == param else v) for k, v in parts]
            )
        else:
            raise ValueError("unsupported_body_content_type")
    elif action == "remove_cookie":
        new_req["headers"] = {
            k: v for k, v in new_req.get("headers", {}).items()
            if k.lower() != "cookie"
        }
    elif action == "remove_header" and param:
        new_req["headers"] = {
            k: v for k, v in new_req.get("headers", {}).items()
            if k.lower() != param.lower()
        }
    return new_req


def _host_allowed(url: str, allowed_hosts: list) -> bool:
    """Fail-closed host policy. Subdomains require an explicit *.example.com entry."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        host = parsed.hostname.rstrip(".").lower()
        port = parsed.port
    except (ValueError, TypeError):
        return False
    for entry in allowed_hosts or []:
        raw = str(entry).strip().lower()
        if not raw:
            continue
        # Optional explicit port: host:port. IPv6 literal support is intentionally
        # conservative; use an exact URL host entry without a port for IPv6.
        entry_port = None
        if raw.startswith("*."):
            pattern = raw[2:]
            wildcard = True
        else:
            pattern = raw
            wildcard = False
        if ":" in pattern and not pattern.startswith("["):
            maybe_host, maybe_port = pattern.rsplit(":", 1)
            if maybe_port.isdigit():
                pattern, entry_port = maybe_host, int(maybe_port)
        if entry_port is not None:
            if port != entry_port:
                continue
        else:
            default_port = 443 if parsed.scheme == "https" else 80
            if port not in (None, default_port):
                continue
        pattern = pattern.strip("[]").rstrip(".")
        if (wildcard and host.endswith("." + pattern) and host != pattern) or (not wildcard and host == pattern):
            return True
    return False


NEUTRAL_STATUS = {400, 404, 405, 410}  # "not found" / "bad request" — expected
                                        # for a made-up ID; not IDOR evidence


def _diff_label(baseline: dict, result: dict) -> str:
    """Semantic, not just size-based. A 404 for a nonexistent ID is NOT
    evidence of anything — it's expected. The real IDOR signal is: same
    (successful) status, but DIFFERENT content for a different ID value,
    which means the endpoint returns per-record data without checking
    that the caller owns that record."""
    bstatus, rstatus = baseline.get("status"), result.get("status")
    blen, rlen = baseline.get("length"), result.get("length") or 0

    if rstatus in NEUTRAL_STATUS:
        return "not_found_or_denied"  # neutral — proves nothing either way

    if bstatus != rstatus:
        if bstatus in (401, 403) and rstatus == 200:
            return "auth_bypass_signal"  # strong signal, handled separately
        if bstatus == 200 and rstatus in (401, 403):
            return "access_control_enforced"  # good sign, not a vuln
        return "status_changed_other"

    # same status — compare actual content, not just length
    if result.get("body_hash") and baseline.get("body_hash") and \
            result["body_hash"] != baseline["body_hash"]:
        return "content_differs_same_status"
    if blen is not None and abs(rlen - blen) > max(50, blen * 0.2):
        return "major_size_change"
    if blen is not None and rlen != blen:
        return "minor_size_change"
    return "no_change"


def validate_plan(plan: dict) -> tuple[bool, str]:
    """Strict schema validation for untrusted model output."""
    if not isinstance(plan, dict):
        return False, "plan_not_object"
    action = plan.get("action")
    if action is None and plan.get("vuln_type", "Unclear") == "Unclear":
        return False, "no_test_proposed"
    if action not in ALLOWED_ACTIONS:
        return False, "rejected_action"
    param = plan.get("param")
    if action in ("set_param", "set_body_param", "remove_header"):
        if not isinstance(param, str) or not param or len(param) > 128:
            return False, "invalid_param"
        if any(ord(c) < 32 for c in param):
            return False, "invalid_param"
        if action == "remove_header" and param.lower() not in {
                "cookie", "authorization", "proxy-authorization", "x-api-key",
                "x-auth-token", "origin", "referer"}:
            return False, "header_not_allowlisted"
        if action == "set_body_param" and (len(param.split(".")) > 6 or any(not x for x in param.split("."))):
            return False, "invalid_body_param_path"
    values = plan.get("try_values", [])
    if not isinstance(values, list) or len(values) > MAX_TRY_VALUES:
        return False, "invalid_try_values"
    if action in {"set_param", "set_body_param"}:
        if not values:
            return False, "empty_try_values"
        for value in values:
            if not isinstance(value, (str, int)) or isinstance(value, bool):
                return False, "invalid_try_value_type"
            if len(str(value)) > MAX_VALUE_LENGTH or any(ord(c) < 32 for c in str(value)):
                return False, "invalid_try_value"
    if action not in {"set_param", "set_body_param"} and values:
        return False, "unexpected_try_values"
    confidence = plan.get("confidence", 0)
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        return False, "invalid_confidence"
    return True, "ok"


def _merge_live_credentials(headers: dict) -> dict:
    """Use explicit environment overrides without persisting credentials."""
    out = {str(k): str(v) for k, v in (headers or {}).items()
           if v != "[REDACTED]" and not str(v).startswith("[REDACTED]")}
    cookie = os.environ.get("LH_COOKIE")
    authorization = os.environ.get("LH_AUTHORIZATION")
    if cookie:
        out = {k: v for k, v in out.items() if k.lower() != "cookie"}
        out["Cookie"] = cookie
    if authorization:
        out = {k: v for k, v in out.items() if k.lower() != "authorization"}
        out["Authorization"] = authorization
    return out


def execute_plan(plan: dict, original_request: dict, allowed_hosts: list,
                 live: bool, rate_limit: float = 1.0,
                 sanitize_fn=None, request_budget: int = MAX_REQUESTS_PER_RUN_DEFAULT,
                 request_counter: Optional[dict] = None) -> list:
    """Execute a small validated plan. Network is disabled unless live=True.

    request_counter may be shared by the caller to enforce a run-wide budget:
    {"used": int, "limit": int}. Only explicit environment credentials are
    used for redacted authentication headers; secrets are never written here.
    """
    valid, validation_reason = validate_plan(plan)
    if not valid:
        return [{"value": None, "status": None, "length": None,
                 "diff_vs_baseline": validation_reason, "snippet": ""}]
    url = original_request.get("url", "")
    if not _host_allowed(url, allowed_hosts):
        return [{"value": None, "status": None, "length": None,
                 "diff_vs_baseline": "host_not_allowed", "snippet": ""}]
    action = plan["action"]
    try_values = plan.get("try_values") or [None]
    if not live:
        return [{"value": v, "status": None, "length": None,
                 "diff_vs_baseline": "dry_run_not_sent", "snippet": ""}
                for v in try_values]
    try:
        rate_limit = float(rate_limit)
    except (TypeError, ValueError):
        rate_limit = 1.0
    rate_limit = min(max(rate_limit, 0.25), 30.0)
    budget = max(0, min(int(request_budget), MAX_REQUESTS_PER_RUN_DEFAULT))
    counter = request_counter if request_counter is not None else {"used": 0, "limit": budget}
    counter.setdefault("used", 0)
    counter.setdefault("limit", budget)
    counter["limit"] = min(int(counter["limit"]), budget)

    headers = _merge_live_credentials(original_request.get("headers", {}))
    body = original_request.get("body", "")
    original_method = str(original_request.get("method", "GET")).upper()
    if action == "set_body_param" and original_method in {"GET", "HEAD", "OPTIONS"}:
        return [{"value": None, "status": None, "length": None,
                 "diff_vs_baseline": "body_mutation_requires_state_changing_method", "snippet": ""}]
    if body and ("[REDACTED]" in body or "[BODY_OMITTED" in body) and not os.environ.get("LH_REQUEST_BODY"):
        return [{"value": None, "status": None, "length": None,
                 "diff_vs_baseline": "redacted_body_requires_LH_REQUEST_BODY", "snippet": ""}]
    if os.environ.get("LH_REQUEST_BODY") is not None:
        body = os.environ.get("LH_REQUEST_BODY", "")

    import requests
    session_http = requests.Session()
    session_http.trust_env = False
    results = []
    for value in try_values:
        if counter["used"] >= counter["limit"]:
            results.append({"value": value, "status": None, "length": None,
                            "diff_vs_baseline": "request_budget_exhausted", "snippet": ""})
            break
        last_sent = float(counter.get("last_sent", 0.0) or 0.0)
        elapsed = time.monotonic() - last_sent if last_sent else rate_limit
        if last_sent and elapsed < rate_limit:
            time.sleep(rate_limit - elapsed)
        try:
            modified = _apply_action({"url": url, "headers": headers, "body": body,
                                      "method": original_request.get("method", "GET")},
                                     action, plan.get("param"), str(value if value is not None else ""))
        except ValueError as e:
            results.append({"value": value, "status": None, "length": None,
                            "diff_vs_baseline": str(e), "snippet": ""})
            continue
        method = str(modified.get("method", "GET")).upper()
        safe_methods = {"GET", "HEAD", "OPTIONS"}
        state_changing_methods = {"POST", "PUT", "PATCH", "DELETE"}
        if method not in safe_methods and not (
                method in state_changing_methods
                and os.environ.get("LH_ALLOW_STATE_CHANGING") == "1"
                and os.environ.get("LH_CONFIRM_STATE_CHANGE") == "I_HAVE_AUTHORIZATION"):
            results.append({"value": value, "status": None, "length": None,
                            "diff_vs_baseline": "unsafe_method_blocked", "snippet": ""})
            continue
        try:
            counter["used"] += 1
            # Do not let Set-Cookie from one probe silently alter the next probe.
            session_http.cookies.clear()
            counter["last_sent"] = time.monotonic()
            kwargs = {"method": method, "url": modified["url"],
                      "headers": modified.get("headers", {}),
                      "timeout": (5, 10), "allow_redirects": False}
            if method not in safe_methods and modified.get("body", body):
                kwargs["data"] = modified.get("body", body)
            r = session_http.request(**kwargs)
            body_text = r.text
            sanitized_full = sanitize_fn(body_text) if sanitize_fn else body_text
            # Hash the same-sized preview as the stored baseline, not a full live
            # response against a truncated Burp preview.
            preview_length = original_request.get("response_preview_length")
            if not isinstance(preview_length, int) or preview_length < 0:
                preview_length = len(sanitized_full)
            comparable = sanitized_full[:preview_length]
            results.append({
                "value": value, "status": r.status_code, "length": len(r.content),
                "body_hash": hashlib.sha256(comparable.encode()).hexdigest()[:16],
                "hash_source": "sanitized_preview",
                "diff_vs_baseline": None,
                "snippet": sanitized_full[:300],
                "content_type": r.headers.get("Content-Type", "")[:120],
            })
            retry_after = r.headers.get("Retry-After")
            if r.status_code == 429 and retry_after and retry_after.isdigit():
                time.sleep(min(int(retry_after), 30))
        except requests.RequestException as e:
            results.append({"value": value, "status": None, "length": None,
                            "diff_vs_baseline": f"error:{type(e).__name__}", "snippet": ""})
    return results


def local_verdict(executed: list, baseline: dict) -> tuple[str, str]:
    """Deterministic, non-AI gate. Decides confirmed / rejected / ambiguous.
    This — not the AI's confidence score — controls whether the loop stops.

    IDOR signal: same (successful) status, DIFFERENT content for a
    different ID value — the endpoint returns per-record data without an
    ownership check. A 404 for a made-up ID is NOT evidence of anything
    (it's the expected, correct behavior) and is excluded from scoring.

    AuthBypass signal: status moves from 401/403 to 200 when auth is
    stripped.
    """
    if not executed:
        return "ambiguous", "no results to evaluate"

    reasons = [e.get("diff_vs_baseline") for e in executed]
    if any(r in ("rejected_action", "host_not_allowed") for r in reasons):
        return "rejected", f"blocked by guard: {reasons}"
    if all(r == "dry_run_not_sent" for r in reasons):
        return "ambiguous", "dry run only — no live data yet"

    auth_bypass = sum(1 for r in reasons if r == "auth_bypass_signal")
    content_differs = [e for e in executed if e.get("diff_vs_baseline") == "content_differs_same_status"]
    # Distinct content across distinct tried values is the real IDOR tell —
    # one lucky diff could be a fluke, two independently-different bodies
    # for two different ID values is a pattern.
    distinct_hashes = {e.get("body_hash") for e in content_differs if e.get("body_hash")}

    if auth_bypass >= 1:
        return "ambiguous", (f"high-signal authentication status change ({auth_bypass} response(s) returned 200); "
                              "verify that protected data/actions were actually accessible without valid credentials")
    distinct_values = {str(e.get("value")) for e in content_differs}
    # Two distinct test values with independently differing bodies are still only
    # a candidate signal; absent ownership evidence, never auto-confirm IDOR.
    if len(content_differs) >= 2 and len(distinct_hashes) >= 2 and len(distinct_values) >= 2:
        return "ambiguous", (f"{len(content_differs)} distinct responses across different values; "
                              "requires ownership/record evidence before confirmation")

    informative = [r for r in reasons if r not in ("not_found_or_denied",)]
    if not informative:
        return "ambiguous", "all tested values returned not-found/denied — inconclusive, try different IDs"
    if all(r in ("no_change", "not_found_or_denied") for r in reasons):
        return "rejected", "no meaningful difference from baseline across all tested values"
    return "ambiguous", f"partial signal, no confirmed pattern yet: {reasons}"


def fill_diffs(executed: list, baseline: dict) -> list:
    for e in executed:
        if e.get("diff_vs_baseline") in (None,):
            e["diff_vs_baseline"] = _diff_label(baseline, e)
    return executed
