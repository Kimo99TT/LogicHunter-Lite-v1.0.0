#!/usr/bin/env python3
"""LogicHunter Lite — local-first Burp XML triage + guarded, budget-aware
AI-assisted testing loop.

Pipeline (see docs/ARCHITECTURE.md):
    Burp XML -> import (sanitize + allowlist + dedupe)
             -> analyze (deterministic signals + correlation)
             -> test (AI proposes a plan as JSON; this file / sessions.py
                       is the ONLY code that ever sends a request; a local
                       deterministic verdict — not the AI's confidence —
                       decides whether a candidate is confirmed/rejected)
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any
from collections import defaultdict

try:
    import defusedxml.ElementTree as ET
except ImportError:
    print("FATAL: defusedxml required. pip install defusedxml")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("FATAL: pyyaml required. pip install pyyaml")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
CONFIG_FILE = ROOT / "config.yaml"
REQUESTS_FILE = DATA / "requests.jsonl"
CANDIDATES_FILE = DATA / "candidates.json"
FINDINGS_FILE = DATA / "findings.json"
REVIEW_QUEUE_FILE = DATA / "review_queue.json"
INDEX_FILE = DATA / "imported_hashes.json"

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie",
                     "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token"}

# Fixed: no longer matches "valid" / "paid" / "void" / "grid" / "avoid"
ID_KEYS = re.compile(
    r"(^id$|(^|_)id(_|$)|uuid|"
    r"(^|_)(account|tenant|organi[sz]ation|owner|profile|project|"
    r"invoice|order|document|record)(_|$))",
    re.I,
)

SENSITIVE_KEYS = re.compile(
    r"(token|secret|password|passwd|authorization|cookie|"
    r"api[_-]?key|session|csrf)", re.I
)
PII_KEYS = re.compile(r"(^|_)(email|e_mail|phone|mobile|telephone|ssn|social_security|card_number|credit_card)(_|$)", re.I)

STATIC_EXT = re.compile(
    r"\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|mp4|webm)(?:$|\?)", re.I
)

ADMIN_PATH_RE = re.compile(
    r"/(admin|internal|debug|actuator|manage|dashboard|superuser|root|\.git|\.env)"
    r"(/|$|\.)", re.I,
)

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\s\-()]{7,15}\d")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
API_KEY_RE = re.compile(r"\b(sk|pk|api|key)_[A-Za-z0-9]{16,}\b", re.I)


def ensure_data():
    DATA.mkdir(exist_ok=True)


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        default = {
            "allowed_hosts": ["localhost", "127.0.0.1"],
            "import": {"ignore_static": True, "max_body_preview": 3000,
                      "max_response_preview": 5000},
            "test_loop": {"max_iterations": 3, "max_requests_per_run": 30},
        }
        CONFIG_FILE.write_text(yaml.safe_dump(default, sort_keys=False),
                               encoding="utf-8")
        print(f"[config] Created default {CONFIG_FILE}. Edit allowed_hosts.")
        return default
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    if not isinstance(cfg, dict):
        raise ValueError("config.yaml must contain a YAML mapping")
    allowed = cfg.get("allowed_hosts", [])
    if not isinstance(allowed, list) or any(not isinstance(x, str) for x in allowed):
        raise ValueError("allowed_hosts must be a list of host strings; use *.example.com for explicit subdomains")
    cfg.setdefault("test_loop", {})
    cfg["test_loop"].setdefault("max_iterations", 3)
    cfg["test_loop"].setdefault("max_requests_per_run", 30)
    return cfg


def decode_text(s: str, is_base64: bool = True) -> str:
    if not s:
        return ""
    if not is_base64:
        return s
    try:
        return base64.b64decode(s, validate=True).decode("utf-8", "replace")
    except Exception:
        try:
            return base64.b64decode("".join(s.split()),
                                    validate=True).decode("utf-8", "replace")
        except Exception:
            return s


def _is_b64(elem) -> bool:
    if elem is None:
        return True
    return (elem.get("base64") or "true").lower() == "true"


def _redact_nested(value):
    """Recursively redact secret/PII fields while preserving identifiers as evidence."""
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            name = str(key)
            normalized_name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
            if SENSITIVE_KEYS.search(name) or PII_KEYS.search(normalized_name):
                out[name] = "[REDACTED]"
            else:
                out[name] = _redact_nested(child)
        return out
    if isinstance(value, list):
        return [_redact_nested(v) for v in value]
    return value


def sanitize_response_body(body: str) -> str:
    if not body:
        return ""
    structured_json = False
    try:
        parsed = json.loads(body)
        if isinstance(parsed, (dict, list)):
            body = json.dumps(_redact_nested(parsed), ensure_ascii=False, separators=(",", ":"))
            structured_json = True
    except (ValueError, TypeError):
        pass
    out = JWT_RE.sub("[JWT_REDACTED]", body)
    out = EMAIL_RE.sub("[EMAIL_REDACTED]", out)
    out = API_KEY_RE.sub("[API_KEY_REDACTED]", out)
    # Broad phone/card regexes can accidentally erase long numeric object IDs.
    # For structured JSON, key-aware redaction is safer and preserves IDOR evidence.
    if not structured_json:
        out = SSN_RE.sub("[SSN_REDACTED]", out)
        out = CC_RE.sub("[CARD_REDACTED]", out)
        out = PHONE_RE.sub("[PHONE_REDACTED]", out)
    return out


def sanitize_response_header(name: str, value: str) -> str:
    """Redact cookie values but preserve security attributes for header analysis."""
    key = name.lower()
    if key == "set-cookie":
        parts = [part.strip() for part in value.split(";") if part.strip()]
        if not parts:
            return "[REDACTED]"
        first = parts[0].split("=", 1)[0].strip() or "cookie"
        attrs = []
        for part in parts[1:]:
            low = part.lower()
            if low in {"secure", "httponly"} or low.startswith("samesite="):
                attrs.append(part)
        return "; ".join([f"{first}=[REDACTED]"] + attrs)[:500]
    if key in SENSITIVE_HEADERS:
        return "[REDACTED]"
    return value[:500]


def sanitize_request_body(body: str, ctype: str) -> str:
    if not body:
        return ""
    if "json" in ctype.lower():
        try:
            obj = json.loads(body)
            return json.dumps(_redact_nested(obj), ensure_ascii=False)[:3000]
        except (ValueError, TypeError):
            pass
    if "form-urlencoded" in ctype.lower():
        try:
            parts = urllib.parse.parse_qsl(body, keep_blank_values=True)
            cleaned = [(k, "[REDACTED]" if SENSITIVE_KEYS.search(k) else v)
                       for k, v in parts]
            return urllib.parse.urlencode(cleaned)[:3000]
        except (ValueError, TypeError):
            pass
    # For unknown content types do not persist arbitrary body bytes as they may contain secrets.
    return "[BODY_OMITTED_UNRECOGNIZED_CONTENT_TYPE]" if body else ""


def redact_value(key: str, value: str) -> str:
    if SENSITIVE_KEYS.search(key):
        return "[REDACTED]"
    return value[:1000]


def parse_http(raw: str) -> dict[str, Any]:
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    start = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"start_line": start, "headers": headers, "body": body[:20000]}


def fingerprint(rec):
    stable = {
        "host": rec.get("host"), "method": rec.get("method"),
        "path": rec.get("path"),
        "qkeys": sorted(p["key"] for p in rec.get("query_params", [])),
        "bkeys": sorted(p["key"] for p in rec.get("body_params", [])),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()[:20]


def raw_hash(req_raw: str, resp_raw: str) -> str:
    return hashlib.sha256((req_raw + "|" + resp_raw).encode()).hexdigest()[:32]


def load_import_index() -> set:
    if not INDEX_FILE.exists():
        return set()
    try:
        data = json.loads(INDEX_FILE.read_text(encoding="utf-8"))
        return set(data) if isinstance(data, list) else set()
    except Exception:
        return set()


def save_import_index(hashes: set):
    INDEX_FILE.write_text(json.dumps(sorted(hashes), indent=2), encoding="utf-8")


def host_allowed(host: str, allowed: list) -> bool:
    """Fail-closed hostname allowlist; subdomains need an explicit *.domain entry."""
    if not allowed or not host:
        return False
    host_l = str(host).strip().lower().rstrip(".")
    # Imported Burp host may be host:port; normalize only unambiguous DNS names.
    if host_l.startswith("[") and "]" in host_l:
        host_l = host_l[1:host_l.index("]")]
    elif host_l.count(":") == 1:
        host_l = host_l.rsplit(":", 1)[0]
    for entry in allowed:
        item = str(entry).strip().lower().rstrip(".")
        if item.startswith("*."):
            suffix = item[2:]
            if host_l != suffix and host_l.endswith("." + suffix):
                return True
        elif host_l == item:
            return True
    return False


def _parse_burp_timestamp(value, fallback_index=0):
    """Parse Burp timestamp (epoch seconds/ms or ISO-8601); fallback stays ordered."""
    from datetime import datetime, timezone
    if value:
        try:
            n = float(value)
            if n > 10_000_000_000:
                n /= 1000
            if n > 0:
                return int(n)
        except (TypeError, ValueError):
            pass
        try:
            dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except (TypeError, ValueError, OverflowError):
            pass
    # Stable, monotonic fallback; never pretend this is the original capture time.
    return int(time.time()) + int(fallback_index)


def parse_burp_xml(path: Path, account_role: str = "unknown", principal_id: str | None = None) -> list[dict[str, Any]]:
    """Safe Burp XML parse (XXE-protected via defusedxml). Reads the
    base64 attribute per element instead of guessing."""
    tree = ET.parse(path)
    root = tree.getroot()
    items = []
    for item in root.findall(".//item"):
        burp_time = item.findtext("time") or item.findtext("timestamp")
        url = (item.findtext("url") or "").strip()
        method = (item.findtext("method") or "").strip().upper()
        host = (item.findtext("host") or urllib.parse.urlparse(url).netloc).strip()

        req_elem = item.find("request")
        resp_elem = item.find("response")
        req_raw = decode_text(item.findtext("request") or "", is_base64=_is_b64(req_elem))
        resp_raw = decode_text(item.findtext("response") or "", is_base64=_is_b64(resp_elem))

        req = parse_http(req_raw)
        resp = parse_http(resp_raw)
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        params = [{"key": k, "value": redact_value(k, v)} for k, v in query]

        body_params = []
        ctype = req["headers"].get("content-type", "")
        if "application/x-www-form-urlencoded" in ctype:
            body_params = [
                {"key": k, "value": redact_value(k, v)}
                for k, v in urllib.parse.parse_qsl(req["body"], keep_blank_values=True)
            ]
        elif "json" in ctype:
            try:
                obj = json.loads(req["body"])
                if isinstance(obj, dict):
                    body_params = [
                        {"key": str(k), "value": redact_value(
                            str(k),
                            json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
                        )}
                        for k, v in obj.items()
                    ]
            except Exception:
                pass

        status_match = re.match(r"HTTP/\S+\s+(\d{3})", resp["start_line"])
        response_body_raw = resp["body"][:20000]

        rec = {
            "timestamp": _parse_burp_timestamp(burp_time, len(items)),
            "timestamp_source": "burp" if burp_time else "import_order_fallback",
            "account_role": account_role if account_role in {"attacker", "victim", "unknown"} else "unknown",
            "account_principal_id": str(principal_id).strip()[:128] if principal_id else None,
            "url": url, "host": host, "method": method,
            "path": urllib.parse.urlunsplit(("", "", parsed.path or "/", "", "")),
            "query_params": params, "body_params": body_params,
            "request_headers": {
                k: ("[REDACTED]" if k in SENSITIVE_HEADERS else v[:500])
                for k, v in req["headers"].items()
            },
            "request_body_preview": sanitize_request_body(req["body"], ctype),
            # Raw evidence is stored only when the operator explicitly opts in.
            # This may include test credentials and must never be committed/shared.
            "status": int(status_match.group(1)) if status_match else None,
            "response_headers": {
                k: sanitize_response_header(k, v)
                for k, v in resp["headers"].items()
            },
            "response_body_preview": sanitize_response_body(response_body_raw)[:5000],
            "response_length": len(response_body_raw),
            "mime_type": resp["headers"].get("content-type", ""),
            "_raw_hash": raw_hash(req_raw, resp_raw),
        }
        if os.environ.get("LH_STORE_RAW_EVIDENCE", "0") == "1":
            rec["_raw_evidence"] = {
                "request": req_raw[:16000],
                "response": resp_raw[:16000],
                "truncated": len(req_raw) > 16000 or len(resp_raw) > 16000,
            }
        rec["fingerprint"] = fingerprint(rec)
        items.append(rec)
    return items


def import_burp(path: Path, account_role: str = "unknown", principal_id: str | None = None):
    ensure_data()
    cfg = load_config()
    allowed = cfg.get("allowed_hosts", [])
    if not allowed:
        print("[config] allowed_hosts empty. Edit config.yaml first.")
        return

    items = parse_burp_xml(path, account_role=account_role, principal_id=principal_id)
    existing = load_import_index()
    imported = rejected = dup = 0
    accepted = set()

    with REQUESTS_FILE.open("a", encoding="utf-8") as f:
        try:
            REQUESTS_FILE.chmod(0o600)
        except OSError:
            pass
        for item in items:
            if not host_allowed(item.get("host", ""), allowed):
                rejected += 1
                continue
            # Include the explicit role in dedupe identity: identical requests
            # captured under attacker/victim test accounts are distinct evidence.
            h = hashlib.sha256((account_role + ":" + str(principal_id or "") + ":" + item["_raw_hash"]).encode()).hexdigest()
            if h in existing:
                dup += 1
                continue
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
            accepted.add(h)
            imported += 1

    save_import_index(existing | accepted)
    print(f"Imported {imported} items")
    if rejected:
        print(f"Skipped {rejected} (host not allowed)")
    if dup:
        print(f"Skipped {dup} duplicates")


def load_requests():
    if not REQUESTS_FILE.exists():
        return []
    out = []
    for line in REQUESTS_FILE.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    import context_engine
    return context_engine.chronological(out)


def _summarize_signals(reasons):
    return [r["signal"] for r in reasons]


def _hypothesize(reasons):
    signals = {r["signal"] for r in reasons}
    if "resource_or_identity_parameter" in signals and "authorization_response" in signals:
        return "possible_access_control_issue"
    if "resource_or_identity_parameter" in signals:
        return "possible_idor_requires_verification"
    if "admin_or_debug_path" in signals:
        return "possible_exposed_admin_surface"
    if "cors_wildcard" in signals:
        return "possible_cors_misconfiguration"
    if "insecure_cookie_flags" in signals:
        return "possible_session_hygiene_issue"
    if "error_disclosure_candidate" in signals:
        return "possible_information_disclosure"
    return "needs_human_review"


def _request_has_auth(r) -> bool:
    h = r.get("request_headers", {})
    return bool(h.get("cookie")) or bool(h.get("authorization"))


def analyze_correlations(items, seen):
    groups = defaultdict(list)
    for r in items:
        groups[(r.get("host"), r.get("method"), r.get("path"))].append(r)

    correlations = []
    for key, group in groups.items():
        if len(group) < 2:
            continue

        id_values = defaultdict(set)
        for r in group:
            for p in r.get("query_params", []) + r.get("body_params", []):
                if ID_KEYS.search(p["key"]) and p["value"] and p["value"] != "[REDACTED]":
                    id_values[p["key"]].add(p["value"])

        for param_key, values in id_values.items():
            if len(values) < 2:
                continue
            statuses = {r.get("status") for r in group if r.get("status") is not None}
            lengths = {r.get("response_length") for r in group
                      if r.get("response_length") is not None}
            if len(statuses) > 1 or len(lengths) > 1:
                fp = hashlib.sha256(f"corr_idor:{key}:{param_key}".encode()).hexdigest()[:20]
                if fp in seen:
                    continue
                seen.add(fp)
                correlations.append({
                    "id": fp, "classification": "needs_review", "confidence": 0,
                    "host": key[0], "method": key[1], "path": key[2], "status": None,
                    "signals": [{"signal": "potential_idor_multi_value", "details": {
                        "param": param_key, "distinct_values": sorted(values)[:10],
                        "statuses_observed": list(statuses),
                        "response_lengths_observed": list(lengths)[:10],
                    }}],
                    "parameter_names": [param_key],
                    "source_fingerprint": next((r.get("fingerprint") for r in group
                                                 if any(p.get("key") == param_key
                                                        for p in r.get("query_params", []) + r.get("body_params", []))), None),
                    "correlation_fingerprints": [r.get("fingerprint") for r in group if r.get("fingerprint")],
                    "signal": ["potential_idor_multi_value"],
                    "hypothesis": "possible_idor_requires_verification",
                    "evidence": None,
                    "note": "Same endpoint, different IDs, different responses. Verify manually.",
                })

        authed = [r for r in group if _request_has_auth(r)]
        unauth = [r for r in group if not _request_has_auth(r)]
        if authed and unauth:
            for r_a in authed:
                for r_u in unauth:
                    if (r_a.get("status") == r_u.get("status") == 200
                            and r_a.get("response_length") is not None
                            and r_u.get("response_length") is not None
                            and abs(r_a["response_length"] - r_u["response_length"]) <= 20):
                        fp = hashlib.sha256(f"corr_noauth:{key}".encode()).hexdigest()[:20]
                        if fp in seen:
                            break
                        seen.add(fp)
                        correlations.append({
                            "id": fp, "classification": "needs_review", "confidence": 0,
                            "host": key[0], "method": key[1], "path": key[2],
                            "status": r_a.get("status"),
                            "signals": [{"signal": "potential_missing_auth", "details": {
                                "reason": "same status/length with and without auth",
                                "with_auth_len": r_a.get("response_length"),
                                "without_auth_len": r_u.get("response_length"),
                            }}],
                            "parameter_names": [],
                            "source_fingerprint": r_a.get("fingerprint"),
                            "correlation_fingerprints": [r_a.get("fingerprint"), r_u.get("fingerprint")],
                            "signal": ["potential_missing_auth"],
                            "hypothesis": "possible_missing_authentication",
                            "evidence": None,
                            "note": "Endpoint returns similar response with and without auth.",
                        })
                        break
    return correlations


def analyze(items, persist: bool = True):
    """Analyze imported records. With persist=False, avoid modifying project state (used by tests)."""
    import signal_plugins
    signal_plugins.load_external_plugins()
    candidates = []
    seen = set()

    for r in items:
        if STATIC_EXT.search(r.get("path", "")):
            continue
        reasons = []
        params = r.get("query_params", []) + r.get("body_params", [])
        id_params = [p["key"] for p in params if ID_KEYS.search(p["key"])]
        if id_params:
            reasons.append({"signal": "resource_or_identity_parameter",
                            "details": sorted(set(id_params))})
        if r.get("status") in (401, 403):
            reasons.append({"signal": "authorization_response",
                            "details": {"status": r.get("status")}})
        if r.get("status") in (500, 502, 503):
            reasons.append({"signal": "server_error",
                            "details": {"status": r.get("status")}})

        text = (r.get("response_body_preview") or "").lower()
        error_terms = [x for x in ("stack trace", "traceback", "sql syntax",
                                   "exception", "internal server error", "debug=true")
                      if x in text]
        if error_terms:
            reasons.append({"signal": "error_disclosure_candidate", "details": error_terms})

        if any(k in r.get("request_headers", {}) for k in ("origin", "referer")):
            reasons.append({"signal": "browser_context_headers",
                            "details": [k for k in ("origin", "referer")
                                       if k in r.get("request_headers", {})]})

        if ADMIN_PATH_RE.search(r.get("path", "")):
            reasons.append({"signal": "admin_or_debug_path", "details": {"path": r.get("path")}})

        resp_h = {k.lower(): v for k, v in r.get("response_headers", {}).items()}
        if resp_h.get("access-control-allow-origin", "").strip() == "*":
            reasons.append({"signal": "cors_wildcard", "details": {"acao": "*"}})

        mime = (r.get("mime_type") or "").lower()
        if "html" in mime and r.get("status", 0) == 200:
            missing = [h for h in ("content-security-policy", "x-frame-options",
                                   "strict-transport-security", "x-content-type-options")
                      if h not in resp_h]
            if missing:
                reasons.append({"signal": "missing_security_headers", "details": missing})

        sc = resp_h.get("set-cookie", "")
        if sc:
            issues = []
            if "secure" not in sc.lower():
                issues.append("no_secure")
            if "httponly" not in sc.lower():
                issues.append("no_httponly")
            if "samesite" not in sc.lower():
                issues.append("no_samesite")
            if issues:
                reasons.append({"signal": "insecure_cookie_flags", "details": issues})

        for plugin_signal in signal_plugins.run_plugins(r):
            reasons.append({"signal": plugin_signal["signal"], "details": plugin_signal.get("details", {}),
                            "source": plugin_signal.get("source", "passive_plugin"),
                            "plugin": plugin_signal.get("plugin")})

        if not reasons:
            continue

        fp = hashlib.sha256(
            (r["fingerprint"] + json.dumps(reasons, sort_keys=True)).encode()
        ).hexdigest()[:20]
        if fp in seen:
            continue
        seen.add(fp)

        hypothesis = _hypothesize(reasons)
        note = "Heuristic signal only; not a confirmed vulnerability."
        if ADMIN_PATH_RE.search(r.get("path", "")) and r.get("status") in (401, 403):
            hypothesis = "admin_surface_access_controlled"
            note = "Admin/debug path returned 401/403; this is not evidence of exposure."

        candidates.append({
            "id": fp, "classification": "needs_review", "confidence": 0,
            "host": r.get("host"), "method": r.get("method"), "path": r.get("path"),
            "status": r.get("status"), "signals": reasons,
            "parameter_names": sorted(set(p["key"] for p in params)),
            "response_length": r.get("response_length"), "mime_type": r.get("mime_type"),
            "source_fingerprint": r.get("fingerprint"),
            "signal": _summarize_signals(reasons),
            "hypothesis": hypothesis,
            "evidence": None,
            "note": note,
        })

    candidates.extend(analyze_correlations(items, seen))
    if not persist:
        return candidates
    # Persist an explainable relationship graph so later test plans can reason
    # across related endpoints/candidates rather than treating every signal alone.
    import adaptive
    adaptive.build_context_graph(candidates, items)
    CANDIDATES_FILE.write_text(json.dumps(candidates, indent=2, ensure_ascii=False),
                               encoding="utf-8")
    import context_engine
    context_engine_path = DATA / "site_context.json"
    context_engine_path.write_text(json.dumps(context_engine.build_site_context(items), indent=2, ensure_ascii=False), encoding="utf-8")
    import workflow_engine
    workflow_path = DATA / "workflow_model.json"
    workflow_path.write_text(json.dumps(workflow_engine.build_workflow_model(items), indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        workflow_path.chmod(0o600)
    except OSError:
        pass
    try:
        context_engine_path.chmod(0o600)
    except OSError:
        pass
    print(f"Generated {len(candidates)} review candidates; context graph and compact site context saved")
    return candidates


def report():
    ensure_data()
    candidates = json.loads(CANDIDATES_FILE.read_text(encoding="utf-8")) \
        if CANDIDATES_FILE.exists() else []
    findings = json.loads(FINDINGS_FILE.read_text(encoding="utf-8")) \
        if FINDINGS_FILE.exists() else []
    review_queue = json.loads(REVIEW_QUEUE_FILE.read_text(encoding="utf-8")) \
        if REVIEW_QUEUE_FILE.exists() else []
    print(f"Requests: {len(load_requests())}")
    print(f"Candidates: {len(candidates)}")
    print(f"Confirmed findings: {len(findings)}")
    print(f"Needs manual review: {len(review_queue)}")
    print()
    for c in candidates[:200]:
        sig = ",".join(c.get("signal", []))
        print(f"- [{c['id']}] {c['method']} {c['host']}{c['path']} "
              f"status={c['status']} signals={sig} hyp={c.get('hypothesis','')}")


# --- Guarded AI-assisted test loop ---

def _find_original_request(candidate, requests_data):
    source_fps = [candidate.get("source_fingerprint")]
    source_fps.extend(candidate.get("correlation_fingerprints", []))
    by_fp = {r.get("fingerprint"): r for r in requests_data if r.get("fingerprint")}
    for src_fp in source_fps:
        if src_fp and src_fp in by_fp:
            return by_fp[src_fp]
    return None


def run_test_loop(candidates: list, requests_data: list, live: bool,
                  rate_limit: float, max_candidates: int | None = None):
    import providers
    import sessions as sess

    cfg = load_config()
    allowed_hosts = cfg.get("allowed_hosts", [])
    test_cfg = cfg.get("test_loop", {})
    max_iterations = int(test_cfg.get("max_iterations", 3))
    request_budget = max(1, min(int(test_cfg.get("max_requests_per_run", 30)), 30))
    request_counter = {"used": 0, "limit": request_budget}

    removed = sess.cleanup_orphaned_sessions(candidates)
    if removed:
        print(f"[cleanup] removed {removed} orphaned session file(s)")

    budget = providers.load_budget()
    import adaptive
    pending = adaptive.rank_candidates([c for c in candidates if c.get("classification") == "needs_review"])
    if max_candidates is not None:
        pending = pending[:max(0, int(max_candidates))]

    for cand in pending:
        session = sess.load_session(cand["id"])
        if session is None:
            original = _find_original_request(cand, requests_data)
            if not original:
                print(f"[{cand['id']}] no source request found — skip")
                continue
            session = sess.init_session(cand, original, max_iterations)
            session["related_context"] = adaptive.related_context(cand["id"])
            sess.save_session(session)

        # Refresh graph context for resumed sessions too, so new imported traffic
        # can influence the next plan without resetting the stored test history.
        session["related_context"] = adaptive.related_context(cand["id"])
        if session["status"] != "in_progress":
            print(f"[{cand['id']}] status={session['status']} (already decided) — skip")
            continue
        if session["iterations_used"] >= session["max_iterations"]:
            session["status"] = "needs_manual_review"
            sess.save_session(session)
            _record_review_candidate(cand, session)
            print(f"[{cand['id']}] needs_manual_review (iteration cap reached; inconclusive, not a rejection)")
            continue

        gemini_only = (os.environ.get("LH_GEMINI_ONLY", "0") == "1" or
                       os.environ.get("LH_GEMINI_SEND_RAW_EVIDENCE", "0") == "1")
        available = sorted(
            ((name, item) for name, item in budget.get("providers", {}).items()
             if item.get("calls_used", 0) < item.get("calls_limit", 0)
             and providers.is_configured(name)
             and (not gemini_only or name == "gemini")),
            key=lambda pair: pair[1].get("priority", 999),
        )
        if not available:
            configured = [name for name in budget.get("providers", {}) if providers.is_configured(name)]
            if not configured:
                print("No LLM provider API key configured. Set GEMINI_API_KEY or another supported provider key.")
            else:
                print("No provider budget left today for configured providers. Stopping.")
            break

        import context_engine
        site_context = context_engine.build_site_context(requests_data)
        session["site_context_compact"] = context_engine.compact_focus(
            site_context, str(cand.get("host", "")), str(cand.get("path", "")))
        # Gemini can receive full captured HTTP evidence only when the operator
        # opted in both when importing and when running the analysis. Raw evidence
        # is not copied into the persistent session/history files.
        if os.environ.get("LH_GEMINI_SEND_RAW_EVIDENCE", "0") == "1":
            original_for_evidence = _find_original_request(cand, requests_data)
            if original_for_evidence and original_for_evidence.get("_raw_evidence"):
                session["raw_evidence_for_prompt"] = original_for_evidence["_raw_evidence"]
        prompt = providers.build_context_prompt(session)
        session.pop("raw_evidence_for_prompt", None)
        plan = None
        provider = None
        # Fail over within this candidate. Count each actual API attempt, including
        # failed requests, so local budgets do not under-report usage.
        for provider_name, _provider_cfg in available:
            try:
                plan = providers.call_ai_provider(provider_name, prompt)
                provider = provider_name
                providers.record_call(budget, provider_name)
                break
            except Exception as e:
                providers.record_call(budget, provider_name)
                if isinstance(e, getattr(providers, "ProviderQuotaError", ())):
                    # Persist a local circuit-breaker for the rest of today's run.
                    # Never retry the same exhausted quota on every candidate.
                    budget["providers"][provider_name]["calls_used"] = budget["providers"][provider_name]["calls_limit"]
                    providers.save_budget(budget)
                    print(f"[{cand['id']}] provider {provider_name} quota reached; disabled for this budget window")
                else:
                    print(f"[{cand['id']}] provider {provider_name} call failed: "
                          f"{type(e).__name__}: {e}; trying next provider")
        if plan is None or provider is None:
            continue

        original = _find_original_request(cand, requests_data)
        if not original:
            print(f"[{cand['id']}] source request vanished — skip")
            continue
        orig_request_for_exec = {
            "url": original["url"],
            "method": original["method"],
            "headers": {k: v for k, v in original.get("request_headers", {}).items()
                       if v != "[REDACTED]"},
            "body": original.get("request_body_preview", ""),
            "response_preview_length": len(original.get("response_body_preview", "") or ""),
        }

        executed = sess.execute_plan(
            plan, orig_request_for_exec, allowed_hosts, live=live,
            rate_limit=rate_limit, sanitize_fn=sanitize_response_body,
            request_budget=request_budget, request_counter=request_counter,
        )
        executed = sess.fill_diffs(executed, session["baseline"])
        verdict, notes = sess.local_verdict(executed, session["baseline"])

        adaptive.record_outcome(cand, plan, verdict, notes)
        session["history"].append({
            "iteration": session["iterations_used"] + 1,
            "provider": provider,
            "timestamp": int(time.time()),
            "plan": plan,
            "executed": executed,
            "local_verdict": verdict,
            "local_notes": notes,
        })
        session["iterations_used"] += 1
        session["status"] = ("confirmed" if verdict == "confirmed" else
                             "rejected" if verdict == "rejected" else
                             "needs_manual_review" if session["iterations_used"] >= session["max_iterations"]
                             else "in_progress")
        sess.save_session(session)

        print(f"[{cand['id']}] provider={provider} verdict={verdict} "
              f"({'LIVE' if live else 'DRY-RUN'}) — {notes}")

        if session["status"] == "confirmed":
            _record_finding(cand, session)
            _remove_review_candidate(cand.get("id"))
        elif session["status"] == "rejected":
            _remove_review_candidate(cand.get("id"))
        elif verdict == "ambiguous" or session["status"] == "needs_manual_review":
            _record_review_candidate(cand, session)

    print()
    print(f"Budget used today: " +
          ", ".join(f"{n}={p['calls_used']}/{p['calls_limit']}"
                    for n, p in budget["providers"].items()))


def _record_finding(candidate, session):
    ensure_data()
    findings = json.loads(FINDINGS_FILE.read_text(encoding="utf-8")) \
        if FINDINGS_FILE.exists() else []
    last = session["history"][-1]
    if any(f.get("candidate_id") == candidate.get("id") for f in findings):
        return
    findings.append({
        "candidate_id": candidate["id"],
        "host": candidate["host"], "path": candidate["path"],
        "method": candidate["method"],
        "vuln_type": last["plan"].get("vuln_type"),
        "confidence_ai": last["plan"].get("confidence"),
        "local_verdict": last["local_verdict"],
        "local_notes": last["local_notes"],
        "iterations_used": session["iterations_used"],
        "evidence": last["executed"],
        "confirmed_at": int(time.time()),
    })
    FINDINGS_FILE.write_text(json.dumps(findings, indent=2, ensure_ascii=False),
                             encoding="utf-8")



def _record_review_candidate(candidate, session):
    """Persist ambiguous/high-signal cases without mislabeling them as confirmed."""
    ensure_data()
    queue = json.loads(REVIEW_QUEUE_FILE.read_text(encoding="utf-8")) \
        if REVIEW_QUEUE_FILE.exists() else []
    last = session.get("history", [])[-1] if session.get("history") else {}
    entry = {
        "candidate_id": candidate.get("id"),
        "host": candidate.get("host"),
        "path": candidate.get("path"),
        "method": candidate.get("method"),
        "hypothesis": candidate.get("hypothesis"),
        "status": session.get("status", "in_progress"),
        "local_verdict": last.get("local_verdict", "ambiguous"),
        "local_notes": last.get("local_notes", "iteration cap reached without conclusive evidence"),
        "evidence": last.get("executed", []),
        "plan": last.get("plan", {}),
        "updated_at": int(time.time()),
    }
    for index, old in enumerate(queue):
        if old.get("candidate_id") == candidate.get("id"):
            queue[index] = entry
            break
    else:
        queue.append(entry)
    tmp = REVIEW_QUEUE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(queue, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    tmp.replace(REVIEW_QUEUE_FILE)


def _remove_review_candidate(candidate_id):
    if not REVIEW_QUEUE_FILE.exists():
        return
    try:
        queue = json.loads(REVIEW_QUEUE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    queue = [item for item in queue if item.get("candidate_id") != candidate_id]
    tmp = REVIEW_QUEUE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(queue, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    tmp.replace(REVIEW_QUEUE_FILE)

def report_sessions():
    import sessions as sess
    idx = sess.load_index()
    if not idx:
        print("No test sessions yet. Run `test` first.")
        return
    counts = {"in_progress": 0, "confirmed": 0, "rejected": 0, "needs_manual_review": 0}
    for status in idx.values():
        counts[status] = counts.get(status, 0) + 1
    print(f"Sessions: {len(idx)} total | confirmed={counts.get('confirmed',0)} "
          f"rejected={counts.get('rejected',0)} in_progress={counts.get('in_progress',0)} "
          f"needs_manual_review={counts.get('needs_manual_review',0)}")


def main():
    p = argparse.ArgumentParser(description="LogicHunter Lite")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("import-burp")
    i.add_argument("file", type=Path)
    i.add_argument("--role", choices=("attacker", "victim", "unknown"), default="unknown",
                   help="Label every request in this export; export accounts separately for reliable attribution")
    i.add_argument("--principal-id", default=None,
                   help="Optional known account/user ID for this export; never use a password or session token")

    sub.add_parser("analyze")
    sub.add_parser("report")
    sub.add_parser("report-sessions")
    sub.add_parser("context-report", help="Show compact chronological site context")
    sub.add_parser("workflow-report", help="Infer chronological workflows and cross-role differences")
    sub.add_parser("benchmark", help="Run deterministic offline workflow/ownership benchmark")
    sub.add_parser("lab-benchmark", help="Exercise vulnerable and secure fixtures on loopback only")
    sub.add_parser("adaptive-report", help="Show learned outcome statistics and context-graph size")
    sub.add_parser("improvement-plan", help="Generate reviewable self-improvement proposals from local outcomes")
    sub.add_parser("report-review-queue", help="List high-signal/inconclusive cases for manual validation")
    sub.add_parser("check-detection", help="Run deterministic synthetic signal regression checks (not real-world accuracy)")
    sub.add_parser("list-signal-plugins", help="List built-in and explicitly loaded trusted local signal plugins")

    a = sub.add_parser("agent", help="Gemini-led bounded manager loop with checkpoints and reviewable change proposals")
    a.add_argument("--max-steps", type=int, default=8, help="Maximum manager decisions this run (1..20)")
    a.add_argument("--live", action="store_true", help="Allow guarded live tests only for configured allowed_hosts")
    a.add_argument("--rate-limit", type=float, default=1.0)
    a.add_argument("--no-resume", action="store_true", help="Start a fresh manager state instead of resuming the checkpoint")

    t = sub.add_parser("test", help="Guarded AI-assisted test loop")
    t.add_argument("--live", action="store_true",
                   help="Actually send requests. Without this flag: dry-run only.")
    t.add_argument("--rate-limit", type=float, default=1.0)
    t.add_argument("--max-candidates", type=int, default=None,
                   help="Sanity cap on how many candidates to process this run")

    args = p.parse_args()
    if args.cmd == "import-burp":
        import_burp(args.file, account_role=args.role, principal_id=args.principal_id)
    elif args.cmd == "analyze":
        analyze(load_requests())
    elif args.cmd == "report":
        report()
    elif args.cmd == "report-sessions":
        report_sessions()
    elif args.cmd == "context-report":
        import context_engine
        ctx = context_engine.build_site_context(load_requests())
        print(json.dumps({"request_count": ctx["request_count"], "role_counts": ctx["role_counts"],
                          "common_parameters": ctx["common_parameters"],
                          "endpoints": ctx["endpoints"][:25], "recent_timeline": ctx["chronology"][-20:]},
                         ensure_ascii=False, indent=2))
    elif args.cmd == "workflow-report":
        import workflow_engine
        records = load_requests()
        model = workflow_engine.build_workflow_model(records)
        findings = workflow_engine.rank_cross_role_hypotheses(records)
        print(json.dumps({"workflow": model, "cross_role_hypotheses": findings}, ensure_ascii=False, indent=2))
    elif args.cmd == "benchmark":
        import workflow_engine
        result = workflow_engine.benchmark()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result["failed"]:
            raise SystemExit(1)
    elif args.cmd == "lab-benchmark":
        import workflow_engine
        result = workflow_engine.run_local_lab_benchmark()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result["failed"]:
            raise SystemExit(1)
    elif args.cmd == "adaptive-report":
        import adaptive
        stats = adaptive.report()
        print(f"Context graph: {stats['graph_nodes']} nodes / {stats['graph_edges']} relationships")
        print(f"Recorded outcomes: {stats['observations']}")
        print("Signal outcomes:")
        for signal, counts in sorted(stats["signal_outcomes"].items()):
            print(f"- {signal}: confirmed={counts.get('confirmed',0)} rejected={counts.get('rejected',0)} ambiguous={counts.get('ambiguous',0)}")
        print("Action outcomes:")
        for action, counts in sorted(stats["action_outcomes"].items()):
            print(f"- {action}: confirmed={counts.get('confirmed',0)} rejected={counts.get('rejected',0)} ambiguous={counts.get('ambiguous',0)}")
    elif args.cmd == "improvement-plan":
        import adaptive
        proposals = adaptive.improvement_plan()
        print(f"Improvement proposals: {len(proposals)} (none are applied automatically)")
        for item in proposals:
            print(f"- [{item['priority']}] {item['area']}: {item['trigger']}\n  {item['proposal']}")
    elif args.cmd == "check-detection":
        import fixture_generator
        result = fixture_generator.check_detection_quality(lambda records: analyze(records, persist=False))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result["failed"]:
            raise SystemExit(1)
    elif args.cmd == "list-signal-plugins":
        import signal_plugins
        signal_plugins.load_external_plugins()
        print(json.dumps({"plugins": signal_plugins.list_plugins(),
                          "external_plugins_enabled": os.environ.get("LH_ENABLE_EXTERNAL_PLUGINS", "0").lower() in {"1", "true", "yes"}}, indent=2))
    elif args.cmd == "report-review-queue":
        ensure_data()
        queue = json.loads(REVIEW_QUEUE_FILE.read_text(encoding="utf-8")) if REVIEW_QUEUE_FILE.exists() else []
        print(f"Manual review queue: {len(queue)}")
        for item in queue:
            print(f"- [{item.get('candidate_id')}] {item.get('method')} {item.get('host')}{item.get('path')} "
                  f"hypothesis={item.get('hypothesis')} note={item.get('local_notes')}")
    elif args.cmd == "agent":
        ensure_data()
        import agent_manager
        state = agent_manager.run(max_steps=max(1, min(args.max_steps, 20)), live=args.live,
                                  rate_limit=max(0.2, args.rate_limit), resume=not args.no_resume)
        print(json.dumps({"run_id": state.get("run_id"), "status": state.get("status"),
                          "step": state.get("step"), "last_action": state.get("last_action")}, ensure_ascii=False, indent=2))
    elif args.cmd == "test":
        ensure_data()
        candidates = json.loads(CANDIDATES_FILE.read_text(encoding="utf-8")) \
            if CANDIDATES_FILE.exists() else []
        if not candidates:
            print("No candidates. Run analyze first.")
            sys.exit(1)
        if not args.live:
            print("[dry-run] No requests will be sent. Pass --live to send real traffic.\n")
        run_test_loop(candidates, load_requests(), live=args.live,
                      rate_limit=args.rate_limit, max_candidates=args.max_candidates)


if __name__ == "__main__":
    main()
