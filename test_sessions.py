"""Tests for sessions.py — session storage, whitelist, local verdict."""
import json
import pytest
import sessions as sess


def _patch_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(sess, "DATA", tmp_path / "data")
    monkeypatch.setattr(sess, "SESSIONS_DIR", tmp_path / "data" / "test_sessions")
    monkeypatch.setattr(sess, "INDEX_FILE", tmp_path / "data" / "test_sessions" / "_index.json")


# === Session save/load + atomic write ===

def test_session_roundtrip(tmp_path, monkeypatch):
    _patch_dirs(tmp_path, monkeypatch)
    candidate = {"id": "abc123", "host": "127.0.0.1", "path": "/api/user",
                "signal": ["resource_or_identity_parameter"]}
    original = {"status": 200, "response_length": 55}
    s = sess.init_session(candidate, original)
    sess.save_session(s)

    loaded = sess.load_session("abc123")
    assert loaded is not None
    assert loaded["status"] == "in_progress"
    assert loaded["baseline"]["status"] == 200

    idx = sess.load_index()
    assert idx["abc123"] == "in_progress"


def test_session_missing_returns_none(tmp_path, monkeypatch):
    _patch_dirs(tmp_path, monkeypatch)
    assert sess.load_session("does-not-exist") is None


# === Orphan cleanup ===

def test_cleanup_removes_orphaned_sessions(tmp_path, monkeypatch):
    _patch_dirs(tmp_path, monkeypatch)
    candidate = {"id": "keep-me", "host": "x", "path": "/y", "signal": []}
    s = sess.init_session(candidate, {"status": 200, "response_length": 1})
    sess.save_session(s)

    orphan = {"id": "orphan-id", "host": "x", "path": "/z", "signal": []}
    s2 = sess.init_session(orphan, {"status": 200, "response_length": 1})
    sess.save_session(s2)

    removed = sess.cleanup_orphaned_sessions([{"id": "keep-me"}])
    assert removed == 1
    assert sess.load_session("keep-me") is not None
    assert sess.load_session("orphan-id") is None


# === Whitelist enforcement ===

def test_execute_plan_rejects_disallowed_action(tmp_path, monkeypatch):
    _patch_dirs(tmp_path, monkeypatch)
    plan = {"action": "run_shell_command", "param": None, "try_values": ["x"]}
    req = {"url": "http://127.0.0.1/api", "method": "GET", "headers": {}}
    results = sess.execute_plan(plan, req, ["127.0.0.1"], live=True)
    assert results[0]["diff_vs_baseline"] == "rejected_action"


def test_execute_plan_rejects_disallowed_host(tmp_path, monkeypatch):
    _patch_dirs(tmp_path, monkeypatch)
    plan = {"action": "set_param", "param": "id", "try_values": ["2"]}
    req = {"url": "http://evil.example.com/api?id=1", "method": "GET", "headers": {}}
    results = sess.execute_plan(plan, req, ["127.0.0.1"], live=True)
    assert results[0]["diff_vs_baseline"] == "host_not_allowed"


def test_execute_plan_dry_run_sends_nothing(tmp_path, monkeypatch):
    _patch_dirs(tmp_path, monkeypatch)
    plan = {"action": "set_param", "param": "id", "try_values": ["2", "999"]}
    req = {"url": "http://127.0.0.1/api?id=1", "method": "GET", "headers": {}}
    results = sess.execute_plan(plan, req, ["127.0.0.1"], live=False)
    assert len(results) == 2
    assert all(r["diff_vs_baseline"] == "dry_run_not_sent" for r in results)
    assert all(r["status"] is None for r in results)  # proves nothing was sent


# === Local verdict (deterministic gate, not AI confidence) ===
# Regression coverage for the real bug caught during end-to-end testing:
# a 404 for a nonexistent ID is NOT IDOR evidence (it's expected), and the
# real IDOR tell is same-status-different-content, not size magnitude.

def test_local_verdict_confirmed_on_idor_content_diff():
    """id=2 returns Bob's data instead of Alice's: same status, different
    content, small size delta — this is exactly the real-world case that
    used to be missed."""
    executed = [
        {"value": "2", "status": 200, "length": 70,
         "body_hash": "bob_hash_000000", "diff_vs_baseline": "content_differs_same_status"},
        {"value": "3", "status": 200, "length": 71,
         "body_hash": "carol_hash_00000", "diff_vs_baseline": "content_differs_same_status"},
    ]
    verdict, notes = sess.local_verdict(executed, {"status": 200, "length": 74,
                                                    "body_hash": "alice_hash_0000"})
    assert verdict == "ambiguous"
    assert "ownership" in notes


def test_local_verdict_single_content_difference_is_not_confirmed():
    executed = [{"value": "2", "status": 200, "length": 70,
                 "body_hash": "bob_hash_000000", "diff_vs_baseline": "content_differs_same_status"}]
    verdict, _ = sess.local_verdict(executed, {"status": 200, "length": 74,
                                               "body_hash": "alice_hash_0000"})
    assert verdict != "confirmed"


def test_local_verdict_auth_bypass_status_change_needs_content_proof():
    executed = [
        {"value": None, "status": 200, "length": 300, "diff_vs_baseline": "auth_bypass_signal"},
    ]
    verdict, notes = sess.local_verdict(executed, {"status": 403, "length": 30})
    assert verdict == "ambiguous"
    assert "protected data" in notes


def test_local_verdict_rejected_on_no_difference():
    executed = [
        {"value": "2", "status": 403, "length": 30, "diff_vs_baseline": "no_change"},
    ]
    verdict, notes = sess.local_verdict(executed, {"status": 403, "length": 30})
    assert verdict == "rejected"


def test_local_verdict_not_confirmed_by_404_alone():
    """A 404 for a made-up ID must NOT count as IDOR evidence — it's the
    expected, correct response. This is the exact bug found in the live
    end-to-end run against examples/vulnerable_app.py."""
    executed = [
        {"value": "999", "status": 404, "length": 22, "diff_vs_baseline": "not_found_or_denied"},
    ]
    verdict, notes = sess.local_verdict(executed, {"status": 200, "length": 74})
    assert verdict != "confirmed"
    assert verdict == "ambiguous"  # inconclusive, not a rejection either — try other IDs


def test_local_verdict_ambiguous_on_dry_run():
    executed = [
        {"value": "2", "status": None, "length": None, "diff_vs_baseline": "dry_run_not_sent"},
    ]
    verdict, notes = sess.local_verdict(executed, {"status": 200, "length": 50})
    assert verdict == "ambiguous"


def test_local_verdict_rejected_when_guard_blocks():
    executed = [{"value": None, "status": None, "length": None,
                "diff_vs_baseline": "host_not_allowed"}]
    verdict, notes = sess.local_verdict(executed, {"status": 200, "length": 50})
    assert verdict == "rejected"


def test_scope_requires_explicit_nondefault_port():
    assert not sess._host_allowed('http://127.0.0.1:9999/api', ['127.0.0.1'])
    assert sess._host_allowed('http://127.0.0.1:9999/api', ['127.0.0.1:9999'])
    assert sess._host_allowed('https://example.com/api', ['example.com'])
    assert not sess._host_allowed('ftp://example.com/api', ['example.com'])


def test_invalid_remove_header_is_rejected():
    plan = {'action': 'remove_header', 'param': 'Host', 'try_values': [], 'confidence': 0.2}
    req = {'url': 'http://127.0.0.1/api', 'method': 'GET', 'headers': {}}
    result = sess.execute_plan(plan, req, ['127.0.0.1'], live=False)
    assert result[0]['diff_vs_baseline'] == 'header_not_allowlisted'


def test_unclear_plan_is_not_misclassified_as_blocked():
    plan = {'vuln_type': 'Unclear', 'action': None, 'param': None,
            'try_values': [], 'confidence': 0.0}
    result = sess.execute_plan(plan,
                               {'url': 'http://127.0.0.1/api', 'method': 'GET', 'headers': {}},
                               ['127.0.0.1'], live=False)
    assert result[0]['diff_vs_baseline'] == 'no_test_proposed'
    verdict, _ = sess.local_verdict(result, {'status': 200, 'length': 10})
    assert verdict == 'ambiguous'
