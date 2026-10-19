import json
from pathlib import Path

import adaptive


def test_graph_links_related_candidates_and_does_not_store_bodies(tmp_path, monkeypatch):
    monkeypatch.setattr(adaptive, "DATA", tmp_path)
    monkeypatch.setattr(adaptive, "GRAPH_FILE", tmp_path / "context_graph.json")
    candidates = [
        {"id": "a", "host": "lab.local", "method": "GET", "path": "/api/users/12",
         "signal": ["resource_or_identity_parameter"], "parameter_names": ["user_id"],
         "hypothesis": "possible_idor_requires_verification", "source_fingerprint": "f1"},
        {"id": "b", "host": "lab.local", "method": "GET", "path": "/api/users/13",
         "signal": ["resource_or_identity_parameter", "authorization_response"], "parameter_names": ["user_id"],
         "hypothesis": "possible_access_control_issue", "source_fingerprint": "f2"},
        {"id": "c", "host": "other.local", "method": "GET", "path": "/api/users/13",
         "signal": ["other"], "parameter_names": [], "hypothesis": "review", "source_fingerprint": "f3"},
    ]
    graph = adaptive.build_context_graph(candidates)
    assert len(graph["nodes"]) == 3
    assert any({e["source"], e["target"]} == {"a", "b"} for e in graph["edges"])
    related = adaptive.related_context("a")
    assert related and related[0]["candidate_id"] == "b"
    raw = (tmp_path / "context_graph.json").read_text()
    assert "response_body" not in raw and "Authorization:" not in raw


def test_outcome_memory_updates_signal_and_action_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(adaptive, "DATA", tmp_path)
    monkeypatch.setattr(adaptive, "MEMORY_FILE", tmp_path / "adaptive_memory.json")
    c = {"id": "abc", "signal": ["potential_idor_multi_value"]}
    adaptive.record_outcome(c, {"action": "set_param"}, "ambiguous", "needs ownership proof")
    adaptive.record_outcome(c, {"action": "set_param"}, "confirmed", "lab ownership evidence")
    report = adaptive.report()
    assert report["observations"] == 2
    assert report["signal_outcomes"]["potential_idor_multi_value"]["ambiguous"] == 1
    assert report["signal_outcomes"]["potential_idor_multi_value"]["confirmed"] == 1
    assert report["action_outcomes"]["set_param"]["confirmed"] == 1


def test_rank_is_deterministic_and_prioritizes_richer_access_control_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(adaptive, "DATA", tmp_path)
    monkeypatch.setattr(adaptive, "GRAPH_FILE", tmp_path / "context_graph.json")
    monkeypatch.setattr(adaptive, "MEMORY_FILE", tmp_path / "adaptive_memory.json")
    adaptive.build_context_graph([])
    basic = {"id": "a", "signal": ["missing_security_headers"]}
    rich = {"id": "b", "signal": ["potential_idor_multi_value", "resource_or_identity_parameter", "authorization_response"]}
    assert adaptive.rank_candidates([basic, rich])[0]["id"] == "b"
    assert adaptive.rank_candidates([basic, rich]) == adaptive.rank_candidates([basic, rich])


def test_improvement_plan_is_advisory_and_not_applied(tmp_path, monkeypatch):
    monkeypatch.setattr(adaptive, "DATA", tmp_path)
    monkeypatch.setattr(adaptive, "MEMORY_FILE", tmp_path / "adaptive_memory.json")
    for _ in range(2):
        adaptive.record_outcome({"id": "x", "signal": ["potential_idor_multi_value"]},
                                {"action": "set_param"}, "ambiguous", "no ownership oracle")
    proposals = adaptive.improvement_plan()
    assert proposals
    assert proposals[0]["status"] == "proposed_not_applied"
    assert (tmp_path / "improvement_proposals.json").exists()


def test_context_engine_sorts_and_keeps_role_labels_and_no_raw_body():
    import context_engine
    requests = [
        {"timestamp": 20, "account_role": "victim", "host": "lab.local", "method": "GET",
         "path": "/api/item", "status": 200, "mime_type": "application/json",
         "response_length": 20, "response_body_preview": '{"id":1,"owner":"secret"}',
         "query_params": [{"key": "id", "value": "1"}], "body_params": [], "fingerprint": "b"},
        {"timestamp": 10, "account_role": "attacker", "host": "lab.local", "method": "GET",
         "path": "/api/item", "status": 403, "mime_type": "application/json",
         "response_length": 10, "response_body_preview": '{"error":"no"}',
         "query_params": [{"key": "id", "value": "2"}], "body_params": [], "fingerprint": "a"},
    ]
    ordered = context_engine.chronological(requests)
    assert ordered[0]["account_role"] == "attacker"
    ctx = context_engine.build_site_context(requests)
    assert ctx["role_counts"] == {"attacker": 1, "victim": 1}
    raw = json.dumps(ctx)
    assert "secret" not in raw and "response_body_preview" not in raw
    compact = context_engine.compact_focus(ctx, "lab.local", "/api/item")
    assert "attacker" in compact and "victim" in compact
