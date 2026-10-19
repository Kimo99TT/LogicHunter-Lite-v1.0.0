import json
import workflow_engine as we


def rec(role, path, status, body, timestamp, params=None):
    return {
        "account_role": role, "host": "lab.local", "method": "GET", "path": path,
        "status": status, "response_body_preview": json.dumps(body),
        "response_length": len(json.dumps(body)), "timestamp": timestamp,
        "query_params": [{"key": k, "value": v} for k, v in (params or {}).items()],
        "body_params": [],
    }


def test_workflow_graph_is_chronological_and_role_scoped():
    records = [rec("attacker", "/b", 200, {}, 2), rec("attacker", "/a", 200, {}, 1), rec("victim", "/x", 200, {}, 1)]
    model = we.build_workflow_model(records)
    assert model["events"] == 3
    assert any(e["role"] == "attacker" and e["from"]["path"] == "/a" and e["to"]["path"] == "/b" for e in model["transitions"])
    assert model["role_contrasts"] == []


def test_cross_role_status_change_is_hypothesis_not_confirmation():
    records = [rec("attacker", "/api/record", 200, {"id": "8", "owner_id": "user-b"}, 1, {"id": "8"}),
               rec("victim", "/api/record", 403, {"error": "forbidden"}, 2, {"id": "8"})]
    findings = we.analyze_cross_role_ownership(records)
    assert len(findings) == 1
    assert findings[0]["confirmed"] is False
    assert findings[0]["classification"] == "cross_role_differential_needs_validation"


def test_owner_identity_difference_flags_same_route():
    records = [rec("attacker", "/api/record", 200, {"id": "8", "owner_id": "user-b"}, 1),
               rec("victim", "/api/record", 200, {"id": "8", "owner_id": "user-a"}, 2)]
    findings = we.analyze_cross_role_ownership(records)
    assert len(findings) == 1
    assert "owner_id" in findings[0]["evidence"][0]["identity_fields_differ"]
    assert findings[0]["confirmed"] is False


def test_same_response_does_not_create_finding():
    records = [rec("attacker", "/api/public", 200, {"id": "8", "owner_id": "shared"}, 1),
               rec("victim", "/api/public", 200, {"id": "8", "owner_id": "shared"}, 2)]
    assert we.analyze_cross_role_ownership(records) == []


def test_workflow_model_does_not_store_response_values():
    records = [rec("attacker", "/api/record", 200, {"id": "secret-id", "owner_id": "secret-owner", "email": "a@b.com"}, 1)]
    text = json.dumps(we.build_workflow_model(records))
    assert "secret-id" not in text
    assert "secret-owner" not in text
    assert "a@b.com" not in text


def test_offline_benchmark_all_cases_pass():
    result = we.benchmark()
    assert result["failed"] == 0
    assert result["cases"] >= 6


def test_known_principal_mapping_detects_cross_account_owner_mismatch():
    attacker = rec("attacker", "/api/record", 200, {"id": "42", "owner_id": "victim-2"}, 1, {"id": "42"})
    victim = rec("victim", "/api/record", 200, {"id": "42", "owner_id": "victim-2"}, 2, {"id": "42"})
    attacker["account_principal_id"] = "attacker-1"
    victim["account_principal_id"] = "victim-2"
    findings = we.analyze_cross_role_ownership([attacker, victim])
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["owner_matches_victim_but_not_attacker"] is True
    assert findings[0]["confirmed"] is False


def test_loopback_lab_benchmark_uses_only_local_fixtures_and_passes():
    result = we.run_local_lab_benchmark()
    assert result["network_scope"] == "127.0.0.1 ephemeral port only"
    assert result["requests_executed"] == 6
    assert result["failed"] == 0


def test_different_objects_with_different_owners_are_not_compared_as_same_object():
    attacker = rec("attacker", "/api/record", 200, {"id": "8", "owner_id": "user-a"}, 1, {"id": "8"})
    victim = rec("victim", "/api/record", 200, {"id": "9", "owner_id": "user-b"}, 2, {"id": "9"})
    assert we.analyze_cross_role_ownership([attacker, victim]) == []


def test_ranked_hypotheses_explain_priority_without_claiming_probability():
    attacker = rec("attacker", "/api/record", 200, {"id": "42", "owner_id": "victim-2"}, 1, {"id": "42"})
    victim = rec("victim", "/api/record", 200, {"id": "42", "owner_id": "victim-2"}, 2, {"id": "42"})
    attacker["account_principal_id"] = "attacker-1"
    victim["account_principal_id"] = "victim-2"
    ranked = we.rank_cross_role_hypotheses([attacker, victim])
    assert ranked[0]["priority_score"] == 0.9
    assert "not exploit probability" in ranked[0]["score_semantics"]


def test_expanded_benchmark_reports_fixture_metrics_and_passes():
    result = we.benchmark()
    assert result["cases"] >= 10
    assert result["failed"] == 0
    assert "precision" in result["fixture_metrics"]
    assert "not real-world accuracy estimates" in " ".join(result["limitations"])
