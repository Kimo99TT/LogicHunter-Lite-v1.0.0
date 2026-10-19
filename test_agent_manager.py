import json
import agent_manager


def test_manager_decision_allowlist():
    ok, reason = agent_manager.validate_decision({"action": "status", "args": {}})
    assert ok and reason == "ok"
    ok, _ = agent_manager.validate_decision({"action": "run_shell", "args": {"cmd": "id"}})
    assert not ok


def test_manager_proposal_validation():
    valid = {"action": "propose_change", "args": {"title": "Improve workflow inference", "change_plan": "Add a deterministic workflow fixture.", "tests": ["pytest -q"]}}
    assert agent_manager.validate_decision(valid)[0]
    invalid = {"action": "propose_change", "args": {"title": "", "change_plan": "x", "tests": []}}
    assert not agent_manager.validate_decision(invalid)[0]


def test_test_batch_is_bounded():
    assert agent_manager.validate_decision({"action": "run_test_batch", "args": {"max_candidates": 5}})[0]
    assert not agent_manager.validate_decision({"action": "run_test_batch", "args": {"max_candidates": 500}})[0]


def test_provider_manager_action_contract():
    import providers
    assert "call_gemini_manager" in dir(providers)
    assert "propose_change" in providers.MANAGER_SYSTEM


def test_draft_patch_rejects_sensitive_paths():
    bad = {"action": "draft_patch", "args": {"title": "x", "patch": "--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-x\n+y"}}
    assert not agent_manager.validate_decision(bad)[0]


def test_draft_patch_accepts_reviewable_python_diff():
    good = {"action": "draft_patch", "args": {"title": "Add test", "patch": "--- a/test_example.py\n+++ b/test_example.py\n@@ -1 +1 @@\n-x\n+y"}}
    assert agent_manager.validate_decision(good)[0]


def test_manager_prompt_can_include_explicitly_enabled_raw_evidence(monkeypatch):
    monkeypatch.setenv("LH_GEMINI_ADMIN", "1")
    prompt = agent_manager._make_prompt({"status": "running", "raw_evidence": [{"request": "Authorization: Bearer TEST_ONLY_TOKEN"}]}, False, 3)
    assert "administrative planning manager" in prompt.lower()
    assert "TEST_ONLY_TOKEN" in prompt
    assert "Live network testing explicitly enabled by operator: False" in prompt
