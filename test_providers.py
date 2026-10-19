"""Tests for providers.py — budget tracking and rotation (no live API calls)."""
import json
import providers


def _patch_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(providers, "DATA", tmp_path / "data")
    monkeypatch.setattr(providers, "BUDGET_FILE", tmp_path / "data" / "provider_budget.json")


def test_load_budget_creates_default(tmp_path, monkeypatch):
    _patch_budget(tmp_path, monkeypatch)
    budget = providers.load_budget()
    assert "deepseek" in budget["providers"]
    assert budget["providers"]["deepseek"]["calls_used"] == 0


def test_pick_provider_respects_priority(tmp_path, monkeypatch):
    _patch_budget(tmp_path, monkeypatch)
    budget = providers.load_budget()
    # Gemini is the default first provider in v0.4.
    assert providers.pick_provider(budget) == "gemini"


def test_pick_provider_falls_back_when_exhausted(tmp_path, monkeypatch):
    _patch_budget(tmp_path, monkeypatch)
    budget = providers.load_budget()
    budget["providers"]["gemini"]["calls_used"] = budget["providers"]["gemini"]["calls_limit"]
    assert providers.pick_provider(budget) == "deepseek"


def test_all_providers_exhausted(tmp_path, monkeypatch):
    _patch_budget(tmp_path, monkeypatch)
    budget = providers.load_budget()
    for p in budget["providers"].values():
        p["calls_used"] = p["calls_limit"]
    assert providers.all_providers_exhausted(budget)
    assert providers.pick_provider(budget) is None


def test_record_call_increments_and_persists(tmp_path, monkeypatch):
    _patch_budget(tmp_path, monkeypatch)
    budget = providers.load_budget()
    providers.record_call(budget, "deepseek")
    reloaded = providers.load_budget()
    assert reloaded["providers"]["deepseek"]["calls_used"] == 1


def test_call_ai_provider_rejects_disallowed_action(monkeypatch):
    """If a provider ever returns a disallowed action, it must be
    downgraded to Unclear before it reaches the executor."""
    def fake_deepseek(prompt):
        return {"vuln_type": "SQLi", "action": "raw_sql_injection",
               "param": "id", "try_values": ["' OR 1=1"], "confidence": 0.9,
               "rationale": "malicious plan attempt"}
    monkeypatch.setitem(providers._DISPATCH, "deepseek", fake_deepseek)
    plan = providers.call_ai_provider("deepseek", "irrelevant prompt")
    assert plan["vuln_type"] == "Unclear"
    assert plan["action"] is None


def test_build_context_prompt_includes_history():
    session = {
        "host": "127.0.0.1", "path": "/api/user",
        "baseline": {"status": 200, "length": 50},
        "candidate_signals": ["resource_or_identity_parameter"],
        "history": [{
            "iteration": 1, "provider": "deepseek",
            "plan": {"action": "set_param", "param": "id", "try_values": ["2"]},
            "executed": [{"value": "2", "status": 200, "diff_vs_baseline": "minor_size_change"}],
            "local_verdict": "ambiguous", "local_notes": "inconclusive",
        }],
    }
    prompt = providers.build_context_prompt(session)
    assert "127.0.0.1" in prompt
    assert "Iteration 1" in prompt
    assert "ambiguous" in prompt


def test_is_configured_checks_environment_only(monkeypatch):
    monkeypatch.delenv('DEEPSEEK_API_KEY', raising=False)
    assert not providers.is_configured('deepseek')
    monkeypatch.setenv('DEEPSEEK_API_KEY', 'test-placeholder')
    assert providers.is_configured('deepseek')


def test_provider_plan_rejects_oversized_value_list(monkeypatch):
    def fake_deepseek(_prompt):
        return {'vuln_type': 'IDOR', 'action': 'set_param', 'param': 'id',
                'try_values': ['1', '2', '3', '4', '5', '6'], 'confidence': 0.8,
                'rationale': 'too many'}
    monkeypatch.setitem(providers._DISPATCH, 'deepseek', fake_deepseek)
    import pytest
    with pytest.raises(ValueError):
        providers.call_ai_provider('deepseek', 'test')


def test_gemini_is_configured_from_numbered_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY_3", "test-only-key")
    assert providers.is_configured("gemini")



def test_gemini_429_stops_key_rotation(monkeypatch):
    class FakeResponse:
        status_code = 429
        def raise_for_status(self):
            import requests
            raise requests.HTTPError("429")
    calls = []
    def fake_post(*args, **kwargs):
        calls.append(kwargs.get("headers", {}).get("x-goog-api-key"))
        return FakeResponse()
    monkeypatch.setenv("GEMINI_API_KEY", "key-a")
    monkeypatch.setenv("GEMINI_API_KEY_1", "key-b")
    monkeypatch.setattr("requests.post", fake_post)
    try:
        providers._call_gemini("{}")
        assert False, "expected quota error"
    except RuntimeError as exc:
        assert "quota/rate limit" in str(exc)
    assert len(calls) == 1


def test_gemini_parses_json_response(monkeypatch):
    class FakeResponse:
        status_code = 200
        def raise_for_status(self):
            return None
        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": '{"vuln_type":"Unclear","action":null,"param":null,"try_values":[],"confidence":0,"rationale":"insufficient evidence"}'}]}}]}
    monkeypatch.setenv("GEMINI_API_KEY", "key-a")
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: FakeResponse())
    plan = providers._call_gemini("{}").copy()
    assert plan["vuln_type"] == "Unclear"


def test_gemini_priority_beats_legacy_budget_priorities(tmp_path, monkeypatch):
    _patch_budget(tmp_path, monkeypatch)
    providers.DATA.mkdir(parents=True, exist_ok=True)
    providers.BUDGET_FILE.write_text(json.dumps({"date": providers.time.strftime("%Y-%m-%d"),
        "providers": {"deepseek": {"calls_used": 0, "calls_limit": 30, "priority": 1},
                      "groq": {"calls_used": 0, "calls_limit": 500, "priority": 2},
                      "mistral": {"calls_used": 0, "calls_limit": 200, "priority": 3}}}))
    budget = providers.load_budget()
    assert providers.pick_provider(budget) == "gemini"


def test_gemini_quota_error_is_distinct_and_stops_rotation(monkeypatch):
    class FakeResponse:
        status_code = 429
        def raise_for_status(self):
            import requests
            raise requests.HTTPError("429")
    calls = []
    def fake_post(*args, **kwargs):
        calls.append(kwargs.get("headers", {}).get("x-goog-api-key"))
        return FakeResponse()
    monkeypatch.setenv("GEMINI_API_KEY", "key-a")
    monkeypatch.setenv("GEMINI_API_KEY_1", "key-b")
    monkeypatch.setattr("requests.post", fake_post)
    import pytest
    with pytest.raises(providers.ProviderQuotaError):
        providers._call_gemini("{}")
    assert calls == ["key-a"]


def test_context_prompt_respects_configured_character_budget(monkeypatch):
    monkeypatch.setenv("LH_MAX_PROMPT_CHARS", "3000")
    session = {
        "host": "lab.local", "path": "/api/item",
        "baseline": {"status": 200, "length": 100},
        "history": [{"iteration": i, "provider": "gemini",
                     "plan": {"action": "set_param", "param": "id", "try_values": [str(i)]},
                     "executed": [{"value": str(i), "status": 200, "diff_vs_baseline": "none"}],
                     "local_verdict": "ambiguous", "local_notes": "x" * 400}
                    for i in range(1, 20)],
        "site_context_compact": "context " * 5000,
    }
    prompt = providers.build_context_prompt(session)
    assert len(prompt) <= 3000
    assert "Return exactly one JSON object" in prompt


def test_gemini_manager_parses_structured_decision(monkeypatch):
    class FakeResponse:
        status_code = 200
        def raise_for_status(self):
            return None
        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": '{"action":"status","args":{},"summary":"inspect state","rationale":"start with baseline"}'}]}}]}
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: FakeResponse())
    result = providers.call_gemini_manager("test prompt")
    assert result["action"] == "status"
    assert result["args"] == {}


def test_gemini_manager_429_stops_key_rotation(monkeypatch):
    class FakeResponse:
        status_code = 429
        def raise_for_status(self):
            import requests
            raise requests.HTTPError("429")
    calls = []
    def fake_post(*args, **kwargs):
        calls.append(kwargs.get("headers", {}).get("x-goog-api-key"))
        return FakeResponse()
    monkeypatch.setenv("GEMINI_API_KEY", "key-a")
    monkeypatch.setenv("GEMINI_API_KEY_1", "key-b")
    monkeypatch.setattr("requests.post", fake_post)
    import pytest
    with pytest.raises(providers.ProviderQuotaError):
        providers.call_gemini_manager("test prompt")
    assert calls == ["key-a"]


def test_build_context_prompt_includes_operator_enabled_raw_evidence():
    session = {
        "host": "example.test", "path": "/api/profile",
        "baseline": {"status": 200, "length": 20},
        "raw_evidence_for_prompt": {
            "request": "GET /api/profile HTTP/1.1\\r\\nAuthorization: Bearer TEST_ONLY_TOKEN\\r\\n\\r\\n",
            "response": "HTTP/1.1 200 OK\\r\\n\\r\\n{\\\"owner_id\\\":\\\"user-b\\\"}",
            "truncated": False,
        },
    }
    prompt = providers.build_context_prompt(session)
    assert "TEST_ONLY_TOKEN" in prompt
    assert "owner_id" in prompt
    assert "OPERATOR-ENABLED RAW HTTP EVIDENCE" in prompt
