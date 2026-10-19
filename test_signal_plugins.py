from __future__ import annotations
import os
from pathlib import Path
import pytest
import signal_plugins


def setup_function():
    signal_plugins._reset_for_tests()


def test_builtin_ssrf_is_candidate_only():
    record = {"query_params": [{"key": "url", "value": "https://example.invalid/x"}], "body_params": []}
    found = signal_plugins.run_plugins(record)
    assert any(x["signal"] == "ssrf_input_candidate" for x in found)


def test_xml_detector_does_not_claim_xxe():
    found = signal_plugins.run_plugins({"request_headers": {"Content-Type": "application/xml"}, "request_body_preview": "<root/>"})
    assert any(x["signal"] == "xml_input_candidate" for x in found)
    assert not any("xxe" in x["signal"].lower() for x in found)


def test_redirect_detector_requires_redirect_status_and_location():
    rec = {"status": 302, "query_params": [{"key": "next", "value": "/"}], "body_params": [], "response_headers": {"Location": "/"}}
    assert any(x["signal"] == "redirect_behavior_candidate" for x in signal_plugins.run_plugins(rec))
    rec["status"] = 200
    assert not any(x["signal"] == "redirect_behavior_candidate" for x in signal_plugins.run_plugins(rec))


def test_detector_exception_does_not_break_pipeline():
    signal_plugins.register("test_broken", lambda record: 1 / 0)
    result = signal_plugins.run_plugins({})
    assert isinstance(result, list)


def test_external_plugins_disabled_by_default(tmp_path, monkeypatch):
    (tmp_path / "evil.py").write_text("raise RuntimeError('must not import')\n", encoding="utf-8")
    monkeypatch.delenv("LH_ENABLE_EXTERNAL_PLUGINS", raising=False)
    assert signal_plugins.load_external_plugins(tmp_path) == []


def test_external_plugin_import_error_is_isolated(tmp_path, monkeypatch, capsys):
    (tmp_path / "broken.py").write_text("raise RuntimeError('broken')\n", encoding="utf-8")
    monkeypatch.setenv("LH_ENABLE_EXTERNAL_PLUGINS", "1")
    assert signal_plugins.load_external_plugins(tmp_path) == []
    assert "skipped broken.py" in capsys.readouterr().out


def test_external_plugins_load_once(tmp_path, monkeypatch):
    (tmp_path / "safe.py").write_text("def detector(record):\n    return {'signal':'test_external_signal','details':{}}\ndef register_plugins(register):\n    register('external_test', detector)\n", encoding="utf-8")
    monkeypatch.setenv("LH_ENABLE_EXTERNAL_PLUGINS", "1")
    assert signal_plugins.load_external_plugins(tmp_path) == ["safe"]
    assert signal_plugins.load_external_plugins(tmp_path) == []
    assert any(x["signal"] == "test_external_signal" for x in signal_plugins.run_plugins({}))
