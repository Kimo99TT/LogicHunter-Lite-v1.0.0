"""Tests for LogicHunter Lite core (import/sanitize/analyze/correlate)."""
import json
from pathlib import Path
import pytest
import logichunter

FIXTURES = Path(__file__).parent / "fixtures"


# === decode_text / base64 handling ===

def test_decode_text_reads_flag():
    b64 = "R0VUIC8gSFRUUC8xLjANCg0K"
    assert "GET / HTTP/1.0" in logichunter.decode_text(b64, is_base64=True)
    plain = "GET / HTTP/1.0\r\n\r\n"
    assert logichunter.decode_text(plain, is_base64=False) == plain


def test_parse_b64_fixture_decodes_correctly():
    items = logichunter.parse_burp_xml(FIXTURES / "burp_b64_sample.xml")
    assert len(items) == 1
    item = items[0]
    assert item["method"] == "GET"
    assert item["status"] == 200
    assert item["path"] == "/"


# === ID_KEYS regex ===

def test_id_regex_no_false_positives():
    for word in ["valid", "paid", "void", "grid", "said", "avoid"]:
        assert not logichunter.ID_KEYS.search(word), f"false positive: {word}"


def test_id_regex_matches_real_identifiers():
    for param in ["id", "user_id", "account_id", "uuid", "owner_id",
                  "tenant", "profile"]:
        assert logichunter.ID_KEYS.search(param), f"false negative: {param}"


# === Sanitizer ===

def test_sanitizer_redacts_jwt():
    body = '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxw"}'
    out = logichunter.sanitize_response_body(body)
    assert "eyJhbGciOiJIUzI1NiJ9" not in out
    assert "[REDACTED]" in out


def test_sanitizer_redacts_email():
    out = logichunter.sanitize_response_body("Contact support@example.com")
    assert "support@example.com" not in out
    assert "[EMAIL_REDACTED]" in out


def test_sanitizer_redacts_ssn():
    out = logichunter.sanitize_response_body("SSN: 123-45-6789")
    assert "123-45-6789" not in out


# === XXE defense ===

def test_xxe_payload_rejected():
    with pytest.raises(Exception):
        logichunter.parse_burp_xml(FIXTURES / "malicious_xxe.xml")


# === host_allowed ===

def test_host_allowed_exact_match():
    assert logichunter.host_allowed("localhost", ["localhost"])
    assert logichunter.host_allowed("127.0.0.1", ["127.0.0.1"])


def test_host_allowed_subdomain_requires_explicit_wildcard():
    assert not logichunter.host_allowed("api.example.com", ["example.com"])
    assert logichunter.host_allowed("api.example.com", ["*.example.com"])
    assert logichunter.host_allowed("test.example.com", ["*.example.com"])
    assert not logichunter.host_allowed("example.com", ["*.example.com"])


def test_host_allowed_rejects_unknown():
    assert not logichunter.host_allowed("evil.com", ["localhost"])
    assert not logichunter.host_allowed("example.com.evil.com", ["example.com"])


def test_host_allowed_handles_empty():
    assert not logichunter.host_allowed("anything", [])
    assert not logichunter.host_allowed("anything", None)


# === Minimal fixture ===

def test_parse_minimal_fixture():
    items = logichunter.parse_burp_xml(FIXTURES / "burp_minimal.xml")
    assert len(items) == 2
    assert items[0]["method"] == "GET"
    assert items[0]["status"] == 200
    assert items[1]["status"] == 403


# === Correlation + full pipeline, isolated from real data/ ===

def _setup_isolated(tmp_path, monkeypatch, fixture_name):
    monkeypatch.setattr(logichunter, "DATA", tmp_path / "data")
    monkeypatch.setattr(logichunter, "REQUESTS_FILE", tmp_path / "data" / "requests.jsonl")
    monkeypatch.setattr(logichunter, "CANDIDATES_FILE", tmp_path / "data" / "candidates.json")
    monkeypatch.setattr(logichunter, "FINDINGS_FILE", tmp_path / "data" / "findings.json")
    monkeypatch.setattr(logichunter, "INDEX_FILE", tmp_path / "data" / "imported_hashes.json")
    monkeypatch.setattr(logichunter, "CONFIG_FILE", tmp_path / "config.yaml")
    (tmp_path / "config.yaml").write_text(
        "allowed_hosts:\n  - 127.0.0.1\n  - localhost\n", encoding="utf-8",
    )
    logichunter.ensure_data()
    logichunter.import_burp(FIXTURES / fixture_name)


def test_correlation_detects_multi_id(tmp_path, monkeypatch):
    _setup_isolated(tmp_path, monkeypatch, "burp_multi_id.xml")
    items = logichunter.load_requests()
    assert len(items) == 3

    logichunter.analyze(items)
    candidates = json.loads(logichunter.CANDIDATES_FILE.read_text(encoding="utf-8"))
    multi_id = [c for c in candidates
               if "potential_idor_multi_value" in c.get("signal", [])]
    assert len(multi_id) >= 1

    details = multi_id[0]["signals"][0]["details"]
    assert details["param"] == "id"
    assert len(details["distinct_values"]) == 3


def test_candidates_cover_multiple_signal_types(tmp_path, monkeypatch):
    """Regression guard against optimizing for candidate COUNT instead of
    DIVERSITY — see the 'don't measure success by diff count' principle
    agreed on earlier in planning."""
    _setup_isolated(tmp_path, monkeypatch, "burp_minimal.xml")
    items = logichunter.load_requests()
    candidates = logichunter.analyze(items)
    all_signals = set()
    for c in candidates:
        all_signals.update(c.get("signal", []))
    assert len(all_signals) >= 2, f"expected signal diversity, got: {all_signals}"


def test_structured_redaction_preserves_long_numeric_identifiers():
    out = logichunter.sanitize_response_body(
        '{"user_id":"1234567890","phone":"1234567890","access_token":"secret-value"}'
    )
    assert '"user_id":"1234567890"' in out
    assert '"phone":"[REDACTED]"' in out
    assert 'secret-value' not in out


def test_set_cookie_redacts_value_but_preserves_security_flags():
    out = logichunter.sanitize_response_header(
        'set-cookie', 'sessionid=secret123; Path=/; Secure; HttpOnly; SameSite=Lax'
    )
    assert 'secret123' not in out
    assert 'Secure' in out
    assert 'HttpOnly' in out
    assert 'SameSite=Lax' in out


def test_review_queue_updates_existing_candidate_without_duplicates(tmp_path, monkeypatch):
    monkeypatch.setattr(logichunter, "DATA", tmp_path / "data")
    monkeypatch.setattr(logichunter, "REVIEW_QUEUE_FILE", tmp_path / "data" / "review_queue.json")
    candidate = {"id": "cand-1", "host": "127.0.0.1", "path": "/api/user",
                 "method": "GET", "hypothesis": "possible_idor_requires_verification"}
    session = {"history": [{"local_verdict": "ambiguous", "local_notes": "ownership proof needed",
                            "executed": [{"status": 200}], "plan": {"action": "set_param"}}]}
    logichunter._record_review_candidate(candidate, session)
    session["history"][0]["local_notes"] = "new evidence still needs manual review"
    logichunter._record_review_candidate(candidate, session)
    queue = __import__('json').loads(logichunter.REVIEW_QUEUE_FILE.read_text())
    assert len(queue) == 1
    assert queue[0]["local_notes"] == "new evidence still needs manual review"


def test_burp_import_role_and_timestamp_parser():
    import logichunter
    from pathlib import Path
    items = logichunter.parse_burp_xml(Path(__file__).parent / "fixtures" / "burp_minimal.xml",
                                       account_role="attacker")
    assert items
    assert all(item["account_role"] == "attacker" for item in items)
    assert all(isinstance(item["timestamp"], int) for item in items)
    assert logichunter._parse_burp_timestamp("2026-10-18T12:00:00Z") > 0


def test_raw_evidence_is_opt_in(tmp_path, monkeypatch):
    xml = tmp_path / "raw.xml"
    xml.write_text('''<items><item><time>2026-01-01T00:00:00Z</time><url>http://localhost/api</url><host>localhost</host><method>GET</method><request base64="false">GET /api HTTP/1.1&#13;&#10;Host: localhost&#13;&#10;Authorization: Bearer TEST_ONLY_TOKEN&#13;&#10;&#13;&#10;</request><response base64="false">HTTP/1.1 200 OK&#13;&#10;Content-Type: application/json&#13;&#10;&#13;&#10;{"ok":true}</response></item></items>''', encoding="utf-8")
    monkeypatch.delenv("LH_STORE_RAW_EVIDENCE", raising=False)
    default = logichunter.parse_burp_xml(xml)
    assert "_raw_evidence" not in default[0]
    monkeypatch.setenv("LH_STORE_RAW_EVIDENCE", "1")
    opted_in = logichunter.parse_burp_xml(xml)
    assert "TEST_ONLY_TOKEN" in opted_in[0]["_raw_evidence"]["request"]
