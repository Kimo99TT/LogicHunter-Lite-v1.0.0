import logichunter
import fixture_generator


def test_synthetic_detection_regression_passes_without_persisting(tmp_path, monkeypatch):
    import signal_plugins
    signal_plugins._reset_for_tests()
    monkeypatch.setattr(logichunter, "DATA", tmp_path)
    monkeypatch.setattr(logichunter, "CANDIDATES_FILE", tmp_path / "candidates.json")
    monkeypatch.setattr(logichunter, "FINDINGS_FILE", tmp_path / "findings.json")
    monkeypatch.setattr(logichunter, "REVIEW_QUEUE_FILE", tmp_path / "review_queue.json")
    monkeypatch.setattr(logichunter, "INDEX_FILE", tmp_path / "index.json")
    result = fixture_generator.check_detection_quality(lambda records: logichunter.analyze(records, persist=False))
    assert result["failed"] == 0, result
    assert result["required_signal_recall"] == 1.0
    assert not (tmp_path / "candidates.json").exists()


def test_fixture_writer_uses_requested_path(tmp_path):
    path = fixture_generator.write_fixtures(tmp_path / "fixtures.json")
    assert path.exists()
    assert len(__import__("json").loads(path.read_text(encoding="utf-8"))) >= 5
