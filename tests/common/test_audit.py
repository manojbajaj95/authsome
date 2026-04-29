"""Tests for the AuditLogger."""

import json
from pathlib import Path

from authsome import audit


def test_audit_logger_initialization(tmp_path: Path):
    filepath = tmp_path / "audit.log"
    audit.setup(filepath)
    assert audit._logger_instance is not None
    assert audit._logger_instance.filepath == filepath


def test_audit_logger_writes_json_line(tmp_path: Path):
    filepath = tmp_path / "audit.log"
    audit.setup(filepath)
    audit.log("test_event", provider="test_provider", status="success")

    assert filepath.exists()
    lines = filepath.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1

    event_data = json.loads(lines[0])
    assert "timestamp" in event_data
    assert event_data["event"] == "test_event"
    assert event_data["provider"] == "test_provider"
    assert event_data["status"] == "success"


def test_audit_logger_filters_none_values(tmp_path: Path):
    filepath = tmp_path / "audit.log"
    audit.setup(filepath)
    audit.log("test_event", provider="test_provider", missing=None)

    lines = filepath.read_text(encoding="utf-8").strip().split("\n")
    event_data = json.loads(lines[0])
    assert "provider" in event_data
    assert "missing" not in event_data





def test_audit_logger_creates_parent_directory(tmp_path: Path):
    filepath = tmp_path / "nested" / "dir" / "audit.log"
    audit.setup(filepath)
    audit.log("test_event")

    assert filepath.exists()
    assert filepath.parent.exists()


def test_audit_logger_graceful_failure(tmp_path: Path, monkeypatch):
    filepath = tmp_path / "audit.log"
    audit.setup(filepath)

    def mock_open(*args, **kwargs):
        raise OSError("Permission denied")

    monkeypatch.setattr("builtins.open", mock_open)
    # This should not raise an exception
    audit.log("test_event")
