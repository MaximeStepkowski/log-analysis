from datetime import datetime

from log_engine.routing import route_log
from log_transformation.filter import valid_log
from log_transformation.normalization import normalize_record
from log_transformation.tracker import Tracker


def valid_record():
    return {
        "timestamp": datetime(2026, 10, 29),
        "level": "INFO",
        "user": " Alice ",
        "payload": {"message": " hello "},
        "connection": ("192.168.1.1", 80, "http"),
    }


def test_normalize_record_handles_none_and_records_without_connection():
    assert normalize_record(None) is None
    result = normalize_record({"level": " info ", "status": "200"})

    assert result == {"level": "INFO", "status": 200}


def test_normalize_record_normalizes_connection_and_payload():
    result = normalize_record(valid_record())

    assert result["user"] == "alice"
    assert result["connection"] == ("192.168.1.1", 80, "HTTP")
    assert result["payload"] == {"message": "hello"}


def test_valid_log_accepts_valid_record_and_rejects_invalid_shapes():
    assert valid_log(valid_record())

    invalid_records = [
        None,
        {**valid_record(), "timestamp": 123},
        {**valid_record(), "timestamp": "   "},
        {**valid_record(), "level": "TRACE"},
        {**valid_record(), "user": None},
        {**valid_record(), "payload": []},
        {**valid_record(), "connection": ("192.168.1.1", 80)},
        {**valid_record(), "connection": ("", 80, "HTTP")},
        {**valid_record(), "connection": ("192.168.1.1", True, "HTTP")},
        {**valid_record(), "connection": ("192.168.1.1", 0, "HTTP")},
        {**valid_record(), "connection": ("192.168.1.1", 80, "")},
    ]

    assert all(not valid_log(record) for record in invalid_records)


def test_route_log_covers_supported_structures():
    assert route_log({"raw_line": "bad", "error": "invalid"})[0] == "invalid"
    assert route_log({"level": "ERROR", "status": 500, "path": "/"})[0] == "http_error"
    assert route_log({"status": 200, "method": "GET", "path": "/"})[0] == "http"
    assert route_log({"level": "ERROR", "code": 401})[0] == "dict"
    assert route_log({"level": "INFO"})[0] == "dict"
    assert route_log("   ")[0] == "ignored"
    assert route_log("raw")[0] == "raw"
    assert route_log(("192.168.1.1", 80, "TCP"))[0] == "connection"
    assert route_log(("invalid", 80, "TCP"))[0] == "invalid"
    assert route_log(object())[0] == "unknown"


def test_tracker_counts_and_samples_records():
    tracker = Tracker(sample_size=1)
    valid = valid_record()
    invalid = {"raw_line": "bad", "error": "invalid"}

    assert tracker(valid)
    assert not tracker(invalid)
    assert tracker.seen == 2
    assert tracker.rejected == 1
    assert len(tracker.valid_samples) == 1
    assert len(tracker.invalid_samples) == 1
    assert tracker.route_examples.keys() >= {"dict", "invalid"}
