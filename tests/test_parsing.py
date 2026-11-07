from datetime import datetime, timezone

import pytest

from log_engine.parsing import (
    _parse_batch,
    build_http_record,
    build_record,
    invalid_record,
    parse_line,
    parse_logs,
    parse_logs_parallel,
    parse_timestamp,
    validate_ip,
)


VALID_SYSTEM_LINE = (
    '2026-10-29 15:26:45 | LEVEL=INFO | '
    'CONNECTION=(192.168.1.83,24649,UDP) | USER=bob | MSG="hello"'
)
VALID_COMBINED_LINE = (
    '192.168.1.9:49152 - - [29/Oct/2026:18:20:52 +0000] '
    '"POST /index.html HTTP/1.1" 200 10121 "-" "curl/7.68.0"'
)
VALID_JSON_LINE = (
    '{"timestamp":"2026-10-29T18:20:52Z","remote_addr":"192.168.1.9",'
    '"remote_port":49152,"request_method":"GET","request_uri":"/",'
    '"status":200,"body_bytes_sent":123,"request_time_ms":42,'
    '"http_referrer":"-","http_user_agent":"curl"}'
)


def test_invalid_record():
    assert invalid_record("bad", "error") == {
        "raw_line": "bad",
        "error": "error",
    }


@pytest.mark.parametrize(
    "value, expected",
    [
        (
            "2026-10-29T18:20:52Z",
            datetime(2026, 10, 29, 18, 20, 52, tzinfo=timezone.utc),
        ),
        (
            "29/Oct/2026:18:20:52 +0000",
            datetime(2026, 10, 29, 18, 20, 52, tzinfo=timezone.utc),
        ),
    ],
)
def test_parse_timestamp(value, expected):
    assert parse_timestamp(value) == expected


def test_parse_timestamp_rejects_invalid_value():
    with pytest.raises(ValueError, match="Horodatage invalide"):
        parse_timestamp("invalid")


def test_validate_ip():
    assert validate_ip("192.168.1.1") == "192.168.1.1"
    with pytest.raises(ValueError, match="Adresse IP invalide"):
        validate_ip("999.999.999.999")


def test_build_record_validates_level_and_connection():
    record = build_record(
        "2026-10-29 15:26:45",
        "INFO",
        "192.168.1.1",
        "80",
        "tcp",
        "alice",
        "msg",
    )
    assert record["connection"] == ("192.168.1.1", 80, "tcp")

    with pytest.raises(ValueError, match="Niveau de sévérité"):
        build_record(
            "2026-10-29 15:26:45", "TRACE", "192.168.1.1", 80, "tcp", "alice", "msg"
        )


def test_build_http_record_assigns_levels_and_optional_fields():
    record = build_http_record(
        "2026-10-29T18:20:52Z", "192.168.1.1", "GET", "/", 500, 12,
        duration_ms="7",
    )

    assert record["level"] == "CRITICAL"
    assert record["connection"] == ("192.168.1.1", 80, "HTTP/1.1")
    assert record["duration_ms"] == 7

    assert build_http_record(
        "2026-10-29T18:20:52Z", "192.168.1.1", "GET", "/", 404, 12
    )["level"] == "ERROR"
    assert build_http_record(
        "2026-10-29T18:20:52Z", "192.168.1.1", "GET", "/", 302, 12
    )["level"] == "WARNING"
    assert build_http_record(
        "2026-10-29T18:20:52Z", "192.168.1.1", "GET", "/", 200, 12
    )["level"] == "INFO"


def test_parse_line_supports_all_formats_and_invalid_lines():
    assert parse_line("")["error"] == "Ligne vide"
    assert parse_line(VALID_SYSTEM_LINE)["user"] == "bob"
    assert parse_line(VALID_COMBINED_LINE)["status"] == 200
    assert parse_line(VALID_JSON_LINE)["method"] == "GET"
    assert parse_line(
        "2026-10-29 15:26:48 INFO 10.0.0.43:63092 [david] - denied"
    )["user"] == "david"
    assert parse_line("unknown")["error"] == "Format de ligne inconnu"


def test_parse_logs_and_batch_normalize_records():
    records = list(parse_logs([VALID_SYSTEM_LINE, "bad"]))
    batch = _parse_batch([VALID_SYSTEM_LINE])

    assert records[0]["connection"][2] == "UDP"
    assert records[1]["raw_line"] == "bad"
    assert batch[0]["user"] == "bob"


def test_parse_logs_parallel_supports_serial_and_parallel_modes():
    lines = [VALID_SYSTEM_LINE, VALID_COMBINED_LINE, "bad"]

    assert len(list(parse_logs_parallel(lines, workers=1))) == 3
    assert len(list(parse_logs_parallel(lines, workers=2, batch_size=1))) == 3
