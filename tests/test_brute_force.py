from datetime import datetime, timezone

from log_process.brute_force import detect_brute_force, detect_brute_force_from_directory


def http_record(ip: str, status: int, second: int) -> dict:
    return {
        "ip": ip,
        "status": status,
        "path": "/admin/login",
        "timestamp": datetime(2026, 10, 30, 12, 0, second, tzinfo=timezone.utc),
    }


def test_detects_three_consecutive_failures_for_one_ip(caplog):
    records = [
        http_record("192.168.1.10", 401, 1),
        http_record("192.168.1.10", 403, 2),
        http_record("192.168.1.10", 401, 3),
    ]

    alerts = detect_brute_force(records)

    assert len(alerts) == 1
    assert alerts[0]["ip"] == "192.168.1.10"
    assert alerts[0]["attempts"] == 3
    assert "Force brute détectée" in caplog.text


def test_success_resets_the_counter_and_allows_a_new_alert():
    records = [
        http_record("10.0.0.7", 401, 1),
        http_record("10.0.0.7", 401, 2),
        http_record("10.0.0.7", 200, 3),
        http_record("10.0.0.7", 401, 4),
        http_record("10.0.0.7", 401, 5),
        http_record("10.0.0.7", 401, 6),
    ]

    alerts = detect_brute_force(records)

    assert len(alerts) == 1
    assert alerts[0]["attempts"] == 3


def test_detection_continues_after_an_alert_and_ignores_other_statuses():
    records = [
        http_record("10.0.0.1", 401, 1),
        http_record("10.0.0.1", 500, 2),
        http_record("10.0.0.1", 401, 3),
        http_record("10.0.0.1", 401, 4),
        http_record("10.0.0.2", 401, 5),
        http_record("10.0.0.2", 401, 6),
        http_record("10.0.0.2", 401, 7),
    ]

    alerts = detect_brute_force(records)

    assert [alert["ip"] for alert in alerts] == ["10.0.0.1", "10.0.0.2"]


def test_cycle_without_three_failures_does_not_create_alert():
    records = [
        http_record("10.0.0.3", 401, 1),
        http_record("10.0.0.3", 500, 2),
        http_record("10.0.0.3", 401, 3),
    ]

    assert detect_brute_force(records) == []


def test_detects_mixed_log_formats_from_directory(tmp_path):
    log_file = tmp_path / "sample.log"
    log_file.write_text(
        "\n".join([
            '192.168.1.30 - - [30/Oct/2026:12:00:01 +0000] "POST /admin/login HTTP/1.1" 401 20 "-" "curl"',
            'time="2026-10-30 12:00:02" client_ip=192.168.1.30 method=POST path="/admin/login" status=403 bytes=20 duration_ms=5 agent="curl"',
            '{"timestamp":"2026-10-30T12:00:03Z","remote_addr":"192.168.1.30","request_method":"POST","request_uri":"/admin/login","status":401,"body_bytes_sent":20}',
        ]),
        encoding="utf-8",
    )

    alerts = detect_brute_force_from_directory(tmp_path)

    assert [alert["ip"] for alert in alerts] == ["192.168.1.30"]