from datetime import datetime

import pytest

from log_generator.generate_logs import (
    generate_http_log_line,
    generate_huge_log_file,
    get_output_file,
)
from log_generator.generate_multiple_logs import generate_multiple_logs


def test_get_output_file_validates_number(tmp_path):
    assert get_output_file(2, tmp_path).name == "logs_file_http_2.log"
    with pytest.raises(ValueError):
        get_output_file(0, tmp_path)


def test_generate_http_log_line_can_generate_empty_and_corrupt_lines(monkeypatch):
    monkeypatch.setattr(
        "log_generator.generate_logs.random.choice", lambda values: values[0]
    )

    assert generate_http_log_line(datetime.now(), empty_rate=1) == ""
    assert "CORRUPTED" in generate_http_log_line(datetime.now(), corrupt_rate=1)


def test_generate_http_log_line_generates_supported_formats(monkeypatch):
    monkeypatch.setattr("log_generator.generate_logs.random.random", lambda: 1)
    monkeypatch.setattr(
        "log_generator.generate_logs.random.choice", lambda values: values[0]
    )

    line = generate_http_log_line(datetime(2026, 11, 5, 12, 0, 0))
    assert "GET" in line
    assert "HTTP/1.1" in line


def test_generate_huge_log_file_writes_requested_lines(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "log_generator.generate_logs.generate_http_log_line",
        lambda timestamp: "test-line",
    )
    output = tmp_path / "nested" / "logs.log"

    generate_huge_log_file(output, total_lines=3, batch_size=2)

    assert output.read_text(encoding="utf-8").splitlines() == [
        "test-line",
        "test-line",
        "test-line",
    ]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"total_lines": -1},
        {"total_lines": 1, "max_lines_per_second": 0},
        {"total_lines": 1, "batch_size": 0},
    ],
)
def test_generate_huge_log_file_rejects_invalid_arguments(tmp_path, kwargs):
    with pytest.raises(ValueError):
        generate_huge_log_file(tmp_path / "logs.log", **kwargs)


def test_generate_multiple_logs_creates_numbered_files(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "log_generator.generate_multiple_logs.generate_huge_log_file",
        lambda filename, *args: filename.write_text("line\n", encoding="utf-8"),
    )

    generate_multiple_logs(2, 1, tmp_path)

    assert sorted(path.name for path in tmp_path.glob("*.log")) == [
        "logs_file_http_1.log",
        "logs_file_http_2.log",
    ]


@pytest.mark.parametrize("file_count, line_count", [(0, 1), (1, -1)])
def test_generate_multiple_logs_rejects_invalid_arguments(
    tmp_path, file_count, line_count
):
    with pytest.raises(ValueError):
        generate_multiple_logs(file_count, line_count, tmp_path)
