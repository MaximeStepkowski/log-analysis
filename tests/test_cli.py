import sys

import pytest

import main
from log_generator import generate_multiple_logs as multiple_logs


def test_main_runs_pipeline_with_cli_options(monkeypatch, capsys):
    records = [
        {
            "timestamp": "2026-10-29T18:20:52+00:00",
            "level": "INFO",
            "user": "alice",
            "payload": "message",
            "connection": ("192.168.1.1", 80, "HTTP"),
        }
    ]
    monkeypatch.setattr(sys, "argv", ["main.py", "--memory", "--workers", "1"])
    monkeypatch.setattr(
        main, "read_logs_from_directory", lambda directory: iter([])
    )
    monkeypatch.setattr(
        main, "parse_logs_parallel", lambda lines, workers: iter(records)
    )
    monkeypatch.setattr(main, "get_current_memory_bytes", lambda: 1024)
    monkeypatch.setattr(main, "get_peak_memory_bytes", lambda: 2048)

    main.main()

    output = capsys.readouterr().out
    assert "Records valides" in output
    assert "Moyenne de RAM" in output


def test_main_rejects_invalid_worker_count(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py", "--workers", "0"])

    with pytest.raises(SystemExit):
        main.main()


def test_parse_arguments(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["generate_multiple_logs.py", "--files", "2", "--lines", "10"],
    )

    arguments = multiple_logs.parse_arguments()

    assert arguments.files == 2
    assert arguments.lines == 10


def test_generate_multiple_main_converts_value_error_to_system_exit(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["generate_multiple_logs.py", "--files", "0", "--lines", "1"],
    )

    with pytest.raises(SystemExit, match="Erreur"):
        multiple_logs.main()
