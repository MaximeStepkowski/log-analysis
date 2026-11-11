import io
import os

import log_analysis
from log_generator.generate_multiple_logs import generate_multiple_logs


def test_display_report_scrolls_and_returns_on_q(tmp_path, monkeypatch, capsys):
    report = tmp_path / "long_report.txt"
    report.write_text("\n".join(f"ligne {index}" for index in range(45)), encoding="utf-8")
    answers = iter(["", "q"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    log_analysis.display_report(report, page_size=20)

    output = capsys.readouterr().out
    assert "ligne 0" in output
    assert "ligne 19" in output
    assert "ligne 20" in output
    assert "ligne 39" in output
    assert "ligne 40" not in output


def test_display_report_navigates_back_to_previous_page(tmp_path, monkeypatch, capsys):
    report = tmp_path / "report.txt"
    report.write_text("\n".join(f"ligne {index}" for index in range(5)), encoding="utf-8")
    keys = iter(["right", "left", "quit"])
    monkeypatch.setattr(log_analysis, "read_navigation_key", lambda: next(keys))

    log_analysis.display_report(report, page_size=2)

    output = capsys.readouterr().out
    assert output.count("Page 1/3") == 2
    assert "Page 2/3" in output
    assert "Page 1/3 | ← page précédente | → page suivante | q retour" in output
    assert output.index("=== report.txt ===") < output.index("ligne 0")
    assert output.index("ligne 0") < output.index("Page 1/3 |")


def test_display_report_adapts_to_terminal_size(tmp_path, monkeypatch, capsys):
    report = tmp_path / "report.txt"
    report.write_text("abcdefgh\nabcdefgh\nabcdefgh\nabcdefgh", encoding="utf-8")
    sizes = iter([
        os.terminal_size((4, 8)),
        os.terminal_size((20, 8)),
        os.terminal_size((20, 8)),
    ])
    monkeypatch.setattr(
        log_analysis.shutil,
        "get_terminal_size",
        lambda _fallback: next(sizes),
    )
    keys = iter(["right", "right", "quit"])
    monkeypatch.setattr(log_analysis, "read_navigation_key", lambda: next(keys))

    log_analysis.display_report(report)

    output = capsys.readouterr().out
    assert "abcd" in output
    assert "Page 1/8" in output
    assert "Page 1/2" in output


def test_reports_menu_opens_selected_report(tmp_path, monkeypatch, capsys):
    reports_directory = tmp_path / "reports"
    reports_directory.mkdir()
    brute_force_directory = tmp_path / "brute_force"
    brute_force_directory.mkdir()
    (brute_force_directory / "brute_force_report.txt").write_text(
        "rapport brute force",
        encoding="utf-8",
    )
    (reports_directory / "rapport.txt").write_text("contenu du rapport", encoding="utf-8")
    monkeypatch.setattr(log_analysis, "REPORTS_DIRECTORY", reports_directory)
    answers = iter(["1", "q", "0"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    log_analysis.reports_menu()

    output = capsys.readouterr().out
    assert "rapport.txt" in output
    assert "brute_force_report.txt" not in output
    assert "contenu du rapport" in output


def test_generation_menu_passes_selected_parameters(tmp_path, monkeypatch):
    answers = iter(["2", "10", "100", "5", str(tmp_path)])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    calls = []
    monkeypatch.setattr(
        log_analysis,
        "generate_multiple_logs",
        lambda *args: calls.append(args),
    )

    log_analysis.generation_menu()

    assert calls == [(2, 10, tmp_path, 100, 5)]


def test_generate_multiple_logs_creates_configured_file(tmp_path):
    generate_multiple_logs(1, 1, tmp_path, batch_size=1)

    generated_file = tmp_path / "logs_file_http_1.log"
    assert generated_file.is_file()
    assert len(generated_file.read_text(encoding="utf-8").splitlines()) == 1


def test_run_application_saves_the_latest_output(tmp_path, monkeypatch):
    report_directory = tmp_path / "reports"
    report_path = report_directory / "last_run.txt"
    monkeypatch.setattr(log_analysis, "REPORTS_DIRECTORY", report_directory)
    monkeypatch.setattr(log_analysis, "LAST_RUN_REPORT", report_path)
    monkeypatch.setattr(log_analysis, "MAIN_SCRIPT", tmp_path / "main.py")

    class Process:
        stdout = io.StringIO("rapport de test\n")

        def wait(self):
            return 0

    monkeypatch.setattr(log_analysis.subprocess, "Popen", lambda *args, **kwargs: Process())

    log_analysis.run_application(memory=True, workers=2)

    assert report_path.read_text(encoding="utf-8") == "rapport de test\n"


def test_main_exits_from_the_menu(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda _prompt: "0")

    log_analysis.main()

    assert "Au revoir." in capsys.readouterr().out
