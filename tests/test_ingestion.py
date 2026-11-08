from log_engine.ingestion import read_logs, read_logs_from_directory


def test_read_logs_reads_lines_without_newlines(tmp_path):
    log_file = tmp_path / "first.log"
    log_file.write_text("first\nsecond\n", encoding="utf-8")

    assert list(read_logs(log_file)) == ["first", "second"]


def test_read_logs_from_directory_reads_sorted_files(tmp_path):
    (tmp_path / "b.log").write_text("b\n", encoding="utf-8")
    (tmp_path / "a.log").write_text("a\n", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("ignored\n", encoding="utf-8")

    assert list(read_logs_from_directory(tmp_path)) == ["a", "b"]


def test_read_logs_from_directory_rejects_missing_directory(tmp_path):
    missing = tmp_path / "missing"

    try:
        list(read_logs_from_directory(missing))
    except NotADirectoryError as error:
        assert str(missing) in str(error)
    else:
        raise AssertionError("NotADirectoryError was not raised")


def test_read_logs_from_directory_rejects_empty_directory(tmp_path):
    try:
        list(read_logs_from_directory(tmp_path))
    except FileNotFoundError as error:
        assert "Aucun fichier" in str(error)
    else:
        raise AssertionError("FileNotFoundError was not raised")
