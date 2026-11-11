import pytest

from log_processing.ip_sets import (
    DEFAULT_BLACKLIST_PATH,
    IPCollector,
    compare_with_blacklist,
    format_ip_report,
    load_blacklist,
    track_ips,
)


def make_record(ip, level="INFO"):
    return {"level": level, "connection": (ip, 80, "HTTP/1.1")}


def test_load_blacklist_ignores_comments_and_blank_lines(tmp_path):
    path = tmp_path / "blacklist.txt"
    path.write_text(
        "# commentaire\n\n10.0.0.1\n  10.0.0.2  # en fin de ligne\n10.0.0.1\n",
        encoding="utf-8",
    )

    blacklist = load_blacklist(path)

    assert blacklist == frozenset({"10.0.0.1", "10.0.0.2"})
    assert isinstance(blacklist, frozenset)


def test_load_blacklist_rejects_invalid_ip_with_line_number(tmp_path):
    path = tmp_path / "blacklist.txt"
    path.write_text("10.0.0.1\nnot-an-ip\n", encoding="utf-8")

    with pytest.raises(ValueError, match="ligne 2"):
        load_blacklist(path)


def test_default_blacklist_file_is_valid():
    assert load_blacklist(DEFAULT_BLACKLIST_PATH)


def test_collector_separates_active_and_error_ips():
    collector = IPCollector()

    for record in (
        make_record("10.0.0.1"),
        make_record("10.0.0.2", "ERROR"),
        make_record("10.0.0.2", "INFO"),
        make_record("10.0.0.3", "CRITICAL"),
        make_record("10.0.0.3", "WARNING"),
    ):
        collector.observe(record)

    assert collector.active_ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert collector.error_ips == {"10.0.0.2", "10.0.0.3"}
    assert collector.error_ips <= collector.active_ips
    assert collector.records_seen == 5
    assert collector.error_records == 2


def test_collector_ignores_records_without_connection():
    collector = IPCollector()

    for record in (
        {"raw_line": "bad", "error": "Ligne vide"},
        {"level": "ERROR"},
        {"level": "ERROR", "connection": ("10.0.0.1", 80)},
        None,
        "texte brut",
    ):
        collector.observe(record)

    assert collector.active_ips == set()
    assert collector.records_seen == 0


def test_track_ips_is_lazy_and_does_not_alter_records():
    collector = IPCollector()
    records = [make_record("10.0.0.1"), make_record("10.0.0.2", "ERROR")]

    stream = track_ips(iter(records), collector)
    assert collector.records_seen == 0

    assert next(stream) is records[0]
    assert collector.records_seen == 1
    assert list(stream) == records[1:]
    assert collector.error_ips == {"10.0.0.2"}


def test_compare_with_blacklist_applies_the_four_set_operations():
    blacklist = frozenset({"1.1.1.1", "2.2.2.2", "3.3.3.3"})
    active = {"2.2.2.2", "3.3.3.3", "4.4.4.4"}
    errors = {"3.3.3.3", "4.4.4.4"}

    report = compare_with_blacklist(blacklist, active, errors)

    assert report.blacklisted_active == {"2.2.2.2", "3.3.3.3"}
    assert report.dormant_blacklisted == {"1.1.1.1"}
    assert report.unlisted_active == {"4.4.4.4"}
    assert report.only_in_one == {"1.1.1.1", "4.4.4.4"}
    assert report.known_ips == {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
    assert report.blacklisted_errors == {"3.3.3.3"}
    assert report.only_in_one == report.dormant_blacklisted | report.unlisted_active


def test_compare_with_blacklist_returns_only_immutable_sets():
    blacklist = frozenset({"1.1.1.1"})
    active = {"1.1.1.1", "2.2.2.2"}

    report = compare_with_blacklist(blacklist, active, set())

    # set - frozenset returns a set, so the report must still be immutable.
    assert isinstance(active - blacklist, set)
    for name in (
        "blacklist",
        "active_ips",
        "error_ips",
        "blacklisted_active",
        "dormant_blacklisted",
        "unlisted_active",
        "only_in_one",
        "known_ips",
        "blacklisted_errors",
    ):
        assert isinstance(getattr(report, name), frozenset)
    with pytest.raises(AttributeError):
        report.known_ips = frozenset()


def test_compare_with_blacklist_handles_empty_inputs():
    report = compare_with_blacklist(frozenset(), set(), set())

    assert report.known_ips == frozenset()
    assert report.only_in_one == frozenset()


def test_format_ip_report_sorts_numerically_and_truncates():
    collector = IPCollector()
    for last_byte in (10, 9, 2):
        collector.observe(make_record(f"192.168.1.{last_byte}", "ERROR"))
    report = compare_with_blacklist(
        frozenset({"203.0.113.7"}), collector.active_ips, collector.error_ips
    )

    text = format_ip_report(collector, report, limit=2)

    assert "192.168.1.2, 192.168.1.9, ... (+1)" in text
    assert "203.0.113.7" in text
    assert "Toutes les IP blacklistées ou observées" in text
    assert "Différence symétrique (blacklist ^ actives)" in text
    assert "aucune" in text  # blacklist & actives est vide
