"""Tests du comptage par defaultdict (Module 3.2)."""

from log_engine.aggregation import (
    UNKNOWN_KEY,
    aggregate_counts,
    count_by_level,
    count_by_user,
    count_occurrences,
    most_common,
    new_counter,
    new_nested_counter,
    user_of,
)

SYSTEM_LOGS = [
    {"level": "INFO", "user": "alice", "connection": ("10.0.0.1", 80, "TCP")},
    {"level": "ERROR", "user": "alice", "connection": ("10.0.0.1", 80, "TCP")},
    {"level": "ERROR", "user": "bob", "connection": ("10.0.0.2", 80, "TCP")},
]
HTTP_LOG = {
    "level": "ERROR",
    "user": "curl/7.68.0",
    "status": 404,
    "method": "GET",
    "path": "/admin",
}
INVALID_LOG = {"raw_line": "garbage", "error": "Format de ligne inconnu"}


def test_counter_never_raises_key_error() -> None:
    counts = new_counter()
    counts["jamais_vu"] += 1
    assert counts["toujours_absent"] == 0


def test_nested_counter_never_raises_key_error() -> None:
    nested = new_nested_counter()
    nested["alice"]["ERROR"] += 1
    assert nested["alice"]["ERROR"] == 1
    assert nested["inconnu"]["INFO"] == 0


def test_count_by_level() -> None:
    counts = count_by_level(SYSTEM_LOGS)
    assert counts["INFO"] == 1
    assert counts["ERROR"] == 2
    assert counts["CRITICAL"] == 0


def test_count_by_user() -> None:
    counts = count_by_user(SYSTEM_LOGS)
    assert dict(counts) == {"alice": 2, "bob": 1}


def test_missing_field_falls_back_instead_of_raising() -> None:
    assert user_of({"level": "INFO"}) == UNKNOWN_KEY
    assert user_of({"level": "INFO", "user": ""}) == UNKNOWN_KEY


def test_count_occurrences_accepts_any_key_function() -> None:
    counts = count_occurrences(SYSTEM_LOGS, lambda record: record["connection"][0])
    assert dict(counts) == {"10.0.0.1": 2, "10.0.0.2": 1}


def test_aggregate_counts_single_pass() -> None:
    stream = iter([*SYSTEM_LOGS, HTTP_LOG, INVALID_LOG])
    report = aggregate_counts(stream)

    assert report.total == 5
    assert report.invalid == 1
    assert report.valid == 4
    assert report.by_category["invalid"] == 1
    assert report.by_category["http_error"] == 1
    assert report.by_category["dict"] == 3
    assert report.by_level["ERROR"] == 3
    assert report.by_user["alice"] == 2


def test_invalid_records_excluded_from_level_and_user_counters() -> None:
    report = aggregate_counts([INVALID_LOG, None])
    assert report.total == 2
    assert report.invalid == 2
    assert report.by_level == {}
    assert report.by_user == {}


def test_user_level_cross_counter() -> None:
    report = aggregate_counts(SYSTEM_LOGS)
    assert report.by_user_level["alice"]["INFO"] == 1
    assert report.by_user_level["alice"]["ERROR"] == 1
    assert report.by_user_level["bob"]["ERROR"] == 1


def test_as_dict_returns_plain_dicts() -> None:
    exported = aggregate_counts(SYSTEM_LOGS).as_dict()
    assert type(exported["by_level"]) is dict
    assert type(exported["by_user_level"]["alice"]) is dict


def test_most_common_sorts_by_count_then_key() -> None:
    counts = count_by_user([*SYSTEM_LOGS, {"level": "INFO", "user": "zoe"}])
    assert most_common(counts) == [("alice", 2), ("bob", 1), ("zoe", 1)]
    assert most_common(counts, limit=1) == [("alice", 2)]
