"""Count occurrences by category, level, and user (defaultdict)."""

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, TypeAlias

from log_engine.routing import route_log

Record: TypeAlias = dict[str, Any]
Counter: TypeAlias = defaultdict[str, int]
NestedCounter: TypeAlias = defaultdict[str, Counter]

UNKNOWN_KEY = "<inconnu>"


def new_counter() -> Counter:
    """Create a counter whose missing keys default to zero."""
    return defaultdict(int)


def new_nested_counter() -> NestedCounter:
    """Create a two-level counter, for example user -> level."""
    return defaultdict(new_counter)


@dataclass
class CountReport:
    """Counters accumulated from a record stream."""

    by_category: Counter = field(default_factory=new_counter)
    by_level: Counter = field(default_factory=new_counter)
    by_user: Counter = field(default_factory=new_counter)
    by_user_level: NestedCounter = field(default_factory=new_nested_counter)
    total: int = 0
    invalid: int = 0

    @property
    def valid(self) -> int:
        """Return the number of usable records."""
        return self.total - self.invalid

    def update(self, record: Record | None, category: str | None = None) -> str:
        """Count a record and return its category."""
        self.total += 1
        category = category if category is not None else category_of(record)
        self.by_category[category] += 1

        # A rejected line has no level or user; counting it would skew both
        # distributions.
        if record is None or category == "invalid":
            self.invalid += 1
            return category

        level = level_of(record)
        user = user_of(record)
        self.by_level[level] += 1
        self.by_user[user] += 1
        self.by_user_level[user][level] += 1
        return category

    def as_dict(self) -> dict[str, Any]:
        """Convert the report to standard dictionaries for display or JSON."""
        return {
            "total": self.total,
            "valid": self.valid,
            "invalid": self.invalid,
            "by_category": dict(self.by_category),
            "by_level": dict(self.by_level),
            "by_user": dict(self.by_user),
            "by_user_level": {
                user: dict(levels) for user, levels in self.by_user_level.items()
            },
        }


def category_of(record: Record | None) -> str:
    """Return a record category derived from match-case routing."""
    if record is None:
        return "invalid"
    category, _ = route_log(record)
    return category


def level_of(record: Record) -> str:
    """Return the severity level, or a fallback when the field is empty or missing."""
    return str(record.get("level") or UNKNOWN_KEY)


def user_of(record: Record) -> str:
    """Return the user identifier, or a fallback when the field is empty or missing."""
    return str(record.get("user") or UNKNOWN_KEY)


def count_occurrences(
    records: Iterable[Record],
    key: Callable[[Record], str],
) -> Counter:
    """Count stream occurrences using a key function."""
    counts = new_counter()
    for record in records:
        if record is None:
            continue
        counts[key(record)] += 1
    return counts


def count_by_level(records: Iterable[Record]) -> Counter:
    """Count records by severity level."""
    return count_occurrences(records, level_of)


def count_by_user(records: Iterable[Record]) -> Counter:
    """Count records by user."""
    return count_occurrences(records, user_of)


def count_by_category(records: Iterable[Record]) -> Counter:
    """Count records by log category."""
    return count_occurrences(records, category_of)


def aggregate_counts(records: Iterable[Record | None]) -> CountReport:
    """Aggregate all counters in a single pass over the stream."""
    report = CountReport()
    for record in records:
        report.update(record)
    return report


def most_common(counts: Counter, limit: int | None = None) -> list[tuple[str, int]]:
    """Sort a counter by descending occurrence count, then by key."""
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ranked if limit is None else ranked[:limit]
