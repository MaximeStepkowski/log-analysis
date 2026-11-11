"""Module 3.1: unique IP addresses and set operations.

IPs are collected in a single pass over the record stream without storing
lines: memory depends on the number of *distinct* IPs, not the number of lines
read. The blacklist is an immutable ``frozenset`` and observed IPs are mutable
``set`` instances populated as the stream is consumed.
"""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path

from log_engine.parsing import Record

ERROR_LEVELS = frozenset({"ERROR", "CRITICAL"})
DEFAULT_BLACKLIST_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "blacklist.txt"
)


def load_blacklist(path: Path = DEFAULT_BLACKLIST_PATH) -> frozenset[str]:
    """Load the blacklist, one IP per line, into an immutable frozenset."""
    ips: set[str] = set()
    with open(path, encoding="utf-8") as file:
        for number, line in enumerate(file, start=1):
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                ip_address(entry)
            except ValueError as error:
                raise ValueError(
                    f"{path}, ligne {number} : adresse IP invalide '{entry}'"
                ) from error
            ips.add(entry)
    return frozenset(ips)


@dataclass
class IPCollector:
    """Accumulate active IPs and IPs that generated errors."""

    active_ips: set[str] = field(default_factory=set)
    error_ips: set[str] = field(default_factory=set)
    records_seen: int = 0
    error_records: int = 0

    def observe(self, record: Record) -> None:
        """Record the source IP; records without an IP are ignored."""
        match record:
            case {"connection": (str() as ip, _, _), "level": level}:
                self.records_seen += 1
                self.active_ips.add(ip)
                if level in ERROR_LEVELS:
                    self.error_records += 1
                    self.error_ips.add(ip)
            case _:
                pass


def track_ips(records: Iterable[Record], collector: IPCollector) -> Iterator[Record]:
    """Transparent pipeline step that feeds the collector and yields each record."""
    for record in records:
        collector.observe(record)
        yield record


@dataclass(frozen=True, slots=True)
class BlacklistReport:
    """Result of set operations between the blacklist and observed IPs."""

    blacklist: frozenset[str]
    active_ips: frozenset[str]
    error_ips: frozenset[str]
    # blacklist & active: blacklisted IPs that contacted the server
    blacklisted_active: frozenset[str]
    # blacklist - active: blacklisted IPs that remained silent
    dormant_blacklisted: frozenset[str]
    # active - blacklist: active IPs absent from the blacklist
    unlisted_active: frozenset[str]
    # blacklist | active: all known, blacklisted, or observed IPs
    known_ips: frozenset[str]
    # blacklist ^ active: IPs present in exactly one set
    only_in_one: frozenset[str]
    # blacklist & error_ips: blacklisted IPs that also generated errors
    blacklisted_errors: frozenset[str]


def compare_with_blacklist(
    blacklist: frozenset[str],
    active_ips: set[str],
    error_ips: set[str],
) -> BlacklistReport:
    """Compare the blacklist with observed IPs using |, &, -, and ^.

    ``frozenset(...)`` is applied to every result: the operation type depends
    on the left operand (``set - frozenset`` returns a ``set``), while the
    report must remain fully immutable.
    """
    return BlacklistReport(
        blacklist=blacklist,
        active_ips=frozenset(active_ips),
        error_ips=frozenset(error_ips),
        blacklisted_active=frozenset(blacklist & active_ips),
        dormant_blacklisted=frozenset(blacklist - active_ips),
        unlisted_active=frozenset(active_ips - blacklist),
        known_ips=frozenset(blacklist | active_ips),
        only_in_one=frozenset(blacklist ^ active_ips),
        blacklisted_errors=frozenset(blacklist & error_ips),
    )


def _sort_key(ip: str) -> tuple[int, int]:
    """Sort IPs numerically (192.168.1.9 before 192.168.1.10)."""
    address = ip_address(ip)
    return address.version, int(address)


def _describe(ips: frozenset[str], limit: int) -> str:
    """Return a sorted and truncated list of IPs for display."""
    ordered = sorted(ips, key=_sort_key)
    shown = ", ".join(ordered[:limit])
    if len(ordered) > limit:
        shown += f", ... (+{len(ordered) - limit})"
    return shown or "aucune"


def format_ip_report(
    collector: IPCollector,
    report: BlacklistReport,
    limit: int = 3,
) -> str:
    """Format the IP analysis with three addresses per set by default."""
    rows = (
        ("IP actives (uniques)", report.active_ips, "set"),
        ("IP ayant généré des erreurs", report.error_ips, "set"),
        ("IP blacklistées", report.blacklist, "frozenset"),
        ("IP blacklistées qui ont contacté le serveur", report.blacklisted_active, ""),
        ("IP blacklistées restées silencieuses", report.dormant_blacklisted, ""),
        ("IP actives non blacklistées", report.unlisted_active, ""),
        ("Toutes les IP blacklistées ou observées", report.known_ips, ""),
        ("Différence symétrique (blacklist ^ actives)", report.only_in_one, ""),
        ("IP blacklistées ayant généré des erreurs", report.blacklisted_errors, ""),
    )
    lines = [
        "\n=== ANALYSE DES ADRESSES IP (set / frozenset) ===",
        f" {'Records valides avec IP':<44}: {collector.records_seen:,} "
        f"dont {collector.error_records:,} en ERROR/CRITICAL",
    ]
    for label, ips, kind in rows:
        suffix = f" [{kind}]" if kind else ""
        lines.append(f" {label:<44}: {len(ips):>3}{suffix}")
        lines.append(f"      {_describe(ips, limit)}")
    return "\n".join(lines)
