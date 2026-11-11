"""Module 3.1 : unicité des adresses IP et opérations d'ensembles.

Les IP sont collectées en un seul passage sur le flux de records, sans jamais
stocker les lignes : la mémoire dépend du nombre d'IP *distinctes*, pas du
nombre de lignes lues. La liste noire est un ``frozenset`` (immuable), les IP
observées sont des ``set`` (mutables, alimentés au fil de l'eau).
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
    """Charge la liste noire (une IP par ligne) dans un frozenset immuable."""
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
    """Accumule les IP actives et les IP ayant généré des erreurs."""

    active_ips: set[str] = field(default_factory=set)
    error_ips: set[str] = field(default_factory=set)
    records_seen: int = 0
    error_records: int = 0

    def observe(self, record: Record) -> None:
        """Enregistre l'IP source d'un record (les records sans IP sont ignorés)."""
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
    """Étape de pipeline transparente : alimente le collecteur, rend chaque record."""
    for record in records:
        collector.observe(record)
        yield record


@dataclass(frozen=True, slots=True)
class BlacklistReport:
    """Résultat des opérations d'ensembles entre la liste noire et les IP vues."""

    blacklist: frozenset[str]
    active_ips: frozenset[str]
    error_ips: frozenset[str]
    # blacklist & active : IP blacklistées qui ont bien contacté le serveur
    blacklisted_active: frozenset[str]
    # blacklist - active : IP blacklistées restées silencieuses
    dormant_blacklisted: frozenset[str]
    # active - blacklist : IP actives absentes de la liste noire
    unlisted_active: frozenset[str]
    # blacklist | active : toutes les IP connues, listées ou observées
    known_ips: frozenset[str]
    # blacklist ^ active : IP à réconcilier, présentes dans un seul ensemble
    only_in_one: frozenset[str]
    # blacklist & error_ips : IP blacklistées qui ont aussi généré des erreurs
    blacklisted_errors: frozenset[str]


def compare_with_blacklist(
    blacklist: frozenset[str],
    active_ips: set[str],
    error_ips: set[str],
) -> BlacklistReport:
    """Croise la liste noire avec les IP observées (|, &, -, ^).

    ``frozenset(...)`` est appliqué à chaque résultat : le type d'une opération
    dépend de l'opérande de gauche (``set - frozenset`` renvoie un ``set``),
    alors que le rapport doit rester entièrement immuable.
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
    """Tri numérique des IP (192.168.1.9 avant 192.168.1.10)."""
    address = ip_address(ip)
    return address.version, int(address)


def _describe(ips: frozenset[str], limit: int) -> str:
    """Liste triée et tronquée des IP, pour l'affichage."""
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
    """Met en forme l'analyse des IP, avec trois adresses par ensemble par défaut."""
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
