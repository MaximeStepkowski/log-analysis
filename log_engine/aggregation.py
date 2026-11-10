"""Comptage des occurrences par catégorie, niveau et utilisateur (defaultdict)."""

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
    """Cree un compteur dont toute cle absente vaut 0."""
    return defaultdict(int)


def new_nested_counter() -> NestedCounter:
    """Cree un compteur a deux niveaux (ex: utilisateur -> niveau)."""
    return defaultdict(new_counter)


@dataclass
class CountReport:
    """Compteurs accumules sur un flux d'enregistrements."""

    by_category: Counter = field(default_factory=new_counter)
    by_level: Counter = field(default_factory=new_counter)
    by_user: Counter = field(default_factory=new_counter)
    by_user_level: NestedCounter = field(default_factory=new_nested_counter)
    total: int = 0
    invalid: int = 0

    @property
    def valid(self) -> int:
        """Nombre d'enregistrements exploitables."""
        return self.total - self.invalid

    def update(self, record: Record | None) -> str:
        """Comptabilise un enregistrement et renvoie sa categorie."""
        self.total += 1
        category = category_of(record)
        self.by_category[category] += 1

        # Une ligne rejetee n'a ni niveau ni utilisateur : la compter
        # fausserait les deux repartitions.
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
        """Convertit le rapport en dictionnaires standards (affichage, JSON)."""
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
    """Categorie d'un enregistrement, deduite du routage match-case."""
    if record is None:
        return "invalid"
    category, _ = route_log(record)
    return category


def level_of(record: Record) -> str:
    """Niveau de severite, ou valeur de repli si le champ est absent ou vide."""
    return str(record.get("level") or UNKNOWN_KEY)


def user_of(record: Record) -> str:
    """Identifiant utilisateur, ou valeur de repli si le champ est absent ou vide."""
    return str(record.get("user") or UNKNOWN_KEY)


def count_occurrences(
    records: Iterable[Record],
    key: Callable[[Record], str],
) -> Counter:
    """Compte les occurrences d'un flux selon une fonction de cle."""
    counts = new_counter()
    for record in records:
        if record is None:
            continue
        counts[key(record)] += 1
    return counts


def count_by_level(records: Iterable[Record]) -> Counter:
    """Compte les enregistrements par niveau de severite."""
    return count_occurrences(records, level_of)


def count_by_user(records: Iterable[Record]) -> Counter:
    """Compte les enregistrements par utilisateur."""
    return count_occurrences(records, user_of)


def count_by_category(records: Iterable[Record]) -> Counter:
    """Compte les enregistrements par categorie de log."""
    return count_occurrences(records, category_of)


def aggregate_counts(records: Iterable[Record | None]) -> CountReport:
    """Agrege tous les compteurs en une seule passe sur le flux."""
    report = CountReport()
    for record in records:
        report.update(record)
    return report


def most_common(counts: Counter, limit: int | None = None) -> list[tuple[str, int]]:
    """Trie un compteur par occurrences decroissantes, puis par cle."""
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ranked if limit is None else ranked[:limit]
