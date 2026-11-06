"""Module 3.2 : accumulation dynamique des compteurs via ``defaultdict``.

Tous les compteurs reposent sur :class:`collections.defaultdict`, ce qui permet
d'incrémenter une clé inconnue sans jamais lever de ``KeyError`` ni tester son
existence au préalable.

L'agrégation se fait en **une seule passe** sur le flux : un pipeline de logs est
un itérateur à usage unique, on ne peut donc pas le parcourir une fois par
critère de comptage.
"""

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, TypeAlias

from log_engine.routing import route_log

Record: TypeAlias = dict[str, Any]
Counter: TypeAlias = defaultdict[str, int]
NestedCounter: TypeAlias = defaultdict[str, Counter]

#: Valeur de repli lorsqu'un enregistrement ne porte pas le champ attendu.
UNKNOWN_KEY = "<inconnu>"


def new_counter() -> Counter:
    """Crée un compteur vide : toute clé absente vaut 0."""
    return defaultdict(int)


def new_nested_counter() -> NestedCounter:
    """Crée un compteur à deux niveaux (ex: utilisateur -> niveau)."""
    return defaultdict(new_counter)


@dataclass
class CountReport:
    """Résultat d'une passe d'agrégation sur un flux d'enregistrements."""

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
        """Comptabilise un enregistrement et renvoie sa catégorie.

        Permet d'alimenter le rapport depuis une boucle existante, sans
        reparcourir le flux une seconde fois.
        """
        self.total += 1
        category = category_of(record)
        self.by_category[category] += 1

        if record is None or category == "invalid":
            self.invalid += 1
            return category

        level = level_of(record)
        user = user_of(record)
        self.by_level[level] += 1
        self.by_user[user] += 1
        # defaultdict imbriqué : ni la clé utilisateur ni la clé niveau
        # n'ont besoin d'être initialisées.
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
    """Catégorie d'un enregistrement, déduite du routage match-case."""
    if record is None:
        return "invalid"
    category, _ = route_log(record)
    return category


def level_of(record: Record) -> str:
    """Niveau de sévérité, ou valeur de repli si le champ est absent."""
    return str(record.get("level") or UNKNOWN_KEY)


def user_of(record: Record) -> str:
    """Identifiant utilisateur, ou valeur de repli si le champ est absent."""
    return str(record.get("user") or UNKNOWN_KEY)


def count_occurrences(
    records: Iterable[Record],
    key: Callable[[Record], str],
) -> Counter:
    """Compte les occurrences d'un flux selon une fonction de clé.

    La fonction de clé est passée en argument (objet de première classe), ce qui
    permet de réutiliser le même compteur pour n'importe quel critère.

    Args:
        records: flux d'enregistrements parsés.
        key: fonction extrayant la clé de regroupement d'un enregistrement.

    Returns:
        Un ``defaultdict`` associant chaque clé à son nombre d'occurrences.

    Examples:
        >>> counts = count_occurrences([{"level": "INFO"}], level_of)
        >>> counts["INFO"], counts["JAMAIS_VU"]
        (1, 0)
    """
    counts = new_counter()
    for record in records:
        if record is None:
            continue
        counts[key(record)] += 1
    return counts


def count_by_level(records: Iterable[Record]) -> Counter:
    """Compte les enregistrements par niveau de sévérité."""
    return count_occurrences(records, level_of)


def count_by_user(records: Iterable[Record]) -> Counter:
    """Compte les enregistrements par utilisateur."""
    return count_occurrences(records, user_of)


def count_by_category(records: Iterable[Record]) -> Counter:
    """Compte les enregistrements par catégorie de log (routage match-case)."""
    return count_occurrences(records, category_of)


def aggregate_counts(records: Iterable[Record | None]) -> CountReport:
    """Agrège tous les compteurs en une seule passe sur le flux.

    Les lignes rejetées par le parser sont comptées dans ``by_category`` sous la
    catégorie ``"invalid"`` mais exclues des compteurs par niveau et par
    utilisateur, qu'elles fausseraient.

    Args:
        records: flux paresseux d'enregistrements (``parse_logs``, ``map``...).

    Returns:
        Un :class:`CountReport` renseigné.
    """
    report = CountReport()
    for record in records:
        report.update(record)
    return report


def most_common(counts: Counter, limit: int | None = None) -> list[tuple[str, int]]:
    """Trie un compteur par occurrences décroissantes, puis par clé.

    Args:
        counts: compteur à trier.
        limit: nombre maximum d'entrées renvoyées (``None`` = toutes).

    Returns:
        Une liste de couples ``(clé, occurrences)``.
    """
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ranked if limit is None else ranked[:limit]
