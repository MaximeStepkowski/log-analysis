"""Routage des logs par Structural Pattern Matching (match-case)."""

from ipaddress import ip_address
from typing import Any, TypeAlias

from log_engine.parsing import Record

LogItem: TypeAlias = str | Record | tuple[Any, ...]
Route: TypeAlias = tuple[str, str]


def _is_valid_connection(ip: str, port: int, protocol: str) -> bool:
    """Verifie les invariants d'une connexion normalisee."""
    if isinstance(port, bool):  # bool est un sous-type de int : on l'exclut
        return False
    try:
        ip_address(ip)
    except ValueError:
        return False
    return 0 <= port <= 65_535 and bool(protocol.strip())


def route_log(item: LogItem) -> Route:
    """Route un log selon sa structure et renvoie son type et sa description."""
    match item:

        # Ligne rejetee par le parser : {"raw_line": ..., "error": ...}
        case {"raw_line": _, "error": error}:
            return ("invalid", f"Ligne invalide : {error}")

        # Requete HTTP en echec : le code de statut joue le role du code d'erreur
        case {"level": "ERROR" | "CRITICAL", "status": status, "path": path}:
            return ("http_error", f"Erreur HTTP {status} sur {path}")

        # Requete HTTP traitee normalement
        case {"status": status, "method": method, "path": path}:
            return ("http", f"{method} {path} -> {status}")

        # Log d'erreur portant un code explicite
        case {"level": ("ERROR" | "CRITICAL") as level, "code": code}:
            return ("dict", f"Alerte {level} (code {code})")

        # Log systeme : dictionnaire porteur d'un niveau de severite
        case {"level": level}:
            return ("dict", f"Log de niveau {level}")

        # Chaine brute vide ou non vide
        case str() as text if not text.strip():
            return ("ignored", "Ligne vide ignoree")
        case str() as text:
            return ("raw", text)

        # Tuple de connexion (IP, Port, Protocole)
        case (str() as ip, int() as port, str() as protocol):
            if _is_valid_connection(ip, port, protocol):
                return ("connection", f"Connexion {protocol} depuis {ip}:{port}")
            return ("invalid", f"Connexion invalide : {ip}:{port}")

        # Structure inconnue
        case _:
            return ("unknown", "Structure non reconnue")
