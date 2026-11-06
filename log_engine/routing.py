"""Routage des logs par Structural Pattern Matching (match-case)."""

from typing import Any, TypeAlias

Record: TypeAlias = dict[str, Any]
Route: TypeAlias = tuple[str, str]


def route_log(item: Any) -> Route:
    """Route un log selon sa structure et renvoie son type et sa description."""
    match item:

        # Ligne rejetee par le parser : {"raw_line": ..., "error": ...}
        case {"error": error}:
            return ("invalid", f"Ligne invalide : {error}")

        # Requete HTTP en echec : le code de statut joue le role du code d'erreur
        case {"level": "ERROR" | "CRITICAL", "status": status, "path": path}:
            return ("http_error", f"Erreur HTTP {status} sur {path}")

        # Requete HTTP traitee normalement
        case {"status": status, "method": method, "path": path}:
            return ("http", f"{method} {path} -> {status}")

        # Log systeme : dictionnaire porteur d'un niveau de severite
        case {"level": level}:
            return ("dict", f"Log de niveau {level}")

        # Chaine brute (payload des formats combined et cle=valeur)
        case str() as text:
            return ("raw", text)

        # Tuple de connexion (IP, Port, Protocole)
        case (ip, port, protocol):
            return ("connection", f"Connexion {protocol} depuis {ip}:{port}")

        # Structure inconnue
        case _:
            return ("unknown", "Structure non reconnue")
