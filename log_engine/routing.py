"""Route logs using structural pattern matching (match-case)."""

from ipaddress import ip_address
from typing import Any, TypeAlias

from log_engine.parsing import Record

LogItem: TypeAlias = str | Record | tuple[Any, ...]
Route: TypeAlias = tuple[str, str]


def _is_valid_connection(ip: str, port: int, protocol: str) -> bool:
    """Check the invariants of a normalized connection."""
    if isinstance(port, bool):  # bool est un sous-type de int : on l'exclut
        return False
    try:
        ip_address(ip)
    except ValueError:
        return False
    return 0 <= port <= 65_535 and bool(protocol.strip())


def route_log(item: LogItem) -> Route:
    """Route a log by structure and return its type and description."""
    match item:

        # Line rejected by the parser: {"raw_line": ..., "error": ...}
        case {"raw_line": _, "error": error}:
            return ("invalid", f"Ligne invalide : {error}")

        # Failed HTTP request: the status code acts as the error code
        case {"level": "ERROR" | "CRITICAL", "status": status, "path": path}:
            return ("http_error", f"Erreur HTTP {status} sur {path}")

        # Normally processed HTTP request
        case {"status": status, "method": method, "path": path}:
            return ("http", f"{method} {path} -> {status}")

        # Error log with an explicit code
        case {"level": ("ERROR" | "CRITICAL") as level, "code": code}:
            return ("dict", f"Alerte {level} (code {code})")

        # System log: dictionary containing a severity level
        case {"level": level}:
            return ("dict", f"Log de niveau {level}")

        # Empty or non-empty raw string
        case str() as text if not text.strip():
            return ("ignored", "Ligne vide ignoree")
        case str() as text:
            return ("raw", text)

        # Connection tuple (IP, port, protocol)
        case (str() as ip, int() as port, str() as protocol):
            if _is_valid_connection(ip, port, protocol):
                return ("connection", f"Connexion {protocol} depuis {ip}:{port}")
            return ("invalid", f"Connexion invalide : {ip}:{port}")

        # Unknown structure
        case _:
            return ("unknown", "Structure non reconnue")
