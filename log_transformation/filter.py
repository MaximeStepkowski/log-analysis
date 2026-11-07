from datetime import datetime
from collections.abc import Iterable, Iterator
from typing import Any

# ============================================================
# CONSTANTES ET CRITERES DE FILTRAGE
# ============================================================

VALID_LEVELS = {"INFO", "WARNING", "ERROR", "CRITICAL"}

# ============================================================
# FILTRAGE DES ENTREES VIDES
# ============================================================

def delete_empty_entries(logs: Iterable[Any]) -> Iterator[Any]:
    """
    Supprime les entrées vides ou None.
    Utilisation de filter(None, ...).
    """

    return filter(None, logs)


# ============================================================
# VERIFICATION DE LA STRUCTURE DES LOGS
# ============================================================

def valid_log(log: Any) -> bool:
    """
    Vérifie que le log possède une structure exploitable.
    """

    if not isinstance(log, dict):
        return False

    timestamp = log.get("timestamp")
    if not isinstance(timestamp, (str, datetime)):
        return False

    if isinstance(timestamp, str) and not timestamp.strip():
        return False

    if log.get("level") not in VALID_LEVELS:
        return False

    if not isinstance(log.get("user"), str):
        return False

    if not isinstance(log.get("payload"), (dict, str)):
        return False

    connection = log.get("connection")
    if not isinstance(connection, tuple) or len(connection) != 3:
        return False

    ip, port, protocol = connection

    if not isinstance(ip, str) or not ip.strip():
        return False

    if not isinstance(port, int) or isinstance(port, bool):
        return False

    if not 1 <= port <= 65535:
        return False

    if not isinstance(protocol, str) or not protocol.strip():
        return False

    return True


def smart_filter(record: Any) -> bool:
    """Écarte les entrées vides et les logs invalides."""
    return any(filter(lambda entry: valid_log(entry), delete_empty_entries((record,))))