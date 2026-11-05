"""Module 1 : parsing des lignes de logs vers des dictionnaires Python."""

import json
import re

LEVELS = ("INFO", "WARNING", "ERROR", "CRITICAL")

# 2026-10-29 15:26:45 | LEVEL=INFO | CONNECTION=(192.168.1.83,24649,UDP) | USER=bob | MSG="..."
KV_PATTERN = re.compile(
    r'^(?P<timestamp>[\d-]+ [\d:]+) \| LEVEL=(?P<level>\w+) \| '
    r'CONNECTION=\((?P<ip>[\d.]+),(?P<port>\d+),(?P<protocol>\w+)\) \| '
    r'USER=(?P<user>\w+) \| MSG="(?P<payload>.*)"$'
)

# 2026-10-29 15:26:48 INFO 10.0.0.43:63092 [david] - Unauthorized access attempt detected
RAW_PATTERN = re.compile(
    r'^(?P<timestamp>[\d-]+ [\d:]+) (?P<level>\w+) '
    r'(?P<ip>[\d.]+):(?P<port>\d+) \[(?P<user>\w+)\] - (?P<payload>.*)$'
)


def build_record(timestamp, level, ip, port, protocol, user, payload):
    """Construit le dictionnaire d'un log, ou None si le niveau est invalide."""
    if level not in LEVELS:
        return None

    return {
        "timestamp": timestamp,
        "level": level,
        "user": user,
        "payload": payload,
        # metadonnees fixes immuables : (IP, Port, Protocole)
        "connection": (ip, int(port), protocol),
    }


def parse_line(line):
    """Parse une ligne de log et renvoie un dict, ou None si la ligne est invalide."""
    if not line or not line.strip():
        return None

    line = line.strip()

    # Format JSON : le payload est le dictionnaire JSON complet
    if line.startswith("{"):
        try:
            data = json.loads(line)
            return build_record(
                data["timestamp"], data["level"], data["ip"], data["port"],
                data["protocol"], data["user"], data,
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return None

    # Format cle=valeur puis format brut : le payload est la chaine brute
    match = KV_PATTERN.match(line) or RAW_PATTERN.match(line)
    if match is None:
        return None

    try:
        return build_record(**match.groupdict())
    except (TypeError, ValueError):
        return None


def parse_logs(lines):
    """Parse un flux de lignes et ne laisse passer que les logs valides (generateur)."""
    for line in lines:
        record = parse_line(line)
        if record is not None:
            yield record
