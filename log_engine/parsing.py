"""Module 1 : parsing des lignes de logs vers des dictionnaires Python."""

import json
import re
from concurrent.futures import ProcessPoolExecutor
from collections.abc import Iterable, Iterator
from functools import lru_cache
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, TypeAlias

Record: TypeAlias = dict[str, Any]

from log_engine.normalization import normalize_record

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

# 192.168.1.9:49152 - - [29/Oct/2026:18:20:52 +0000] "POST /index.html HTTP/1.1" 200 10121 "-" "curl/7.68.0"
HTTP_COMBINED_PATTERN = re.compile(
    r'^(?P<ip>[\d.]+)(?::(?P<port>\d+))? - - \[(?P<timestamp>[^]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) (?P<protocol>HTTP/[\d.]+)" '
    r'(?P<status>\d{3}) (?P<bytes_sent>\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"$'
)

# time="2026-10-29 18:20:52" client_ip=192.168.1.9 client_port=49152 method=GET path="/" status=200 bytes=123 duration_ms=42 agent="curl/7.68.0"
HTTP_KV_PATTERN = re.compile(
    r'^time="(?P<timestamp>.*?)" client_ip=(?P<ip>[\d.]+)(?: client_port=(?P<port>\d+))? '
    r'method=(?P<method>\w+) path="(?P<path>.*?)" '
    r'status=(?P<status>\d{3}) bytes=(?P<bytes_sent>\d+) '
    r'duration_ms=(?P<duration_ms>\d+) agent="(?P<user_agent>.*?)"$'
)


def invalid_record(line: str, error: str) -> Record:
    """Construit un dictionnaire décrivant une ligne invalide."""
    return {"raw_line": line, "error": error}


@lru_cache(maxsize=256)
def parse_timestamp(value: str) -> datetime:
    """Convertit les formats de date supportés et rejette les dates invalides."""
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"

    if "T" in normalized or normalized[4:5] == "-":
        try:
            parsed = datetime.fromisoformat(normalized)
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        except ValueError:
            pass

    try:
        return datetime.strptime(normalized, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError as error:
        raise ValueError(f"Horodatage invalide: {value}") from error


@lru_cache(maxsize=256)
def validate_ip(value: str) -> str:
    """Valide une adresse IPv4 ou IPv6 et renvoie sa représentation texte."""
    try:
        ip_address(value)
    except ValueError as error:
        raise ValueError(f"Adresse IP invalide: {value}") from error
    return value


def build_record(
    timestamp: str,
    level: str,
    ip: str,
    port: int | str,
    protocol: str,
    user: str,
    payload: Any,
) -> Record:
    """Construit le dictionnaire d'un log ou lève une erreur de validation."""
    if level not in LEVELS:
        raise ValueError(f"Niveau de sévérité invalide: {level}")

    return {
        "timestamp": parse_timestamp(timestamp),
        "level": level,
        "user": user,
        "payload": payload,
        # metadonnees fixes immuables : (IP, Port, Protocole)
        "connection": (validate_ip(ip), int(port), protocol),
    }


def build_http_record(
    timestamp: str,
    ip: str,
    method: str,
    path: str,
    status: int | str,
    bytes_sent: int | str,
    port: int | str | None = None,
    protocol: str = "HTTP/1.1",
    duration_ms: int | str | None = None,
    referer: str = "-",
    user_agent: str = "",
    payload: Any = None,
) -> Record:
    """Construit un enregistrement à partir d'un log HTTP."""
    status = int(status)
    if status >= 500:
        level = "CRITICAL"
    elif status >= 400:
        level = "ERROR"
    elif status >= 300:
        level = "WARNING"
    else:
        level = "INFO"

    validated_ip = validate_ip(ip)
    record = {
        "timestamp": parse_timestamp(timestamp),
        "level": level,
        "user": user_agent,
        "payload": payload,
        "ip": validated_ip,
        "method": method,
        "path": path,
        "protocol": protocol,
        "status": status,
        "bytes": int(bytes_sent),
        "referer": referer,
        "user_agent": user_agent,
        "connection": (validated_ip, int(port) if port is not None else 80, protocol),
    }
    if duration_ms is not None:
        record["duration_ms"] = int(duration_ms)
    return record


def parse_line(line: str) -> Record | None:
    """Parse une ligne de log et renvoie un dict, ou None si la ligne est invalide."""
    if not line or not line.strip():
        return invalid_record(line, "Ligne vide")

    line = line.strip()

    # Format JSON : le payload est le dictionnaire JSON complet
    if line.startswith("{"):
        try:
            data = json.loads(line)
            if "remote_addr" in data:
                return build_http_record(
                    data["timestamp"],
                    data["remote_addr"],
                    data["request_method"],
                    data["request_uri"],
                    data["status"],
                    data["body_bytes_sent"],
                    port=data.get("remote_port"),
                    duration_ms=data.get("request_time_ms"),
                    referer=data.get("http_referrer", "-"),
                    user_agent=data.get("http_user_agent", ""),
                    payload=data,
                )
            return build_record(
                data["timestamp"], data["level"], data["ip"], data["port"],
                data["protocol"], data["user"], data,
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            return invalid_record(line, str(error))

    http_match = HTTP_COMBINED_PATTERN.match(line)
    if http_match is not None:
        try:
            return build_http_record(**http_match.groupdict(), payload=line)
        except (TypeError, ValueError) as error:
            return invalid_record(line, str(error))

    http_match = HTTP_KV_PATTERN.match(line)
    if http_match is not None:
        try:
            return build_http_record(**http_match.groupdict(), payload=line)
        except (TypeError, ValueError) as error:
            return invalid_record(line, str(error))

    # Formats de logs système : clé=valeur puis format brut
    match = KV_PATTERN.match(line) or RAW_PATTERN.match(line)
    if match is None:
        return invalid_record(line, "Format de ligne inconnu")

    try:
        fields = match.groupdict()
        fields.setdefault("protocol", "HTTP")
        return build_record(**fields)
    except (TypeError, ValueError) as error:
        return invalid_record(line, str(error))


def parse_logs(lines: Iterable[str]) -> Iterator[Record]:
    """Parse et normalise chaque ligne sans supprimer les enregistrements invalides."""
    parsed_records = map(parse_line, lines)
    yield from map(normalize_record, parsed_records)


def _parse_batch(lines: list[str]) -> list[Record | None]:
    """Parse un lot dans un processus worker."""
    return list(map(normalize_record, map(parse_line, lines)))


def parse_logs_parallel(
    lines: Iterable[str],
    workers: int,
    batch_size: int = 2_000,
) -> Iterator[Record]:
    """Parse les lignes en parallèle avec un nombre borné de lots en mémoire."""
    if workers < 2:
        yield from parse_logs(lines)
        return

    def batches() -> Iterator[list[str]]:
        batch: list[str] = []
        for line in lines:
            batch.append(line)
            if len(batch) == batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

    with ProcessPoolExecutor(max_workers=workers) as executor:
        pending = []
        batches_iterator = iter(batches())

        for _ in range(workers * 2):
            try:
                pending.append(executor.submit(_parse_batch, next(batches_iterator)))
            except StopIteration:
                break

        while pending:
            future = pending.pop(0)
            yield from future.result()
            try:
                pending.append(executor.submit(_parse_batch, next(batches_iterator)))
            except StopIteration:
                pass
