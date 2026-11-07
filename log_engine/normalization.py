"""Normalisation des enregistrements de logs déjà parsés."""

from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from log_engine.parsing import Record


def normalize_record(record: "Record | None") -> "Record | None":
    """Nettoie et normalise un enregistrement déjà parsé."""
    if record is None:
        return None

    normalized = record.copy()

    for key, value in record.items():
        if isinstance(value, str):
            normalized[key] = " ".join(value.split())

    if "level" in normalized:
        normalized["level"] = normalized["level"].upper()
    if "protocol" in normalized:
        normalized["protocol"] = normalized["protocol"].upper()
    if "method" in normalized:
        normalized["method"] = normalized["method"].upper()

    for key in ("status", "bytes", "duration_ms"):
        if key in normalized:
            normalized[key] = int(normalized[key])

    if "bytes_sent" in normalized:
        normalized["bytes_sent"] = int(normalized["bytes_sent"])

    if "connection" not in record:
        return normalized

    if isinstance(record.get("timestamp"), datetime):
        normalized["timestamp"] = record["timestamp"]
    else:
        normalized["timestamp"] = f"{record['timestamp']}".strip()
    normalized["user"] = f"{record['user']}".strip()
    if "level" in record and "ip" not in record:
        normalized["user"] = normalized["user"].lower()

    ip, port, protocol = record["connection"]
    normalized["connection"] = (
        f"{ip}".strip(),
        int(port),
        f"{protocol}".strip().upper(),
    )

    payload = record["payload"]
    if isinstance(payload, dict):
        normalized["payload"] = {
            key: value.strip() if isinstance(value, str) else value
            for key, value in payload.items()
        }
    else:
        normalized["payload"] = " ".join(f"{payload}".split())

    return normalized
