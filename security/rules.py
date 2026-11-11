"""Detection rules used by the security engine."""

from typing import Any

from security.engine import Finding, Record, SecurityContext


def _record_ip(record: Record) -> str | None:
    """Return the IP from a system or HTTP record."""
    if isinstance(record.get("ip"), str):
        return record["ip"]
    connection = record.get("connection")
    if isinstance(connection, tuple) and connection and isinstance(connection[0], str):
        return connection[0]
    return None


def rule_blacklisted_ip(
    *, record: Record, context: SecurityContext, **_: Any
) -> Finding | None:
    """Report an address that appears in the blacklist."""
    ip = _record_ip(record)
    if ip is not None and ip in context.blacklist:
        return {
            "rule": "blacklisted_ip",
            "message": f"IP blacklistée détectée : {ip}",
            "ip": ip,
            "timestamp": record.get("timestamp"),
        }
    return None


def rule_http_errors(
    *,
    record: Record,
    context: SecurityContext,
    http_error_threshold: int = 3,
    **_: Any,
) -> Finding | None:
    """Report when an IP crosses the HTTP error threshold."""
    status = record.get("status")
    ip = _record_ip(record)
    if ip is None or status is None or not 400 <= int(status) <= 599:
        return None

    context.http_errors_by_ip[ip] += 1
    count = context.http_errors_by_ip[ip]
    if count < http_error_threshold or ip in context.alerted_http_error_ips:
        return None

    context.alerted_http_error_ips.add(ip)
    return {
        "rule": "http_error_threshold",
        "message": (
            f"Seuil d'erreurs HTTP atteint pour {ip} : "
            f"{count} erreurs"
        ),
        "ip": ip,
        "count": count,
        "threshold": http_error_threshold,
        "status": int(status),
        "timestamp": record.get("timestamp"),
    }


def rule_brute_force(
    *, record: Record, context: SecurityContext, **_: Any
) -> Finding | None:
    """Report a new alert produced by the brute-force detector."""
    if "ip" not in record or "status" not in record:
        return None

    alert_count = len(context.brute_force_detector.alerts)
    context.brute_force_detector.process(record)
    if len(context.brute_force_detector.alerts) == alert_count:
        return None

    alert = context.brute_force_detector.alerts[-1]
    return {
        "rule": "brute_force",
        "message": alert["message"],
        "ip": alert["ip"],
        "attempts": alert["attempts"],
        "status": alert["status"],
        "timestamp": alert["timestamp"],
    }
