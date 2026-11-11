"""Detect brute-force attacks in HTTP logs."""

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from log_engine.ingestion import read_logs_from_directory
from log_engine.parsing import parse_line


LOGGER = logging.getLogger(__name__)
BRUTE_FORCE_THRESHOLD = 3
FAILED_STATUSES = frozenset({401, 403})


class BruteForceDetector:
    """Detect consecutive failures from already parsed records."""

    def __init__(self, threshold: int = BRUTE_FORCE_THRESHOLD) -> None:
        if threshold < 1:
            raise ValueError("Le seuil doit être supérieur ou égal à 1.")
        self.threshold = threshold
        self.failures: dict[str, int] = {}
        self.alerted_ips: set[str] = set()
        self.alerts: list[dict[str, Any]] = []

    def process(self, record: dict[str, Any]) -> None:
        """Analyze an HTTP record without rereading or reparsing its source."""
        ip = record["ip"]
        status = int(record["status"])

        if status in FAILED_STATUSES:
            # Each IP has its own consecutive-failure counter.
            self.failures[ip] = self.failures.get(ip, 0) + 1
            if self.failures[ip] >= self.threshold:
                self._add_alert(record, ip)
        elif status < 400:
            # A successful response ends this IP's failure streak.
            self.failures[ip] = 0
            self.alerted_ips.discard(ip)

    def process_cycles(self, records: Iterable[dict[str, Any]]) -> None:
        """Analyze each IP cycle without stopping the global analysis."""
        # A success separates two failure cycles for the same IP.
        cycles_by_ip: dict[str, list[list[dict[str, Any]]]] = {}
        current_cycles: dict[str, list[dict[str, Any]]] = {}

        for record in records:
            ip = record["ip"]
            status = int(record["status"])
            cycle = current_cycles.setdefault(ip, [])

            if status < 400:
                # Close the cycle before ignoring the successful record.
                if cycle:
                    cycles_by_ip.setdefault(ip, []).append(cycle)
                    current_cycles[ip] = []
                self.failures[ip] = 0
                self.alerted_ips.discard(ip)
                continue

            cycle.append(record)

        # Preserve cycles that end at the end of the file.
        for ip, cycle in current_cycles.items():
            if cycle:
                cycles_by_ip.setdefault(ip, []).append(cycle)

        for ip, cycles in cycles_by_ip.items():
            cycle_index = 0
            while cycle_index < len(cycles):
                cycle = cycles[cycle_index]
                self.failures[ip] = 0
                self.alerted_ips.discard(ip)

                for record in cycle:
                    status = int(record["status"])
                    if status not in FAILED_STATUSES:
                        # Statuses other than 401/403 do not count as failures.
                        continue

                    self.failures[ip] += 1
                    if self.failures[ip] >= self.threshold:
                        self._add_alert(record, ip)
                        # This alert ends only the current cycle.
                        break
                else:
                    # This block runs when the cycle ends without reaching the threshold.
                    LOGGER.info("Cycle de détection terminé sans alerte pour %s", ip)

                cycle_index += 1

        self.alerts.sort(key=lambda alert: alert.get("timestamp"))

    def _add_alert(self, record: dict[str, Any], ip: str) -> None:
        """Add an alert if this IP has not already been reported."""
        if ip in self.alerted_ips:
            return

        # The record reaching the threshold provides the alert details.
        alert = {
            "ip": ip,
            "attempts": self.failures[ip],
            "timestamp": record.get("timestamp"),
            "status": int(record["status"]),
            "message": (
                f"Force brute détectée depuis {ip}: "
                f"{self.failures[ip]} échecs consécutifs"
            ),
        }
        self.alerts.append(alert)
        self.alerted_ips.add(ip)
        LOGGER.warning(alert["message"])


def _parse_records(lines_or_records: Iterable[str | dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse lines and keep valid HTTP records."""
    records = []
    for item in lines_or_records:
        # Strings are parsed; dictionaries are already usable records.
        record = parse_line(item) if isinstance(item, str) else item
        if not record or "ip" not in record or "status" not in record:
            # An invalid line must not interrupt the entire analysis.
            LOGGER.warning("Log ignoré pendant la détection de force brute: %s", item)
            continue
        records.append(record)
    # Detection must preserve the chronological order of events.
    return sorted(records, key=lambda record: record.get("timestamp"))


def detect_brute_force(
    lines_or_records: Iterable[str | dict[str, Any]],
    threshold: int = BRUTE_FORCE_THRESHOLD,
) -> list[dict[str, Any]]:
    """Return alerts for three consecutive failures from the same IP.

    HTTP statuses 401 and 403 count as failures. Any status below 400 resets
    the failure streak for the corresponding IP.
    """
    records = _parse_records(lines_or_records)
    detector = BruteForceDetector(threshold)
    # The detector then processes every cycle instead of stopping at the first alert.
    detector.process_cycles(records)

    return detector.alerts


def write_report(alerts: Iterable[dict[str, Any]], output: str | Path) -> None:
    """Write an alert report to the specified file."""
    alert_list = list(alerts)
    output_path = Path(output)
    # The output directory may not exist on the first run.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_format_report(alert_list), encoding="utf-8")


def _format_report(alerts: Iterable[dict[str, Any]]) -> str:
    """Build the text shared by the CLI and the report file."""
    alert_list = list(alerts)
    report_lines = [f"Nombre d'alertes de force brute : {len(alert_list)}"]
    report_lines.extend(
        f"- IP {alert['ip']} : {alert['attempts']} échecs consécutifs "
        f"(statut {alert['status']}, date {alert['timestamp']})"
        for alert in alert_list
    )
    return "\n".join(report_lines) + "\n"


def detect_brute_force_from_directory(
    directory: str | Path,
    pattern: str = "*.log",
    threshold: int = BRUTE_FORCE_THRESHOLD,
) -> list[dict[str, Any]]:
    """Analyze a directory's log files and return the alerts."""
    return detect_brute_force(
        read_logs_from_directory(Path(directory), pattern), threshold=threshold
    )

