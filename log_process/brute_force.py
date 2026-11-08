"""Détection d'attaques par force brute dans les logs HTTP."""

import argparse
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
    """Détecte les échecs consécutifs en consommant des records déjà parsés."""

    def __init__(self, threshold: int = BRUTE_FORCE_THRESHOLD) -> None:
        if threshold < 1:
            raise ValueError("Le seuil doit être supérieur ou égal à 1.")
        self.threshold = threshold
        self.failures: dict[str, int] = {}
        self.alerted_ips: set[str] = set()
        self.alerts: list[dict[str, Any]] = []

    def process(self, record: dict[str, Any]) -> None:
        """Analyse un record HTTP sans relire ni reparser sa source."""
        ip = record["ip"]
        status = int(record["status"])

        if status in FAILED_STATUSES:
            self.failures[ip] = self.failures.get(ip, 0) + 1
            if self.failures[ip] >= self.threshold and ip not in self.alerted_ips:
                alert = {
                    "ip": ip,
                    "attempts": self.failures[ip],
                    "timestamp": record.get("timestamp"),
                    "status": status,
                    "message": (
                        f"Force brute détectée depuis {ip}: "
                        f"{self.failures[ip]} échecs consécutifs"
                    ),
                }
                self.alerts.append(alert)
                self.alerted_ips.add(ip)
                LOGGER.warning(alert["message"])
        elif status < 400:
            self.failures[ip] = 0
            self.alerted_ips.discard(ip)


def _parse_records(lines_or_records: Iterable[str | dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse les lignes et conserve les enregistrements HTTP valides."""
    records = []
    for item in lines_or_records:
        record = parse_line(item) if isinstance(item, str) else item
        if not record or "ip" not in record or "status" not in record:
            LOGGER.warning("Log ignoré pendant la détection de force brute: %s", item)
            continue
        records.append(record)
    return sorted(records, key=lambda record: record.get("timestamp"))


def detect_brute_force(
    lines_or_records: Iterable[str | dict[str, Any]],
    threshold: int = BRUTE_FORCE_THRESHOLD,
) -> list[dict[str, Any]]:
    """Retourne les alertes pour trois échecs consécutifs d'une même IP.

    Les statuts HTTP 401 et 403 sont considérés comme des échecs. Tout statut
    inférieur à 400 réinitialise la série d'échecs de l'IP concernée.
    """
    records = _parse_records(lines_or_records)
    detector = BruteForceDetector(threshold)
    index = 0

    while index < len(records):
        record = records[index]
        detector.process(record)
        index += 1

    return detector.alerts


def write_report(alerts: Iterable[dict[str, Any]], output: str | Path) -> None:
    """Écrit un rapport d'alertes dans le fichier indiqué."""
    alert_list = list(alerts)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_format_report(alert_list), encoding="utf-8")


def _format_report(alerts: Iterable[dict[str, Any]]) -> str:
    """Construit le texte partagé par l'affichage CLI et le fichier rapport."""
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
    """Analyse les fichiers de logs d'un dossier et retourne les alertes."""
    return detect_brute_force(
        read_logs_from_directory(Path(directory), pattern), threshold=threshold
    )


def parse_arguments() -> argparse.Namespace:
    """Construit les options de la commande de détection."""
    project_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description="Détecte les attaques par force brute dans des logs HTTP."
    )
    parser.add_argument(
        "--directory",
        "-d",
        type=Path,
        default=project_root / "logs",
        help="Dossier des logs (défaut : logs).",
    )
    parser.add_argument(
        "--pattern",
        default="*.log",
        help="Motif des fichiers à analyser (défaut : *.log).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=project_root / "brute_force" / "brute_force_report.txt",
        help="Fichier de sortie (défaut : brute_force/brute_force_report.txt).",
    )
    return parser.parse_args()


def main() -> None:
    """Lance la détection depuis la ligne de commande et affiche les alertes."""
    arguments = parse_arguments()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    alerts = detect_brute_force_from_directory(
        arguments.directory,
        pattern=arguments.pattern,
    )

    write_report(alerts, arguments.output)

    print(_format_report(alerts), end="")
    print(f"Rapport écrit dans : {arguments.output}")


if __name__ == "__main__":
    main()