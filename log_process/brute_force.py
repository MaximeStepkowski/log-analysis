"""Détection d'attaques par force brute dans les logs HTTP."""

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
            # Chaque IP possède son propre compteur d'échecs consécutifs.
            self.failures[ip] = self.failures.get(ip, 0) + 1
            if self.failures[ip] >= self.threshold:
                self._add_alert(record, ip)
        elif status < 400:
            # Une réponse réussie termine la série d'échecs de cette IP.
            self.failures[ip] = 0
            self.alerted_ips.discard(ip)

    def process_cycles(self, records: Iterable[dict[str, Any]]) -> None:
        """Analyse les cycles de chaque IP sans arrêter l'analyse globale."""
        # Un succès sépare deux cycles d'échecs pour une même IP.
        cycles_by_ip: dict[str, list[list[dict[str, Any]]]] = {}
        current_cycles: dict[str, list[dict[str, Any]]] = {}

        for record in records:
            ip = record["ip"]
            status = int(record["status"])
            cycle = current_cycles.setdefault(ip, [])

            if status < 400:
                # On clôt le cycle avant d'ignorer le record de réussite.
                if cycle:
                    cycles_by_ip.setdefault(ip, []).append(cycle)
                    current_cycles[ip] = []
                self.failures[ip] = 0
                self.alerted_ips.discard(ip)
                continue

            cycle.append(record)

        # Les cycles qui se terminent en fin de fichier doivent être conservés.
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
                        # Les statuts hors 401/403 ne comptent pas comme échecs.
                        continue

                    self.failures[ip] += 1
                    if self.failures[ip] >= self.threshold:
                        self._add_alert(record, ip)
                        # Cette alerte termine uniquement le cycle courant.
                        break
                else:
                    # Ce bloc s'exécute si le cycle finit sans atteindre le seuil.
                    LOGGER.info("Cycle de détection terminé sans alerte pour %s", ip)

                cycle_index += 1

        self.alerts.sort(key=lambda alert: alert.get("timestamp"))

    def _add_alert(self, record: dict[str, Any], ip: str) -> None:
        """Ajoute une alerte si cette IP n'a pas déjà été signalée."""
        if ip in self.alerted_ips:
            return

        # Le record qui atteint le seuil fournit les détails de l'alerte.
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
    """Parse les lignes et conserve les enregistrements HTTP valides."""
    records = []
    for item in lines_or_records:
        # Les chaînes sont parsées ; les dictionnaires sont déjà exploitables.
        record = parse_line(item) if isinstance(item, str) else item
        if not record or "ip" not in record or "status" not in record:
            # Une ligne invalide ne doit pas interrompre toute l'analyse.
            LOGGER.warning("Log ignoré pendant la détection de force brute: %s", item)
            continue
        records.append(record)
    # La détection doit respecter l'ordre temporel des événements.
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
    # Le détecteur traite ensuite tous les cycles sans s'arrêter à la première alerte.
    detector.process_cycles(records)

    return detector.alerts


def write_report(alerts: Iterable[dict[str, Any]], output: str | Path) -> None:
    """Écrit un rapport d'alertes dans le fichier indiqué."""
    alert_list = list(alerts)
    output_path = Path(output)
    # Le dossier de sortie peut ne pas exister lors du premier lancement.
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

