"""
Main entry point (main.py).
Measure peak RAM and calculate average memory usage.
"""

import argparse
import sys
import time
from pathlib import Path

from log_engine.aggregation import CountReport, most_common
from log_engine.ingestion import read_logs_from_directory
from log_engine.memory import get_current_memory_bytes, get_peak_memory_bytes
from log_engine.parsing import parse_logs_parallel
from log_processing.ip_sets import (
    IPCollector,
    compare_with_blacklist,
    format_ip_report,
    load_blacklist,
    track_ips,
)

from log_process.brute_force import BruteForceDetector, write_report
from log_transformation.tracker import Tracker
from security import (
    SecurityContext,
    apply_security_rules,
    rule_blacklisted_ip,
    rule_brute_force,
    rule_http_errors,
)
from security.report import write_security_report


def format_count_report(report: CountReport) -> str:
    """Build the summary report for category and user counts."""
    lines = [
        "=== COMPTAGE PAR CATÉGORIE ET PAR UTILISATEUR ===",
        "Par catégorie de log :",
    ]
    for category, count in most_common(report.by_category):
        lines.append(f"  - {category:<12} : {count:,}")
    lines.append("Par niveau de sévérité :")
    for level, count in most_common(report.by_level):
        lines.append(f"  - {level:<12} : {count:,}")
    lines.append(f"Utilisateurs distincts : {len(report.by_user):,}")
    lines.append("Top 5 utilisateurs :")
    for user, count in most_common(report.by_user, limit=5):
        levels = most_common(report.by_user_level[user], limit=3)
        detail = ", ".join(f"{name}={value:,}" for name, value in levels)
        label = user if len(user) <= 28 else f"{user[:25]}..."
        lines.append(f"  - {label:<28} : {count:,} ({detail})")
    return "\n".join(lines) + "\n"


def format_memory_report(
    *,
    total_lines: int,
    valid_records: int,
    invalid_lines: int,
    elapsed_time: float,
    peak_ram_mb: float | None,
    avg_ram_mb: float | None,
    memory_enabled: bool,
) -> str:
    """Build the memory and runtime summary report."""
    lines = [
        "=== RAPPORT DE CONSOMMATION MÉMOIRE ET PERFORMANCES ===",
        f"Total de lignes lues   : {total_lines:,} lignes",
        f"Records valides        : {valid_records:,}",
        f"Lignes invalides       : {invalid_lines:,}",
        f"Temps d'exécution      : {elapsed_time:.2f} secondes",
    ]
    if memory_enabled:
        if peak_ram_mb is not None:
            lines.append(f"📈 Pic de RAM (Peak)    : {peak_ram_mb:.2f} Mo")
        if avg_ram_mb is not None:
            lines.append(f"📊 Moyenne de RAM       : {avg_ram_mb:.2f} Mo")
    else:
        lines.append("Suivi RAM              : désactivé (utilisez --memory)")
    return "\n".join(lines) + "\n"


def write_count_report(report: CountReport, output_path: Path) -> None:
    """Persist the counting report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(format_count_report(report), encoding="utf-8")


def write_memory_report(
    *,
    total_lines: int,
    valid_records: int,
    invalid_lines: int,
    elapsed_time: float,
    peak_ram_mb: float | None,
    avg_ram_mb: float | None,
    memory_enabled: bool,
    output_path: Path,
) -> None:
    """Persist the memory report to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        format_memory_report(
            total_lines=total_lines,
            valid_records=valid_records,
            invalid_lines=invalid_lines,
            elapsed_time=elapsed_time,
            peak_ram_mb=peak_ram_mb,
            avg_ram_mb=avg_ram_mb,
            memory_enabled=memory_enabled,
        ),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyse et normalise les logs HTTP.")
    parser.add_argument(
        "--memory",
        action="store_true",
        help="Active le suivi détaillé de la consommation mémoire.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Nombre de processus de parsing (1 désactive le parallélisme).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=5_000,
        help="Nombre de lignes par lot envoyé à un worker.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Désactive les messages de progression intermédiaires.",
    )
    parser.add_argument(
        "--ip-report-output",
        type=Path,
        default=Path(__file__).resolve().parent / "reports" / "ip_report.txt",
        help="Chemin du rapport complet des adresses IP.",
    )
    parser.add_argument(
        "--brute-force-output",
        type=Path,
        default=Path(__file__).resolve().parent.joinpath(
            "reports", "brute_force_report.txt"
        ),
        help="Rapport force brute produit pendant l'analyse.",
    )
    parser.add_argument(
        "--security-report",
        type=Path,
        default=Path(__file__).resolve().parent / "reports" / "security_report.txt",
        help="Rapport texte des règles de sécurité et de l'audit.",
    )
    parser.add_argument(
        "--count-report-output",
        type=Path,
        default=Path(__file__).resolve().parent / "reports" / "comptage_report.txt",
        help="Chemin du rapport de comptage par catégorie et utilisateur.",
    )
    parser.add_argument(
        "--memory-report-output",
        type=Path,
        default=Path(__file__).resolve().parent / "reports" / "memory_report.txt",
        help="Chemin du rapport de consommation mémoire et performances.",
    )
    arguments = parser.parse_args()

    if arguments.workers < 1:
        parser.error("--workers doit être supérieur ou égal à 1")
    if arguments.batch_size < 1:
        parser.error("--batch-size doit être supérieur ou égal à 1")

    try:
        blacklist = load_blacklist()
    except (FileNotFoundError, PermissionError, ValueError) as error:
        print(f"Erreur de chargement de la liste noire : {error}", file=sys.stderr)
        raise SystemExit(1) from error

    logs_directory = Path(__file__).resolve().parent / "logs"

    # 1. Start memory tracking and the timer
    start_time = time.time()

    print(
        "=== ANCIEN/NOUVEAU PIPELINE : "
        f"LECTURE DE TOUT LE DOSSIER '{logs_directory}' ==="
    )

    # 2. Chain generators (continuous streaming via yield from)
    raw_stream = read_logs_from_directory(logs_directory)
    parsed_stream = parse_logs_parallel(
        raw_stream,
        arguments.workers,
        batch_size=arguments.batch_size,
    )
    preview_limit = 3
    tracker = Tracker(sample_size=preview_limit)
    ip_collector = IPCollector()

    valid_stream = track_ips(
        filter(lambda record: tracker(record), parsed_stream),
        ip_collector,
    )
    brute_force_detector = BruteForceDetector()
    security_enabled = arguments.security_report is not None
    if security_enabled:
        security_context = SecurityContext(
            blacklist=blacklist,
            brute_force_detector=brute_force_detector,
        )
        security_findings = []
        security_rules = (
            rule_blacklisted_ip,
            rule_http_errors,
            rule_brute_force,
        )
    # Feed from the already filtered stream: only valid records are counted.
    report = CountReport()

    valid_records = 0
    sample_interval = 10_000
    memory_samples = []
    progress_interval = 100_000

    # 3. Filter each record individually
    for record in valid_stream:

        valid_records += 1
        report.update(record, category=tracker.last_category)
        if "ip" in record and "status" in record and not security_enabled:
            brute_force_detector.process(record)
        if security_enabled:
            apply_security_rules(
                *security_rules,
                record=record,
                context=security_context,
                _sink=security_findings,
            )

        if not arguments.quiet and tracker.seen % progress_interval == 0:
            elapsed = time.time() - start_time
            rate = tracker.seen / elapsed if elapsed else 0
            print(
                f"Progression : {tracker.seen:,} lignes | "
                f"valides : {valid_records:,} | "
                f"invalides : {tracker.rejected:,} | "
                f"débit : {rate:,.0f} lignes/s"
            )

        # Sample regularly to calculate the average without affecting performance.
        if arguments.memory and tracker.seen % sample_interval == 0:
            memory_samples.append(get_current_memory_bytes())

    if arguments.memory:
        current_mem = get_current_memory_bytes()
        if current_mem:
            memory_samples.append(current_mem)
        peak_mem = get_peak_memory_bytes()
    else:
        peak_mem = 0
    elapsed_time = time.time() - start_time
    write_report(brute_force_detector.alerts, arguments.brute_force_output)
    if security_enabled:
        write_security_report(
            security_findings,
            arguments.security_report,
            audit_context={
                "record_count": tracker.seen,
                "valid_record_count": valid_records,
                "security_findings": security_findings,
            },
        )

    # 4. Calculate RAM usage in megabytes
    peak_ram_mb = peak_mem / (1024 * 1024)

    if arguments.memory and memory_samples:
        avg_ram_mb = (sum(memory_samples) / len(memory_samples)) / (1024 * 1024)
    else:
        avg_ram_mb = None

    try:
        write_count_report(report, arguments.count_report_output)
        print(f"\nRapport de comptage enregistré dans : {arguments.count_report_output}")
    except OSError as error:
        print(f"Erreur d'écriture du rapport de comptage : {error}", file=sys.stderr)
        raise SystemExit(1) from error

    try:
        write_memory_report(
            total_lines=tracker.seen,
            valid_records=valid_records,
            invalid_lines=tracker.rejected,
            elapsed_time=elapsed_time,
            peak_ram_mb=peak_ram_mb if arguments.memory else None,
            avg_ram_mb=avg_ram_mb if arguments.memory else None,
            memory_enabled=arguments.memory,
            output_path=arguments.memory_report_output,
        )
        print(f"Rapport mémoire enregistré dans : {arguments.memory_report_output}")
    except OSError as error:
        print(f"Erreur d'écriture du rapport mémoire : {error}", file=sys.stderr)
        raise SystemExit(1) from error

    # 5. Display the execution report
    print("\n=== RAPPORT DE CONSOMMATION MÉMOIRE ET PERFORMANCES ===")
    print(f" Total de lignes lues   : {tracker.seen:,} lignes")
    print(f" Records valides        : {valid_records:,}")
    print(f" Lignes invalides       : {tracker.rejected:,}")
    print(f" Temps d'exécution      : {elapsed_time:.2f} secondes")
    if arguments.memory:
        print(f" 📈 Pic de RAM (Peak)    : {peak_ram_mb:.2f} Mo")
        print(f" 📊 Moyenne de RAM       : {avg_ram_mb:.2f} Mo")
    else:
        print(" Suivi RAM              : désactivé (utilisez --memory)")

    print("\n=== COMPTAGE PAR CATÉGORIE ET PAR UTILISATEUR ===")
    print(" Par catégorie de log :")
    for category, count in most_common(report.by_category):
        print(f"   - {category:<12} : {count:,}")
    print(" Par niveau de sévérité :")
    for level, count in most_common(report.by_level):
        print(f"   - {level:<12} : {count:,}")
    print(f" Utilisateurs distincts : {len(report.by_user):,}")
    print(" Top 5 utilisateurs :")
    for user, count in most_common(report.by_user, limit=5):
        levels = most_common(report.by_user_level[user], limit=3)
        detail = ", ".join(f"{name}={value:,}" for name, value in levels)
        label = user if len(user) <= 28 else f"{user[:25]}..."
        print(f"   - {label:<28} : {count:,} ({detail})")

    if tracker.unknown:
        print(
            f"\n ⚠ {tracker.unknown:,} records n'ont été reconnus "
            "par aucun case de route_log :")
        for sample in tracker.unknown_samples:
            print(f"     {sample}")

    print("\n=== PREMIER EXEMPLE PAR TYPE DE ROUTAGE ===")
    for kind, (description, record) in tracker.route_examples.items():
        print(f" [{kind}] {description}")
        print(f"             {record}")

    print("\n=== APERÇU DES LIGNES INVALIDES ===")
    if tracker.invalid_samples:
        for index, (description, record) in enumerate(tracker.invalid_samples, start=1):
            print(f" Invalide {index} : {description}")
            print(f"             {record}")
    else:
        print(" Aucune ligne invalide.")

    print("\n=== APERÇU DES RECORDS TRAITÉS ===")
    for index, (kind, description, record) in enumerate(tracker.valid_samples, start=1):
        print(f" Record {index} : [{kind}] {description}")
        print(f"             {record}")
    print("=======================================================")
    print(
        f"\n=== RAPPORT FORCE BRUTE ===\n"
        f" Alertes détectées : {len(brute_force_detector.alerts)}\n"
        f" Rapport écrit dans : {arguments.brute_force_output}"
    )
    if arguments.security_report:
        print(f"\nRapport de sécurité écrit dans : {arguments.security_report}")

    ip_report = compare_with_blacklist(
        blacklist,
        ip_collector.active_ips,
        ip_collector.error_ips,
    )
    print(format_ip_report(ip_collector, ip_report))

    report_path = arguments.ip_report_output
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        full_report = format_ip_report(
            ip_collector,
            ip_report,
            limit=max(len(ip_report.known_ips), 1),
        )
        report_path.write_text(
            "Rapport IP des logs (listes complètes)\n"
            "Source : dossier logs/\n"
            f"{full_report.lstrip()}\n",
            encoding="utf-8",
        )
    except OSError as error:
        print(f"Erreur d'écriture du rapport IP : {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print(f"\nRapport IP enregistré dans : {report_path}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, NotADirectoryError, PermissionError) as error:
        print(f"Erreur d'accès aux logs : {error}", file=sys.stderr)
        raise SystemExit(1) from error
