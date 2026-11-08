"""
Point d'entrée principal (main.py)
Mesure du pic de RAM et calcul de la moyenne de consommation mémoire.
"""

import argparse
import sys
import time
from pathlib import Path

from log_engine.ingestion import read_logs_from_directory
from log_engine.memory import get_current_memory_bytes, get_peak_memory_bytes
from log_engine.parsing import parse_logs_parallel
from log_transformation.tracker import Tracker


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
    arguments = parser.parse_args()

    if arguments.workers < 1:
        parser.error("--workers doit être supérieur ou égal à 1")

    logs_directory = Path(__file__).resolve().parent / "logs"

    # 1. Démarrer le suivi mémoire et le chronomètre
    start_time = time.time()

    print(
        "=== ANCIEN/NOUVEAU PIPELINE : "
        f"LECTURE DE TOUT LE DOSSIER '{logs_directory}' ==="
    )

    # 2. Chaînage des générateurs (Streaming continu via yield from)
    raw_stream = read_logs_from_directory(logs_directory)
    parsed_stream = parse_logs_parallel(raw_stream, arguments.workers)
    preview_limit = 3
    tracker = Tracker(sample_size=preview_limit)
    valid_stream = filter(tracker, parsed_stream)

    valid_records = 0
    sample_interval = 10_000
    memory_samples = []
    progress_interval = 100_000

    # 3. Filtrage de chaque enregistrement individuellement
    for record in valid_stream:

        valid_records += 1

        if tracker.seen % progress_interval == 0:
            elapsed = time.time() - start_time
            rate = tracker.seen / elapsed if elapsed else 0
            print(
                f"Progression : {tracker.seen:,} lignes | "
                f"valides : {valid_records:,} | "
                f"invalides : {tracker.rejected:,} | "
                f"débit : {rate:,.0f} lignes/s"
            )

        # Échantillonnage régulier pour calculer la moyenne sans impacter les
        # performances
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

    # 4. Calculs de la RAM (en Mégaoctets - Mo)
    peak_ram_mb = peak_mem / (1024 * 1024)

    if arguments.memory and memory_samples:
        avg_ram_mb = (sum(memory_samples) / len(memory_samples)) / (1024 * 1024)
    else:
        avg_ram_mb = None

    # 5. Affichage du rapport d'exécution
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


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, NotADirectoryError, PermissionError) as error:
        print(f"Erreur d'accès aux logs : {error}", file=sys.stderr)
        raise SystemExit(1) from error
