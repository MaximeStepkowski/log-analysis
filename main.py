"""
Point d'entrée principal (main.py)
Mesure du pic de RAM et calcul de la moyenne de consommation mémoire sur l'ensemble des fichiers.
"""

import argparse
import ctypes
import os
import sys
import time
from pathlib import Path

try:
    import resource
except ImportError:  # pragma: no cover - disponible sous Unix uniquement
    resource = None

from log_engine.ingestion import read_logs_from_directory
from log_engine.parsing import parse_logs_parallel
from log_engine.routing import route_log
from log_transformation.filter import smart_filter


if sys.platform == "win32":
    class MemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]


def get_windows_memory() -> tuple[int, int]:
    """Retourne le RSS courant et le pic RSS sous Windows."""
    counters = MemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    process = ctypes.windll.kernel32.GetCurrentProcess()
    success = ctypes.windll.psapi.GetProcessMemoryInfo(
        process,
        ctypes.byref(counters),
        counters.cb,
    )
    if not success:
        return 0, 0
    return counters.WorkingSetSize, counters.PeakWorkingSetSize


def get_current_memory_bytes() -> int:
    """Retourne la mémoire résidente courante du processus."""
    if sys.platform == "win32":
        return get_windows_memory()[0]

    try:
        with open("/proc/self/statm", encoding="ascii") as statm_file:
            resident_pages = int(statm_file.readline().split()[1])
        return resident_pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, IndexError, ValueError):
        return 0


def get_peak_memory_bytes() -> int:
    """Retourne le pic RSS en octets selon le système d'exploitation."""
    if sys.platform == "win32":
        return get_windows_memory()[1]

    if resource is None:
        return 0

    peak_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "linux":
        return peak_memory * 1024
    return peak_memory


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
        f"=== ANCIEN/NOUVEAU PIPELINE : LECTURE DE TOUT LE DOSSIER '{logs_directory}' ===")

    # 2. Chaînage des générateurs (Streaming continu via yield from)
    raw_stream = read_logs_from_directory(logs_directory)
    parsed_stream = parse_logs_parallel(raw_stream, arguments.workers)

    total_lines = 0
    valid_records = 0
    invalid_lines = 0
    unknown_records = 0
    memory_samples = []
    sample_interval = 10_000  # Prendre un échantillon de la RAM toutes les 10 000 lignes
    progress_interval = 100_000
    preview_limit = 3
    preview_records = []
    unknown_samples = []
    invalid_samples = []
    route_examples: dict[str, tuple[str, object]] = {}

    # 3. Filtrage de chaque enregistrement individuellement
    for record in parsed_stream:
        
        total_lines += 1

        # Routage de chaque enregistrement par Structural Pattern Matching
        kind, description = route_log(record)

        if not smart_filter(record):
            invalid_lines += 1
            if len(invalid_samples) < preview_limit:
                invalid_samples.append((description, record))
            continue

        if kind not in route_examples:
            route_examples[kind] = (description, record)

        valid_records += 1
        if len(preview_records) < preview_limit:
            preview_records.append((kind, description, record))

        if kind == "unknown":
            unknown_records += 1
            if len(unknown_samples) < preview_limit:
                unknown_samples.append(record)

        if total_lines % progress_interval == 0:
            elapsed = time.time() - start_time
            rate = total_lines / elapsed if elapsed else 0
            print(
                f"Progression : {total_lines:,} lignes | "
                f"valides : {valid_records:,} | "
                f"invalides : {invalid_lines:,} | "
                f"débit : {rate:,.0f} lignes/s"
            )

        # Échantillonnage régulier pour calculer la moyenne sans impacter les performances
        if arguments.memory and total_lines % sample_interval == 0:
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
    print(f" Total de lignes lues   : {total_lines:,} lignes")
    print(f" Records valides        : {valid_records:,}")
    print(f" Lignes invalides       : {invalid_lines:,}")
    print(f" Temps d'exécution      : {elapsed_time:.2f} secondes")
    if arguments.memory:
        print(f" 📈 Pic de RAM (Peak)    : {peak_ram_mb:.2f} Mo")
        print(f" 📊 Moyenne de RAM       : {avg_ram_mb:.2f} Mo")
    else:
        print(" Suivi RAM              : désactivé (utilisez --memory)")

    if unknown_records:
        print(
            f"\n ⚠ {unknown_records:,} records n'ont été reconnus "
            "par aucun case de route_log :")
        for sample in unknown_samples:
            print(f"     {sample}")

    print("\n=== PREMIER EXEMPLE PAR TYPE DE ROUTAGE ===")
    for kind, (description, record) in route_examples.items():
        print(f" [{kind}] {description}")
        print(f"             {record}")

    print("\n=== APERÇU DES LIGNES INVALIDES ===")
    if invalid_samples:
        for index, (description, record) in enumerate(invalid_samples, start=1):
            print(f" Invalide {index} : {description}")
            print(f"             {record}")
    else:
        print(" Aucune ligne invalide.")

    print("\n=== APERÇU DES RECORDS TRAITÉS ===")
    for index, (kind, description, record) in enumerate(preview_records, start=1):
        print(f" Record {index} : [{kind}] {description}")
        print(f"             {record}")
    print("=======================================================")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, NotADirectoryError, PermissionError) as error:
        print(f"Erreur d'accès aux logs : {error}", file=sys.stderr)
        raise SystemExit(1) from error