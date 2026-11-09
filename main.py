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
from log_processing.ip_sets import (
    IPCollector,
    compare_with_blacklist,
    format_ip_report,
    load_blacklist,
    track_ips,
)

from log_process.brute_force import BruteForceDetector, write_report
from log_transformation.tracker import Tracker


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
    parser.add_argument(
        "--ip-report-output",
        type=Path,
        default=Path(__file__).resolve().parent / "reports" / "ip_report.txt",
        help="Chemin du rapport complet des adresses IP.",
    parser.add_argument(
        "--brute-force-output",
        type=Path,
        default=Path(__file__).resolve().parent
        / "brute_force"
        / "brute_force_report.txt",
        help="Rapport force brute produit pendant l'analyse.",
    )
    arguments = parser.parse_args()

    if arguments.workers < 1:
        parser.error("--workers doit être supérieur ou égal à 1")

    try:
        blacklist = load_blacklist()
    except (FileNotFoundError, PermissionError, ValueError) as error:
        print(f"Erreur de chargement de la liste noire : {error}", file=sys.stderr)
        raise SystemExit(1) from error

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
    ip_collector = IPCollector()
    
    valid_stream = track_ips(
        filter(lambda record: tracker(record), parsed_stream),
        ip_collector,
    )
    brute_force_detector = BruteForceDetector()

    valid_records = 0
    sample_interval = 10_000
    memory_samples = []
    progress_interval = 100_000

    # 3. Filtrage de chaque enregistrement individuellement
    for record in valid_stream:

        valid_records += 1
        if "ip" in record and "status" in record:
            brute_force_detector.process(record)

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
    write_report(brute_force_detector.alerts, arguments.brute_force_output)

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
    print(
        f"\n=== RAPPORT FORCE BRUTE ===\n"
        f" Alertes détectées : {len(brute_force_detector.alerts)}\n"
        f" Rapport écrit dans : {arguments.brute_force_output}"
    )

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
