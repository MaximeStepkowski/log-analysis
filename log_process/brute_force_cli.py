"""Command-line interface for brute-force detection."""

import argparse
import logging
from pathlib import Path

from log_process.brute_force import (
    _format_report,
    detect_brute_force_from_directory,
    write_report,
)


def parse_arguments() -> argparse.Namespace:
    """Build the detection command options."""
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
        default=project_root / "reports" / "brute_force_report.txt",
        help="Fichier de sortie (défaut : reports/brute_force_report.txt).",
    )
    return parser.parse_args()


def main() -> None:
    """Run detection from the command line and display the alerts."""
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
