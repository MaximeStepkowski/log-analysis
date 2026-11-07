"""Génère plusieurs fichiers de logs avec une taille configurable."""

import argparse
from pathlib import Path

from log_generator.generate_logs import get_output_file, generate_huge_log_file


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "logs"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Génère plusieurs fichiers de logs avec le même nombre de lignes."
    )
    parser.add_argument(
        "--files",
        "-f",
        type=int,
        required=True,
        help="Nombre de fichiers à générer.",
    )
    parser.add_argument(
        "--lines",
        "-l",
        type=int,
        required=True,
        help="Nombre de lignes par fichier.",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Dossier de sortie (défaut : {DEFAULT_OUTPUT_DIR}).",
    )
    parser.add_argument(
        "--max-rate",
        type=int,
        default=None,
        help="Limite le nombre de lignes générées par seconde et par fichier.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50_000,
        help="Nombre de lignes écrites par lot.",
    )
    return parser.parse_args()


def generate_multiple_logs(
    file_count: int,
    line_count: int,
    output_dir: Path,
    max_lines_per_second: int | None = None,
    batch_size: int = 50_000,
) -> None:
    """Génère ``file_count`` fichiers contenant chacun ``line_count`` lignes."""
    if file_count < 1:
        raise ValueError("Le nombre de fichiers doit être supérieur ou égal à 1.")
    if line_count < 0:
        raise ValueError("Le nombre de lignes doit être supérieur ou égal à 0.")

    output_dir.mkdir(parents=True, exist_ok=True)

    for file_number in range(1, file_count + 1):
        output_file = get_output_file(file_number, output_dir)
        generate_huge_log_file(
            output_file,
            line_count,
            max_lines_per_second,
            batch_size,
        )


def main() -> None:
    arguments = parse_arguments()
    try:
        generate_multiple_logs(
            arguments.files,
            arguments.lines,
            arguments.output_dir,
            arguments.max_rate,
            arguments.batch_size,
        )
    except ValueError as error:
        raise SystemExit(f"Erreur : {error}") from error


if __name__ == "__main__":
    main()
