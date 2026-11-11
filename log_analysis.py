"""Interactive menu for generating, analyzing, and viewing logs."""

import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

from log_generator.generate_multiple_logs import generate_multiple_logs


PROJECT_ROOT = Path(__file__).resolve().parent
LOGS_DIRECTORY = PROJECT_ROOT / "logs"
REPORTS_DIRECTORY = PROJECT_ROOT / "reports"
MAIN_SCRIPT = PROJECT_ROOT / "main.py"
LAST_RUN_REPORT = REPORTS_DIRECTORY / "last_run.txt"


def prompt_integer(
    prompt: str,
    default: int,
    minimum: int
) -> int:
    """Ask for an integer within the allowed range."""
    while True:
        value = input(f"{prompt} [{default}] : ").strip()
        if not value:
            return default
        try:
            number = int(value)
        except ValueError:
            print("Veuillez saisir un nombre entier.")
            continue
        if number < minimum:
            print(f"La valeur doit être supérieure ou égale à {minimum}.")
            continue
        return number


def generation_menu() -> None:
    """Print the log generation menu and prompt for parameters."""
    print("\n=== Génération des logs ===")
    file_count = prompt_integer("Nombre de fichiers", default=3, minimum=1)
    line_count = prompt_integer("Nombre de lignes par fichier", default=1_000_000, minimum=1)
    max_rate = prompt_integer("Cadence maximale (lignes/seconde/fichier)", default=None, minimum=1)
    batch_size = prompt_integer("Taille des lots", default=50_000, minimum=1)
    output_value = input(f"Dossier de sortie [{LOGS_DIRECTORY}] : ").strip()
    output_directory = Path(output_value).expanduser() if output_value else LOGS_DIRECTORY

    try:
        generate_multiple_logs(
            file_count,
            line_count,
            output_directory,
            max_rate,
            batch_size,
        )
    except (OSError, ValueError) as error:
        print(f"Erreur pendant la génération des logs : {error}")
        return

    print("Génération terminée.")


def prompt_yes_no(prompt: str, default: bool = False) -> bool:
    """Ask for a yes/no response."""
    default_value = "o" if default else "n"
    while True:
        value = input(f"{prompt} (o/n) [{default_value}] : ").strip().lower()
        if not value:
            return default
        if value in {"o", "y", "yes", "oui"}:
            return True
        if value in {"n", "no", "non"}:
            return False
        print("Répondez par o ou n.")


def run_application(memory: bool, workers: int) -> None:
    """Launch the main application and record its output in the last run report."""
    command = [sys.executable, "-u", str(MAIN_SCRIPT), "--workers", str(workers)]
    if memory:
        command.append("--memory")

    print(f"\nLancement de l'analyse. Rapport : {LAST_RUN_REPORT}")
    try:
        REPORTS_DIRECTORY.mkdir(parents=True, exist_ok=True)
        with LAST_RUN_REPORT.open("w", encoding="utf-8") as report:
            process = subprocess.Popen(
                command,
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if process.stdout is None:
                raise RuntimeError("La sortie de l'application n'est pas disponible.")
            with process.stdout:
                for line in process.stdout:
                    print(line, end="")
                    report.write(line)
            return_code = process.wait()
    except OSError as error:
        print(f"Erreur lors du lancement de l'application : {error}")
        return

    if return_code == 0:
        print(f"\nRapport enregistré dans : {LAST_RUN_REPORT}")
    else:
        print(
            f"\nL'application s'est terminée avec le code {return_code}. "
            f"Sa sortie est disponible dans {LAST_RUN_REPORT}."
        )


def application_menu() -> None:
    """Ask for the application parameters before launching."""
    print("\n=== Paramètres de l'application ===")
    workers = prompt_integer("Nombre de processus", default=1, minimum=1)
    memory = prompt_yes_no("Activer le suivi détaillé de la mémoire", default=True)
    run_application(memory, workers)


def read_navigation_key() -> str:
    """Read a navigation key from the user."""
    if not sys.stdin.isatty():
        key = input("Navigation (←/gauche, →/droite, q/retour) : ").strip().lower()
        if key in {"left", "gauche", "←"}:
            return "left"
        if key in {"right", "droite", "→", ""}:
            return "right"
        return "quit" if key in {"q", "quit", "retour"} else key

    if sys.platform == "win32":
        import msvcrt

        key = msvcrt.getch()
        if key in {b"\x00", b"\xe0"}:
            arrow = msvcrt.getch()
            return {b"K": "left", b"M": "right"}.get(arrow, "")
        return "quit" if key.lower() == b"q" else ""

    import termios
    import tty

    descriptor = sys.stdin.fileno()
    previous_settings = termios.tcgetattr(descriptor)
    try:
        tty.setcbreak(descriptor)
        key = sys.stdin.read(1)
        if key == "\x1b":
            sequence = sys.stdin.read(2)
            return {"[D": "left", "[C": "right"}.get(sequence, "")
        return "quit" if key.lower() == "q" else ""
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, previous_settings)


def wrap_report_lines(lines: list[str], width: int) -> list[str]:
    """Compacts and wraps lines to fit within the specified width."""
    wrapped_lines = []
    for line in lines:
        wrapped_lines.extend(
            textwrap.wrap(
                line,
                width=max(1, width),
                replace_whitespace=False,
                drop_whitespace=False,
                break_long_words=True,
                break_on_hyphens=False,
            ) or [""]
        )
    return wrapped_lines


def display_report(report_path: Path, page_size: int | None = None) -> None:
    """Display the content of a report with pagination and navigation."""
    try:
        lines = report_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        print(f"Impossible de lire le rapport : {error}")
        return

    if not lines:
        lines = ["(Rapport vide)"]

    offset = 0
    while True:
        terminal_size = shutil.get_terminal_size((80, 24))
        width = max(1, terminal_size.columns)
        wrapped_lines = wrap_report_lines(lines, width)
        title_lines = wrap_report_lines([f"=== {report_path.name} ==="], width)
        navigation_lines = wrap_report_lines(
            ["← page précédente | → page suivante | q retour"],
            width,
        )
        height = (
            max(1, page_size)
            if page_size is not None
            else max(
                1,
                terminal_size.lines - len(title_lines) - len(navigation_lines) - 2,
            )
        )
        page_count = max(1, (len(wrapped_lines) + height - 1) // height)
        page = min(offset // height, page_count - 1)
        start = page * height
        end = min(start + height, len(wrapped_lines))

        if sys.stdout.isatty():
            sys.stdout.write("\x1b[2J\x1b[H")
        print("\n".join(title_lines))
        print("\n".join(wrapped_lines[start:end]))
        print(f"Page {page + 1}/{page_count} | {' '.join(navigation_lines)}")

        key = read_navigation_key()
        if key == "quit":
            return
        if key == "left" and page > 0:
            offset = max(0, start - height)
        elif key == "right" and page + 1 < page_count:
            offset = end
        else:
            offset = start


def reports_menu() -> None:
    """List available reports and allow the user to select one to view."""
    try:
        reports = sorted(
            path
            for path in REPORTS_DIRECTORY.glob("*.txt")
            if path.is_file()
        )
    except OSError as error:
        print(f"Impossible de rechercher les rapports : {error}")
        return

    if not reports:
        print("\nAucun rapport disponible. Lancez d'abord l'application.")
        return

    while True:
        print("\n=== Rapports disponibles ===")
        for index, report in enumerate(reports, start=1):
            print(f"{index}. {report.parent.name}/{report.name}")
        print("0. Retour au menu principal")
        choice = input("Votre choix : ").strip()
        if choice == "0":
            return
        try:
            selected = int(choice)
        except ValueError:
            print("Choix invalide.")
            continue
        if not 1 <= selected <= len(reports):
            print("Choix invalide.")
            continue
        display_report(reports[selected - 1])


def main() -> None:
    """Entrypoint for the log analysis menu."""
    actions = {
        "1": generation_menu,
        "2": application_menu,
        "3": reports_menu,
    }
    while True:
        print(
            "\n=== Analyse de logs ===\n"
            "1. Générer des logs\n"
            "2. Lancer l'application principale\n"
            "3. Lire les rapports\n"
            "0. Quitter"
        )
        try:
            choice = input("Votre choix : ").strip()
        except EOFError:
            print("\nAu revoir.")
            return
        if choice == "0":
            print("Au revoir.")
            return
        action = actions.get(choice)
        if action is None:
            print("Choix invalide.")
            continue
        action()


if __name__ == "__main__":
    main()
