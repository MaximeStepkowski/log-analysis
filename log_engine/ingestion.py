from collections.abc import Iterator
from pathlib import Path

IO_BUFFER_SIZE = 1024 * 1024
READ_BATCH_SIZE = 4 * 1024 * 1024


def read_logs(path: Path) -> Iterator[str]:
    """Read a log file line by line (generator)"""
    with open(path, encoding="utf-8", buffering=IO_BUFFER_SIZE) as file:
        while batch := file.readlines(READ_BATCH_SIZE):
            yield from map(str.removesuffix, batch, ("\n",) * len(batch))


def read_logs_from_directory(
    directory: Path,
    pattern: str = "*.log",
) -> Iterator[str]:
    """Read every log file of a directory, one after the other (sub-generator)"""
    folder = Path(directory)
    if not folder.is_dir():
        raise NotADirectoryError(f"Directory not found: {directory}")

    paths = sorted(folder.glob(pattern))
    for path in paths:
        yield from read_logs(path)
    else:
        if not paths:
            raise FileNotFoundError(
                f"Aucun fichier correspondant à '{pattern}' dans {folder}"
            )
