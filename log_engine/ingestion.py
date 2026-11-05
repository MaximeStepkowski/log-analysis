from pathlib import Path

def read_logs(path):
    """Read a log file line by line (generator)"""
    with open(path, encoding="utf-8") as file:
        for line in file:
            yield line.rstrip("\n")


def read_logs_from_directory(directory, pattern="*.log"):
    """Read every log file of a directory, one after the other (sub-generator)"""
    folder = Path(directory)
    if not folder.is_dir():
        raise NotADirectoryError(f"Directory not found: {directory}")

    for path in sorted(folder.glob(pattern)):
        yield from read_logs(path)