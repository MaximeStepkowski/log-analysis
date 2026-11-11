"""Process logs and detect suspicious behavior."""

from log_process.brute_force import (
    BruteForceDetector,
    detect_brute_force,
    detect_brute_force_from_directory,
    write_report,
)

__all__ = [
    "BruteForceDetector",
    "detect_brute_force",
    "detect_brute_force_from_directory",
    "write_report",
]
