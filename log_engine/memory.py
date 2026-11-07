"""Utilities for reading the current and peak process memory usage."""

import ctypes
import os
import sys

try:
    import resource
except ImportError:  # pragma: no cover - disponible sous Unix uniquement
    resource = None


if sys.platform == "win32":
    class MemoryCounters(ctypes.Structure):
        """Windows structure used by GetProcessMemoryInfo."""

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
